"""Exact, scoped retention of Documents consumed by a timeline commit.

This module deliberately has no public route and no mutable-document history
API.  The acceptance layer owns the outer transaction and calls the hooks
below while it holds the Runtime store lock.  A connection passed to
``persist_document_input_links`` is therefore either already in the commit
transaction or is wrapped in one for the small standalone helper use case.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from .cas import file_identity
from .errors import ConflictError, NotFoundError, ValidationError
from .timeline_commit_validation import finite_json
from .util import canonical_json, now


DOCUMENT_INPUT_SCHEMA_VERSION = 1
TRANSCRIPT_KIND = "media.transcript"
TRANSCRIPT_SCHEMA = "media.transcript/v1"
TRANSCRIPT_PREFIX = "transcript:"
PROJECT_PACK_KIND = "astrid.project-pack"
PROJECT_PACK_SCHEMA = "astrid.project-pack/v1"
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_MEDIA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


# The acceptance worker adds these tables to the canonical Runtime schema.
# Keeping the SQL here makes the migration and the acceptance hook use one
# exact definition without adding a second schema owner.
DOCUMENT_INPUT_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS timeline_document_input_contents (
    content_digest TEXT PRIMARY KEY,
    content_json TEXT NOT NULL,
    content_size INTEGER NOT NULL CHECK (content_size >= 0),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS timeline_document_input_bindings (
    project_id TEXT NOT NULL,
    document_id TEXT NOT NULL,
    document_version INTEGER NOT NULL CHECK (document_version >= 1),
    content_digest TEXT NOT NULL REFERENCES timeline_document_input_contents(content_digest),
    kind TEXT NOT NULL,
    document_created_at TEXT NOT NULL,
    document_updated_at TEXT NOT NULL,
    source_media_id TEXT,
    source_id TEXT,
    retained_at TEXT NOT NULL,
    PRIMARY KEY (project_id, document_id, document_version, content_digest)
);
CREATE TABLE IF NOT EXISTS timeline_document_input_links (
    project_id TEXT NOT NULL,
    timeline_id TEXT NOT NULL,
    publication_id TEXT NOT NULL,
    revision_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    dependency_kind TEXT NOT NULL,
    document_id TEXT NOT NULL,
    document_version INTEGER NOT NULL CHECK (document_version >= 1),
    content_digest TEXT NOT NULL,
    linked_at TEXT NOT NULL,
    PRIMARY KEY (
        project_id, timeline_id, publication_id, revision_id, ordinal,
        document_id, document_version, content_digest
    ),
    UNIQUE (project_id, timeline_id, publication_id, revision_id, ordinal),
    FOREIGN KEY (
        project_id, document_id, document_version, content_digest
    ) REFERENCES timeline_document_input_bindings(
        project_id, document_id, document_version, content_digest
    )
);
CREATE INDEX IF NOT EXISTS timeline_document_input_links_pin_idx
    ON timeline_document_input_links(
        project_id, timeline_id, document_id, document_version, content_digest
    );
"""


@dataclass(frozen=True)
class CapturedDocument:
    """Detached exact input returned by a port source read.

    ``retained`` distinguishes an old binding from a first-use live capture.
    The live version/digest are kept separately so acceptance can reject a
    capture/update race in its own transaction.
    """

    pin: dict[str, Any]
    document: dict[str, Any]
    retained: bool
    live_version: int | None
    live_digest: str | None
    source_media_id: str | None
    source_id: str | None
    expected_kind: str | None
    expected_schema: str | None


@dataclass(frozen=True)
class DocumentInputLink:
    capture: CapturedDocument
    dependency_kind: str
    ordinal: int


def initialize_document_input_schema(connection: sqlite3.Connection) -> None:
    """Create the input-retention tables in a migration-owned connection."""
    if not isinstance(connection, sqlite3.Connection):
        raise TypeError("connection must be a sqlite3.Connection")
    connection.executescript(DOCUMENT_INPUT_SCHEMA_SQL)


def content_digest(content: Any) -> str:
    """Return the port-format digest of canonical finite JSON content."""
    return _content_bytes(content)[0]


def _content_bytes(content: Any) -> tuple[str, str, int]:
    finite_json(content)
    try:
        encoded = canonical_json(content).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ValidationError("document content must be canonical UTF-8 JSON") from exc
    digest = "sha256:" + hashlib.sha256(encoded).hexdigest()
    return digest, encoded.decode("utf-8"), len(encoded)


def _pin(pin: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(pin, Mapping):
        raise ValidationError("document pin must be an object")
    if set(pin) != {"document_id", "version", "content_digest"}:
        raise ValidationError("document pin must contain document_id, version, and content_digest")
    document_id = pin["document_id"]
    version = pin["version"]
    digest = pin["content_digest"]
    if not isinstance(document_id, str) or not document_id.strip():
        raise ValidationError("document pin document_id must be a non-empty string")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise ValidationError("document pin version must be a positive integer")
    if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
        raise ValidationError("document pin content_digest must be a canonical SHA-256 digest")
    return {"document_id": document_id, "version": version, "content_digest": digest}


def _pin_key(pin: Mapping[str, Any]) -> tuple[str, int, str]:
    value = _pin(pin)
    return value["document_id"], value["version"], value["content_digest"]


def _transcript_id(project_id: str, media_id: str, source_id: str) -> str:
    identity = [TRANSCRIPT_SCHEMA, project_id, media_id, source_id]
    return TRANSCRIPT_PREFIX + hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()


def _document_source(content: Any, *, project_id: str, document_id: str, kind: str,
                     expected_kind: str | None, expected_schema: str | None,
                     connection: sqlite3.Connection) -> tuple[str | None, str | None]:
    if expected_kind is not None and kind != expected_kind:
        raise ConflictError("document kind is not authorized for this input")
    if kind == PROJECT_PACK_KIND:
        _project_pack_source(connection, project_id, document_id, content)
    if kind == TRANSCRIPT_KIND:
        if not isinstance(content, dict) or content.get("schema") != TRANSCRIPT_SCHEMA:
            raise ConflictError("transcript document schema is not authorized")
        media_id = content.get("media_id")
        source_id = content.get("source_id")
        if not isinstance(media_id, str) or not _MEDIA_RE.fullmatch(media_id):
            raise ConflictError("transcript media identity is invalid")
        if not isinstance(source_id, str) or not source_id.strip():
            raise ConflictError("transcript source identity is invalid")
        if document_id != _transcript_id(project_id, media_id, source_id):
            raise ConflictError("transcript document identity does not match its source")
        owned = connection.execute(
            "SELECT 1 FROM objects o JOIN project_objects po ON po.digest=o.digest "
            "WHERE o.digest=? AND po.project_id=? AND po.relation='managed'",
            (media_id.removeprefix("sha256:"), project_id),
        ).fetchone()
        if owned is None:
            raise ConflictError("transcript source media is not currently managed by the project")
        if expected_schema is not None and content.get("schema") != expected_schema:
            raise ConflictError("document schema is not authorized for this input")
        return media_id, source_id
    if expected_kind is None:
        raise ValidationError("config/document input requires its registered kind")
    if expected_schema is not None:
        if not isinstance(content, dict) or content.get("schema") != expected_schema:
            raise ConflictError("document schema is not authorized for this input")
    return None, None


def _project_pack_source(connection: sqlite3.Connection, project_id: str,
                         document_id: str, content: Any) -> None:
    if not isinstance(content, dict) or set(content) != {
        "schema", "pack_id", "source_binding_key", "relative_manifest", "admissions",
    } or content.get("schema") != PROJECT_PACK_SCHEMA or content.get("source_binding_key") != "project-packs":
        raise ConflictError("project pack schema/source binding is not authorized")
    owner = content["pack_id"]
    if not isinstance(owner, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", owner):
        raise ConflictError("project pack owner is invalid")
    project = connection.execute("SELECT realm_id FROM projects WHERE id=?", (project_id,)).fetchone()
    if project is None:
        raise ConflictError("project pack project binding is missing")
    default_owner = "project_" + hashlib.sha256(f"{project['realm_id']}:{project_id}:default".encode()).hexdigest()[:20]
    collections = [owner, "default"] if owner == default_owner else [owner]
    identities = {
        "document:" + str(uuid.uuid5(uuid.NAMESPACE_URL, json.dumps([project_id, PROJECT_PACK_KIND, collection])))
        for collection in collections
    }
    if document_id not in identities or content["relative_manifest"] != (
        f"{project['realm_id']}/{project_id}/packs/{owner}/pack.yaml"
    ):
        raise ConflictError("project pack document identity is outside its project binding")
    admissions = content["admissions"]
    if not isinstance(admissions, list):
        raise ConflictError("project pack admissions are invalid")
    seen = set()
    for admission in admissions:
        if (not isinstance(admission, dict) or not {"id", "kind", "revision", "snapshot_digest"} <= set(admission)
                or set(admission) - {"id", "kind", "revision", "snapshot_digest", "snapshot_object"}
                or not isinstance(admission["id"], str) or not admission["id"]
                or not isinstance(admission["kind"], str) or admission["kind"] not in {"effect", "animation", "transition"}
                or not isinstance(admission["revision"], str) or not _DIGEST_RE.fullmatch(admission["revision"])
                or not isinstance(admission["snapshot_digest"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", admission["snapshot_digest"])):
            raise ConflictError("project pack admission identity/digest is invalid")
        identity = admission["id"], admission["kind"], admission["revision"]
        if identity in seen:
            raise ConflictError("project pack admission identity is ambiguous")
        seen.add(identity)
    validate_pack_snapshot_objects(connection, project_id, content)


def pack_snapshot_objects(content: Any) -> list[dict[str, Any]]:
    """Return the optional portable descriptors; missing means legacy admission."""
    descriptors = []
    if not isinstance(content, dict) or not isinstance(content.get("admissions"), list):
        return descriptors
    for admission in content["admissions"]:
        if not isinstance(admission, dict) or "snapshot_object" not in admission:
            continue
        value = admission["snapshot_object"]
        if (not isinstance(value, dict) or set(value) != {"object_id", "digest", "size", "media_type"}
                or not isinstance(value["object_id"], str) or not _DIGEST_RE.fullmatch(value["object_id"])
                or value["digest"] != value["object_id"]
                or type(value["size"]) is not int or value["size"] <= 0
                or value["media_type"] != "application/json"):
            raise ValidationError("project pack snapshot_object descriptor is invalid")
        descriptors.append(copy.deepcopy(value))
    return descriptors


def validate_pack_snapshot_objects(connection: sqlite3.Connection, project_id: str,
                                   content: Any) -> None:
    for descriptor in pack_snapshot_objects(content):
        row = connection.execute(
            "SELECT o.size, o.media_type FROM objects o JOIN project_objects po ON po.digest=o.digest "
            "WHERE po.project_id=? AND o.digest=? AND po.relation='managed'",
            (project_id, descriptor["object_id"].removeprefix("sha256:")),
        ).fetchone()
        if row is None or row["size"] != descriptor["size"] or row["media_type"] != descriptor["media_type"]:
            raise ConflictError("project pack snapshot object metadata or managed project association is invalid")


def read_pack_snapshot_object(connection: sqlite3.Connection, cas, project_id: str,
                              descriptor: Mapping[str, Any], *, max_bytes: int):
    """Read managed CAS bytes and their file identity, never a source/cache path."""
    validate_pack_snapshot_objects(connection, project_id, {"admissions": [{"snapshot_object": descriptor}]})
    if descriptor["size"] > max_bytes:
        raise ValidationError("project pack snapshot object exceeds the object byte limit")
    try:
        with cas.open(descriptor["object_id"].removeprefix("sha256:")) as stream:
            identity = file_identity(os.fstat(stream.fileno()))
            if identity[2] != descriptor["size"]:
                raise ConflictError("project pack snapshot object size is corrupt")
            data = stream.read(descriptor["size"] + 1)
            if (len(data) != descriptor["size"] or file_identity(os.fstat(stream.fileno())) != identity
                    or "sha256:" + hashlib.sha256(data).hexdigest() != descriptor["digest"]):
                raise ConflictError("project pack snapshot object bytes are corrupt or changed")
    except (OSError, NotFoundError) as exc:
        raise ConflictError("project pack snapshot object bytes are unavailable") from exc
    return data, identity


def _reachable(pin: Mapping[str, Any], reachable_pins: Iterable[Any] | None) -> bool:
    if reachable_pins is None:
        return False
    wanted = _pin_key(pin)
    for candidate in reachable_pins:
        if isinstance(candidate, CapturedDocument):
            candidate = candidate.pin
        try:
            if _pin_key(candidate) == wanted:
                return True
        except (TypeError, ValidationError):
            continue
    return False


def _load_content(connection: sqlite3.Connection, digest: str) -> Any:
    row = connection.execute(
        "SELECT content_json, content_size FROM timeline_document_input_contents WHERE content_digest=?",
        (digest,),
    ).fetchone()
    if row is None:
        raise ConflictError("retained document content is missing")
    encoded = row["content_json"] if isinstance(row, sqlite3.Row) else row[0]
    size = row["content_size"] if isinstance(row, sqlite3.Row) else row[1]
    try:
        raw = encoded.encode("utf-8")
        content = json.loads(encoded)
    except (AttributeError, TypeError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise ConflictError("retained document content is corrupt") from exc
    try:
        loaded_digest, loaded_encoded, _ = _content_bytes(content)
    except ValidationError as exc:
        raise ConflictError("retained document content is corrupt") from exc
    if len(raw) != size or loaded_digest != digest or loaded_encoded != encoded:
        raise ConflictError("retained document content digest or canonical bytes failed")
    return content


def _binding_document(connection: sqlite3.Connection, row: sqlite3.Row,
                      *, expected_kind: str | None, expected_schema: str | None) -> CapturedDocument:
    content = _load_content(connection, row["content_digest"])
    media_id, source_id = _document_source(
        content,
        project_id=row["project_id"],
        document_id=row["document_id"],
        kind=row["kind"],
        expected_kind=expected_kind,
        expected_schema=expected_schema,
        connection=connection,
    )
    if (row["source_media_id"], row["source_id"]) != (media_id, source_id):
        raise ConflictError("retained document source identity does not match its content")
    document = {
        "document_id": row["document_id"],
        "project_id": row["project_id"],
        "kind": row["kind"],
        "content": copy.deepcopy(content),
        "version": int(row["document_version"]),
        "created_at": row["document_created_at"],
        "updated_at": row["document_updated_at"],
    }
    return CapturedDocument(
        pin={"document_id": row["document_id"], "version": int(row["document_version"]), "content_digest": row["content_digest"]},
        document=document,
        retained=True,
        live_version=None,
        live_digest=None,
        source_media_id=media_id,
        source_id=source_id,
        expected_kind=expected_kind,
        expected_schema=expected_schema,
    )
def _current_document(connection: sqlite3.Connection, project_id: str, document_id: str) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM project_documents WHERE project_id=? AND id=?",
        (project_id, document_id),
    ).fetchone()
    if row is None:
        raise NotFoundError("document input is not available in the project")
    return row


def _live_capture(connection: sqlite3.Connection, row: sqlite3.Row, pin: Mapping[str, Any],
                  *, expected_kind: str | None, expected_schema: str | None) -> CapturedDocument:
    try:
        content = json.loads(row["content_json"])
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ConflictError("live document content is corrupt") from exc
    digest, encoded, _ = _content_bytes(content)
    if digest != pin["content_digest"] or int(row["version"]) != pin["version"]:
        raise NotFoundError("exact document version is not retained")
    # Canonicalize the live row before returning it. A non-canonical row is
    # not an exact byte identity even when JSON values happen to compare equal.
    if row["content_json"] != encoded:
        raise ConflictError("live document content is not canonical")
    media_id, source_id = _document_source(
        content,
        project_id=row["project_id"],
        document_id=row["id"],
        kind=row["kind"],
        expected_kind=expected_kind,
        expected_schema=expected_schema,
        connection=connection,
    )
    document = {
        "document_id": row["id"],
        "project_id": row["project_id"],
        "kind": row["kind"],
        "content": copy.deepcopy(content),
        "version": int(row["version"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
    return CapturedDocument(
        pin=copy.deepcopy(dict(pin)),
        document=document,
        retained=False,
        live_version=int(row["version"]),
        live_digest=digest,
        source_media_id=media_id,
        source_id=source_id,
        expected_kind=expected_kind,
        expected_schema=expected_schema,
    )


def capture_document_input(connection: sqlite3.Connection, project_id: str,
                           pin: Mapping[str, Any], *,
                           reachable_pins: Iterable[Any] | None = None,
                           expected_kind: str | None = None,
                           expected_schema: str | None = None) -> CapturedDocument:
    """Capture the exact authorized Document named by ``pin``.

    ``reachable_pins`` is required only when resolving an old retained
    binding. It is intentionally caller-supplied: the acceptance layer knows
    which base closure or accepted-history records the request is authorized
    to read, while this helper refuses to infer reachability from a digest.
    """
    if not isinstance(project_id, str) or not project_id.strip():
        raise ValidationError("project_id must be a non-empty string")
    pin = _pin(pin)
    started = not connection.in_transaction
    if started:
        connection.execute("BEGIN")
    try:
        row = connection.execute(
            "SELECT * FROM timeline_document_input_bindings "
            "WHERE project_id=? AND document_id=? AND document_version=? AND content_digest=?",
            (project_id, pin["document_id"], pin["version"], pin["content_digest"]),
        ).fetchone()
        if row is not None:
            if not _reachable(pin, reachable_pins):
                raise ConflictError("retained document input is outside the authorized closure")
            value = _binding_document(connection, row, expected_kind=expected_kind, expected_schema=expected_schema)
        else:
            current = _current_document(connection, project_id, pin["document_id"])
            value = _live_capture(connection, current, pin, expected_kind=expected_kind, expected_schema=expected_schema)
        if started:
            connection.commit()
        return value
    except Exception:
        if started:
            connection.rollback()
        raise


def reachable_document_input_pins(connection: sqlite3.Connection, project_id: str,
                                  timeline_id: str, *,
                                  revision_ids: Iterable[str] | None = None,
                                  publication_ids: Iterable[str] | None = None) -> list[dict[str, Any]]:
    """Return exact pins linked by the caller-authorized accepted records.

    Callers should pass already-authorized revision/publication IDs. This
    helper does not turn a guessed revision or publication into authority.
    """
    revisions = list(revision_ids or [])
    publications = list(publication_ids or [])
    if not revisions and not publications:
        return []
    clauses = []
    args: list[Any] = [project_id, timeline_id]
    if revisions:
        clauses.append("revision_id IN (" + ",".join("?" for _ in revisions) + ")")
        args.extend(revisions)
    if publications:
        clauses.append("publication_id IN (" + ",".join("?" for _ in publications) + ")")
        args.extend(publications)
    rows = connection.execute(
        "SELECT DISTINCT document_id, document_version, content_digest FROM timeline_document_input_links "
        "WHERE project_id=? AND timeline_id=? AND (" + " OR ".join(clauses) + ") "
        "ORDER BY document_id, document_version, content_digest",
        args,
    ).fetchall()
    return [{"document_id": row[0], "version": int(row[1]), "content_digest": row[2]} for row in rows]


def _capture_source(
    connection: sqlite3.Connection, capture: CapturedDocument
) -> tuple[tuple[str | None, str | None], str]:
    pin = _pin(capture.pin)
    document = capture.document
    if not isinstance(document, dict) or not isinstance(document.get("project_id"), str):
        raise ValidationError("captured document is malformed")
    if document.get("document_id") != pin["document_id"]:
        raise ConflictError("captured document does not match its pin")
    if not isinstance(document.get("kind"), str):
        raise ValidationError("captured document kind is malformed")
    version = document.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise ValidationError("captured document version is malformed")
    source = _document_source(
        document.get("content"),
        project_id=document["project_id"],
        document_id=document.get("document_id"),
        kind=document.get("kind"),
        expected_kind=capture.expected_kind,
        expected_schema=capture.expected_schema,
        connection=connection,
    )
    digest, encoded, _ = _content_bytes(document["content"])
    if digest != pin["content_digest"] or version != pin["version"]:
        raise ConflictError("captured document does not match its pin")
    if source != (capture.source_media_id, capture.source_id):
        raise ConflictError("captured document source identity changed")
    return source, encoded


def _revalidate_capture(connection: sqlite3.Connection, capture: CapturedDocument) -> None:
    source, encoded = _capture_source(connection, capture)
    pin = _pin(capture.pin)
    document = capture.document
    if capture.retained:
        row = connection.execute(
            "SELECT * FROM timeline_document_input_bindings WHERE project_id=? AND document_id=? AND document_version=? AND content_digest=?",
            (document["project_id"], pin["document_id"], pin["version"], pin["content_digest"]),
        ).fetchone()
        if row is None:
            raise ConflictError("retained document binding is missing")
        if any(row[key] != document[field] for key, field in (
            ("kind", "kind"), ("document_created_at", "created_at"), ("document_updated_at", "updated_at"),
        )):
            raise ConflictError("retained document header changed")
        if (row["source_media_id"], row["source_id"]) != source:
            raise ConflictError("retained document source identity changed")
        stored_content = _load_content(connection, pin["content_digest"])
        _, stored_encoded, _ = _content_bytes(stored_content)
        if stored_encoded != encoded:
            raise ConflictError("retained document content changed")
        return
    if capture.live_version != pin["version"] or capture.live_digest != pin["content_digest"]:
        raise ConflictError("captured live document metadata does not match its pin")
    current = _current_document(connection, document["project_id"], document["document_id"])
    try:
        current_content = json.loads(current["content_json"])
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ConflictError("live document content is corrupt") from exc
    current_digest, current_encoded, _ = _content_bytes(current_content)
    if (int(current["version"]) != capture.live_version or current_digest != capture.live_digest
            or current_digest != pin["content_digest"] or current_encoded != encoded):
        raise ConflictError("document changed while the commit was being prepared")
    current_source = _document_source(
        current_content,
        project_id=current["project_id"],
        document_id=current["id"],
        kind=current["kind"],
        expected_kind=capture.expected_kind,
        expected_schema=capture.expected_schema,
        connection=connection,
    )
    if current_source != source:
        raise ConflictError("document source identity changed while the commit was being prepared")
    if any(current[key] != document[field] for key, field in (
        ("id", "document_id"), ("project_id", "project_id"), ("kind", "kind"),
        ("created_at", "created_at"), ("updated_at", "updated_at"),
    )):
        raise ConflictError("document header changed while the commit was being prepared")
def validate_captured_document_inputs(connection: sqlite3.Connection,
                                      captures: Iterable[CapturedDocument]) -> None:
    """Validate every detached input against current authority and stored bytes.

    This is the acceptance-layer preflight hook. It performs no writes and
    must run for the complete capture set before the caller allocates any
    retained content or publication links.
    """
    values = list(captures)
    for capture in values:
        if not isinstance(capture, CapturedDocument):
            raise ValidationError("captured document input is invalid")
        _revalidate_capture(connection, capture)


@contextmanager
def _write_transaction(connection: sqlite3.Connection):
    started = not connection.in_transaction
    if started:
        connection.execute("BEGIN IMMEDIATE")
    try:
        yield
    except Exception:
        if started:
            connection.rollback()
        raise
    else:
        if started:
            connection.commit()


def _link_item(item: Any, index: int) -> DocumentInputLink:
    if isinstance(item, DocumentInputLink):
        capture = item.capture
        dependency_kind = item.dependency_kind
        ordinal = item.ordinal
    elif isinstance(item, Mapping):
        capture = item.get("capture")
        dependency_kind = item.get("dependency_kind")
        ordinal = item.get("ordinal", index)
    elif isinstance(item, Sequence) and not isinstance(item, (str, bytes)) and len(item) == 2:
        capture, dependency_kind = item
        ordinal = index
    else:
        raise ValidationError("document input links must identify a capture and dependency kind")
    if not isinstance(capture, CapturedDocument):
        raise ValidationError("document input link capture is invalid")
    if dependency_kind not in {"transcript", "source"}:
        raise ValidationError("document input dependency_kind must be transcript or source")
    if isinstance(ordinal, bool) or not isinstance(ordinal, int) or ordinal < 0:
        raise ValidationError("document input link ordinal must be a non-negative integer")
    kind = capture.document.get("kind") if isinstance(capture.document, dict) else None
    if dependency_kind == "transcript" and kind != TRANSCRIPT_KIND:
        raise ValidationError("transcript links require a transcript document")
    if dependency_kind == "source" and (not isinstance(kind, str) or not (
            kind.endswith(".config") or kind == PROJECT_PACK_KIND)):
        raise ValidationError("source links require a config or project pack document")
    return DocumentInputLink(capture, dependency_kind, ordinal)


def persist_document_input_links(connection: sqlite3.Connection, *, project_id: str,
                                 timeline_id: str, publication_id: str, revision_id: str,
                                 links: Iterable[Any]) -> list[dict[str, Any]]:
    """Persist captured inputs and their accepted publication links atomically.

    All captures are revalidated before the first insert. If this helper owns
    the transaction it commits once; when called from acceptance it leaves the
    caller's single transaction open.
    """
    if not all(isinstance(value, str) and value.strip() for value in (project_id, timeline_id, publication_id, revision_id)):
        raise ValidationError("document input link identities must be non-empty strings")
    items = [_link_item(item, index) for index, item in enumerate(links)]
    if len({item.ordinal for item in items}) != len(items):
        raise ValidationError("document input link ordinals must be unique")
    with _write_transaction(connection):
        for item in items:
            if item.capture.document.get("project_id") != project_id:
                raise ConflictError("captured document belongs to a different project")
        validate_captured_document_inputs(connection, (item.capture for item in items))
        timestamp = now()
        results = []
        for item in items:
            capture = item.capture
            digest, encoded, size = _content_bytes(capture.document["content"])
            connection.execute(
                "INSERT OR IGNORE INTO timeline_document_input_contents(content_digest, content_json, content_size, created_at) VALUES (?, ?, ?, ?)",
                (digest, encoded, size, timestamp),
            )
            stored = connection.execute(
                "SELECT content_json, content_size FROM timeline_document_input_contents WHERE content_digest=?",
                (digest,),
            ).fetchone()
            if stored is None or stored[0] != encoded or int(stored[1]) != size:
                raise ConflictError("immutable retained document content has conflicting bytes")
            document = capture.document
            connection.execute(
                "INSERT OR IGNORE INTO timeline_document_input_bindings(" \
                "project_id, document_id, document_version, content_digest, kind, document_created_at, document_updated_at, source_media_id, source_id, retained_at) " \
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (project_id, document["document_id"], document["version"], digest, document["kind"],
                 document["created_at"], document["updated_at"], capture.source_media_id, capture.source_id, timestamp),
            )
            binding = connection.execute(
                "SELECT * FROM timeline_document_input_bindings WHERE project_id=? AND document_id=? AND document_version=? AND content_digest=?",
                (project_id, document["document_id"], document["version"], digest),
            ).fetchone()
            if binding is None:
                raise ConflictError("retained document binding was not persisted")
            for key, expected in (("kind", document["kind"]), ("document_created_at", document["created_at"]),
                                  ("document_updated_at", document["updated_at"]), ("source_media_id", capture.source_media_id),
                                  ("source_id", capture.source_id)):
                if binding[key] != expected:
                    raise ConflictError("retained document binding has conflicting header or source")
            try:
                connection.execute(
                    "INSERT INTO timeline_document_input_links(project_id, timeline_id, publication_id, revision_id, ordinal, dependency_kind, document_id, document_version, content_digest, linked_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (project_id, timeline_id, publication_id, revision_id, item.ordinal, item.dependency_kind,
                     document["document_id"], document["version"], digest, timestamp),
                )
            except sqlite3.IntegrityError as exc:
                existing = connection.execute(
                    "SELECT dependency_kind, document_id, document_version, content_digest FROM timeline_document_input_links "
                    "WHERE project_id=? AND timeline_id=? AND publication_id=? AND revision_id=? AND ordinal=?",
                    (project_id, timeline_id, publication_id, revision_id, item.ordinal),
                ).fetchone()
                if existing is None or tuple(existing) != (item.dependency_kind, document["document_id"], document["version"], digest):
                    raise ConflictError("accepted document input link identity was reused with different data") from exc
            results.append({
                "document_id": document["document_id"],
                "version": int(document["version"]),
                "content_digest": digest,
                "dependency_kind": item.dependency_kind,
                "ordinal": item.ordinal,
            })
        return results
