"""Read-only capture certification using the startup semantic provider."""
from __future__ import annotations

import copy
import json

from .errors import ConflictError, RuntimeErrorBase, ValidationError
from .snapshot_refs import SNAPSHOT_KEYS, source_kind_of, working_copy_binding
from .timeline_commit import CommitRejected
from .timeline_commit_port import detached, digest
from .util import canonical_json

RESEND_HINT = 'send it as source_kind "cas" (explicit UNCERTIFIED) or forward the real authoring_preview.candidate'


def _equal(left, right, message):
    if canonical_json(left) != canonical_json(right):
        raise ConflictError(message)


def _candidate_document(commits, base, preview, ref, provider):
    candidate = preview["candidate"]
    publication = preview["publication"]
    binding = ref["working_copy"]
    _equal(preview["kind"], "authoring-candidate-preview", "invalid authoring preview kind")
    _equal(preview["candidate_digest"], digest(candidate), "candidate digest changed")
    _equal(preview["publication_digest"], digest(publication), "candidate publication digest changed")
    _equal(preview["head"], candidate["base_parent"], "candidate base bindings differ")
    _equal(candidate["base_parent"], {
        "revision_id": binding["base_revision_id"], "content_digest": binding["base_revision_digest"],
    }, "candidate base differs from capture binding")
    for value in (candidate, publication):
        _equal([value["project_id"], value["timeline_id"]],
               [base["project_id"], base["timeline_id"]], "candidate scope differs from saved base")
    _equal([preview["candidate_digest"], preview["publication_digest"],
            publication["parent_revision_id"], publication["expected_head"]],
           [binding["candidate_digest"], binding["publication_digest"],
            ref["revision_id"], binding["base_revision_id"]], "candidate differs from capture binding")
    method = getattr(provider, "capture_candidate_inputs", None)
    if not callable(method):
        raise ValidationError("canonical capture candidate provider is unavailable")
    # Agent owns construction; Runtime compares against the retained saved base.
    try:
        inputs = detached(method(detached(base), candidate=detached(candidate)))
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidationError("capture candidate inputs are invalid") from exc
    baseline = inputs["base"]
    for key in ("project_id", "timeline_id", "base_parent", "base_parent_payload"):
        _equal(candidate[key], baseline[key], "candidate " + key + " differs from saved base")
    source = candidate["source_mapping"]
    _equal(candidate["base_placements"], baseline["base_placements"],
           "candidate placement base differs from saved base")
    retained_placements = {canonical_json(row) for row in baseline["base_placements"].values()}
    for row in source["placements"].values():
        _equal(canonical_json(row) in retained_placements, True,
               "candidate placement source differs from saved base")
    for row in candidate["placements"]:
        identity = row["occurrence_id"]
        if identity in baseline["base_placements"]:
            _equal(source["placements"].get(identity), baseline["base_placements"][identity],
                   "candidate placement source differs from saved base")
    if "_runtime_document" in source:
        _equal(source["_runtime_document"], base, "candidate document base differs from saved base")
    # Authoring keys can change on a clone/rename. Match the complete retained
    # source, including its item mapping, even for sources no longer authored.
    retained = {canonical_json(row): baseline["shots"][identity]
                for identity, row in baseline["source_mapping"]["shots"].items()}
    for row in source["shots"].values():
        _equal(canonical_json(row) in retained, True,
               "candidate child source differs from saved base")
    for identity, shot in candidate["shots"].items():
        origin = source["shots"].get(identity)
        original = retained[canonical_json(origin)] if origin is not None else {}
        for key in ("base_payload", "base_internal_timeline"):
            _equal(shot.get(key, {}), original.get(key, {}),
                   "candidate child base differs from saved base")
    for key in ("kind", "head", "candidate_digest", "publication_digest", "publication"):
        _equal(preview[key], inputs["preview"][key], "candidate " + key + " is not derived from candidate")
    document = copy.deepcopy(base)
    document["parent_revision"] = {
        "revision_id": publication["parent_revision_id"], "content_digest": publication["content_digest"],
        "payload": publication["parent_composition"],
    }
    manifest = copy.deepcopy(publication["dependency_manifest"])
    # A draft may reuse the exact document inputs retained by its saved base.
    pins = base["dependency_manifest"]["documents"]
    _equal(manifest.get("documents", pins), pins, "candidate document inputs are not retained by its base")
    manifest["documents"] = copy.deepcopy(pins)
    document["dependency_manifest"] = manifest
    for family, key in (("shot_revisions", "shots"), ("internal_timeline_revisions", "internal_timelines")):
        rows = {row["revision_id"]: row for row in base[family]}
        rows.update((row["revision_id"], row) for row in publication[family])
        document[family] = [rows[pin["revision_id"]] for pin in manifest[key]]
    commits._validate_closure(document)


def _contradicts_own_authority(snapshot):
    """Whether a candidate-less working-copy marker disagrees with the capture's own authority."""
    metadata = snapshot["metadata"]
    authority = metadata.get("capture_authority")
    return isinstance(authority, dict) and metadata["working_copy"] != authority["expansion"].get("working_copy")


def validate_capture(service, snapshot, ref, inputs):
    """Refuse a forged capture; return whether it is certified.

    A working copy sent without its candidate cannot be verified, so it is
    admitted CAS-only (uncertified) and never certified.
    """
    source_kind = source_kind_of(ref)
    if source_kind == "cas":
        return False
    preview = detached(inputs.get("authoring_preview")) if source_kind == "working_copy" else None
    if source_kind == "working_copy" and not (isinstance(preview, dict) and isinstance(preview.get("candidate"), dict)):
        try:
            contradicts = _contradicts_own_authority(snapshot)
        except (KeyError, TypeError) as exc:
            raise ValidationError("capture source is invalid; " + RESEND_HINT) from exc
        if contradicts:
            raise ConflictError("capture candidate marker changed; " + RESEND_HINT)
        return False
    method = getattr(service._timeline_commit_provider, "project_capture", None)
    if not callable(method):
        raise ValidationError("canonical capture projection provider is unavailable")
    try:
        commits, _ = service._timeline_commits()
        revision = ref["revision_id"]
        if source_kind == "working_copy":
            revision = ref["working_copy"]["base_revision_id"]
        document = commits.revision_closure(ref["project_id"], ref["timeline_id"], revision)
        if preview is not None:
            _candidate_document(commits, document, preview, ref, service._timeline_commit_provider)
        projection = detached(method(detached(document), authoring_preview=preview))
        for key in ("config", "registry"):
            _equal(snapshot[key], projection[key], "capture differs from authoritative " + key)
        expansion = projection["expansion"]
        _equal(expansion["parent_revision_id"], ref["revision_id"], "projector returned a different revision")
        if preview is None:
            _equal(expansion["parent_content_digest"], ref["revision_digest"], "capture parent digest changed")
        metadata = snapshot["metadata"]
        authority = metadata["capture_authority"]
        for value in (authority, metadata.get("canonical_timeline", authority)):
            _equal(value["parent_content_digest"], expansion["parent_content_digest"], "capture parent digest changed")
            _equal(value["expansion"], expansion, "capture expansion differs from authoritative projection")
        if preview is not None:
            _equal(metadata["working_copy"], expansion["working_copy"], "capture candidate marker changed")
            _equal(working_copy_binding(snapshot, ref["revision_id"]), ref["working_copy"],
                   "capture candidate binding changed")
        return True
    except CommitRejected as exc:
        raise ConflictError(exc.failure["message"], details=exc.failure["details"]) from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidationError("capture source or authoring_preview is invalid; " + RESEND_HINT) from exc


def claim_capture_view(service, spec):
    """Present a stored capture as canonical only while it still verifies.

    Specs admitted before capture content was checked stay readable and are
    never rewritten; a claim of one that cannot be verified exactly now is
    labelled CAS-only (uncertified legacy preview) instead.
    """
    inner = spec.get("spec") if isinstance(spec.get("spec"), dict) else {}
    context = inner.get("authority_context") if isinstance(inner.get("authority_context"), dict) else None
    outer_context = spec.get("authority_context") if isinstance(spec.get("authority_context"), dict) else None
    if context is None:
        context = outer_context
    contexts = [context] if context is not None else []
    # Admission and host materialization prefer the nested context, but old
    # task envelopes can retain an outer context as well.  Inspect both so an
    # active alias in the non-preferred location cannot evade certification.
    if outer_context is not None and outer_context is not context:
        contexts.append(outer_context)
    inputs = inner.get("inputs") if isinstance(inner.get("inputs"), dict) else {}
    labels = {}

    def claim_identity(key, ref):
        """Identify one authority claim, including its binding and scope."""
        return key, canonical_json(ref)

    for context in contexts:
        for key in SNAPSHOT_KEYS:
            ref = context.get(key + "_ref")
            if not isinstance(ref, dict) or source_kind_of(ref) not in {"revision", "working_copy"}:
                continue
            try:
                snapshot = json.loads(service.object(ref["digest"])[1])
                certified = validate_capture(service, snapshot, ref, inputs)
            except (RuntimeErrorBase, OSError, KeyError, TypeError, ValueError):
                certified = False
            if not certified:
                # Match the complete authority claim so exact duplicates
                # (including argv/filmstrip JSON) lose rejected claims while
                # independently verified claims for the same bytes survive.
                ref_key = key + "_ref"
                labels[claim_identity(ref_key, ref)] = {
                    "digest": ref["digest"], "project_id": ref.get("project_id"),
                    "timeline_id": ref.get("timeline_id"), "source_kind": "cas",
                }

    if not labels:
        return spec

    def relabel(value):
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                replacement = labels.get(claim_identity(key, item)) if (
                    key.endswith("_snapshot_ref") and isinstance(item, dict)
                ) else None
                result[key] = replacement if replacement is not None else relabel(item)
            return result
        if isinstance(value, list):
            return [relabel(item) for item in value]
        if isinstance(value, str):
            try:
                decoded = json.loads(value)
            except ValueError:
                return value
            if isinstance(decoded, (dict, list)):
                relabelled = relabel(decoded)
                return canonical_json(relabelled) if relabelled != decoded else value
        return value

    return relabel(spec)
