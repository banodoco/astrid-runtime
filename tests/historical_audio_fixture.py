"""Private setup for the genuine-audio public journey fixture.

The captured ``film`` timeline is retained as historical evidence. This helper
adds a sibling publication to the caller-owned realm before the journey
captures its head, receipt, and event baseline. Authored leaves remain exact;
only legal child-owner identities, their binding identities, and the source
CAS pin are remapped.
"""

from __future__ import annotations

import copy
import io
import wave
from pathlib import Path
from types import SimpleNamespace

from runtime_protocol.service import RuntimeService
from runtime_protocol.timeline_commit_baseline import verify_baseline
from runtime_protocol.timeline_commit_store import digest
from runtime_protocol.util import now
from timeline_commit_film_fixture import FilmFixture


_TIMELINE_ID = "historical-audio-pcm"
_BOOTSTRAP_TIMELINE_ID = "historical-audio-pcm-child-bootstrap"
_SEED_PARENT_REVISION_ID = "historical-audio-pcm-parent-v1"
_PARENT_REVISION_ID = "historical-audio-pcm-parent-v2"
_BOOTSTRAP_PARENT_REVISION_ID = "historical-audio-pcm-child-bootstrap-v1"
_AUDIO_NAME = "music-bed.wav"
_AUDIO_IDEMPOTENCY_KEY = "historical-audio-pcm-source"
_SEED_PUBLICATION_IDEMPOTENCY_KEY = "historical-audio-pcm-publication-v1"
_PUBLICATION_IDEMPOTENCY_KEY = "historical-audio-pcm-publication-v2"
_MALFORMED_AUDIO = b"synthetic-music-bed"


def _child_identity_mapping(canonical: dict) -> dict:
    """Allocate sibling-owned identities without changing semantic order."""
    internals = {
        image["revision_id"]: f"{_TIMELINE_ID}-{image['revision_id']}"
        for image in canonical["internal_timeline_revisions"]
    }
    shots = {
        image["shot_id"]: f"{_TIMELINE_ID}-{image['shot_id']}"
        for image in canonical["shot_revisions"]
    }
    shot_revisions = {
        image["revision_id"]: f"{_TIMELINE_ID}-{image['revision_id']}"
        for image in canonical["shot_revisions"]
    }
    assert len(internals) == len(canonical["internal_timeline_revisions"])
    assert len(shots) == len(canonical["shot_revisions"])
    assert len(shot_revisions) == len(canonical["shot_revisions"])
    return {"internals": internals, "shots": shots, "shot_revisions": shot_revisions}


def _pcm_wav() -> bytes:
    """Return six seconds of genuine mono 8 kHz, 16-bit PCM audio."""
    stream = io.BytesIO()
    with wave.open(stream, "wb") as output:
        output.setparams((1, 2, 8000, 0, "NONE", "not compressed"))
        output.writeframes(b"\x00\x00" * 48000)
    return stream.getvalue()


def assert_malformed_audio_metadata_unavailable(tmp_path: Path) -> None:
    """Keep the captured 19-byte control visibly unknown to Main's reader.

    The control is a temporary local input only: it is not ingested, attached
    to a timeline, accepted, or left as a draft.  ``media_seconds`` is Main's
    existing raw-media duration helper and reports ``None`` for this input.
    """
    from astrid.sdk.timeline.store import media_seconds

    tmp_path.mkdir(parents=True, exist_ok=True)
    malformed = tmp_path / "historical-audio-malformed19.bin"
    malformed.write_bytes(_MALFORMED_AUDIO)
    try:
        assert media_seconds("", malformed) is None
    finally:
        malformed.unlink(missing_ok=True)
    assert not malformed.exists()


def _cloned_parent_body(
    canonical: dict,
    *,
    project_id: str,
    audio_id: str,
    identities: dict,
    bindings: dict,
    timeline_id: str = _TIMELINE_ID,
    parent_revision_id: str = _SEED_PARENT_REVISION_ID,
) -> dict:
    old_parent = canonical["parent_revision"]["payload"]
    old_audio_id = old_parent["registry"]["assets"]["music-bed"]["object_id"]
    parent = copy.deepcopy(old_parent)
    parent["registry"]["assets"]["music-bed"]["object_id"] = audio_id
    assert "duration" not in parent["registry"]["assets"]["music-bed"]

    internals = []
    for source in canonical["internal_timeline_revisions"]:
        internal = copy.deepcopy(source)
        internal["timeline_id"] = _TIMELINE_ID
        internal["revision_id"] = identities["internals"][source["revision_id"]]
        internal["content_digest"] = digest(internal["payload"])
        internals.append(internal)

    shots = []
    for source in canonical["shot_revisions"]:
        shot = copy.deepcopy(source)
        shot_id = identities["shots"][source["shot_id"]]
        shot_revision_id = identities["shot_revisions"][source["revision_id"]]
        internal_revision_id = identities["internals"][
            source["internal_timeline_revision_id"]
        ]
        shot["shot_id"] = shot_id
        shot["revision_id"] = shot_revision_id
        shot["internal_timeline_revision_id"] = internal_revision_id
        shot["payload"]["internal_timeline_revision_id"] = internal_revision_id
        for binding in shot["payload"].get("text_bindings", []):
            source_binding = bindings[(source["shot_id"], binding["binding_id"])]
            binding.update(
                binding_id=source_binding["binding_id"],
                project_id=project_id,
                shot_id=shot_id,
                event_stream_id=source_binding["event_stream_id"],
            )
        shot["content_digest"] = digest(shot["payload"])
        shots.append(shot)

    parent["occurrences"] = copy.deepcopy(parent["occurrences"])
    for occurrence in parent["occurrences"]:
        occurrence["shot_id"] = identities["shots"][occurrence["shot_id"]]
        occurrence["shot_revision_id"] = identities["shot_revisions"][
            occurrence["shot_revision_id"]
        ]

    # ``documents`` is a read-side closure field, not an accepted publication
    # input. Runtime derives the child closure and normalizes its media pins.
    manifest = {
        "shots": [
            {
                key: image[key]
                for key in (
                    "shot_id",
                    "revision_id",
                    "internal_timeline_revision_id",
                    "content_digest",
                )
            }
            for image in sorted(
                shots, key=lambda image: (image["shot_id"], image["revision_id"])
            )
        ],
        "internal_timelines": [
            {
                key: image[key]
                for key in ("timeline_id", "revision_id", "content_digest")
            }
            for image in sorted(
                internals, key=lambda image: (image["timeline_id"], image["revision_id"])
            )
        ],
        "media": copy.deepcopy(canonical["dependency_manifest"]["media"]),
    }
    for item in manifest["media"]:
        if item["media_id"] == old_audio_id:
            item["media_id"] = audio_id
            item["content_digest"] = audio_id
    manifest["media"].sort(key=lambda item: item["media_id"])

    return {
        "project_id": project_id,
        "timeline_id": timeline_id,
        "expected_head": None,
        "parent_revision_id": parent_revision_id,
        "internal_timeline_revisions": internals,
        "shot_revisions": shots,
        "parent_composition": parent,
        "dependency_manifest": manifest,
    }


def prepare_pcm_historical_audio_film(film, tmp_path):
    """Seed and read back a genuine audio sibling before journey capture."""
    assert_malformed_audio_metadata_unavailable(tmp_path)
    audio_bytes = _pcm_wav()
    prepared = None

    for root in (film.fixture.source_root, film.fixture.duplicate_root):
        service = RuntimeService(root)
        try:
            old_baseline = verify_baseline(
                service.store.conn,
                film.fixture.project_id,
                film.fixture.timeline_id,
                read_object=service.cas.read,
            )
            old_document = copy.deepcopy(old_baseline["canonical_document"])
            audio = service.ingest(
                film.fixture.project_id,
                audio_bytes,
                media_type="audio/wav",
                original_name=_AUDIO_NAME,
                idempotency_key=_AUDIO_IDEMPOTENCY_KEY,
            )
            audio_id = audio["data"]["object_id"]
            service.create_timeline(
                film.fixture.project_id,
                _TIMELINE_ID,
                idempotency_key=f"{_TIMELINE_ID}-create",
            )
            service.create_timeline(
                film.fixture.project_id,
                _BOOTSTRAP_TIMELINE_ID,
                idempotency_key=f"{_BOOTSTRAP_TIMELINE_ID}-create",
            )
            identities = _child_identity_mapping(old_document)
            binding_identities = {}
            for source in old_document["shot_revisions"]:
                source_shot_id = source["shot_id"]
                sibling_shot_id = identities["shots"][source_shot_id]
                payload = copy.deepcopy(source["payload"])
                payload["internal_timeline_revision_id"] = identities["internals"][
                    source["internal_timeline_revision_id"]
                ]
                service._apply_published_shot_projection(
                    film.fixture.project_id,
                    {"shot_id": sibling_shot_id, "payload": payload},
                    now(),
                )
                for descriptor in payload.get("text_bindings", []):
                    binding_id = RuntimeService._text_binding_id(
                        film.fixture.project_id,
                        sibling_shot_id,
                        descriptor["kind"],
                        descriptor.get("slot"),
                    )
                    binding_identities[(source_shot_id, descriptor["binding_id"])] = {
                        "binding_id": binding_id,
                        "event_stream_id": binding_id + ":shot.text_binding",
                    }
            body = _cloned_parent_body(
                old_document,
                project_id=film.fixture.project_id,
                audio_id=audio_id,
                identities=identities,
                bindings=binding_identities,
            )
            seed_document = {
                "schema_version": 1,
                "project_id": film.fixture.project_id,
                "timeline_id": _BOOTSTRAP_TIMELINE_ID,
                "parent_revision": {
                    "revision_id": _BOOTSTRAP_PARENT_REVISION_ID,
                    "content_digest": digest(
                        {**body["parent_composition"], "occurrences": []}
                    ),
                    "payload": {
                        **copy.deepcopy(body["parent_composition"]),
                        "occurrences": [],
                    },
                },
                "shot_revisions": copy.deepcopy(body["shot_revisions"]),
                "internal_timeline_revisions": copy.deepcopy(
                    body["internal_timeline_revisions"]
                ),
                # The private seed is only an unplaced child-owner bootstrap.
                # Its parent payload still carries the immutable media pins,
                # so retain those real edges in the bootstrap graph. Child
                # revision edges belong to the subsequent authored publication
                # once the occurrences are placed.
                "dependency_manifest": {
                    "shots": [],
                    "internal_timelines": [],
                    "media": copy.deepcopy(body["dependency_manifest"]["media"]),
                },
            }
            # Seed the complete child closure while it is still unplaced. The
            # existing private closure helper writes no history; the empty
            # parent has no occurrence, so normal binding creation remains
            # legal before the authored publication below.
            commits, _ = service._timeline_commits()
            with service.store._transaction():
                commits._persist_closure(seed_document)
            bindings = {}
            for source in old_document["shot_revisions"]:
                sibling_shot_id = identities["shots"][source["shot_id"]]
                for descriptor in source["payload"].get("text_bindings", []):
                    text = descriptor.get("text")
                    if text is None:
                        text = service.cas.read(
                            descriptor["media_id"].removeprefix("sha256:")
                        ).decode("utf-8")
                    created = service.set_project_shot_text_binding(
                        film.fixture.project_id,
                        {
                            "shot_id": sibling_shot_id,
                            "kind": descriptor["kind"],
                            "slot": descriptor.get("slot"),
                            "text": text,
                            "expected_head": 0,
                        },
                        idempotency_key=(
                            f"{_TIMELINE_ID}-binding-{source['shot_id']}-"
                            f"{descriptor['kind']}-{descriptor.get('slot') or 'none'}"
                        ),
                    )
                    bindings[(source["shot_id"], descriptor["binding_id"])] = created[
                        "data"
                    ]
                    assert created["data"]["binding_id"] == binding_identities[
                        (source["shot_id"], descriptor["binding_id"])
                    ]["binding_id"]
            expected_document = {
                "schema_version": 1,
                "project_id": film.fixture.project_id,
                "timeline_id": _TIMELINE_ID,
                "parent_revision": {
                    "revision_id": _SEED_PARENT_REVISION_ID,
                    "content_digest": digest(body["parent_composition"]),
                    "payload": copy.deepcopy(body["parent_composition"]),
                },
                "shot_revisions": copy.deepcopy(body["shot_revisions"]),
                "internal_timeline_revisions": copy.deepcopy(
                    body["internal_timeline_revisions"]
                ),
                "dependency_manifest": {
                    **copy.deepcopy(body["dependency_manifest"]),
                    "documents": [],
                },
            }
            service.publish_parent_composition(
                film.fixture.project_id,
                _TIMELINE_ID,
                body,
                idempotency_key=_SEED_PUBLICATION_IDEMPOTENCY_KEY,
            )
            second_body = copy.deepcopy(body)
            second_body["expected_head"] = _SEED_PARENT_REVISION_ID
            second_body["parent_revision_id"] = _PARENT_REVISION_ID
            publication = service.publish_parent_composition(
                film.fixture.project_id,
                _TIMELINE_ID,
                second_body,
                idempotency_key=_PUBLICATION_IDEMPOTENCY_KEY,
            )

            sibling = verify_baseline(
                service.store.conn,
                film.fixture.project_id,
                _TIMELINE_ID,
                read_object=service.cas.read,
            )
            sibling_document = sibling["canonical_document"]
            expected_document["parent_revision"]["revision_id"] = _PARENT_REVISION_ID
            expected_document["parent_revision"]["content_digest"] = digest(
                body["parent_composition"]
            )
            assert sibling_document == expected_document
            assert sibling_document["parent_revision"]["payload"]["registry"][
                "assets"
            ]["music-bed"]["object_id"] == audio_id
            assert [
                row["occurrence_id"]
                for row in sibling_document["parent_revision"]["payload"][
                    "occurrences"
                ]
            ] == [
                row["occurrence_id"]
                for row in old_document["parent_revision"]["payload"]["occurrences"]
            ]
            for old, new in zip(
                old_document["parent_revision"]["payload"]["occurrences"],
                sibling_document["parent_revision"]["payload"]["occurrences"],
            ):
                restored = copy.deepcopy(new)
                restored["shot_id"] = old["shot_id"]
                restored["shot_revision_id"] = old["shot_revision_id"]
                assert restored == old
                assert new["shot_id"] == identities["shots"][old["shot_id"]]
                assert new["shot_revision_id"] == identities["shot_revisions"][
                    old["shot_revision_id"]
                ]
            for old, new in zip(
                old_document["internal_timeline_revisions"],
                sibling_document["internal_timeline_revisions"],
            ):
                assert old["payload"] == new["payload"]
                assert new["timeline_id"] == _TIMELINE_ID
            for old, new in zip(
                old_document["shot_revisions"], sibling_document["shot_revisions"]
            ):
                expected_payload = copy.deepcopy(old["payload"])
                expected_payload["internal_timeline_revision_id"] = new[
                    "internal_timeline_revision_id"
                ]
                for old_binding, new_binding in zip(
                    old["payload"].get("text_bindings", []),
                    expected_payload.get("text_bindings", []),
                ):
                    binding = bindings[(old["shot_id"], old_binding["binding_id"])]
                    new_binding.update(
                        binding_id=binding["binding_id"],
                        project_id=film.fixture.project_id,
                        shot_id=new["shot_id"],
                        event_stream_id=binding["event_stream_id"],
                    )
                assert new["payload"] == expected_payload
                assert new["shot_id"] == identities["shots"][old["shot_id"]]
            assert "duration" not in sibling_document["parent_revision"]["payload"][
                "registry"
            ]["assets"]["music-bed"]
            # Exercise ordinary Runtime reads and the canonical open-bundle
            # path before returning the fixture to the authoring journey.
            service.get_project_parent_composition_revision(
                film.fixture.project_id, _TIMELINE_ID, _PARENT_REVISION_ID
            )
            for image in sibling_document["shot_revisions"]:
                service.get_project_shot_revision(
                    film.fixture.project_id, image["shot_id"], image["revision_id"]
                )
            for image in sibling_document["internal_timeline_revisions"]:
                service.get_project_timeline_revision(
                    film.fixture.project_id, _TIMELINE_ID, image["revision_id"]
                )
            assert commits.revision_closure(
                film.fixture.project_id, _TIMELINE_ID, _PARENT_REVISION_ID
            ) == sibling_document
            assert service.object_location(film.fixture.project_id, audio_id)["verified"]
            assert service.cas.read(audio_id.removeprefix("sha256:")) == audio_bytes

            # The historical timeline's accepted history and closure remain
            # unchanged; setup only added the private sibling publication.
            assert verify_baseline(
                service.store.conn,
                film.fixture.project_id,
                film.fixture.timeline_id,
                read_object=service.cas.read,
            ) == old_baseline

            if root == film.fixture.duplicate_root:
                receipt = sibling["entries"][-1]["receipt"]
                original_events = [
                    tuple(row)
                    for row in service.store.conn.execute(
                        "SELECT * FROM timeline_events ORDER BY id"
                    )
                ]
                # Reopen the caller-owned realm through Runtime's ordinary
                # startup admission after all setup writes. This is a
                # read-only control for the graph that the next door startup
                # will consume; it does not repair or rewrite the realm.
                service.close()
                service = RuntimeService(root)
                try:
                    assert service.store.admission_report["ok"]
                    reopened = verify_baseline(
                        service.store.conn,
                        film.fixture.project_id,
                        _TIMELINE_ID,
                        read_object=service.cas.read,
                    )
                    assert reopened["canonical_document"] == sibling_document
                finally:
                    service.close()
                prepared = SimpleNamespace(
                    fixture=FilmFixture(
                        source_root=film.fixture.source_root,
                        duplicate_root=film.fixture.duplicate_root,
                        project_id=film.fixture.project_id,
                        timeline_id=_TIMELINE_ID,
                        parent_revision_id=_PARENT_REVISION_ID,
                        media_ids=tuple(sorted({*film.fixture.media_ids, audio_id})),
                        transcript_document_id=film.fixture.transcript_document_id,
                        text_binding_id=film.fixture.text_binding_id,
                    ),
                    publication={"data": receipt["result"], "receipt": receipt},
                    original_events=original_events,
                )
        finally:
            service.close()

    assert prepared is not None
    return prepared
