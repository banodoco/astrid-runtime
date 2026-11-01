"""Detached synchronous timeline commit provider ABI (interface version 1)."""

from __future__ import annotations

from copy import deepcopy
from typing import NotRequired, Protocol, TypedDict

from . import timeline_commit_types as dto
from .timeline_commit_producer import ProducerAttemptPin, VerifiedProducerAttempt
from .timeline_commit_types import *  # noqa: F403


class CommitRejected(Exception):
    def __init__(self, failure: dto.CommitFailure):
        self.failure = deepcopy(failure)
        super().__init__(self.failure["message"])


class StaleHead(Exception):
    def __init__(self, current_head: dto.HeadPin):
        self.current_head = deepcopy(current_head)
        super().__init__("timeline head changed")


# Internal to the port: no HTTP route, not part of the generated contract.
TextSelection = TypedDict("TextSelection", {"object_id": dto.Digest, "digest": dto.Digest, "size": int, "media_type": str})
VerifiedText = TypedDict("VerifiedText", {"object_id": dto.Digest, "digest": dto.Digest, "size": int,
                                          "media_type": str, "utf8": bool})
MediaInfo = TypedDict("MediaInfo", {"object_id": dto.Digest, "media_type": str, "size": int,
                                     "duration_seconds": NotRequired[float], "width": NotRequired[int],
                                     "height": NotRequired[int]})


class RuntimeCommitPort(Protocol):
    def capture_sequential_execution(self, capture: dict) -> None: ...
    def head(self) -> dto.HeadPin: ...
    def revision_closure(self, revision_id: str) -> dto.CanonicalDocument: ...
    def shot_closure(self, shot_id: str, revision_id: str) -> dto.ShotClosure: ...
    def history(
        self,
        through: dto.HeadPin,
        after_publication_id: str | None = None,
        cursor: str | None = None,
        limit: int = 100,
    ) -> dto.HistoryPage: ...
    def history_entry(self, publication_id: str) -> dto.HistoryEntry: ...
    def selected_media(self, selection: dto.MediaSelection) -> dto.VerifiedMedia: ...
    def raw_media_info(self, pin: dto.MediaManifestEntry) -> MediaInfo: ...
    def producer_attempt(self, pin: ProducerAttemptPin) -> VerifiedProducerAttempt: ...
    def text_selection(self, selection: TextSelection) -> VerifiedText: ...
    def transcript_source(self, pin: dto.DocumentPin) -> dto.VerifiedDocument: ...
    def config_source(self, pin: dto.DocumentPin) -> dto.VerifiedDocument: ...
    def document_object(
        self, pin: dto.DocumentPin, object_id: dto.Digest
    ) -> dto.VerifiedDocumentObject: ...
    def narration_take(
        self, refs: dto.NarrationTakeRefs
    ) -> dto.VerifiedNarrationTake: ...
    def preview(self, prepared: dto.PreparedCommit) -> dto.CommitPreviewResponse: ...
    def accept(self, prepared: dto.PreparedCommit) -> dto.CommitAcceptedMutation: ...
