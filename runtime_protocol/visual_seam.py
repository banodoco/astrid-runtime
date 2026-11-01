"""Authoritative metadata admission for one-level immutable compositions.

Publication and render call this inside their existing transaction. Derived
reports never replace authored bytes. No media/decoder/plugin imports.
"""
from __future__ import annotations

import bisect
import copy
import hashlib
import json
import math
from collections import ChainMap, defaultdict
from itertools import pairwise

from .errors import ConflictError, NotFoundError, ValidationError
from .seam_intent import (
    boundary_intent_owners,
    intent_context,
    opaque_activation_cues,
    pause_covers,
    relevant_intent_owners,
)
from .seam_intent import cue_identity as portable_cue_identity
from .util import canonical_json
from .visual_boundary import (
    DISCLOSURE_VERSION,
    VERSION,
    boundary_report,
    finite,
    js_round,
    transition_frames,
)

MAX_METADATA_CLIPS = 20_000
AUXILIARY = frozenset({"end-spanning-layer", "effect-layer", "frame-overlay", "text"})
PICTURE = frozenset({"media", "hold", "video", "image", "animated-media-transform", "haus.astrid.liveScene"})
MEDIA_CLIP_TYPES = frozenset({"media", "video", "image"})


def covers_frame(clip, track, config):
    """Mirror the editor's coversFrame; unknown geometry is not a picture claim.

    Declared picture lanes explicitly opt custom renderers into this check.
    Aggregate child picture presence (picture_clip) remains independent.
    """
    if track.get("kind") != "visual" or track.get("role") == "source":
        return False
    policy = (config.get("app") or {}).get("visualSeamContract") or {}
    declared = policy.get("pictureTracks")
    declared = declared if isinstance(declared, list) else []
    kind = clip.get("clipType")
    kind = kind if isinstance(kind, str) and kind.strip() else "media"
    asset = clip.get("asset")
    if track.get("id") not in declared and not (kind in MEDIA_CLIP_TYPES and isinstance(asset, str) and asset.strip()):
        return False
    if finite(clip.get("opacity"), 1) < 1 or finite(track.get("opacity"), 1) < 1:
        return False
    resolution = str((config.get("output") or {}).get("resolution", "")).split("x")
    for index, dimension in enumerate(("width", "height")):
        try:
            size = float(resolution[index]) if resolution[index].strip() else 0
        except (ValueError, IndexError):
            size = 0
        value = finite(clip.get(dimension), None)
        if value is not None and not math.isnan(size) and size and value < size:
            return False
    return True


def picture_clip(clip, track):
    """A visual lane may carry a custom renderer's opaque picture clips.

    Unknown types count as picture on visual tracks. Known auxiliary types and
    source/audio lanes cannot supply picture coverage. Timing disclosure remains independent,
    including for custom picture.
    """
    kind = clip.get("clipType", clip.get("clip_type", "media"))
    element = clip.get("elementRef")
    if (kind in AUXILIARY or kind == "audio"
            or isinstance(element, dict) and element.get("kind") in ("effect", "animation", "transition")
            or track.get("kind") == "audio" or track.get("role") == "source"):
        return False
    return kind in PICTURE or track.get("kind") == "visual"


def active(clip):
    return (clip.get("enabled") is not False and clip.get("active") is not False
            and clip.get("disabled") is not True and clip.get("hidden") is not True and clip.get("deleted") is not True)


def seconds(clip, key, fallback=0):
    return finite(clip.get(key + "_ms"), fallback * 1000) / 1000 if key + "_ms" in clip else finite(clip.get(key), fallback)


def speed_value(value):
    if isinstance(value, dict):
        value = finite(value.get("numerator"), 0) / finite(value.get("denominator"), 1)
    result = finite(value, None)
    if result is None or result <= 0:
        raise ValidationError("visual timing speed must be positive")
    return result


def clip_seconds(clip, fallback=0, *, speed=None):
    if "hold" in clip:
        value = finite(clip["hold"], None)
    elif "duration_ms" in clip:
        value = finite(clip["duration_ms"], None)
        value = value / 1000 if value is not None else None
    elif "duration" in clip:
        value = finite(clip["duration"], None)
    elif "to" in clip or "to_ms" in clip:
        value = seconds(clip, "to") - seconds(clip, "from")
    else:
        value = fallback
    if value is None or value < 0:
        raise ValidationError("visual timing duration must be finite and non-negative")
    return value / (speed if speed is not None else speed_value(clip.get("speed", 1)))


def audio_clip(clip, track, registry):
    """Classify audio from the authored track, then explicit clip/asset metadata.

    Track IDs are arbitrary and never imply media kind. A declared visual or
    audio track is authoritative; legacy rows without a usable kind may fall
    back to an explicit audio clip type or the selected asset's media type.
    """
    track_kind = track.get("kind") if isinstance(track, dict) else None
    if track_kind in ("audio", "visual"):
        return track_kind == "audio"
    clip_type = clip.get("clipType", clip.get("clip_type", clip.get("type")))
    if isinstance(clip_type, str) and clip_type.lower() == "audio":
        return True
    asset_key = clip.get("asset", clip.get("asset_id"))
    assets = registry.get("assets", {}) if isinstance(registry, dict) else {}
    asset = assets.get(asset_key, {}) if hasattr(assets, "get") and isinstance(asset_key, str) else {}
    source = asset.get("source", {}) if isinstance(asset, dict) else {}
    for value in (
        asset.get("media_type"), asset.get("type"), asset.get("role"),
        source.get("media_type") if isinstance(source, dict) else None,
        source.get("type") if isinstance(source, dict) else None,
    ):
        if isinstance(value, str) and (value.strip().lower() == "audio" or value.strip().lower().startswith("audio/")):
            return True
    return False


def projected_speed(clip, track, registry, inherited_speed):
    child_speed = clip.get("speed")
    if child_speed is not None:
        return speed_value(child_speed)
    return 1 if audio_clip(clip, track, registry) else speed_value(inherited_speed)


def parent_clips(parent):
    config = parent.get("config", {})
    clips, configured = parent.get("clips", []), config.get("clips", []) if isinstance(config, dict) else None
    if not isinstance(clips, list) or not isinstance(configured, list):
        raise ValidationError("canonical parent clips must be lists")
    return agreed_clips(clips, configured)


def agreed_clips(clips, configured):
    """Return the canonical clip list; the two authorities must agree when both are present."""
    if clips and configured and clips != configured:
        raise ConflictError("canonical parent clips and config.clips disagree", details={"reason": "canonical_payload_mismatch"})
    return clips or configured


def load_closure(conn, project_id, timeline_id, parent_row):
    """Read exact pinned bytes, including bodies omitted by render callers."""
    def verified(row, kind):
        if row is None:
            raise NotFoundError(f"canonical {kind} dependency is missing")
        if row["project_id"] != project_id:
            raise ConflictError(f"canonical {kind} dependency belongs to a different project")
        payload = json.loads(row["payload_json"])
        digest = "sha256:" + hashlib.sha256(canonical_json(payload).encode()).hexdigest()
        if digest != row["content_digest"]:
            raise ConflictError(f"canonical {kind} revision content integrity failed")
        return payload

    if parent_row["timeline_id"] != timeline_id:
        raise ConflictError("canonical parent has a different timeline identity")
    parent = verified(parent_row, "parent")
    shots, internal = {}, {}
    for o in parent.get("occurrences", []):
        key = (o["shot_id"], o["shot_revision_id"])
        if key in shots:
            continue
        row = conn.execute("SELECT * FROM shot_revisions WHERE id=? AND shot_id=?", (key[1], key[0])).fetchone()
        payload = verified(row, "shot")
        pin = row["internal_timeline_revision_id"]
        if payload.get("internal_timeline_revision_id") != pin:
            raise ConflictError("canonical shot internal pin disagrees with its bytes")
        shots[key] = {"payload": payload, "internal_timeline_revision_id": pin}
        if pin not in internal:
            child = conn.execute("SELECT * FROM internal_timeline_revisions WHERE id=?", (pin,)).fetchone()
            internal[pin] = {"payload": verified(child, "internal timeline")}
    return parent, shots, internal


def _fps(value):
    """Read raw authored FPS locally without changing the stored payload."""
    if isinstance(value, (dict, list)):
        from .timeline_inspection import _fraction

        try:
            result = float(_fraction(value, "fps", nonnegative=False))
        except (OverflowError, ValidationError):
            return None
        return result if math.isfinite(result) else None
    return finite(value, None)


def _strip_derived(value):
    if isinstance(value, dict):
        # Most authored clips have no app/report/intent. Keep their immutable
        # JSON object without allocating an identical recursive copy.
        if not any(k in value for k in ("app", "intents", "report", "visualSeamIntents", "visual_seam_report")):
            return value
        return {k: _strip_derived(v) for k, v in value.items() if k not in ("intents", "report", "visualSeamIntents", "visual_seam_report")}
    if isinstance(value, list):
        return [_strip_derived(v) for v in value]
    return value


def normalize_closure(parent, shots, internal, *, timeline_id, materialize=False):
    """Authored geometry plus effective spans. No mutable heads or clipping loss."""
    config = parent.get("config", {})
    fps = _fps((config.get("output") or {}).get("fps", config.get("fps", 30)))
    if fps is None or fps <= 0:
        raise ValidationError("visual timing fps must be finite and positive")
    policy = (config.get("app") or {}).get("visualSeamContract") or {}
    tracks = {t["id"]: t for t in config.get("tracks", []) if isinstance(t, dict) and "id" in t}
    explicit = policy.get("continuityTracks")
    authored_continuity = isinstance(explicit, list)
    continuity = {t for t in explicit if isinstance(t, str)} if authored_continuity else set()
    # Preserve aggregate picture presence even for older occurrence lanes with
    # no definition. Full-frame continuity still requires a visual definition.
    picture_lanes = continuity if authored_continuity else {o["track"] for o in parent.get("occurrences", [])}
    spans, occurrences, structural = [], [], []
    render_config = copy.deepcopy(config) if materialize else None
    render_registry = copy.deepcopy(parent.get("registry", {})) if materialize else None
    if materialize:
        render_config["clips"] = []
        render_registry.setdefault("assets", {})
    occurrence_groups = defaultdict(list)
    for o in parent.get("occurrences", []):
        occurrence_groups[o["track"]].append(o)
    next_start = {}
    for group in occurrence_groups.values():
        ordered = sorted(group, key=lambda o: seconds(o, "at", finite(o.get("placement", {}).get("start_ms"), 0) / 1000))
        for a, b in pairwise(ordered):
            next_start[a["occurrence_id"]] = seconds(b, "at", finite(b.get("placement", {}).get("start_ms"), 0) / 1000)

    def add(raw, registry, path, *, offset=0, bound=None, inherited_speed=1, inherited_track=None, source_offset=0, inherited_gain=1, muted=False, render=True, track_definitions=None):
        if not isinstance(raw, dict):
            raise ValidationError("canonical clips must be objects")
        if not active(raw):
            return
        clip = dict(raw)
        kind = clip.get("clipType", clip.get("clip_type", "media"))
        if kind in ("shot", "composition", "sequence"):
            raise ValidationError("nested composition is not supported by visual admission")
        clip["clipType"] = kind
        at = seconds(clip, "at")
        if finite(clip.get("at_ms", clip.get("at", 0)), None) is None:
            raise ValidationError("visual timing start must be finite")
        track = clip.get("track", inherited_track or "video")
        definition = (track_definitions if track_definitions is not None else tracks).get(track, {})
        is_audio = audio_clip(clip, definition, registry)
        child_speed = clip.get("speed")
        effective_speed = projected_speed(clip, definition, registry, inherited_speed)
        if child_speed is not None:
            clip["speed"] = effective_speed
        elif not is_audio and effective_speed != 1:
            clip["speed"] = effective_speed
        else:
            clip.pop("speed", None)
        duration = clip_seconds(clip, (bound[1] - offset) * effective_speed if bound else 0, speed=effective_speed)
        # Canonical child clips may carry the schema's asset_id spelling. Resolve
        # that reference before coverage classification so media aliases retain
        # the same full-frame semantics as clips already normalized to asset.
        asset_key = clip.get("asset")
        if not isinstance(asset_key, str) or not asset_key.strip():
            asset_id = clip.get("asset_id")
            if isinstance(asset_id, str) and asset_id.strip():
                asset_key = asset_id
                clip["asset"] = asset_id
        primary = render and (track in picture_lanes or definition.get("kind") == "visual") and picture_clip(clip, definition)
        covered = render and covers_frame(clip, definition, config)
        if not authored_continuity and primary and covered:
            continuity.add(track)
        if at < 0 or offset + at < 0:
            structural.append({"code": "boundary/negative-start", "path": path, "frame": js_round((offset + at) * fps)})
        raw_start = js_round((offset + at) * fps)
        raw_end = raw_start + max(1, js_round(duration * fps))
        start, end = raw_start, raw_end
        if bound:
            lower, upper = js_round(bound[0] * fps), js_round(bound[1] * fps)
            if primary and covered and (raw_start < lower or raw_end > upper):
                structural.append({"code": "boundary/owner-overhang", "path": path, "startFrame": raw_start, "endFrame": raw_end, "ownerEndFrame": upper})
            start, end = max(start, lower), min(end, upper)
        if end <= start:
            return
        clip["at"] = (offset + at)
        clip.pop("at_ms", None)
        if "duration_ms" in clip or "duration" in clip:
            clip["hold"] = duration * effective_speed
            clip.pop("duration_ms", None)
            clip.pop("duration", None)
        applied_source_offset = 0 if is_audio else source_offset
        if "from" in clip or "from_ms" in clip or applied_source_offset:
            clip["from"] = seconds(raw, "from") + applied_source_offset
            clip.pop("from_ms", None)
        if "to" in clip or "to_ms" in clip:
            clip["to"] = seconds(raw, "to") + applied_source_offset
            clip.pop("to_ms", None)
        asset = (registry.get("assets") or {}).get(asset_key, {})
        source = next((asset[k] for k in ("content_sha256", "object_id", "media_id", "digest", "file") if isinstance(asset.get(k), str)), None)
        disclosure = boundary_report({"clip": clip, "params": clip.get("params", {}), "fps": fps, "startFrame": start, "endFrame": end,
                                      "originFrame": raw_start, "path": path, "source": source, "sourceType": asset.get("type", "")})
        spans.append({"path": path, "track": track, "startFrame": start, "endFrame": end, "rawStartFrame": raw_start, "rawEndFrame": raw_end,
                      "primary": primary, "coversFrame": covered, "source": source, "clip": clip, "disclosure": disclosure})
        # Materialization is deliberately outside metadata evaluator timing.
        if not materialize or not render:
            rendered = None
        else:
            rendered = copy.deepcopy(clip)
        if rendered is not None:
            rendered["id"] = path[-1] if len(path) == 4 else path[3] + ":" + path[-1]
            rendered["track"] = track
            rendered["volume"] = 0 if muted else finite(clip.get("volume", clip.get("gain", inherited_gain)), 1)
        if rendered is not None and bound:
            rendered.setdefault("app", {})["canonical"] = {"parentDocumentId": timeline_id, "occurrenceId": path[3], "sourceClipId": path[-1]}
            rendered["app"]["canonicalTiming"] = {
                "occurrenceStartMs": bound[0] * 1000,
                "occurrenceDurationMs": (bound[1] - bound[0]) * 1000,
                "sourceOffsetMs": source_offset * 1000,
                "occurrenceSpeed": inherited_speed,
            }
            visible_seconds = (end - start) / fps
            rendered["at"] = start / fps
            if "hold" in rendered or "to" not in rendered:
                rendered["hold"] = visible_seconds * effective_speed
            else:
                rendered["to"] = rendered.get("from", 0) + visible_seconds * effective_speed
            if is_audio and child_speed is None:
                rendered.pop("speed", None)
            if isinstance(asset_key, str):
                qualified = path[3] + ":" + asset_key
                rendered["asset"] = qualified
                render_registry["assets"][qualified] = copy.deepcopy(asset)
        if rendered is not None:
            render_config["clips"].append(rendered)
        for i, effect in enumerate(raw.get("effects", [])):
            # Nested supported effects participate, but unsupported time semantics
            # remain opaque instead of invoking an interpreter.
            if not isinstance(effect, dict):
                raise ValidationError("clip effects must be objects")
            effect_clip = {**effect, "id": effect.get("id", str(i)), "clipType": effect.get("type", "unknown"), "at": clip["at"], "hold": duration,
                           "params": effect.get("params", effect), "track": track}
            effect_path = path + ["effect", str(effect_clip["id"])]
            d = boundary_report({"clip": effect_clip, "fps": fps, "startFrame": start, "endFrame": end, "originFrame": raw_start, "path": effect_path, "source": source})
            spans.append({"path": effect_path, "track": track, "startFrame": start, "endFrame": end, "rawStartFrame": raw_start, "rawEndFrame": raw_end,
                          "primary": False, "coversFrame": covered, "source": source, "clip": effect_clip, "disclosure": d})

    for raw in parent_clips(parent):
        add(raw, parent.get("registry", {}), ["parent", timeline_id, "clip", str(raw.get("id", "?"))])
    for o in parent.get("occurrences", []):
        shot = shots.get((o["shot_id"], o["shot_revision_id"]))
        if shot is None:
            raise NotFoundError("canonical shot closure is incomplete")
        pin = shot["internal_timeline_revision_id"]
        child = internal.get(pin)
        if child is None:
            raise NotFoundError("canonical internal closure is incomplete")
        body = child["payload"]
        # Resolve aliases from their nearest pinned owner, as inspection does.
        # A child may reference a shot asset or an inherited parent asset;
        # qualifying that reference must not replace its metadata with {}.
        shot_assets = {}
        for asset in shot.get("payload", {}).get("assets", []):
            if isinstance(asset, dict) and isinstance(asset.get("asset_id"), str):
                shot_assets[asset["asset_id"]] = {
                    **asset, "media_id": asset.get("object_id"), "content_sha256": asset.get("digest"),
                    "type": asset.get("media_type"),
                }
        child_registry = {"assets": ChainMap(
            (body.get("registry", {}).get("assets") or {}), shot_assets,
            (parent.get("registry", {}).get("assets") or {}),
        )}
        # Flattening keeps the parent's definition when lane IDs collide.
        child_tracks = {**{t["id"]: t for t in body.get("tracks", []) if isinstance(t, dict) and "id" in t}, **tracks}
        clips = body.get("clips", body.get("local_clips", []))
        if not isinstance(clips, list):
            raise ValidationError("canonical child clips must be a list")
        offset = seconds(o, "at", finite(o.get("placement", {}).get("start_ms"), 0) / 1000)
        fallback_duration = o["duration_ms"] / 1000
        inherited_speed = speed_value(o.get("speed", 1))

        def child_end(c):
            definition = child_tracks.get(c.get("track", o["track"]), {})
            effective_speed = projected_speed(c, definition, child_registry, inherited_speed)
            return seconds(c, "at") + clip_seconds(
                c, fallback_duration * effective_speed, speed=effective_speed,
            )

        extent = max((child_end(c) for c in clips
                      if active(c) and child_tracks.get(c.get("track", o["track"]), {}).get("role") != "source"),
                     default=fallback_duration)
        extent = math.ceil(extent * 1000 - 1e-6) / 1000
        end = min(offset + extent, next_start.get(o["occurrence_id"], offset + extent))
        path = ["parent", timeline_id, "occurrence", o["occurrence_id"]]
        occurrences.append({"path": path, "track": o["track"], "startFrame": js_round(offset * fps), "endFrame": js_round(end * fps),
                            "rawEndFrame": js_round((offset + extent) * fps), "clip": o, "source": o["shot_revision_id"], "primary": False})
        if offset < 0 or end <= offset:
            structural.append({"code": "boundary/invalid-occurrence", "path": path, "frame": js_round(offset * fps)})
        source_offset = o.get("source_offset", o.get("source_offset_ms", 0))
        if isinstance(source_offset, dict):
            source_offset = source_offset.get("start", 0)
        source_offset = finite(source_offset) / 1000
        span_begin = len(spans)
        render_begin = len(render_config["clips"]) if materialize else 0
        if materialize:
            known_tracks = {t.get("id") for t in render_config.get("tracks", []) if isinstance(t, dict)}
            for t in body.get("tracks", []):
                if isinstance(t, dict) and t.get("id") not in known_tracks:
                    render_config.setdefault("tracks", []).append(copy.deepcopy(t))
                    known_tracks.add(t.get("id"))
        for c in clips:
            add(c, child_registry, path + ["clip", str(c.get("id", "?"))], offset=offset, bound=(offset, end), inherited_speed=inherited_speed,
                inherited_track=o["track"], source_offset=source_offset, inherited_gain=o.get("gain", 1), muted=o.get("muted", o.get("mute", False)),
                track_definitions=child_tracks)
        # An overlay-only occurrence cannot create a picture-lane seam either.
        full_frame_pictures = [s for s in spans[span_begin:] if s["primary"] and s["coversFrame"]]
        occurrence_picture = bool(full_frame_pictures)
        if not authored_continuity and occurrence_picture:
            continuity.add(o["track"])
        occurrences[-1]["primary"] = occurrence_picture and o["track"] in continuity
        if occurrence_picture:
            # Overlay tails can extend a rendered occurrence, but cannot extend
            # its base picture into the next cut. Preserve the render bounds.
            first = min(full_frame_pictures, key=lambda s: s["startFrame"])
            last = max(full_frame_pictures, key=lambda s: s["rawEndFrame"])
            occurrences[-1]["pictureSpan"] = {
                "startFrame": first["startFrame"], "endFrame": max(s["endFrame"] for s in full_frame_pictures),
                "rawEndFrame": last["rawEndFrame"], "firstPath": first["path"], "lastPath": last["path"],
            }
        # Occurrence ownership cannot stand in for picture output. Verify the
        # union of its child picture spans, including leading and trailing holes.
        pictures = sorted((s for s in spans[span_begin:] if s["primary"]), key=lambda s: s["startFrame"])
        # Clip start/duration and renderer sequences use nearest frames. Ceil
        # here invented a trailing frame for rounded fractional-second cuts.
        lower, upper = js_round(offset * fps), js_round(end * fps)
        if not pictures:
            structural.append({"code": "boundary/empty-child-picture", "path": path, "startFrame": lower, "endFrame": upper})
        else:
            covered = lower
            for picture in pictures:
                if picture["startFrame"] > covered:
                    pause = pause_covers(policy.get("gaps"), o["track"], covered, picture["startFrame"])
                    if not pause:
                        structural.append({"code": "boundary/child-picture-gap", "path": path,
                                           "startFrame": covered, "endFrame": picture["startFrame"]})
                covered = max(covered, picture["endFrame"])
            if covered < upper and not pause_covers(policy.get("gaps"), o["track"], covered, upper):
                structural.append({"code": "boundary/child-picture-gap", "path": path, "startFrame": covered, "endFrame": upper})
        # Timeline-scoped effects are authored data too. Attach them to the
        # occurrence's rendered children; retain existing clip-local effects.
        if materialize and body.get("effects"):
            for rendered in render_config["clips"][render_begin:]:
                local_effects = rendered.get("effects", [])
                if not isinstance(local_effects, list):
                    raise ValidationError("clip effects must be a list")
                rendered["effects"] = copy.deepcopy(local_effects + body["effects"])
                rendered.setdefault("app", {})["canonicalEffects"] = {
                    "localCount": len(local_effects), "timeline": copy.deepcopy(body["effects"])}
        for i, e in enumerate(body.get("effects", [])):
            add({**e, "id": e.get("id", str(i)), "clipType": e.get("type", "unknown"), "hold": e.get("hold", end - offset), "track": e.get("track", "fx")},
                child_registry, path + ["effect", str(e.get("id", i))], offset=offset, bound=(offset, end), render=False)
    for i, e in enumerate(config.get("effects", [])):
        if isinstance(e, dict):
            add({**e, "id": e.get("id", str(i)), "clipType": e.get("type", "unknown"), "hold": e.get("hold", max((s["endFrame"] / fps for s in spans), default=1)), "track": e.get("track", "fx")},
                parent.get("registry", {}), ["parent", timeline_id, "effect", str(e.get("id", i))], render=False)
    if len(spans) > MAX_METADATA_CLIPS:
        raise ValidationError("visual seam metadata exceeds the bounded clip limit")
    return {"fps": fps, "policy": policy, "continuity": continuity, "spans": spans, "occurrences": occurrences, "structural": structural,
            "render_config": render_config, "render_registry": render_registry}


def cue_identity(cue):
    return "/".join(cue["path"]) + ":" + cue["kind"] + ":" + cue["id"] + ":" + str(cue["frame"])


def _transition(a, b, fps):
    duration = transition_frames(b["clip"].get("transition"), fps)
    # Existing incoming transition owns precisely this incoming pre-roll.
    return duration is not None and 0 < a["endFrame"] - b["startFrame"] <= duration <= min(a["endFrame"] - a["startFrame"], b["endFrame"] - b["startFrame"])


def analyze_normalized(metadata):
    fps, policy, spans = metadata["fps"], metadata["policy"], metadata["spans"]
    issues = list(metadata["structural"])
    candidates = defaultdict(list)
    groups = defaultdict(list)
    for s in spans:
        if s["primary"] and s["coversFrame"] and s["track"] in metadata["continuity"]:
            groups[(s["track"], tuple(s["path"][:4]) if "occurrence" in s["path"] else ("parent",))].append(s)
    for o in metadata["occurrences"]:
        if o["primary"]:
            groups[(o["track"], ("parent",))].append({**o, **o["pictureSpan"]})
    for (track, _), rows in groups.items():
        ordered = sorted(rows, key=lambda s: (s["startFrame"], s["endFrame"]))
        furthest = None
        for b in ordered:
            if furthest is not None:
                a = furthest
                frame = b["startFrame"]
                gap = frame - a.get("rawEndFrame", a["endFrame"])
                valid_transition = _transition(a, b, fps)
                pause = pause_covers(policy.get("gaps"), track, a["endFrame"], frame)
                if gap < 0 and not valid_transition:
                    issues.append({"code": "boundary/overlap", "frame": frame, "track": track,
                                   "paths": [a.get("lastPath", a["path"]), b.get("firstPath", b["path"])], "frames": -gap})
                elif gap > 0 and not pause:
                    issues.append({"code": "boundary/gap", "frame": frame, "track": track,
                                   "paths": [a.get("lastPath", a["path"]), b.get("firstPath", b["path"])], "frames": gap})
                candidates[frame].extend([a, b])
            if furthest is None or b["rawEndFrame"] > furthest["rawEndFrame"]:
                furthest = b
    cues = []
    for s in spans:
        cues.extend(c for c in s["disclosure"]["cues"]
                    if not (s["disclosure"]["opaque"] and not s["coversFrame"] and c["kind"] == "activation"))
    cues.extend(opaque_activation_cues([s for s in spans if s["coversFrame"]], candidates))
    cues.sort(key=lambda c: (c["frame"], cue_identity(c)))
    frames = [c["frame"] for c in cues]
    opaque = sorted((s for s in spans if s["coversFrame"] and s["disclosure"]["opaque"]), key=lambda s: s["startFrame"])
    live_opaque, cursor, boundaries = {}, 0, []
    portable_boundaries = boundary_intent_owners(spans)
    fingerprints = {}
    def fingerprint(s):
        path = tuple(s["path"])
        if path not in fingerprints:
            fingerprints[path] = hashlib.sha256(canonical_json({"path": s["path"], "clip": _strip_derived(s["clip"]), "source": s["source"]}).encode()).hexdigest()
        return fingerprints[path]
    for frame, owners in sorted(candidates.items()):
        lo, hi = bisect.bisect_left(frames, frame - 2), bisect.bisect_right(frames, frame + 2)
        nearby = cues[lo:hi]
        while cursor < len(opaque) and opaque[cursor]["startFrame"] <= frame:
            s = opaque[cursor]
            live_opaque[tuple(s["path"])] = s
            cursor += 1
        live_opaque = {p: s for p, s in live_opaque.items() if s["endFrame"] > frame}
        # Bind only participants and their relevant timing/source metadata.
        # Intent/report bytes and unrelated edits never affect this context.
        relevant = {tuple(s["path"]): s for s in relevant_intent_owners(spans + metadata["occurrences"], owners, nearby)}
        # A cue-free cut cannot acknowledge additional cues. Defer content
        # fingerprinting until there is known behavior to acknowledge.
        context = "sha256:" + hashlib.sha256((DISCLOSURE_VERSION + "|" + str(fps) + "|" + str(frame) + "|"
                  + "|".join(fingerprint(s) for _, s in sorted(relevant.items()))).encode()).hexdigest() if nearby else None
        # Portable witnesses use the actual child clips at the occurrence seam,
        # rather than the transport occurrence record or mutable projection IDs.
        portable_boundary = portable_boundaries.get(frame, [])
        portable_relevant = relevant_intent_owners(spans, portable_boundary, nearby)
        portable_owners = {tuple(s["path"]): s for s in portable_relevant}
        portable_context = intent_context(fps, frame, portable_owners.values())
        intent = (policy.get("intents") or {}).get(str(frame))
        valid = isinstance(intent, dict) and intent.get("frame") == frame and intent.get("context") == context and intent.get("kind") in ("hard-cut", "transition", "synchronized")
        canonical_intent = intent.get("canonical", intent) if isinstance(intent, dict) else None
        if isinstance(intent, dict) and "canonical" in intent:
            valid = False  # Never downgrade a new record to a legacy grant.
        portable_ids = {portable_cue_identity(c) for c in nearby}
        portable_valid = (isinstance(canonical_intent, dict) and canonical_intent.get("contextVersion") == DISCLOSURE_VERSION
                          and canonical_intent.get("frame") == frame and canonical_intent.get("context") == portable_context
                          and canonical_intent.get("kind") in ("hard-cut", "transition", "synchronized")
                          and canonical_intent.get("kind") == intent.get("kind") and canonical_intent.get("frame") == intent.get("frame")
                          and isinstance(canonical_intent.get("participants"), list)
                          and all(isinstance(p, str) and p in portable_ids for p in canonical_intent["participants"]))
        acknowledged = set(intent.get("participants", [])) if valid and intent["kind"] == "synchronized" and isinstance(intent.get("participants"), list) else set()
        portable_ack = set(canonical_intent["participants"]) if portable_valid and canonical_intent["kind"] == "synchronized" else set()
        risky = [c for c in nearby if c["kind"] in ("activation", "motion-start", "phase-change", "source-reset", "source-change", "rate-change")]
        uncovered = [c for c in risky if cue_identity(c) not in acknowledged and portable_cue_identity(c) not in portable_ack]
        boundaries.append({"frame": frame, "context": context, "ownerPaths": [list(p) for p in sorted({tuple(s["path"]) for s in owners})],
                           "cues": nearby, "opaquePaths": [list(p) for p in sorted(live_opaque)], "requiresIntent": bool(uncovered),
                           "canonicalContext": portable_context, "canonicalCueIds": sorted(portable_ids),
                           "unacknowledgedCues": [cue_identity(c) for c in uncovered]})
    return {"version": VERSION, "disclosureVersion": DISCLOSURE_VERSION, "fps": fps, "guardFrames": 2,
            "spans": [{k: v for k, v in s.items() if k not in ("clip", "disclosure")} for s in spans], "cues": cues,
            "boundaries": boundaries, "opaqueElements": [s["disclosure"] for s in opaque], "structuralIssues": issues,
            "warningCount": sum(bool(b["requiresIntent"] or b["opaquePaths"]) for b in boundaries),
            "blocked": bool(issues or any(b["requiresIntent"] for b in boundaries))}


def evaluate_closure(parent, shots, internal, *, timeline_id, materialize=False):
    metadata = normalize_closure(parent, shots, internal, timeline_id=timeline_id, materialize=materialize)
    return analyze_normalized(metadata), metadata


def admit_closure(parent, shots, internal, *, timeline_id, materialize=False):
    """Return advisory seam diagnostics and the optional render projection.

    As with authoring saves, report findings do not prevent rendering. Closure
    integrity and timing errors still raise during normalization.
    """
    return evaluate_closure(parent, shots, internal, timeline_id=timeline_id, materialize=materialize)
