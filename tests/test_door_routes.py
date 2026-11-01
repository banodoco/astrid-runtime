"""Route conformance for the browser door (runtime_protocol/door.py).

Ported from the App's paired route policy tests (app-door:
src/integrations/paired/pairedRoutePolicy.test.ts, the first test of
scripts/astrid-loopback-gateway.test.ts, and
src/integrations/paired/objectCachePolicy.test.ts). The door's route table is a
port of config/vite/pairedRoutePolicy.ts, so the same rows must hold here.
"""

from __future__ import annotations

import pytest

from runtime_protocol.door import classify, object_cache_control

P = "proj-1"
T = "tl-1"
R = "rev-1"
DIGEST = "a" * 64


def runtime(path: str) -> str:
    return f"/api/runtime{path}"


def astrid(path: str) -> str:
    return f"/api/astrid{path}"


# Every call the App's product code sends through the relay: (method, path, service).
PRODUCT_CALLS = [
    # RuntimeClient
    ("GET", runtime("/v1/health"), "runtime"),
    ("POST", runtime("/v1/handshake"), "runtime"),
    ("GET", runtime("/v1/realm"), "runtime"),
    ("GET", runtime("/v1/app-state/user/editor-tour"), "runtime"),
    ("PUT", runtime("/v1/app-state/user/editor-tour"), "runtime"),
    ("GET", runtime("/v1/projects?limit=50&cursor=c1"), "runtime"),
    ("POST", runtime("/v1/projects"), "runtime"),
    ("PUT", runtime("/v1/projects/selection"), "runtime"),
    ("GET", runtime(f"/v1/projects/{P}"), "runtime"),
    ("PATCH", runtime(f"/v1/projects/{P}"), "runtime"),
    ("GET", runtime(f"/v1/projects/{P}/timelines?limit=50"), "runtime"),
    ("POST", runtime(f"/v1/projects/{P}/timelines"), "runtime"),  # createTimeline
    ("POST", runtime(f"/v1/projects/{P}/timelines/import"), "runtime"),
    ("GET", runtime(f"/v1/projects/{P}/timelines/{T}"), "runtime"),
    ("PATCH", runtime(f"/v1/projects/{P}/timelines/{T}"), "runtime"),  # renameTimeline
    ("GET", runtime(f"/v1/projects/{P}/timelines/{T}/revisions/{R}"), "runtime"),
    ("POST", runtime(f"/v1/projects/{P}/timelines/{T}/composition-revisions"), "runtime"),
    ("GET", runtime(f"/v1/projects/{P}/timelines/{T}/composition-revisions?limit=50"), "runtime"),
    ("GET", runtime(f"/v1/projects/{P}/timelines/{T}/composition-revisions/{R}"), "runtime"),
    ("POST", runtime(f"/v1/projects/{P}/timelines/{T}/composition-revisions/{R}/restore"), "runtime"),
    ("POST", runtime(f"/v1/projects/{P}/timelines/{T}/inspect"), "runtime"),
    ("GET", runtime(f"/v1/projects/{P}/shots/shot-1/revisions/{R}"), "runtime"),
    # Transcript documents
    ("GET", runtime(f"/v1/projects/{P}/documents?limit=50&kind=transcript"), "runtime"),
    ("POST", runtime(f"/v1/projects/{P}/documents"), "runtime"),
    ("GET", runtime(f"/v1/projects/{P}/documents/transcript:{DIGEST}"), "runtime"),
    ("PATCH", runtime(f"/v1/projects/{P}/documents/transcript:{DIGEST}"), "runtime"),
    ("GET", runtime(f"/v1/projects/{P}/thumbnails/source-frame?media_id=m1&time=1"), "runtime"),
    ("POST", runtime(f"/v1/projects/{P}/thumbnails/source-frame"), "runtime"),
    ("GET", runtime(f"/v1/projects/{P}/objects?limit=50&cursor=c1"), "runtime"),
    ("POST", runtime(f"/v1/projects/{P}/objects"), "runtime"),
    ("GET", runtime(f"/v1/projects/{P}/objects/obj-1/location"), "runtime"),
    ("POST", runtime(f"/v1/projects/{P}/media-imports"), "runtime"),
    ("GET", runtime(f"/v1/projects/{P}/media-imports/op-1"), "runtime"),
    ("GET", runtime("/v1/objects/obj-1"), "runtime"),
    ("HEAD", runtime("/v1/objects/obj-1"), "runtime"),
    ("POST", runtime("/v1/tasks"), "runtime"),
    ("GET", runtime("/v1/tasks/task-1"), "runtime"),
    ("POST", runtime("/v1/tasks/task-1/cancel"), "runtime"),
    ("POST", runtime("/v1/tasks/task-1/retry"), "runtime"),
    ("GET", runtime(f"/v1/projects/{P}/tasks?limit=50"), "runtime"),
    ("GET", runtime("/v1/tasks/task-1/managed-outputs?limit=50"), "runtime"),
    ("GET", runtime("/v1/managed-outputs/assoc-1"), "runtime"),
    ("POST", runtime("/v1/managed-outputs/assoc-1/export"), "runtime"),
    ("GET", runtime("/v1/events?limit=50&aggregate_id=a1"), "runtime"),
    ("GET", runtime(f"/v1/projects/{P}/generations?limit=50"), "runtime"),
    ("GET", runtime("/v1/generations/gen-1"), "runtime"),
    ("GET", runtime("/v1/generations/gen-1/variants?limit=50"), "runtime"),
    ("POST", runtime("/v1/variants/var-1/viewed"), "runtime"),
    ("POST", runtime("/v1/generations/gen-1/variants/viewed"), "runtime"),
    # AstridLocalClient
    ("GET", astrid("/v1/capabilities?limit=50"), "astrid"),
    ("POST", astrid("/v1/tasks"), "astrid"),
    ("GET", astrid("/v1/tasks/task-1"), "astrid"),
    ("POST", astrid("/v1/tasks/task-1/cancel"), "astrid"),
    ("GET", astrid("/v1/events?limit=50"), "astrid"),
    ("GET", astrid(f"/v1/projects/{P}/tasks?limit=1"), "astrid"),
    ("GET", astrid(f"/v1/projects/{P}/generations?limit=1"), "astrid"),
    ("GET", astrid("/v1/generations/gen-1/variants?limit=50"), "astrid"),
    ("POST", astrid(f"/v1/projects/{P}/objects"), "astrid"),
    ("GET", astrid("/v1/projects"), "astrid"),
    ("PATCH", astrid(f"/v1/projects/{P}"), "astrid"),
    # ACP agent chat
    ("POST", astrid("/acp/connect"), "acp"),
    ("GET", astrid("/acp/models"), "acp"),
    ("GET", astrid("/acp/conn-1/models?sessionId=codex%3Aabc-123"), "acp"),
    ("POST", astrid("/acp/conn-1/rpc"), "acp"),
    ("GET", astrid("/acp/conn-1/events"), "acp"),
    ("POST", astrid("/acp/conn-1/cancel"), "acp"),
    ("POST", astrid("/acp/conn-1/reconnect"), "acp"),
    ("GET", astrid(f"/acp/projects/{P}/chat"), "acp"),
    ("PATCH", astrid(f"/acp/projects/{P}/chat"), "acp"),
    ("GET", astrid("/acp/health"), "acp"),
    ("DELETE", astrid("/acp/conn-1"), "acp"),
    ("POST", astrid(f"/acp/projects/{P}/chat/sessions"), "acp"),
    ("GET", astrid(f"/acp/projects/{P}/chat/unassigned?connection_id=conn-1"), "acp"),
    ("POST", astrid(f"/acp/projects/{P}/chat/associate"), "acp"),
    ("PATCH", astrid(f"/acp/projects/{P}/chat/draft"), "acp"),
    ("PATCH", astrid(f"/acp/projects/{P}/chat/main"), "acp"),
    ("POST", astrid(f"/acp/projects/{P}/chat/prompt"), "acp"),
]

FORBIDDEN = [
    ("GET", runtime("/v1/projects/selection")),
    ("PATCH", runtime("/v1/projects/selection")),
    ("POST", astrid("/acp/model")),
    ("POST", astrid("/acp/conn-1/model")),
    ("DELETE", astrid("/acp/models")),
    ("POST", astrid("/acp/models")),
    ("GET", astrid("/acp/model")),
    ("DELETE", astrid("/acp/model")),
    ("POST", astrid("/acp/conn-1/models")),
    ("GET", astrid("/acp/conn-1/model")),
    ("DELETE", astrid("/acp/conn-1/model")),
    ("GET", astrid("/acp/conn-1/models/extra?sessionId=s1")),
    ("GET", astrid("/acp/health/models?sessionId=s1")),
    ("GET", runtime("/v1/doctor")),
    ("POST", runtime("/v1/backup")),
    ("POST", runtime("/v1/restore")),
    ("GET", runtime("/v1/export")),
    ("POST", runtime("/v1/realm/tombstone")),
    ("POST", runtime("/v1/realm/recover")),
    ("POST", runtime("/v1/realm/purge")),
    ("POST", runtime("/v1/realm/replace")),
    ("POST", runtime("/v1/tasks/claim")),
    ("GET", runtime("/v1/tasks/claim")),
    ("POST", runtime("/v1/attempts/att-1/settle")),
    ("POST", runtime("/v1/recovery/checkpoint")),
    ("POST", runtime("/v1/executors")),
    ("GET", runtime("/v1/executors/ex-1")),
    ("POST", runtime("/v1/capabilities")),
    ("GET", runtime("/v1/capabilities")),
    ("POST", astrid("/v1/capabilities")),
    ("PUT", astrid("/v1/capabilities/cap-1")),
    ("POST", astrid("/v1/tasks/claim")),
    ("GET", astrid("/v1/doctor")),
    ("POST", astrid("/v1/realm/purge")),
    ("POST", astrid("/v1/attempts/att-1/settle")),
    ("POST", astrid("/v1/executors")),
    ("POST", runtime("/v1/tasks/task-1/remote-credential")),
    ("POST", runtime("/v1/tasks/task-1/placement-recovery")),
    ("POST", runtime(f"/v1/projects/{P}/timelines/{T}/replace-parent-media")),
    ("POST", runtime(f"/v1/projects/{P}/timelines/{T}/composition-revisions/{R}/restore/extra")),
    ("POST", runtime(f"/v1/projects/{P}/timelines/{T}/composition-revisions/{R}/purge")),
    ("POST", runtime(f"/v1/projects/{P}/timelines/{T}/doctor")),
    ("POST", runtime(f"/v1/projects/{P}/timelines/{T}/composition-revisions/")),
    ("GET", runtime(f"/v1/projects/{P}/timelines/{T}/composition-revisions/{R}/../../../doctor")),
    ("GET", runtime(f"/v1/projects/{P}/timelines/{T}/composition-revisions/%2e%2e/doctor")),
    ("GET", runtime(f"/v1/projects/{P}/timelines/{T}/composition-revisions//x")),
    ("GET", runtime(f"/v1/projects/{P}/timelines/{T}/inspect/../../../../doctor")),
    ("GET", runtime(f"/v1/projects/{P}/thumbnails/other")),
    ("GET", runtime(f"/v1/projects/{P}/objects/obj-1/location/extra")),
    ("GET", runtime("/v1/unknown")),
    # Transcript documents are never deleted through the product surface.
    ("DELETE", runtime(f"/v1/projects/{P}/documents/transcript:{DIGEST}")),
    ("DELETE", astrid(f"/v1/projects/{P}/documents/transcript:{DIGEST}")),
    ("POST", runtime(f"/v1/projects/{P}/documents/transcript:{DIGEST}")),
    ("DELETE", runtime(f"/v1/projects/{P}/documents")),
    ("GET", runtime(f"/v1/projects/{P}/documents/transcript:{DIGEST}/versions")),
    ("GET", astrid(f"/acp/projects/{P}/chat/unknown")),
    ("GET", astrid(f"/acp/projects/{P}/chat/../../x")),
    ("TRACE", runtime("/v1/health")),
]

PRIVILEGED = [
    "/v1/tasks/task-1/remote-credential",
    "/v1/tasks/task-1/remote-activation",
    "/v1/tasks/task-1/remote-activation/revoke",
    "/v1/tasks/task-1/placement-recovery",
    "/v1/tasks/task-1/events/extra",
    f"/v1/projects/{P}/timelines/{T}/replace-parent-media",
    f"/v1/projects/{P}/timelines/{T}/views",
    f"/v1/projects/{P}/timelines/{T}/archive",
    "/v1/delegated-tasks",
    "/v1/replace",
    "/v1/credentials",
    "/v1/preferences/x",
    "/v1/tasks/claim",
    "/v1/doctor",
    "/v1/export",
    "/v1/backup",
    "/v1/restore",
    "/v1/realm/purge",
    "/v1/realm/tombstone",
    "/v1/realm/recover",
    "/v1/attempts/att-1/settle",
    "/v1/recovery/reboot",
    "/v1/executors",
    "/v1/executors/ex-1",
    "/v1/managed-outputs/assoc-1/adopt",
    "/v1/managed-outputs/assoc-1/lifecycle",
    "/v1/objects",
    "/v1/runs/run-1/cancel",
]

MALFORMED = [
    "/v1/tasks/%63laim",
    "/v1/tasks/cl%61im",
    "/v1/%64octor",
    "/v1/realm/%70urge",
    "/v1/%65xecutors",
    "/v1/tasks/task-1/%72emote-credential",
    "/v1/tasks/cl\taim",
    "/v1/health\t",
    "/v1/tasks/cl\naim",
    "/v1/tasks/cl\raim",
    "/v1/tasks/cl\u0000aim",
    "/v1/tasks/cl\u007faim",
    "/v1/tasks/cl aim",
    "/v1/tasks/cl%09aim",
    "/v1/tasks/task-1%0a",
    "/v1/tasks/task-1%00",
    "/v1/tasks/täsk",
    "/v1/tasks/%2563laim",
    "/v1/tasks/task%251",
    "/v1/tasks/task-1%2fcancel",
    "/v1/tasks/task-1%2Fcancel",
    "/v1/tasks/task-1%5ccancel",
    "/v1/tasks/%2e%2e/doctor",
    "/v1/tasks/%2e/task-1",
    "/v1/tasks/./task-1",
    "/v1/tasks/task-1/../claim",
    "/v1/tasks//task-1",
    "/v1/tasks/task-1/",
    "/v1/tasks/task-1/cancel/extra",
    "/v1/tasks/task-1#/claim",
    "/v1/tasks/task-1%23",
    "/v1/tasks/task-1%3Fx",
    "/v1/tasks/task-1%",
    "/v1/tasks/task-1%4",
    "/v1/tasks/task-1%zz",
    "/v1/tasks/%c0%af",
    "/v1/tasks/task-1\\cancel",
    "/v1/tasks/http://127.0.0.1:1/x",
    "/v1/tasks/" + "a" * 300,
    "/v1/tasks/.hidden",
    f"/v1/projects/{P}/timelines/{T}/" + "a" * 5000,
    "/v1/events?limit=1\tx",
    "/v1/events?limit=1#x",
    "/v1/events?x=\\y",
]


# 1. Every allowed row classifies to its service.
@pytest.mark.parametrize(("method", "path", "service"), PRODUCT_CALLS)
def test_allowed_product_call(method: str, path: str, service: str) -> None:
    route = classify(path, method)
    assert route is not None
    assert route.service == service
    bare = path.split("/api/runtime", 1)[-1] if path.startswith("/api/runtime") else path.split("/api/astrid", 1)[-1]
    assert route.path == bare


# 2. Every forbidden row is refused.
@pytest.mark.parametrize(("method", "path"), FORBIDDEN)
def test_forbidden_row_refused(method: str, path: str) -> None:
    assert classify(path, method) is None


@pytest.mark.parametrize("path", [f"{prefix}{p}{q}" for prefix in ("/api/runtime", "/api/astrid")
                                  for p in PRIVILEGED for q in ("", "?limit=1", "?x=%2e%2e")])
@pytest.mark.parametrize("method", ["GET", "POST", "PUT", "PATCH", "DELETE"])
def test_privileged_refused(method: str, path: str) -> None:
    assert classify(path, method) is None


@pytest.mark.parametrize("prefix", ["/api/runtime", "/api/astrid"])
@pytest.mark.parametrize("path", MALFORMED)
@pytest.mark.parametrize("method", ["GET", "POST", "PATCH"])
def test_malformed_path_refused(prefix: str, path: str, method: str) -> None:
    assert classify(prefix + path, method) is None


# 3. Compose and anything outside /api/runtime and /api/astrid is not served.
@pytest.mark.parametrize("path", [
    "/api/astrid/generation/compose",
    "/session/abc/api/runtime/v1/health",
    "/v1/health",
    "/api/other/v1/health",
    "/",
])
def test_compose_and_foreign_prefixes_not_served(path: str) -> None:
    assert classify(path, "POST") is None
    assert classify(path, "GET") is None


# 4. The gateway's first test, translated.
def test_closed_table_allows_inspect_and_composition_revision_get() -> None:
    assert classify(runtime(f"/v1/projects/{P}/timelines/{T}/inspect"), "POST") is not None
    assert classify(runtime(f"/v1/projects/{P}/timelines/{T}/composition-revisions/{R}"), "GET") is not None


def test_project_object_catalog_is_get_only() -> None:
    path = runtime(f"/v1/projects/{P}/objects?limit=50")
    assert classify(path, "GET") is not None
    assert classify(runtime(f"/v1/projects/{P}/objects"), "POST") is not None
    for method in ("PUT", "PATCH", "DELETE", "HEAD"):
        assert classify(path, method) is None


@pytest.mark.parametrize("path", [
    "/api/runtime/v1/doctor",
    "/api/runtime/v1/backup",
    "/api/runtime/v1/tasks/claim",
    "/api/runtime/v1/objects/../secret",
    "/api/runtime/v1/objects/a%2fb",
    "/api/runtime/v1/objects/a%252fb",
    "//remote.test/x",
])
def test_closed_table_refuses_traversal_admin_and_remote_for_post(path: str) -> None:
    assert classify(path, "POST") is None


def test_inspect_is_post_only() -> None:
    assert classify(runtime(f"/v1/projects/{P}/timelines/{T}/inspect"), "DELETE") is None


def test_rename_timeline_is_patch_on_the_timeline_only() -> None:
    timeline = runtime(f"/v1/projects/{P}/timelines/{T}")
    assert classify(timeline, "PATCH") is not None
    assert classify(timeline, "DELETE") is None
    assert classify(timeline, "PUT") is None
    assert classify(runtime(f"/v1/projects/{P}/timelines/{T}/inspect"), "PATCH") is None
    assert classify(runtime(f"/v1/projects/{P}/timelines"), "PATCH") is None


# 5. Canonicalisation: decoded once, raw query kept verbatim.
def test_digest_id_percent_encoded_is_decoded_once() -> None:
    route = classify(f"/api/runtime/v1/objects/sha256%3A{DIGEST}", "GET")
    assert route is not None
    assert route.path == "/v1/objects/sha256:" + DIGEST


def test_raw_query_is_kept_verbatim() -> None:
    route = classify("/api/runtime/v1/projects?limit=50&cursor=c%2F1", "GET")
    assert route is not None
    assert route.path == "/v1/projects?limit=50&cursor=c%2F1"


@pytest.mark.parametrize("path", [
    "/api/runtime/v1/projects/p\ttab/x",
    "/api/runtime/v1/projects/p space",
    "/api/runtime/v1/projects/pä",
    "/api/runtime/v1/projects/p#frag",
    "/api/runtime/v1/projects/p\\x",
    "/api/runtime/v1/projects/%2e%2e",
    "/api/runtime/v1/projects//x",
    "/api/runtime/v1/projects/%zz",
    "/api/runtime/v1/projects/" + "a" * 4100,
])
def test_non_canonical_paths_refused(path: str) -> None:
    assert classify(path, "GET") is None


# 6. ACP connection ids.
def test_acp_connection_route_allowed() -> None:
    route = classify("/api/astrid/acp/conn-1/rpc", "POST")
    assert route is not None
    assert route.service == "acp"


@pytest.mark.parametrize(("method", "path"), [
    ("GET", "/api/astrid/acp/health/models"),
    ("POST", "/api/astrid/acp/projects/rpc"),
    ("POST", "/api/astrid/acp/connect/rpc"),
    ("GET", "/api/astrid/acp/models/models"),
])
def test_acp_reserved_words_are_not_connection_ids(method: str, path: str) -> None:
    assert classify(path, method) is None


def test_runtime_prefix_never_reaches_acp() -> None:
    assert classify("/api/runtime/acp/connect", "POST") is None


# 7. Capability catalog is astrid-only.
def test_capabilities_only_on_astrid_alias() -> None:
    route = classify("/api/astrid/v1/capabilities", "GET")
    assert route is not None
    assert route.service == "astrid"
    assert classify("/api/runtime/v1/capabilities", "GET") is None


# 8. Object cache policy.
@pytest.mark.parametrize("method", ["GET", "HEAD"])
@pytest.mark.parametrize("status", [200, 206, 304])
def test_digest_object_is_immutable_on_success(method: str, status: int) -> None:
    route = classify(f"/api/runtime/v1/objects/sha256:{DIGEST}", method)
    assert object_cache_control(method, route, status) == "private, max-age=31536000, immutable"


@pytest.mark.parametrize(("method", "path", "status"), [
    ("GET", f"/api/runtime/v1/objects/sha256:{DIGEST}", 404),
    ("GET", f"/api/runtime/v1/objects/sha256:{DIGEST}", 500),
    ("GET", "/api/runtime/v1/objects/card", 200),
    ("GET", "/api/runtime/v1/projects", 200),
    ("GET", "/api/astrid/acp/conn-1/events", 200),
])
def test_everything_else_is_no_store(method: str, path: str, status: int) -> None:
    assert object_cache_control(method, classify(path, method), status) == "no-store"


def test_route_none_is_no_store() -> None:
    assert object_cache_control("GET", None, 200) == "no-store"
