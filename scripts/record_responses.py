"""Record Runtime responses from a real daemon into conformance/responses/ (testing plan C2.1, R-4).

    PYTHONPATH=.:/path/to/astrid python scripts/record_responses.py [OUT_DIR]

The real Astrid authoring provider must be importable. OUT_DIR defaults to
conformance/responses; obsolete fixture removal requires a reviewed diff.

Consumers (the App's zod parsers and conflict classifier, Astrid's fake) are trusted
only for responses they reproduce from these files. Each file is
{"case", "request": {"method", "path", "body"}, "status", "headers": {"content-type"}, "body"},
with volatile values replaced by the placeholders listed in `Normalizer`, so recording
twice is byte-identical. tests/test_recorded_responses.py fails when they drift.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from astrid_runtime.loopback_http import urlopen_loopback  # noqa: E402
from runtime_protocol.daemon import RuntimeDaemon  # noqa: E402
from runtime_protocol.store import RealmStore  # noqa: E402

DEFAULT_OUT = ROOT / "conformance" / "responses"
CAPABILITY = "render.recorded"
CAPABILITY_DIGEST = "sha256:" + hashlib.sha256(CAPABILITY.encode()).hexdigest()
KEYED = {"request_id": "<request_id>", "realm_id": "<realm_id>"}
PATTERNS = [  # applied in order, after the ids learned from the journey
    (re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:\+00:00|Z)"), "<timestamp>"),
    (re.compile(r"sha256:[0-9a-f]{64}"), "<digest>"),
    (re.compile(r"txn-[0-9a-f]{32}"), "<receipt_id>"),
    (re.compile(r"\b[0-9a-f]{64}\b"), "<hash>"),
    (re.compile(r"\b[0-9a-f]{32}\b"), "<id>"),
]


class Normalizer:
    """Replace every volatile value with a stable placeholder.

    * ids and the pagination cursor that the journey learned (`learn`) -> "<task_id>", "<cursor>", ...
    * `request_id` / `realm_id` values -> "<request_id>" / "<realm_id>"
    * ISO timestamps -> "<timestamp>"; "sha256:<64 hex>" -> "<digest>"; "txn-<32 hex>" -> "<receipt_id>"
    * any other 64-hex string -> "<hash>"; any other 32-hex string -> "<id>"
    """

    def __init__(self) -> None:
        self.known: dict[str, str] = {}

    def learn(self, value: str, name: str) -> str:
        self.known[value] = f"<{name}>"
        return value

    def text(self, value: str) -> str:
        for known in sorted(self.known, key=len, reverse=True):
            value = value.replace(known, self.known[known])
        for pattern, placeholder in PATTERNS:
            value = pattern.sub(placeholder, value)
        return value

    def __call__(self, value):
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self(item) for item in value]
        if isinstance(value, dict):
            return {key: KEYED[key] if key in KEYED and isinstance(item, str) else self(item) for key, item in value.items()}
        return value


class Recorder:
    def __init__(self, endpoint: str, token: str) -> None:
        self.endpoint, self.token = endpoint, token
        self.normalizer = Normalizer()
        self.cases: list[dict] = []  # normalized, as written
        self.raw: dict[str, dict] = {}  # case -> {"status", "body"} before normalization
        self.pending: tuple | None = None

    def call(self, method: str, path: str, body=None, *, key: str | None = None, case: str | None = None):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(self.endpoint + path, data=data, method=method)
        request.add_header("Authorization", f"Bearer {self.token}")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        if key:
            request.add_header("Idempotency-Key", key)
        try:
            with urlopen_loopback(request, timeout=10) as response:
                status, content_type, payload = response.status, response.headers.get("Content-Type"), response.read()
        except urllib.error.HTTPError as error:
            status, content_type, payload = error.code, error.headers.get("Content-Type"), error.read()
        value = json.loads(payload)
        if case:
            self.raw[case] = {"status": status, "body": value}
            self.pending = (case, method, path, body, status, content_type, value)
        return status, value

    def keep(self) -> None:
        """Write down the call just made, once any ids it taught the normalizer are known."""
        case, method, path, body, status, content_type, value = self.pending
        norm = self.normalizer
        self.cases.append({
            "case": case,
            "request": {"method": method, "path": norm(path), "body": norm(body)},
            "status": status,
            "headers": {"content-type": content_type},
            "body": norm(value),
        })


def drive(recorder: Recorder) -> None:
    """Exactly what a client does; the order is part of the contract (event ids are positional)."""
    call, norm = recorder.call, recorder.normalizer
    _, project = call("POST", "/v1/projects", {"slug": "recorded", "name": "Recorded", "metadata": {}}, key="project")
    project_id = norm.learn(project["data"]["project_id"], "project_id")
    call("POST", f"/v1/projects/{project_id}/timelines", {"timeline_id": "main"}, key="timeline")

    # (a) the compatibility publication route is unconditionally retired.
    publish = f"/v1/projects/{project_id}/timelines/main/composition-revisions"
    status, retired = call("POST", publish, {}, key="publish", case="retired_route_410")
    assert status == 410 and retired["code"] == "retired_route"
    recorder.keep()

    call("POST", "/v1/capabilities", {"capability_id": CAPABILITY, "definition_digest": CAPABILITY_DIGEST, "status": "ready", "required_resource_keys": [], "estimated_scratch_bytes": 0, "estimated_output_bytes": 0}, key="capability")
    descriptor = {"capability_id": CAPABILITY, "definition_digest": CAPABILITY_DIGEST, "status": "ready", "required_resource_keys": [], "estimated_scratch_bytes": 0, "estimated_output_bytes": 1}
    call("POST", "/v1/executors", {"executor_id": "recorder", "capabilities": [descriptor], "max_concurrency": 1, "resource_keys": [], "protocol": "workspace.v1"}, key="executor")

    # (b) task admission, (c) task read.
    admit = {"capability_id": CAPABILITY, "capability_digest": CAPABILITY_DIGEST, "input_object_ids": [], "spec": {"prompt": "recorded"}, "project": project_id}
    _, admitted = call("POST", "/v1/tasks", admit, key="task", case="task_admission_201")
    task_id = norm.learn(admitted["data"]["task_id"], "task_id")
    norm.learn(admitted["data"]["run_id"], "run_id")
    recorder.keep()
    call("GET", f"/v1/tasks/{task_id}", case="task_read_200")
    recorder.keep()

    # A worker claims and settles the task with one output, so it has events and a managed output.
    _, health = call("GET", "/v1/health")
    _, attempt = call("POST", "/v1/tasks/claim", {"executor_id": "recorder", "capability_ids": [CAPABILITY], "runtime_epoch": health["runtime_epoch"]}, key="claim")
    norm.learn(attempt["attempt_id"], "attempt_id")
    payload = b"recorded-output"
    output = {"name": "video", "kind": "object", "digest": "sha256:" + hashlib.sha256(payload).hexdigest(), "media_type": "video/mp4", "size": len(payload), "data_base64": base64.b64encode(payload).decode("ascii")}
    call("POST", f"/v1/attempts/{attempt['attempt_id']}/settle", {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": attempt["runtime_epoch"], "outputs": [output]}, key="settle")

    # (d) managed outputs of that task.
    _, outputs = call("GET", f"/v1/tasks/{task_id}/managed-outputs", case="managed_outputs_200")
    norm.learn(outputs["items"][0]["association_id"], "association_id")
    recorder.keep()

    # (e) an events page that crosses a page boundary: three events, two per page.
    _, first = call("GET", "/v1/events?limit=2", case="events_page_1_200")
    cursor = norm.learn(first["next_cursor"], "cursor")
    recorder.keep()
    _, second = call("GET", f"/v1/events?limit=2&cursor={cursor}", case="events_page_2_200")
    assert second["next_cursor"] is None
    recorder.keep()

    # (f) 404, (g) validation errors.
    call("GET", "/v1/tasks/task-does-not-exist", case="not_found_404")
    recorder.keep()
    call("POST", "/v1/tasks", {"capability_id": "", "capability_digest": CAPABILITY_DIGEST, "input_object_ids": []}, key="invalid-task", case="validation_error_422")
    recorder.keep()
    call("GET", "/v1/events?cursor=not-a-cursor", case="invalid_cursor_400")
    recorder.keep()

    # A real canonical edit advances the head; restoring from the earlier pair conflicts.
    _, timeline = call("GET", f"/v1/projects/{project_id}/timelines/main")
    revision = norm.learn(timeline["head_revision_id"], "base_revision_id")
    publication = norm.learn(timeline["head_publication_id"], "base_publication_id")
    _, source = call("GET", f"{publish}/{revision}")
    commit = f"/v1/projects/{project_id}/timelines/main/commit"
    request = {
        "api_version": 1, "project_id": project_id, "timeline_id": "main",
        "base_revision_id": revision, "base_publication_id": publication,
        "commands": [{"schema_version": 1, "op": "doc.patch", "version": "1", "select": None,
                      "args": {"changes": [{"op": "set", "ref": "parent", "path": ["config", "title"],
                                            "before": {"state": "absent"}, "value": "Recorded"}]}}],
        "label": "Recorded title", "merge": "fields",
    }
    status, accepted = call("POST", commit, request, key="commit-title")
    assert status == 200, accepted
    norm.learn(accepted["data"]["accepted_revision_id"], "current_revision_id")
    norm.learn(accepted["receipt"]["receipt_id"], "current_publication_id")
    request["commands"] = [{"schema_version": 1, "op": "timeline.restore", "version": "1", "select": None,
                            "args": {"revision_id": revision, "content_digest": source["content_digest"]}}]
    status, conflict = call("POST", commit, request, key="stale-restore", case="commit_conflict_409")
    assert status == 409 and conflict["code"] == "conflict"
    assert conflict["details"]["reason"] == "stale_head"
    recorder.keep()


def record(out_dir: Path = DEFAULT_OUT) -> dict[str, dict]:
    """Run the journey against a fresh daemon and write one file per case.

    Returns {case: {"status", "body"}} with the bodies exactly as the daemon sent them,
    for callers that must validate un-normalized values.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="record-responses-") as tmp:
        RealmStore.initialize(Path(tmp) / "realm").close()
        daemon = RuntimeDaemon(Path(tmp) / "realm", support_root=Path(tmp) / "support", authoring_profile="astrid").start()
        try:
            recorder = Recorder(daemon.endpoint, daemon.token)
            drive(recorder)
        finally:
            daemon.stop()
    for entry in recorder.cases:
        (out_dir / f"{entry['case']}.json").write_text(json.dumps(entry, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return recorder.raw


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUT
    cases = record(target)
    print(f"recorded {len(cases)} cases into {target}: " + ", ".join(f"{case} ({value['status']})" for case, value in cases.items()))
