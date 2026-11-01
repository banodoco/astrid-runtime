#!/usr/bin/env python3
"""Render checked-in contract metadata and the Python client from canonical inputs.

The release/conformance client generators consume the same component manifest;
this small repository-local command keeps the package artifacts bound to that
manifest as well.  The Python client is rendered from the tracked template;
``--check`` remains a read-only stale-artifact check.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "contract" / "manifest.json"
COMPONENT_MANIFEST = ROOT / "contract" / "component-manifest.json"
PYTHON_CLIENT_TEMPLATE = ROOT / "generators" / "python_client_template.py"
PYTHON_CLIENT_OUTPUT = ROOT / "packages" / "python" / "astrid_runtime_client" / "generated.py"
TYPESCRIPT_CLIENT_OUTPUT = ROOT / "packages" / "typescript" / "src" / "generated.ts"
RELEASE_METADATA = ROOT / "generators" / "release.json"


def _regular(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"{label} must be a regular file")
    return path.read_bytes()


def _component(path: Path = COMPONENT_MANIFEST) -> tuple[bytes, Mapping[str, Any]]:
    raw = _regular(path, "component manifest")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit("component manifest must be UTF-8 JSON") from exc
    canonical = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    if raw != canonical:
        raise SystemExit("component manifest must use canonical JSON bytes")
    if value.get("schema_version") != 1 or value.get("manifest_id") != "GENERATOR-CONFORMANCE-ID":
        raise SystemExit("component manifest identity is invalid")
    return raw, value


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def contract_version(release_path: Path = RELEASE_METADATA) -> str:
    version = json.loads(_regular(release_path, "release metadata"))["contract_version"]
    if not isinstance(version, str) or not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version):
        raise SystemExit("contract version must be a major.minor.patch release")
    return version


def render_package_versions(version: str) -> dict[str, str]:
    """Stamp package metadata without changing dependencies or package contents."""
    python_path = "packages/python/pyproject.toml"
    python, count = re.subn(r'^version = "[^"]*"$', f'version = "{version}"',
                            (ROOT / python_path).read_text(encoding="utf-8"), flags=re.MULTILINE)
    if count != 1:
        raise SystemExit("Python client package must declare exactly one version")
    outputs = {python_path: python}
    for relative in ("packages/typescript/package.json", "packages/typescript/package-lock.json"):
        package = json.loads((ROOT / relative).read_text(encoding="utf-8"))
        package["version"] = version
        if relative.endswith("package-lock.json"):
            package["packages"][""]["version"] = version
        outputs[relative] = json.dumps(package, indent=2) + "\n"
    return outputs


def contract_digest(manifest_path: Path = MANIFEST) -> str:
    manifest = json.loads(_regular(manifest_path, "schema manifest"))
    paths = [ROOT / "contract" / manifest["openapi"], *(ROOT / "contract" / p for p in manifest["schemas"])]
    h = hashlib.sha256()
    for path in paths:
        relative = path.relative_to(ROOT).as_posix().encode()
        data = _regular(path, "contract input")
        h.update(len(relative).to_bytes(4, "big")); h.update(relative)
        h.update(len(data).to_bytes(8, "big")); h.update(data)
    return "sha256:" + h.hexdigest()


def operation_index(manifest_path: Path = MANIFEST) -> list[str]:
    manifest = json.loads(_regular(manifest_path, "schema manifest"))
    text = (ROOT / "contract" / manifest["openapi"]).read_text(encoding="utf-8")
    return [line.split(":", 1)[1].strip() for line in text.splitlines() if re.match(r"^\s+operationId:", line)]


def validate_command_schema() -> None:
    """Require the candidate to contain published schemas and the Agent freeze.

    Keep older snapshots immutable; advance this floor only after an authorized
    publication passes against the previous floor. Unsupported structural or
    regex rewrites require review, not sample-based compatibility guesses.
    """
    from generators.command_schema_compatibility import compatibility_errors, legacy_022_compatibility_errors

    fixtures = ROOT / "tests/fixtures/published-command-schemas"
    sources = json.loads(_regular(fixtures / "sources.json", "published schema sources"))
    candidate = json.loads(_regular(ROOT / "contract/schemas/edit-command.json", "candidate command schema"))
    # The Agent freeze is a staging floor, not a published Runtime release.
    floors = {
        "runtime-0.2.3.json": "472622c45fa6b5c7a425c949516a64a52d83192d3749e78a0f000decd088aee9",
        "runtime-0.2.10.json": "472622c45fa6b5c7a425c949516a64a52d83192d3749e78a0f000decd088aee9",
        "runtime-0.2.2.json": "460e61c70702f1f6bfa5cd033c8da859c913c3c8839f2a5b928df7691e08a388",
        "agent-0a0ac7ba.json": "30da4fde84c328e7cb44035b50eb53fd2cd9637a14a0c948f4412f6469ce34bd",
        "agent-26ef2bbb.json": "a6f1aaa9dfcc31828bd04c908158fd7fd9a825df6c9f88f79b81779273a190ef",
    }
    for filename, digest in floors.items():
        previous = _regular(fixtures / filename, "published command schema")
        if hashlib.sha256(previous).hexdigest() != digest or sources[filename]["sha256"] != digest:
            raise SystemExit("published command schema floor digest mismatch")
        check = legacy_022_compatibility_errors if filename == "runtime-0.2.2.json" else compatibility_errors
        errors = check(json.loads(previous), candidate)
        if errors:
            raise SystemExit(
                f"command schema compatibility failed against {filename}:\n  "
                + "\n  ".join(errors)
            )


def render_python_client(manifest_path: Path = MANIFEST) -> str:
    """Render the checked-in Python client from its tracked template.

    The template is deliberately separate from the output: ``--check`` must
    detect a mutated generated client rather than merely re-reading it.  The
    contract digest and operation projection are embedded so the artifact is
    also bound to the canonical OpenAPI/schema inputs.
    """
    template = _regular(PYTHON_CLIENT_TEMPLATE, "Python client template").decode("utf-8")
    if "__SCHEMA_DIGEST__" not in template or "__OPERATIONS__" not in template:
        raise SystemExit("Python client template is missing generator placeholders")
    operations = operation_index(manifest_path)
    if not operations or len(operations) != len(set(operations)):
        raise SystemExit("contract operation projection must be non-empty and unique")
    rendered = template.replace("Authoritative Python client template; rendered by generators/generate.py.", "Generated from contract/openapi/workspace-v1.yaml; do not edit by hand.")
    rendered = rendered.replace("__SCHEMA_DIGEST__", contract_digest(manifest_path))
    rendered = rendered.replace("__OPERATIONS__", repr(tuple(operations)))
    return rendered


def render_typescript_client() -> str:
    """Render contract response guards and resource operations into the TS client."""
    source = _regular(TYPESCRIPT_CLIENT_OUTPUT, "TypeScript client").decode("utf-8")
    generation_query_method = '  async listGenerations(projectId: string, cursor?: string, limit = 50, filters: { kind?: string; model?: string; target?: string; tag?: string } = {}): Promise<Page<Generation>> { const query = new URLSearchParams({ limit: String(limit) }); if (cursor) query.set("cursor", cursor); for (const name of ["kind", "model", "target", "tag"] as const) { const value = filters[name]; if (value !== undefined) query.set(name, value); } return this.page((await this.request("GET", `/v1/projects/${encodeURIComponent(projectId)}/generations?${query}`)).body) }'
    source = '\n'.join(generation_query_method if line.startswith('  async listGenerations(') else line for line in source.split('\n'))
    task_query_method = '  async listProjectTasks(projectId: string, cursor?: string, limit = 50, kind?: "root_generation", order?: "admitted_desc"): Promise<Page<Task>> { return this.page((await this.request("GET", `/v1/projects/${encodeURIComponent(projectId)}/tasks?limit=${limit}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}${kind !== undefined ? `&kind=${encodeURIComponent(kind)}` : ""}${order !== undefined ? `&order=${encodeURIComponent(order)}` : ""}`)).body) }'
    source = '\n'.join(task_query_method if line.startswith('  async listProjectTasks(') else line for line in source.split('\n'))
    custody_method = '  async reconcileTaskCustody(taskId: string, body: Record<string, unknown>, idempotencyKey: string): Promise<Record<string, unknown>> { return this.json((await this.request("POST", `/v1/control/tasks/${encodeURIComponent(taskId)}/reconcile`, new TextEncoder().encode(JSON.stringify(body)), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey })).body) }'
    if '  async reconcileTaskCustody(' in source:
        source = '\n'.join(custody_method if line.startswith('  async reconcileTaskCustody(') else line for line in source.split('\n'))
    else:
        source = source.replace('  async getLocalWorkerGeneration(', custody_method + '\n  async getLocalWorkerGeneration(', 1)
    abandon_types = ('export interface TaskAbandonRequest { expected_task_version: number; attempt_id: string; lease_id: string; fence: number; runtime_epoch: number; execution_binding: NonNullable<Task["execution_binding"]>; reason: string }\n'
        'export interface TaskAbandonResult { task_id: string; run_id: string; attempt_id: string; disposition: "lost"; reason: string; remote_stop_confirmed: false; billing_stop_confirmed: false; task: Task }')
    if 'export interface TaskAbandonRequest ' not in source:
        source = source.replace('export interface ObjectLocation', abandon_types + '\nexport interface ObjectLocation', 1)
    abandon_method = '  async abandonTask(taskId: string, body: TaskAbandonRequest, idempotencyKey: string): Promise<MutationResult<TaskAbandonResult>> { return this.mutation<TaskAbandonResult>((await this.request("POST", `/v1/control/tasks/${encodeURIComponent(taskId)}/abandon`, new TextEncoder().encode(JSON.stringify(body)), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey })).body) }'
    if '  async abandonTask(' in source:
        source = '\n'.join(abandon_method if line.startswith('  async abandonTask(') else line for line in source.split('\n'))
    else:
        source = source.replace('  async getLocalWorkerGeneration(', abandon_method + '\n  async getLocalWorkerGeneration(', 1)
    settlement_method = '  async getTaskSettlement(taskId: string): Promise<{ task_id: string; state: string; settled: boolean; blockers: Record<string, unknown>[]; task: Task; lost_disposition?: { event_id: string; attempt_id: string; reason: string } }> { return this.json((await this.request("GET", `/v1/control/tasks/${encodeURIComponent(taskId)}/settlement`)).body) }'
    if "  async getTaskSettlement(" in source:
        source = "\n".join(settlement_method if line.startswith("  async getTaskSettlement(") else line for line in source.split("\n"))
    else:
        source = source.replace("  async getLocalWorkerGeneration(", settlement_method + "\n  async getLocalWorkerGeneration(", 1)
    source = source.replace(
        'async relinquishLocalWorker(executorIncarnation: string, evidenceDigest: string):',
        'async relinquishLocalWorker(executorIncarnation: string, evidenceDigest: string, expectedTaskIds?: string[]):',
    ).replace(
        'JSON.stringify({ executor_incarnation: executorIncarnation, evidence_digest: evidenceDigest })',
        'JSON.stringify({ executor_incarnation: executorIncarnation, evidence_digest: evidenceDigest, ...(expectedTaskIds === undefined ? {} : { expected_task_ids: expectedTaskIds }) })',
    )
    exact_claim_method = '  async claimDelegatedChild(taskId: string, body: { executor_id: string; capability_ids: string[]; runtime_epoch: number; target: ExecutionTarget; authority: string }, idempotencyKey: string): Promise<AttemptFence> { return this.json<AttemptFence>((await this.request("POST", `/v1/tasks/${encodeURIComponent(taskId)}/claim-delegated-child`, new TextEncoder().encode(JSON.stringify(body)), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey }, [200])).body) }'
    if "  async claimDelegatedChild(" not in source:
        source = source.replace("  async claimTask(", exact_claim_method + "\n  async claimTask(", 1)
    terminal_evidence_types = (
        'export interface TerminalEvidence { outputs?: Record<string, unknown>[]; result?: Record<string, unknown> }\n'
        'export interface CancellationEvidence extends TerminalEvidence { attempt_id: string; lease_id: string; fence: number; runtime_epoch: number; stop_observed?: boolean }\n'
    )
    source = re.sub(
        r"^export interface (?:TerminalEvidence|CancellationEvidence)[^\n]*\n",
        "",
        source,
        flags=re.MULTILINE,
    )
    terminal_anchor = "export interface RecoveryAuthorization"
    if terminal_anchor not in source:
        raise SystemExit("TypeScript client is missing the terminal-evidence type insertion point")
    source = source.replace(terminal_anchor, terminal_evidence_types + terminal_anchor, 1)
    cancel_method = '  async cancelTask(taskId: string, idempotencyKey: string, expectedVersion?: number, evidence?: CancellationEvidence): Promise<MutationResult<Task>> { const payload = { ...evidence, ...(expectedVersion === undefined ? {} : { expected_version: expectedVersion }) }; return this.mutation<Task>((await this.request("POST", `/v1/tasks/${encodeURIComponent(taskId)}/cancel`, new TextEncoder().encode(JSON.stringify(payload)), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey })).body) }'
    source, cancel_count = re.subn(
        r"^  async cancelTask\([^\n]*\n",
        cancel_method + "\n",
        source,
        flags=re.MULTILINE,
    )
    if cancel_count != 1:
        raise SystemExit("TypeScript client must contain exactly one cancel task method")
    fail_method = '  async failAttempt(attemptId: string, leaseId: string, fence: number, error: unknown, runtimeEpoch: number, idempotencyKey: string, evidence: TerminalEvidence = {}): Promise<MutationResult<Task>> { return this.mutation<Task>((await this.request("POST", `/v1/attempts/${encodeURIComponent(attemptId)}/fail`, new TextEncoder().encode(JSON.stringify({ ...evidence, lease_id: leaseId, fence, runtime_epoch: runtimeEpoch, error })), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey })).body) }'
    source, fail_count = re.subn(
        r"^  async failAttempt\([^\n]*\n",
        fail_method + "\n",
        source,
        flags=re.MULTILINE,
    )
    if fail_count != 1:
        raise SystemExit("TypeScript client must contain exactly one fail attempt method")
    commit_response = '''  private commitResponse(body: Uint8Array, preview: boolean): CommitAcceptedMutation | CommitPreviewResponse {
    const value = this.json<Record<string, unknown>>(body);
    if (!value || typeof value !== "object" || Array.isArray(value) || !value.data || typeof value.data !== "object" || Array.isArray(value.data) || !("receipt" in value)) throw new Error("invalid commit response");
    const data = value.data as Record<string, unknown>;
    const receipt = value.receipt;
    if (preview) {
      if (data.status !== "preview" || !["accepted", "merged"].includes(data.would_status as string) || receipt !== null) throw new Error("invalid commit preview status, would_status or receipt");
    } else {
      if (!["accepted", "rebased", "merged"].includes(data.status as string) || !receipt || typeof receipt !== "object" || Array.isArray(receipt)) throw new Error("invalid commit status or receipt");
      const committed = receipt as Record<string, unknown>;
      const sequence = committed.project_seq;
      if (["receipt_id", "command_kind", "idempotency_key", "request_hash", "project_id", "created_at"].some(key => typeof committed[key] !== "string") || !("result" in committed) || !Array.isArray(sequence) || sequence.length !== 2 || sequence.some(item => !Number.isInteger(item) || item < 1) || !Array.isArray(committed.event_ids) || committed.event_ids.some(item => typeof item !== "string")) throw new Error("invalid commit receipt fields");
    }
    return value as unknown as CommitAcceptedMutation | CommitPreviewResponse;
  }
'''
    source, count = re.subn(r"^  private commitResponse\([^\n]*\n.*?^  }\n", lambda _: commit_response, source, flags=re.MULTILINE | re.DOTALL)
    if count != 1:
        raise SystemExit("TypeScript client must contain exactly one commit response guard")
    agent = json.loads(_regular(ROOT / "contract/schemas/edit-command.json", "command schema"))["$defs"]
    native_types = [name for name in agent if name.endswith("Args") or name.startswith("Producer")]
    native_types += ["ElementRef", "SettledProducerProposal", "DocumentPin", "VerifiedDocument", "VerifiedDocumentObject"]
    native_exports = 'export type { ' + ', '.join(native_types) + ' } from "./timeline-commit-types.js";'
    source = re.sub(r'^export type \{ [^\n]*\bClipAddArgs\b[^\n]* from "\./timeline-commit-types.js";\n', '', source, flags=re.MULTILINE)
    source = native_exports + "\n" + source
    child_authority_types = (
        'export interface ChildAuthorityChild { child_id: string; capability_id: string; capability_digest: string }\n'
        'export interface DerivedInputDescriptor { name: string; output_port: string; filename: string; object_id: string; size: number; media_type: string }\n'
        'export interface ChildAuthorityRequest { lease_id: string; fence: number; runtime_epoch: number; child?: ChildAuthorityChild; derived_inputs?: DerivedInputDescriptor[] }'
    )
    if "export interface ChildAuthorityRequest " not in source:
        anchor = "export interface ObjectLocation"
        if anchor not in source:
            raise SystemExit("TypeScript client is missing the child-authority type insertion point")
        source = source.replace(anchor, child_authority_types + "\n" + anchor, 1)
    old_child_authority_method = '  async issueChildAuthority(attemptId: string, body: { lease_id: string; fence: number; runtime_epoch: number }): Promise<Record<string, unknown>>'
    new_child_authority_method = '  async issueChildAuthority(attemptId: string, body: ChildAuthorityRequest): Promise<Record<string, unknown>>'
    if new_child_authority_method not in source:
        if old_child_authority_method not in source:
            raise SystemExit("TypeScript child-authority client projection is partially present")
        source = source.replace(old_child_authority_method, new_child_authority_method, 1)
    snapshot_type = 'export interface RecoverableSnapshotRequest { lease_id: string; fence: number; runtime_epoch: number; revision: number; output: DerivedInputDescriptor }'
    if "export interface RecoverableSnapshotRequest " not in source:
        source = source.replace("export interface ObjectLocation", snapshot_type + "\nexport interface ObjectLocation", 1)
    app_state_types = 'export interface AppStateResource { scope: "user"; actor_id: string; key: string; content: Record<string, unknown> | null; version: number; created_at: string | null; updated_at: string | null }\n'
    if "export interface AppStateResource " not in source:
        anchor = "export type PreferenceScope"
        if anchor not in source:
            raise SystemExit("TypeScript client is missing the app-state type insertion point")
        source = source.replace(anchor, app_state_types + anchor, 1)
    app_state_methods = '''  private appStateResource(value: unknown, key: string): AppStateResource {
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid app-state resource");
    const v = value as Record<string, unknown>;
    if (["scope", "actor_id", "key", "content", "version", "created_at", "updated_at"].some(name => !(name in v))) throw new Error("invalid app-state resource fields");
    const content = v.content;
    if (v.scope !== "user" || typeof v.actor_id !== "string" || !v.actor_id || v.key !== key || !(content === null || (typeof content === "object" && !Array.isArray(content))) || !Number.isInteger(v.version) || (v.version as number) < 0 || (content === null) !== (v.version === 0) || [v.created_at, v.updated_at].some(item => item !== null && typeof item !== "string")) throw new Error("invalid app-state resource ownership, content or version");
    return v as unknown as AppStateResource;
  }
  async getUserAppState(key: string): Promise<AppStateResource> {
    return this.appStateResource(this.json((await this.request("GET", `/v1/app-state/user/${encodeURIComponent(key)}`)).body), key);
  }
  async updateUserAppState(key: string, content: Record<string, unknown>, expectedVersion: number, idempotencyKey: string): Promise<AppStateResource> {
    const value = this.json<Record<string, unknown>>((await this.request("PUT", `/v1/app-state/user/${encodeURIComponent(key)}`, new TextEncoder().encode(JSON.stringify({ content, expected_version: expectedVersion })), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey })).body);
    if (!value || typeof value !== "object" || !("data" in value) || value.receipt !== null) throw new Error("invalid app-state mutation: data and null receipt are required");
    return this.appStateResource(value.data, key);
  }
'''
    if "  async getUserAppState(" not in source:
        anchor = "  async handshake("
        if anchor not in source:
            raise SystemExit("TypeScript client is missing the handshake insertion point")
        source = source.replace(anchor, app_state_methods + anchor, 1)
    snapshot_method = '  async publishRecoverableSnapshot(attemptId: string, body: RecoverableSnapshotRequest, idempotencyKey: string): Promise<MutationResult<ManagedOutput>> { return this.mutation<ManagedOutput>((await this.request("POST", `/v1/attempts/${encodeURIComponent(attemptId)}/recoverable-snapshots`, new TextEncoder().encode(JSON.stringify(body)), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey })).body) }'
    if "  async publishRecoverableSnapshot(" not in source:
        source = source.replace("  async issueChildAuthority(", snapshot_method + "\n  async issueChildAuthority(", 1)
    source = source.replace(
        'export interface GenerationVariant { variant_id: string; generation_id: string; object_id?: string | null; variant_type: string; metadata: Record<string, unknown>; thumbnail?: { object_id: string; source_object_id: string; recipe_version: number } | null; viewed_at?: string | null; created_at: string }',
        'export interface ThumbnailDescriptor { object_id: string; source_object_id: string; recipe_version: number; selection?: { kind: "variant" | "source_frame"; source_time_seconds?: number } }\nexport interface GenerationVariant { variant_id: string; generation_id: string; object_id?: string | null; variant_type: string; metadata: Record<string, unknown>; thumbnail?: ThumbnailDescriptor | null; viewed_at?: string | null; created_at: string }',
        1,
    )
    get_method = '  async getSourceFrameThumbnail(projectId: string, sourceObjectId: string, sourceTimeSeconds: number, recipeVersion = 1): Promise<Record<string, unknown> | null> { const query = `source_object_id=${encodeURIComponent(sourceObjectId)}&source_time_seconds=${sourceTimeSeconds.toFixed(6)}&recipe_version=${recipeVersion}`; return this.json<{ thumbnail: Record<string, unknown> | null }>((await this.request("GET", `/v1/projects/${encodeURIComponent(projectId)}/thumbnails/source-frame?${query}`)).body).thumbnail }'
    ensure_method = '  async ensureSourceFrameThumbnail(projectId: string, thumbnail: Record<string, unknown>, idempotencyKey: string): Promise<MutationResult<Record<string, unknown>>> { return this.mutation<Record<string, unknown>>((await this.request("POST", `/v1/projects/${encodeURIComponent(projectId)}/thumbnails/source-frame`, new TextEncoder().encode(JSON.stringify(thumbnail)), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey }, [200, 201])).body) }'
    markers = ("  async getSourceFrameThumbnail(", "  async ensureSourceFrameThumbnail(")
    present = tuple(marker in source for marker in markers)
    if all(present):
        return source
    if any(present):
        raise SystemExit("TypeScript source-frame thumbnail client projection is partially present")
    anchor = next((line for line in source.splitlines() if line.startswith("  async listMediaRelations(")), None)
    if anchor is None:
        raise SystemExit("TypeScript client is missing the listMediaRelations insertion point")
    return source.replace(anchor, anchor + "\n" + get_method + "\n" + ensure_method, 1)


def validate_typescript_client(manifest_path: Path = MANIFEST) -> None:
    """Fail closed when the typed product projection drifts from OpenAPI.

    The TypeScript client remains a typed repository source rather than a
    Python-template copy.  This check still binds every public method to the
    canonical operation projection and asserts the execution binding fields
    whose types cannot be inferred by the small metadata renderer.
    """
    source = _regular(TYPESCRIPT_CLIENT_OUTPUT, "TypeScript client").decode("utf-8")
    methods = set(re.findall(r"^  async (\w+)\(", source, re.MULTILINE))
    expected = set(operation_index(manifest_path)) | {"updateTimelineDocument"}
    if methods != expected:
        missing = sorted(expected - methods)
        extra = sorted(methods - expected)
        raise SystemExit(
            "TypeScript client operation projection drifted"
            + (f"; missing={missing}" if missing else "")
            + (f"; extra={extra}" if extra else "")
        )
    required_fragments = (
        "async listDocuments(projectId: string, cursor?: string, limit = 50, kind?: string)",
        "kind=${encodeURIComponent(kind)}",
        'async listEvents(cursor?: string, limit = 50, aggregateId?: string, from?: "latest")',
        "from=${encodeURIComponent(from)}",
        "actual_target?: ExecutionTarget",
        "verification?: ExecutionBindingVerification",
        "executor_incarnation?: string",
        "run_id: string; project_id: string | null; lease_id: string",
        "lease_expires_at: string; runtime_epoch: number",
        "provider_state_unknown",
        "request: CommitRequest, idempotencyKey: string",
        "Promise<CommitAcceptedMutation | CommitPreviewResponse>",
        "expected_publication_id: expectedPublicationId",
        "Promise<HistoryPage>",
        "selection: MediaSelectionQuery",
        "async getProjectVerifiedMedia(projectId: string, selection: MediaSelection): Promise<VerifiedMedia>",
        "async getProjectVerifiedDocument(projectId: string, pin: DocumentPin): Promise<VerifiedDocument>",
        "async getProjectVerifiedDocumentObject(projectId: string, pin: DocumentPin, objectId: string): Promise<VerifiedDocumentObject>",
        "export interface TerminalEvidence { outputs?: Record<string, unknown>[]; result?: Record<string, unknown> }",
        "export interface CancellationEvidence extends TerminalEvidence",
        "async cancelTask(taskId: string, idempotencyKey: string, expectedVersion?: number, evidence?: CancellationEvidence)",
        "const payload = { ...evidence, ...(expectedVersion === undefined ? {} : { expected_version: expectedVersion }) };",
        "async failAttempt(attemptId: string, leaseId: string, fence: number, error: unknown, runtimeEpoch: number, idempotencyKey: string, evidence: TerminalEvidence = {})",
        "JSON.stringify({ ...evidence, lease_id: leaseId, fence, runtime_epoch: runtimeEpoch, error })",
    )
    missing_fragments = [value for value in required_fragments if value not in source]
    if missing_fragments:
        raise SystemExit(
            "TypeScript execution contract projection is stale: "
            + ", ".join(missing_fragments)
        )


def render(manifest_path: Path = MANIFEST, component_path: Path = COMPONENT_MANIFEST,
           release_path: Path = RELEASE_METADATA) -> dict[str, str]:
    component_bytes, component = _component(component_path)
    digest = contract_digest(manifest_path)
    operations = operation_index(manifest_path)
    component_digest = _digest(component_bytes)
    version = contract_version(release_path)
    py = ('"""Generated contract metadata; do not edit by hand."""\n\n'
          'CONTRACT_VERSION = ' + repr(version) + '\nPROTOCOL = "workspace.v1"\nCOMPONENT_MANIFEST_SHA256 = ' + repr(component_digest) +
          '\nSCHEMA_DIGEST = ' + repr(digest) + "\nOPERATIONS = " + repr(tuple(operations)) + "\n")
    ts = ('/** Generated contract metadata; do not edit by hand. */\n\n'
          'export const CONTRACT_VERSION = ' + json.dumps(version) + ' as const;\nexport const PROTOCOL = "workspace.v1" as const;\nexport const COMPONENT_MANIFEST_SHA256 = ' + json.dumps(component_digest) +
          ';\nexport const SCHEMA_DIGEST = ' + json.dumps(digest) + ";\nexport const OPERATIONS = " + json.dumps(operations) + " as const;\n")
    runtime = ('"""Generated contract metadata; do not edit by hand."""\n\n'
               'PROTOCOL = "workspace.v1"\nCOMPONENT_MANIFEST_SHA256 = ' + repr(component_digest) +
               '\nSCHEMA_DIGEST = ' + repr(digest) + "\nOPERATIONS = " + repr(tuple(operations)) + "\n")
    # Keep the three metadata modules bound to the same manifest.  The
    # standalone Python/TypeScript client artifacts and fixture bundle are
    # emitted by their language-specific conformance generators.
    _ = component
    return {"packages/python/astrid_runtime_client/contract_metadata.py": py,
            "packages/typescript/src/contract-metadata.ts": ts,
            "runtime_protocol/contract_metadata.py": runtime,
            **render_package_versions(version)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if generated metadata differs")
    parser.add_argument("--component-manifest", default=str(COMPONENT_MANIFEST))
    parser.add_argument("--python-output", default=str(PYTHON_CLIENT_OUTPUT), help="Python client output path (for isolated checks)")
    args = parser.parse_args()
    sys.path.insert(0, str(ROOT))
    validate_command_schema()
    sys.path.insert(0, str(ROOT / "generators"))
    from timeline_commit_types import render as render_commit_types
    generated = render_commit_types()
    generated.update(render(component_path=Path(args.component_manifest).expanduser()))
    generated["packages/python/astrid_runtime_client/__init__.py"] = _regular(
        ROOT / "generators/python_client_init_template.py", "Python package exports template"
    ).decode("utf-8").replace(
        "Authoritative Python package exports; rendered by generators/generate.py.",
        "Generated, product-neutral client for the workspace.v1 protocol.",
    )
    generated["packages/python/astrid_runtime_client/generated.py"] = render_python_client()
    generated["packages/typescript/src/generated.ts"] = render_typescript_client()
    from timeline_commit_resources import render as render_commit_resources
    generated.update(render_commit_resources())
    for relative, content in generated.items():
        path = Path(args.python_output).expanduser().resolve() if relative == "packages/python/astrid_runtime_client/generated.py" else ROOT / relative
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                print(f"stale generated file: {relative}")
                return 1
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            print(relative)
    validate_typescript_client()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
