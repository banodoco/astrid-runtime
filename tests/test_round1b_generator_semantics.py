"""Exercise the merged TypeScript renderer without writing contract outputs."""
import re
import subprocess
from pathlib import Path

import pytest

from generators import generate


def test_typescript_renderer_reconciles_m_and_r1_with_timeline_seed(tmp_path, monkeypatch):
    seed = generate.TYPESCRIPT_CLIENT_OUTPUT.read_text()
    seed = "\n".join(
        line for line in seed.split("\n")
        if not line.startswith(("  async abandonTask(", "  async getTaskSettlement(",
                                "  async claimDelegatedChild("))
    )
    seed = re.sub(r'^  async listGenerations\([^\n]*',
                  '  async listGenerations() { throw new Error("old"); }', seed,
                  flags=re.MULTILINE)
    source = tmp_path / "seed.ts"
    source.write_text(seed)
    monkeypatch.setattr(generate, "TYPESCRIPT_CLIENT_OUTPUT", source)
    rendered = generate.render_typescript_client()
    for fragment in (
        'for (const name of ["kind", "model", "target", "tag"] as const)',
        'async abandonTask(', 'async getTaskSettlement(', 'async claimDelegatedChild(',
        'expected_task_ids: expectedTaskIds', 'async ensureSourceFrameThumbnail(',
        'private commitResponse(', 'invalid commit preview status, would_status or receipt',
        'async getProjectVerifiedDocument(',
    ):
        assert fragment in rendered
    source.write_text(rendered)
    assert generate.render_typescript_client() == rendered


def test_typescript_renderer_reconciles_f05_terminal_evidence_from_pre_f05_seed(tmp_path, monkeypatch):
    seed = generate.TYPESCRIPT_CLIENT_OUTPUT.read_text()
    seed = re.sub(r"^export interface (?:TerminalEvidence|CancellationEvidence)[^\n]*\n", "", seed,
                  flags=re.MULTILINE)
    seed = re.sub(
        r"^  async cancelTask\([^\n]*",
        '  async cancelTask(taskId: string, idempotencyKey: string, expectedVersion?: number): Promise<MutationResult<Task>> { return this.transitionTask(taskId, "cancel", idempotencyKey, expectedVersion) }',
        seed,
        flags=re.MULTILINE,
    )
    seed = re.sub(
        r"^  async failAttempt\([^\n]*",
        '  async failAttempt(attemptId: string, leaseId: string, fence: number, error: unknown, runtimeEpoch: number, idempotencyKey: string): Promise<MutationResult<Task>> { return this.mutation<Task>((await this.request("POST", `/v1/attempts/${encodeURIComponent(attemptId)}/fail`, new TextEncoder().encode(JSON.stringify({ lease_id: leaseId, fence, runtime_epoch: runtimeEpoch, error })), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey })).body) }',
        seed,
        flags=re.MULTILINE,
    )
    source = tmp_path / "seed.ts"
    source.write_text(seed)
    monkeypatch.setattr(generate, "TYPESCRIPT_CLIENT_OUTPUT", source)

    rendered = generate.render_typescript_client()

    for fragment in (
        "export interface TerminalEvidence { outputs?: Record<string, unknown>[]; result?: Record<string, unknown> }",
        "export interface CancellationEvidence extends TerminalEvidence",
        "async cancelTask(taskId: string, idempotencyKey: string, expectedVersion?: number, evidence?: CancellationEvidence)",
        "const payload = { ...evidence, ...(expectedVersion === undefined ? {} : { expected_version: expectedVersion }) };",
        "async failAttempt(attemptId: string, leaseId: string, fence: number, error: unknown, runtimeEpoch: number, idempotencyKey: string, evidence: TerminalEvidence = {})",
        "JSON.stringify({ ...evidence, lease_id: leaseId, fence, runtime_epoch: runtimeEpoch, error })",
    ):
        assert fragment in rendered
    source.write_text(rendered)
    assert generate.render_typescript_client() == rendered


def test_conformance_renderer_unites_timeline_and_f05_surfaces(tmp_path):
    root = Path(__file__).parents[1]
    output = tmp_path / "generated"
    subprocess.run([
        "node", str(root / "tools" / "generate_typescript_conformance.mjs"),
        "--contract", str(root / "contract" / "openapi" / "workspace-v1.yaml"),
        "--schema-manifest", str(root / "contract" / "manifest.json"),
        "--component-manifest", str(root / "contract" / "component-manifest.json"),
        "--output-root", str(output),
    ], check=True)
    rendered = (output / "conformance" / "typescript" / "generated.ts").read_text()
    for fragment in (
        "export interface TerminalEvidence { outputs?: Record<string, unknown>[]; result?: Record<string, unknown> }",
        "async cancelTask(taskId: string, idempotencyKey: string, expectedVersion?: number, evidence?: CancellationEvidence)",
        "JSON.stringify({ ...evidence, lease_id: leaseId, fence, runtime_epoch: runtimeEpoch, error })",
        "async createTimelineView(projectId: string, timelineId: string, options: Record<string, unknown>, idempotencyKey: string)",
        '"Idempotency-Key": idempotencyKey',
    ):
        assert fragment in rendered


@pytest.mark.parametrize("guard_count", [0, 2])
def test_typescript_renderer_rejects_missing_or_duplicate_timeline_guard(tmp_path, monkeypatch, guard_count):
    source = tmp_path / "seed.ts"
    original = generate.TYPESCRIPT_CLIENT_OUTPUT.read_text()
    guard = re.search(r'^  private commitResponse\([^\n]*\n.*?^  }\n', original,
                      flags=re.MULTILINE | re.DOTALL).group()
    source.write_text(original.replace(guard, guard * guard_count, 1))
    monkeypatch.setattr(generate, "TYPESCRIPT_CLIENT_OUTPUT", source)
    with pytest.raises(SystemExit, match="exactly one commit response guard"):
        generate.render_typescript_client()
