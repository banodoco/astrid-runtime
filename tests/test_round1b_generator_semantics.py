"""Exercise the merged TypeScript renderer without writing contract outputs."""
import re

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
