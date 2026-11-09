"""The skip guard (tests/lanes.py) fails the run on undeclared skips and xfails."""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

from tests import lanes

pytest_plugins = ["pytester"]

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture
def sandbox(pytester):
    pytester.makeconftest(
        f"""
        import sys
        sys.path.insert(0, {str(REPO)!r})
        from tests.lanes import pytest_configure  # noqa: F401
        """
    )
    pytester.makeini("[pytest]\npython_files = check_*.py\n")
    return pytester


def _run(sandbox, body: str):
    sandbox.makepyfile(check_it=textwrap.dedent(body))
    return sandbox.runpytest_subprocess("-p", "no:cacheprovider", "-q")


def test_undeclared_pytest_skip_fails_the_run(sandbox):
    result = _run(sandbox, """
        import pytest
        def test_a():
            pytest.skip("flaky today")
        """)
    assert result.ret != 0
    result.stdout.fnmatch_lines(["UNDECLARED SKIP *::test_a: *flaky today*"])


def test_skip_mark_importorskip_and_xfail_fail_the_run(sandbox):
    result = _run(sandbox, """
        import pytest
        @pytest.mark.skip(reason="x")
        def test_mark(): pass
        @pytest.mark.skipif(True, reason="[declared:not-in-registry] nope")
        def test_unknown_tag(): pass
        @pytest.mark.xfail(reason="later")
        def test_xfail(): assert False
        """)
    assert result.ret != 0
    result.stdout.fnmatch_lines([
        "UNDECLARED SKIP *::test_mark: *",
        "UNDECLARED SKIP *::test_unknown_tag: *",
        "UNDECLARED SKIP *::test_xfail: xfail is not allowed*",
    ])


@pytest.mark.parametrize("variant", ["new-node", "moved-function", "new-parameter", "changed-reason", "missing-reason"])
def test_xfail_reason_does_not_authorize_a_different_node_or_contract(sandbox, variant):
    reason = lanes.DECLARED_XFAILS["runtime-domains-update"].reason
    if variant == "new-node":
        marker = f'pytest.mark.xfail(strict=True, raises=RuntimeError, reason={reason!r})'
        test = f"@{marker}\ndef test_new_node(): raise RuntimeError('known')"
    elif variant == "moved-function":
        marker = f'pytest.mark.xfail(strict=True, raises=RuntimeError, reason={reason!r})'
        test = f"@{marker}\ndef test_generated_direct_timeline_shot_reference_writers_remain_retired_moved(): raise RuntimeError('known')"
    elif variant == "new-parameter":
        test = (
            "@pytest.mark.parametrize('case', [pytest.param('new', marks=pytest.mark.xfail("
            f"strict=True, raises=RuntimeError, reason={reason!r}))])\n"
            "def test_generated_direct_timeline_shot_reference_writers_remain_retired(case): raise RuntimeError('known')"
        )
    elif variant == "changed-reason":
        marker = f'pytest.mark.xfail(strict=True, raises=RuntimeError, reason={(reason + " changed")!r})'
        test = f"@{marker}\ndef test_generated_direct_timeline_shot_reference_writers_remain_retired(): raise RuntimeError('known')"
    else:
        test = "@pytest.mark.xfail(strict=True, raises=RuntimeError)\ndef test_generated_direct_timeline_shot_reference_writers_remain_retired(): raise RuntimeError('known')"
    result = _run(sandbox, f"import pytest\n{test}\ndef test_control(): pass\n")
    assert result.ret != 0
    result.stdout.fnmatch_lines(["UNDECLARED SKIP *xfail is not allowed*"])


# The exact declared xfails: name -> (test ids, exception type, reason). Adding, removing, rewording,
# repointing an xfail at another test, or widening its exception fails here until this table changes too;
# a bare count or a name-to-reason map cannot catch a swap. Plan 38's E1 removes the xfail and its entry together.
_PINNED_XFAILS = {
    'runtime-domains-publication': (
        ('tests/test_runtime_domains.py::test_generated_python_client_timeline_publication_is_retired_pending_commit_replacement',),
        'tests.test_runtime_domains._RetiredTimelinePublication',
        '[declared-xfail:runtime-domains-publication] RT02/D04 held: legacy timeline publication (update_timeline) is retired (410); restored by the /v1 commit replacement',
    ),
    'runtime-domains-update': (
        ('tests/test_runtime_domains.py::test_generated_direct_timeline_shot_reference_writers_remain_retired',),
        'tests.test_runtime_domains._RetiredTimelineUpdate',
        '[declared-xfail:runtime-domains-update] direct timeline update writer remains retired',
    ),
    'runtime-exact-idempotency': (
        ('tests/test_runtime_exact_idempotency.py::test_timeline_shot_and_reference_creation_are_keyed_durable_and_non_overwriting',),
        'astrid_runtime_client.generated.ApiError',
        '[declared-xfail:runtime-exact-idempotency] RT02 held: direct shot writes are retired (410); the reference half is the KEPT catalog (RK01)',
    ),
    'second-client-core': (
        ('tests/test_second_client_e2e.py::test_second_client_core_journey_is_executable',),
        'subprocess.CalledProcessError',
        '[declared-xfail:second-client-core] RT02/D04 held: direct shot writes and legacy timeline publication are retired (410); the actor is ported with their replacements',
    ),
    'snapshot-legacy-certification': (
        ('tests/test_snapshot_legacy_certification.py::test_already_admitted_capture_after_upgrade[genuine-ref]',
         'tests/test_snapshot_legacy_certification.py::test_already_admitted_capture_after_upgrade[genuine-inline]'),
        'tests.test_snapshot_legacy_certification.LegacyGenuineUncertified',
        '[declared-xfail:snapshot-legacy-certification] ledger: no row id yet (PLAN 2026-10-20 capture certification); valid legacy capture is not re-certified until Agent project_capture lands',
    ),
    'stage1-runtime-contract': (
        ('tests/test_stage1_runtime_contract_completion.py::test_timeline_update_archive_recover_replay_the_same_committed_receipt',),
        'runtime_protocol.errors.RetiredRouteError',
        '[declared-xfail:stage1-runtime-contract] ledger D04: direct timeline writes retired; awaiting commit-path replacement',
    ),
    'timeline-clip-replacement': (
        ('tests/test_timeline_clip_replacement.py::test_replace_timeline_clip_is_atomic_cas_and_exactly_replayable',
         'tests/test_timeline_clip_replacement.py::test_replace_timeline_clip_rejects_cross_project_source',
         'tests/test_timeline_clip_replacement.py::test_replace_timeline_clip_rejects_malformed_source_without_mutation',
         'tests/test_timeline_clip_replacement.py::test_replace_timeline_clip_rejects_tampered_cas_without_mutation',
         'tests/test_timeline_clip_replacement.py::test_replace_timeline_clip_rejects_wrong_stream_without_mutation',
         'tests/test_timeline_clip_replacement.py::test_replace_timeline_clip_rejects_too_short_source_without_mutation',
         'tests/test_timeline_clip_replacement.py::test_replace_timeline_clip_requires_source_to_reach_authored_end',
         'tests/test_timeline_clip_replacement.py::test_replace_timeline_clip_generic_visual_media_requires_video_stream',
         'tests/test_timeline_clip_replacement.py::test_replace_timeline_clip_replays_after_intervening_edit_and_reopen',
         'tests/test_timeline_clip_replacement.py::test_replace_timeline_clip_public_http_route'),
        'runtime_protocol.errors.RetiredRouteError',
        '[declared-xfail:timeline-clip-replacement] ledger D04: direct clip replacement retired; awaiting commit-path replacement',
    ),
    'timeline-public-s2-historical-audio': (
        ('tests/test_timeline_public_s2_mixed_cli_journey.py::test_public_cli_stale_trim_rebases_label_lost_ack_restart_retry_and_undo[historical-audio]',),
        'tests.test_timeline_public_s2_mixed_cli_journey.HistoricalAudioCaptureGap',
        "[declared-xfail:timeline-public-s2-historical-audio] M2 historical audio capture: the public CLI trim of "
        "the original music-bed audio clip is refused before POST ('clip.trim applies to media clips'); held "
        "until the CLI captures the original audio film before POST",
    ),
    'installed-pair-source-closure': (
        ('tests/test_installed_pack_custody_spawn.py::test_real_custody_spawn_launches_granted_installed_pack_and_refuses_ungranted',),
        'tests.test_installed_pack_custody_spawn.KnownSourceClosureMismatch',
        "[declared-xfail:installed-pair-source-closure] the Agent and Runtime measure different source-closure "
        "digests for an installed pair, so the darwin custody spawn is refused as 'differs from original launch'; "
        "proven by CI run 42602337622 (darwin-native job 129109610936 at 49a062c raised KnownSourceClosureMismatch "
        "under the strict xfail); fixed by astrid-dev Plan 38",
    ),
    'p1-top-level-text-hook': (
        ('tests/test_timeline_visual_fields.py::test_supported_top_level_type_on_retains_original_roundtrip_expectations',),
        'runtime_protocol.errors.RuntimeErrorBase',
        '[declared-xfail:p1-top-level-text-hook] P1 top-level text-hook restoration requirement',
    ),
}


def _declared_xfail_contract(declarations):
    return {name: (spec.nodeids, spec.raises, spec.reason) for name, spec in declarations.items()}


def test_xfail_declarations_are_immutable_and_semantic():
    assert _declared_xfail_contract(lanes.DECLARED_XFAILS) == _PINNED_XFAILS
    assert all(spec.strict is True and spec.nodeids and spec.reason and spec.raises
               for spec in lanes.DECLARED_XFAILS.values())


def test_xfail_reasons_carry_no_session_path():
    for spec in lanes.DECLARED_XFAILS.values():
        assert "/tmp/" not in spec.reason and "scratchpad" not in spec.reason and "claude-0" not in spec.reason, spec.reason


@pytest.mark.parametrize("change", ["repointed-test", "added-test", "other-exception"])
def test_the_pin_catches_a_repointed_or_widened_xfail(change):
    import dataclasses
    name = "runtime-domains-update"
    spec = lanes.DECLARED_XFAILS[name]
    if change == "repointed-test":
        changed = dataclasses.replace(spec, nodeids=("tests/test_runtime_domains.py::test_some_other_test",))
    elif change == "added-test":
        changed = dataclasses.replace(spec, nodeids=spec.nodeids + ("tests/test_runtime_domains.py::test_some_other_test",))
    else:
        changed = dataclasses.replace(spec, raises="builtins.Exception")
    assert _declared_xfail_contract({**lanes.DECLARED_XFAILS, name: changed}) != _PINNED_XFAILS


def _foreign_helper() -> str:
    return "requires_windows_security" if sys.platform != "win32" else "requires_posix_process_groups"


def test_declared_skip_passes_and_is_listed_by_name(sandbox):
    helper = _foreign_helper()
    result = _run(sandbox, f"""
        from tests.lanes import {helper}
        @{helper}
        def test_platform_only(): assert False
        def test_runs(): pass
        """)
    assert result.ret == 0, result.stdout.str()
    result.stdout.fnmatch_lines(["declared skips (1):", "  SKIP *::test_platform_only: [[]declared:*"])


def test_declared_runtime_skip_passes_where_the_error_matches(sandbox):
    result = _run(sandbox, """
        import pytest
        from tests import lanes
        from tests.lanes import HOSTS, skip_for_declared_error

        def test_symlink(monkeypatch):
            monkeypatch.setattr(lanes, "CURRENT", HOSTS["windows"])
            error = OSError(1314, "no privilege")
            error.winerror = 1314
            skip_for_declared_error("windows-symlink-creation", error)
        def test_runs(): pass
        """)
    assert result.ret == 0, result.stdout.str()
    result.stdout.fnmatch_lines(["  SKIP *::test_symlink: [[]declared:windows-symlink-creation]*"])


def test_declared_runtime_skip_reraises_a_different_error(sandbox):
    result = _run(sandbox, """
        import pytest
        from tests import lanes
        from tests.lanes import HOSTS, skip_for_declared_error

        def test_other_error(monkeypatch):
            monkeypatch.setattr(lanes, "CURRENT", HOSTS["windows"])
            error = OSError(5, "access denied")
            error.winerror = 5
            with pytest.raises(OSError) as raised:
                skip_for_declared_error("windows-symlink-creation", error)
            assert raised.value is error
        def test_off_windows(monkeypatch):
            monkeypatch.setattr(lanes, "CURRENT", HOSTS["linux"])
            error = OSError(1314, "x")
            error.winerror = 1314
            with pytest.raises(OSError):
                skip_for_declared_error("windows-symlink-creation", error)
        """)
    assert result.ret == 0, result.stdout.str()


def test_a_run_in_which_every_test_is_skipped_by_a_declared_skip_fails(sandbox):
    helper = _foreign_helper()
    result = _run(sandbox, f"""
        from tests.lanes import {helper}
        @{helper}
        def test_platform_only(): assert False
        """)
    assert result.ret != 0
    result.stdout.fnmatch_lines(["*no test passed in this run*"])


def test_a_skip_raised_in_a_fixture_teardown_fails_the_run(sandbox):
    result = _run(sandbox, """
        import pytest
        @pytest.fixture
        def late():
            yield
            pytest.skip("gave up at teardown")
        def test_a(late): pass
        def test_b(): pass
        """)
    assert result.ret != 0
    result.stdout.fnmatch_lines(["UNDECLARED SKIP *::test_a: *gave up at teardown*"])


def test_a_declared_skip_raised_in_a_fixture_teardown_is_listed(sandbox):
    result = _run(sandbox, """
        import pytest
        @pytest.fixture
        def late():
            yield
            pytest.skip("[declared:windows-security] native Windows socket exclusivity and file DACL APIs")
        def test_a(late): pass
        def test_b(): pass
        """)
    assert result.ret == 0, result.stdout.str()
    result.stdout.fnmatch_lines(["declared skips (1):", "  SKIP *::test_a: [[]declared:windows-security]*"])


def test_skips_of_non_blocking_entries_are_listed_under_their_own_header(sandbox):
    helper = _foreign_helper()
    result = _run(sandbox, f"""
        import dataclasses
        from tests import lanes
        from tests.lanes import {helper}

        lanes.SKIP_REGISTRY.update({{
            name: dataclasses.replace(entry, blocking=False)
            for name, entry in lanes.SKIP_REGISTRY.items()
        }})
        @{helper}
        def test_platform_only(): assert False
        def test_runs(): pass
        """)
    assert result.ret == 0, result.stdout.str()
    result.stdout.fnmatch_lines([
        "declared skips whose tests run only in non-blocking CI jobs (1):",
        "  NON-BLOCKING *::test_platform_only: [[]declared:*",
    ])


def test_skips_of_entries_no_ci_job_runs_are_listed_under_their_own_header(sandbox):
    helper = _foreign_helper()
    result = _run(sandbox, f"""
        import dataclasses
        from tests import lanes
        from tests.lanes import {helper}

        lanes.SKIP_REGISTRY.update({{
            name: dataclasses.replace(entry, no_ci="no job on purpose")
            for name, entry in lanes.SKIP_REGISTRY.items()
        }})
        @{helper}
        def test_platform_only(): assert False
        def test_runs(): pass
        """)
    assert result.ret == 0, result.stdout.str()
    result.stdout.fnmatch_lines([
        "NOT RUN BY ANY CI JOB (1):",
        "  NO CI *::test_platform_only: [[]declared:*] no job on purpose",
    ])


def test_a_declared_skip_where_its_condition_is_false_here_fails_the_run(sandbox):
    # An entry whose condition is false on this host: the tag is registered but the reason does not apply.
    # `name`'s condition is false on this host (so the skip hides a test that should run); `right`'s is true.
    name, right = ("posix-fork", "windows-security") if sys.platform != "win32" else ("windows-security", "posix-fork")
    result = _run(sandbox, f"""
        import pytest
        @pytest.mark.skipif(True, reason="[declared:{name}] misused")
        def test_misused(): pass
        @pytest.mark.skipif(True, reason="[declared:{right}] fine")
        def test_proper(): pass
        def test_runs(): pass
        """)
    assert result.ret != 0
    result.stdout.fnmatch_lines(["UNDECLARED SKIP *::test_misused: *[[]declared:" + name + "] used where its condition*is false*"])
