# Runtime collection, skip and result gates

## Declared selection and source census

CI passes every lane selection on the command line. The unit job uses
`-m "not integration and not darwin_native and not live"`; Nightly uses
`-m integration`, portability uses `-m ""`, and the sandbox retains its existing
explicit marker expression. These are the same selections the jobs previously
obtained from the default configuration. A direct pytest invocation without
`-m` now selects every marker rather than inheriting a configuration exclusion.

`scripts/ci/run_pytest.py` launches the protected absolute
`pytest_entrypoint.py` with `python -I -u`. Installed pytest is imported before
project and dependency paths are restored. The entrypoint captures its original
arguments in a frozen plugin before candidate conftests load. The controller
passes that same argument capture to xdist workers. Selection does not come
from mutable `config.option` or a replacement `config.invocation_params`.

Only literal command-line `-k` and `-m` tokens select tests; their normal
last-option-wins behavior is preserved. Nonempty `PYTEST_ADDOPTS`, alternate
pytest configuration files (`pytest.ini`, `tox.ini`, pytest TOML variants or a
pytest section in `setup.cfg`), argument files and command-line configuration
overrides fail closed. Pyproject remains the configuration source for naming,
test paths and ordinary reporting options, but its `addopts` cannot select
tests. Pyproject is an owner-protected gate input.

The collection guard reads the requested test source with AST before test
modules are imported. It counts definitions, including local class inheritance
and `unittest.TestCase` methods, without executing test code. Explicit file and
method selectors bound the census. Every expected definition must produce a
collected item: a module's `__test__ = False`, a `pycollect_makeitem` drop or an
ignore hook in a plugin cannot silently remove a definition. Parameterized
cases expand one source definition; the per-item inventory retains every case.

Keyword/marker matchers are captured when each item is first collected. The
guard independently computes the allowed selection and compares it after
collection hooks. Rewriting live selection options fails. An independent
collect-only run writes the selected IDs, command-line selection and static
definition count; execution must match that manifest. Hidden deselection and
undeclared ignore options remain forbidden.

## Historical authority for skips and quarantines

The existing strict xfail gate checks exact nodes, reasons, exception types and
expiry contracts against Git history. The static skip-binding check now also
compares both `tests/skip-bindings.json` and the live binding map with the Git
merge-base file. Entries may be removed; declaration/node pairs may not be
added, moved or self-approved by changing a marker and the JSON together.
Missing history, malformed data, duplicate entries and a missing base registry
fail closed. Candidate files never become their own historical allowance.

PR jobs use the target branch's merge base. Push jobs use the actual event's
immutable `before` SHA and verify that the event ref matches the pushed branch.
This covers every commit in a multi-commit push. Missing, zero or ambiguous
push authority fails, rather than comparing with an unrelated fixed plan
branch. Other branch events resolve their actual branch. The local fallback
remains `origin/release/14/plan-39`; callers may pass an explicit comparison
target to the history checker. The sandbox relays only this event metadata and
its read-only event file, never the job token.

**Initial registry prerequisite:** the introducing packet's plan base
`6cfe9a19024d73bdcbd7a428f5149f46259451a6` has no `skip-bindings.json`.
The live comparison therefore reports the missing immutable reference. The
Lead must establish the reviewed initial binding table in target history or
explicitly disposition that introducing-PR failure. There is no fallback to a
candidate table and no implied approval inherited from another repository.

## Trusted gate-path approval

The separate `Gate integrity` workflow is adapted from Agent #397. It runs on
`pull_request_target`, checks out only the trusted default-branch policy and
executes `python -I scripts/ci/protect_gate_paths.py`. It installs no project
code, has read-only contents/PR permissions and never checks out or imports the
candidate tree. The policy reads candidate Git blobs against their merge base.

Protected inputs include the runner, entrypoint, result verifier, collection
guard/policy, lane and quarantine code, binding JSON, gate regression tests,
conftests, workflows, worker setup, sandbox launcher/profile, dependency and
build configuration, fixture pin and CODEOWNERS files. Top-level modules that
could shadow the standard library or pytest also require review.

The repository variable `ASTRID_GATE_OWNERS` supplies explicit authorized GitHub
logins outside the candidate. A protected change requires an owner's latest
substantive formal review to be `APPROVED` for the exact current head SHA.
Old-head approvals, unconfigured reviewers, comments, later change requests
and dismissed approvals cannot authorize new gate bytes. Local mode grants no
approval; it is useful for injected negative checks.

**Trusted workflow installation is a Lead/owner integration prerequisite.**
The Lead must install the workflow and policy on the default branch, configure
the owner variable, and require this particular trusted workflow through the
organization ruleset for release destinations. A candidate-controlled job with
the same name is not equivalent. After an exact-head owner approval, rerun the
latest PR-triggered integrity job so it reads that review. This packet does not
push the default/target branches or change repository settings, and does not
claim the required-workflow protection is already deployed.

## Complete results and limits

The original result protocol is retained: independent collection JSON/log,
flushed report JSONL, actual JUnit testcases and the final console summary must
agree, with every selected test completed and a session-finish event. Failing
tests retain their failing status; interrupted streams remain incomplete.

The shared Lead threat model requires fail-closed handling of configuration,
markers, collection, selection, registries and inconsistent result evidence.
It does not isolate arbitrary code executing inside the test process. A
candidate that deliberately rewrites all result representations to agree or
replaces execution with a no-op remains a code-review/trusted-runner boundary.
Conftests and the gate code have explicit path protection for that reason.
Source-declared lane moves still require the lane-coverage review; one job's
census cannot establish that another job runs the moved test.
