"""Focused setup and authentic installed generator/loader qualification.

The installed cohort is opt-in through HOST_PROFILE_TEST_PYTHON. It never starts
Runtime/Host/Worker. Adversarial documents are test-only copies of a generated
profile; installation metadata substitutions are read-only test doubles.
"""
import json
import os
from pathlib import Path
import subprocess

import pytest

from banodoco_local import cli
from banodoco_local.bootstrap import BootstrapError, SourceProfile
from banodoco_local.host_only_profile import _identity, _path


def test_identity_has_no_digest_self_reference(tmp_path):
    raw = {"capability_matrix": None, "host_executable": "/selected/python"}
    kwargs = dict(workspace_uuid="workspace", realm_root=tmp_path / "realm", support_root=tmp_path / "support")
    expected = _identity(raw, **kwargs)
    assert _identity({**raw, "profile_digest": "stale", "profile_revision": "stale"}, **kwargs) == expected
    assert _identity({**raw, "host_executable": "/other/python"}, **kwargs) != expected
    assert _identity(raw, **{**kwargs, "workspace_uuid": "other"}) != expected


def test_setup_rejects_alias_before_writing(tmp_path):
    target = tmp_path / "target"; target.mkdir()
    alias = tmp_path / "alias"; alias.symlink_to(target)
    with pytest.raises(BootstrapError, match="symlink"):
        _path(alias / "profile.json")
    assert list(target.iterdir()) == []


def test_record_pin_retains_installer_newline_bytes(monkeypatch, tmp_path):
    import hashlib
    import sys
    from types import SimpleNamespace
    from runtime_protocol.local_worker_composition import _installed_record_bytes
    path = tmp_path / "sample.dist-info/RECORD"
    path.parent.mkdir()
    payload = b"module.py,sha256=test,1\r\nsample.dist-info/RECORD,,\r\n"
    path.write_bytes(payload)
    distribution = SimpleNamespace(files=[Path("sample.dist-info/RECORD")],
        locate_file=lambda relative: tmp_path / relative, read_text=lambda name: path.read_text())
    monkeypatch.setattr(sys, "prefix", str(tmp_path))
    assert _installed_record_bytes(distribution) == payload
    assert hashlib.sha256(payload).hexdigest() != hashlib.sha256(distribution.read_text("RECORD").encode()).hexdigest()


@pytest.mark.parametrize('edge', ['valid', 'ambient-origin', 'missing-transitive'])
def test_producer_and_release_verifier_share_explicit_host_closure(tmp_path, monkeypatch, edge):
    from types import SimpleNamespace
    from banodoco_local import host_only_profile as producer
    from runtime_protocol import local_worker_composition as composition
    from runtime_protocol import verified_host_launch as gate
    from test_selected_python_inventory import write_host_records
    for relative in ('schemas/astrid-intent/astrid-intent.schema.json',
                     'astrid/core/rendering/schemas/v1/plan.json', 'astrid/packs/rendering/pack.yaml'):
        path = tmp_path/relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('{}')
    write_host_records(tmp_path)
    distributions = {gate.re.sub(r'[-_.]+', '-', d.metadata['Name']).lower(): d
                     for d in producer.metadata.distributions(path=[str(tmp_path)])}
    monkeypatch.setattr(producer.sys, 'prefix', str(tmp_path))
    monkeypatch.setattr(producer.sysconfig, 'get_path', lambda name: str(tmp_path))
    monkeypatch.setattr(producer.metadata, 'distribution', lambda name: distributions[name])
    def imported(name):
        relative = 'typing_extensions.py' if name == 'typing_extensions' else name+'/__init__.py'
        path = tmp_path/relative
        if edge == 'ambient-origin' and name == 'jsonschema': path = tmp_path.parent/'ambient/jsonschema/__init__.py'
        return SimpleNamespace(__file__=str(path))
    monkeypatch.setattr(producer.importlib, 'import_module', imported)
    if edge == 'missing-transitive':
        import shutil
        shutil.rmtree(Path(distributions['referencing']._path))
    if edge != 'valid':
        with pytest.raises((BootstrapError, gate.HostLaunchError)):
            producer._installed_inputs()
        return
    root, identities = producer._installed_inputs()
    assert set(identities) == set(gate.HOST_DISTRIBUTIONS)
    profile = SimpleNamespace(release_digest='sha256:'+gate.raw_digest(identities))
    assert composition._verify_installed_host_records(profile, {'source_checkout':str(root)}) == identities
    profile.release_digest = 'sha256:'+'0'*64
    from runtime_protocol.errors import ConflictError
    with pytest.raises(ConflictError, match='release digest differs'):
        composition._verify_installed_host_records(profile, {'source_checkout':str(root)})


def test_cli_provisions_existing_source_route_without_runtime(monkeypatch, tmp_path, capsys):
    captured = {}
    def provision(**kwargs):
        captured.update(kwargs)
        return SourceProfile("astrid", "/installed", "/installed", worker_profile=str(kwargs["worker_profile"]))
    monkeypatch.setattr(SourceProfile, "provision_host_only", provision)
    def forbidden(*a, **kw):
        pytest.fail("profile provisioning must not construct a runtime boundary")
    monkeypatch.setattr(cli, "LocalRuntimeBoundary", forbidden)
    assert cli.main(["provision-host-profile", "--data-root", str(tmp_path), "--workspace-uuid", "workspace",
                     "--realm-root", str(tmp_path / "realm"), "--max-concurrency", "2", "--no-capability-matrix", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["source_profile"]["worker_profile"] == str(tmp_path / "runtime/host-profiles/astrid.json")
    assert captured["capability_matrix"] is None and captured["max_concurrency"] == 2


def test_cli_reports_installed_refusal_as_error(monkeypatch, tmp_path, capsys):
    from runtime_protocol.errors import ConflictError
    def refuse(**kwargs):
        raise ConflictError("installed release file differs from RECORD")
    monkeypatch.setattr(SourceProfile, "provision_host_only", refuse)
    assert cli.main(["provision-host-profile", "--data-root", str(tmp_path), "--workspace-uuid", "workspace",
                     "--realm-root", str(tmp_path / "realm"), "--max-concurrency", "2", "--no-capability-matrix", "--json"]) == 1
    assert json.loads(capsys.readouterr().out) == {"ok": False, "error": "installed release file differs from RECORD"}


INSTALLED_CASES = [
    "roundtrip", "missing_record", "changed_record", "missing_record_entry", "missing_schema_record_entry",
    "missing_record_file", "changed_record_file",
    "mixed_metadata_root", "raw_import_origin", "editable_origin", "stale_source", "stale_profile",
    "stale_revision", "stale_session", "stale_boot", "stale_release", "stale_protocol", "escaped_pack",
    "substituted_interpreter", "substituted_kernel", "worker_field", "engine_field", "forged_preparation",
    "forged_activation", "stale_matrix", "stale_inventory", "symlink_output", "invalid_environment",
]


@pytest.mark.parametrize("case", INSTALLED_CASES)
def test_installed_generator_loader(case, tmp_path):
    python = os.environ.get("HOST_PROFILE_TEST_PYTHON")
    if not python:
        pytest.skip("select a task-owned noneditable installed environment")
    code = INSTALLED_DRIVER
    result = subprocess.run([python, "-I", "-B", "-c", code, case, str(tmp_path)],
                            cwd=tmp_path, capture_output=True, text=True)
    if result.returncode:
        pytest.fail(result.stdout + result.stderr)
    assert json.loads(result.stdout)["case"] == case


INSTALLED_DRIVER = r'''
import hashlib, importlib.metadata, json, os, pathlib, sys
from types import SimpleNamespace
from banodoco_local.bootstrap import SourceProfile
from banodoco_local import host_only_profile as producer
from runtime_protocol.local_worker import _selected_profile_payload
from runtime_protocol.verified_host_launch import raw_digest

case, temporary = sys.argv[1:]
refusal = None
root = pathlib.Path(temporary)
support = root / "support"; support.mkdir(mode=0o700)
worker = support / "profiles/astrid.json"; source_path = support / "source-profiles/astrid.json"
selections = dict(worker_profile=worker, source_manifest=source_path, workspace_uuid="test-workspace",
                  realm_root=root / "realm", support_root=support, max_concurrency=2, capability_matrix=None)
if case == "symlink_output":
    (support / "profiles").symlink_to(root)
    try: producer.provision_host_only_profile(**selections)
    except Exception as exc:
        assert "symlink" in str(exc)
        refusal = str(exc)
    else: raise AssertionError("accepted symlink output")
    assert not (root / "astrid.json").exists()
elif case == "invalid_environment":
    try: producer.provision_host_only_profile(**selections, environment={"PYTHONPATH": "/raw"})
    except Exception as exc:
        assert "environment" in str(exc)
        refusal = str(exc)
    else: raise AssertionError("accepted authority environment")
    assert not worker.exists() and not source_path.exists()
else:
    if case == "stale_matrix":
        # A selected ledger is validated by the production reader, then its
        # exact bytes are part of deterministic identity, even at the same path.
        matrix = support / "matrix.json"
        matrix.write_text('{"schema_version": 1, "capabilities": []}')
        selections["capability_matrix"] = matrix
    if case == "stale_inventory":
        extra = root / "extra"; extra.mkdir(); (extra / "pack.yaml").write_text("schema_version: 3\n")
        selections["additional_pack_roots"] = (extra,)
    source = producer.provision_host_only_profile(**selections)
    before = worker.read_bytes()
    producer.provision_host_only_profile(**selections)
    assert before == worker.read_bytes(), "producer is not deterministic"
    assert worker.stat().st_mode & 0o777 == 0o600
    assert source_path.stat().st_mode & 0o777 == 0o600
    assert SourceProfile.load(source_path) == source
    raw = json.loads(before)
    target = support / "adversarial.json"
    original_distribution = producer.metadata.distribution
    if case in {"missing_record", "changed_record", "missing_record_entry", "missing_schema_record_entry", "mixed_metadata_root", "editable_origin"}:
        class Distribution:
            def __init__(self, original): self.original = original
            def __getattr__(self, name): return getattr(self.original, name)
            def locate_file(self, value):
                return root if case == "mixed_metadata_root" and value == "" else self.original.locate_file(value)
            def read_text(self, name):
                value = self.original.read_text(name)
                if name == "direct_url.json" and case == "editable_origin": return '{"dir_info":{"editable":true}}'
                if name == "RECORD":
                    if case == "missing_record": return None
                    if case == "changed_record": return value + "unrecorded.py,,\n"
                    if case == "missing_record_entry": return "\n".join(row for row in value.splitlines() if not row.startswith("astrid/__init__.py,")) + "\n"
                    if case == "missing_schema_record_entry": return "\n".join(row for row in value.splitlines() if not row.startswith("schemas/astrid-intent/astrid-intent.schema.json,")) + "\n"
                return value
        producer.metadata.distribution = lambda name: Distribution(original_distribution(name))
    restoration = None
    if case == "raw_import_origin":
        import astrid
        astrid.__file__ = str(root / "raw/astrid/__init__.py")
    elif case in {"changed_record_file", "missing_record_file"}:
        # The only on-disk negative edits a test-owned installation file and
        # restores original bytes in finally. No RECORD/digest is fabricated.
        resource = pathlib.Path(raw["pack_root"]) / "shots/conformance.py"
        restoration = (resource, resource.read_bytes())
        if case == "missing_record_file": resource.unlink()
        else: resource.write_bytes(restoration[1] + b"\n# negative test\n")
    elif case == "stale_source": raw["host_protocol"]["source_closure_digest"] = "0" * 64
    elif case == "stale_profile": raw["profile_digest"] = "sha256:" + "0" * 64
    elif case == "stale_revision": raw["profile_revision"] = "stale"
    elif case == "stale_session": raw["session_config_digest"] = "sha256:" + "0" * 64
    elif case == "stale_boot": raw["boot_manifest_hash"] = "sha256:" + "0" * 64
    elif case == "stale_release": raw["release_digest"] = "sha256:" + "0" * 64
    elif case == "stale_protocol": raw["host_protocol"]["version"] = "stale/v0"
    elif case == "escaped_pack": raw["pack_root"] = str(root)
    elif case == "substituted_interpreter": raw["host_executable"] = str(pathlib.Path(sys.executable).resolve())
    elif case == "substituted_kernel": raw["host_os_artifact_digest"] = "sha256:" + "0" * 64
    elif case == "worker_field": raw["worker_executable"] = sys.executable
    elif case == "engine_field": raw["engine_launch"] = {}
    elif case == "forged_preparation": raw["preparation"] = {"status": "prepared"}
    elif case == "forged_activation": raw["activation"] = {"status": "active"}
    elif case == "stale_matrix": matrix.write_text(matrix.read_text() + "\n")
    elif case == "stale_inventory": (extra / "pack.yaml").write_text("changed\n")
    # Repair the adversary's session hash when changing a launch field, so
    # boot/pack controls reach the independent check instead of a trivial hash.
    if case in {"stale_boot", "escaped_pack"}:
        launch = {k: raw[k] for k in ("source_checkout", "pack_root", "boot_manifest_path", "boot_manifest_hash", "capability_matrix", "environment", "max_concurrency")}
        raw["session_config_digest"] = "sha256:" + raw_digest(launch)
    target.write_text(json.dumps(raw))
    try:
        composition = producer.qualify_host_only_profile(target, workspace_uuid="test-workspace", realm_root=root / "realm", support_root=support)
        assert case == "roundtrip", "accepted adversarial selection: " + case
        profile = composition.profiles["astrid"]
        assert profile.worker_executable is None and profile.engine_launch is None
        assert str(profile.host_executable) == os.path.abspath(sys.executable)
        _selected_profile_payload(profile)
        from runtime_protocol.verified_host_launch import installed_host_closure
        actual_records = installed_host_closure(raw["source_checkout"])["distributions"]
        assert profile.release_digest == "sha256:" + raw_digest(actual_records)
    except AssertionError: raise
    except Exception as exc:
        assert case != "roundtrip"
        expected = {
            "missing_record": "no RECORD", "changed_record": "RECORD metadata differs",
            "missing_record_entry": "missing from RECORD", "changed_record_file": "differs from RECORD",
            "missing_schema_record_entry": "resource is missing from RECORD",
            "missing_record_file": "file escapes selected environment",
            "mixed_metadata_root": "installed root", "raw_import_origin": "import origin",
            "editable_origin": "editable", "stale_source": "source closure differs",
            "stale_profile": "profile identity differs", "stale_revision": "profile identity differs",
            "stale_session": "configuration digest differs", "stale_boot": "boot manifest differs",
            "stale_release": "release digest differs", "stale_protocol": "shape/version/module/closure",
            "escaped_pack": "pack root is outside", "substituted_interpreter": "interpreter must be",
            "substituted_kernel": "interpreter/kernel artifact differs", "worker_field": "cannot declare",
            "engine_field": "cannot declare", "forged_preparation": "unsupported fields",
            "forged_activation": "unsupported fields", "stale_matrix": "profile identity differs",
            "stale_inventory": "inventory differs",
        }[case]
        assert expected in str(exc), (case, type(exc).__name__, str(exc))
        refusal = str(exc)
    finally:
        if restoration: restoration[0].write_bytes(restoration[1])
result = {"case": case, "ok": True, "refusal": refusal}
(root / "case-result.json").write_text(json.dumps(result, sort_keys=True) + "\n")
print(json.dumps(result))
'''


def test_loader_routes_optional_renderer_selection_only_to_host_mode(tmp_path, monkeypatch):
    from runtime_protocol import local_worker_composition as composition
    from runtime_protocol.errors import ValidationError
    profile = tmp_path/'selection.json'
    renderer = {"selected": "test router input, not an admission"}
    captured = []
    def load(raw, **kwargs):
        captured.append(raw)
        return "typed-host-loader"
    monkeypatch.setattr(composition, "_load_host_only_composition", load)
    profile.write_text(json.dumps({"execution_mode":"host_only_cpu", "renderer_selection":renderer}))
    kwargs = dict(workspace_uuid="test", realm_root=tmp_path, support_root=tmp_path, runtime_instance_id="test")
    assert composition.load_local_worker_composition(profile, **kwargs) == "typed-host-loader"
    assert captured[0]["renderer_selection"] == renderer
    profile.write_text(json.dumps({"execution_mode":"worker_engine", "renderer_selection":renderer}))
    with pytest.raises(ValidationError, match="host-only"):
        composition.load_local_worker_composition(profile, **kwargs)
    assert len(captured) == 1
