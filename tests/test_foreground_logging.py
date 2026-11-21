"""Foreground logging must not retain closed streams or disclose failed records."""
import logging
from types import SimpleNamespace


from astrid_runtime import cli
from astrid_runtime.paths import RuntimePaths


def test_foreground_restores_logging_and_records_timing(tmp_path, monkeypatch):
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    monkeypatch.setattr(cli, "platform", SimpleNamespace(
        log_dir=lambda _: tmp_path / "logs", owner_only=lambda _: None,
        install_stop_handlers=lambda _: lambda: None,
    ))
    monkeypatch.setattr(cli, "ForegroundRuntimeBoundary", lambda: SimpleNamespace(stop=lambda: None))
    def bootstrap(*_):
        logging.getLogger("runtime.test").info("timing event")
        raise RuntimeError("stop")
    monkeypatch.setattr(cli, "bootstrap", bootstrap)
    assert cli._run_foreground(RuntimePaths.sandbox(tmp_path), cli.BootstrapConfig(), json_mode=True) == 1
    assert root.handlers == handlers
    assert root.level == level
    assert " INFO runtime.test timing event" in (tmp_path / "logs/runtime.log").read_text()
    assert all(not getattr(h.stream, "closed", False) for h in root.handlers if hasattr(h, "stream"))


def test_foreground_logging_write_failure_never_prints_exception(capsys):
    class BrokenStream:
        def write(self, _): raise OSError("failed")
        def flush(self): pass
    secret = "provider-private-message-and-note"
    with cli._foreground_logging(BrokenStream()):
        try:
            error = RuntimeError(secret)
            error.add_note(secret)
            raise error
        except RuntimeError:
            logging.getLogger("runtime.test").exception("record " + secret)
    assert secret not in capsys.readouterr().err
