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


def test_concurrent_module_logging_cannot_install_closed_stream_handler(monkeypatch):
    import contextlib
    import io
    import threading

    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level
    original = logging.NullHandler()
    stream = io.StringIO()
    trigger = threading.Event()
    done = threading.Event()
    real_remove = root.removeHandler

    def concurrent_log():
        trigger.wait()
        logging.warning("concurrent event")
        done.set()

    def remove_with_race(handler):
        real_remove(handler)
        if not root.handlers:
            trigger.set()
            assert done.wait(5)

    root.handlers = [original]
    monkeypatch.setattr(root, "removeHandler", remove_with_race)
    thread = threading.Thread(target=concurrent_log)
    thread.start()
    try:
        with contextlib.redirect_stderr(stream), cli._foreground_logging(stream):
            trigger.set()
            assert done.wait(5)
        stream.close()
        assert root.handlers == [original]
        assert not any(getattr(h, "stream", None) is stream for h in root.handlers)
    finally:
        trigger.set()
        thread.join(5)
        root.handlers = saved_handlers
        root.setLevel(saved_level)


def test_force_reconfiguration_does_not_retain_redirected_stream():
    import contextlib
    import io
    import threading

    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level
    original = logging.NullHandler()
    stream = io.StringIO()
    root.handlers = [original]
    try:
        with cli._foreground_logging(stream), contextlib.redirect_stderr(stream):
            thread = threading.Thread(target=lambda: logging.basicConfig(force=True))
            thread.start()
            thread.join(5)
            assert not thread.is_alive()
            assert any(getattr(h, "stream", None) is stream for h in root.handlers)
        stream.close()
        assert root.handlers == [original]
    finally:
        root.handlers = saved_handlers
        root.setLevel(saved_level)


def test_inflight_forced_handler_does_not_leak_after_foreground_closes(tmp_path, monkeypatch, capsys):
    import threading

    entered = threading.Event()
    resume = threading.Event()
    secret = "inflight-private-message-and-note"
    worker = None
    monkeypatch.setattr(cli, "platform", SimpleNamespace(
        log_dir=lambda _: tmp_path / "logs", owner_only=lambda _: None,
        install_stop_handlers=lambda _: lambda: None,
    ))
    monkeypatch.setattr(cli, "ForegroundRuntimeBoundary", lambda: SimpleNamespace(stop=lambda: None))

    def bootstrap(*_):
        nonlocal worker
        logging.basicConfig(force=True)
        handler = logging.getLogger().handlers[0]
        emit = handler.emit
        def delayed_emit(record):
            entered.set()
            assert resume.wait(5)
            emit(record)
        handler.emit = delayed_emit
        def log_exception():
            try:
                error = RuntimeError(secret)
                error.add_note(secret)
                raise error
            except RuntimeError:
                logging.exception("private record %s", secret)
        worker = threading.Thread(target=log_exception)
        worker.start()
        assert entered.wait(5)
        raise RuntimeError("stop")

    monkeypatch.setattr(cli, "bootstrap", bootstrap)
    try:
        assert cli._run_foreground(RuntimePaths.sandbox(tmp_path), cli.BootstrapConfig(), json_mode=True) == 1
    finally:
        resume.set()
        if worker:
            worker.join(5)
    assert worker and not worker.is_alive()
    assert secret not in capsys.readouterr().err
