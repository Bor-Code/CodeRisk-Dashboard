import json
import signal
import sys
from pathlib import Path

import pytest

from app import scan_subprocess
from app import worker as worker_entrypoint


def _subprocess_arguments(repository: Path, output: Path, result_limit: int) -> list[str]:
    return [
        "scan_subprocess",
        str(repository),
        str(output),
        str(result_limit),
        "512",
        "10",
    ]


def test_scan_subprocess_writes_valid_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "pyproject.toml").write_text(
        "[project]\nname = 'entrypoint-test'\n",
        encoding="utf-8",
    )
    output = tmp_path / "report.json"
    monkeypatch.setattr(scan_subprocess, "_apply_resource_limits", lambda **_limits: None)
    monkeypatch.setattr(
        sys,
        "argv",
        _subprocess_arguments(repository, output, 1024 * 1024),
    )

    assert scan_subprocess.main() == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["metadata"]["name"] == "repository"


def test_scan_subprocess_returns_bounded_exit_codes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    output = tmp_path / "report.json"
    monkeypatch.setattr(scan_subprocess, "_apply_resource_limits", lambda **_limits: None)

    monkeypatch.setattr(sys, "argv", ["scan_subprocess"])
    assert scan_subprocess.main() == scan_subprocess.EXIT_SCAN_FAILED

    monkeypatch.setattr(
        sys,
        "argv",
        _subprocess_arguments(tmp_path / "missing", output, 1024 * 1024),
    )
    assert scan_subprocess.main() == scan_subprocess.EXIT_INVALID_TARGET

    monkeypatch.setattr(sys, "argv", _subprocess_arguments(repository, output, 1))
    assert scan_subprocess.main() == scan_subprocess.EXIT_RESULT_TOO_LARGE

    def fail_scan(_target: str):
        raise OSError("private filesystem detail")

    monkeypatch.setattr(scan_subprocess, "scan_repository", fail_scan)
    monkeypatch.setattr(
        sys,
        "argv",
        _subprocess_arguments(repository, output, 1024 * 1024),
    )
    assert scan_subprocess.main() == scan_subprocess.EXIT_SCAN_FAILED


class FakeEngine:
    def __init__(self) -> None:
        self.disposed = False

    def dispose(self) -> None:
        self.disposed = True


class FakeDatabase:
    def __init__(self) -> None:
        self.engine = FakeEngine()


class FakeSettings:
    database_auto_create = False


def _configure_worker_entrypoint(
    monkeypatch: pytest.MonkeyPatch,
    worker_class: type,
) -> FakeDatabase:
    database = FakeDatabase()
    monkeypatch.setattr(worker_entrypoint, "get_settings", FakeSettings)
    monkeypatch.setattr(worker_entrypoint, "create_database", lambda _settings: database)
    monkeypatch.setattr(worker_entrypoint, "prepare_database", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(worker_entrypoint, "ScanWorker", worker_class)
    return database


def test_worker_entrypoint_processes_one_job_and_disposes_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class FakeWorker:
        def __init__(self, _database: FakeDatabase, _settings: FakeSettings) -> None:
            pass

        def run_once(self) -> bool:
            calls.append("run_once")
            return False

    database = _configure_worker_entrypoint(monkeypatch, FakeWorker)
    monkeypatch.setattr(sys, "argv", ["worker", "--once"])

    worker_entrypoint.main()

    assert calls == ["run_once"]
    assert database.engine.disposed is True


def test_worker_entrypoint_installs_shutdown_handlers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handlers = {}

    class FakeWorker:
        def __init__(self, _database: FakeDatabase, _settings: FakeSettings) -> None:
            pass

        def run_forever(self, stop_event) -> None:
            handlers[signal.SIGTERM](signal.SIGTERM, None)
            assert stop_event.is_set()

    database = _configure_worker_entrypoint(monkeypatch, FakeWorker)
    monkeypatch.setattr(sys, "argv", ["worker"])
    monkeypatch.setattr(
        worker_entrypoint.signal,
        "signal",
        lambda signal_number, handler: handlers.__setitem__(signal_number, handler),
    )

    worker_entrypoint.main()

    assert signal.SIGINT in handlers
    assert signal.SIGTERM in handlers
    assert database.engine.disposed is True
