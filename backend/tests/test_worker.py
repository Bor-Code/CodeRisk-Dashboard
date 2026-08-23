import time
from datetime import timedelta
from pathlib import Path
from threading import Event, Thread

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.db.base import utc_now
from app.db.models import ScanModel
from app.domain.reports import ScanReport
from app.jobs.errors import (
    InvalidScanTargetError,
    LostScanLeaseError,
    ScanCancelledError,
    ScanResultTooLargeError,
    ScanTimedOutError,
)
from app.jobs.executor import ProcessScanExecutor, _subprocess_environment
from app.jobs.worker import (
    INVALID_TARGET_MESSAGE,
    SCAN_RESULT_LIMIT_MESSAGE,
    SCAN_TIMEOUT_MESSAGE,
    ScanWorker,
)
from app.repositories.scans import WORKER_RETRY_EXHAUSTED_MESSAGE, ScanStore
from app.scanner import scan_repository


@pytest.fixture
def scan_worker(client: TestClient, test_settings: Settings) -> ScanWorker:
    return ScanWorker(client.app.state.database, test_settings, worker_id="test-worker")


def _make_repository(tmp_path: Path) -> Path:
    repository = tmp_path / "worker-repository"
    repository.mkdir()
    (repository / ".gitignore").write_text(".env\n", encoding="utf-8")
    (repository / "pyproject.toml").write_text(
        "[project]\nname = 'worker-test'\n",
        encoding="utf-8",
    )
    return repository


def _enqueue_scan(client: TestClient, repository: Path) -> str:
    repository_response = client.post(
        "/api/v1/repositories",
        json={"target": str(repository), "target_type": "local_path"},
    )
    scan_response = client.post(f"/api/v1/repositories/{repository_response.json()['id']}/scans")
    assert scan_response.status_code == 202
    scan_id = scan_response.json()["id"]
    assert scan_response.headers["location"] == f"/api/v1/scans/{scan_id}"
    return scan_id


class ImmediateExecutor:
    def execute(self, target: str, **callbacks) -> ScanReport:
        assert callbacks["should_cancel"]() is False
        assert callbacks["renew_lease"]() is True
        return scan_repository(target)


class AwaitCancellationExecutor:
    def __init__(self) -> None:
        self.started = Event()

    def execute(self, _target: str, **callbacks) -> ScanReport:
        self.started.set()
        deadline = time.monotonic() + 5

        while time.monotonic() < deadline:
            if callbacks["should_cancel"]():
                raise ScanCancelledError
            time.sleep(0.01)

        raise AssertionError("Cancellation was not observed by the worker.")


class AwaitReleaseExecutor:
    def __init__(self) -> None:
        self.started = Event()
        self.release = Event()
        self.execution_count = 0

    def execute(self, target: str, **_callbacks) -> ScanReport:
        self.execution_count += 1
        self.started.set()
        if not self.release.wait(timeout=5):
            raise AssertionError("The test did not release the scan executor.")
        return scan_repository(target)


class RaisingExecutor:
    def __init__(self, error_type: type[Exception]) -> None:
        self.error_type = error_type

    def execute(self, _target: str, **_callbacks) -> ScanReport:
        raise self.error_type


def test_worker_recovers_expired_lease_and_retries_scan(
    client: TestClient,
    test_settings: Settings,
    tmp_path: Path,
) -> None:
    scan_id = _enqueue_scan(client, _make_repository(tmp_path))
    database = client.app.state.database

    with database.session_factory() as session:
        claimed = ScanStore(session).claim_next_scan(
            worker_id="expired-worker",
            lease_seconds=test_settings.scan_lease_seconds,
            max_attempts=test_settings.scan_max_attempts,
        )
        assert claimed is not None
        session.commit()

    with database.session_factory() as session:
        model = session.get(ScanModel, scan_id)
        assert model is not None
        model.lease_expires_at = utc_now() - timedelta(seconds=1)
        session.commit()

    worker = ScanWorker(
        database,
        test_settings,
        worker_id="recovery-worker",
        executor=ImmediateExecutor(),
    )
    assert worker.run_once() is True

    detail = client.get(f"/api/v1/scans/{scan_id}").json()
    assert detail["status"] == "completed"
    assert detail["attempt_count"] == 2
    assert detail["engine_runs"][0]["status"] == "completed"


def test_running_scan_cannot_be_claimed_by_second_worker(
    client: TestClient,
    test_settings: Settings,
    tmp_path: Path,
) -> None:
    scan_id = _enqueue_scan(client, _make_repository(tmp_path))
    executor = AwaitReleaseExecutor()
    first_worker = ScanWorker(
        client.app.state.database,
        test_settings,
        worker_id="first-worker",
        executor=executor,
    )
    second_worker = ScanWorker(
        client.app.state.database,
        test_settings,
        worker_id="second-worker",
        executor=ImmediateExecutor(),
    )
    thread = Thread(target=first_worker.run_once)

    thread.start()
    assert executor.started.wait(timeout=5)
    assert second_worker.run_once() is False
    executor.release.set()
    thread.join(timeout=5)

    assert not thread.is_alive()
    assert executor.execution_count == 1
    detail = client.get(f"/api/v1/scans/{scan_id}").json()
    assert detail["status"] == "completed"
    assert detail["attempt_count"] == 1


def test_worker_fails_scan_after_retry_budget_is_exhausted(
    client: TestClient,
    test_settings: Settings,
    tmp_path: Path,
) -> None:
    scan_id = _enqueue_scan(client, _make_repository(tmp_path))
    database = client.app.state.database
    single_attempt_settings = test_settings.model_copy(update={"scan_max_attempts": 1})

    with database.session_factory() as session:
        claimed = ScanStore(session).claim_next_scan(
            worker_id="expired-worker",
            lease_seconds=single_attempt_settings.scan_lease_seconds,
            max_attempts=single_attempt_settings.scan_max_attempts,
        )
        assert claimed is not None
        session.commit()

    with database.session_factory() as session:
        model = session.get(ScanModel, scan_id)
        assert model is not None
        model.lease_expires_at = utc_now() - timedelta(seconds=1)
        session.commit()

    worker = ScanWorker(
        database,
        single_attempt_settings,
        worker_id="recovery-worker",
        executor=ImmediateExecutor(),
    )
    assert worker.run_once() is False

    detail = client.get(f"/api/v1/scans/{scan_id}").json()
    assert detail["status"] == "failed"
    assert detail["error_message"] == WORKER_RETRY_EXHAUSTED_MESSAGE
    assert detail["engine_runs"][0]["status"] == "failed"


def test_worker_persists_safe_error_when_target_disappears(
    client: TestClient,
    scan_worker: ScanWorker,
    tmp_path: Path,
) -> None:
    repository = _make_repository(tmp_path)
    scan_id = _enqueue_scan(client, repository)
    for path in repository.iterdir():
        path.unlink()
    repository.rmdir()

    assert scan_worker.run_once() is True

    detail = client.get(f"/api/v1/scans/{scan_id}").json()
    assert detail["status"] == "failed"
    assert detail["error_message"] == INVALID_TARGET_MESSAGE
    assert detail["engine_runs"][0]["status"] == "failed"


@pytest.mark.parametrize(
    ("error_type", "error_message"),
    [
        (ScanTimedOutError, SCAN_TIMEOUT_MESSAGE),
        (ScanResultTooLargeError, SCAN_RESULT_LIMIT_MESSAGE),
    ],
)
def test_worker_persists_bounded_executor_failures(
    client: TestClient,
    test_settings: Settings,
    tmp_path: Path,
    error_type: type[Exception],
    error_message: str,
) -> None:
    scan_id = _enqueue_scan(client, _make_repository(tmp_path))
    worker = ScanWorker(
        client.app.state.database,
        test_settings,
        worker_id="bounded-failure-worker",
        executor=RaisingExecutor(error_type),
    )

    assert worker.run_once() is True

    detail = client.get(f"/api/v1/scans/{scan_id}").json()
    assert detail["status"] == "failed"
    assert detail["error_message"] == error_message


def test_running_scan_cancellation_stops_worker_execution(
    client: TestClient,
    test_settings: Settings,
    tmp_path: Path,
) -> None:
    scan_id = _enqueue_scan(client, _make_repository(tmp_path))
    executor = AwaitCancellationExecutor()
    worker = ScanWorker(
        client.app.state.database,
        test_settings,
        worker_id="cancellation-worker",
        executor=executor,
    )
    errors: list[BaseException] = []

    def run_worker() -> None:
        try:
            worker.run_once()
        except BaseException as error:
            errors.append(error)

    thread = Thread(target=run_worker)
    thread.start()
    assert executor.started.wait(timeout=5)

    cancel_response = client.post(f"/api/v1/scans/{scan_id}/cancel")
    thread.join(timeout=5)

    assert cancel_response.status_code == 202
    assert cancel_response.json()["status"] == "cancelling"
    assert not thread.is_alive()
    assert errors == []

    detail = client.get(f"/api/v1/scans/{scan_id}").json()
    assert detail["status"] == "cancelled"
    assert detail["cancellation_requested_at"] is not None
    assert detail["engine_runs"][0]["status"] == "cancelled"


def test_stale_cancellation_cannot_reopen_completed_scan(
    client: TestClient,
    scan_worker: ScanWorker,
    tmp_path: Path,
) -> None:
    scan_id = _enqueue_scan(client, _make_repository(tmp_path))
    database = client.app.state.database

    with database.session_factory() as stale_session:
        store = ScanStore(stale_session)
        stale_scan = store.get_scan(scan_id)
        assert stale_scan is not None
        assert stale_scan.summary.status == "queued"

        assert scan_worker.run_once() is True
        store.request_cancellation(scan_id)
        stale_session.commit()
        cancellation_result = store.get_scan(scan_id)

    assert cancellation_result.summary.status == "completed"
    detail = client.get(f"/api/v1/scans/{scan_id}").json()
    assert detail["status"] == "completed"
    assert detail["cancellation_requested_at"] is None


def test_process_executor_enforces_cancellation_timeout_and_result_limit(
    tmp_path: Path,
) -> None:
    repository = _make_repository(tmp_path)
    executor = ProcessScanExecutor(
        timeout_seconds=10,
        heartbeat_seconds=1,
        result_limit_bytes=1024 * 1024,
        memory_limit_mb=512,
        terminate_grace_seconds=1,
    )

    with pytest.raises(ScanCancelledError):
        executor.execute(
            str(repository),
            should_cancel=lambda: True,
            renew_lease=lambda: True,
        )

    with pytest.raises(InvalidScanTargetError):
        executor.execute(
            str(tmp_path / "missing"),
            should_cancel=lambda: False,
            renew_lease=lambda: True,
        )

    timeout_executor = ProcessScanExecutor(
        timeout_seconds=0,
        heartbeat_seconds=1,
        result_limit_bytes=1024 * 1024,
        memory_limit_mb=512,
        terminate_grace_seconds=1,
    )
    with pytest.raises(ScanTimedOutError):
        timeout_executor.execute(
            str(repository),
            should_cancel=lambda: False,
            renew_lease=lambda: True,
        )

    limited_executor = ProcessScanExecutor(
        timeout_seconds=10,
        heartbeat_seconds=1,
        result_limit_bytes=1,
        memory_limit_mb=512,
        terminate_grace_seconds=1,
    )
    with pytest.raises(ScanResultTooLargeError):
        limited_executor.execute(
            str(repository),
            should_cancel=lambda: False,
            renew_lease=lambda: True,
        )


def test_process_executor_terminates_when_worker_loses_lease(tmp_path: Path) -> None:
    repository = _make_repository(tmp_path)
    executor = ProcessScanExecutor(
        timeout_seconds=10,
        heartbeat_seconds=0,
        result_limit_bytes=1024 * 1024,
        memory_limit_mb=512,
        terminate_grace_seconds=1,
    )

    with pytest.raises(LostScanLeaseError):
        executor.execute(
            str(repository),
            should_cancel=lambda: False,
            renew_lease=lambda: False,
        )


def test_scan_subprocess_environment_excludes_application_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CODERISK_DATABASE_URL", "postgresql+psycopg://user:secret@database/app")
    monkeypatch.setenv("UNRELATED_SECRET", "sensitive")

    environment = _subprocess_environment()

    assert "CODERISK_DATABASE_URL" not in environment
    assert "UNRELATED_SECRET" not in environment
    assert environment["PYTHONPATH"]
