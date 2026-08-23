import logging
import os
import socket
from threading import Event
from uuid import uuid4

from app.core.config import Settings
from app.db.session import Database
from app.domain.entities import ClaimedScan
from app.domain.reports import ScanReport
from app.jobs.errors import (
    InvalidScanTargetError,
    LostScanLeaseError,
    ScanCancelledError,
    ScanProcessError,
    ScanResultTooLargeError,
    ScanTimedOutError,
)
from app.jobs.executor import ProcessScanExecutor, ScanExecutor
from app.repositories.scans import ScanStore

logger = logging.getLogger(__name__)

INVALID_TARGET_MESSAGE = "Repo path must point to an existing directory."
SCAN_FAILURE_MESSAGE = "The built-in scanner could not read the repository."
SCAN_TIMEOUT_MESSAGE = "The scan exceeded its configured time limit."
SCAN_RESULT_LIMIT_MESSAGE = "The scan result exceeded its configured size limit."


class ScanWorker:
    def __init__(
        self,
        database: Database,
        settings: Settings,
        *,
        worker_id: str | None = None,
        executor: ScanExecutor | None = None,
    ) -> None:
        self.database = database
        self.settings = settings
        self.worker_id = worker_id or _new_worker_id()
        self.stop_event: Event | None = None
        self.executor = executor or ProcessScanExecutor(
            timeout_seconds=settings.scan_timeout_seconds,
            heartbeat_seconds=settings.scan_heartbeat_seconds,
            result_limit_bytes=settings.scan_result_limit_bytes,
            memory_limit_mb=settings.scan_memory_limit_mb,
            terminate_grace_seconds=settings.scan_terminate_grace_seconds,
        )

    def run_once(self) -> bool:
        self._recover_expired_scans()
        claimed_scan = self._claim_next_scan()

        if claimed_scan is None:
            return False

        try:
            report = self.executor.execute(
                claimed_scan.target,
                should_cancel=lambda: self._cancellation_requested(claimed_scan),
                renew_lease=lambda: self._renew_lease(claimed_scan),
            )
        except ScanCancelledError:
            self._cancel_scan(claimed_scan)
        except LostScanLeaseError:
            return True
        except InvalidScanTargetError:
            self._fail_scan(claimed_scan, INVALID_TARGET_MESSAGE)
        except ScanTimedOutError:
            self._fail_scan(claimed_scan, SCAN_TIMEOUT_MESSAGE)
        except ScanResultTooLargeError:
            self._fail_scan(claimed_scan, SCAN_RESULT_LIMIT_MESSAGE)
        except ScanProcessError:
            self._fail_scan(claimed_scan, SCAN_FAILURE_MESSAGE)
        except Exception:
            self._fail_scan(claimed_scan, SCAN_FAILURE_MESSAGE)
        else:
            self._complete_scan(claimed_scan, report)

        return True

    def run_forever(self, stop_event: Event) -> None:
        self.stop_event = stop_event

        while not stop_event.is_set():
            try:
                processed_scan = self.run_once()
            except Exception as error:
                logger.error("Scan worker iteration failed: %s", type(error).__name__)
                processed_scan = False

            if not processed_scan:
                stop_event.wait(self.settings.scan_poll_interval_seconds)

    def _recover_expired_scans(self) -> None:
        with self.database.session_factory() as session:
            ScanStore(session).recover_expired_scans(max_attempts=self.settings.scan_max_attempts)
            session.commit()

    def _claim_next_scan(self) -> ClaimedScan | None:
        with self.database.session_factory() as session:
            scan = ScanStore(session).claim_next_scan(
                worker_id=self.worker_id,
                lease_seconds=self.settings.scan_lease_seconds,
                max_attempts=self.settings.scan_max_attempts,
            )
            session.commit()
            return scan

    def _cancellation_requested(self, scan: ClaimedScan) -> bool:
        with self.database.session_factory() as session:
            return ScanStore(session).cancellation_requested(scan.id, scan.worker_id)

    def _renew_lease(self, scan: ClaimedScan) -> bool:
        if self.stop_event is not None and self.stop_event.is_set():
            return False

        with self.database.session_factory() as session:
            renewed = ScanStore(session).renew_lease(
                scan.id,
                scan.worker_id,
                lease_seconds=self.settings.scan_lease_seconds,
            )
            session.commit()
            return renewed

    def _complete_scan(self, scan: ClaimedScan, report: ScanReport) -> None:
        with self.database.session_factory() as session:
            try:
                ScanStore(session).complete_scan(
                    scan.id,
                    report,
                    worker_id=scan.worker_id,
                )
                session.commit()
            except LostScanLeaseError:
                session.rollback()

    def _fail_scan(self, scan: ClaimedScan, error_message: str) -> None:
        with self.database.session_factory() as session:
            try:
                ScanStore(session).fail_scan(
                    scan.id,
                    error_message,
                    worker_id=scan.worker_id,
                )
                session.commit()
            except LostScanLeaseError:
                session.rollback()

    def _cancel_scan(self, scan: ClaimedScan) -> None:
        with self.database.session_factory() as session:
            try:
                ScanStore(session).cancel_claimed_scan(scan.id, scan.worker_id)
                session.commit()
            except LostScanLeaseError:
                session.rollback()


def _new_worker_id() -> str:
    hostname = socket.gethostname()[:64]
    return f"{hostname}-{os.getpid()}-{uuid4().hex[:12]}"
