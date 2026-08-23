import os
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from pydantic import TypeAdapter, ValidationError

from app.domain.reports import ScanReport
from app.jobs.errors import (
    InvalidScanTargetError,
    LostScanLeaseError,
    ScanCancelledError,
    ScanProcessError,
    ScanResultTooLargeError,
    ScanTimedOutError,
)
from app.scan_subprocess import (
    EXIT_INVALID_TARGET,
    EXIT_RESULT_TOO_LARGE,
    EXIT_SCAN_FAILED,
)

REPORT_ADAPTER = TypeAdapter(ScanReport)
BACKEND_ROOT = Path(__file__).resolve().parents[2]
POLL_INTERVAL_SECONDS = 0.1


class ScanExecutor(Protocol):
    def execute(
        self,
        target: str,
        *,
        should_cancel: Callable[[], bool],
        renew_lease: Callable[[], bool],
    ) -> ScanReport: ...


class ProcessScanExecutor:
    def __init__(
        self,
        *,
        timeout_seconds: int,
        heartbeat_seconds: int,
        result_limit_bytes: int,
        memory_limit_mb: int,
        terminate_grace_seconds: int,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.heartbeat_seconds = heartbeat_seconds
        self.result_limit_bytes = result_limit_bytes
        self.memory_limit_mb = memory_limit_mb
        self.terminate_grace_seconds = terminate_grace_seconds

    def execute(
        self,
        target: str,
        *,
        should_cancel: Callable[[], bool],
        renew_lease: Callable[[], bool],
    ) -> ScanReport:
        if should_cancel():
            raise ScanCancelledError

        with tempfile.TemporaryDirectory(prefix="coderisk-scan-") as workspace:
            output_path = Path(workspace) / "report.json"
            process = self._start_process(
                target=target,
                output_path=output_path,
                workspace=workspace,
            )

            try:
                self._wait_for_process(
                    process,
                    should_cancel=should_cancel,
                    renew_lease=renew_lease,
                )
            except BaseException:
                self._terminate_process(process)
                raise

            return self._read_report(process.returncode, output_path)

    def _start_process(
        self,
        *,
        target: str,
        output_path: Path,
        workspace: str,
    ) -> subprocess.Popen[bytes]:
        command = [
            sys.executable,
            "-m",
            "app.scan_subprocess",
            target,
            str(output_path),
            str(self.result_limit_bytes),
            str(self.memory_limit_mb),
            str(self.timeout_seconds + self.terminate_grace_seconds),
        ]
        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        return subprocess.Popen(
            command,
            cwd=workspace,
            env=_subprocess_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            creationflags=creation_flags,
        )

    def _wait_for_process(
        self,
        process: subprocess.Popen[bytes],
        *,
        should_cancel: Callable[[], bool],
        renew_lease: Callable[[], bool],
    ) -> None:
        deadline = time.monotonic() + self.timeout_seconds
        next_heartbeat = time.monotonic() + self.heartbeat_seconds

        while process.poll() is None:
            now = time.monotonic()

            if should_cancel():
                raise ScanCancelledError
            if now >= deadline:
                raise ScanTimedOutError
            if now >= next_heartbeat:
                if not renew_lease():
                    raise LostScanLeaseError
                next_heartbeat = now + self.heartbeat_seconds

            time.sleep(POLL_INTERVAL_SECONDS)

    def _terminate_process(self, process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return

        process.terminate()

        try:
            process.wait(timeout=self.terminate_grace_seconds)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

    def _read_report(self, return_code: int, output_path: Path) -> ScanReport:
        if return_code == EXIT_INVALID_TARGET:
            raise InvalidScanTargetError
        if return_code == EXIT_RESULT_TOO_LARGE:
            raise ScanResultTooLargeError
        if return_code == EXIT_SCAN_FAILED or return_code != 0:
            raise ScanProcessError
        if not output_path.is_file() or output_path.stat().st_size > self.result_limit_bytes:
            raise ScanProcessError

        try:
            return REPORT_ADAPTER.validate_json(output_path.read_bytes())
        except (OSError, ValidationError, ValueError) as error:
            raise ScanProcessError from error


def _subprocess_environment() -> dict[str, str]:
    allowed_keys = (
        "LANG",
        "LC_ALL",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "WINDIR",
    )
    environment = {key: os.environ[key] for key in allowed_keys if key in os.environ}
    environment["PYTHONIOENCODING"] = "utf-8"
    environment["PYTHONPATH"] = str(BACKEND_ROOT)
    return environment
