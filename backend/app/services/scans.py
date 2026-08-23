from pathlib import Path

from sqlalchemy.orm import Session

from app.core.errors import InvalidTargetError, ResourceNotFoundError, ScanExecutionError
from app.domain.entities import (
    PersistedFinding,
    PersistedScan,
    Repository,
    RepositoryTargetType,
    ScanStatus,
    ScanSummary,
)
from app.domain.reports import FindingCategory, ScanReport, Severity
from app.repositories.scans import ScanStore
from app.scanner import scan_repository

GITHUB_DISABLED_MESSAGE = "GitHub URL scanning is planned, but remote clone is disabled in the MVP."
INVALID_LOCAL_PATH_MESSAGE = "Repo path must point to an existing directory."
SCAN_FAILURE_MESSAGE = "The built-in scanner could not read the repository."


class ScanService:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.store = ScanStore(session)

    def create_repository(
        self,
        *,
        target: str,
        target_type: RepositoryTargetType,
    ) -> tuple[Repository, bool]:
        name, normalized_target = _normalize_target(target, target_type)
        repository, created = self.store.get_or_create_repository(
            name=name,
            target_type=target_type,
            target=normalized_target,
        )
        self.session.commit()
        return repository, created

    def list_repositories(self, *, offset: int, limit: int) -> tuple[list[Repository], int]:
        return self.store.list_repositories(offset=offset, limit=limit)

    def get_repository(self, repository_id: str) -> Repository:
        repository = self.store.get_repository(repository_id)

        if repository is None:
            raise ResourceNotFoundError("Repository was not found.")

        return repository

    def enqueue_scan(self, repository_id: str) -> ScanSummary:
        repository = self.get_repository(repository_id)
        scan = self.store.begin_scan(repository.id)
        self.session.commit()
        return scan

    def run_scan(self, repository_id: str) -> PersistedScan:
        repository = self.get_repository(repository_id)
        scan = self.store.begin_scan(repository.id)
        self.session.commit()

        try:
            report = scan_repository(repository.target)
        except ValueError as error:
            self.store.fail_scan(scan.id, str(error))
            self.session.commit()
            raise InvalidTargetError(str(error)) from error
        except Exception as error:
            self.store.fail_scan(scan.id, SCAN_FAILURE_MESSAGE)
            self.session.commit()
            raise ScanExecutionError(SCAN_FAILURE_MESSAGE) from error

        persisted_scan = self.store.complete_scan(scan.id, report)
        self.session.commit()
        return persisted_scan

    def scan_target(
        self,
        *,
        target: str,
        target_type: RepositoryTargetType,
    ) -> PersistedScan:
        repository, _ = self.create_repository(target=target, target_type=target_type)
        return self.run_scan(repository.id)

    def cancel_scan(self, scan_id: str) -> None:
        self.store.request_cancellation(scan_id)
        self.session.commit()

    def get_scan(self, scan_id: str) -> PersistedScan:
        scan = self.store.get_scan(scan_id)

        if scan is None:
            raise ResourceNotFoundError("Scan was not found.")

        return scan

    def get_latest_completed_scan(self) -> PersistedScan:
        scan = self.store.get_latest_completed_scan()

        if scan is None:
            raise ResourceNotFoundError("No scan report exists yet.")

        return scan

    def list_scans(
        self,
        *,
        offset: int,
        limit: int,
        repository_id: str | None = None,
        status: ScanStatus | None = None,
        severity: Severity | None = None,
    ) -> tuple[list[ScanSummary], int]:
        return self.store.list_scans(
            offset=offset,
            limit=limit,
            repository_id=repository_id,
            status=status,
            severity=severity,
        )

    def list_findings(
        self,
        scan_id: str,
        *,
        offset: int,
        limit: int,
        severity: Severity | None = None,
        category: FindingCategory | None = None,
    ) -> tuple[list[PersistedFinding], int]:
        self.get_scan(scan_id)
        return self.store.list_findings(
            scan_id,
            offset=offset,
            limit=limit,
            severity=severity,
            category=category,
        )

    def get_report(self, scan_id: str) -> ScanReport:
        scan = self.get_scan(scan_id)

        if scan.report is None:
            raise ResourceNotFoundError("The scan does not have a completed report.")

        return scan.report


def _normalize_target(
    target: str,
    target_type: RepositoryTargetType,
) -> tuple[str, str]:
    if target_type == "github_url":
        raise InvalidTargetError(GITHUB_DISABLED_MESSAGE)

    try:
        root = Path(target).expanduser().resolve()
    except (OSError, RuntimeError) as error:
        raise InvalidTargetError(INVALID_LOCAL_PATH_MESSAGE) from error

    if not root.exists() or not root.is_dir():
        raise InvalidTargetError(INVALID_LOCAL_PATH_MESSAGE)

    return root.name, str(root)
