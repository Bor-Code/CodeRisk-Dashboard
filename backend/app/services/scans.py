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

    def ignore_finding(
        self, repository_id: str, source_finding_id: str, reason: str | None = None
    ) -> None:
        self.get_repository(repository_id)
        self.store.ignore_finding(repository_id, source_finding_id, reason)
        self.session.commit()

    def unignore_finding(self, repository_id: str, source_finding_id: str) -> None:
        self.get_repository(repository_id)
        self.store.unignore_finding(repository_id, source_finding_id)
        self.session.commit()

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

    def get_scan_diff(self, scan_id: str) -> dict[str, list[PersistedFinding]]:
        current_scan = self.get_scan(scan_id)
        if current_scan.status != "completed":
            return {"new": [], "resolved": [], "persistent": []}

        previous_scan = self.store.get_previous_completed_scan(
            current_scan.summary.repository_id, current_scan.id
        )

        current_findings, _ = self.list_findings(scan_id, offset=0, limit=10000)
        current_finding_ids = {f.source_finding_id: f for f in current_findings}

        if previous_scan is None:
            return {
                "new": current_findings,
                "resolved": [],
                "persistent": [],
            }

        previous_findings, _ = self.list_findings(previous_scan.id, offset=0, limit=10000)
        previous_finding_ids = {f.source_finding_id: f for f in previous_findings}

        new_findings = [
            f for f in current_findings if f.source_finding_id not in previous_finding_ids
        ]
        persistent_findings = [
            f for f in current_findings if f.source_finding_id in previous_finding_ids
        ]
        resolved_findings = [
            f for f in previous_findings if f.source_finding_id not in current_finding_ids
        ]

        return {
            "new": new_findings,
            "resolved": resolved_findings,
            "persistent": persistent_findings,
        }


def _normalize_target(
    target: str,
    target_type: RepositoryTargetType,
) -> tuple[str, str]:
    if target_type == "github_url":
        from app.services.github import validate_github_url  # noqa: PLC0415

        try:
            url = validate_github_url(target)
        except ValueError as error:
            raise InvalidTargetError(str(error)) from error

        repo_name = url.split("/")[-1].removesuffix(".git")
        return repo_name, url

    try:
        root = Path(target).expanduser().resolve()
    except (OSError, RuntimeError) as error:
        raise InvalidTargetError(INVALID_LOCAL_PATH_MESSAGE) from error

    if not root.exists() or not root.is_dir():
        raise InvalidTargetError(INVALID_LOCAL_PATH_MESSAGE)

    return root.name, str(root)
