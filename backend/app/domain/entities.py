from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from app.domain.reports import Finding, FindingCategory, ScanReport, Severity

RepositoryTargetType = Literal["local_path", "github_url"]
ScanStatus = Literal["queued", "running", "completed", "failed", "cancelled"]
EngineRunStatus = Literal["running", "completed", "failed", "cancelled"]


@dataclass(frozen=True)
class ClaimedScan:
    id: str
    target: str
    target_type: RepositoryTargetType
    worker_id: str


@dataclass(frozen=True)
class Repository:
    id: str
    name: str
    target_type: RepositoryTargetType
    target: str
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class ScanSummary:
    id: str
    repository_id: str
    status: ScanStatus
    score: int | None
    total_files: int | None
    severity_counts: dict[str, int]
    scanned_at_utc: datetime | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    attempt_count: int = 0
    cancellation_requested_at: datetime | None = None


@dataclass(frozen=True)
class PersistedScan:
    summary: ScanSummary
    report: ScanReport | None
    engine_runs: list["EngineRun"]


@dataclass(frozen=True)
class PersistedFinding:
    id: str
    scan_id: str
    source_finding_id: str
    category: FindingCategory
    severity: Severity
    title: str
    file_path: str
    line: int | None
    evidence: str
    remediation: str
    created_at: datetime

    def to_report_finding(self) -> Finding:
        return Finding(
            id=self.source_finding_id,
            category=self.category,
            severity=self.severity,
            title=self.title,
            file_path=self.file_path,
            line=self.line,
            evidence=self.evidence,
            remediation=self.remediation,
        )


@dataclass(frozen=True)
class EngineRun:
    id: str
    scan_id: str
    engine: str
    engine_version: str
    status: EngineRunStatus
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
