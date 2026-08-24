from datetime import datetime
from typing import Generic, TypeVar

from pydantic import BaseModel, Field

from app.domain.entities import (
    EngineRun,
    EngineRunStatus,
    PersistedFinding,
    PersistedScan,
    Repository,
    RepositoryTargetType,
    ScanStatus,
    ScanSummary,
)
from app.domain.reports import Finding, FindingCategory, RepoMetadata, ScanReport, Severity

T = TypeVar("T")


class ProblemDetail(BaseModel):
    type: str
    title: str
    status: int
    detail: str
    instance: str
    code: str


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    offset: int
    limit: int


class RepositoryCreateRequest(BaseModel):
    target: str = Field(min_length=1)
    target_type: RepositoryTargetType = "local_path"


class IgnoreFindingRequest(BaseModel):
    source_finding_id: str
    reason: str | None = None


class RepositoryResponse(BaseModel):
    id: str
    name: str
    target_type: RepositoryTargetType
    target: str
    created_at: datetime
    updated_at: datetime


class SeverityCountsResponse(BaseModel):
    high: int
    medium: int
    low: int
    info: int


class ScanSummaryResponse(BaseModel):
    id: str
    repository_id: str
    status: ScanStatus
    score: int | None
    total_files: int | None
    severity_counts: SeverityCountsResponse
    scanned_at_utc: datetime | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    attempt_count: int
    cancellation_requested_at: datetime | None = None


class EngineRunResponse(BaseModel):
    id: str
    scan_id: str
    engine: str
    engine_version: str
    status: EngineRunStatus
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None


class ScanDetailResponse(ScanSummaryResponse):
    dependency_files: list[str]
    file_tree: list[str]
    finding_count: int
    engine_runs: list[EngineRunResponse]


class FindingResponse(BaseModel):
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
    engine_id: str = "built-in"
    rule_id: str | None = None
    created_at: datetime
    is_ignored: bool


class ScanDiffResponse(BaseModel):
    new: list[FindingResponse]
    resolved: list[FindingResponse]
    persistent: list[FindingResponse]


class ReportMetadataResponse(BaseModel):
    name: str
    root_path: str
    scanned_at_utc: str
    total_files: int
    dependency_files: list[str]


class ReportFindingResponse(BaseModel):
    id: str
    category: FindingCategory
    severity: Severity
    title: str
    file_path: str
    line: int | None
    evidence: str
    remediation: str


class ScanReportResponse(BaseModel):
    metadata: ReportMetadataResponse
    findings: list[ReportFindingResponse]
    severity_counts: SeverityCountsResponse
    score: int
    file_tree: list[str]


def repository_response(repository: Repository) -> RepositoryResponse:
    return RepositoryResponse(
        id=repository.id,
        name=repository.name,
        target_type=repository.target_type,
        target=repository.target,
        created_at=repository.created_at,
        updated_at=repository.updated_at,
    )


def scan_summary_response(scan: ScanSummary) -> ScanSummaryResponse:
    return ScanSummaryResponse(
        id=scan.id,
        repository_id=scan.repository_id,
        status=scan.status,
        score=scan.score,
        total_files=scan.total_files,
        severity_counts=SeverityCountsResponse(**scan.severity_counts),
        scanned_at_utc=scan.scanned_at_utc,
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        error_message=scan.error_message,
        attempt_count=scan.attempt_count,
        cancellation_requested_at=scan.cancellation_requested_at,
    )


def scan_detail_response(scan: PersistedScan) -> ScanDetailResponse:
    summary = scan_summary_response(scan.summary)
    report = scan.report
    return ScanDetailResponse(
        **summary.model_dump(),
        dependency_files=report.metadata.dependency_files if report else [],
        file_tree=report.file_tree if report else [],
        finding_count=sum(scan.summary.severity_counts.values()),
        engine_runs=[engine_run_response(item) for item in scan.engine_runs],
    )


def engine_run_response(engine_run: EngineRun) -> EngineRunResponse:
    return EngineRunResponse(
        id=engine_run.id,
        scan_id=engine_run.scan_id,
        engine=engine_run.engine,
        engine_version=engine_run.engine_version,
        status=engine_run.status,
        started_at=engine_run.started_at,
        completed_at=engine_run.completed_at,
        error_message=engine_run.error_message,
    )


def finding_response(finding: PersistedFinding) -> FindingResponse:
    return FindingResponse(
        id=finding.id,
        scan_id=finding.scan_id,
        source_finding_id=finding.source_finding_id,
        category=finding.category,
        severity=finding.severity,
        title=finding.title,
        file_path=finding.file_path,
        line=finding.line,
        evidence=finding.evidence,
        remediation=finding.remediation,
        engine_id=getattr(finding, "engine_id", "built-in"),
        rule_id=getattr(finding, "rule_id", None),
        created_at=finding.created_at,
        is_ignored=finding.is_ignored,
    )


def report_response(report: ScanReport) -> ScanReportResponse:
    return ScanReportResponse(
        metadata=_report_metadata_response(report.metadata),
        findings=[_report_finding_response(finding) for finding in report.findings],
        severity_counts=SeverityCountsResponse(**report.severity_counts),
        score=report.score,
        file_tree=report.file_tree,
    )


def _report_metadata_response(metadata: RepoMetadata) -> ReportMetadataResponse:
    return ReportMetadataResponse(
        name=metadata.name,
        root_path=metadata.root_path,
        scanned_at_utc=metadata.scanned_at_utc,
        total_files=metadata.total_files,
        dependency_files=metadata.dependency_files,
    )


def _report_finding_response(finding: Finding) -> ReportFindingResponse:
    return ReportFindingResponse(
        id=finding.id,
        category=finding.category,
        severity=finding.severity,
        title=finding.title,
        file_path=finding.file_path,
        line=finding.line,
        evidence=finding.evidence,
        remediation=finding.remediation,
    )
