from datetime import UTC, datetime
from typing import cast

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session, selectinload

from app.db.base import utc_now
from app.db.models import EngineRunModel, FindingModel, RepositoryModel, ScanModel
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
from app.domain.reports import FindingCategory, RepoMetadata, ScanReport, Severity

BUILTIN_ENGINE_NAME = "builtin"
BUILTIN_ENGINE_VERSION = "0.1.0"


class ScanStore:
    def __init__(self, session: Session) -> None:
        self.session = session

    def get_or_create_repository(
        self,
        *,
        name: str,
        target_type: RepositoryTargetType,
        target: str,
    ) -> tuple[Repository, bool]:
        statement = select(RepositoryModel).where(
            RepositoryModel.target_type == target_type,
            RepositoryModel.target == target,
        )
        model = self.session.scalar(statement)

        if model is not None:
            if model.name != name:
                model.name = name
                model.updated_at = utc_now()
                self.session.flush()
            return _repository_from_model(model), False

        model = RepositoryModel(name=name, target_type=target_type, target=target)
        self.session.add(model)
        self.session.flush()
        return _repository_from_model(model), True

    def get_repository(self, repository_id: str) -> Repository | None:
        model = self.session.get(RepositoryModel, repository_id)
        return _repository_from_model(model) if model is not None else None

    def list_repositories(self, *, offset: int, limit: int) -> tuple[list[Repository], int]:
        total = self.session.scalar(select(func.count()).select_from(RepositoryModel)) or 0
        statement = (
            select(RepositoryModel)
            .order_by(RepositoryModel.created_at.desc(), RepositoryModel.id)
            .offset(offset)
            .limit(limit)
        )
        models = self.session.scalars(statement).all()
        return [_repository_from_model(model) for model in models], total

    def begin_scan(self, repository_id: str) -> ScanSummary:
        scan = ScanModel(repository_id=repository_id, status="running")
        scan.engine_runs.append(
            EngineRunModel(
                engine=BUILTIN_ENGINE_NAME,
                engine_version=BUILTIN_ENGINE_VERSION,
                status="running",
            )
        )
        self.session.add(scan)
        self.session.flush()
        return _scan_summary_from_model(scan)

    def complete_scan(self, scan_id: str, report: ScanReport) -> PersistedScan:
        model = self._get_scan_model(scan_id)
        completed_at = utc_now()
        model.status = "completed"
        model.score = report.score
        model.total_files = report.metadata.total_files
        model.high_count = report.severity_counts["high"]
        model.medium_count = report.severity_counts["medium"]
        model.low_count = report.severity_counts["low"]
        model.info_count = report.severity_counts["info"]
        model.dependency_files = report.metadata.dependency_files
        model.file_tree = report.file_tree
        model.scanned_at_utc = _parse_datetime(report.metadata.scanned_at_utc)
        model.completed_at = completed_at
        model.updated_at = completed_at
        model.error_message = None
        model.findings = [
            FindingModel(
                source_finding_id=finding.id,
                position=position,
                category=finding.category,
                severity=finding.severity,
                title=finding.title,
                file_path=finding.file_path,
                line=finding.line,
                evidence=finding.evidence,
                remediation=finding.remediation,
            )
            for position, finding in enumerate(report.findings)
        ]

        engine_run = _builtin_engine_run(model)
        engine_run.status = "completed"
        engine_run.completed_at = completed_at
        engine_run.error_message = None
        engine_run.details = {"finding_count": len(report.findings)}
        self.session.flush()
        return _persisted_scan_from_model(model)

    def fail_scan(self, scan_id: str, error_message: str) -> ScanSummary:
        model = self._get_scan_model(scan_id)
        completed_at = utc_now()
        model.status = "failed"
        model.completed_at = completed_at
        model.updated_at = completed_at
        model.error_message = error_message
        engine_run = _builtin_engine_run(model)
        engine_run.status = "failed"
        engine_run.completed_at = completed_at
        engine_run.error_message = error_message
        self.session.flush()
        return _scan_summary_from_model(model)

    def get_scan(self, scan_id: str) -> PersistedScan | None:
        statement = _scan_detail_statement().where(ScanModel.id == scan_id)
        model = self.session.scalar(statement)
        return _persisted_scan_from_model(model) if model is not None else None

    def get_latest_completed_scan(self) -> PersistedScan | None:
        statement = (
            _scan_detail_statement()
            .where(ScanModel.status == "completed")
            .order_by(ScanModel.completed_at.desc(), ScanModel.id.desc())
            .limit(1)
        )
        model = self.session.scalar(statement)
        return _persisted_scan_from_model(model) if model is not None else None

    def list_scans(
        self,
        *,
        offset: int,
        limit: int,
        repository_id: str | None = None,
        status: ScanStatus | None = None,
        severity: Severity | None = None,
    ) -> tuple[list[ScanSummary], int]:
        filters = []

        if repository_id is not None:
            filters.append(ScanModel.repository_id == repository_id)
        if status is not None:
            filters.append(ScanModel.status == status)
        if severity is not None:
            filters.append(ScanModel.findings.any(FindingModel.severity == severity))

        statement = (
            select(ScanModel)
            .where(*filters)
            .order_by(ScanModel.created_at.desc(), ScanModel.id.desc())
            .offset(offset)
            .limit(limit)
        )
        count_statement = select(func.count()).select_from(ScanModel).where(*filters)
        models = self.session.scalars(statement).all()
        total = self.session.scalar(count_statement) or 0
        return [_scan_summary_from_model(model) for model in models], total

    def list_findings(
        self,
        scan_id: str,
        *,
        offset: int,
        limit: int,
        severity: Severity | None = None,
        category: FindingCategory | None = None,
    ) -> tuple[list[PersistedFinding], int]:
        filters = [FindingModel.scan_id == scan_id]

        if severity is not None:
            filters.append(FindingModel.severity == severity)
        if category is not None:
            filters.append(FindingModel.category == category)

        statement = (
            select(FindingModel)
            .where(*filters)
            .order_by(FindingModel.position)
            .offset(offset)
            .limit(limit)
        )
        count_statement = select(func.count()).select_from(FindingModel).where(*filters)
        models = self.session.scalars(statement).all()
        total = self.session.scalar(count_statement) or 0
        return [_finding_from_model(model) for model in models], total

    def _get_scan_model(self, scan_id: str) -> ScanModel:
        statement = _scan_detail_statement().where(ScanModel.id == scan_id)
        model = self.session.scalar(statement)

        if model is None:
            raise LookupError(scan_id)

        return model


def _scan_detail_statement() -> Select[tuple[ScanModel]]:
    return select(ScanModel).options(
        selectinload(ScanModel.repository),
        selectinload(ScanModel.findings),
        selectinload(ScanModel.engine_runs),
    )


def _repository_from_model(model: RepositoryModel) -> Repository:
    return Repository(
        id=model.id,
        name=model.name,
        target_type=cast(RepositoryTargetType, model.target_type),
        target=model.target,
        created_at=_as_utc(model.created_at),
        updated_at=_as_utc(model.updated_at),
    )


def _scan_summary_from_model(model: ScanModel) -> ScanSummary:
    return ScanSummary(
        id=model.id,
        repository_id=model.repository_id,
        status=cast(ScanStatus, model.status),
        score=model.score,
        total_files=model.total_files,
        severity_counts={
            "high": model.high_count,
            "medium": model.medium_count,
            "low": model.low_count,
            "info": model.info_count,
        },
        scanned_at_utc=_as_utc(model.scanned_at_utc) if model.scanned_at_utc else None,
        created_at=_as_utc(model.created_at),
        started_at=_as_utc(model.started_at),
        completed_at=_as_utc(model.completed_at) if model.completed_at else None,
        error_message=model.error_message,
    )


def _finding_from_model(model: FindingModel) -> PersistedFinding:
    return PersistedFinding(
        id=model.id,
        scan_id=model.scan_id,
        source_finding_id=model.source_finding_id,
        category=cast(FindingCategory, model.category),
        severity=cast(Severity, model.severity),
        title=model.title,
        file_path=model.file_path,
        line=model.line,
        evidence=model.evidence,
        remediation=model.remediation,
        created_at=_as_utc(model.created_at),
    )


def _engine_run_from_model(model: EngineRunModel) -> EngineRun:
    return EngineRun(
        id=model.id,
        scan_id=model.scan_id,
        engine=model.engine,
        engine_version=model.engine_version,
        status=cast(EngineRunStatus, model.status),
        started_at=_as_utc(model.started_at),
        completed_at=_as_utc(model.completed_at) if model.completed_at else None,
        error_message=model.error_message,
    )


def _persisted_scan_from_model(model: ScanModel) -> PersistedScan:
    summary = _scan_summary_from_model(model)
    report = None

    if model.status == "completed" and model.scanned_at_utc is not None:
        findings = [_finding_from_model(item).to_report_finding() for item in model.findings]
        report = ScanReport(
            metadata=RepoMetadata(
                name=model.repository.name,
                root_path=model.repository.target,
                scanned_at_utc=_as_utc(model.scanned_at_utc).isoformat(),
                total_files=model.total_files or 0,
                dependency_files=list(model.dependency_files or []),
            ),
            findings=findings,
            severity_counts=summary.severity_counts,
            score=model.score or 0,
            file_tree=list(model.file_tree or []),
        )

    return PersistedScan(
        summary=summary,
        report=report,
        engine_runs=[_engine_run_from_model(item) for item in model.engine_runs],
    )


def _builtin_engine_run(model: ScanModel) -> EngineRunModel:
    for engine_run in model.engine_runs:
        if engine_run.engine == BUILTIN_ENGINE_NAME:
            return engine_run

    raise LookupError(f"Built-in engine run is missing for scan {model.id}.")


def _parse_datetime(value: str) -> datetime:
    return _as_utc(datetime.fromisoformat(value))


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)

    return value.astimezone(UTC)
