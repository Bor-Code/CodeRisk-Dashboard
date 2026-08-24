from datetime import datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, utc_now


def _new_id() -> str:
    return str(uuid4())


class RepositoryModel(Base):
    __tablename__ = "repositories"
    __table_args__ = (UniqueConstraint("target_type", "target", name="uq_repositories_target"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    name: Mapped[str] = mapped_column(String(255))
    target_type: Mapped[str] = mapped_column(String(32))
    target: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
    )

    scans: Mapped[list["ScanModel"]] = relationship(
        back_populates="repository",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    ignored_findings: Mapped[list["IgnoredFindingModel"]] = relationship(
        back_populates="repository",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class IgnoredFindingModel(Base):
    __tablename__ = "ignored_findings"
    __table_args__ = (
        UniqueConstraint("repository_id", "source_finding_id", name="uq_ignored_findings_repo_src"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    repository_id: Mapped[str] = mapped_column(
        ForeignKey("repositories.id", ondelete="CASCADE"), index=True
    )
    source_finding_id: Mapped[str] = mapped_column(Text)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    repository: Mapped[RepositoryModel] = relationship(back_populates="ignored_findings")


class ScanModel(Base):
    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_repository_created", "repository_id", "created_at"),
        Index("ix_scans_status_created", "status", "created_at"),
        Index("ix_scans_status_lease", "status", "lease_expires_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    repository_id: Mapped[str] = mapped_column(
        ForeignKey("repositories.id", ondelete="CASCADE"),
        index=True,
    )
    status: Mapped[str] = mapped_column(String(32), default="queued")
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    total_files: Mapped[int | None] = mapped_column(Integer, nullable=True)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    info_count: Mapped[int] = mapped_column(Integer, default=0)
    dependency_files: Mapped[list[str]] = mapped_column(JSON, default=list)
    file_tree: Mapped[list[str]] = mapped_column(JSON, default=list)
    scanned_at_utc: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    worker_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    cancellation_requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    repository: Mapped[RepositoryModel] = relationship(back_populates="scans")
    findings: Mapped[list["FindingModel"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="FindingModel.position",
        passive_deletes=True,
    )
    engine_runs: Mapped[list["EngineRunModel"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class FindingModel(Base):
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_scan_severity", "scan_id", "severity"),
        Index("ix_findings_scan_category", "scan_id", "category"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"),
        index=True,
    )
    source_finding_id: Mapped[str] = mapped_column(Text)
    position: Mapped[int] = mapped_column(Integer)
    category: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(String(255))
    file_path: Mapped[str] = mapped_column(Text)
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    evidence: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text)
    is_ignored: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    scan: Mapped[ScanModel] = relationship(back_populates="findings")


class EngineRunModel(Base):
    __tablename__ = "engine_runs"
    __table_args__ = (UniqueConstraint("scan_id", "engine", name="uq_engine_runs_scan_engine"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"),
        index=True,
    )
    engine: Mapped[str] = mapped_column(String(64))
    engine_version: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), default="queued")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    scan: Mapped[ScanModel] = relationship(back_populates="engine_runs")
