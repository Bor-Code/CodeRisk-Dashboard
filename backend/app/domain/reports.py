from dataclasses import asdict, dataclass
from typing import Literal

Severity = Literal["high", "medium", "low", "info"]
FindingCategory = Literal["dependency", "metadata", "secret", "config", "sast"]


@dataclass(frozen=True)
class Finding:
    id: str
    category: FindingCategory
    severity: Severity
    title: str
    file_path: str
    line: int | None
    evidence: str
    remediation: str
    engine_id: str = "built-in"
    rule_id: str | None = None


@dataclass(frozen=True)
class RepoMetadata:
    name: str
    root_path: str
    scanned_at_utc: str
    total_files: int
    dependency_files: list[str]


@dataclass(frozen=True)
class ScanReport:
    metadata: RepoMetadata
    findings: list[Finding]
    severity_counts: dict[str, int]
    score: int
    file_tree: list[str]
    sbom: dict | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
