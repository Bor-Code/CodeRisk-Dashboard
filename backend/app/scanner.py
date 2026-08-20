from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

Severity = Literal["high", "medium", "low", "info"]
FindingCategory = Literal["dependency", "metadata", "secret", "config", "sast"]

DEPENDENCY_FILES = {
    "package.json",
    "package-lock.json",
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
}

IGNORED_DIR_NAMES = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    "tests",
}

TEXT_FILE_SUFFIXES = {
    ".env",
    ".js",
    ".jsx",
    ".json",
    ".lock",
    ".md",
    ".py",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}

MAX_TEXT_FILE_SIZE_BYTES = 400_000

SECRET_PATTERNS = [
    (
        "github-token",
        "Possible GitHub token exposure",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
        "Rotate the token and remove it from repository history.",
    ),
    (
        "private-key",
        "Possible private key exposure",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        "Remove the key from git history and generate a new key pair.",
    ),
    (
        "database-url",
        "Possible database URL exposure",
        re.compile(r"\bDATABASE_URL\s*=\s*['\"]?[^'\"\s]+", re.IGNORECASE),
        "Load database URLs from environment variables outside git.",
    ),
    (
        "jwt-secret",
        "Possible JWT secret exposure",
        re.compile(r"\bJWT_SECRET\s*=\s*['\"]?[^'\"\s]+", re.IGNORECASE),
        "Use a strong environment-specific JWT secret outside source control.",
    ),
    (
        "api-key",
        "Possible API key or token exposure",
        re.compile(
            r"\b[A-Z0-9_]*(API_KEY|ACCESS_TOKEN|AUTH_TOKEN)\s*=\s*['\"]?[^'\"\s]+",
            re.IGNORECASE,
        ),
        "Move the value to a secret manager or environment variable.",
    ),
]

CONFIG_PATTERNS = [
    (
        "debug-enabled",
        "Debug mode appears enabled",
        "medium",
        re.compile(r"\bDEBUG\s*=\s*(true|1|yes)", re.IGNORECASE),
        "Disable debug mode outside local development.",
    ),
    (
        "cors-wildcard",
        "Wildcard CORS configuration",
        "medium",
        re.compile(
            r"(allow_origins|Access-Control-Allow-Origin).*(\*|\[.*\*.*\])",
            re.IGNORECASE,
        ),
        "Restrict CORS origins to known frontend domains.",
    ),
    (
        "default-secret",
        "Default secret value detected",
        "medium",
        re.compile(
            r"(secret|jwt_secret|secret_key).*(changeme|default|dev-secret)",
            re.IGNORECASE,
        ),
        "Replace default secrets with unique environment-specific values.",
    ),
    (
        "localstorage-token",
        "Token stored in localStorage",
        "low",
        re.compile(
            r"localStorage\.(setItem|getItem)\(['\"][^'\"]*(token|jwt|auth)",
            re.IGNORECASE,
        ),
        "Consider httpOnly cookies for browser sessions when the architecture allows it.",
    ),
]

SAST_PATTERNS = [
    (
        "python-sql-string-concat",
        "Possible SQL string concatenation",
        "high",
        re.compile(r"(execute|executemany)\(.+[+%].+\)", re.IGNORECASE),
        "Use parameterized queries instead of building SQL strings.",
    ),
    (
        "hardcoded-password",
        "Possible hardcoded password",
        "high",
        re.compile(
            r"\b(password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]",
            re.IGNORECASE,
        ),
        "Move passwords to environment variables or a secret manager.",
    ),
    (
        "unsafe-subprocess-shell",
        "Subprocess uses shell=True",
        "medium",
        re.compile(
            r"subprocess\.(run|call|Popen)\(.+shell\s*=\s*True",
            re.IGNORECASE,
        ),
        "Avoid shell=True and pass command arguments as a list.",
    ),
    (
        "dangerously-set-inner-html",
        "React dangerouslySetInnerHTML usage",
        "medium",
        re.compile(r"dangerouslySetInnerHTML"),
        "Avoid raw HTML rendering or sanitize trusted HTML before rendering.",
    ),
    (
        "insecure-http-url",
        "Insecure HTTP URL",
        "low",
        re.compile(r"['\"]http://[^'\"]+['\"]", re.IGNORECASE),
        "Prefer HTTPS endpoints unless local development explicitly requires HTTP.",
    ),
]


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

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def scan_repository(repo_path: str) -> ScanReport:
    root = Path(repo_path).expanduser().resolve()

    if not root.exists() or not root.is_dir():
        raise ValueError("Repo path must point to an existing directory.")

    files = _list_repo_files(root)
    dependency_files = _find_dependency_files(root, files)
    findings = _build_dependency_findings(dependency_files)
    findings.extend(_build_config_findings(root, files))

    for path in files:
        findings.extend(_scan_file_for_secrets(root, path))
        findings.extend(_scan_file_for_config_patterns(root, path))
        findings.extend(_scan_file_for_sast_patterns(root, path))

    severity_counts = _count_severities(findings)
    metadata = RepoMetadata(
        name=root.name,
        root_path=str(root),
        scanned_at_utc=datetime.now(UTC).isoformat(),
        total_files=len(files),
        dependency_files=dependency_files,
    )

    return ScanReport(
        metadata=metadata,
        findings=findings,
        severity_counts=severity_counts,
        score=_calculate_score(severity_counts),
        file_tree=_build_file_tree(root, files),
    )


def _list_repo_files(root: Path) -> list[Path]:
    files: list[Path] = []

    for path in root.rglob("*"):
        if path.is_dir():
            continue

        relative_parts = path.relative_to(root).parts

        if any(part in IGNORED_DIR_NAMES for part in relative_parts):
            continue

        files.append(path)

    return files


def _find_dependency_files(root: Path, files: list[Path]) -> list[str]:
    dependency_files = []

    for path in files:
        if path.name in DEPENDENCY_FILES:
            dependency_files.append(str(path.relative_to(root)).replace("\\", "/"))

    return sorted(dependency_files)


def _build_dependency_findings(dependency_files: list[str]) -> list[Finding]:
    if dependency_files:
        return [
            Finding(
                id="dependency-files-detected",
                category="dependency",
                severity="info",
                title="Dependency manifest files detected",
                file_path=", ".join(dependency_files),
                line=None,
                evidence=f"{len(dependency_files)} dependency file(s) found.",
                remediation="Run OSV-Scanner or Trivy later to check known CVEs.",
            )
        ]

    return [
        Finding(
            id="dependency-files-missing",
            category="dependency",
            severity="low",
            title="No dependency manifest detected",
            file_path="repo root",
            line=None,
            evidence="No supported dependency manifest was found.",
            remediation=(
                "Add a dependency manifest or confirm this repo does not require external packages."
            ),
        )
    ]


def _build_config_findings(root: Path, files: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    repo_file_paths = {str(path.relative_to(root)).replace("\\", "/") for path in files}

    if ".env" in repo_file_paths:
        findings.append(
            Finding(
                id="env-file-in-repository",
                category="config",
                severity="high",
                title=".env file exists inside repository",
                file_path=".env",
                line=None,
                evidence=".env was found in the scanned repository.",
                remediation="Remove .env from git and keep only a sanitized .env.example file.",
            )
        )

    gitignore_path = root / ".gitignore"
    gitignore_text = _read_text(gitignore_path) if gitignore_path.exists() else ""

    if ".env" not in (gitignore_text or ""):
        findings.append(
            Finding(
                id="gitignore-missing-env",
                category="config",
                severity="medium",
                title=".gitignore does not ignore .env",
                file_path=".gitignore",
                line=None,
                evidence=".env pattern was not found in .gitignore.",
                remediation="Add .env and local secret files to .gitignore.",
            )
        )

    return findings


def _scan_file_for_secrets(root: Path, path: Path) -> list[Finding]:
    if not _is_text_file_candidate(path):
        return []

    content = _read_text(path)

    if content is None:
        return []

    relative_path = str(path.relative_to(root)).replace("\\", "/")
    findings: list[Finding] = []

    for line_number, line in enumerate(content.splitlines(), start=1):
        for rule_id, title, pattern, remediation in SECRET_PATTERNS:
            if not pattern.search(line):
                continue

            findings.append(
                Finding(
                    id=f"secret-{rule_id}-{relative_path}-{line_number}",
                    category="secret",
                    severity="high",
                    title=title,
                    file_path=relative_path,
                    line=line_number,
                    evidence=_mask_secret_line(line),
                    remediation=remediation,
                )
            )

    return findings


def _scan_file_for_config_patterns(root: Path, path: Path) -> list[Finding]:
    if not _is_text_file_candidate(path):
        return []

    content = _read_text(path)

    if content is None:
        return []

    relative_path = str(path.relative_to(root)).replace("\\", "/")
    findings: list[Finding] = []

    for line_number, line in enumerate(content.splitlines(), start=1):
        for rule_id, title, severity, pattern, remediation in CONFIG_PATTERNS:
            if not pattern.search(line):
                continue

            if rule_id == "default-secret":
                evidence = _mask_secret_line(line)
            else:
                evidence = line.strip()[:180]

            findings.append(
                Finding(
                    id=f"config-{rule_id}-{relative_path}-{line_number}",
                    category="config",
                    severity=severity,
                    title=title,
                    file_path=relative_path,
                    line=line_number,
                    evidence=evidence,
                    remediation=remediation,
                )
            )

    return findings


def _scan_file_for_sast_patterns(root: Path, path: Path) -> list[Finding]:
    if not _is_text_file_candidate(path):
        return []

    content = _read_text(path)

    if content is None:
        return []

    relative_path = str(path.relative_to(root)).replace("\\", "/")
    findings: list[Finding] = []

    for line_number, line in enumerate(content.splitlines(), start=1):
        for rule_id, title, severity, pattern, remediation in SAST_PATTERNS:
            if not pattern.search(line):
                continue

            if rule_id == "hardcoded-password":
                evidence = _mask_secret_line(line)
            else:
                evidence = line.strip()[:180]

            findings.append(
                Finding(
                    id=f"sast-{rule_id}-{relative_path}-{line_number}",
                    category="sast",
                    severity=severity,
                    title=title,
                    file_path=relative_path,
                    line=line_number,
                    evidence=evidence,
                    remediation=remediation,
                )
            )

    return findings


def _is_text_file_candidate(path: Path) -> bool:
    if path.stat().st_size > MAX_TEXT_FILE_SIZE_BYTES:
        return False

    return path.suffix.lower() in TEXT_FILE_SUFFIXES or path.name in {".env", ".gitignore"}


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None


def _mask_secret_line(line: str) -> str:
    if "=" not in line:
        return "[masked secret-like value]"

    key, value = line.split("=", 1)
    clean_value = value.strip().strip("'\"")

    if len(clean_value) <= 8:
        masked_value = "***"
    else:
        masked_value = f"{clean_value[:3]}***{clean_value[-3:]}"

    return f"{key.strip()}={masked_value}"


def _count_severities(findings: list[Finding]) -> dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}

    for finding in findings:
        counts[finding.severity] += 1

    return counts


def _calculate_score(severity_counts: dict[str, int]) -> int:
    penalty = (
        severity_counts["high"] * 20 + severity_counts["medium"] * 10 + severity_counts["low"] * 4
    )

    return max(0, 100 - penalty)


def _build_file_tree(root: Path, files: list[Path]) -> list[str]:
    return sorted(str(path.relative_to(root)).replace("\\", "/") for path in files)[:200]
