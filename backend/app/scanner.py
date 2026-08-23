from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

from app.domain.reports import Finding, FindingCategory, RepoMetadata, ScanReport, Severity


@dataclass(frozen=True)
class PatternRule:
    id: str
    title: str
    severity: Severity
    pattern: re.Pattern[str]
    remediation: str
    file_suffixes: frozenset[str] | None = None
    mask_evidence: bool = False


DEPENDENCY_FILES = {
    "package.json",
    "package-lock.json",
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "yarn.lock",
    "pnpm-lock.yaml",
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

CODE_AND_CONFIG_SUFFIXES = frozenset(
    {".env", ".js", ".jsx", ".json", ".py", ".toml", ".ts", ".tsx", ".yaml", ".yml"}
)
PYTHON_SUFFIXES = frozenset({".py"})
REACT_SUFFIXES = frozenset({".jsx", ".tsx"})

SECRET_RULES = [
    PatternRule(
        id="github-token",
        title="Possible GitHub token exposure",
        severity="high",
        pattern=re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
        remediation="Rotate the token and remove it from repository history.",
        mask_evidence=True,
    ),
    PatternRule(
        id="private-key",
        title="Possible private key exposure",
        severity="high",
        pattern=re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        remediation="Remove the key from git history and generate a new key pair.",
        mask_evidence=True,
    ),
    PatternRule(
        id="database-url",
        title="Possible database URL exposure",
        severity="high",
        pattern=re.compile(
            r"\bDATABASE_URL\s*=\s*['\"]?[a-z][a-z0-9+.-]*://[^'\"\s]+",
            re.IGNORECASE,
        ),
        remediation="Load database URLs from environment variables outside git.",
        mask_evidence=True,
    ),
    PatternRule(
        id="weak-jwt-secret",
        title="Weak JWT secret detected",
        severity="medium",
        # Match JWT_SECRET assignments with a short value (<=15 chars) to flag weak secrets
        pattern=re.compile(r"\bJWT_SECRET\s*=\s*['\"]?([^'\"\s]{1,15})['\"]?", re.IGNORECASE),
        remediation="Use a strong JWT secret (>=32 chars) kept out of source control.",
        mask_evidence=True,
    ),
    PatternRule(
        id="aws-access-key",
        title="Possible AWS access key exposure",
        severity="high",
        pattern=re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
        remediation="Rotate the AWS access key and remove it from source control.",
        mask_evidence=True,
    ),
    PatternRule(
        id="aws-secret-key",
        title="Possible AWS secret access key exposure",
        severity="high",
        pattern=re.compile(
            r"(?i)(?:aws[_-]?secret[_-]?access[_-]?key|aws_secret_access_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})",
        ),
        remediation=(
            "Replace the AWS secret with a managed secret source such as IAM roles or a vault."
        ),
        mask_evidence=True,
    ),
    PatternRule(
        id="gitlab-token",
        title="Possible GitLab personal access token exposure",
        severity="high",
        pattern=re.compile(r"(?i)\bglpat-[A-Za-z0-9_\-]{20,}\b"),
        remediation="Revoke the GitLab token and rotate it from a secure secret store.",
        mask_evidence=True,
    ),
    PatternRule(
        id="google-api-key",
        title="Possible Google API key exposure",
        severity="high",
        pattern=re.compile(r"(?i)\bAIza[0-9A-Za-z\-_]{35,}\b"),
        remediation="Restrict the key to expected APIs and move it to a secret manager.",
        mask_evidence=True,
    ),
    PatternRule(
        id="aws-role-arn",
        title="Possible AWS role ARN exposure",
        severity="medium",
        pattern=re.compile(r"(?i)\barn:aws:iam::\d{12}:role/[A-Za-z0-9+=,._:/@-]+\b"),
        remediation=(
            "Ensure AWS role ARNs are not committed and restrict access to the intended role."
        ),
        mask_evidence=True,
    ),
    PatternRule(
        id="jwt-secret",
        title="Possible JWT secret exposure",
        severity="high",
        pattern=re.compile(r"\bJWT_SECRET\s*=\s*['\"]?[^'\"\s]+", re.IGNORECASE),
        remediation="Use a strong environment-specific JWT secret outside source control.",
        mask_evidence=True,
    ),
    PatternRule(
        id="api-key",
        title="Possible API key or token exposure",
        severity="high",
        pattern=re.compile(
            r"\b[A-Z0-9_]*(API_KEY|ACCESS_TOKEN|AUTH_TOKEN)\s*=\s*['\"]?[^'\"\s]+",
            re.IGNORECASE,
        ),
        remediation="Move the value to a secret manager or environment variable.",
        mask_evidence=True,
    ),
    PatternRule(
        id="aws-access-key",
        title="AWS Access Key ID exposure",
        severity="high",
        pattern=re.compile(r"\b(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b"),
        remediation="Rotate the AWS credentials and use IAM roles where possible.",
        mask_evidence=True,
    ),
    PatternRule(
        id="stripe-secret-key",
        title="Stripe Secret Key exposure",
        severity="high",
        pattern=re.compile(r"\b(?:sk_live|rk_live)_[0-9a-zA-Z]{24,99}\b"),
        remediation="Rotate Stripe keys via Stripe Dashboard.",
        mask_evidence=True,
    ),
    PatternRule(
        id="slack-webhook",
        title="Slack Webhook exposure",
        severity="high",
        pattern=re.compile(
            r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"
        ),
        remediation="Revoke the webhook URL in Slack and use secrets manager.",
        mask_evidence=True,
    ),
]

CONFIG_RULES = [
    PatternRule(
        id="debug-enabled",
        title="Debug mode appears enabled",
        severity="medium",
        pattern=re.compile(r"\bDEBUG\s*=\s*(true|1|yes)\b", re.IGNORECASE),
        remediation="Disable debug mode outside local development.",
        file_suffixes=CODE_AND_CONFIG_SUFFIXES,
    ),
    PatternRule(
        id="cors-wildcard",
        title="Wildcard CORS configuration",
        severity="medium",
        pattern=re.compile(
            r"\ballow_origins\s*=\s*\[[^\]]*['\"]\*['\"][^\]]*\]"
            r"|Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*['\"]",
            re.IGNORECASE,
        ),
        remediation="Restrict CORS origins to known frontend domains.",
        file_suffixes=CODE_AND_CONFIG_SUFFIXES,
    ),
    PatternRule(
        id="default-secret",
        title="Default secret value detected",
        severity="medium",
        pattern=re.compile(
            r"\b(secret|jwt_secret|secret_key)\s*[:=]\s*['\"]?"
            r"(changeme|default|dev-secret)\b",
            re.IGNORECASE,
        ),
        remediation="Replace default secrets with unique environment-specific values.",
        file_suffixes=CODE_AND_CONFIG_SUFFIXES,
        mask_evidence=True,
    ),
    PatternRule(
        id="localstorage-token",
        title="Token stored in localStorage",
        severity="low",
        pattern=re.compile(
            r"localStorage\.(setItem|getItem)\(\s*['\"][^'\"]*(token|jwt|auth)",
            re.IGNORECASE,
        ),
        remediation=(
            "Consider httpOnly cookies for browser sessions when the architecture allows it."
        ),
        file_suffixes=CODE_AND_CONFIG_SUFFIXES,
    ),
]

SAST_RULES = [
    PatternRule(
        id="python-sql-string-concat",
        title="Possible SQL string concatenation",
        severity="high",
        pattern=re.compile(r"(execute|executemany)\(.+[+%].+\)", re.IGNORECASE),
        remediation="Use parameterized queries instead of building SQL strings.",
        file_suffixes=PYTHON_SUFFIXES,
    ),
    PatternRule(
        id="hardcoded-password",
        title="Possible hardcoded password",
        severity="high",
        pattern=re.compile(
            r"\b(password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]",
            re.IGNORECASE,
        ),
        remediation="Move passwords to environment variables or a secret manager.",
        file_suffixes=CODE_AND_CONFIG_SUFFIXES,
        mask_evidence=True,
    ),
    PatternRule(
        id="unsafe-subprocess-shell",
        title="Subprocess uses shell=True",
        severity="medium",
        pattern=re.compile(
            r"subprocess\.(run|call|Popen)\(.+shell\s*=\s*True",
            re.IGNORECASE,
        ),
        remediation="Avoid shell=True and pass command arguments as a list.",
        file_suffixes=PYTHON_SUFFIXES,
    ),
    PatternRule(
        id="dangerously-set-inner-html",
        title="React dangerouslySetInnerHTML usage",
        severity="medium",
        pattern=re.compile(r"\bdangerouslySetInnerHTML\s*="),
        remediation="Avoid raw HTML rendering or sanitize trusted HTML before rendering.",
        file_suffixes=REACT_SUFFIXES,
    ),
    PatternRule(
        id="insecure-http-url",
        title="Insecure HTTP URL",
        severity="low",
        pattern=re.compile(
            r"(?P<quote>['\"])(?P<url>http://[^'\"\s]+)(?P=quote)",
            re.IGNORECASE,
        ),
        remediation="Prefer HTTPS endpoints unless local development explicitly requires HTTP.",
        file_suffixes=CODE_AND_CONFIG_SUFFIXES,
    ),
    PatternRule(
        id="python-eval-exec",
        title="Usage of eval(), exec() or pickle",
        severity="high",
        pattern=re.compile(r"\b(eval|exec|pickle\.loads)\s*\("),
        remediation="Avoid dynamic execution or deserialization of untrusted data.",
        file_suffixes=PYTHON_SUFFIXES,
    ),
]


def scan_repository(repo_path: str) -> ScanReport:
    root = Path(repo_path).expanduser().resolve()

    if not root.exists() or not root.is_dir():
        raise ValueError("Repo path must point to an existing directory.")

    files = _list_repo_files(root)
    dependency_files = _find_dependency_files(root, files)
    findings = _build_dependency_findings(dependency_files)
    findings.extend(_build_config_findings(root, files))

    for path in files:
        findings.extend(_scan_file(root, path))

    findings = _sort_findings(findings)
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


def _scan_file(root: Path, path: Path) -> list[Finding]:
    if not _is_text_file_candidate(path):
        return []

    content = _read_text(path)

    if content is None:
        return []

    relative_path = str(path.relative_to(root)).replace("\\", "/")
    lines = content.splitlines()
    findings: list[Finding] = []

    categories: list[tuple[FindingCategory, list[PatternRule]]] = [
        ("secret", SECRET_RULES),
        ("config", CONFIG_RULES),
        ("sast", SAST_RULES),
    ]
    for category, rules in categories:
        applicable_rules = [rule for rule in rules if _rule_applies_to_path(rule, path)]
        findings.extend(_scan_lines_for_rules(relative_path, lines, category, applicable_rules))

    return findings


def _scan_lines_for_rules(
    relative_path: str,
    lines: list[str],
    category: FindingCategory,
    rules: list[PatternRule],
) -> list[Finding]:
    findings: list[Finding] = []

    for line_number, line in enumerate(lines, start=1):
        for rule in rules:
            matches = list(rule.pattern.finditer(line))

            if not matches:
                continue

            if rule.id == "insecure-http-url" and all(
                _is_loopback_http_url(match.group("url")) for match in matches
            ):
                continue

            evidence = _mask_secret_line(line) if rule.mask_evidence else line.strip()[:180]
            findings.append(
                Finding(
                    id=f"{category}-{rule.id}-{relative_path}-{line_number}",
                    category=category,
                    severity=rule.severity,
                    title=rule.title,
                    file_path=relative_path,
                    line=line_number,
                    evidence=evidence,
                    remediation=rule.remediation,
                )
            )

    return findings


def _rule_applies_to_path(rule: PatternRule, path: Path) -> bool:
    return rule.file_suffixes is None or _normalized_suffix(path) in rule.file_suffixes


def _is_loopback_http_url(url: str) -> bool:
    try:
        hostname = urlsplit(url).hostname
    except ValueError:
        return False

    if hostname is None:
        return False

    hostname = hostname.rstrip(".").lower()

    if hostname == "localhost":
        return True

    try:
        return ip_address(hostname).is_loopback
    except ValueError:
        return False


def _is_text_file_candidate(path: Path) -> bool:
    if path.stat().st_size > MAX_TEXT_FILE_SIZE_BYTES:
        return False

    return _normalized_suffix(path) in TEXT_FILE_SUFFIXES or path.name == ".gitignore"


def _normalized_suffix(path: Path) -> str:
    if path.name == ".env" or path.name.startswith(".env."):
        return ".env"

    return path.suffix.lower()


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


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    severity_rank = {"high": 0, "medium": 1, "low": 2, "info": 3}

    return sorted(
        findings,
        key=lambda finding: (
            severity_rank[finding.severity],
            finding.category,
            finding.file_path,
            finding.line or 0,
        ),
    )


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
