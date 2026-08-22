from pathlib import Path

import pytest

from app.scanner import scan_repository


def test_scan_repository_detects_dependency_files(tmp_path: Path) -> None:
    repo = tmp_path / "sample-repo"
    repo.mkdir()
    (repo / ".gitignore").write_text(".env\n", encoding="utf-8")
    (repo / "package.json").write_text("{}", encoding="utf-8")
    (repo / "requirements.txt").write_text("fastapi\n", encoding="utf-8")

    report = scan_repository(str(repo))

    assert report.metadata.name == "sample-repo"
    assert report.metadata.total_files == 3
    assert report.metadata.dependency_files == ["package.json", "requirements.txt"]
    assert report.severity_counts["info"] == 1
    assert report.score == 100


def test_scan_repository_adds_low_finding_when_dependency_files_are_missing(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "sample-repo"
    repo.mkdir()
    (repo / ".gitignore").write_text(".env\n", encoding="utf-8")
    (repo / "README.md").write_text("# Sample\n", encoding="utf-8")

    report = scan_repository(str(repo))

    assert report.metadata.dependency_files == []
    assert report.findings[0].id == "dependency-files-missing"
    assert report.severity_counts["low"] == 1
    assert report.score == 96


def test_scan_repository_ignores_common_generated_directories(tmp_path: Path) -> None:
    repo = tmp_path / "sample-repo"
    repo.mkdir()
    node_modules = repo / "node_modules"
    node_modules.mkdir()
    (node_modules / "package.json").write_text("{}", encoding="utf-8")
    (repo / ".gitignore").write_text(".env\n", encoding="utf-8")
    (repo / "pyproject.toml").write_text("[project]\nname = 'sample'\n", encoding="utf-8")

    report = scan_repository(str(repo))

    assert report.metadata.total_files == 2
    assert report.metadata.dependency_files == ["pyproject.toml"]


def test_scan_repository_rejects_missing_path(tmp_path: Path) -> None:
    missing_path = tmp_path / "missing"

    with pytest.raises(ValueError, match="Repo path must point to an existing directory."):
        scan_repository(str(missing_path))


def test_scan_repository_detects_and_masks_database_url(tmp_path: Path) -> None:
    repo = tmp_path / "sample-repo"
    repo.mkdir()
    (repo / ".gitignore").write_text(".env\n", encoding="utf-8")
    (repo / "pyproject.toml").write_text("[project]\nname = 'sample'\n", encoding="utf-8")
    (repo / "settings.py").write_text(
        "DATABASE_URL=postgresql://admin:secret@example.com/app\n",
        encoding="utf-8",
    )

    report = scan_repository(str(repo))

    secret_findings = [finding for finding in report.findings if finding.category == "secret"]

    assert len(secret_findings) == 1
    assert secret_findings[0].severity == "high"
    assert "admin:secret" not in secret_findings[0].evidence
    assert "***" in secret_findings[0].evidence
    assert report.severity_counts["high"] == 1
    assert report.score == 80


def test_scan_repository_detects_github_like_token(tmp_path: Path) -> None:
    repo = tmp_path / "sample-repo"
    repo.mkdir()
    (repo / ".gitignore").write_text(".env\n", encoding="utf-8")
    (repo / "pyproject.toml").write_text("[project]\nname = 'sample'\n", encoding="utf-8")
    (repo / "settings.py").write_text(
        "TOKEN='ghp_1234567890abcdefghijklmnopqrstuvwxyz'\n",
        encoding="utf-8",
    )

    report = scan_repository(str(repo))

    assert any(finding.title == "Possible GitHub token exposure" for finding in report.findings)


def test_scan_repository_detects_env_file_and_missing_gitignore_env(tmp_path: Path) -> None:
    repo = tmp_path / "sample-repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text("[project]\nname = 'sample'\n", encoding="utf-8")
    (repo / ".env").write_text("JWT_SECRET=dev-secret\n", encoding="utf-8")
    (repo / ".gitignore").write_text("node_modules\n", encoding="utf-8")

    report = scan_repository(str(repo))

    finding_ids = {finding.id for finding in report.findings}

    assert "env-file-in-repository" in finding_ids
    assert "gitignore-missing-env" in finding_ids


def test_scan_repository_detects_config_patterns(tmp_path: Path) -> None:
    repo = tmp_path / "sample-repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text("[project]\nname = 'sample'\n", encoding="utf-8")
    (repo / ".gitignore").write_text(".env\n", encoding="utf-8")
    (repo / "settings.py").write_text(
        "DEBUG=true\nallow_origins=['*']\nJWT_SECRET=dev-secret\n",
        encoding="utf-8",
    )
    (repo / "auth.ts").write_text(
        "localStorage.setItem('access-token', token)\n",
        encoding="utf-8",
    )

    report = scan_repository(str(repo))
    titles = {finding.title for finding in report.findings}

    assert "Debug mode appears enabled" in titles
    assert "Wildcard CORS configuration" in titles
    assert "Default secret value detected" in titles
    assert "Token stored in localStorage" in titles


def test_scan_repository_detects_basic_sast_patterns(tmp_path: Path) -> None:
    repo = tmp_path / "sample-repo"
    repo.mkdir()
    (repo / ".gitignore").write_text(".env\n", encoding="utf-8")
    (repo / "pyproject.toml").write_text("[project]\nname = 'sample'\n", encoding="utf-8")
    (repo / "main.py").write_text(
        "password = 'admin123'\n"
        "cursor.execute('SELECT * FROM users WHERE id=' + user_id)\n"
        "subprocess.run(command, shell=True)\n",
        encoding="utf-8",
    )
    (repo / "App.tsx").write_text(
        "const api = 'http://example.com'\n"
        "return <div dangerouslySetInnerHTML={{__html: html}} />\n",
        encoding="utf-8",
    )

    report = scan_repository(str(repo))
    titles = {finding.title for finding in report.findings}

    assert "Possible hardcoded password" in titles
    assert "Possible SQL string concatenation" in titles
    assert "Subprocess uses shell=True" in titles
    assert "React dangerouslySetInnerHTML usage" in titles
    assert "Insecure HTTP URL" in titles


def test_scan_repository_masks_hardcoded_password_evidence(tmp_path: Path) -> None:
    repo = tmp_path / "sample-repo"
    repo.mkdir()
    (repo / ".gitignore").write_text(".env\n", encoding="utf-8")
    (repo / "pyproject.toml").write_text("[project]\nname = 'sample'\n", encoding="utf-8")
    (repo / "settings.py").write_text("password = 'supersecret123'\n", encoding="utf-8")

    report = scan_repository(str(repo))

    password_findings = [
        finding for finding in report.findings if finding.title == "Possible hardcoded password"
    ]

    assert len(password_findings) == 1
    assert "supersecret123" not in password_findings[0].evidence
    assert "***" in password_findings[0].evidence


def test_scan_repository_detects_node_lockfiles(tmp_path: Path) -> None:
    repo = tmp_path / "sample-repo"
    repo.mkdir()
    (repo / ".gitignore").write_text(".env\n", encoding="utf-8")
    (repo / "yarn.lock").write_text("# yarn lockfile\n", encoding="utf-8")
    (repo / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")

    report = scan_repository(str(repo))

    assert report.metadata.dependency_files == ["pnpm-lock.yaml", "yarn.lock"]


def test_scan_repository_sorts_findings_by_severity(tmp_path: Path) -> None:
    repo = tmp_path / "sample-repo"
    repo.mkdir()
    (repo / ".gitignore").write_text(".env\n", encoding="utf-8")
    (repo / "pyproject.toml").write_text("[project]\nname = 'sample'\n", encoding="utf-8")
    (repo / "settings.py").write_text(
        "password = 'admin123'\nDEBUG=true\n",
        encoding="utf-8",
    )
    (repo / "client.ts").write_text(
        "const apiUrl = 'http://example.com'\n",
        encoding="utf-8",
    )

    report = scan_repository(str(repo))

    assert [finding.severity for finding in report.findings] == [
        "high",
        "medium",
        "low",
        "info",
    ]


def test_scan_repository_does_not_match_rule_definitions_or_documentation(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "sample-repo"
    repo.mkdir()
    (repo / ".gitignore").write_text(".env\n", encoding="utf-8")
    (repo / "pyproject.toml").write_text("[project]\nname = 'sample'\n", encoding="utf-8")
    (repo / "rules.py").write_text(
        "CORS_PATTERN = r'(allow_origins|Access-Control-Allow-Origin).*(\\\\*)'\n"
        "DEFAULT_PATTERN = r'(secret|secret_key).*(default|dev-secret)'\n"
        "HTML_PATTERN = r'dangerouslySetInnerHTML'\n"
        "database_url = settings.database_url.get_secret_value()\n"
        "database_url = resolve_database_url()\n",
        encoding="utf-8",
    )
    (repo / "security.md").write_text(
        "Avoid dangerouslySetInnerHTML and replace http://example.com URLs.\n",
        encoding="utf-8",
    )

    report = scan_repository(str(repo))

    assert [(finding.category, finding.severity) for finding in report.findings] == [
        ("dependency", "info")
    ]


def test_scan_repository_ignores_loopback_http_urls(tmp_path: Path) -> None:
    repo = tmp_path / "sample-repo"
    repo.mkdir()
    (repo / ".gitignore").write_text(".env\n", encoding="utf-8")
    (repo / "package.json").write_text("{}", encoding="utf-8")
    (repo / "client.ts").write_text(
        "const local = 'http://localhost:8000'\n"
        "const ipv4 = 'http://127.0.0.1:8000'\n"
        "const ipv6 = 'http://[::1]:8000'\n"
        "const remote = 'http://example.com'\n",
        encoding="utf-8",
    )

    report = scan_repository(str(repo))
    http_findings = [finding for finding in report.findings if finding.title == "Insecure HTTP URL"]

    assert len(http_findings) == 1
    assert http_findings[0].line == 4


def test_scan_repository_applies_sast_rules_to_supported_languages(tmp_path: Path) -> None:
    repo = tmp_path / "sample-repo"
    repo.mkdir()
    (repo / ".gitignore").write_text(".env\n", encoding="utf-8")
    (repo / "package.json").write_text("{}", encoding="utf-8")
    (repo / "notes.md").write_text(
        "subprocess.run(command, shell=True)\n<div dangerouslySetInnerHTML={{__html: html}} />\n",
        encoding="utf-8",
    )
    (repo / "client.ts").write_text(
        "subprocess.run(command, shell=True)\n",
        encoding="utf-8",
    )
    (repo / "component.tsx").write_text(
        "return <div dangerouslySetInnerHTML={{__html: html}} />\n",
        encoding="utf-8",
    )
    (repo / "main.py").write_text(
        "subprocess.run(command, shell=True)\n",
        encoding="utf-8",
    )

    report = scan_repository(str(repo))
    sast_findings = [finding for finding in report.findings if finding.category == "sast"]

    assert {(finding.title, finding.file_path) for finding in sast_findings} == {
        ("React dangerouslySetInnerHTML usage", "component.tsx"),
        ("Subprocess uses shell=True", "main.py"),
    }
