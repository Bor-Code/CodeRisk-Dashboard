from pathlib import Path

from app.scanner import scan_repository


def test_scan_repository_detects_weak_jwt_secret(tmp_path: Path) -> None:
    repo = tmp_path / "sample-repo"
    repo.mkdir()
    (repo / ".gitignore").write_text(".env\n", encoding="utf-8")
    (repo / "pyproject.toml").write_text("[project]\nname = 'sample'\n", encoding="utf-8")
    # short secret (less than or equal to 15 chars) should be flagged as weak
    (repo / "settings.py").write_text("JWT_SECRET='shortsecret'\n", encoding="utf-8")

    report = scan_repository(str(repo))

    titles = {finding.title for finding in report.findings}

    assert "Weak JWT secret detected" in titles
