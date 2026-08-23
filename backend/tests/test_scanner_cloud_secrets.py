from pathlib import Path

from app.scanner import scan_repository


def test_scan_repository_detects_cloud_and_gitlab_secrets(tmp_path: Path) -> None:
    repo = tmp_path / "sample-repo"
    repo.mkdir()
    (repo / ".gitignore").write_text(".env\n", encoding="utf-8")
    (repo / "pyproject.toml").write_text("[project]\nname = 'sample'\n", encoding="utf-8")
    (repo / ".env").write_text(
        "AWS_ACCESS_KEY_ID=AKIA1234567890123456\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "GITLAB_TOKEN=glpat-abcdefghijklmnopqrstuvwxyz123456\n"
        "GOOGLE_API_KEY=AIzaSyD1e5fG3hJ7kL9mN2pQ4rT6uV8wX0yZ2aB\n",
        encoding="utf-8",
    )

    report = scan_repository(str(repo))
    titles = {finding.title for finding in report.findings}

    assert "Possible AWS access key exposure" in titles
    assert "Possible AWS secret access key exposure" in titles
    assert "Possible GitLab personal access token exposure" in titles
    assert "Possible Google API key exposure" in titles


def test_scan_repository_detects_aws_role_arn(tmp_path: Path) -> None:
    repo = tmp_path / "sample-repo"
    repo.mkdir()
    (repo / ".gitignore").write_text(".env\n", encoding="utf-8")
    (repo / "aws-role.txt").write_text(
        "arn:aws:iam::123456789012:role/deploy-admin\n",
        encoding="utf-8",
    )

    report = scan_repository(str(repo))

    assert any(finding.title == "Possible AWS role ARN exposure" for finding in report.findings)
    assert any("masked" in finding.evidence for finding in report.findings)
