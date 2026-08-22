from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app


def test_latest_report_exports_json_and_markdown(tmp_path: Path) -> None:
    repo = tmp_path / "sample-repo"
    repo.mkdir()
    (repo / ".gitignore").write_text(".env\n", encoding="utf-8")
    (repo / "pyproject.toml").write_text("[project]\nname = 'sample'\n", encoding="utf-8")

    client = TestClient(app)

    scan_response = client.post(
        "/scan",
        json={"target": str(repo), "target_type": "local_path"},
    )
    json_response = client.get("/reports/latest.json")
    markdown_response = client.get("/reports/latest.md")

    assert scan_response.status_code == 200
    assert json_response.status_code == 200
    assert markdown_response.status_code == 200
    assert json_response.json()["metadata"]["name"] == "sample-repo"
    assert "# CodeRisk Scan Report" in markdown_response.text
    assert "Dependency manifest files detected" in markdown_response.text


def test_latest_report_returns_404_before_scan() -> None:
    from app import main

    previous_report = main.LAST_REPORT
    main.LAST_REPORT = None

    try:
        client = TestClient(app)

        json_response = client.get("/reports/latest.json")
        markdown_response = client.get("/reports/latest.md")

        assert json_response.status_code == 404
        assert markdown_response.status_code == 404
        assert json_response.json()["detail"] == "No scan report exists yet."
        assert markdown_response.json()["detail"] == "No scan report exists yet."
    finally:
        main.LAST_REPORT = previous_report
