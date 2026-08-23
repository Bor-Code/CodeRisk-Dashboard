from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.jobs.worker import ScanWorker
from app.main import create_app


def _create_repository(client: TestClient, repo: Path) -> dict[str, object]:
    response = client.post(
        "/api/v1/repositories",
        json={"target": str(repo), "target_type": "local_path"},
    )
    assert response.status_code == 201
    return response.json()


def _make_repository(tmp_path: Path) -> Path:
    repo = tmp_path / "sample-repo"
    repo.mkdir()
    (repo / ".gitignore").write_text(".env\n", encoding="utf-8")
    (repo / "pyproject.toml").write_text("[project]\nname = 'sample'\n", encoding="utf-8")
    (repo / "settings.py").write_text("DEBUG=true\n", encoding="utf-8")
    return repo


def _process_scans(client: TestClient) -> None:
    settings = client.app.state.settings
    worker = ScanWorker(client.app.state.database, settings, worker_id="test-worker")
    while worker.run_once():
        pass


def test_repository_creation_is_idempotent_and_paginated(
    client: TestClient,
    tmp_path: Path,
) -> None:
    repo = _make_repository(tmp_path)
    created = _create_repository(client, repo)

    duplicate_response = client.post(
        "/api/v1/repositories",
        json={"target": str(repo), "target_type": "local_path"},
    )
    list_response = client.get("/api/v1/repositories?offset=0&limit=1")

    assert duplicate_response.status_code == 200
    assert duplicate_response.json()["id"] == created["id"]
    assert list_response.status_code == 200
    assert list_response.json()["total"] == 1
    assert list_response.json()["items"][0]["target"] == str(repo.resolve())


def test_v1_scan_history_filters_findings_and_exports_reports(
    client: TestClient,
    tmp_path: Path,
) -> None:
    repository = _create_repository(client, _make_repository(tmp_path))

    first_response = client.post(f"/api/v1/repositories/{repository['id']}/scans")
    second_response = client.post(f"/api/v1/repositories/{repository['id']}/scans")

    assert first_response.status_code == 202
    assert second_response.status_code == 202
    _process_scans(client)
    first_scan = client.get(f"/api/v1/scans/{first_response.json()['id']}").json()
    second_scan = client.get(f"/api/v1/scans/{second_response.json()['id']}").json()
    assert first_scan["id"] != second_scan["id"]
    assert first_scan["status"] == "completed"
    assert first_scan["severity_counts"]["medium"] == 1
    assert first_scan["engine_runs"][0]["engine"] == "builtin"
    assert first_scan["engine_runs"][0]["status"] == "completed"

    scans_response = client.get(
        f"/api/v1/scans?repository_id={repository['id']}&status=completed&severity=medium"
    )
    paged_response = client.get("/api/v1/scans?offset=0&limit=1")
    findings_response = client.get(
        f"/api/v1/scans/{first_scan['id']}/findings?severity=medium&category=config"
    )
    json_response = client.get(f"/api/v1/scans/{first_scan['id']}/reports/json")
    markdown_response = client.get(f"/api/v1/scans/{first_scan['id']}/reports/markdown")

    assert scans_response.status_code == 200
    assert scans_response.json()["total"] == 2
    assert paged_response.json()["total"] == 2
    assert len(paged_response.json()["items"]) == 1
    assert findings_response.status_code == 200
    assert findings_response.json()["total"] == 1
    assert findings_response.json()["items"][0]["title"] == "Debug mode appears enabled"
    assert json_response.status_code == 200
    assert json_response.json()["metadata"]["name"] == "sample-repo"
    assert markdown_response.status_code == 200
    assert "# CodeRisk Scan Report" in markdown_response.text


def test_scan_history_survives_application_restart(
    test_settings: Settings,
    tmp_path: Path,
) -> None:
    repo = _make_repository(tmp_path)
    first_application = create_app(test_settings)

    with TestClient(first_application) as first_client:
        repository = _create_repository(first_client, repo)
        scan_response = first_client.post(f"/api/v1/repositories/{repository['id']}/scans")
        scan_id = scan_response.json()["id"]
        _process_scans(first_client)

    second_application = create_app(test_settings)

    with TestClient(second_application) as second_client:
        detail_response = second_client.get(f"/api/v1/scans/{scan_id}")
        legacy_response = second_client.get("/reports/latest.json")

    assert detail_response.status_code == 200
    assert detail_response.json()["id"] == scan_id
    assert legacy_response.status_code == 200
    assert legacy_response.json()["metadata"]["name"] == "sample-repo"


def test_persisted_secret_evidence_remains_masked(
    client: TestClient,
    tmp_path: Path,
) -> None:
    repo = _make_repository(tmp_path)
    raw_credential = "admin:secret"
    (repo / "database.py").write_text(
        f"DATABASE_URL=postgresql://{raw_credential}@example.com/app\n",
        encoding="utf-8",
    )
    repository = _create_repository(client, repo)

    scan_response = client.post(f"/api/v1/repositories/{repository['id']}/scans")
    scan_id = scan_response.json()["id"]
    _process_scans(client)
    findings_response = client.get(f"/api/v1/scans/{scan_id}/findings?category=secret")
    report_response = client.get(f"/api/v1/scans/{scan_id}/reports/json")

    assert scan_response.status_code == 202
    assert findings_response.json()["total"] == 1
    assert raw_credential not in findings_response.text
    assert raw_credential not in report_response.text
    assert "***" in findings_response.json()["items"][0]["evidence"]


def test_scan_failure_is_persisted_without_exposing_internal_error_details(
    client: TestClient,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _create_repository(client, _make_repository(tmp_path))

    def fail_scan(*args, **kwargs):
        from app.jobs.errors import ScanProcessError

        raise ScanProcessError()

    monkeypatch.setattr("app.jobs.executor.ProcessScanExecutor.execute", fail_scan)
    response = client.post(f"/api/v1/repositories/{repository['id']}/scans")
    _process_scans(client)
    scans_response = client.get("/api/v1/scans?status=failed")

    assert response.status_code == 202
    assert scans_response.json()["total"] == 1

    failed_scan_id = scans_response.json()["items"][0]["id"]
    detail_response = client.get(f"/api/v1/scans/{failed_scan_id}")

    assert detail_response.json()["status"] == "failed"
    assert detail_response.json()["engine_runs"][0]["status"] == "failed"
    assert detail_response.json()["finding_count"] == 0


def test_repository_creation_masks_path_resolution_errors(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_resolution(_path: Path) -> Path:
        raise OSError("private filesystem detail")

    monkeypatch.setattr(Path, "resolve", fail_resolution)
    response = client.post(
        "/api/v1/repositories",
        json={"target": "unresolvable", "target_type": "local_path"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Repo path must point to an existing directory."
    assert "private filesystem detail" not in response.text


def test_v1_returns_problem_details_without_echoing_invalid_input(
    client: TestClient,
) -> None:
    missing_response = client.get("/api/v1/scans/not-a-real-scan")
    validation_response = client.get("/api/v1/scans?limit=0")

    assert missing_response.status_code == 404
    assert missing_response.headers["content-type"].startswith("application/problem+json")
    assert missing_response.json() == {
        "type": "urn:coderisk:problem:not_found",
        "title": "Resource not found",
        "status": 404,
        "detail": "Scan was not found.",
        "instance": "/api/v1/scans/not-a-real-scan",
        "code": "not_found",
    }
    assert validation_response.status_code == 422
    assert validation_response.json()["detail"] == "The request does not match the API contract."
    assert "input" not in validation_response.text
