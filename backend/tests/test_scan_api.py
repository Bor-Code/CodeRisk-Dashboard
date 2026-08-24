from pathlib import Path

from fastapi.testclient import TestClient


def test_scan_endpoint_scans_local_path(client: TestClient, tmp_path: Path) -> None:
    repo = tmp_path / "sample-repo"
    repo.mkdir()
    (repo / ".gitignore").write_text(".env\n", encoding="utf-8")
    (repo / "pyproject.toml").write_text("[project]\nname = 'sample'\n", encoding="utf-8")

    response = client.post(
        "/scan",
        json={"target": str(repo), "target_type": "local_path"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["metadata"]["name"] == "sample-repo"
    assert payload["metadata"]["dependency_files"] == ["pyproject.toml"]
    assert payload["score"] == 100


def test_scan_endpoint_rejects_missing_local_path(client: TestClient, tmp_path: Path) -> None:
    response = client.post(
        "/scan",
        json={"target": str(tmp_path / "missing"), "target_type": "local_path"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Repo path must point to an existing directory."
    assert response.headers["content-type"].startswith("application/problem+json")


def test_scan_endpoint_rejects_github_url_for_legacy(client: TestClient) -> None:
    response = client.post(
        "/scan",
        json={
            "target": "https://github.com/Bor-Code/CodeRisk-Dashboard",
            "target_type": "github_url",
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Repo path must point to an existing directory."
