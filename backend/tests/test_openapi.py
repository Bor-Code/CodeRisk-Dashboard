import json
from pathlib import Path

from scripts.openapi_contract import render_openapi_contract

CONTRACT_PATH = Path(__file__).resolve().parents[2] / "docs" / "openapi.json"


def test_committed_openapi_contract_is_current() -> None:
    rendered_contract = render_openapi_contract()

    assert CONTRACT_PATH.read_text(encoding="utf-8") == rendered_contract


def test_openapi_documents_problem_details_and_legacy_deprecations() -> None:
    contract = json.loads(render_openapi_contract())
    create_repository = contract["paths"]["/api/v1/repositories"]["post"]
    list_scans = contract["paths"]["/api/v1/scans"]["get"]

    assert set(create_repository["responses"]["400"]["content"]) == {"application/problem+json"}
    assert set(list_scans["responses"]["422"]["content"]) == {"application/problem+json"}
    assert contract["paths"]["/scan"]["post"]["deprecated"] is True
    assert contract["info"]["version"] == "0.2.0"
