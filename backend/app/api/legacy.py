from fastapi import APIRouter
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from app.api.dependencies import ScanServiceDependency
from app.core.errors import ResourceNotFoundError
from app.domain.entities import RepositoryTargetType
from app.reporting import report_to_markdown

router = APIRouter()


class ScanRequest(BaseModel):
    target: str = Field(min_length=1)
    target_type: RepositoryTargetType = "local_path"


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.post("/scan", deprecated=True)
def scan(
    request: ScanRequest,
    service: ScanServiceDependency,
) -> dict[str, object]:
    persisted_scan = service.scan_target(
        target=request.target,
        target_type=request.target_type,
    )

    if persisted_scan.report is None:
        raise ResourceNotFoundError("The scan does not have a completed report.")

    return persisted_scan.report.to_dict()


@router.get("/reports/latest.json", deprecated=True)
def latest_json_report(service: ScanServiceDependency) -> dict[str, object]:
    persisted_scan = service.get_latest_completed_scan()

    if persisted_scan.report is None:
        raise ResourceNotFoundError("No scan report exists yet.")

    return persisted_scan.report.to_dict()


@router.get(
    "/reports/latest.md",
    response_class=PlainTextResponse,
    deprecated=True,
)
def latest_markdown_report(service: ScanServiceDependency) -> str:
    persisted_scan = service.get_latest_completed_scan()

    if persisted_scan.report is None:
        raise ResourceNotFoundError("No scan report exists yet.")

    return report_to_markdown(persisted_scan.report)
