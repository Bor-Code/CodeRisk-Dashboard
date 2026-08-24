from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Response, status
from fastapi.responses import PlainTextResponse

from app.api.dependencies import ScanServiceDependency
from app.api.v1.schemas import (
    FindingResponse,
    IgnoreFindingRequest,
    Page,
    ProblemDetail,
    RepositoryCreateRequest,
    RepositoryResponse,
    ScanDetailResponse,
    ScanDiffResponse,
    ScanReportResponse,
    ScanSummaryResponse,
    finding_response,
    report_response,
    repository_response,
    scan_detail_response,
    scan_summary_response,
)
from app.auth.jwt import require_jwt
from app.domain.entities import ScanStatus
from app.domain.reports import FindingCategory, Severity
from app.reporting import report_to_markdown

router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_jwt)])

PROBLEM_CONTENT = {"application/problem+json": {"schema": ProblemDetail.model_json_schema()}}

ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    400: {"description": "Invalid scan target", "content": PROBLEM_CONTENT},
    404: {"description": "Resource not found", "content": PROBLEM_CONTENT},
    422: {"description": "Request validation failed", "content": PROBLEM_CONTENT},
    500: {"description": "Scan execution failed", "content": PROBLEM_CONTENT},
}


@router.post(
    "/repositories",
    response_model=RepositoryResponse,
    status_code=status.HTTP_201_CREATED,
    responses=ERROR_RESPONSES,
)
def create_repository(
    request: RepositoryCreateRequest,
    response: Response,
    service: ScanServiceDependency,
) -> RepositoryResponse:
    repository, created = service.create_repository(
        target=request.target,
        target_type=request.target_type,
    )

    if not created:
        response.status_code = status.HTTP_200_OK

    return repository_response(repository)


@router.get(
    "/repositories",
    response_model=Page[RepositoryResponse],
    responses=ERROR_RESPONSES,
)
def list_repositories(
    service: ScanServiceDependency,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> Page[RepositoryResponse]:
    repositories, total = service.list_repositories(offset=offset, limit=limit)
    return Page[RepositoryResponse](
        items=[repository_response(item) for item in repositories],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.post(
    "/repositories/{repository_id}/scans",
    response_model=ScanSummaryResponse,
    status_code=status.HTTP_202_ACCEPTED,
    responses=ERROR_RESPONSES,
)
def create_scan(
    repository_id: str,
    response: Response,
    service: ScanServiceDependency,
) -> ScanSummaryResponse:
    scan = service.enqueue_scan(repository_id)
    response.headers["Location"] = f"/api/v1/scans/{scan.id}"
    return scan_summary_response(scan)


@router.get(
    "/scans",
    response_model=Page[ScanSummaryResponse],
    responses=ERROR_RESPONSES,
)
def list_scans(
    service: ScanServiceDependency,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    repository_id: str | None = None,
    scan_status: Annotated[ScanStatus | None, Query(alias="status")] = None,
    severity: Severity | None = None,
) -> Page[ScanSummaryResponse]:
    scans, total = service.list_scans(
        offset=offset,
        limit=limit,
        repository_id=repository_id,
        status=scan_status,
        severity=severity,
    )
    return Page[ScanSummaryResponse](
        items=[scan_summary_response(item) for item in scans],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.post(
    "/scans/{scan_id}/cancel",
    status_code=status.HTTP_202_ACCEPTED,
    responses=ERROR_RESPONSES,
)
def cancel_scan(scan_id: str, service: ScanServiceDependency) -> dict[str, str]:
    service.cancel_scan(scan_id)
    return {"status": "cancelling"}


@router.get(
    "/scans/{scan_id}",
    response_model=ScanDetailResponse,
    responses=ERROR_RESPONSES,
)
def get_scan(scan_id: str, service: ScanServiceDependency) -> ScanDetailResponse:
    return scan_detail_response(service.get_scan(scan_id))


@router.get(
    "/scans/{scan_id}/findings",
    response_model=Page[FindingResponse],
    responses=ERROR_RESPONSES,
)
def list_findings(
    scan_id: str,
    service: ScanServiceDependency,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    severity: Severity | None = None,
    category: FindingCategory | None = None,
) -> Page[FindingResponse]:
    findings, total = service.list_findings(
        scan_id,
        offset=offset,
        limit=limit,
        severity=severity,
        category=category,
    )
    return Page[FindingResponse](
        items=[finding_response(item) for item in findings],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get(
    "/scans/{scan_id}/diff",
    response_model=ScanDiffResponse,
    responses=ERROR_RESPONSES,
)
def get_scan_diff(scan_id: str, service: ScanServiceDependency) -> ScanDiffResponse:
    diff = service.get_scan_diff(scan_id)
    return ScanDiffResponse(
        new=[finding_response(item) for item in diff["new"]],
        resolved=[finding_response(item) for item in diff["resolved"]],
        persistent=[finding_response(item) for item in diff["persistent"]],
    )


@router.post(
    "/repositories/{repository_id}/ignored-findings",
    status_code=status.HTTP_201_CREATED,
    responses=ERROR_RESPONSES,
)
def ignore_finding(
    repository_id: str,
    request: IgnoreFindingRequest,
    service: ScanServiceDependency,
) -> dict[str, str]:
    service.ignore_finding(repository_id, request.source_finding_id, request.reason)
    return {"status": "ignored"}


@router.delete(
    "/repositories/{repository_id}/ignored-findings/{source_finding_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=ERROR_RESPONSES,
)
def unignore_finding(
    repository_id: str,
    source_finding_id: str,
    service: ScanServiceDependency,
) -> None:
    service.unignore_finding(repository_id, source_finding_id)


@router.get(
    "/scans/{scan_id}/reports/json",
    response_model=ScanReportResponse,
    responses=ERROR_RESPONSES,
)
def get_json_report(
    scan_id: str,
    service: ScanServiceDependency,
) -> ScanReportResponse:
    return report_response(service.get_report(scan_id))


@router.get(
    "/scans/{scan_id}/reports/markdown",
    response_class=PlainTextResponse,
    responses=ERROR_RESPONSES,
)
def get_markdown_report(scan_id: str, service: ScanServiceDependency) -> str:
    return report_to_markdown(service.get_report(scan_id))


@router.get(
    "/scans/{scan_id}/sbom",
    responses=ERROR_RESPONSES,
)
def get_sbom_report(
    scan_id: str,
    service: ScanServiceDependency,
) -> dict:
    return service.get_sbom(scan_id)


@router.get(
    "/engines",
    response_model=dict[str, bool],
    summary="List external engine availability",
    description=(
        "Returns a map of engine identifiers to availability status. "
        "An engine is available when its binary is installed and on PATH."
    ),
)
def list_engines() -> dict[str, bool]:
    from app.engines.registry import engine_availability  # noqa: PLC0415

    return engine_availability()
