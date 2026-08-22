from typing import Annotated

from fastapi import APIRouter, Query, Response, status
from fastapi.responses import PlainTextResponse

from app.api.dependencies import ScanServiceDependency
from app.api.v1.schemas import (
    FindingResponse,
    Page,
    ProblemDetail,
    RepositoryCreateRequest,
    RepositoryResponse,
    ScanDetailResponse,
    ScanReportResponse,
    ScanSummaryResponse,
    finding_response,
    report_response,
    repository_response,
    scan_detail_response,
    scan_summary_response,
)
from app.domain.entities import ScanStatus
from app.domain.reports import FindingCategory, Severity
from app.reporting import report_to_markdown

router = APIRouter(prefix="/api/v1")

PROBLEM_CONTENT = {"application/problem+json": {"schema": ProblemDetail.model_json_schema()}}
ERROR_RESPONSES = {
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
    response_model=ScanDetailResponse,
    status_code=status.HTTP_201_CREATED,
    responses=ERROR_RESPONSES,
)
def create_scan(
    repository_id: str,
    service: ScanServiceDependency,
) -> ScanDetailResponse:
    return scan_detail_response(service.run_scan(repository_id))


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
