from http import HTTPStatus

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api.v1.schemas import ProblemDetail
from app.core.errors import ApplicationError

PROBLEM_MEDIA_TYPE = "application/problem+json"


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(ApplicationError, application_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(HTTPException, http_error_handler)


async def application_error_handler(
    request: Request,
    error: Exception,
) -> JSONResponse:
    application_error = error
    assert isinstance(application_error, ApplicationError)
    return _problem_response(
        request=request,
        status=application_error.status_code,
        title=application_error.title,
        detail=application_error.detail,
        code=application_error.code,
    )


async def validation_error_handler(
    request: Request,
    _error: Exception,
) -> JSONResponse:
    return _problem_response(
        request=request,
        status=422,
        title="Request validation failed",
        detail="The request does not match the API contract.",
        code="invalid_request",
    )


async def http_error_handler(request: Request, error: Exception) -> JSONResponse:
    http_error = error
    assert isinstance(http_error, HTTPException)
    title = HTTPStatus(http_error.status_code).phrase
    detail = http_error.detail if isinstance(http_error.detail, str) else title
    return _problem_response(
        request=request,
        status=http_error.status_code,
        title=title,
        detail=detail,
        code="http_error",
    )


def _problem_response(
    *,
    request: Request,
    status: int,
    title: str,
    detail: str,
    code: str,
) -> JSONResponse:
    problem = ProblemDetail(
        type=f"urn:coderisk:problem:{code}",
        title=title,
        status=status,
        detail=detail,
        instance=request.url.path,
        code=code,
    )
    return JSONResponse(
        status_code=status,
        content=problem.model_dump(),
        media_type=PROBLEM_MEDIA_TYPE,
    )
