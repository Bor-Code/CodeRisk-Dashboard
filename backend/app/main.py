from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from app.reporting import report_to_markdown
from app.scanner import ScanReport, scan_repository

app = FastAPI(title="CodeRisk Dashboard API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

LAST_REPORT: ScanReport | None = None


class ScanRequest(BaseModel):
    target: str = Field(min_length=1)
    target_type: Literal["local_path", "github_url"] = "local_path"


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan")
def scan(request: ScanRequest) -> dict[str, object]:
    global LAST_REPORT

    if request.target_type == "github_url":
        raise HTTPException(
            status_code=400,
            detail="GitHub URL scanning is planned, but remote clone is disabled in the MVP.",
        )

    try:
        LAST_REPORT = scan_repository(request.target)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    return LAST_REPORT.to_dict()


@app.get("/reports/latest.json")
def latest_json_report() -> dict[str, object]:
    if LAST_REPORT is None:
        raise HTTPException(status_code=404, detail="No scan report exists yet.")

    return LAST_REPORT.to_dict()


@app.get("/reports/latest.md", response_class=PlainTextResponse)
def latest_markdown_report() -> str:
    if LAST_REPORT is None:
        raise HTTPException(status_code=404, detail="No scan report exists yet.")

    return report_to_markdown(LAST_REPORT)
