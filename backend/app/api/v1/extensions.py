from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text

from app.api.dependencies import SessionDependency
from app.auth.jwt import require_jwt
from app.db.models import FindingModel, IntegrationModel, PolicyModel, ScanModel, UserModel

router = APIRouter(prefix="/api/v1/extensions", dependencies=[Depends(require_jwt)])


class ExtensionUserResponse(BaseModel):
    id: str
    username: str
    first_name: str
    last_name: str
    phone_number: str
    created_at: datetime


class GlobalFindingResponse(BaseModel):
    id: str
    scan_id: str
    title: str
    severity: str
    category: str
    file_path: str
    created_at: datetime


class ScanHistoryPoint(BaseModel):
    date: str
    scans: int


class StatsResponse(BaseModel):
    total_scans: int
    total_findings: int
    high_findings: int
    history: list[ScanHistoryPoint]


class IntegrationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    integration_type: str = Field(min_length=1, max_length=64)
    credentials: str = Field(min_length=1)


class IntegrationResponse(BaseModel):
    id: str
    name: str
    type: str


class PolicyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    rule_type: str = Field(min_length=1, max_length=64)
    rule_value: str = Field(min_length=1)


class PolicyResponse(BaseModel):
    id: str
    name: str
    rule_type: str
    rule_value: str


@router.get("/users", response_model=list[ExtensionUserResponse])
def get_users(db: SessionDependency) -> list[ExtensionUserResponse]:
    users = db.scalars(select(UserModel).order_by(UserModel.created_at.desc())).all()
    return [
        ExtensionUserResponse(
            id=user.id,
            username=user.username,
            first_name=user.first_name,
            last_name=user.last_name,
            phone_number=user.phone_number,
            created_at=user.created_at,
        )
        for user in users
    ]


@router.get("/findings/all", response_model=list[GlobalFindingResponse])
def get_all_findings(db: SessionDependency) -> list[GlobalFindingResponse]:
    findings = db.scalars(
        select(FindingModel).order_by(FindingModel.created_at.desc()).limit(100)
    ).all()
    return [
        GlobalFindingResponse(
            id=finding.id,
            scan_id=finding.scan_id,
            title=finding.title,
            severity=finding.severity,
            category=finding.category,
            file_path=finding.file_path,
            created_at=finding.created_at,
        )
        for finding in findings
    ]


@router.get("/stats", response_model=StatsResponse)
def get_stats(db: SessionDependency) -> StatsResponse:
    total_scans = db.scalar(select(func.count(ScanModel.id))) or 0
    total_findings = db.scalar(select(func.count(FindingModel.id))) or 0
    high_findings = (
        db.scalar(select(func.count(FindingModel.id)).where(FindingModel.severity == "high")) or 0
    )

    history_sql = """
    SELECT date(created_at) as d, COUNT(id) as c
    FROM scans
    GROUP BY date(created_at)
    ORDER BY date(created_at) DESC LIMIT 7
    """
    history_records = db.execute(text(history_sql)).fetchall()
    history = [ScanHistoryPoint(date=record.d, scans=record.c) for record in history_records]
    history.reverse()

    return StatsResponse(
        total_scans=total_scans,
        total_findings=total_findings,
        high_findings=high_findings,
        history=history,
    )


@router.get("/integrations", response_model=list[IntegrationResponse])
def get_integrations(db: SessionDependency) -> list[IntegrationResponse]:
    statement = select(IntegrationModel).order_by(IntegrationModel.created_at.desc())
    integrations = db.scalars(statement).all()
    return [
        IntegrationResponse(
            id=integration.id,
            name=integration.name,
            type=integration.integration_type,
        )
        for integration in integrations
    ]


@router.post("/integrations", response_model=IntegrationResponse)
def create_integration(
    integration: IntegrationCreate, db: SessionDependency
) -> IntegrationResponse:
    db_obj = IntegrationModel(
        name=integration.name,
        integration_type=integration.integration_type,
        credentials=integration.credentials,
    )
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    return IntegrationResponse(id=db_obj.id, name=db_obj.name, type=db_obj.integration_type)


@router.get("/policies", response_model=list[PolicyResponse])
def get_policies(db: SessionDependency) -> list[PolicyResponse]:
    policies = db.scalars(select(PolicyModel).order_by(PolicyModel.created_at.desc())).all()
    return [
        PolicyResponse(
            id=policy.id,
            name=policy.name,
            rule_type=policy.rule_type,
            rule_value=policy.rule_value,
        )
        for policy in policies
    ]


@router.post("/policies", response_model=PolicyResponse)
def create_policy(policy: PolicyCreate, db: SessionDependency) -> PolicyResponse:
    db_obj = PolicyModel(
        name=policy.name,
        rule_type=policy.rule_type,
        rule_value=policy.rule_value,
    )
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    return PolicyResponse(
        id=db_obj.id,
        name=db_obj.name,
        rule_type=db_obj.rule_type,
        rule_value=db_obj.rule_value,
    )
