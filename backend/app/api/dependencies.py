from collections.abc import Generator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.db.session import Database
from app.services.scans import ScanService


def get_session(request: Request) -> Generator[Session, None, None]:
    database: Database = request.app.state.database

    with database.session_factory() as session:
        try:
            yield session
        except Exception:
            session.rollback()
            raise


SessionDependency = Annotated[Session, Depends(get_session)]


def get_scan_service(session: SessionDependency) -> ScanService:
    return ScanService(session)


ScanServiceDependency = Annotated[ScanService, Depends(get_scan_service)]
