from dataclasses import dataclass

from sqlalchemy import Engine, create_engine, event, inspect, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool, StaticPool

from app.core.config import Settings
from app.db.base import Base
from app.db.models import (
    EngineRunModel,
    FindingModel,
    IgnoredFindingModel,
    IntegrationModel,
    PolicyModel,
    RepositoryModel,
    SbomModel,
    ScanModel,
    UserModel,
)

REQUIRED_TABLES = {
    RepositoryModel.__tablename__,
    ScanModel.__tablename__,
    FindingModel.__tablename__,
    EngineRunModel.__tablename__,
    IgnoredFindingModel.__tablename__,
    UserModel.__tablename__,
    SbomModel.__tablename__,
    IntegrationModel.__tablename__,
    PolicyModel.__tablename__,
}
SCHEMA_REVISION = "20260825_0001"


@dataclass(frozen=True)
class Database:
    engine: Engine
    session_factory: sessionmaker[Session]


def create_database(settings: Settings) -> Database:
    database_url = settings.database_url.get_secret_value()
    engine_kwargs: dict[str, object] = {
        "echo": settings.database_echo,
        "pool_pre_ping": True,
    }

    if database_url.startswith("sqlite"):
        engine_kwargs["connect_args"] = {"check_same_thread": False}
        engine_kwargs["poolclass"] = StaticPool if ":memory:" in database_url else NullPool

    engine = create_engine(database_url, **engine_kwargs)

    if database_url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return Database(
        engine=engine,
        session_factory=sessionmaker(
            bind=engine,
            autoflush=False,
            expire_on_commit=False,
        ),
    )


def prepare_database(database: Database, *, auto_create: bool) -> None:
    if auto_create:
        Base.metadata.create_all(database.engine)
        return

    existing_tables = set(inspect(database.engine).get_table_names())
    missing_tables = REQUIRED_TABLES - existing_tables

    if missing_tables:
        missing = ", ".join(sorted(missing_tables))
        raise RuntimeError(
            f"Database schema is not initialized (missing: {missing}). "
            "Run `uv run alembic upgrade head` from the backend directory."
        )

    if "alembic_version" not in existing_tables:
        raise RuntimeError(
            "Database migration revision is missing. "
            "Run `uv run alembic upgrade head` from the backend directory."
        )

    with database.engine.connect() as connection:
        current_revision = connection.scalar(text("SELECT version_num FROM alembic_version"))

    if current_revision != SCHEMA_REVISION:
        raise RuntimeError(
            f"Database schema revision is {current_revision!r}; expected {SCHEMA_REVISION!r}. "
            "Run `uv run alembic upgrade head` from the backend directory."
        )
