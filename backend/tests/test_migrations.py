from pathlib import Path

from alembic.config import Config
from sqlalchemy import create_engine, inspect

from alembic import command
from app.db.session import REQUIRED_TABLES

BACKEND_ROOT = Path(__file__).resolve().parents[1]


def test_initial_migration_upgrades_and_downgrades(tmp_path: Path) -> None:
    database_path = (tmp_path / "migration.db").as_posix()
    database_url = f"sqlite+pysqlite:///{database_path}"
    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", database_url)

    command.upgrade(config, "head")

    engine = create_engine(database_url)
    with engine.connect() as connection:
        assert REQUIRED_TABLES <= set(inspect(connection).get_table_names())

    command.check(config)
    command.downgrade(config, "base")

    with engine.connect() as connection:
        assert REQUIRED_TABLES.isdisjoint(inspect(connection).get_table_names())
    engine.dispose()
