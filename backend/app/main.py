# ruff: noqa: E402
import logging
import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

bin_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bin"))
os.environ["PATH"] = bin_dir + os.pathsep + os.environ.get("PATH", "")

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.errors import register_exception_handlers
from app.api.legacy import router as legacy_router
from app.api.v1.auth import router as auth_router
from app.api.v1.extensions import router as extensions_router
from app.api.v1.router import router as v1_router
from app.core.config import Settings, get_settings
from app.db.session import create_database, prepare_database


def create_app(settings: Settings | None = None) -> FastAPI:
    runtime_settings = settings or get_settings()

    # Configure logging
    log_level = logging.INFO if runtime_settings.environment == "production" else logging.DEBUG
    logging.basicConfig(
        stream=sys.stdout,
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logger = logging.getLogger("coderisk")
    logger.info("Starting CodeRisk backend...", extra={"environment": runtime_settings.environment})

    database = create_database(runtime_settings)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        import threading

        from app.jobs.worker import ScanWorker

        stop_event = threading.Event()
        worker = ScanWorker(database, runtime_settings)
        worker_thread = threading.Thread(target=worker.run_forever, args=(stop_event,), daemon=True)

        try:
            prepare_database(
                database,
                auto_create=runtime_settings.database_auto_create,
            )
            worker_thread.start()
            yield
        finally:
            stop_event.set()
            if worker_thread.is_alive():
                worker_thread.join(timeout=runtime_settings.scan_terminate_grace_seconds)
            database.engine.dispose()

    application = FastAPI(
        title="CodeRisk Dashboard API",
        version="0.2.0",
        description=(
            "Persistent, versioned API for local repository security scans. "
            "Legacy MVP routes remain available during the dashboard migration."
        ),
        lifespan=lifespan,
    )
    application.state.database = database
    application.state.settings = runtime_settings
    application.dependency_overrides[get_settings] = lambda: runtime_settings
    application.add_middleware(
        CORSMiddleware,
        allow_origins=runtime_settings.cors_origins,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    register_exception_handlers(application)
    application.include_router(legacy_router)
    application.include_router(auth_router)
    application.include_router(v1_router)
    application.include_router(extensions_router)
    return application


app = create_app()
