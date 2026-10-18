"""Application factory."""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator

from fastapi import APIRouter, Depends, FastAPI

from certfabric.api import auth as auth_api
from certfabric.api import system as system_api
from certfabric.api.deps import require_session
from certfabric.clock import Clock, SystemClock
from certfabric.config import Settings, load_settings
from certfabric.db import Database, migrate
from certfabric.scheduler import Scheduler
from certfabric.vault import Vault

# Routers in this list are reachable only with a valid admin session.
PROTECTED_ROUTERS: list[APIRouter] = [system_api.router]


def create_app(settings: Settings, clock: Clock | None = None) -> FastAPI:
    clock = clock or SystemClock()

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        await asyncio.to_thread(migrate, settings.db_path)
        app.state.db = Database(settings.db_path)
        loop_task = (
            asyncio.create_task(app.state.scheduler.run_forever()) if settings.run_scheduler else None
        )
        try:
            yield
        finally:
            if loop_task:
                loop_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await loop_task
            await app.state.db.dispose()

    app = FastAPI(title="CertFabric", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.clock = clock
    app.state.vault = Vault(settings.secret_key)
    app.state.scheduler = Scheduler(clock)

    app.include_router(auth_api.router)
    for router in PROTECTED_ROUTERS:
        app.include_router(router, dependencies=[Depends(require_session)])
    return app


def create_app_from_env() -> FastAPI:
    """Entry point for uvicorn. Raises ConfigError when no usable secret key is configured."""
    return create_app(load_settings())
