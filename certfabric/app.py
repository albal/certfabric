"""Application factory."""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator

from fastapi import APIRouter, Depends, FastAPI

from certfabric import devices, spa
from certfabric.acme import AcmeRunner
from certfabric.api import auth as auth_api
from certfabric.api import certificates as certificates_api
from certfabric.api import dashboard as dashboard_api
from certfabric.api import devices as devices_api
from certfabric.api import dns_providers as dns_providers_api
from certfabric.api import events as events_api
from certfabric.api import jobs as jobs_api
from certfabric.api import plugins as plugins_api
from certfabric.api import settings as settings_api
from certfabric.api import system as system_api
from certfabric.api import webhooks as webhooks_api
from certfabric.api.deps import require_session
from certfabric.clock import Clock, SystemClock
from certfabric.config import Settings, load_settings
from certfabric.db import Database, migrate
from certfabric.deployments import RETRY_SWEEP_INTERVAL, Deployer
from certfabric.jobs import JobRegistry
from certfabric.notifier import Notifier
from certfabric.plugins.registry import BUILTIN_DIR, PluginRegistry
from certfabric.renewal import RENEWAL_CHECK_INTERVAL, Renewer
from certfabric.scheduler import Scheduler
from certfabric.vault import Vault

# Routers in this list are reachable only with a valid admin session.
PROTECTED_ROUTERS: list[APIRouter] = [
    system_api.router,
    settings_api.router,
    dns_providers_api.router,
    certificates_api.router,
    devices_api.router,
    plugins_api.router,
    jobs_api.router,
    webhooks_api.router,
    events_api.router,
    dashboard_api.router,
]


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
            await app.state.jobs.shutdown()
            await app.state.notifier.drain()
            await app.state.db.dispose()

    app = FastAPI(title="CertFabric", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.clock = clock
    app.state.vault = Vault(settings.secret_key)
    app.state.scheduler = Scheduler(clock)
    app.state.jobs = JobRegistry()
    app.state.acme = AcmeRunner(settings.acme_sh)
    app.state.plugins = PluginRegistry([BUILTIN_DIR, *settings.plugin_dirs])
    app.state.deployer = Deployer(app.state)
    app.state.notifier = Notifier(app.state)
    app.state.scheduler.add_job("deploy-retry", RETRY_SWEEP_INTERVAL, app.state.deployer.retry_due)
    app.state.renewer = Renewer(app.state)
    app.state.scheduler.add_job("renewal-check", RENEWAL_CHECK_INTERVAL, app.state.renewer.check, run_immediately=True)
    app.state.scheduler.add_job("probe-sweep", devices.SWEEP_INTERVAL, lambda: devices.sweep(app.state))

    app.include_router(auth_api.router)
    for router in PROTECTED_ROUTERS:
        app.include_router(router, dependencies=[Depends(require_session)])
    if dist := spa.find_dist(settings.frontend_dir):
        spa.mount(app, dist)  # last, so it never shadows an API route
    return app


def create_app_from_env() -> FastAPI:
    """Entry point for uvicorn. Raises ConfigError when no usable secret key is configured."""
    return create_app(load_settings())
