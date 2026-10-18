"""Seam 1 harness: the real application with a fake clock, driven over HTTP."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI

from certfabric.app import create_app
from certfabric.clock import FakeClock
from certfabric.config import Settings
from certfabric.scheduler import Scheduler

ADMIN_PASSWORD = "correct horse battery staple"
BASE_URL = "http://certfabric.test"


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(secret_key=Fernet.generate_key(), db_path=tmp_path / "certfabric.db", run_scheduler=False)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
async def app(settings: Settings, clock: FakeClock) -> AsyncIterator[FastAPI]:
    app = create_app(settings, clock)
    async with app.router.lifespan_context(app):
        yield app


@pytest.fixture
def scheduler(app: FastAPI) -> Scheduler:
    return app.state.scheduler


@pytest.fixture
async def anon(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """A client with no session."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL) as client:
        yield client


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """A client logged in as the admin, after first-run setup."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL) as client:
        response = await client.post("/api/auth/setup", json={"password": ADMIN_PASSWORD})
        assert response.status_code == 204
        yield client
