"""Seam 1 harness: the real application with a fake clock, driven over HTTP."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI

from certfabric.app import create_app
from certfabric.clock import FakeClock
from certfabric.config import Settings
from certfabric.scheduler import Scheduler
from tests.fakes import fake_device_control
from tests.fakes.acme_harness import FakeAcme
from tests.fakes.tls_device import FakeTlsDevice

ADMIN_PASSWORD = "correct horse battery staple"
TEST_PLUGINS = Path(__file__).parent / "fakes" / "plugins"
BASE_URL = "http://certfabric.test"


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def fake_acme(tmp_path, clock: FakeClock) -> FakeAcme:
    return FakeAcme(tmp_path / "fake-acme", clock)


@pytest.fixture
def settings(tmp_path, fake_acme: FakeAcme) -> Settings:
    return Settings(
        secret_key=Fernet.generate_key(),
        db_path=tmp_path / "certfabric.db",
        acme_sh=str(fake_acme.executable),
        plugin_dirs=(TEST_PLUGINS,),
        run_scheduler=False,
    )


@pytest.fixture
async def app(settings: Settings, clock: FakeClock) -> AsyncIterator[FastAPI]:
    app = create_app(settings, clock)
    async with app.router.lifespan_context(app):
        yield app


@pytest.fixture
async def tls_device() -> AsyncIterator[FakeTlsDevice]:
    """A running fake Device presenting a factory self-signed certificate."""
    device = await FakeTlsDevice().start()
    fake_device_control.register(device)
    yield device
    await device.stop()


@pytest.fixture
def scheduler(app: FastAPI) -> Scheduler:
    return app.state.scheduler


@pytest.fixture
async def anon(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """A client with no session."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL) as client:
        yield client


class ReloginAuth(httpx.Auth):
    """Logs back in when the session has expired, so tests can move the clock by months."""

    def auth_flow(self, request: httpx.Request):
        response = yield request
        if response.status_code == 401 and not request.url.path.startswith("/api/auth/"):
            login = yield httpx.Request("POST", f"{BASE_URL}/api/auth/login", json={"password": ADMIN_PASSWORD})
            cookie = login.headers["set-cookie"].split(";")[0]
            request.headers["cookie"] = cookie
            yield request


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """A client logged in as the admin, after first-run setup. It re-logs in if the session expires."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=BASE_URL, auth=ReloginAuth()) as client:
        response = await client.post("/api/auth/setup", json={"password": ADMIN_PASSWORD})
        assert response.status_code == 204
        yield client


CF_TOKEN = "cf-token-0123456789abcdef"
DEVICE_PASSWORD = "device-password-0123456789"


async def wait_for_job(client: httpx.AsyncClient, job_id: str) -> dict:
    """Poll a job through the API until it finishes."""
    for _ in range(1000):
        job = (await client.get(f"/api/jobs/{job_id}")).json()
        if job["state"] != "running":
            return job
        await asyncio.sleep(0.01)
    raise AssertionError(f"job {job_id} did not finish")


async def create_dns_provider(client: httpx.AsyncClient) -> str:
    body = {"name": "Cloudflare", "acme_dns_type": "dns_cf", "credentials": {"CF_Token": CF_TOKEN}}
    response = await client.post("/api/dns-providers", json=body)
    assert response.status_code == 201, response.text
    return response.json()["id"]


async def issue_certificate(client: httpx.AsyncClient, domains: list[str], **extra) -> dict:
    """Issue a Certificate through the API and return it. Fails the test if issuance fails."""
    provider_id = extra.pop("dns_provider_id", None) or await create_dns_provider(client)
    response = await client.post(
        "/api/certificates", json={"domains": domains, "dns_provider_id": provider_id, **extra}
    )
    assert response.status_code == 202, response.text
    job = await wait_for_job(client, response.json()["job_id"])
    assert job["state"] == "succeeded", job
    return (await client.get(f"/api/certificates/{job['result']['certificate_id']}")).json()


async def create_device(client: httpx.AsyncClient, tls_device: FakeTlsDevice, **extra) -> dict:
    body = {
        "name": "Printer",
        "hostname": tls_device.host,
        "port": tls_device.port,
        "plugin_id": "fake_device",
        "credentials": {"username": "admin", "password": DEVICE_PASSWORD},
        **extra,
    }
    response = await client.post("/api/devices", json=body)
    assert response.status_code == 201, response.text
    return response.json()


async def managed_device(client: httpx.AsyncClient, tls_device: FakeTlsDevice, domain: str = "printer.lan.example.com", **extra) -> tuple[dict, dict]:
    """A Device with a freshly issued Certificate assigned (not yet deployed)."""
    cert = await issue_certificate(client, [domain])
    device = await create_device(client, tls_device, sni=domain, certificate_id=cert["id"], **extra)
    return device, cert


async def deploy(client: httpx.AsyncClient, device_id: str) -> dict:
    response = await client.post(f"/api/devices/{device_id}/deploy")
    assert response.status_code == 202, response.text
    return await wait_for_job(client, response.json()["job_id"])
