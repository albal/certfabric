"""UI tests: the built dashboard in Chrome, against the real API served by uvicorn (Seam 1)."""

from __future__ import annotations

import asyncio
import shutil
import subprocess
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import uvicorn
from fastapi import FastAPI

from tests.conftest import ADMIN_PASSWORD

FRONTEND = Path(__file__).parents[2] / "frontend"


@pytest.fixture(scope="session", autouse=True)
def built_dashboard() -> None:
    if not (FRONTEND / "dist" / "index.html").exists():
        if shutil.which("npm") is None:
            pytest.skip("npm is needed to build the dashboard")
        subprocess.run(["npm", "run", "build"], cwd=FRONTEND, check=True)


@pytest.fixture
async def live_url(app: FastAPI) -> AsyncIterator[str]:
    """Serve the already-started app over real HTTP so a browser can use it."""
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, lifespan="off", log_level="warning"))
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.01)
    port = server.servers[0].sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    await task


@pytest.fixture
async def browser():
    from playwright.async_api import async_playwright

    async with async_playwright() as playwright:
        try:
            browser = await playwright.chromium.launch(channel="chrome", headless=True)
        except Exception as exc:  # no system Chrome
            pytest.skip(f"Chrome is not available: {exc}")
        yield browser
        await browser.close()


@pytest.fixture
async def page(browser, live_url):
    context = await browser.new_context(base_url=live_url)
    page = await context.new_page()
    page.set_default_timeout(10_000)
    yield page
    await context.close()


async def sign_in(page) -> None:
    await page.goto("/")
    await page.get_by_label("Admin password").fill(ADMIN_PASSWORD)
    await page.get_by_role("button", name="Sign in").click()
    await page.get_by_test_id("fleet-table").wait_for()
