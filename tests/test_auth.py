import sqlite3
from datetime import timedelta

import pytest
from fastapi.routing import APIRoute, APIWebSocketRoute
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from certfabric.app import create_app
from tests.conftest import ADMIN_PASSWORD, BASE_URL

def all_routes(routes, prefix=""):
    """Flatten the app's routes, including those from included routers."""
    for route in routes:
        if hasattr(route, "original_router"):  # FastAPI keeps included routers nested
            yield from all_routes(route.original_router.routes, prefix + route.include_context.prefix)
        else:
            yield prefix, route


PUBLIC_PATHS = {"/api/auth/status", "/api/auth/setup", "/api/auth/login", "/api/auth/logout"}


async def test_first_run_requires_setup(anon):
    status = (await anon.get("/api/auth/status")).json()
    assert status == {"setup_required": True, "authenticated": False}


async def test_setup_logs_in_and_cannot_be_repeated(client):
    assert (await client.get("/api/auth/status")).json() == {"setup_required": False, "authenticated": True}
    assert (await client.get("/api/system/info")).status_code == 200
    again = await client.post("/api/auth/setup", json={"password": "another long password"})
    assert again.status_code == 409


async def test_setup_rejects_short_password(anon):
    assert (await anon.post("/api/auth/setup", json={"password": "short"})).status_code == 422


async def test_password_is_not_stored_in_plaintext(client, settings):
    stored = sqlite3.connect(settings.db_path).execute("SELECT password_hash FROM admin_user").fetchone()[0]
    assert ADMIN_PASSWORD not in stored


async def test_login_and_logout(client, anon):
    assert (await anon.post("/api/auth/login", json={"password": "wrong password!"})).status_code == 401
    assert (await anon.post("/api/auth/login", json={"password": ADMIN_PASSWORD})).status_code == 204
    assert (await anon.get("/api/system/info")).status_code == 200

    token = anon.cookies.get("certfabric_session")
    assert (await anon.post("/api/auth/logout")).status_code == 204
    assert (await anon.get("/api/system/info")).status_code == 401
    # The old token is dead server-side, not just removed from the browser.
    anon.cookies.set("certfabric_session", token)
    assert (await anon.get("/api/system/info")).status_code == 401


async def test_session_expires(client, anon, clock):
    assert (await anon.post("/api/auth/login", json={"password": ADMIN_PASSWORD})).status_code == 204
    clock.advance(timedelta(days=6))
    assert (await anon.get("/api/system/info")).status_code == 200
    clock.advance(timedelta(days=2))
    assert (await anon.get("/api/system/info")).status_code == 401


async def test_every_http_route_requires_a_session(app, anon):
    routes = [
        (prefix + r.path_format, r)
        for prefix, r in all_routes(app.routes)
        if isinstance(r, APIRoute) and prefix + r.path not in PUBLIC_PATHS
    ]
    assert routes, "expected protected routes"
    for path_format, route in routes:
        path = path_format.replace("{", "").replace("}", "")
        for method in route.methods:
            response = await anon.request(method, path)
            assert response.status_code == 401, f"{method} {route.path} answered {response.status_code}"


def test_every_websocket_route_requires_a_session(settings, clock):
    app = create_app(settings, clock)
    ws_paths = [prefix + r.path for prefix, r in all_routes(app.routes) if isinstance(r, APIWebSocketRoute)]
    assert ws_paths
    with TestClient(app, base_url=BASE_URL) as tc:
        for path in ws_paths:
            with pytest.raises(WebSocketDisconnect):
                with tc.websocket_connect(path.replace("{", "").replace("}", "")) as ws:
                    ws.receive_json()
        assert tc.post("/api/auth/setup", json={"password": ADMIN_PASSWORD}).status_code == 204
        cookie = f"certfabric_session={tc.cookies.get('certfabric_session')}"
        with tc.websocket_connect("/ws/ping", headers={"cookie": cookie}) as ws:
            assert ws.receive_json() == {"type": "pong"}


async def test_openapi_is_behind_the_session(client, anon):
    assert (await anon.get("/api/openapi.json")).status_code == 401
    assert "paths" in (await client.get("/api/openapi.json")).json()
