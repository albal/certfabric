"""System information and the OpenAPI document, both behind the session."""

from __future__ import annotations

from importlib.metadata import version
from typing import Any

from fastapi import APIRouter, Request, WebSocket
from pydantic import BaseModel

router = APIRouter(tags=["system"])


class SystemInfo(BaseModel):
    version: str


@router.get("/api/system/info")
async def system_info() -> SystemInfo:
    return SystemInfo(version=version("certfabric"))


@router.get("/api/openapi.json", include_in_schema=False)
async def openapi(request: Request) -> dict[str, Any]:
    return request.app.openapi()


@router.websocket("/ws/ping")
async def ping(websocket: WebSocket) -> None:
    """Liveness check for the UI's WebSocket connection."""
    await websocket.accept()
    await websocket.send_json({"type": "pong"})
    await websocket.close()
