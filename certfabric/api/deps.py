"""Shared FastAPI dependencies."""

from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import HTTPException, WebSocketException, status
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import HTTPConnection

from certfabric import auth


async def get_db(conn: HTTPConnection) -> AsyncIterator[AsyncSession]:
    async with conn.app.state.db.session() as db, db.begin():
        yield db


async def require_session(conn: HTTPConnection) -> None:
    """Reject the request or WebSocket unless it carries a valid admin session."""
    token = conn.cookies.get(auth.SESSION_COOKIE)
    if token:
        async with conn.app.state.db.session() as db:
            if await auth.session_is_valid(db, conn.app.state.clock, token):
                return
    if conn.scope["type"] == "websocket":
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
