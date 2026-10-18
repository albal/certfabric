"""First-run setup, login and logout. These are the only routes reachable without a session."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from certfabric import auth
from certfabric.api.deps import get_db

router = APIRouter(prefix="/api/auth", tags=["auth"])


class AuthStatus(BaseModel):
    setup_required: bool
    authenticated: bool


class SetupRequest(BaseModel):
    password: str = Field(min_length=auth.MIN_PASSWORD_LENGTH)


class LoginRequest(BaseModel):
    password: str


def _set_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        auth.SESSION_COOKIE,
        token,
        max_age=int(auth.SESSION_TTL.total_seconds()),
        httponly=True,
        samesite="strict",
    )


@router.get("/status")
async def get_status(request: Request, db: AsyncSession = Depends(get_db)) -> AuthStatus:
    token = request.cookies.get(auth.SESSION_COOKIE)
    authenticated = bool(token) and await auth.session_is_valid(db, request.app.state.clock, token)
    return AuthStatus(setup_required=not await auth.admin_exists(db), authenticated=authenticated)


@router.post("/setup", status_code=status.HTTP_204_NO_CONTENT)
async def setup(
    body: SetupRequest, request: Request, response: Response, db: AsyncSession = Depends(get_db)
) -> None:
    if await auth.admin_exists(db):
        raise HTTPException(status.HTTP_409_CONFLICT, "Admin password is already set")
    await auth.create_admin(db, body.password)
    _set_cookie(response, await auth.start_session(db, request.app.state.clock))


@router.post("/login", status_code=status.HTTP_204_NO_CONTENT)
async def login(
    body: LoginRequest, request: Request, response: Response, db: AsyncSession = Depends(get_db)
) -> None:
    if not await auth.check_admin_password(db, body.password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Wrong password")
    _set_cookie(response, await auth.start_session(db, request.app.state.clock))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request, response: Response, db: AsyncSession = Depends(get_db)) -> None:
    if token := request.cookies.get(auth.SESSION_COOKIE):
        await auth.end_session(db, token)
    response.delete_cookie(auth.SESSION_COOKIE)
