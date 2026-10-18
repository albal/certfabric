"""Single-admin authentication: scrypt password hashes and server-side sessions."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from datetime import timedelta

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from certfabric.clock import Clock
from certfabric.models import AdminUser, AuthSession

SESSION_COOKIE = "certfabric_session"
SESSION_TTL = timedelta(days=7)
MIN_PASSWORD_LENGTH = 12

_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**14, 8, 1


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    _, n, r, p, salt, digest = stored.split("$")
    candidate = hashlib.scrypt(
        password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p)
    )
    return hmac.compare_digest(candidate, base64.b64decode(digest))


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def admin_exists(db: AsyncSession) -> bool:
    return await db.get(AdminUser, 1) is not None


async def create_admin(db: AsyncSession, password: str) -> None:
    db.add(AdminUser(id=1, password_hash=hash_password(password)))
    await db.flush()


async def check_admin_password(db: AsyncSession, password: str) -> bool:
    admin = await db.get(AdminUser, 1)
    return admin is not None and verify_password(password, admin.password_hash)


async def start_session(db: AsyncSession, clock: Clock) -> str:
    token = secrets.token_urlsafe(32)
    now = clock.now()
    db.add(AuthSession(token_hash=_token_hash(token), created_at=now, expires_at=now + SESSION_TTL))
    await db.flush()
    return token


async def session_is_valid(db: AsyncSession, clock: Clock, token: str) -> bool:
    found = await db.scalar(
        select(AuthSession).where(
            AuthSession.token_hash == _token_hash(token),
            AuthSession.expires_at > clock.now(),
        )
    )
    return found is not None


async def end_session(db: AsyncSession, token: str) -> None:
    await db.execute(delete(AuthSession).where(AuthSession.token_hash == _token_hash(token)))
