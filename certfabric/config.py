"""Runtime settings, loaded from the environment.

CertFabric refuses to start without a usable secret key: every stored secret is
encrypted with it (ADR-0001), so running without one would be unsafe.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from cryptography.fernet import Fernet

SECRET_KEY_ENV = "CERTFABRIC_SECRET_KEY"
SECRET_KEY_FILE_ENV = "CERTFABRIC_SECRET_KEY_FILE"
DB_PATH_ENV = "CERTFABRIC_DB_PATH"
ACME_SH_ENV = "CERTFABRIC_ACME_SH"


class ConfigError(Exception):
    """Raised when CertFabric cannot start with the configuration it was given."""


@dataclass(frozen=True)
class Settings:
    secret_key: bytes
    db_path: Path
    acme_sh: str = "acme.sh"
    run_scheduler: bool = True


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    env = os.environ if env is None else env
    return Settings(
        secret_key=_load_secret_key(env),
        db_path=Path(env.get(DB_PATH_ENV, "certfabric.db")),
        acme_sh=env.get(ACME_SH_ENV, "acme.sh"),
    )


def _load_secret_key(env: Mapping[str, str]) -> bytes:
    if raw := env.get(SECRET_KEY_ENV):
        key = raw.strip().encode()
    elif path := env.get(SECRET_KEY_FILE_ENV):
        key = _read_key_file(Path(path))
    else:
        raise ConfigError(
            f"No secret key: set {SECRET_KEY_ENV} or {SECRET_KEY_FILE_ENV}. "
            "Generate one with `certfabric generate-key`."
        )
    validate_key(key)
    return key


def _read_key_file(path: Path) -> bytes:
    try:
        mode = path.stat().st_mode
    except FileNotFoundError:
        raise ConfigError(f"Secret key file {path} does not exist") from None
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ConfigError(
            f"Secret key file {path} is accessible by group or others; "
            "restrict it with `chmod 0400`."
        )
    return path.read_bytes().strip()


def validate_key(key: bytes) -> None:
    try:
        Fernet(key)
    except (ValueError, TypeError):
        raise ConfigError("Secret key is not a valid Fernet key") from None
