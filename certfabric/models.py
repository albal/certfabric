"""SQLAlchemy models. The schema is created and changed only through Alembic migrations."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, TypeDecorator
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class UtcDateTime(TypeDecorator[datetime]):
    """Stores naive UTC in SQLite and always hands back timezone-aware UTC datetimes."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: object) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("Naive datetimes are not allowed; use a Clock")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: object) -> datetime | None:
        return value.replace(tzinfo=UTC) if value is not None else None


class Base(DeclarativeBase):
    pass


class AdminUser(Base):
    __tablename__ = "admin_user"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)


class DnsProvider(Base):
    __tablename__ = "dns_providers"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    acme_dns_type: Mapped[str] = mapped_column(String, nullable=False)
    encrypted_credentials: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)


class Certificate(Base):
    __tablename__ = "certificates"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    domain_primary: Mapped[str] = mapped_column(String, nullable=False)
    san_list: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    dns_provider_id: Mapped[str] = mapped_column(
        ForeignKey("dns_providers.id", ondelete="RESTRICT"), nullable=False
    )
    key_type: Mapped[str] = mapped_column(String, nullable=False)
    cert_pem: Mapped[str] = mapped_column(Text, nullable=False)
    fullchain_pem: Mapped[str] = mapped_column(Text, nullable=False)
    privkey_pem_encrypted: Mapped[str | None] = mapped_column(Text)
    serial_number: Mapped[str] = mapped_column(String, nullable=False)
    fingerprint_sha256: Mapped[str] = mapped_column(String, nullable=False, index=True)
    issued_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, index=True)
    # VALID, REVOKED or SUPERSEDED. EXPIRING and EXPIRED are derived from expires_at.
    status: Mapped[str] = mapped_column(String, nullable=False, default="VALID")


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    hostname: Mapped[str] = mapped_column(String, nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=443)
    sni: Mapped[str | None] = mapped_column(String)
    plugin_id: Mapped[str] = mapped_column(String, nullable=False)
    plugin_options: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    assigned_cert_id: Mapped[str | None] = mapped_column(
        ForeignKey("certificates.id", ondelete="SET NULL")
    )
    encrypted_credentials: Mapped[str | None] = mapped_column(Text)
    polling_interval_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=360)
    presented_fingerprint: Mapped[str | None] = mapped_column(String)
    presented_issuer: Mapped[str | None] = mapped_column(String)
    presented_common_name: Mapped[str | None] = mapped_column(String)
    presented_sans: Mapped[list[str] | None] = mapped_column(JSON)
    presented_serial: Mapped[str | None] = mapped_column(String)
    presented_expires_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    # UNKNOWN until classified, then IN_SYNC, OUTDATED, DRIFT_DETECTED, UNREACHABLE or DEPLOY_FAILED.
    drift_status: Mapped[str] = mapped_column(String, nullable=False, default="UNKNOWN")
    consecutive_probe_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    consecutive_deploy_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_retry_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    last_probe_error: Mapped[str | None] = mapped_column(String)
    last_scanned_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)


class AppSetting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String, primary_key=True)
    value: Mapped[str] = mapped_column(String, nullable=False)


class AuthSession(Base):
    __tablename__ = "sessions"

    token_hash: Mapped[str] = mapped_column(String, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)


class DeploymentLog(Base):
    __tablename__ = "deployment_logs"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    cert_id: Mapped[str] = mapped_column(ForeignKey("certificates.id", ondelete="CASCADE"), nullable=False)
    # MANUAL, DRIFT_HEAL, OUTDATED_HEAL, RENEWAL, RETRY or INITIAL_SETUP
    trigger_source: Mapped[str] = mapped_column(String, nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    execution_time_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    log_output: Mapped[str | None] = mapped_column(Text)
    timestamp: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)


class Webhook(Base):
    __tablename__ = "webhooks"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    url: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
