"""Devices

Revision ID: 0004
Revises: 0003
"""

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"


def upgrade() -> None:
    op.create_table(
        "devices",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("name", sa.String, nullable=False),
        sa.Column("hostname", sa.String, nullable=False),
        sa.Column("port", sa.Integer, nullable=False, server_default="443"),
        sa.Column("sni", sa.String),
        sa.Column("plugin_id", sa.String, nullable=False),
        sa.Column("plugin_options", sa.JSON, nullable=False),
        sa.Column("assigned_cert_id", sa.String, sa.ForeignKey("certificates.id", ondelete="SET NULL")),
        sa.Column("encrypted_credentials", sa.Text),
        sa.Column("polling_interval_minutes", sa.Integer, nullable=False, server_default="360"),
        sa.Column("presented_fingerprint", sa.String),
        sa.Column("presented_issuer", sa.String),
        sa.Column("presented_common_name", sa.String),
        sa.Column("presented_sans", sa.JSON),
        sa.Column("presented_serial", sa.String),
        sa.Column("presented_expires_at", sa.DateTime),
        sa.Column("drift_status", sa.String, nullable=False, server_default="UNKNOWN"),
        sa.Column("consecutive_probe_failures", sa.Integer, nullable=False, server_default="0"),
        sa.Column("consecutive_deploy_failures", sa.Integer, nullable=False, server_default="0"),
        sa.Column("next_retry_at", sa.DateTime),
        sa.Column("last_probe_error", sa.String),
        sa.Column("last_scanned_at", sa.DateTime),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )
    op.create_index("idx_devices_drift_status", "devices", ["drift_status"])
    op.create_index("idx_devices_presented_expires", "devices", ["presented_expires_at"])


def downgrade() -> None:
    op.drop_table("devices")
