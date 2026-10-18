"""Audit events

Revision ID: 0007
Revises: 0006
"""

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("timestamp", sa.DateTime, nullable=False),
        sa.Column("level", sa.String, nullable=False),
        sa.Column("event", sa.String, nullable=False),
        sa.Column("message", sa.Text, nullable=False),
        sa.Column("device_id", sa.String, sa.ForeignKey("devices.id", ondelete="SET NULL")),
        sa.Column("cert_id", sa.String, sa.ForeignKey("certificates.id", ondelete="SET NULL")),
    )
    op.create_index("idx_audit_events_timestamp", "audit_events", ["timestamp"])


def downgrade() -> None:
    op.drop_table("audit_events")
