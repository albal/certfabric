"""Deployment logs

Revision ID: 0005
Revises: 0004
"""

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"


def upgrade() -> None:
    op.create_table(
        "deployment_logs",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("device_id", sa.String, sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("cert_id", sa.String, sa.ForeignKey("certificates.id", ondelete="CASCADE"), nullable=False),
        sa.Column("trigger_source", sa.String, nullable=False),
        sa.Column("success", sa.Boolean, nullable=False),
        sa.Column("execution_time_ms", sa.Integer, nullable=False),
        sa.Column("log_output", sa.Text),
        sa.Column("timestamp", sa.DateTime, nullable=False),
    )
    op.create_index("idx_deployment_logs_device", "deployment_logs", ["device_id", "timestamp"])


def downgrade() -> None:
    op.drop_table("deployment_logs")
