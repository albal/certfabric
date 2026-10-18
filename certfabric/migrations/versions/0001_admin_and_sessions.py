"""Admin user and sessions

Revision ID: 0001
Revises:
"""

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None


def upgrade() -> None:
    op.create_table(
        "admin_user",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("password_hash", sa.String, nullable=False),
        sa.CheckConstraint("id = 1", name="single_admin"),
    )
    op.create_table(
        "sessions",
        sa.Column("token_hash", sa.String, primary_key=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("expires_at", sa.DateTime, nullable=False),
    )


def downgrade() -> None:
    op.drop_table("sessions")
    op.drop_table("admin_user")
