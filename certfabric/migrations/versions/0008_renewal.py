"""Renewal tracking on Certificates

Revision ID: 0008
Revises: 0007
"""

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"


def upgrade() -> None:
    with op.batch_alter_table("certificates") as batch:
        batch.add_column(sa.Column("superseded_by", sa.String))
        batch.add_column(sa.Column("superseded_at", sa.DateTime))
        batch.add_column(sa.Column("renewal_attempted_at", sa.DateTime))
        batch.add_column(sa.Column("renewal_error", sa.Text))


def downgrade() -> None:
    with op.batch_alter_table("certificates") as batch:
        for column in ("renewal_error", "renewal_attempted_at", "superseded_at", "superseded_by"):
            batch.drop_column(column)
