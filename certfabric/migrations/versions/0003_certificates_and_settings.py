"""Certificates and settings

Revision ID: 0003
Revises: 0002
"""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"


def upgrade() -> None:
    op.create_table(
        "certificates",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("domain_primary", sa.String, nullable=False),
        sa.Column("san_list", sa.JSON, nullable=False),
        sa.Column(
            "dns_provider_id",
            sa.String,
            sa.ForeignKey("dns_providers.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("key_type", sa.String, nullable=False),
        sa.Column("cert_pem", sa.Text, nullable=False),
        sa.Column("fullchain_pem", sa.Text, nullable=False),
        sa.Column("privkey_pem_encrypted", sa.Text),
        sa.Column("serial_number", sa.String, nullable=False),
        sa.Column("fingerprint_sha256", sa.String, nullable=False),
        sa.Column("issued_at", sa.DateTime, nullable=False),
        sa.Column("expires_at", sa.DateTime, nullable=False),
        sa.Column("status", sa.String, nullable=False),
    )
    op.create_index("idx_certificates_expires", "certificates", ["expires_at"])
    op.create_index("idx_certificates_fingerprint", "certificates", ["fingerprint_sha256"])
    op.create_table(
        "settings",
        sa.Column("key", sa.String, primary_key=True),
        sa.Column("value", sa.String, nullable=False),
    )


def downgrade() -> None:
    op.drop_table("settings")
    op.drop_table("certificates")
