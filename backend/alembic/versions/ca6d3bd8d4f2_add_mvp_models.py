"""Add MVP models

Revision ID: ca6d3bd8d4f2
Revises: e255071e78cf
Create Date: 2026-08-25 14:24:51.286458
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "ca6d3bd8d4f2"
down_revision: str | None = "e255071e78cf"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "integrations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("integration_type", sa.String(length=64), nullable=False),
        sa.Column("credentials", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "policies",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("rule_type", sa.String(length=64), nullable=False),
        sa.Column("rule_value", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("policies")
    op.drop_table("integrations")
