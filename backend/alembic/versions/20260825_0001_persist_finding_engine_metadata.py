"""Persist finding engine metadata

Revision ID: 20260825_0001
Revises: ca6d3bd8d4f2
Create Date: 2026-08-25
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "20260825_0001"
down_revision: str | None = "ca6d3bd8d4f2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.add_column(sa.Column("engine_id", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("rule_id", sa.String(length=255), nullable=True))

    op.execute(sa.text("UPDATE findings SET engine_id = 'built-in' WHERE engine_id IS NULL"))

    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.alter_column(
            "engine_id",
            existing_type=sa.String(length=64),
            nullable=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.drop_column("rule_id")
        batch_op.drop_column("engine_id")
