"""Add durable asynchronous scan queue state.

Revision ID: 20260822_0002
Revises: 20260822_0001
Create Date: 2026-08-22
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "20260822_0002"
down_revision: str | None = "20260822_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("scans") as batch_op:
        batch_op.alter_column(
            "started_at",
            existing_type=sa.DateTime(timezone=True),
            nullable=True,
        )
        batch_op.add_column(
            sa.Column(
                "cancellation_requested_at",
                sa.DateTime(timezone=True),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "attempt_count",
                sa.Integer(),
                server_default="0",
                nullable=False,
            )
        )
        batch_op.add_column(sa.Column("worker_id", sa.String(length=255), nullable=True))
        batch_op.add_column(
            sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True)
        )

    with op.batch_alter_table("engine_runs") as batch_op:
        batch_op.alter_column(
            "started_at",
            existing_type=sa.DateTime(timezone=True),
            nullable=True,
        )

    with op.batch_alter_table("scans") as batch_op:
        batch_op.alter_column(
            "attempt_count",
            existing_type=sa.Integer(),
            server_default=None,
        )
        batch_op.create_index(
            "ix_scans_status_lease",
            ["status", "lease_expires_at"],
            unique=False,
        )


def downgrade() -> None:
    op.execute(sa.text("UPDATE scans SET started_at = created_at WHERE started_at IS NULL"))
    op.execute(
        sa.text(
            "UPDATE engine_runs SET started_at = "
            "(SELECT scans.created_at FROM scans WHERE scans.id = engine_runs.scan_id) "
            "WHERE started_at IS NULL"
        )
    )

    with op.batch_alter_table("engine_runs") as batch_op:
        batch_op.alter_column(
            "started_at",
            existing_type=sa.DateTime(timezone=True),
            nullable=False,
        )

    with op.batch_alter_table("scans") as batch_op:
        batch_op.drop_index("ix_scans_status_lease")
        batch_op.drop_column("lease_expires_at")
        batch_op.drop_column("worker_id")
        batch_op.drop_column("attempt_count")
        batch_op.drop_column("cancellation_requested_at")
        batch_op.alter_column(
            "started_at",
            existing_type=sa.DateTime(timezone=True),
            nullable=False,
        )
