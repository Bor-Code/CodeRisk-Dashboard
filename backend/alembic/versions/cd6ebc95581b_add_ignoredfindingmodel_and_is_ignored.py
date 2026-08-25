"""Add IgnoredFindingModel and is_ignored

Revision ID: cd6ebc95581b
Revises: 20260822_0002
Create Date: 2026-08-24 16:35:00.276898
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "cd6ebc95581b"
down_revision: str | None = "20260822_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ignored_findings",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("repository_id", sa.String(length=36), nullable=False),
        sa.Column("source_finding_id", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["repository_id"], ["repositories.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "repository_id",
            "source_finding_id",
            name="uq_ignored_findings_repo_src",
        ),
    )
    with op.batch_alter_table("ignored_findings", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_ignored_findings_repository_id"), ["repository_id"], unique=False
        )

    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.add_column(sa.Column("is_ignored", sa.Boolean(), nullable=True))

    op.execute(sa.text("UPDATE findings SET is_ignored = false WHERE is_ignored IS NULL"))

    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.alter_column(
            "is_ignored",
            existing_type=sa.Boolean(),
            nullable=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.drop_column("is_ignored")

    with op.batch_alter_table("ignored_findings", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_ignored_findings_repository_id"))

    op.drop_table("ignored_findings")
