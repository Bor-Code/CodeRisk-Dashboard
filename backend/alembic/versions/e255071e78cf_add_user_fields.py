"""add user fields

Revision ID: e255071e78cf
Revises: b8e854eb3d0b
Create Date: 2026-08-25 13:58:25.360252
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "e255071e78cf"
down_revision: str | None = "b8e854eb3d0b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.add_column(sa.Column("first_name", sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column("last_name", sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column("phone_number", sa.String(length=20), nullable=True))

    op.execute(sa.text("UPDATE users SET first_name = '' WHERE first_name IS NULL"))
    op.execute(sa.text("UPDATE users SET last_name = '' WHERE last_name IS NULL"))
    op.execute(sa.text("UPDATE users SET phone_number = '' WHERE phone_number IS NULL"))

    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.alter_column("first_name", existing_type=sa.String(length=100), nullable=False)
        batch_op.alter_column("last_name", existing_type=sa.String(length=100), nullable=False)
        batch_op.alter_column("phone_number", existing_type=sa.String(length=20), nullable=False)


def downgrade() -> None:
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.drop_column("phone_number")
        batch_op.drop_column("last_name")
        batch_op.drop_column("first_name")
