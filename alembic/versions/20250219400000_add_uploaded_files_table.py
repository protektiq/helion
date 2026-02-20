"""Add uploaded_files table for encrypted upload metadata.

Revision ID: 20250219400000
Revises: 20250219300000
Create Date: 2025-02-19

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "20250219400000"
down_revision: Union[str, None] = "20250219300000"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "uploaded_files",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("storage_key", sa.String(length=64), nullable=False),
        sa.Column("original_filename", sa.String(length=512), nullable=False, server_default=""),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_uploaded_files_user_id"),
        "uploaded_files",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_uploaded_files_storage_key"),
        "uploaded_files",
        ["storage_key"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_uploaded_files_storage_key"), table_name="uploaded_files")
    op.drop_index(op.f("ix_uploaded_files_user_id"), table_name="uploaded_files")
    op.drop_table("uploaded_files")
