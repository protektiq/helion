"""Add upload_jobs table for per-upload processing runs.

Revision ID: 20250222000000
Revises: 20250219500000
Create Date: 2025-02-22

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "20250222000000"
down_revision: Union[str, None] = "20250219500000"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "upload_jobs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("source", sa.String(length=32), nullable=False, server_default="file"),
        sa.Column("raw_blob_ref", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_upload_jobs_user_id"),
        "upload_jobs",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        "ix_upload_jobs_user_id_created_at",
        "upload_jobs",
        ["user_id", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_upload_jobs_user_id_created_at", table_name="upload_jobs")
    op.drop_index(op.f("ix_upload_jobs_user_id"), table_name="upload_jobs")
    op.drop_table("upload_jobs")
