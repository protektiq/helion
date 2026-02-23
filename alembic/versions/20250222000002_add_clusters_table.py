"""Add clusters table for materialized cluster output per job.

Revision ID: 20250222000002
Revises: 20250222000001
Create Date: 2025-02-22

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "20250222000002"
down_revision: Union[str, None] = "20250222000001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "clusters",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("upload_job_id", sa.Integer(), nullable=False),
        sa.Column("vulnerability_id", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("repo", sa.String(length=1024), nullable=False, server_default=""),
        sa.Column("file_path", sa.String(length=2048), nullable=False, server_default=""),
        sa.Column("dependency", sa.String(length=1024), nullable=False, server_default=""),
        sa.Column("cvss_score", sa.Float(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column(
            "finding_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("affected_services_count", sa.Integer(), nullable=False),
        sa.Column("finding_count", sa.Integer(), nullable=False),
        sa.Column(
            "computed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["upload_job_id"],
            ["upload_jobs.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_clusters_upload_job_id"),
        "clusters",
        ["upload_job_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_clusters_upload_job_id"), table_name="clusters")
    op.drop_table("clusters")
