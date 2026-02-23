"""Add cluster_enrichments table for enrichment JSONB traceability.

Revision ID: 20250222000003
Revises: 20250222000002
Create Date: 2025-02-22

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "20250222000003"
down_revision: Union[str, None] = "20250222000002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "cluster_enrichments",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("upload_job_id", sa.Integer(), nullable=True),
        sa.Column("vulnerability_id", sa.String(length=255), nullable=False),
        sa.Column("dependency", sa.String(length=1024), nullable=False, server_default=""),
        sa.Column(
            "enrichment",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "created_at",
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
        op.f("ix_cluster_enrichments_upload_job_id"),
        "cluster_enrichments",
        ["upload_job_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_cluster_enrichments_vulnerability_id"),
        "cluster_enrichments",
        ["vulnerability_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_cluster_enrichments_vulnerability_id"),
        table_name="cluster_enrichments",
    )
    op.drop_index(
        op.f("ix_cluster_enrichments_upload_job_id"),
        table_name="cluster_enrichments",
    )
    op.drop_table("cluster_enrichments")
