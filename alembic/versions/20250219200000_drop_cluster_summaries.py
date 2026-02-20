"""Drop cluster_summaries table (MVP: retention is delete-only, no summary persistence).

Revision ID: 20250219200000
Revises: 20250219100000
Create Date: 2025-02-19

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "20250219200000"
down_revision: Union[str, None] = "20250219100000"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_index(
        op.f("ix_cluster_summaries_snapshot_at"),
        table_name="cluster_summaries",
    )
    op.drop_index(
        op.f("ix_cluster_summaries_severity"),
        table_name="cluster_summaries",
    )
    op.drop_index(
        op.f("ix_cluster_summaries_vulnerability_id"),
        table_name="cluster_summaries",
    )
    op.drop_table("cluster_summaries")


def downgrade() -> None:
    op.create_table(
        "cluster_summaries",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("vulnerability_id", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("repo", sa.String(length=1024), nullable=False, server_default=""),
        sa.Column("file_path", sa.String(length=2048), nullable=False, server_default=""),
        sa.Column("dependency", sa.String(length=1024), nullable=False, server_default=""),
        sa.Column("cvss_score", sa.Float(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("finding_count", sa.Integer(), nullable=False),
        sa.Column("affected_services_count", sa.Integer(), nullable=False),
        sa.Column(
            "snapshot_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "affected_repos",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_cluster_summaries_vulnerability_id"),
        "cluster_summaries",
        ["vulnerability_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_cluster_summaries_severity"),
        "cluster_summaries",
        ["severity"],
        unique=False,
    )
    op.create_index(
        op.f("ix_cluster_summaries_snapshot_at"),
        "cluster_summaries",
        ["snapshot_at"],
        unique=False,
    )
