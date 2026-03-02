"""Add unique constraint on cluster_enrichments (job, vuln, dependency) for UPSERT.

Revision ID: 20250301000000
Revises: 20250222000003
Create Date: 2025-03-01

"""
from typing import Sequence, Union

from alembic import op

revision: str = "20250301000000"
down_revision: Union[str, None] = "20250222000003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_cluster_enrichments_job_vuln_dep",
        "cluster_enrichments",
        ["upload_job_id", "vulnerability_id", "dependency"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_cluster_enrichments_job_vuln_dep",
        "cluster_enrichments",
        type_="unique",
    )
