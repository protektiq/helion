"""Initial findings table for SAST/SCA uploads.

Revision ID: 20250219000000
Revises:
Create Date: 2025-02-19

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "20250219000000"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("vulnerability_id", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("repo", sa.String(length=1024), nullable=False, server_default=""),
        sa.Column("file_path", sa.String(length=2048), nullable=False, server_default=""),
        sa.Column("dependency", sa.String(length=1024), nullable=False, server_default=""),
        sa.Column("cvss_score", sa.Float(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("scanner_source", sa.String(length=255), nullable=True),
        sa.Column("raw_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_findings_vulnerability_id"),
        "findings",
        ["vulnerability_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_findings_severity"),
        "findings",
        ["severity"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_findings_severity"), table_name="findings")
    op.drop_index(op.f("ix_findings_vulnerability_id"), table_name="findings")
    op.drop_table("findings")
