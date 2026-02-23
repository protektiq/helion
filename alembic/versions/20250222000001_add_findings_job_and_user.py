"""Add upload_job_id and user_id to findings; backfill legacy rows.

Revision ID: 20250222000001
Revises: 20250222000000
Create Date: 2025-02-22

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "20250222000001"
down_revision: Union[str, None] = "20250222000000"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add columns nullable first for backfill
    op.add_column(
        "findings",
        sa.Column("upload_job_id", sa.Integer(), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("user_id", sa.Integer(), nullable=True),
    )
    op.create_foreign_key(
        "fk_findings_upload_job_id",
        "findings",
        "upload_jobs",
        ["upload_job_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "fk_findings_user_id",
        "findings",
        "users",
        ["user_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index(
        op.f("ix_findings_upload_job_id"),
        "findings",
        ["upload_job_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_findings_user_id"),
        "findings",
        ["user_id"],
        unique=False,
    )

    # Backfill: create one legacy upload_job and assign existing findings to it (when at least one user exists)
    conn = op.get_bind()
    result = conn.execute(sa.text("SELECT id FROM users ORDER BY id LIMIT 1"))
    row = result.fetchone()
    if row is not None:
        user_id = row[0]
        conn.execute(
            sa.text(
                "INSERT INTO upload_jobs (user_id, status, source) VALUES (:uid, 'completed', 'legacy')"
            ),
            {"uid": user_id},
        )
        result2 = conn.execute(
            sa.text("SELECT id FROM upload_jobs WHERE source = 'legacy' ORDER BY id DESC LIMIT 1")
        )
        job_row = result2.fetchone()
        if job_row is not None:
            job_id = job_row[0]
            conn.execute(
                sa.text(
                    "UPDATE findings SET upload_job_id = :jid, user_id = :uid WHERE upload_job_id IS NULL"
                ),
                {"jid": job_id, "uid": user_id},
            )
        # Make columns NOT NULL only when we could backfill (so no NULLs remain)
        op.alter_column(
            "findings",
            "upload_job_id",
            existing_type=sa.Integer(),
            nullable=False,
        )
        op.alter_column(
            "findings",
            "user_id",
            existing_type=sa.Integer(),
            nullable=False,
        )


def downgrade() -> None:
    op.drop_index(op.f("ix_findings_user_id"), table_name="findings")
    op.drop_index(op.f("ix_findings_upload_job_id"), table_name="findings")
    op.drop_constraint("fk_findings_user_id", "findings", type_="foreignkey")
    op.drop_constraint("fk_findings_upload_job_id", "findings", type_="foreignkey")
    op.drop_column("findings", "user_id")
    op.drop_column("findings", "upload_job_id")
