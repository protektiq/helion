"""ORM model for upload jobs (one per upload batch)."""

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text, func

from app.models.base import Base


class UploadJob(Base):
    """
    One discrete processing run per upload. Findings are tied to an upload_job_id.
    Enables per-job clustering, reasoning, and export.
    """

    __tablename__ = "upload_jobs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    status = Column(String(32), nullable=False, default="pending")  # pending | processing | completed | failed
    source = Column(String(32), nullable=False, default="file")  # file | api
    raw_blob_ref = Column(Text, nullable=True)  # optional S3/key or path for re-run
