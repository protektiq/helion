"""ORM model for materialized cluster output per upload job."""

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB

from app.models.base import Base


class Cluster(Base):
    """
    Materialized cluster row per upload_job. Populated after clustering runs.
    Enables GET clusters by job without recomputing.
    """

    __tablename__ = "clusters"

    id = Column(Integer, primary_key=True, autoincrement=True)
    upload_job_id = Column(
        Integer,
        ForeignKey("upload_jobs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    vulnerability_id = Column(String(255), nullable=False)
    severity = Column(String(32), nullable=False)
    repo = Column(String(1024), nullable=False, default="")
    file_path = Column(String(2048), nullable=False, default="")
    dependency = Column(String(1024), nullable=False, default="")
    cvss_score = Column(Float, nullable=False)
    description = Column(Text, nullable=False)
    finding_ids = Column(JSONB, nullable=False)  # list of finding id strings
    affected_services_count = Column(Integer, nullable=False)
    finding_count = Column(Integer, nullable=False)
    computed_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
