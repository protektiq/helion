"""ORM model for cluster enrichment payloads (KEV/EPSS/OSV) per run."""

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB

from app.models.base import Base


class ClusterEnrichment(Base):
    """
    One enrichment result per cluster (and optional job). Enables traceability
    of what signals were used for reasoning/tier assignment.
    """

    __tablename__ = "cluster_enrichments"

    id = Column(Integer, primary_key=True, autoincrement=True)
    upload_job_id = Column(
        Integer,
        ForeignKey("upload_jobs.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    vulnerability_id = Column(String(255), nullable=False, index=True)
    dependency = Column(String(1024), nullable=False, default="")
    enrichment = Column(JSONB, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
