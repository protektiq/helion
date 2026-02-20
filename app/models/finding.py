"""ORM model for persisted vulnerability findings."""

from sqlalchemy import Column, DateTime, Float, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB

from app.models.base import Base


class Finding(Base):
    """
    Persisted finding aligned with NormalizedFinding, plus traceability fields.

    Stores one row per normalized finding from SAST/SCA uploads.
    """

    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id = Column(String(255), nullable=False, index=True)
    severity = Column(String(32), nullable=False, index=True)
    repo = Column(String(1024), nullable=False, default="")
    file_path = Column(String(2048), nullable=False, default="")
    dependency = Column(String(1024), nullable=False, default="")
    cvss_score = Column(Float, nullable=False)
    description = Column(Text, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    scanner_source = Column(String(255), nullable=True)
    raw_payload = Column(JSONB, nullable=True)
