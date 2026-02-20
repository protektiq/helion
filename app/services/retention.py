"""Data retention: delete findings older than RETENTION_HOURS."""

import logging
from datetime import datetime, timezone, timedelta
from typing import TYPE_CHECKING

from sqlalchemy.orm import Session

from app.models import Finding

if TYPE_CHECKING:
    from app.core.config import Settings

logger = logging.getLogger(__name__)


def run_retention(session: Session, settings: "Settings") -> tuple[int, int]:
    """
    Delete findings older than RETENTION_HOURS. No cluster summary persistence.

    Returns (0, findings_deleted) for compatibility. Idempotent: safe to run repeatedly.
    """
    if not settings.RETENTION_ENABLED:
        logger.info("Retention is disabled (RETENTION_ENABLED=false); skipping.")
        return (0, 0)

    cutoff = datetime.now(timezone.utc) - timedelta(hours=settings.RETENTION_HOURS)
    deleted_count = (
        session.query(Finding)
        .filter(Finding.created_at < cutoff)
        .delete(synchronize_session=False)
    )
    session.commit()

    if deleted_count > 0:
        logger.info(
            "Retention run: cutoff=%s, findings_deleted=%s",
            cutoff.isoformat(),
            deleted_count,
        )
    return (0, deleted_count)
