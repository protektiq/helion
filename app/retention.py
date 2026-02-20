"""
CLI entrypoint for the data retention job. Run from cron, e.g.:

  python -m app.retention

Or hourly: 0 * * * * cd /path/to/helion && .venv/bin/python -m app.retention
"""

import logging
import sys

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.services.retention import run_retention

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger(__name__)


def main() -> int:
    """Run retention: delete findings older than RETENTION_HOURS."""
    settings = get_settings()
    db = SessionLocal()
    try:
        _, findings_deleted = run_retention(db, settings)
        logger.info("Retention completed: findings_deleted=%s", findings_deleted)
        return 0
    except Exception as e:
        logger.exception("Retention job failed: %s", e)
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
