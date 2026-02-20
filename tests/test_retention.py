"""Unit and integration tests for data retention: delete-only run_retention."""

import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

from app.models import Finding
from app.services.retention import run_retention


class TestRetentionDisabled(unittest.TestCase):
    """When RETENTION_ENABLED is False, run_retention does nothing."""

    def test_returns_zero_and_does_not_query(self) -> None:
        settings = MagicMock()
        settings.RETENTION_ENABLED = False
        settings.RETENTION_HOURS = 48
        session = MagicMock()
        summaries_inserted, findings_deleted = run_retention(session, settings)
        self.assertEqual(summaries_inserted, 0)
        self.assertEqual(findings_deleted, 0)
        session.query.assert_not_called()


class TestRetentionNoOldFindings(unittest.TestCase):
    """When there are no findings older than cutoff, run_retention returns (0, 0)."""

    def test_returns_zero(self) -> None:
        settings = MagicMock()
        settings.RETENTION_ENABLED = True
        settings.RETENTION_HOURS = 48
        session = MagicMock()
        session.query.return_value.filter.return_value.delete.return_value = 0
        summaries_inserted, findings_deleted = run_retention(session, settings)
        self.assertEqual(summaries_inserted, 0)
        self.assertEqual(findings_deleted, 0)
        session.commit.assert_called_once()


class TestRetentionDeletesOldFindings(unittest.TestCase):
    """When there are old findings, run_retention deletes them and returns (0, N)."""

    def test_deletes_old_findings(self) -> None:
        settings = MagicMock()
        settings.RETENTION_ENABLED = True
        settings.RETENTION_HOURS = 48
        session = MagicMock()
        session.query.return_value.filter.return_value.delete.return_value = 2
        summaries_inserted, findings_deleted = run_retention(session, settings)
        self.assertEqual(summaries_inserted, 0)
        self.assertEqual(findings_deleted, 2)
        session.add.assert_not_called()
        session.commit.assert_called_once()


class TestRetentionIntegration(unittest.TestCase):
    """Integration test with real DB: insert old findings, run retention, assert deleted."""

    def test_retention_run_against_real_db(self) -> None:
        try:
            from app.core.database import SessionLocal
            from app.core.config import get_settings
        except Exception:
            self.skipTest("DB or config not available")
        settings = get_settings()
        if not settings.RETENTION_ENABLED:
            self.skipTest("RETENTION_ENABLED is False")
        cutoff = datetime.now(timezone.utc) - timedelta(hours=settings.RETENTION_HOURS + 1)
        try:
            db = SessionLocal()
        except Exception as e:
            self.skipTest(f"Database not available: {e}")
        try:
            f1 = Finding(
                vulnerability_id="CVE-TEST-RETENTION",
                severity="low",
                repo="test-repo",
                file_path="",
                dependency="",
                cvss_score=3.0,
                description="Integration test finding for retention",
                created_at=cutoff,
            )
            db.add(f1)
            db.flush()
            f2 = Finding(
                vulnerability_id="CVE-TEST-RETENTION",
                severity="low",
                repo="test-repo",
                file_path="",
                dependency="",
                cvss_score=3.0,
                description="Integration test finding for retention",
                created_at=cutoff,
            )
            db.add(f2)
            db.commit()
            ids_created = [f1.id, f2.id]
            count_before = db.query(Finding).filter(Finding.id.in_(ids_created)).count()
            self.assertEqual(count_before, 2)

            run_retention(db, settings)

            count_after = db.query(Finding).filter(Finding.id.in_(ids_created)).count()
            self.assertEqual(count_after, 0)
        except Exception as e:
            db.rollback()
            if "Connection refused" in str(e) or "OperationalError" in type(e).__name__:
                self.skipTest(f"Database not running: {e}")
            raise e
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
