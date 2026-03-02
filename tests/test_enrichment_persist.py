"""Unit tests for app.services.enrichment.persist."""

import unittest
from unittest.mock import MagicMock

from app.services.enrichment.persist import save_cluster_enrichment


class TestSaveClusterEnrichment(unittest.TestCase):
    """save_cluster_enrichment requires upload_job_id and raises when it is None."""

    def test_raises_value_error_when_upload_job_id_none(self) -> None:
        session = MagicMock()
        with self.assertRaises(ValueError) as ctx:
            save_cluster_enrichment(
                session,
                None,  # type: ignore[arg-type]
                "CVE-2024-0001",
                {"kev": False, "epss": 0.1},
            )
        self.assertIn("upload_job_id", str(ctx.exception))
        self.assertIn("must not be None", str(ctx.exception))
