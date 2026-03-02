"""Unit tests for EPSS status/reason in cluster enrichment."""

import unittest
from unittest.mock import AsyncMock, patch

from app.schemas.findings import VulnerabilityCluster
from app.services.enrichment.enrich_cluster import enrich_cluster
from app.services.enrichment.client_epss import EpssResult


def _cluster(
    vulnerability_id: str = "CVE-2024-0001",
    severity: str = "high",
    repo: str = "my-repo",
    cvss_score: float = 7.5,
) -> VulnerabilityCluster:
    return VulnerabilityCluster(
        vulnerability_id=vulnerability_id,
        severity=severity,
        repo=repo,
        file_path="",
        dependency="",
        cvss_score=cvss_score,
        description="Test",
        finding_ids=["1"],
        affected_services_count=1,
        finding_count=1,
    )


def _mock_settings_epss_disabled():
    settings = unittest.mock.MagicMock()
    settings.ENRICHMENT_KEV_ENABLED = False
    settings.ENRICHMENT_EPSS_ENABLED = False
    settings.ENRICHMENT_OSV_ENABLED = False
    settings.ENRICHMENT_EPSS_DEBUG = False
    settings.DEBUG = False
    return settings


def _mock_settings():
    settings = unittest.mock.MagicMock()
    settings.ENRICHMENT_KEV_ENABLED = False
    settings.ENRICHMENT_EPSS_ENABLED = True
    settings.ENRICHMENT_OSV_ENABLED = False
    settings.ENRICHMENT_EPSS_DEBUG = False
    settings.DEBUG = False
    return settings


class TestEnrichClusterEpssStatus(unittest.IsolatedAsyncioTestCase):
    """enrich_cluster sets epss_status and epss_reason from EPSS result."""

    @patch("app.services.enrichment.enrich_cluster.fetch_epss")
    async def test_cve_ok_sets_available(self, mock_fetch: AsyncMock) -> None:
        mock_fetch.return_value = EpssResult(
            status="ok",
            score=0.42,
            percentile=0.99,
        )
        cluster = _cluster(vulnerability_id="CVE-2024-1234")
        payload, raw = await enrich_cluster(cluster, _mock_settings())
        self.assertEqual(payload.epss_status, "AVAILABLE")
        self.assertIsNone(payload.epss_reason)
        self.assertEqual(payload.epss, 0.42)
        self.assertEqual(payload.epss_percentile, 0.99)
        self.assertIn("0.42", payload.epss_display or "")
        self.assertEqual(raw.get("epss_status"), "AVAILABLE")
        self.assertIsNone(raw.get("epss_reason"))

    @patch("app.services.enrichment.enrich_cluster.fetch_epss")
    async def test_cve_not_found_sets_not_found(self, mock_fetch: AsyncMock) -> None:
        mock_fetch.return_value = EpssResult(status="not_found")
        cluster = _cluster(vulnerability_id="CVE-2024-0000")
        payload, raw = await enrich_cluster(cluster, _mock_settings())
        self.assertEqual(payload.epss_status, "NOT_FOUND")
        self.assertIsNone(payload.epss_reason)
        self.assertIn("Not available (no EPSS record)", payload.epss_display or "")
        self.assertEqual(raw.get("epss_status"), "NOT_FOUND")

    @patch("app.services.enrichment.enrich_cluster.fetch_epss")
    async def test_cve_unavailable_sets_error(self, mock_fetch: AsyncMock) -> None:
        mock_fetch.return_value = EpssResult(status="unavailable")
        cluster = _cluster(vulnerability_id="CVE-2024-0001")
        payload, raw = await enrich_cluster(cluster, _mock_settings())
        self.assertEqual(payload.epss_status, "ERROR")
        self.assertEqual(payload.epss_reason, "lookup failed")
        self.assertIn("Unavailable (lookup failed)", payload.epss_display or "")
        self.assertEqual(raw.get("epss_status"), "ERROR")
        self.assertEqual(raw.get("epss_reason"), "lookup failed")

    @patch("app.services.enrichment.enrich_cluster.fetch_epss")
    async def test_ghsa_only_sets_not_applicable_ghsa(self, mock_fetch: AsyncMock) -> None:
        cluster = _cluster(vulnerability_id="GHSA-xxxx-xxxx-xxxx")
        payload, raw = await enrich_cluster(cluster, _mock_settings())
        mock_fetch.assert_not_called()
        self.assertEqual(payload.epss_status, "NOT_APPLICABLE")
        self.assertEqual(payload.epss_reason, "GHSA-only")
        self.assertEqual(payload.epss_display, "Not applicable (GHSA-only)")
        self.assertEqual(raw.get("epss_status"), "NOT_APPLICABLE")
        self.assertEqual(raw.get("epss_reason"), "GHSA-only")

    @patch("app.services.enrichment.enrich_cluster.fetch_epss")
    async def test_non_cve_sets_not_applicable_non_cve(self, mock_fetch: AsyncMock) -> None:
        cluster = _cluster(vulnerability_id="OTHER-ID-123")
        payload, raw = await enrich_cluster(cluster, _mock_settings())
        self.assertEqual(payload.epss_status, "NOT_APPLICABLE")
        self.assertEqual(payload.epss_reason, "non-CVE")
        self.assertEqual(payload.epss_display, "Not applicable (non-CVE)")
        self.assertEqual(raw.get("epss_status"), "NOT_APPLICABLE")
        self.assertEqual(raw.get("epss_reason"), "non-CVE")

    @patch("app.services.enrichment.enrich_cluster.fetch_epss")
    async def test_exception_sets_error_and_reason(self, mock_fetch: AsyncMock) -> None:
        mock_fetch.side_effect = RuntimeError("network error")
        cluster = _cluster(vulnerability_id="CVE-2024-9999")
        payload, raw = await enrich_cluster(cluster, _mock_settings())
        self.assertEqual(payload.epss_status, "ERROR")
        self.assertEqual(payload.epss_reason, "lookup failed")
        self.assertIn("Unavailable (lookup failed)", payload.epss_display or "")

    @patch("app.services.enrichment.enrich_cluster.fetch_epss")
    async def test_unavailable_rate_limited_sets_error_and_display(
        self, mock_fetch: AsyncMock
    ) -> None:
        mock_fetch.return_value = EpssResult(
            status="unavailable",
            reason="rate limited",
        )
        cluster = _cluster(vulnerability_id="CVE-2024-0001")
        payload, raw = await enrich_cluster(cluster, _mock_settings())
        self.assertEqual(payload.epss_status, "ERROR")
        self.assertEqual(payload.epss_reason, "rate limited")
        self.assertIn("rate limited", payload.epss_display or "")
        self.assertEqual(raw.get("epss_status"), "ERROR")
        self.assertEqual(raw.get("epss_reason"), "rate limited")

    @patch("app.services.enrichment.enrich_cluster.fetch_epss")
    async def test_ghsa_only_epss_disabled_sets_not_applicable(
        self, mock_fetch: AsyncMock
    ) -> None:
        """When EPSS is disabled, GHSA-only cluster still gets NOT_APPLICABLE (GHSA-only)."""
        cluster = _cluster(vulnerability_id="GHSA-xxxx-xxxx-xxxx")
        payload, raw = await enrich_cluster(cluster, _mock_settings_epss_disabled())
        mock_fetch.assert_not_called()
        self.assertEqual(payload.epss_status, "NOT_APPLICABLE")
        self.assertEqual(payload.epss_reason, "GHSA-only")
        self.assertEqual(payload.epss_display, "Not applicable (GHSA-only)")
        self.assertEqual(raw.get("epss_status"), "NOT_APPLICABLE")
        self.assertEqual(raw.get("epss_reason"), "GHSA-only")

    @patch("app.services.enrichment.enrich_cluster.fetch_epss")
    async def test_non_cve_epss_disabled_sets_not_applicable(
        self, mock_fetch: AsyncMock
    ) -> None:
        """When EPSS is disabled, non-CVE non-GHSA cluster still gets NOT_APPLICABLE (non-CVE)."""
        cluster = _cluster(vulnerability_id="OTHER-ID-123")
        payload, raw = await enrich_cluster(cluster, _mock_settings_epss_disabled())
        mock_fetch.assert_not_called()
        self.assertEqual(payload.epss_status, "NOT_APPLICABLE")
        self.assertEqual(payload.epss_reason, "non-CVE")
        self.assertEqual(payload.epss_display, "Not applicable (non-CVE)")
        self.assertEqual(raw.get("epss_status"), "NOT_APPLICABLE")
        self.assertEqual(raw.get("epss_reason"), "non-CVE")
