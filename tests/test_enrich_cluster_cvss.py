"""Unit tests for CVSS-related behavior in cluster enrichment."""

import unittest

from app.schemas.findings import VulnerabilityCluster
from app.services.enrichment.enrich_cluster import _build_cvss_check


def _cluster(
    severity: str = "high",
    cvss_score: float = 7.5,
) -> VulnerabilityCluster:
    return VulnerabilityCluster(
        vulnerability_id="CVE-2024-0001",
        severity=severity,
        repo="my-repo",
        file_path="",
        dependency="",
        cvss_score=cvss_score,
        description="Test",
        finding_ids=["1"],
        affected_services_count=1,
        finding_count=1,
    )


class TestBuildCvssCheck(unittest.TestCase):
    """_build_cvss_check returns None when CVSS is not present."""

    def test_cvss_check_none_when_score_zero(self) -> None:
        """When severity is high but cvss_score is 0, no CVSS check (avoid 'expected severity: info' mismatch)."""
        cluster = _cluster(severity="high", cvss_score=0.0)
        result = _build_cvss_check(cluster)
        self.assertIsNone(result)

    def test_cvss_check_present_when_score_positive(self) -> None:
        """When cvss_score > 0, a CvssCheck is returned."""
        cluster = _cluster(severity="high", cvss_score=7.5)
        result = _build_cvss_check(cluster)
        self.assertIsNotNone(result)
        self.assertEqual(result.expected_severity, "high")
        self.assertFalse(result.mismatch)
