"""Unit tests for clustering: build_clusters (Python fallback and Rust when available)."""

import json
import unittest
from types import SimpleNamespace

from app.schemas.findings import VulnerabilityCluster
from app.services.clustering import (
    _findings_to_rust_input,
    build_clusters,
    sort_clusters_by_severity_cvss,
)


def _mock_finding(
    id: int = 1,
    vulnerability_id: str = "CVE-2024-1234",
    severity: str = "high",
    repo: str = "my-repo",
    file_path: str = "",
    dependency: str = "pkg",
    cvss_score: float = 7.0,
    description: str = "Test",
) -> object:
    """Minimal Finding-like object for clustering tests."""
    return SimpleNamespace(
        id=id,
        vulnerability_id=vulnerability_id,
        severity=severity,
        repo=repo,
        file_path=file_path,
        dependency=dependency,
        cvss_score=cvss_score,
        description=description,
    )


class TestFindingsToRustInput(unittest.TestCase):
    """_findings_to_rust_input produces JSON-serializable list with required fields."""

    def test_empty(self) -> None:
        out = _findings_to_rust_input([])
        self.assertEqual(out, [])

    def test_single_finding(self) -> None:
        f = _mock_finding(id=42, vulnerability_id="CVE-1", dependency="lodash")
        out = _findings_to_rust_input([f])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["id"], "42")
        self.assertEqual(out[0]["vulnerability_id"], "CVE-1")
        self.assertEqual(out[0]["dependency"], "lodash")
        # Must be JSON-serializable
        json_str = json.dumps(out)
        self.assertIn("CVE-1", json_str)


class TestBuildClusters(unittest.TestCase):
    """build_clusters groups by SCA/SAST key and returns VulnerabilityClusters."""

    def test_empty_findings(self) -> None:
        clusters = build_clusters([])
        self.assertEqual(clusters, [])

    def test_single_finding(self) -> None:
        f = _mock_finding(id=1, vulnerability_id="CVE-2024-1", dependency="d")
        clusters = build_clusters([f])
        self.assertEqual(len(clusters), 1)
        c = clusters[0]
        self.assertEqual(c.vulnerability_id, "CVE-2024-1")
        self.assertEqual(c.finding_ids, ["1"])
        self.assertEqual(c.finding_count, 1)
        self.assertEqual(c.affected_services_count, 1)

    def test_two_findings_same_sca_key_one_cluster(self) -> None:
        f1 = _mock_finding(id=1, vulnerability_id="CVE-2024-9999", dependency="pkg", severity="high")
        f2 = _mock_finding(id=2, vulnerability_id="CVE-2024-9999", dependency="pkg", severity="low")
        clusters = build_clusters([f1, f2])
        self.assertEqual(len(clusters), 1)
        c = clusters[0]
        self.assertEqual(c.vulnerability_id, "CVE-2024-9999")
        self.assertEqual(set(c.finding_ids), {"1", "2"})
        self.assertEqual(c.finding_count, 2)
        self.assertEqual(c.severity, "high")

    def test_two_findings_different_deps_two_clusters(self) -> None:
        f1 = _mock_finding(id=1, vulnerability_id="CVE-2024-1", dependency="lodash")
        f2 = _mock_finding(id=2, vulnerability_id="CVE-2024-1", dependency="express")
        clusters = build_clusters([f1, f2])
        self.assertEqual(len(clusters), 2)
        ids_per_cluster = [set(c.finding_ids) for c in clusters]
        self.assertIn({"1"}, ids_per_cluster)
        self.assertIn({"2"}, ids_per_cluster)

    def test_two_repos_same_cve_canonical_repo_multiple(self) -> None:
        f1 = _mock_finding(id=1, vulnerability_id="CVE-2024-1", dependency="d", repo="repo-a")
        f2 = _mock_finding(id=2, vulnerability_id="CVE-2024-1", dependency="d", repo="repo-b")
        clusters = build_clusters([f1, f2])
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0].repo, "multiple")
        self.assertEqual(clusters[0].affected_services_count, 2)


class TestSortClustersBySeverityCvss(unittest.TestCase):
    """sort_clusters_by_severity_cvss orders worst first."""

    def _cluster(self, severity: str, cvss_score: float, vulnerability_id: str = "CVE-1") -> VulnerabilityCluster:
        return VulnerabilityCluster(
            vulnerability_id=vulnerability_id,
            severity=severity,
            repo="r",
            file_path="",
            dependency="",
            cvss_score=cvss_score,
            description="D",
            finding_ids=["1"],
            affected_services_count=1,
            finding_count=1,
        )

    def test_critical_before_high(self) -> None:
        clusters = [
            self._cluster("high", 8.0, "CVE-2"),
            self._cluster("critical", 9.0, "CVE-1"),
        ]
        sorted_clusters = sort_clusters_by_severity_cvss(clusters)
        self.assertEqual(sorted_clusters[0].severity, "critical")
        self.assertEqual(sorted_clusters[1].severity, "high")
