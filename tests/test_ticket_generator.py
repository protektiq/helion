"""Unit tests for app.services.ticket_generator: cluster to Jira-ready ticket payload."""

import unittest

from app.schemas.findings import VulnerabilityCluster
from app.schemas.reasoning import ClusterNote
from app.schemas.risk_tier import ClusterRiskTierResult
from app.schemas.ticket import DevTicketPayload, TITLE_MAX_LENGTH
from app.services.ticket_generator import (
    DEFAULT_ACCEPTANCE_CRITERIA,
    cluster_to_ticket_payload,
    clusters_to_ticket_payloads,
)


def _cluster(
    vulnerability_id: str = "CVE-2024-0001",
    severity: str = "high",
    repo: str = "my-service",
    cvss_score: float = 7.5,
    description: str = "Test vulnerability description.",
    **kwargs: object,
) -> VulnerabilityCluster:
    """Build a minimal VulnerabilityCluster for tests."""
    defaults = {
        "file_path": "",
        "dependency": "",
        "finding_ids": ["1"],
        "affected_services_count": 1,
        "finding_count": 1,
    }
    defaults.update(kwargs)
    return VulnerabilityCluster(
        vulnerability_id=vulnerability_id,
        severity=severity,
        repo=repo,
        cvss_score=cvss_score,
        description=description,
        **defaults,
    )


class TestSingleClusterNoNoteTier(unittest.TestCase):
    """Single cluster without ClusterNote or ClusterRiskTierResult."""

    def test_has_required_fields(self) -> None:
        cluster = _cluster()
        payload = cluster_to_ticket_payload(cluster)
        self.assertIsInstance(payload, DevTicketPayload)
        self.assertIsInstance(payload.title, str)
        self.assertIsInstance(payload.description, str)
        self.assertIsInstance(payload.affected_services, list)
        self.assertIsInstance(payload.acceptance_criteria, list)
        self.assertIsInstance(payload.recommended_remediation, str)
        self.assertIsInstance(payload.risk_tier_label, str)

    def test_single_repo_affected_services(self) -> None:
        cluster = _cluster(repo="single-repo")
        payload = cluster_to_ticket_payload(cluster)
        self.assertEqual(payload.affected_services, ["single-repo"])

    def test_acceptance_criteria_constant(self) -> None:
        cluster = _cluster()
        payload = cluster_to_ticket_payload(cluster)
        self.assertEqual(payload.acceptance_criteria, DEFAULT_ACCEPTANCE_CRITERIA)

    def test_remediation_fallback_from_cluster_description(self) -> None:
        cluster = _cluster(description="Fix by upgrading the dependency.")
        payload = cluster_to_ticket_payload(cluster)
        self.assertEqual(payload.recommended_remediation, "Fix by upgrading the dependency.")

    def test_risk_tier_label_from_severity(self) -> None:
        cluster = _cluster(severity="critical")
        payload = cluster_to_ticket_payload(cluster)
        self.assertEqual(payload.risk_tier_label, "Tier 1")

        cluster_high = _cluster(severity="high")
        payload_high = cluster_to_ticket_payload(cluster_high)
        self.assertEqual(payload_high.risk_tier_label, "Tier 2")

        cluster_low = _cluster(severity="low")
        payload_low = cluster_to_ticket_payload(cluster_low)
        self.assertEqual(payload_low.risk_tier_label, "Tier 3")

    def test_title_contains_tier_and_vulnerability_id(self) -> None:
        cluster = _cluster(vulnerability_id="CVE-2024-1234", severity="high")
        payload = cluster_to_ticket_payload(cluster)
        self.assertIn("Tier 2", payload.title)
        self.assertIn("CVE-2024-1234", payload.title)

    def test_description_contains_key_fields(self) -> None:
        cluster = _cluster(
            vulnerability_id="CVE-X",
            description="A critical bug.",
            file_path="src/foo.py",
            dependency="lodash",
        )
        payload = cluster_to_ticket_payload(cluster)
        self.assertIn("CVE-X", payload.description)
        self.assertIn("A critical bug.", payload.description)
        self.assertIn("src/foo.py", payload.description)
        self.assertIn("lodash", payload.description)
        self.assertIn("Finding count:", payload.description)
        self.assertIn("Affected services count:", payload.description)


class TestSingleClusterMultipleRepos(unittest.TestCase):
    """Cluster with repo == 'multiple' and optional affected_services override."""

    def test_multiple_without_override_uses_placeholder(self) -> None:
        cluster = _cluster(repo="multiple", affected_services_count=3)
        payload = cluster_to_ticket_payload(cluster)
        self.assertEqual(payload.affected_services, ["multiple repositories"])

    def test_multiple_with_override_uses_passed_list(self) -> None:
        cluster = _cluster(repo="multiple", affected_services_count=2)
        payload = cluster_to_ticket_payload(
            cluster,
            affected_services=["repo-a", "repo-b"],
        )
        self.assertEqual(payload.affected_services, ["repo-a", "repo-b"])


class TestSingleClusterWithNoteAndTier(unittest.TestCase):
    """Cluster with ClusterNote and ClusterRiskTierResult."""

    def test_recommended_remediation_from_note_reasoning(self) -> None:
        cluster = _cluster(description="Generic description.")
        note = ClusterNote(
            vulnerability_id=cluster.vulnerability_id,
            priority="high",
            reasoning="Upgrade to version 2.0 and run tests.",
        )
        payload = cluster_to_ticket_payload(cluster, cluster_note=note)
        self.assertEqual(
            payload.recommended_remediation,
            "Upgrade to version 2.0 and run tests.",
        )

    def test_risk_tier_label_from_tier_result(self) -> None:
        cluster = _cluster(severity="low")
        tier_result = ClusterRiskTierResult(
            vulnerability_id=cluster.vulnerability_id,
            assigned_tier=1,
            llm_reasoning=None,
            override_applied=None,
        )
        payload = cluster_to_ticket_payload(cluster, risk_tier_result=tier_result)
        self.assertEqual(payload.risk_tier_label, "Tier 1")


class TestBatch(unittest.TestCase):
    """clusters_to_ticket_payloads with optional maps."""

    def test_batch_count_matches_clusters(self) -> None:
        clusters = [
            _cluster("CVE-A", repo="r1"),
            _cluster("CVE-B", repo="r2"),
        ]
        payloads = clusters_to_ticket_payloads(clusters)
        self.assertEqual(len(payloads), 2)
        self.assertIn("CVE-A", payloads[0].title)
        self.assertIn("CVE-B", payloads[1].title)
        for p in payloads:
            self.assertIsInstance(p, DevTicketPayload)
            self.assertTrue(len(p.affected_services) >= 1)
            self.assertTrue(len(p.acceptance_criteria) >= 1)

    def test_batch_with_notes_and_tiers(self) -> None:
        clusters = [
            _cluster("CVE-X", severity="high"),
            _cluster("CVE-Y", severity="low"),
        ]
        notes = {
            "CVE-X": ClusterNote(
                vulnerability_id="CVE-X",
                priority="high",
                reasoning="Remediate X.",
            ),
        }
        tiers = {
            "CVE-X": ClusterRiskTierResult(
                vulnerability_id="CVE-X",
                assigned_tier=2,
                llm_reasoning=None,
                override_applied=None,
            ),
            "CVE-Y": ClusterRiskTierResult(
                vulnerability_id="CVE-Y",
                assigned_tier=3,
                llm_reasoning=None,
                override_applied=None,
            ),
        }
        payloads = clusters_to_ticket_payloads(
            clusters,
            notes_by_id=notes,
            tier_by_id=tiers,
        )
        self.assertEqual(len(payloads), 2)
        self.assertEqual(payloads[0].recommended_remediation, "Remediate X.")
        self.assertEqual(payloads[0].risk_tier_label, "Tier 2")
        self.assertEqual(payloads[1].risk_tier_label, "Tier 3")

    def test_batch_empty_clusters(self) -> None:
        payloads = clusters_to_ticket_payloads([])
        self.assertEqual(payloads, [])


class TestEdgeCases(unittest.TestCase):
    """Title truncation, fallback remediation, empty inputs."""

    def test_long_vulnerability_id_title_truncated(self) -> None:
        long_id = "CVE-2024-" + "x" * 300
        cluster = _cluster(vulnerability_id=long_id)
        payload = cluster_to_ticket_payload(cluster)
        self.assertLessEqual(len(payload.title), TITLE_MAX_LENGTH)
        self.assertIn("CVE-2024", payload.title)

    def test_remediation_fallback_when_description_blank(self) -> None:
        # When description is only whitespace, fallback is used
        cluster = _cluster(description="   ")
        payload = cluster_to_ticket_payload(cluster)
        self.assertEqual(
            payload.recommended_remediation,
            "Review and remediate per security guidance.",
        )

    def test_multiple_repos_empty_override_uses_placeholder(self) -> None:
        cluster = _cluster(repo="multiple")
        payload = cluster_to_ticket_payload(cluster, affected_services=[])
        self.assertEqual(payload.affected_services, ["multiple repositories"])
