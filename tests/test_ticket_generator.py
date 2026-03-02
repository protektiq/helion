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
        self.assertIn("CVSS: 7.5", payload.description)

    def test_description_cvss_n_a_when_score_zero(self) -> None:
        """When cvss_score is 0 or 0.0, description shows CVSS: n/a and never 'CVSS: 0.0'."""
        cluster = _cluster(cvss_score=0.0, severity="high")
        payload = cluster_to_ticket_payload(cluster)
        self.assertIn("CVSS: n/a", payload.description)
        self.assertNotIn("CVSS: 0.0", payload.description)

    def test_description_cvss_n_a_when_score_zero_int(self) -> None:
        """When cvss_score is 0 (int coerced to float), description shows CVSS: n/a."""
        cluster = _cluster(cvss_score=0, severity="critical")
        payload = cluster_to_ticket_payload(cluster)
        self.assertIn("CVSS: n/a", payload.description)


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
        """With ClusterNote but no fix versions, remediation uses evidence-only narrative with generic action (no LLM reasoning)."""
        cluster = _cluster(description="Generic description.")
        note = ClusterNote(
            vulnerability_id=cluster.vulnerability_id,
            priority="high",
            reasoning="Upgrade to version 2.0 and run tests.",
        )
        payload = cluster_to_ticket_payload(cluster, cluster_note=note)
        self.assertEqual(
            payload.recommended_remediation,
            "Action: Apply vendor patch or upgrade per advisory.",
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

    def test_description_includes_exploitability_evidence_when_note_has_enrichment(self) -> None:
        """With ClusterNote containing KEV, EPSS, evidence, fix versions, ecosystem, description has compact Exploitability line."""
        cluster = _cluster(vulnerability_id="CVE-2024-1234")
        note = ClusterNote(
            vulnerability_id=cluster.vulnerability_id,
            priority="high",
            reasoning="Upgrade to fixed version.",
            kev=True,
            epss=0.15,
            evidence=["KEV listed", "EPSS 0.15"],
            fixed_in_versions=["2.0.0", "2.1.0"],
            package_ecosystem="npm",
        )
        payload = cluster_to_ticket_payload(cluster, cluster_note=note)
        self.assertIn("Exploitability:", payload.description)
        self.assertIn("KEV: Yes", payload.description)
        self.assertIn("EPSS:", payload.description)
        self.assertIn("0.15", payload.description)
        self.assertIn("Fix:", payload.description)
        self.assertIn("2.0.0", payload.description)

    def test_acceptance_criteria_include_kev_and_epss_when_note_has_enrichment(self) -> None:
        """With ClusterNote containing KEV/EPSS, acceptance criteria are verification-only (no KEV/EPSS/fix bullets); evidence remains in description."""
        cluster = _cluster(vulnerability_id="CVE-2024-5678")
        note = ClusterNote(
            vulnerability_id=cluster.vulnerability_id,
            priority="critical",
            reasoning="Remediate soon.",
            kev=True,
            epss=0.85,
            evidence=["KEV listed"],
            fixed_in_versions=["3.0.0"],
        )
        payload = cluster_to_ticket_payload(cluster, cluster_note=note)
        self.assertEqual(payload.acceptance_criteria, DEFAULT_ACCEPTANCE_CRITERIA)
        self.assertIn("Exploitability:", payload.description)
        self.assertIn("KEV: Yes", payload.description)
        self.assertIn("3.0.0", payload.description)

    def test_epss_display_used_when_present_cve_with_percentile(self) -> None:
        """When ClusterNote has epss_display, ticket uses it for EPSS line in description only (not in acceptance criteria)."""
        cluster = _cluster(vulnerability_id="CVE-2024-1234")
        note = ClusterNote(
            vulnerability_id=cluster.vulnerability_id,
            priority="high",
            reasoning="Remediate.",
            epss=0.94,
            epss_display="0.94 (99.99 percentile)",
        )
        payload = cluster_to_ticket_payload(cluster, cluster_note=note)
        self.assertIn("EPSS: 0.94 (99.99 percentile)", payload.description)
        self.assertEqual(payload.acceptance_criteria, DEFAULT_ACCEPTANCE_CRITERIA)

    def test_epss_display_ghsa_only(self) -> None:
        """When epss_display is Not applicable (GHSA-only), ticket shows it in description only (not in acceptance criteria)."""
        cluster = _cluster(vulnerability_id="GHSA-xxxx-xxxx-xxxx")
        note = ClusterNote(
            vulnerability_id=cluster.vulnerability_id,
            priority="high",
            reasoning="Remediate.",
            epss_display="Not applicable (GHSA-only)",
        )
        payload = cluster_to_ticket_payload(cluster, cluster_note=note)
        self.assertIn("EPSS: Not applicable (GHSA-only)", payload.description)
        self.assertEqual(payload.acceptance_criteria, DEFAULT_ACCEPTANCE_CRITERIA)

    def test_epss_display_not_available_no_record(self) -> None:
        """When epss_status is NOT_FOUND, ticket shows Not available (no EPSS record) in description only."""
        cluster = _cluster(vulnerability_id="CVE-2024-0000")
        note = ClusterNote(
            vulnerability_id=cluster.vulnerability_id,
            priority="medium",
            reasoning="Remediate.",
            epss_status="NOT_FOUND",
        )
        payload = cluster_to_ticket_payload(cluster, cluster_note=note)
        self.assertIn("EPSS: Not available (no EPSS record)", payload.description)
        self.assertEqual(payload.acceptance_criteria, DEFAULT_ACCEPTANCE_CRITERIA)

    def test_epss_display_unavailable_lookup_failed(self) -> None:
        """When epss_status is ERROR, ticket shows Unavailable (lookup failed) in description only."""
        cluster = _cluster(vulnerability_id="CVE-2024-0001")
        note = ClusterNote(
            vulnerability_id=cluster.vulnerability_id,
            priority="high",
            reasoning="Remediate.",
            epss_status="ERROR",
        )
        payload = cluster_to_ticket_payload(cluster, cluster_note=note)
        self.assertIn("EPSS: Unavailable (lookup failed)", payload.description)
        self.assertEqual(payload.acceptance_criteria, DEFAULT_ACCEPTANCE_CRITERIA)

    def test_epss_status_available_with_ordinal_percentile(self) -> None:
        """When epss_status is AVAILABLE with percentile, ticket shows ordinal (e.g. 42nd percentile) in description only."""
        cluster = _cluster(vulnerability_id="CVE-2024-1234")
        note = ClusterNote(
            vulnerability_id=cluster.vulnerability_id,
            priority="high",
            reasoning="Remediate.",
            epss_status="AVAILABLE",
            epss=0.42,
            epss_percentile=0.42,
        )
        payload = cluster_to_ticket_payload(cluster, cluster_note=note)
        self.assertIn("EPSS: 0.42 (42nd percentile)", payload.description)
        self.assertEqual(payload.acceptance_criteria, DEFAULT_ACCEPTANCE_CRITERIA)

    def test_epss_small_score_adaptive_precision(self) -> None:
        """When epss < 0.01 and no epss_display, ticket shows 4 decimal places (e.g. 0.0034) not 0.00."""
        cluster = _cluster(vulnerability_id="CVE-2024-0001")
        note = ClusterNote(
            vulnerability_id=cluster.vulnerability_id,
            priority="medium",
            reasoning="Remediate.",
            epss_status="AVAILABLE",
            epss=0.0034,
        )
        payload = cluster_to_ticket_payload(cluster, cluster_note=note)
        self.assertIn("EPSS: 0.0034", payload.description)

    def test_epss_error_with_reason(self) -> None:
        """When epss_status is ERROR and epss_reason is set, ticket shows Unavailable (reason)."""
        cluster = _cluster(vulnerability_id="CVE-2024-0001")
        note = ClusterNote(
            vulnerability_id=cluster.vulnerability_id,
            priority="high",
            reasoning="Remediate.",
            epss_status="ERROR",
            epss_reason="rate limited",
        )
        payload = cluster_to_ticket_payload(cluster, cluster_note=note)
        self.assertIn("EPSS: Unavailable (rate limited)", payload.description)
        self.assertEqual(payload.acceptance_criteria, DEFAULT_ACCEPTANCE_CRITERIA)


class TestRecommendationUrgencyKEVAndEpss(unittest.TestCase):
    """Recommendation includes 'Why now' sentence when KEV/EPSS available; no old urgency prefix."""

    def test_kev_prepends_urgent_line_to_remediation(self) -> None:
        """When KEV is true, recommended_remediation starts with 'Why now: Listed in CISA KEV (known exploited).' and uses evidence-only action."""
        cluster = _cluster(vulnerability_id="CVE-2024-1234")
        note = ClusterNote(
            vulnerability_id=cluster.vulnerability_id,
            priority="high",
            reasoning="Upgrade to 2.0.",
            kev=True,
            epss=0.1,
        )
        payload = cluster_to_ticket_payload(cluster, cluster_note=note)
        self.assertTrue(
            payload.recommended_remediation.startswith("Why now: Listed in CISA KEV (known exploited)"),
            f"remediation should start with Why now KEV line; got: {payload.recommended_remediation!r}",
        )
        self.assertIn("Action: Apply vendor patch or upgrade per advisory.", payload.recommended_remediation)

    def test_high_epss_not_kev_prepends_high_exploit_likelihood(self) -> None:
        """When EPSS is high (score >= 0.7) and not KEV, recommendation starts with 'Why now: EPSS ... (92nd percentile).' and uses evidence-only action."""
        cluster = _cluster(vulnerability_id="CVE-2024-5678")
        note = ClusterNote(
            vulnerability_id=cluster.vulnerability_id,
            priority="high",
            reasoning="Apply patch when available.",
            kev=False,
            epss=0.85,
            epss_percentile=0.92,
        )
        payload = cluster_to_ticket_payload(cluster, cluster_note=note)
        self.assertTrue(
            payload.recommended_remediation.startswith("Why now: EPSS 0.85 (92nd percentile)."),
            f"remediation should start with Why now EPSS line; got: {payload.recommended_remediation!r}",
        )
        self.assertIn("Action: Apply vendor patch or upgrade per advisory.", payload.recommended_remediation)

    def test_high_epss_percentile_only_prepends_urgency(self) -> None:
        """When epss_percentile >= 0.9 and epss below 0.7, recommendation still includes 'Why now: EPSS ...' and evidence-only action."""
        cluster = _cluster(vulnerability_id="CVE-2024-9999")
        note = ClusterNote(
            vulnerability_id=cluster.vulnerability_id,
            priority="medium",
            reasoning="Remediate per vendor advisory.",
            kev=False,
            epss=0.5,
            epss_percentile=0.91,
        )
        payload = cluster_to_ticket_payload(cluster, cluster_note=note)
        self.assertTrue(
            payload.recommended_remediation.startswith("Why now: EPSS 0.50 (91st percentile)."),
            f"remediation should start with Why now EPSS line; got: {payload.recommended_remediation!r}",
        )
        self.assertIn("Action: Apply vendor patch or upgrade per advisory.", payload.recommended_remediation)

    def test_neither_kev_nor_high_epss_no_urgency_prefix(self) -> None:
        """When not KEV and EPSS below threshold, no 'Why now' sentence; remediation is evidence-only generic action."""
        cluster = _cluster(vulnerability_id="CVE-2024-0000")
        note = ClusterNote(
            vulnerability_id=cluster.vulnerability_id,
            priority="medium",
            reasoning="Standard remediation steps.",
            kev=False,
            epss=0.3,
            epss_percentile=0.4,
        )
        payload = cluster_to_ticket_payload(cluster, cluster_note=note)
        self.assertFalse(
            payload.recommended_remediation.startswith("Why now:"),
            "should not have Why now when no KEV/EPSS signal",
        )
        self.assertEqual(payload.recommended_remediation, "Action: Apply vendor patch or upgrade per advisory.")


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
        notes_by_key = {
            ("CVE-X", ""): ClusterNote(
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
            notes_by_key=notes_by_key,
            tier_by_id=tiers,
        )
        self.assertEqual(len(payloads), 2)
        self.assertIn("Action: Apply vendor patch or upgrade per advisory.", payloads[0].recommended_remediation)
        self.assertEqual(payloads[0].risk_tier_label, "Tier 2")
        self.assertEqual(payloads[1].risk_tier_label, "Tier 3")

    def test_batch_empty_clusters(self) -> None:
        payloads = clusters_to_ticket_payloads([])
        self.assertEqual(payloads, [])


class TestEdgeCases(unittest.TestCase):
    """Title truncation, fallback remediation, empty inputs."""

    def test_clear_action_upgrade_when_dependency_and_fixed_version(self) -> None:
        """When cluster has dependency and note has fixed_in_versions, recommendation includes 'Action: Upgrade <dep> to <ver>.'"""
        cluster = _cluster(
            vulnerability_id="CVE-2024-1111",
            dependency="lodash",
            description="Some vulnerability.",
        )
        note = ClusterNote(
            vulnerability_id=cluster.vulnerability_id,
            priority="high",
            reasoning="Consider upgrading.",
            fixed_in_versions=["4.17.21"],
        )
        payload = cluster_to_ticket_payload(cluster, cluster_note=note)
        self.assertIn("Action: Upgrade lodash to 4.17.21.", payload.recommended_remediation)

    def test_scope_hint_in_recommendation_when_dependency_and_path(self) -> None:
        """When cluster has dependency and file_path, recommendation includes Scope hint and evidence-only action."""
        cluster = _cluster(
            vulnerability_id="CVE-2024-2222",
            dependency="minimist",
            file_path="package-lock.json",
        )
        note = ClusterNote(
            vulnerability_id=cluster.vulnerability_id,
            priority="medium",
            reasoning="Apply patch.",
        )
        payload = cluster_to_ticket_payload(cluster, cluster_note=note)
        self.assertIn("Scope:", payload.recommended_remediation)
        self.assertIn("dependency: minimist", payload.recommended_remediation)
        self.assertIn("path: package-lock.json", payload.recommended_remediation)
        self.assertIn("Action: Apply vendor patch or upgrade per advisory.", payload.recommended_remediation)

    def test_why_now_kev_and_epss_both_present(self) -> None:
        """When both KEV and high EPSS, recommendation starts with 'Why now: ... and EPSS ...' and uses evidence-only action."""
        cluster = _cluster(vulnerability_id="CVE-2024-3333")
        note = ClusterNote(
            vulnerability_id=cluster.vulnerability_id,
            priority="critical",
            reasoning="Remediate immediately.",
            kev=True,
            epss=0.82,
            epss_percentile=0.92,
        )
        payload = cluster_to_ticket_payload(cluster, cluster_note=note)
        self.assertTrue(
            payload.recommended_remediation.startswith("Why now: Listed in CISA KEV (known exploited) and EPSS 0.82 (92nd percentile)."),
            payload.recommended_remediation,
        )
        self.assertIn("Action: Apply vendor patch or upgrade per advisory.", payload.recommended_remediation)

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
