"""Unit tests for app.services.risk_tier: override rules, LLM mapping, and tier assignment."""

import unittest

from app.schemas.findings import VulnerabilityCluster
from app.schemas.reasoning import ClusterNote, ReasoningResponse
from app.schemas.risk_tier import RiskTierAssignmentInput
from app.services.enrichment.schemas import ClusterEnrichmentPayload
from app.services.risk_tier import (
    OVERRIDE_CVSS_BAND_7_9,
    OVERRIDE_CVSS_HIGH,
    OVERRIDE_DEV_ONLY_DOWNGRADE,
    assign_risk_tier,
    assign_risk_tiers,
    assess_tier_from_enrichment,
    validate_grounded_tier,
)


def _cluster(
    vulnerability_id: str = "CVE-2024-0001",
    severity: str = "high",
    cvss_score: float = 7.5,
    **kwargs: object,
) -> VulnerabilityCluster:
    """Build a minimal VulnerabilityCluster for tests."""
    defaults = {
        "repo": "test-repo",
        "file_path": "",
        "dependency": "",
        "description": "Test finding",
        "finding_ids": ["1"],
        "affected_services_count": 1,
        "finding_count": 1,
    }
    defaults.update(kwargs)
    return VulnerabilityCluster(
        vulnerability_id=vulnerability_id,
        severity=severity,
        cvss_score=cvss_score,
        **defaults,
    )


class TestCvssOverrideTier1(unittest.TestCase):
    """CVSS > 9 → Tier 1 unless dev-only."""

    def test_cvss_above_9_not_dev_only_assigns_tier_1(self) -> None:
        cluster = _cluster(cvss_score=9.1, severity="high")
        result = assign_risk_tier(cluster, llm_note=None, is_dev_only=False)
        self.assertEqual(result.assigned_tier, 1)
        self.assertEqual(result.override_applied, OVERRIDE_CVSS_HIGH)

    def test_cvss_above_9_dev_only_assigns_tier_2(self) -> None:
        cluster = _cluster(cvss_score=9.5, severity="critical")
        result = assign_risk_tier(cluster, llm_note=None, is_dev_only=True)
        self.assertEqual(result.assigned_tier, 2)
        self.assertEqual(result.override_applied, OVERRIDE_DEV_ONLY_DOWNGRADE)

    def test_cvss_equals_9_no_override(self) -> None:
        cluster = _cluster(cvss_score=9.0, severity="high")
        result = assign_risk_tier(cluster, llm_note=None, is_dev_only=False)
        self.assertNotEqual(result.override_applied, OVERRIDE_CVSS_HIGH)
        self.assertEqual(result.assigned_tier, 2)


class TestCvssBand7To9(unittest.TestCase):
    """CVSS in [7, 9] → at least Tier 2."""

    def test_cvss_7_suggested_tier_3_upgrades_to_tier_2(self) -> None:
        cluster = _cluster(cvss_score=7.0, severity="low")
        note = ClusterNote(
            vulnerability_id=cluster.vulnerability_id,
            priority="low",
            reasoning="Test",
        )
        result = assign_risk_tier(cluster, llm_note=note, is_dev_only=False)
        self.assertEqual(result.assigned_tier, 2)
        self.assertEqual(result.override_applied, OVERRIDE_CVSS_BAND_7_9)

    def test_cvss_8_high_severity_stays_tier_2(self) -> None:
        cluster = _cluster(cvss_score=8.0, severity="high")
        note = ClusterNote(
            vulnerability_id=cluster.vulnerability_id,
            priority="high",
            reasoning="Test",
        )
        result = assign_risk_tier(cluster, llm_note=note, is_dev_only=False)
        self.assertEqual(result.assigned_tier, 2)
        self.assertIsNone(result.override_applied)


class TestLlmPriorityMapping(unittest.TestCase):
    """LLM priority → suggested tier when no override."""

    def test_critical_priority_suggested_tier_1(self) -> None:
        cluster = _cluster(cvss_score=5.0, severity="high")
        note = ClusterNote(
            vulnerability_id=cluster.vulnerability_id,
            priority="critical",
            reasoning="Critical issue",
        )
        result = assign_risk_tier(cluster, llm_note=note, is_dev_only=False)
        self.assertEqual(result.assigned_tier, 1)
        self.assertIsNone(result.override_applied)

    def test_high_priority_suggested_tier_2(self) -> None:
        cluster = _cluster(cvss_score=5.0, severity="medium")
        note = ClusterNote(
            vulnerability_id=cluster.vulnerability_id,
            priority="high",
            reasoning="High",
        )
        result = assign_risk_tier(cluster, llm_note=note, is_dev_only=False)
        self.assertEqual(result.assigned_tier, 2)
        self.assertIsNone(result.override_applied)

    def test_medium_low_priority_suggested_tier_3(self) -> None:
        cluster = _cluster(cvss_score=3.0, severity="low")
        note = ClusterNote(
            vulnerability_id=cluster.vulnerability_id,
            priority="medium",
            reasoning="Medium",
        )
        result = assign_risk_tier(cluster, llm_note=note, is_dev_only=False)
        self.assertEqual(result.assigned_tier, 3)
        self.assertIsNone(result.override_applied)


class TestSeverityFallback(unittest.TestCase):
    """No LLM output: derive tier from severity/CVSS."""

    def test_critical_severity_no_llm_tier_1(self) -> None:
        cluster = _cluster(cvss_score=6.0, severity="critical")
        result = assign_risk_tier(cluster, llm_note=None, is_dev_only=False)
        self.assertEqual(result.assigned_tier, 1)

    def test_high_severity_no_llm_tier_2(self) -> None:
        cluster = _cluster(cvss_score=5.0, severity="high")
        result = assign_risk_tier(cluster, llm_note=None, is_dev_only=False)
        self.assertEqual(result.assigned_tier, 2)

    def test_low_severity_no_llm_tier_3(self) -> None:
        cluster = _cluster(cvss_score=2.0, severity="low")
        result = assign_risk_tier(cluster, llm_note=None, is_dev_only=False)
        self.assertEqual(result.assigned_tier, 3)


class TestEdgeCases(unittest.TestCase):
    """Missing/unknown inputs and safe defaults."""

    def test_unknown_priority_fallback_default_tier(self) -> None:
        cluster = _cluster(cvss_score=4.0, severity="info")
        note = ClusterNote(
            vulnerability_id=cluster.vulnerability_id,
            priority="unknown-label",
            reasoning="Test",
        )
        result = assign_risk_tier(cluster, llm_note=note, is_dev_only=False)
        self.assertIn(result.assigned_tier, (1, 2, 3))

    def test_low_cvss_high_severity_tier_2(self) -> None:
        """Low CVSS with high severity (no override) yields tier from severity."""
        cluster = _cluster(cvss_score=0.5, severity="high")
        result = assign_risk_tier(cluster, llm_note=None, is_dev_only=False)
        self.assertEqual(result.assigned_tier, 2)

    def test_cvss_zero_high_severity_no_override(self) -> None:
        """When cvss_score is 0, no CVSS override; tier from severity. No 'CVSS 0.0' in narrative."""
        cluster = _cluster(cvss_score=0.0, severity="high")
        result = assign_risk_tier(cluster, llm_note=None, is_dev_only=False)
        self.assertEqual(result.assigned_tier, 2)
        self.assertIsNone(result.override_applied)

    def test_cvss_zero_critical_severity_tier_from_severity(self) -> None:
        """When cvss_score is 0 and severity is critical, tier 1 from severity, no CVSS override."""
        cluster = _cluster(cvss_score=0.0, severity="critical")
        result = assign_risk_tier(cluster, llm_note=None, is_dev_only=False)
        self.assertEqual(result.assigned_tier, 1)
        self.assertIsNone(result.override_applied)

    def test_risk_tier_assignment_input_with_dev_only(self) -> None:
        inp = RiskTierAssignmentInput(
            vulnerability_id="CVE-X",
            cvss_score=9.5,
            severity="critical",
            llm_priority="critical",
            llm_reasoning="Dev dependency",
            is_dev_only=True,
        )
        result = assign_risk_tier(inp)
        self.assertEqual(result.assigned_tier, 2)
        self.assertEqual(result.override_applied, OVERRIDE_DEV_ONLY_DOWNGRADE)
        self.assertEqual(result.llm_reasoning, "Dev dependency")


class TestAssignRiskTiersBatch(unittest.TestCase):
    """Batch assign_risk_tiers with optional reasoning and dev_only map."""

    def test_batch_without_reasoning_uses_severity(self) -> None:
        clusters = [
            _cluster("CVE-A", severity="critical", cvss_score=5.0),
            _cluster("CVE-B", severity="low", cvss_score=2.0),
        ]
        results = assign_risk_tiers(clusters, reasoning_response=None, cluster_dev_only=None)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].vulnerability_id, "CVE-A")
        self.assertEqual(results[0].assigned_tier, 1)
        self.assertEqual(results[1].vulnerability_id, "CVE-B")
        self.assertEqual(results[1].assigned_tier, 3)

    def test_batch_with_reasoning_and_dev_only_map(self) -> None:
        clusters = [
            _cluster("CVE-HIGH", cvss_score=9.2, severity="critical"),
            _cluster("CVE-DEV", cvss_score=9.3, severity="critical"),
        ]
        reasoning = ReasoningResponse(
            summary="Summary",
            cluster_notes=[
                ClusterNote(vulnerability_id="CVE-HIGH", priority="critical", reasoning="R1"),
                ClusterNote(vulnerability_id="CVE-DEV", priority="critical", reasoning="R2"),
            ],
        )
        dev_only = {"CVE-DEV": True}
        results = assign_risk_tiers(clusters, reasoning_response=reasoning, cluster_dev_only=dev_only)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].assigned_tier, 1)
        self.assertEqual(results[0].override_applied, OVERRIDE_CVSS_HIGH)
        self.assertEqual(results[1].assigned_tier, 2)
        self.assertEqual(results[1].override_applied, OVERRIDE_DEV_ONLY_DOWNGRADE)


class TestAssessTierFromEnrichment(unittest.TestCase):
    """assess_tier_from_enrichment reason strings when CVSS is not present."""

    def test_cvss_zero_returns_rules_based_severity(self) -> None:
        """When cvss_score is 0, reason is 'Rules-based severity.' and does not mention CVSS 0.0."""
        payload = ClusterEnrichmentPayload(
            kev=False,
            epss=None,
            epss_percentile=None,
            epss_display="n/a",
            osv=[],
            fixed_in_versions=[],
            package_ecosystem=None,
            cvss_check=None,
            evidence=[],
        )
        tier, reason = assess_tier_from_enrichment(payload, cvss_score=0.0, severity="high")
        self.assertEqual(tier, 2)
        self.assertEqual(reason, "Rules-based severity.")
        self.assertNotIn("CVSS 0.0", reason)
        self.assertNotIn("0.0", reason)

    def test_cvss_present_high_returns_cvss_band_reason(self) -> None:
        """When cvss_score is 7.5, reason references CVSS band."""
        payload = ClusterEnrichmentPayload(
            kev=False,
            epss=None,
            epss_percentile=None,
            epss_display="n/a",
            osv=[],
            fixed_in_versions=[],
            package_ecosystem=None,
            cvss_check=None,
            evidence=[],
        )
        tier, reason = assess_tier_from_enrichment(payload, cvss_score=7.5, severity="high")
        self.assertEqual(tier, 2)
        self.assertIn("CVSS", reason)

    def test_kev_and_dev_only_returns_tier_2(self) -> None:
        """When KEV is true and is_dev_only is True, assess returns Tier 2."""
        payload = ClusterEnrichmentPayload(
            kev=True,
            epss=None,
            epss_percentile=None,
            epss_display="n/a",
            osv=[],
            fixed_in_versions=[],
            package_ecosystem=None,
            cvss_check=None,
            evidence=["KEV listed"],
        )
        tier, reason = assess_tier_from_enrichment(
            payload, cvss_score=8.0, severity="high", is_dev_only=True
        )
        self.assertEqual(tier, 2)
        self.assertIn("dev-only", reason.lower())


class TestValidateGroundedTierKEV(unittest.TestCase):
    """validate_grounded_tier: KEV forces Tier 1."""

    def test_kev_and_llm_medium_sets_tier_1(self) -> None:
        """When KEV is true and LLM says medium (3), final tier is 1."""
        payload = ClusterEnrichmentPayload(
            kev=True,
            epss=0.5,
            epss_percentile=0.8,
            epss_display="0.50",
            osv=[],
            fixed_in_versions=[],
            package_ecosystem=None,
            cvss_check=None,
            evidence=["KEV listed"],
        )
        final_tier, notes = validate_grounded_tier(
            payload, suggested_tier=3, llm_adjusted_tier="medium"
        )
        self.assertEqual(final_tier, 1)
        self.assertTrue(any("Tier 1" in n for n in notes))

    def test_kev_and_llm_high_sets_tier_1(self) -> None:
        """When KEV is true and LLM says high (2), final tier is 1."""
        payload = ClusterEnrichmentPayload(
            kev=True,
            epss=None,
            epss_percentile=None,
            epss_display="n/a",
            osv=[],
            fixed_in_versions=[],
            package_ecosystem=None,
            cvss_check=None,
            evidence=["KEV listed"],
        )
        final_tier, notes = validate_grounded_tier(
            payload, suggested_tier=2, llm_adjusted_tier="high"
        )
        self.assertEqual(final_tier, 1)

    def test_kev_and_dev_only_sets_tier_2(self) -> None:
        """When KEV is true but is_dev_only is True, final tier is 2."""
        payload = ClusterEnrichmentPayload(
            kev=True,
            epss=0.5,
            epss_percentile=0.8,
            epss_display="0.50",
            osv=[],
            fixed_in_versions=[],
            package_ecosystem=None,
            cvss_check=None,
            evidence=["KEV listed"],
        )
        final_tier, notes = validate_grounded_tier(
            payload, suggested_tier=3, llm_adjusted_tier="medium", is_dev_only=True
        )
        self.assertEqual(final_tier, 2)
        self.assertTrue(
            any("dev-only" in n.lower() for n in notes),
            f"Expected a dev-only note in {notes}",
        )


class TestValidateGroundedTierTier1Evidence(unittest.TestCase):
    """validate_grounded_tier: Tier 1 requires KEV or EPSS >= 0.7 / 90th percentile."""

    def test_tier1_without_kev_epss_below_07_downgrades_to_2(self) -> None:
        """Tier 1 without KEV and EPSS 0.5 (below 0.7), no 90th percentile → downgrade to Tier 2."""
        payload = ClusterEnrichmentPayload(
            kev=False,
            epss=0.5,
            epss_percentile=None,
            epss_display="0.50",
            osv=[],
            fixed_in_versions=[],
            package_ecosystem=None,
            cvss_check=None,
            evidence=[],
        )
        final_tier, notes = validate_grounded_tier(
            payload, suggested_tier=1, llm_adjusted_tier="critical"
        )
        self.assertEqual(final_tier, 2)
        self.assertTrue(
            any("0.7" in n or "90th" in n for n in notes),
            f"Expected Tier 1 evidence message in {notes}",
        )

    def test_tier1_with_epss_075_stays_tier_1(self) -> None:
        """Tier 1 with EPSS 0.75 (no KEV) → stays Tier 1."""
        payload = ClusterEnrichmentPayload(
            kev=False,
            epss=0.75,
            epss_percentile=None,
            epss_display="0.75",
            osv=[],
            fixed_in_versions=[],
            package_ecosystem=None,
            cvss_check=None,
            evidence=[],
        )
        final_tier, notes = validate_grounded_tier(
            payload, suggested_tier=1, llm_adjusted_tier="critical"
        )
        self.assertEqual(final_tier, 1)

    def test_tier1_with_percentile_91_stays_tier_1(self) -> None:
        """Tier 1 with EPSS percentile 0.91 (no KEV) → stays Tier 1."""
        payload = ClusterEnrichmentPayload(
            kev=False,
            epss=None,
            epss_percentile=0.91,
            epss_display="n/a",
            osv=[],
            fixed_in_versions=[],
            package_ecosystem=None,
            cvss_check=None,
            evidence=[],
        )
        final_tier, notes = validate_grounded_tier(
            payload, suggested_tier=1, llm_adjusted_tier="critical"
        )
        self.assertEqual(final_tier, 1)
    """assess_tier_from_enrichment: high EPSS bumps tier by 1 (cap at 1)."""

    def test_high_epss_score_bumps_tier_2_to_1(self) -> None:
        """EPSS >= 0.7 with tier 2 from severity (CVSS below 7) → tier 1."""
        payload = ClusterEnrichmentPayload(
            kev=False,
            epss=0.75,
            epss_percentile=0.85,
            epss_display="0.75",
            osv=[],
            fixed_in_versions=[],
            package_ecosystem=None,
            cvss_check=None,
            evidence=[],
        )
        # CVSS 5 so we get tier 2 from severity, not from EPSS 0.1 + CVSS 7 rule
        tier, reason = assess_tier_from_enrichment(
            payload, cvss_score=5.0, severity="high", is_dev_only=False
        )
        self.assertEqual(tier, 1)
        self.assertIn("High EPSS", reason)

    def test_high_epss_percentile_bumps_tier_3_to_2(self) -> None:
        """EPSS percentile >= 0.9 with low CVSS (tier 3) → tier 2."""
        payload = ClusterEnrichmentPayload(
            kev=False,
            epss=0.2,
            epss_percentile=0.92,
            epss_display="0.20 (92nd percentile)",
            osv=[],
            fixed_in_versions=[],
            package_ecosystem=None,
            cvss_check=None,
            evidence=[],
        )
        tier, reason = assess_tier_from_enrichment(
            payload, cvss_score=5.0, severity="low", is_dev_only=False
        )
        self.assertEqual(tier, 2)
        self.assertIn("High EPSS", reason)

    def test_epss_below_threshold_no_bump(self) -> None:
        """EPSS 0.05 and percentile 0.5 do not trigger tier bump; tier stays 2 from CVSS band."""
        payload = ClusterEnrichmentPayload(
            kev=False,
            epss=0.05,
            epss_percentile=0.5,
            epss_display="0.05",
            osv=[],
            fixed_in_versions=[],
            package_ecosystem=None,
            cvss_check=None,
            evidence=[],
        )
        # CVSS 7 gives tier 2; EPSS 0.05 < 0.7 and percentile 0.5 < 0.9 so no bump
        tier, reason = assess_tier_from_enrichment(
            payload, cvss_score=7.0, severity="high", is_dev_only=False
        )
        self.assertEqual(tier, 2)
        self.assertNotIn("High EPSS", reason)


if __name__ == "__main__":
    unittest.main()
