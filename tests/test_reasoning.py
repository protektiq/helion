"""Unit tests for reasoning service: JSON extraction and validation contract."""

import json
import unittest

from app.schemas.findings import VulnerabilityCluster
from app.schemas.reasoning import ReasoningResponse
from app.services.reasoning import _extract_json_object, _normalize_reasoning_output


# Minimal valid ReasoningResponse-shaped object for validation tests
_MINIMAL_VALID = {"summary": "x", "cluster_notes": []}
_MINIMAL_VALID_STR = '{"summary": "x", "cluster_notes": []}'


def _cluster(
    vulnerability_id: str = "CVE-1",
    severity: str = "high",
    repo: str = "repo",
    cvss_score: float = 7.0,
    description: str = "Desc",
) -> VulnerabilityCluster:
    """Minimal VulnerabilityCluster for normalization tests."""
    return VulnerabilityCluster(
        vulnerability_id=vulnerability_id,
        severity=severity,
        repo=repo,
        cvss_score=cvss_score,
        description=description,
        file_path="",
        dependency="",
        finding_ids=["1"],
        affected_services_count=1,
        finding_count=1,
    )


class TestExtractJsonObject(unittest.TestCase):
    """_extract_json_object tolerates wrapping text; validation into ReasoningResponse stays strict."""

    def test_raw_json_unchanged(self) -> None:
        """Raw JSON string with no markdown is passed through; first { to last } only."""
        raw = '{"summary": "Test.", "cluster_notes": [{"vulnerability_id": "CVE-1", "priority": "high", "reasoning": "Fix."}]}'
        out = _extract_json_object(raw)
        self.assertEqual(out, raw)
        parsed = json.loads(out)
        resp = ReasoningResponse.model_validate(parsed)
        self.assertEqual(resp.summary, "Test.")
        self.assertEqual(len(resp.cluster_notes), 1)
        self.assertEqual(resp.cluster_notes[0].vulnerability_id, "CVE-1")

    def test_wrapped_in_json_code_fence(self) -> None:
        """Content wrapped in ```json ... ``` is extracted and still validates."""
        wrapped = (
            "Here is the result:\n\n"
            "```json\n"
            f"{_MINIMAL_VALID_STR}\n"
            "```\n"
            "Done."
        )
        out = _extract_json_object(wrapped)
        self.assertEqual(out, _MINIMAL_VALID_STR)
        parsed = json.loads(out)
        resp = ReasoningResponse.model_validate(parsed)
        self.assertEqual(resp.summary, "x")
        self.assertEqual(resp.cluster_notes, [])

    def test_wrapped_plain_fence(self) -> None:
        """Content wrapped in plain ``` ... ``` (no language tag) is extracted."""
        wrapped = (
            "```\n"
            f"{_MINIMAL_VALID_STR}\n"
            "```"
        )
        out = _extract_json_object(wrapped)
        self.assertEqual(out, _MINIMAL_VALID_STR)
        parsed = json.loads(out)
        ReasoningResponse.model_validate(parsed)

    def test_leading_trailing_whitespace_and_fence(self) -> None:
        """Outer whitespace and single code block with language tag are handled."""
        wrapped = (
            "  \n  Some text\n\n  ```JSON\n  "
            f"{_MINIMAL_VALID_STR}\n  "
            "  ```  \n  Done.  "
        )
        out = _extract_json_object(wrapped)
        self.assertEqual(out, _MINIMAL_VALID_STR)
        parsed = json.loads(out)
        ReasoningResponse.model_validate(parsed)

    def test_schema_unchanged_validation_strict(self) -> None:
        """Extracted JSON must still match ReasoningResponse exactly; no loosening."""
        # Valid shape validates
        out = _extract_json_object(_MINIMAL_VALID_STR)
        parsed = json.loads(out)
        ReasoningResponse.model_validate(parsed)

        # Invalid shape (missing required keys) still raises after extraction
        invalid_str = '{"summary": "x"}'
        out_invalid = _extract_json_object(invalid_str)
        self.assertEqual(out_invalid, invalid_str)
        parsed_invalid = json.loads(out_invalid)
        with self.assertRaises(Exception):
            ReasoningResponse.model_validate(parsed_invalid)


class TestNormalizeReasoningOutput(unittest.TestCase):
    """_normalize_reasoning_output maps alternate keys and enforces schema; model_validate succeeds."""

    def test_notes_and_overall_summary_mapped_to_cluster_notes_and_summary(self) -> None:
        """notes -> cluster_notes, overall_summary -> summary."""
        clusters = [_cluster("CVE-1")]
        parsed = {
            "overall_summary": "Overall.",
            "notes": [
                {"vulnerability_id": "CVE-1", "priority": "high", "reasoning": "Fix it."},
            ],
        }
        normalized = _normalize_reasoning_output(parsed, clusters)
        resp = ReasoningResponse.model_validate(normalized)
        self.assertEqual(resp.summary, "Overall.")
        self.assertEqual(len(resp.cluster_notes), 1)
        self.assertEqual(resp.cluster_notes[0].vulnerability_id, "CVE-1")
        self.assertEqual(resp.cluster_notes[0].reasoning, "Fix it.")

    def test_clusters_used_when_cluster_notes_and_notes_missing(self) -> None:
        """clusters used when cluster_notes and notes are missing."""
        clusters = [_cluster("CVE-A")]
        parsed = {
            "summary": "Ok.",
            "clusters": [
                {"vulnerability_id": "CVE-A", "priority": "low", "reasoning": "Upgrade."},
            ],
        }
        normalized = _normalize_reasoning_output(parsed, clusters)
        resp = ReasoningResponse.model_validate(normalized)
        self.assertEqual(resp.summary, "Ok.")
        self.assertEqual(len(resp.cluster_notes), 1)
        self.assertEqual(resp.cluster_notes[0].vulnerability_id, "CVE-A")

    def test_per_note_id_remediation_severity_mapped(self) -> None:
        """Per-note: id -> vulnerability_id, remediation -> reasoning, severity -> priority."""
        clusters = [_cluster("CVE-X")]
        parsed = {
            "summary": "S",
            "cluster_notes": [
                {
                    "id": "CVE-X",
                    "severity": "critical",
                    "remediation": "Apply patch.",
                },
            ],
        }
        normalized = _normalize_reasoning_output(parsed, clusters)
        resp = ReasoningResponse.model_validate(normalized)
        self.assertEqual(len(resp.cluster_notes), 1)
        self.assertEqual(resp.cluster_notes[0].vulnerability_id, "CVE-X")
        self.assertEqual(resp.cluster_notes[0].priority, "critical")
        self.assertEqual(resp.cluster_notes[0].reasoning, "Apply patch.")

    def test_per_note_recommendation_fallback_for_reasoning(self) -> None:
        """reasoning taken from recommendation when remediation missing."""
        clusters = [_cluster("CVE-Y")]
        parsed = {
            "summary": "S",
            "cluster_notes": [
                {
                    "vulnerability_id": "CVE-Y",
                    "priority": "medium",
                    "recommendation": "Upgrade dependency.",
                },
            ],
        }
        normalized = _normalize_reasoning_output(parsed, clusters)
        resp = ReasoningResponse.model_validate(normalized)
        self.assertEqual(resp.cluster_notes[0].reasoning, "Upgrade dependency.")

    def test_priority_crit_mapped_to_critical(self) -> None:
        """Priority alias 'crit' -> 'critical'."""
        clusters = [_cluster("CVE-1")]
        parsed = {
            "summary": "S",
            "cluster_notes": [
                {"vulnerability_id": "CVE-1", "priority": "crit", "reasoning": "R"},
            ],
        }
        normalized = _normalize_reasoning_output(parsed, clusters)
        resp = ReasoningResponse.model_validate(normalized)
        self.assertEqual(resp.cluster_notes[0].priority, "critical")

    def test_priority_uppercase_mapped_to_lowercase(self) -> None:
        """Priority 'HIGH' -> 'high'."""
        clusters = [_cluster("CVE-1")]
        parsed = {
            "summary": "S",
            "cluster_notes": [
                {"vulnerability_id": "CVE-1", "priority": "HIGH", "reasoning": "R"},
            ],
        }
        normalized = _normalize_reasoning_output(parsed, clusters)
        resp = ReasoningResponse.model_validate(normalized)
        self.assertEqual(resp.cluster_notes[0].priority, "high")

    def test_priority_invalid_defaults_to_medium(self) -> None:
        """Invalid priority -> 'medium'."""
        clusters = [_cluster("CVE-1")]
        parsed = {
            "summary": "S",
            "cluster_notes": [
                {"vulnerability_id": "CVE-1", "priority": "unknown", "reasoning": "R"},
            ],
        }
        normalized = _normalize_reasoning_output(parsed, clusters)
        resp = ReasoningResponse.model_validate(normalized)
        self.assertEqual(resp.cluster_notes[0].priority, "medium")

    def test_notes_with_vulnerability_id_not_in_clusters_filtered_out(self) -> None:
        """Notes whose vulnerability_id is not in clusters are removed."""
        clusters = [_cluster("CVE-ALLOWED")]
        parsed = {
            "summary": "S",
            "cluster_notes": [
                {"vulnerability_id": "CVE-ALLOWED", "priority": "high", "reasoning": "Keep."},
                {"vulnerability_id": "CVE-HALLUCINATED", "priority": "high", "reasoning": "Drop."},
            ],
        }
        normalized = _normalize_reasoning_output(parsed, clusters)
        resp = ReasoningResponse.model_validate(normalized)
        self.assertEqual(len(resp.cluster_notes), 1)
        self.assertEqual(resp.cluster_notes[0].vulnerability_id, "CVE-ALLOWED")

    def test_cluster_notes_non_list_becomes_empty_list(self) -> None:
        """cluster_notes non-list -> []."""
        clusters = [_cluster("CVE-1")]
        parsed = {"summary": "Ok.", "cluster_notes": "not a list"}
        normalized = _normalize_reasoning_output(parsed, clusters)
        resp = ReasoningResponse.model_validate(normalized)
        self.assertEqual(resp.cluster_notes, [])
        self.assertEqual(resp.summary, "Ok.")

    def test_summary_non_string_becomes_fallback(self) -> None:
        """summary non-string -> string or fallback."""
        clusters = []
        parsed = {"summary": 123, "cluster_notes": []}
        normalized = _normalize_reasoning_output(parsed, clusters)
        resp = ReasoningResponse.model_validate(normalized)
        self.assertEqual(resp.summary, "123")

    def test_summary_missing_and_overall_summary_missing_uses_fallback(self) -> None:
        """Missing summary and overall_summary -> 'No summary provided.'."""
        clusters = []
        parsed = {"cluster_notes": []}
        normalized = _normalize_reasoning_output(parsed, clusters)
        resp = ReasoningResponse.model_validate(normalized)
        self.assertEqual(resp.summary, "No summary provided.")

    def test_non_dict_items_in_cluster_notes_skipped(self) -> None:
        """Non-dict items in cluster_notes are skipped."""
        clusters = [_cluster("CVE-1")]
        parsed = {
            "summary": "S",
            "cluster_notes": [
                {"vulnerability_id": "CVE-1", "priority": "high", "reasoning": "Keep."},
                "invalid",
                None,
                [],
            ],
        }
        normalized = _normalize_reasoning_output(parsed, clusters)
        resp = ReasoningResponse.model_validate(normalized)
        self.assertEqual(len(resp.cluster_notes), 1)
        self.assertEqual(resp.cluster_notes[0].vulnerability_id, "CVE-1")
