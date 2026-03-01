"""Unit tests for SARIF parsing: sarif_to_rawfindings and raw_payload shape."""

import unittest

from app.services.sarif_parser import sarif_to_rawfindings


def _minimal_sarif_run(
    rule_id: str = "test-rule",
    result_kind: str | None = "fail",
    rule_help_uri: str | None = "https://example.com/rule-help",
) -> dict:
    """Build a minimal SARIF run with one result and one rule."""
    rule: dict = {"id": rule_id, "name": "Test rule"}
    if rule_help_uri is not None:
        rule["helpUri"] = rule_help_uri
    return {
        "tool": {
            "driver": {
                "name": "test-tool",
                "rules": [rule],
            }
        },
        "results": [
            {
                "ruleId": rule_id,
                "kind": result_kind,
                "level": "error",
                "message": {"text": "Something failed."},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "file:///src/main.py"},
                        }
                    }
                ],
            }
        ],
    }


class TestSarifToRawfindings(unittest.TestCase):
    """sarif_to_rawfindings produces RawFinding-shaped dicts with explicit raw_payload."""

    def test_empty_payload(self) -> None:
        out = sarif_to_rawfindings({})
        self.assertEqual(out, [])

    def test_no_runs(self) -> None:
        out = sarif_to_rawfindings({"version": "2.1.0", "runs": []})
        self.assertEqual(out, [])

    def test_result_kind_and_rule_help_uri_in_raw_payload(self) -> None:
        """raw_payload explicitly contains _sarif_result.kind and rule_helpUri."""
        payload = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [_minimal_sarif_run(result_kind="fail", rule_help_uri="https://codeql.com/rule")],
        }
        out = sarif_to_rawfindings(payload)
        self.assertEqual(len(out), 1)
        raw = out[0]["raw_payload"]
        self.assertIn("_sarif_result", raw)
        self.assertEqual(raw["_sarif_result"]["kind"], "fail")
        self.assertEqual(raw["rule_helpUri"], "https://codeql.com/rule")

    def test_result_kind_absent_defaults_to_none(self) -> None:
        """When result has no kind, _sarif_result.kind is None."""
        run = _minimal_sarif_run(result_kind=None, rule_help_uri="https://a.b/c")
        run["results"][0].pop("kind", None)
        payload = {"version": "2.1.0", "runs": [run]}
        out = sarif_to_rawfindings(payload)
        self.assertEqual(len(out), 1)
        self.assertIsNone(out[0]["raw_payload"]["_sarif_result"]["kind"])

    def test_rule_help_uri_absent_defaults_to_none(self) -> None:
        """When rule has no helpUri, rule_helpUri is None."""
        run = _minimal_sarif_run(rule_help_uri=None)
        payload = {"version": "2.1.0", "runs": [run]}
        out = sarif_to_rawfindings(payload)
        self.assertEqual(len(out), 1)
        self.assertIsNone(out[0]["raw_payload"]["rule_helpUri"])
