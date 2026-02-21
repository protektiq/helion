"""Determinism check: request payload to Ollama includes configured options (no network for unit tests)."""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from app.core.config import get_settings
from app.schemas.findings import VulnerabilityCluster
from app.services.exploitability import run_exploitability_reasoning
from app.services.reasoning import run_reasoning


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


def _ollama_reachable() -> bool:
    """Return True if OLLAMA_BASE_URL is reachable (for optional integration test skip)."""
    settings = get_settings()
    try:
        with httpx.Client(timeout=2.0) as client:
            # Ollama often exposes a simple endpoint; GET / may return 200 or 404
            resp = client.get(settings.OLLAMA_BASE_URL.rstrip("/") + "/")
            return resp.status_code in (200, 404)
    except (httpx.ConnectError, httpx.TimeoutException):
        return False


# Fixed Ollama response bodies so the service parses without error (no real Ollama needed).
REASONING_MOCK_RESPONSE = {
    "response": '{"summary": "Test.", "cluster_notes": [{"vulnerability_id": "CVE-2024-0001", "priority": "high", "reasoning": "Test."}]}',
}
EXPLOITABILITY_MOCK_RESPONSE = {
    "response": '{"adjusted_risk_tier": "high", "reasoning": "Test.", "recommended_action": "Patch."}',
}


class TestReasoningDeterminismOptions(unittest.TestCase):
    """Request payload for run_reasoning includes options with configured defaults."""

    @patch("app.services.reasoning.httpx.AsyncClient")
    def test_payload_includes_deterministic_options(self, mock_client_class: MagicMock) -> None:
        captured: dict[str, object] = {}

        async def fake_post(url: str, **kwargs: object) -> MagicMock:
            payload = kwargs.get("json")
            if isinstance(payload, dict):
                captured["payload"] = payload
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = REASONING_MOCK_RESPONSE
            return resp

        mock_instance = MagicMock()
        mock_instance.post = AsyncMock(side_effect=fake_post)
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

        settings = get_settings()
        cluster = _cluster()
        asyncio.run(run_reasoning([cluster], settings))

        self.assertIn("payload", captured)
        payload = captured["payload"]
        self.assertIsInstance(payload, dict)
        self.assertIn("options", payload)
        options = payload["options"]
        self.assertEqual(
            options,
            {
                "temperature": settings.OLLAMA_TEMPERATURE,
                "top_p": settings.OLLAMA_TOP_P,
                "repeat_penalty": settings.OLLAMA_REPEAT_PENALTY,
                "seed": settings.OLLAMA_SEED,
            },
        )
        self.assertFalse(payload.get("stream"))
        self.assertEqual(payload.get("format"), "json")


class TestExploitabilityDeterminismOptions(unittest.TestCase):
    """Request payload for run_exploitability_reasoning includes options with configured defaults."""

    @patch("app.services.exploitability.httpx.AsyncClient")
    def test_payload_includes_deterministic_options(self, mock_client_class: MagicMock) -> None:
        captured: dict[str, object] = {}

        async def fake_post(url: str, **kwargs: object) -> MagicMock:
            payload = kwargs.get("json")
            if isinstance(payload, dict):
                captured["payload"] = payload
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = EXPLOITABILITY_MOCK_RESPONSE
            return resp

        mock_instance = MagicMock()
        mock_instance.post = AsyncMock(side_effect=fake_post)
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

        settings = get_settings()
        asyncio.run(
            run_exploitability_reasoning(
                vulnerability_summary="Test vuln",
                cvss_score=7.0,
                repo_context="test-repo",
                dependency_type="npm",
                exposure_flags="none",
                settings=settings,
            )
        )

        self.assertIn("payload", captured)
        payload = captured["payload"]
        self.assertIsInstance(payload, dict)
        self.assertIn("options", payload)
        options = payload["options"]
        self.assertEqual(
            options,
            {
                "temperature": settings.OLLAMA_TEMPERATURE,
                "top_p": settings.OLLAMA_TOP_P,
                "repeat_penalty": settings.OLLAMA_REPEAT_PENALTY,
                "seed": settings.OLLAMA_SEED,
            },
        )
        self.assertFalse(payload.get("stream"))
        self.assertEqual(payload.get("format"), "json")


class TestReasoningIntegration(unittest.TestCase):
    """Optional integration test: real run_reasoning when Ollama is reachable."""

    @unittest.skipIf(not _ollama_reachable(), "OLLAMA not reachable")
    def test_run_reasoning_returns_structured_response(self) -> None:
        settings = get_settings()
        cluster = _cluster()
        result = asyncio.run(run_reasoning([cluster], settings))
        self.assertIsNotNone(result.summary)
        self.assertIsInstance(result.cluster_notes, list)
        self.assertEqual(len(result.cluster_notes), 1)
        self.assertEqual(result.cluster_notes[0].vulnerability_id, cluster.vulnerability_id)
