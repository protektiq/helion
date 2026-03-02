"""Unit tests for app.services.enrichment.client_epss: FIRST EPSS API client."""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from app.services.enrichment.client_epss import clear_epss_cache, fetch_epss


def _mock_settings(
    timeout: float = 15.0,
    debug: bool = False,
    epss_cache_ttl_sec: int = 3600,
):
    settings = unittest.mock.MagicMock()
    settings.ENRICHMENT_REQUEST_TIMEOUT_SEC = timeout
    settings.ENRICHMENT_EPSS_DEBUG = debug
    settings.ENRICHMENT_EPSS_CACHE_TTL_SEC = epss_cache_ttl_sec
    settings.DEBUG = debug
    return settings


def _response_mock(status_code: int, json_body: dict, headers: dict | None = None):
    """Build a sync response mock: .json() returns json_body (no coroutine)."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json = MagicMock(return_value=json_body)
    resp.headers = headers or {}
    return resp


class TestEpssResultStatus(unittest.IsolatedAsyncioTestCase):
    """fetch_epss returns correct EpssResult status and fields."""

    async def asyncSetUp(self) -> None:
        clear_epss_cache()

    @patch("app.services.enrichment.client_epss.httpx.AsyncClient")
    async def test_not_applicable_empty_id(self, mock_client_cls: AsyncMock) -> None:
        settings = _mock_settings()
        result = await fetch_epss("", settings)
        self.assertEqual(result.status, "not_applicable")
        self.assertIsNone(result.score)
        self.assertIsNone(result.percentile)
        mock_client_cls.return_value.__aenter__.assert_not_called()

    @patch("app.services.enrichment.client_epss.httpx.AsyncClient")
    async def test_not_applicable_ghsa_id(self, mock_client_cls: AsyncMock) -> None:
        settings = _mock_settings()
        result = await fetch_epss("GHSA-xxxx-xxxx-xxxx", settings)
        self.assertEqual(result.status, "not_applicable")
        mock_client_cls.return_value.__aenter__.assert_not_called()

    @patch("app.services.enrichment.client_epss.httpx.AsyncClient")
    async def test_ok_with_score_and_percentile(self, mock_client_cls: AsyncMock) -> None:
        settings = _mock_settings()
        json_body = {
            "data": [
                {
                    "cve": "CVE-2021-40438",
                    "epss": "0.94432",
                    "percentile": "0.99985",
                    "date": "2026-03-01",
                }
            ]
        }
        mock_response = _response_mock(200, json_body)
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value.__aenter__.return_value = mock_client

        result = await fetch_epss("CVE-2021-40438", settings)

        self.assertEqual(result.status, "ok")
        self.assertIsNotNone(result.score)
        self.assertAlmostEqual(result.score, 0.94432, places=5)
        self.assertIsNotNone(result.percentile)
        self.assertAlmostEqual(result.percentile, 0.99985, places=5)
        mock_client.get.assert_called_once()
        call_kw = mock_client.get.call_args[1]
        self.assertEqual(call_kw["params"], {"cve": "CVE-2021-40438"})

    @patch("app.services.enrichment.client_epss.httpx.AsyncClient")
    async def test_ok_score_only_no_percentile(self, mock_client_cls: AsyncMock) -> None:
        settings = _mock_settings()
        json_body = {
            "data": [
                {"cve": "CVE-2024-1234", "epss": "0.12", "date": "2026-01-01"}
            ]
        }
        mock_response = _response_mock(200, json_body)
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value.__aenter__.return_value = mock_client

        result = await fetch_epss("CVE-2024-1234", settings)

        self.assertEqual(result.status, "ok")
        self.assertAlmostEqual(result.score, 0.12, places=5)
        self.assertIsNone(result.percentile)

    @patch("app.services.enrichment.client_epss.httpx.AsyncClient")
    async def test_not_found_empty_data(self, mock_client_cls: AsyncMock) -> None:
        settings = _mock_settings()
        mock_response = _response_mock(200, {"data": [], "total": 0})
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value.__aenter__.return_value = mock_client

        result = await fetch_epss("CVE-2099-99999", settings)

        self.assertEqual(result.status, "not_found")
        self.assertIsNone(result.score)
        self.assertIsNone(result.percentile)

    @patch("app.services.enrichment.client_epss.httpx.AsyncClient")
    async def test_not_found_missing_data_key(self, mock_client_cls: AsyncMock) -> None:
        settings = _mock_settings()
        mock_response = _response_mock(200, {"total": 0})
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value.__aenter__.return_value = mock_client

        result = await fetch_epss("CVE-2024-0000", settings)

        self.assertEqual(result.status, "not_found")

    @patch("app.services.enrichment.client_epss.httpx.AsyncClient")
    async def test_unavailable_non_2xx(self, mock_client_cls: AsyncMock) -> None:
        settings = _mock_settings()
        mock_response = _response_mock(500, {})
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value.__aenter__.return_value = mock_client

        result = await fetch_epss("CVE-2024-0001", settings)

        self.assertEqual(result.status, "unavailable")
        self.assertIsNone(result.score)

    @patch("app.services.enrichment.client_epss.httpx.AsyncClient")
    async def test_unavailable_http_error(self, mock_client_cls: AsyncMock) -> None:
        import httpx

        settings = _mock_settings()
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        mock_client_cls.return_value.__aenter__.return_value = mock_client

        result = await fetch_epss("CVE-2024-0001", settings)

        self.assertEqual(result.status, "unavailable")
        self.assertIsNone(result.score)

    @patch("app.services.enrichment.client_epss.httpx.AsyncClient")
    async def test_cve_normalized_to_uppercase(self, mock_client_cls: AsyncMock) -> None:
        json_body = {
            "data": [{"cve": "CVE-2024-1234", "epss": "0.5", "date": "2026-01-01"}]
        }
        mock_response = _response_mock(200, json_body)
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value.__aenter__.return_value = mock_client

        await fetch_epss("cve-2024-1234", _mock_settings())

        call_args = mock_client.get.call_args
        self.assertEqual(call_args[1]["params"]["cve"], "CVE-2024-1234")


class TestEpssCache(unittest.IsolatedAsyncioTestCase):
    """EPSS in-memory cache and clear_epss_cache."""

    async def asyncSetUp(self) -> None:
        clear_epss_cache()

    @patch("app.services.enrichment.client_epss.httpx.AsyncClient")
    async def test_cache_hit_second_call_no_http(self, mock_client_cls: AsyncMock) -> None:
        settings = _mock_settings(epss_cache_ttl_sec=3600)
        json_body = {
            "data": [{"cve": "CVE-2024-1111", "epss": "0.5", "date": "2026-01-01"}]
        }
        mock_response = _response_mock(200, json_body)
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value.__aenter__.return_value = mock_client

        result1 = await fetch_epss("CVE-2024-1111", settings)
        result2 = await fetch_epss("CVE-2024-1111", settings)

        self.assertEqual(result1.status, "ok")
        self.assertEqual(result2.status, "ok")
        self.assertEqual(result1.score, result2.score)
        self.assertEqual(mock_client.get.call_count, 1)

    @patch("app.services.enrichment.client_epss.httpx.AsyncClient")
    async def test_cache_miss_when_ttl_zero(self, mock_client_cls: AsyncMock) -> None:
        settings = _mock_settings(epss_cache_ttl_sec=0)
        json_body = {
            "data": [{"cve": "CVE-2024-2222", "epss": "0.3", "date": "2026-01-01"}]
        }
        mock_response = _response_mock(200, json_body)
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value.__aenter__.return_value = mock_client

        await fetch_epss("CVE-2024-2222", settings)
        await fetch_epss("CVE-2024-2222", settings)

        self.assertEqual(mock_client.get.call_count, 2)

    @patch("app.services.enrichment.client_epss.httpx.AsyncClient")
    async def test_clear_epss_cache_forces_new_request(self, mock_client_cls: AsyncMock) -> None:
        settings = _mock_settings(epss_cache_ttl_sec=3600)
        json_body = {
            "data": [{"cve": "CVE-2024-3333", "epss": "0.2", "date": "2026-01-01"}]
        }
        mock_response = _response_mock(200, json_body)
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value.__aenter__.return_value = mock_client

        await fetch_epss("CVE-2024-3333", settings)
        clear_epss_cache()
        await fetch_epss("CVE-2024-3333", settings)

        self.assertEqual(mock_client.get.call_count, 2)


class TestEpss429Retry(unittest.IsolatedAsyncioTestCase):
    """429 rate limit handling with retry and backoff."""

    async def asyncSetUp(self) -> None:
        clear_epss_cache()

    @patch("app.services.enrichment.client_epss.asyncio.sleep", new_callable=AsyncMock)
    @patch("app.services.enrichment.client_epss.httpx.AsyncClient")
    async def test_429_then_200_returns_ok(
        self, mock_client_cls: AsyncMock, mock_sleep: AsyncMock
    ) -> None:
        settings = _mock_settings()
        json_ok = {
            "data": [{"cve": "CVE-2024-4444", "epss": "0.1", "date": "2026-01-01"}]
        }
        resp_429 = _response_mock(429, {}, headers={"Retry-After": "1"})
        resp_200 = _response_mock(200, json_ok)
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[resp_429, resp_200])
        mock_client_cls.return_value.__aenter__.return_value = mock_client

        result = await fetch_epss("CVE-2024-4444", settings)

        self.assertEqual(result.status, "ok")
        self.assertAlmostEqual(result.score, 0.1, places=5)
        mock_sleep.assert_called_once()
        self.assertEqual(mock_client.get.call_count, 2)

    @patch("app.services.enrichment.client_epss.asyncio.sleep", new_callable=AsyncMock)
    @patch("app.services.enrichment.client_epss.httpx.AsyncClient")
    async def test_429_then_429_returns_unavailable_rate_limited(
        self, mock_client_cls: AsyncMock, mock_sleep: AsyncMock
    ) -> None:
        settings = _mock_settings()
        resp_429 = _response_mock(429, {}, headers={"Retry-After": "1"})
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp_429)
        mock_client_cls.return_value.__aenter__.return_value = mock_client

        result = await fetch_epss("CVE-2024-5555", settings)

        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.reason, "rate limited")
        mock_sleep.assert_called_once()
        self.assertEqual(mock_client.get.call_count, 2)


class TestEpssCveValidation(unittest.IsolatedAsyncioTestCase):
    """Response CVE must match requested CVE."""

    async def asyncSetUp(self) -> None:
        clear_epss_cache()

    @patch("app.services.enrichment.client_epss.httpx.AsyncClient")
    async def test_cve_mismatch_returns_not_found(self, mock_client_cls: AsyncMock) -> None:
        settings = _mock_settings()
        json_body = {
            "data": [
                {"cve": "CVE-OTHER-123", "epss": "0.5", "date": "2026-01-01"}
            ]
        }
        mock_response = _response_mock(200, json_body)
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value.__aenter__.return_value = mock_client

        result = await fetch_epss("CVE-2024-1234", settings)

        self.assertEqual(result.status, "not_found")
        self.assertIsNone(result.score)
