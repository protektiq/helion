"""FIRST EPSS API client: fetch exploit probability for a CVE."""

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

import httpx

if TYPE_CHECKING:
    from app.core.config import Settings

logger = logging.getLogger(__name__)

EPSS_BASE_URL = "https://api.first.org/data/v1/epss"

# Max wait for 429 backoff (seconds).
_RETRY_AFTER_CAP_SEC = 300
_DEFAULT_429_BACKOFF_SEC = 60

EpssStatus = Literal["ok", "not_applicable", "not_found", "unavailable"]


@dataclass(frozen=True)
class EpssResult:
    """Structured result from EPSS lookup."""

    status: EpssStatus
    score: float | None = None
    percentile: float | None = None
    reason: str | None = None


# In-memory cache: cve_id -> (EpssResult, cached_at monotonic). Only successful lookups cached.
_epss_cache: dict[str, tuple[EpssResult, float]] = {}


def _epss_debug(settings: "Settings") -> bool:
    """True when EPSS debug logging is enabled (env or DEBUG)."""
    if getattr(settings, "ENRICHMENT_EPSS_DEBUG", False):
        return True
    return getattr(settings, "DEBUG", False)


def _parse_retry_after(response: httpx.Response) -> float:
    """Parse Retry-After header; return seconds to wait (capped)."""
    value = response.headers.get("Retry-After")
    if value is None or not value.strip():
        return _DEFAULT_429_BACKOFF_SEC
    stripped = value.strip()
    try:
        sec = int(stripped)
        return min(max(sec, 0), _RETRY_AFTER_CAP_SEC)
    except ValueError:
        return _DEFAULT_429_BACKOFF_SEC


def _parse_epss_response(data: dict, cve_id: str, debug: bool) -> EpssResult | None:
    """
    Parse FIRST API JSON into EpssResult. Returns None if response shape is invalid.
    Validates that the first entry's 'cve' matches cve_id.
    """
    if not isinstance(data, dict):
        if debug:
            logger.debug("EPSS response root is not dict: type=%s", type(data).__name__)
        return None
    entries = data.get("data")
    if not isinstance(entries, list):
        if debug:
            logger.debug(
                "EPSS data missing or not list: has_data=%s",
                "data" in data,
            )
        return None
    if not entries:
        if debug:
            logger.debug("EPSS data empty (no EPSS record for CVE)")
        return EpssResult(status="not_found")
    first = entries[0]
    if not isinstance(first, dict):
        if debug:
            logger.debug("EPSS data[0] is not dict: type=%s", type(first).__name__)
        return EpssResult(status="not_found")
    # Validate returned CVE matches requested (avoid misattribution).
    if first.get("cve") != cve_id:
        if debug:
            logger.debug(
                "EPSS data[0] CVE mismatch: requested=%s got=%s",
                cve_id,
                first.get("cve"),
            )
        return EpssResult(status="not_found")
    epss_str = first.get("epss")
    percentile_str = first.get("percentile")
    if epss_str is None:
        if debug:
            logger.debug("EPSS data[0] missing 'epss' key")
        return EpssResult(status="not_found")
    try:
        score = float(epss_str)
    except (TypeError, ValueError):
        if debug:
            logger.debug("EPSS epss value not float: %r", epss_str)
        return EpssResult(status="not_found")
    if not (0 <= score <= 1):
        if debug:
            logger.debug("EPSS score out of range [0,1]: %s", score)
        return EpssResult(status="not_found")
    percentile_val: float | None = None
    if percentile_str is not None:
        try:
            p = float(percentile_str)
            if 0 <= p <= 1:
                percentile_val = round(p, 6)
        except (TypeError, ValueError):
            pass
    if debug:
        logger.debug(
            "EPSS parsed: cve=%s score=%s percentile=%s",
            cve_id,
            score,
            percentile_val,
        )
    return EpssResult(
        status="ok",
        score=round(score, 6),
        percentile=percentile_val,
    )


def clear_epss_cache() -> None:
    """Clear the in-memory EPSS cache (e.g. for tests)."""
    global _epss_cache
    _epss_cache = {}


async def fetch_epss(cve_id: str, settings: "Settings") -> EpssResult:
    """
    Fetch EPSS score and percentile for the given CVE. Returns a structured result
    with status: ok | not_applicable | not_found | unavailable.
    Only CVE-like IDs are queried; others return not_applicable.
    Uses in-memory cache with TTL for successful lookups; on 429 retries once after backoff.
    """
    if not cve_id or not cve_id.strip():
        return EpssResult(status="not_applicable")
    cve_id = cve_id.strip()
    if not cve_id.upper().startswith("CVE-"):
        return EpssResult(status="not_applicable")
    if len(cve_id) > 64:
        return EpssResult(status="not_applicable")
    cve_id = cve_id.upper()
    timeout = httpx.Timeout(settings.ENRICHMENT_REQUEST_TIMEOUT_SEC)
    debug = _epss_debug(settings)
    ttl = float(getattr(settings, "ENRICHMENT_EPSS_CACHE_TTL_SEC", 3600))

    # Cache lookup (only successful results are cached).
    now = time.monotonic()
    if ttl > 0 and cve_id in _epss_cache:
        cached_result, cached_at = _epss_cache[cve_id]
        if (now - cached_at) < ttl:
            if debug:
                logger.debug("EPSS cache hit: cve=%s", cve_id)
            return cached_result

    if debug:
        logger.debug("EPSS request: cve=%s", cve_id)

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                EPSS_BASE_URL,
                params={"cve": cve_id},
            )
    except (httpx.HTTPError, ValueError) as e:
        logger.error(
            "EPSS lookup failed for %s: %s",
            cve_id,
            e,
            exc_info=False,
        )
        if debug:
            logger.debug("EPSS exception type=%s", type(e).__name__)
        return EpssResult(status="unavailable")

    status_code = response.status_code
    if debug:
        logger.debug("EPSS response: cve=%s status=%s", cve_id, status_code)

    # 429: one retry after backoff.
    if status_code == 429:
        backoff = _parse_retry_after(response)
        logger.warning(
            "EPSS rate limited for %s; Retry-After=%ss, retrying once after backoff",
            cve_id,
            backoff,
        )
        await asyncio.sleep(backoff)
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(
                    EPSS_BASE_URL,
                    params={"cve": cve_id},
                )
        except (httpx.HTTPError, ValueError) as e:
            logger.warning("EPSS retry failed for %s: %s", cve_id, e)
            return EpssResult(status="unavailable", reason="rate limited")
        if response.status_code == 429 or response.status_code < 200 or response.status_code >= 300:
            logger.warning(
                "EPSS retry still rate limited or error for %s: status=%s",
                cve_id,
                response.status_code,
            )
            return EpssResult(status="unavailable", reason="rate limited")
        status_code = response.status_code

    if status_code < 200 or status_code >= 300:
        logger.error(
            "EPSS API returned non-2xx for %s: status=%s",
            cve_id,
            status_code,
        )
        return EpssResult(status="unavailable")

    try:
        data = response.json()
    except ValueError as e:
        logger.error(
            "EPSS response not valid JSON for %s: %s",
            cve_id,
            e,
        )
        return EpssResult(status="unavailable")

    parsed = _parse_epss_response(data, cve_id, debug)
    if parsed is None:
        return EpssResult(status="not_found")
    if parsed.status == "not_found":
        return parsed
    # status == "ok"
    if ttl > 0:
        _epss_cache[cve_id] = (parsed, time.monotonic())
    return parsed
