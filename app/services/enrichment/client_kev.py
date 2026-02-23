"""CISA KEV catalog client: fetch feed and check if a CVE is known exploited."""

import logging
import time
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from app.core.config import Settings

logger = logging.getLogger(__name__)

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# In-memory cache: (cve_id_set, fetched_at). cve_id_set is frozenset for fast lookup.
_kev_cache: tuple[frozenset[str], float] | None = None


def _parse_kev_response(data: dict) -> frozenset[str]:
    """Extract set of CVE IDs from KEV feed JSON. Validates and bounds input."""
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list):
        return frozenset()
    out: set[str] = set()
    max_entries = 50_000  # sanity limit
    for i, item in enumerate(vulns):
        if i >= max_entries:
            break
        if not isinstance(item, dict):
            continue
        cve_id = item.get("cveID")
        if isinstance(cve_id, str) and cve_id.strip() and len(cve_id) <= 64:
            out.add(cve_id.strip())
    return frozenset(out)


async def _fetch_kev_feed(settings: "Settings") -> frozenset[str]:
    """Fetch KEV JSON and return set of CVE IDs. Raises on network/parse errors."""
    timeout = httpx.Timeout(settings.ENRICHMENT_REQUEST_TIMEOUT_SEC)
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.get(KEV_FEED_URL)
        response.raise_for_status()
        data = response.json()
    if not isinstance(data, dict):
        raise ValueError("KEV feed root is not a JSON object")
    return _parse_kev_response(data)


async def get_kev_cve_set(settings: "Settings") -> frozenset[str]:
    """
    Return the set of CVE IDs in the KEV catalog. Uses in-memory cache with TTL.
    """
    global _kev_cache
    now = time.monotonic()
    ttl = float(settings.ENRICHMENT_KEV_CACHE_TTL_SEC)
    if _kev_cache is not None:
        _, cached_at = _kev_cache
        if (now - cached_at) < ttl:
            return _kev_cache[0]
    try:
        cve_set = await _fetch_kev_feed(settings)
        _kev_cache = (cve_set, now)
        return cve_set
    except Exception as e:
        logger.warning("KEV feed fetch failed: %s", e, exc_info=False)
        if _kev_cache is not None:
            return _kev_cache[0]
        return frozenset()


async def is_in_kev(cve_id: str, settings: "Settings") -> bool:
    """
    Return True if the given CVE ID is in the CISA KEV catalog.
    cve_id should be normalized (e.g. CVE-2024-3400). Empty/None returns False.
    """
    if not cve_id or not cve_id.strip():
        return False
    normalized = cve_id.strip()
    return normalized in await get_kev_cve_set(settings)


def clear_kev_cache() -> None:
    """Clear the in-memory KEV cache (e.g. for tests)."""
    global _kev_cache
    _kev_cache = None
