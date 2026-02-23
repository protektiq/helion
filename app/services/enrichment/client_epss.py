"""FIRST EPSS API client: fetch exploit probability for a CVE."""

import logging
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from app.core.config import Settings

logger = logging.getLogger(__name__)

EPSS_BASE_URL = "https://api.first.org/data/v1/epss"


async def fetch_epss(cve_id: str, settings: "Settings") -> float | None:
    """
    Fetch EPSS score (0-1) for the given CVE. Returns None if not found or on error.
    Only CVE-like IDs are queried; others return None.
    """
    if not cve_id or not cve_id.strip():
        return None
    cve_id = cve_id.strip()
    # FIRST API expects CVE id; avoid sending non-CVE identifiers
    if not cve_id.upper().startswith("CVE-"):
        return None
    if len(cve_id) > 64:
        return None
    url = f"{EPSS_BASE_URL}?cve={cve_id}"
    timeout = httpx.Timeout(settings.ENRICHMENT_REQUEST_TIMEOUT_SEC)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
    except (httpx.HTTPError, ValueError) as e:
        logger.debug("EPSS fetch failed for %s: %s", cve_id, e)
        return None
    if not isinstance(data, dict):
        return None
    entries = data.get("data")
    if not isinstance(entries, list) or not entries:
        return None
    first = entries[0]
    if not isinstance(first, dict):
        return None
    epss_str = first.get("epss")
    if epss_str is None:
        return None
    try:
        score = float(epss_str)
    except (TypeError, ValueError):
        return None
    if not (0 <= score <= 1):
        return None
    return round(score, 6)
