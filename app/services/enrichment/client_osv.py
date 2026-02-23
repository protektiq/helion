"""OSV API client: query by package+version or fetch vuln by GHSA ID."""

import logging
import re
from typing import TYPE_CHECKING, Any

import httpx

from app.services.enrichment.schemas import OsvEntry

if TYPE_CHECKING:
    from app.core.config import Settings

logger = logging.getLogger(__name__)

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_VULNS_URL = "https://api.osv.dev/v1/vulns"

# Dependency parsing: common patterns for name@version (npm), name==version (pypi), etc.
# We only need a best-effort parse to choose ecosystem and call OSV.
_AT_VERSION = re.compile(r"^(.+?)@([^\s@]+)$")  # name@version
_EQ_VERSION = re.compile(r"^(.+?)==([^\s=]+)$")  # name==version (pypi)
_COLON_VERSION = re.compile(r"^(.+?):([^\s:]+)$")  # name:version (maven-like)


def _parse_dependency(dependency: str) -> tuple[str | None, str | None, str | None]:
    """
    Parse dependency string into (package_name, version, ecosystem).
    Returns (None, None, None) if unparseable. Ecosystem is inferred from pattern.
    """
    if not dependency or not dependency.strip():
        return (None, None, None)
    s = dependency.strip()
    if len(s) > 512:
        s = s[:512]
    # name@version -> npm by default
    m = _AT_VERSION.match(s)
    if m:
        name, version = m.group(1).strip(), m.group(2).strip()
        if name and version:
            return (name, version, "npm")
    # name==version -> pypi
    m = _EQ_VERSION.match(s)
    if m:
        name, version = m.group(1).strip(), m.group(2).strip()
        if name and version:
            return (name, version, "PyPI")
    # name:version -> maven
    m = _COLON_VERSION.match(s)
    if m:
        name, version = m.group(1).strip(), m.group(2).strip()
        if name and version:
            return (name, version, "Maven")
    # Fallback: whole string as name, no version
    if s and len(s) <= 255:
        return (s, None, None)
    return (None, None, None)


def _extract_fixed_versions(affected: list[Any]) -> list[str]:
    """From OSV affected[].ranges[].events extract fixed version strings. Bounded output."""
    fixed: list[str] = []
    for item in affected[:10]:
        if not isinstance(item, dict):
            continue
        ranges = item.get("ranges") or []
        if not isinstance(ranges, list):
            continue
        for r in ranges[:5]:
            if not isinstance(r, dict):
                continue
            events = r.get("events") or []
            if not isinstance(events, list):
                continue
            for e in events:
                if not isinstance(e, dict):
                    continue
                f = e.get("fixed")
                if isinstance(f, str) and f.strip() and len(f) <= 64:
                    if f not in fixed:
                        fixed.append(f)
                        if len(fixed) >= 20:
                            return fixed
    return fixed


def _vuln_to_osv_entry(vuln: dict[str, Any]) -> OsvEntry | None:
    """Convert one OSV vuln object to OsvEntry. Bounds strings and list lengths."""
    summary = vuln.get("summary") or vuln.get("details") or ""
    if isinstance(summary, str) and len(summary) > 2000:
        summary = summary[:2000]
    elif not isinstance(summary, str):
        summary = ""
    affected_list = vuln.get("affected") or []
    if not isinstance(affected_list, list):
        affected_list = []
    ecosystem = "unknown"
    fixed_in: list[str] = []
    for a in affected_list[:5]:
        if not isinstance(a, dict):
            continue
        pkg = a.get("package") or {}
        if isinstance(pkg, dict):
            eco = pkg.get("ecosystem")
            if isinstance(eco, str) and eco.strip():
                ecosystem = eco.strip()[:32]
        fixed_in.extend(_extract_fixed_versions([a]))
    fixed_in = list(dict.fromkeys(fixed_in))[:20]  # dedupe, cap
    return OsvEntry(
        ecosystem=ecosystem,
        summary=summary[:2000],
        fixed_in_versions=fixed_in,
    )


async def _query_osv_by_package(
    package_name: str,
    version: str,
    ecosystem: str,
    settings: "Settings",
) -> list[OsvEntry]:
    """POST /v1/query with package and version; return list of OsvEntry."""
    payload: dict[str, Any] = {
        "package": {"name": package_name, "ecosystem": ecosystem},
        "version": version,
    }
    timeout = httpx.Timeout(settings.ENRICHMENT_REQUEST_TIMEOUT_SEC)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(OSV_QUERY_URL, json=payload)
            response.raise_for_status()
            data = response.json()
    except (httpx.HTTPError, ValueError) as e:
        logger.debug("OSV query failed for %s@%s: %s", package_name, version, e)
        return []
    if not isinstance(data, dict):
        return []
    vulns = data.get("vulns")
    if not isinstance(vulns, list):
        return []
    entries: list[OsvEntry] = []
    for v in vulns[:15]:
        if not isinstance(v, dict):
            continue
        entry = _vuln_to_osv_entry(v)
        if entry:
            entries.append(entry)
    return entries


async def _get_osv_by_id(vuln_id: str, settings: "Settings") -> list[OsvEntry]:
    """GET /v1/vulns/{id} for GHSA (and optionally OSV IDs). Returns list of OsvEntry."""
    vuln_id = vuln_id.strip()
    if not vuln_id or len(vuln_id) > 128:
        return []
    url = f"{OSV_VULNS_URL}/{vuln_id}"
    timeout = httpx.Timeout(settings.ENRICHMENT_REQUEST_TIMEOUT_SEC)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url)
            if response.status_code == 404:
                return []
            response.raise_for_status()
            vuln = response.json()
    except (httpx.HTTPError, ValueError) as e:
        logger.debug("OSV GET vuln failed for %s: %s", vuln_id, e)
        return []
    if not isinstance(vuln, dict):
        return []
    entry = _vuln_to_osv_entry(vuln)
    return [entry] if entry else []


async def query_osv(
    vulnerability_id: str,
    dependency: str,
    settings: "Settings",
) -> tuple[list[OsvEntry], str | None]:
    """
    Query OSV for the given cluster. Returns (list of OsvEntry, package_ecosystem or None).
    - If dependency parses to name+version+ecosystem, use POST /v1/query.
    - If vulnerability_id is GHSA-xxx, use GET /v1/vulns/GHSA-xxx.
    - Otherwise returns ([], None).
    """
    # GHSA: direct GET
    if vulnerability_id.strip().upper().startswith("GHSA-"):
        entries = await _get_osv_by_id(vulnerability_id.strip(), settings)
        eco = entries[0].ecosystem if entries else None
        return (entries, eco)
    # Try package+version from dependency
    name, version, ecosystem = _parse_dependency(dependency or "")
    if name and version and ecosystem:
        entries = await _query_osv_by_package(name, version, ecosystem, settings)
        return (entries, ecosystem)
    return ([], None)
