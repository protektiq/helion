"""Orchestrate KEV, EPSS, OSV for one cluster and return typed enrichment payload."""

import logging
from typing import TYPE_CHECKING

from app.schemas.findings import VulnerabilityCluster
from app.services.enrichment.client_epss import fetch_epss
from app.services.enrichment.client_kev import is_in_kev
from app.services.enrichment.client_osv import query_osv
from app.services.enrichment.schemas import (
    ClusterEnrichmentPayload,
    CvssCheck,
    OsvEntry,
)
from app.services.normalize import _is_cve_or_ghsa_like

if TYPE_CHECKING:
    from app.core.config import Settings

logger = logging.getLogger(__name__)

# CVSS bands for severity consistency check (match normalize.py semantics).
_CVSS_TO_SEVERITY: list[tuple[tuple[float, float], str]] = [
    ((9.0, 10.0), "critical"),
    ((7.0, 8.99), "high"),
    ((4.0, 6.99), "medium"),
    ((0.1, 3.99), "low"),
    ((0.0, 0.09), "info"),
]


def _expected_severity_from_cvss(cvss: float) -> str:
    """Derive expected severity from CVSS score."""
    for (lo, hi), sev in _CVSS_TO_SEVERITY:
        if lo <= cvss <= hi:
            return sev
    return "info"


def _build_cvss_check(cluster: VulnerabilityCluster) -> CvssCheck | None:
    """Compare cluster severity to CVSS-derived severity; set mismatch if different."""
    expected = _expected_severity_from_cvss(cluster.cvss_score)
    actual = (cluster.severity or "").strip().lower()
    if not actual:
        return CvssCheck(expected_severity=expected, mismatch=True)
    return CvssCheck(
        expected_severity=expected,
        mismatch=expected != actual,
    )


# Type alias for (payload, raw dict) so callers can persist dict to JSONB.
ClusterEnrichmentResult = tuple[ClusterEnrichmentPayload, dict]


async def enrich_cluster(
    cluster: VulnerabilityCluster,
    settings: "Settings",
    *,
    kev_enabled: bool | None = None,
    epss_enabled: bool | None = None,
    osv_enabled: bool | None = None,
) -> ClusterEnrichmentResult:
    """
    Enrich one cluster with KEV, EPSS, and OSV. Returns (ClusterEnrichmentPayload, raw dict).
    The dict is suitable for JSONB storage. Feature flags default to settings values.
    """
    kev_on = kev_enabled if kev_enabled is not None else settings.ENRICHMENT_KEV_ENABLED
    epss_on = (
        epss_enabled if epss_enabled is not None else settings.ENRICHMENT_EPSS_ENABLED
    )
    osv_on = osv_enabled if osv_enabled is not None else settings.ENRICHMENT_OSV_ENABLED

    vid = (cluster.vulnerability_id or "").strip()
    dep = (cluster.dependency or "").strip()
    evidence: list[str] = []
    kev = False
    epss_val: float | None = None
    osv_entries: list[OsvEntry] = []
    package_ecosystem: str | None = None
    is_cve = vid.upper().startswith("CVE-") if vid else False

    if kev_on and is_cve:
        try:
            kev = await is_in_kev(vid, settings)
            if kev:
                evidence.append("KEV listed")
        except Exception as e:
            logger.debug("KEV lookup failed for %s: %s", vid, e)

    if epss_on and is_cve:
        try:
            epss_val = await fetch_epss(vid, settings)
            if epss_val is not None:
                evidence.append(f"EPSS {epss_val:.2f}")
        except Exception as e:
            logger.debug("EPSS fetch failed for %s: %s", vid, e)

    if osv_on and (_is_cve_or_ghsa_like(vid) or dep):
        try:
            entries, eco = await query_osv(vid, dep, settings)
            osv_entries = entries
            if eco:
                package_ecosystem = eco
            if entries:
                evidence.append("OSV advisory")
        except Exception as e:
            logger.debug("OSV query failed for %s: %s", vid, e)

    fixed_in_versions: list[str] = []
    for e in osv_entries:
        fixed_in_versions.extend(e.fixed_in_versions)
    fixed_in_versions = list(dict.fromkeys(fixed_in_versions))[:50]

    cvss_check = _build_cvss_check(cluster)

    payload = ClusterEnrichmentPayload(
        kev=kev,
        epss=epss_val,
        osv=osv_entries,
        fixed_in_versions=fixed_in_versions,
        package_ecosystem=package_ecosystem,
        cvss_check=cvss_check,
        evidence=evidence[:30],
    )
    raw = payload.model_dump(mode="json")
    return (payload, raw)
