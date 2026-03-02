"""Orchestrate KEV, EPSS, OSV for one cluster and return typed enrichment payload."""

import logging
from typing import TYPE_CHECKING

from app.schemas.findings import is_cvss_present, VulnerabilityCluster
from app.services.enrichment.client_epss import EpssResult, fetch_epss
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

# Max length for epss_display stored in payload (match schema).
_EPSS_DISPLAY_MAX_LEN = 120


def _epss_debug(settings: "Settings") -> bool:
    """True when EPSS debug logging is enabled."""
    return getattr(settings, "ENRICHMENT_EPSS_DEBUG", False) or getattr(
        settings, "DEBUG", False
    )


def _epss_display_from_result(result: EpssResult) -> str:
    """Build display string from EPSS result for CVE lookups (spec wording)."""
    if result.status == "ok" and result.score is not None:
        if result.percentile is not None:
            pct = round(result.percentile * 100, 2)
            return f"{result.score:.2f} ({pct} percentile)"
        return f"{result.score:.2f}"
    if result.status == "not_found":
        return "Not available (no EPSS record)"
    if result.status == "unavailable":
        if getattr(result, "reason", None) == "rate limited":
            return "Unavailable (rate limited)"
        return "Unavailable (lookup failed)"
    return "Not available (no EPSS record)"

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
    """Compare cluster severity to CVSS-derived severity; set mismatch if different. Returns None when CVSS is not present (missing or 0)."""
    if not is_cvss_present(cluster.cvss_score):
        return None
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
    epss_percentile_val: float | None = None
    epss_display_val: str | None = None
    epss_status_val: str | None = None
    epss_reason_val: str | None = None
    osv_entries: list[OsvEntry] = []
    package_ecosystem: str | None = None
    is_cve = vid.upper().startswith("CVE-") if vid else False
    is_ghsa = vid.upper().startswith("GHSA-") if vid else False

    if kev_on and is_cve:
        try:
            kev = await is_in_kev(vid, settings)
            if kev:
                evidence.append("KEV listed")
        except Exception as e:
            logger.debug("KEV lookup failed for %s: %s", vid, e)

    if epss_on:
        if is_cve:
            try:
                epss_result = await fetch_epss(vid, settings)
                epss_display_val = _epss_display_from_result(epss_result)
                if len(epss_display_val) > _EPSS_DISPLAY_MAX_LEN:
                    epss_display_val = epss_display_val[:_EPSS_DISPLAY_MAX_LEN - 3].rstrip() + "..."
                if epss_result.status == "ok":
                    epss_status_val = "AVAILABLE"
                    epss_reason_val = None
                    epss_val = epss_result.score
                    epss_percentile_val = epss_result.percentile
                    if epss_val is not None:
                        evidence.append(f"EPSS {epss_val:.2f}")
                elif epss_result.status == "not_applicable":
                    epss_status_val = "NOT_APPLICABLE"
                    epss_reason_val = "GHSA-only" if is_ghsa else "non-CVE"
                elif epss_result.status == "not_found":
                    epss_status_val = "NOT_FOUND"
                    epss_reason_val = None
                else:
                    epss_status_val = "ERROR"
                    epss_reason_val = getattr(epss_result, "reason", None) or "lookup failed"
                if _epss_debug(settings):
                    logger.debug(
                        "EPSS result: vid=%s status=%s display=%s",
                        vid,
                        epss_result.status,
                        epss_display_val,
                    )
            except Exception as e:
                logger.error("EPSS fetch failed for %s: %s", vid, e, exc_info=False)
                epss_display_val = "Unavailable (lookup failed)"
                epss_status_val = "ERROR"
                epss_reason_val = "lookup failed"
                if _epss_debug(settings):
                    logger.debug("EPSS exception: %s", type(e).__name__)
        else:
            epss_status_val = "NOT_APPLICABLE"
            epss_reason_val = "GHSA-only" if is_ghsa else "non-CVE"
            if is_ghsa:
                epss_display_val = "Not applicable (GHSA-only)"
            else:
                epss_display_val = "Not applicable (non-CVE)"
            if _epss_debug(settings):
                logger.debug(
                    "EPSS skipped: vid=%s reason=%s",
                    vid,
                    "GHSA-only" if is_ghsa else "non-CVE",
                )
    else:
        if not is_cve:
            epss_status_val = "NOT_APPLICABLE"
            epss_reason_val = "GHSA-only" if is_ghsa else "non-CVE"
            if is_ghsa:
                epss_display_val = "Not applicable (GHSA-only)"
            else:
                epss_display_val = "Not applicable (non-CVE)"
        if _epss_debug(settings) and vid and is_cve:
            logger.debug("EPSS skipped: feature disabled")

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
        epss_percentile=epss_percentile_val,
        epss_display=epss_display_val,
        epss_status=epss_status_val,
        epss_reason=epss_reason_val,
        osv=osv_entries,
        fixed_in_versions=fixed_in_versions,
        package_ecosystem=package_ecosystem,
        cvss_check=cvss_check,
        evidence=evidence[:30],
    )
    raw = payload.model_dump(mode="json")
    return (payload, raw)
