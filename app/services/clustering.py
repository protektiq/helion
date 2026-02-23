"""Cluster findings by CVE (SCA) or Rule ID + file path pattern (SAST), with affected services count."""

import json
import logging
import time
from collections import defaultdict
from typing import TYPE_CHECKING

from app.schemas.findings import SeverityLevel, VulnerabilityCluster
from app.services.normalize import _is_cve_or_ghsa_like

if TYPE_CHECKING:
    from app.models.finding import Finding

logger = logging.getLogger(__name__)

# Lazy import for optional Rust extension (cluster_engine); fallback to Python if missing.
_CLUSTER_ENGINE = None


def _get_cluster_engine():
    """Return the cluster_engine module if installed, else None."""
    global _CLUSTER_ENGINE
    if _CLUSTER_ENGINE is not None:
        return _CLUSTER_ENGINE
    try:
        import cluster_engine as ce  # noqa: PLC0415
        _CLUSTER_ENGINE = ce
        return ce
    except ImportError:
        _CLUSTER_ENGINE = False
        return None

# Severity order for choosing "worst" in a cluster (higher index = more severe).
_SEVERITY_ORDER: tuple[SeverityLevel, ...] = (
    "info",
    "low",
    "medium",
    "high",
    "critical",
)


def _is_sca_finding(vulnerability_id: str) -> bool:
    """True if the finding is SCA (CVE/GHSA); else SAST (e.g. rule ID)."""
    if not vulnerability_id or not vulnerability_id.strip():
        return False
    return _is_cve_or_ghsa_like(vulnerability_id.strip())


def _file_path_pattern(repo: str, file_path: str) -> str:
    """
    Normalize file path to a pattern: strip repo prefix if present, normalize slashes.
    Used as the path component of the SAST cluster key.
    """
    if not file_path or not file_path.strip():
        return ""
    path = file_path.strip().replace("\\", "/")
    if not path:
        return ""
    repo_norm = (repo or "").strip().replace("\\", "/").strip("/")
    if repo_norm and path.startswith(repo_norm + "/"):
        path = path[len(repo_norm) + 1 :].lstrip("/")
    elif repo_norm and path == repo_norm:
        path = ""
    return path


def _cluster_key(finding: "Finding") -> str:
    """
    Return a hashable cluster key: for SCA use (vulnerability_id, dependency);
    for SAST use vulnerability_id + file_path_pattern (null-separated).
    Same CVE in different packages (e.g. lodash vs openssl) are separate clusters.
    """
    vid = (finding.vulnerability_id or "").strip()
    dep = (finding.dependency or "").strip()
    if _is_sca_finding(vid):
        return f"{vid}\0{dep}"
    pattern = _file_path_pattern(finding.repo or "", finding.file_path or "")
    return f"{vid}\0{pattern}"


def _worst_severity(severities: list[str]) -> SeverityLevel:
    """Return the highest severity among the list (critical > high > medium > low > info)."""
    order_map = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
    worst: SeverityLevel = "info"
    worst_idx = -1
    for s in severities:
        if not s:
            continue
        normalized = s.strip().lower()
        idx = order_map.get(normalized, -1)
        if idx > worst_idx:
            worst_idx = idx
            worst = normalized if normalized in order_map else worst
    return worst


def _severity_rank(severity: str) -> int:
    """Return index in _SEVERITY_ORDER (higher = more severe). Unknown severity maps to 0 (info)."""
    if not severity or not isinstance(severity, str):
        return 0
    normalized = severity.strip().lower()
    order_map = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
    return order_map.get(normalized, 0)


def sort_clusters_by_severity_cvss(
    clusters: list[VulnerabilityCluster],
) -> list[VulnerabilityCluster]:
    """Sort clusters worst first: by severity (critical > high > medium > low > info), then by CVSS descending."""
    return sorted(
        clusters,
        key=lambda c: (-_severity_rank(c.severity), -c.cvss_score),
    )


def _findings_to_rust_input(findings: list["Finding"]) -> list[dict]:
    """Convert ORM Finding list to JSON-serializable list for the Rust engine."""
    return [
        {
            "id": str(f.id),
            "vulnerability_id": f.vulnerability_id or "",
            "severity": f.severity or "info",
            "repo": f.repo or "",
            "file_path": f.file_path or "",
            "dependency": f.dependency or "",
            "cvss_score": float(f.cvss_score),
            "description": f.description or "No description",
        }
        for f in findings
    ]


def _build_clusters_rust(findings: list["Finding"]) -> list[VulnerabilityCluster]:
    """Run clustering in the Rust engine; raises on error or invalid output."""
    engine = _get_cluster_engine()
    if not engine:
        raise ImportError("cluster_engine not installed")
    payload = _findings_to_rust_input(findings)
    json_input = json.dumps(payload)
    json_output = engine.cluster_findings(json_input)
    data = json.loads(json_output)
    clusters_data = data.get("clusters") or []
    return [
        VulnerabilityCluster(
            vulnerability_id=c["vulnerability_id"],
            severity=c["severity"],
            repo=c["repo"],
            file_path=c.get("file_path") or "",
            dependency=c.get("dependency") or "",
            cvss_score=float(c["cvss_score"]),
            description=c.get("description") or "No description",
            finding_ids=[str(x) for x in c["finding_ids"]],
            affected_services_count=int(c["affected_services_count"]),
            finding_count=int(c["finding_count"]),
        )
        for c in clusters_data
    ]


def build_clusters(findings: list["Finding"]) -> list[VulnerabilityCluster]:
    """
    Group findings by SCA (CVE ID) or SAST (rule ID + file path pattern).
    Returns distinct vulnerability clusters with canonical fields and affected_services_count.
    Uses the Rust cluster_engine when available, otherwise falls back to Python implementation.
    """
    start = time.perf_counter()
    if not findings:
        elapsed = time.perf_counter() - start
        logger.info(
            "Cluster generation completed",
            extra={
                "cluster_generation_seconds": elapsed,
                "finding_count": 0,
                "cluster_count": 0,
            },
        )
        return []

    try:
        clusters = _build_clusters_rust(findings)
        elapsed = time.perf_counter() - start
        logger.info(
            "Cluster generation completed (Rust)",
            extra={
                "cluster_generation_seconds": elapsed,
                "finding_count": len(findings),
                "cluster_count": len(clusters),
            },
        )
        return clusters
    except Exception as e:
        logger.debug(
            "Rust cluster engine unavailable or failed, using Python",
            extra={"reason": str(e)},
        )

    # Python fallback
    groups: defaultdict[str, list["Finding"]] = defaultdict(list)
    for f in findings:
        key = _cluster_key(f)
        groups[key].append(f)

    clusters = []
    for group in groups.values():
        first = group[0]
        finding_ids = [str(f.id) for f in group]
        distinct_repos = len({(f.repo or "").strip() for f in group})
        severities = [f.severity or "info" for f in group]
        canonical_severity = _worst_severity(severities)
        canonical_repo = "multiple" if distinct_repos > 1 else (first.repo or "unknown")

        clusters.append(
            VulnerabilityCluster(
                vulnerability_id=first.vulnerability_id or "unknown",
                severity=canonical_severity,
                repo=canonical_repo,
                file_path=first.file_path or "",
                dependency=first.dependency or "",
                cvss_score=first.cvss_score,
                description=first.description or "No description",
                finding_ids=finding_ids,
                affected_services_count=max(1, distinct_repos),
                finding_count=len(finding_ids),
            )
        )

    elapsed = time.perf_counter() - start
    logger.info(
        "Cluster generation completed",
        extra={
            "cluster_generation_seconds": elapsed,
            "finding_count": len(findings),
            "cluster_count": len(clusters),
        },
    )
    return clusters
