"""Cluster findings by CVE (SCA) or Rule ID + file path pattern (SAST), with affected services count."""

from collections import defaultdict
from typing import TYPE_CHECKING

from app.schemas.findings import SeverityLevel, VulnerabilityCluster
from app.services.normalize import _is_cve_or_ghsa_like

if TYPE_CHECKING:
    from app.models.finding import Finding

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


def build_clusters(findings: list["Finding"]) -> list[VulnerabilityCluster]:
    """
    Group findings by SCA (CVE ID) or SAST (rule ID + file path pattern).
    Returns distinct vulnerability clusters with canonical fields and affected_services_count.
    """
    if not findings:
        return []

    groups: defaultdict[str, list["Finding"]] = defaultdict(list)
    for f in findings:
        key = _cluster_key(f)
        groups[key].append(f)

    clusters: list[VulnerabilityCluster] = []
    for group in groups.values():
        first = group[0]
        finding_ids = [str(f.id) for f in group]
        distinct_repos = len({(f.repo or "").strip() for f in group})
        severities = [f.severity or "info" for f in group]
        canonical_severity = _worst_severity(severities)
        # Avoid misleading single-repo representation when cluster spans multiple repos.
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

    return clusters
