"""Convert vulnerability clusters into Jira-ready ticket payloads.

Cluster → DevTicketPayload with title, description, affected services,
acceptance criteria, recommended remediation, and risk tier label.
"""

from sqlalchemy.orm import Session

from app.schemas.findings import VulnerabilityCluster
from app.schemas.reasoning import ClusterNote
from app.schemas.risk_tier import ClusterRiskTierResult
from app.schemas.ticket import (
    DESCRIPTION_MAX_LENGTH,
    DevTicketPayload,
    REMEDIATION_MAX_LENGTH,
    TITLE_MAX_LENGTH,
)

# Default acceptance criteria for all vulnerability tickets (consistent, easy to change).
DEFAULT_ACCEPTANCE_CRITERIA: list[str] = [
    "Vulnerability remediated and verified.",
    "No findings in rescans for affected services.",
]

FALLBACK_REMEDIATION = "Review and remediate per security guidance."
MULTIPLE_REPOS_PLACEHOLDER = "multiple repositories"


def _tier_to_label(tier: int) -> str:
    """Map numeric tier (1/2/3) to human-readable label."""
    if tier == 1:
        return "Tier 1"
    if tier == 2:
        return "Tier 2"
    if tier == 3:
        return "Tier 3"
    return "Tier 2"  # safe default


def _severity_to_tier_label(severity: str) -> str:
    """Derive risk tier label from cluster severity when no tier result is provided."""
    if not severity or not isinstance(severity, str):
        return "Tier 2"
    normalized = severity.strip().lower()
    if normalized == "critical":
        return "Tier 1"
    if normalized == "high":
        return "Tier 2"
    return "Tier 3"  # medium, low, info


def _build_title(
    risk_tier_label: str,
    cluster: VulnerabilityCluster,
    max_length: int = TITLE_MAX_LENGTH,
) -> str:
    """Build a short, deterministic title: [Tier N] vulnerability_id [optional context]."""
    base = f"[{risk_tier_label}] {cluster.vulnerability_id}"
    if len(base) >= max_length:
        return base[:max_length].rstrip()
    # Optional short context: repo (if single and not long) or dependency (if set and short).
    extra: list[str] = []
    if cluster.repo and cluster.repo != "multiple" and len(cluster.repo) <= 60:
        extra.append(cluster.repo)
    if cluster.dependency and len(cluster.dependency) <= 50:
        extra.append(cluster.dependency)
    if not extra:
        return base
    suffix = " | ".join(extra)
    candidate = f"{base} | {suffix}"
    if len(candidate) <= max_length:
        return candidate
    return base[:max_length].rstrip()


def _build_description(cluster: VulnerabilityCluster) -> str:
    """Structured description: vulnerability_id, description, severity, CVSS, context."""
    lines = [
        f"Vulnerability: {cluster.vulnerability_id}",
        f"Description: {cluster.description}",
        f"Severity: {cluster.severity}",
        f"CVSS: {cluster.cvss_score}",
        f"Finding count: {cluster.finding_count}",
        f"Affected services count: {cluster.affected_services_count}",
    ]
    if cluster.file_path and cluster.file_path.strip():
        lines.append(f"File path: {cluster.file_path.strip()}")
    if cluster.dependency and cluster.dependency.strip():
        lines.append(f"Dependency: {cluster.dependency.strip()}")
    text = "\n".join(lines)
    if len(text) > DESCRIPTION_MAX_LENGTH:
        return text[:DESCRIPTION_MAX_LENGTH].rstrip()
    return text


def _truncate_remediation(text: str, max_length: int = REMEDIATION_MAX_LENGTH) -> str:
    """Ensure remediation string is within limit."""
    if not text or not text.strip():
        return FALLBACK_REMEDIATION
    t = text.strip()
    if len(t) <= max_length:
        return t
    return t[: max_length - 3].rstrip() + "..."


def cluster_to_ticket_payload(
    cluster: VulnerabilityCluster,
    *,
    affected_services: list[str] | None = None,
    cluster_note: ClusterNote | None = None,
    risk_tier_result: ClusterRiskTierResult | None = None,
) -> DevTicketPayload:
    """
    Convert a single vulnerability cluster into a Jira-ready ticket payload.

    - affected_services: When cluster.repo == "multiple", pass resolved repo names here;
      otherwise single-repo clusters use [cluster.repo], and "multiple" uses a placeholder.
    - cluster_note: Optional LLM note; reasoning is used for recommended_remediation.
    - risk_tier_result: Optional tier result; assigned_tier is used for risk_tier_label.
    """
    # Affected services
    if affected_services and len(affected_services) > 0:
        services = [s.strip()[:1024] for s in affected_services if s and str(s).strip()]
    elif cluster.repo != "multiple" and cluster.repo and str(cluster.repo).strip():
        services = [cluster.repo.strip()]
    else:
        services = [MULTIPLE_REPOS_PLACEHOLDER]
    if not services:
        services = [MULTIPLE_REPOS_PLACEHOLDER]

    # Risk tier label
    if risk_tier_result is not None:
        risk_tier_label = _tier_to_label(risk_tier_result.assigned_tier)
    else:
        severity_str = (
            cluster.severity
            if isinstance(cluster.severity, str)
            else getattr(cluster.severity, "value", str(cluster.severity))
        )
        risk_tier_label = _severity_to_tier_label(severity_str)

    # Recommended remediation
    if cluster_note and cluster_note.reasoning and cluster_note.reasoning.strip():
        remediation = _truncate_remediation(cluster_note.reasoning)
    elif cluster.description and cluster.description.strip():
        remediation = _truncate_remediation(cluster.description)
    else:
        remediation = FALLBACK_REMEDIATION

    title = _build_title(risk_tier_label, cluster)
    description = _build_description(cluster)
    acceptance_criteria = DEFAULT_ACCEPTANCE_CRITERIA

    return DevTicketPayload(
        title=title,
        description=description,
        affected_services=services,
        acceptance_criteria=acceptance_criteria,
        recommended_remediation=remediation,
        risk_tier_label=risk_tier_label,
    )


def resolve_affected_services(session: Session, finding_ids: list[str]) -> list[str]:
    """
    Resolve distinct repository names for a list of finding IDs.

    Used when cluster.repo == "multiple" to populate affected_services from the DB.
    Returns sorted distinct repo names (excluding empty strings).
    """
    from app.models import Finding

    ids: list[int] = []
    for fid in finding_ids:
        if not fid:
            continue
        s = str(fid).strip()
        if not s:
            continue
        try:
            ids.append(int(s))
        except ValueError:
            continue
    if not ids:
        return []
    rows = (
        session.query(Finding.repo)
        .distinct()
        .filter(Finding.id.in_(ids))
        .all()
    )
    repos = [r[0].strip() for r in rows if r[0] and str(r[0]).strip()]
    return sorted(set(repos)) if repos else []


def clusters_to_ticket_payloads(
    clusters: list[VulnerabilityCluster],
    *,
    notes_by_id: dict[str, ClusterNote] | None = None,
    tier_by_id: dict[str, ClusterRiskTierResult] | None = None,
    affected_services_by_id: dict[str, list[str]] | None = None,
) -> list[DevTicketPayload]:
    """
    Convert multiple clusters to ticket payloads using optional per-cluster data.

    - notes_by_id: vulnerability_id -> ClusterNote (for recommended_remediation).
    - tier_by_id: vulnerability_id -> ClusterRiskTierResult (for risk_tier_label).
    - affected_services_by_id: vulnerability_id -> list of repo names (for repo=="multiple").
    """
    notes = notes_by_id or {}
    tiers = tier_by_id or {}
    services_by_id = affected_services_by_id or {}
    return [
        cluster_to_ticket_payload(
            c,
            affected_services=services_by_id.get(c.vulnerability_id),
            cluster_note=notes.get(c.vulnerability_id),
            risk_tier_result=tiers.get(c.vulnerability_id),
        )
        for c in clusters
    ]


def apply_tier_overrides(
    tickets: list[DevTicketPayload],
    clusters: list[VulnerabilityCluster],
    overrides: dict[str, str],
) -> list[DevTicketPayload]:
    """
    Apply consultant tier overrides to ticket payloads.

    For each cluster index where vulnerability_id is in overrides, replace the
    ticket's risk_tier_label and title with the override value. Unknown
    vulnerability_ids in overrides are ignored (no-op). Returns a new list.
    """
    if not overrides or len(tickets) != len(clusters):
        return tickets
    result: list[DevTicketPayload] = []
    for i, (ticket, cluster) in enumerate(zip(tickets, clusters)):
        vuln_id = cluster.vulnerability_id
        if vuln_id in overrides:
            new_label = overrides[vuln_id]
            new_title = _build_title(new_label, cluster)
            result.append(
                ticket.model_copy(
                    update={"risk_tier_label": new_label, "title": new_title}
                )
            )
        else:
            result.append(ticket)
    return result
