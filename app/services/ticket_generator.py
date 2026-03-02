"""Convert vulnerability clusters into Jira-ready ticket payloads.

Cluster → DevTicketPayload with title, description, affected services,
acceptance criteria, recommended remediation, and risk tier label.
"""

from sqlalchemy.orm import Session

from app.schemas.findings import VulnerabilityCluster, cvss_display
from app.schemas.reasoning import ClusterNote
from app.schemas.risk_tier import ClusterRiskTierResult
from app.services.risk_tier import is_high_epss
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
# When enrichment is present but no fix versions are known; used for evidence-only narrative.
ACTION_FALLBACK_NO_FIX = "Apply vendor patch or upgrade per advisory."
MULTIPLE_REPOS_PLACEHOLDER = "multiple repositories"
SCOPE_HINT_MAX_LENGTH = 200

# Urgency prefixes for recommendation text (KEV / high EPSS); used only when no cluster_note (no enrichment).
KEV_URGENT_PREFIX = "Known exploited in the wild (CISA KEV). Prioritize immediate remediation. "
HIGH_EPSS_URGENT_PREFIX = "High exploit likelihood (EPSS). "


def enrichment_to_cluster_note(vulnerability_id: str, enrichment: dict) -> ClusterNote:
    """
    Build a ClusterNote from a persisted enrichment dict (JSONB).
    Used when tickets load enrichments from DB but reasoning/agent did not run.
    Uses defaults for priority/reasoning/assigned_tier; EPSS display uses evidence fields.
    """
    if not isinstance(enrichment, dict):
        enrichment = {}
    kev = enrichment.get("kev")
    if not isinstance(kev, bool):
        kev = None
    epss = enrichment.get("epss")
    if epss is not None and not isinstance(epss, (int, float)):
        epss = None
    epss_display = enrichment.get("epss_display")
    epss_display = epss_display if isinstance(epss_display, str) and epss_display.strip() else None
    epss_percentile = enrichment.get("epss_percentile")
    if epss_percentile is not None and not isinstance(epss_percentile, (int, float)):
        epss_percentile = None
    epss_status = enrichment.get("epss_status")
    if epss_status not in ("AVAILABLE", "NOT_APPLICABLE", "NOT_FOUND", "ERROR"):
        epss_status = None
    epss_reason = enrichment.get("epss_reason")
    epss_reason = epss_reason if isinstance(epss_reason, str) and epss_reason.strip() else None
    fixed_in_versions = enrichment.get("fixed_in_versions")
    if not isinstance(fixed_in_versions, list):
        fixed_in_versions = None
    else:
        fixed_in_versions = [str(v).strip() for v in fixed_in_versions[:50] if v]
    package_ecosystem = enrichment.get("package_ecosystem")
    package_ecosystem = package_ecosystem if isinstance(package_ecosystem, str) and package_ecosystem.strip() else None
    evidence = enrichment.get("evidence")
    if not isinstance(evidence, list):
        evidence = None
    else:
        evidence = [str(e).strip() for e in evidence[:30] if e]
    return ClusterNote(
        vulnerability_id=vulnerability_id,
        priority="medium",
        reasoning="",
        assigned_tier=2,
        override_applied=None,
        kev=kev,
        epss=epss,
        epss_display=epss_display,
        epss_percentile=epss_percentile,
        epss_status=epss_status,
        epss_reason=epss_reason,
        fixed_in_versions=fixed_in_versions,
        package_ecosystem=package_ecosystem,
        evidence=evidence,
    )


def _remediation_with_urgency(
    base_remediation: str,
    cluster_note: ClusterNote | None,
) -> str:
    """Prepend KEV or high-EPSS urgency to remediation when applicable; then truncate."""
    if not base_remediation or not base_remediation.strip():
        base_remediation = FALLBACK_REMEDIATION
    if cluster_note is None:
        return _truncate_remediation(base_remediation)
    if cluster_note.kev is True:
        combined = (KEV_URGENT_PREFIX + base_remediation.strip()).strip()
        return _truncate_remediation(combined)
    if is_high_epss(cluster_note.epss, getattr(cluster_note, "epss_percentile", None)):
        combined = (HIGH_EPSS_URGENT_PREFIX + base_remediation.strip()).strip()
        return _truncate_remediation(combined)
    return _truncate_remediation(base_remediation)


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


def _has_enrichment_in_note(note: ClusterNote | None) -> bool:
    """True if cluster_note has any exploitability evidence to show."""
    if note is None:
        return False
    if note.kev is not None:
        return True
    if note.epss is not None:
        return True
    if getattr(note, "epss_status", None) is not None:
        return True
    if note.epss_display and str(note.epss_display).strip():
        return True
    if note.evidence and len(note.evidence) > 0:
        return True
    if note.fixed_in_versions and len(note.fixed_in_versions) > 0:
        return True
    if note.package_ecosystem and str(note.package_ecosystem).strip():
        return True
    return False


def _ordinal_suffix(n: int) -> str:
    """Return ordinal suffix for n (e.g. 1 -> '1st', 2 -> '2nd', 42 -> '42nd')."""
    if n < 0:
        n = 0
    if 10 <= n % 100 <= 20:
        return f"{n}th"
    return {1: f"{n}st", 2: f"{n}nd", 3: f"{n}rd"}.get(n % 10, f"{n}th")


def _epss_text_for_note(note: ClusterNote | None) -> str:
    """Return EPSS value string for display (no 'EPSS: ' prefix). Prefers epss_display, then score with adaptive precision, then status fallbacks."""
    if note is None:
        return "n/a"
    disp = getattr(note, "epss_display", None)
    if isinstance(disp, str) and disp.strip():
        return disp.strip()
    score = getattr(note, "epss", None)
    if isinstance(score, (int, float)):
        score_str = f"{score:.4f}" if score < 0.01 else f"{score:.2f}"
        percentile = getattr(note, "epss_percentile", None)
        if percentile is not None and getattr(note, "epss_status", None) == "AVAILABLE":
            pct_int = round(percentile * 100)
            return f"{score_str} ({_ordinal_suffix(pct_int)} percentile)"
        return score_str
    status = getattr(note, "epss_status", None)
    if status == "NOT_APPLICABLE":
        return "Not applicable (GHSA-only)"
    if status == "NOT_FOUND":
        return "Not available (no EPSS record)"
    if status == "ERROR":
        reason = getattr(note, "epss_reason", None)
        if isinstance(reason, str) and reason.strip():
            return f"Unavailable ({reason.strip()})"
        return "Unavailable (lookup failed)"
    return "n/a"


def _epss_line_for_note(note: ClusterNote | None) -> str:
    """Return the EPSS line for ticket description/acceptance criteria (spec wording)."""
    if note is None:
        return "EPSS: n/a"
    return "EPSS: " + _epss_text_for_note(note)


def _risk_rationale_sentence(note: ClusterNote | None) -> str:
    """Build one-line 'Why now' sentence from KEV and/or high EPSS when available; otherwise empty."""
    if note is None:
        return ""
    parts: list[str] = []
    if note.kev is True:
        parts.append("Listed in CISA KEV (known exploited)")
    # Include EPSS in "Why now" only when high (exploitability signal), not for every score.
    if is_high_epss(note.epss, getattr(note, "epss_percentile", None)) and note.epss is not None:
        percentile = getattr(note, "epss_percentile", None)
        if percentile is not None:
            pct_int = round(percentile * 100)
            parts.append(f"EPSS {note.epss:.2f} ({_ordinal_suffix(pct_int)} percentile)")
        else:
            parts.append(f"EPSS {note.epss:.2f}")
    if not parts:
        return ""
    return "Why now: " + " and ".join(parts) + "."


def _action_line_evidence_only(
    cluster: VulnerabilityCluster,
    cluster_note: ClusterNote,
) -> str:
    """Return evidence-only action sentence with 'Action:' prefix. Uses fixed_in_versions + dependency only; generic fallback when no fix versions."""
    if cluster_note.fixed_in_versions and len(cluster_note.fixed_in_versions) > 0:
        first_ver = cluster_note.fixed_in_versions[0].strip()
        if first_ver:
            dep = (cluster.dependency or "").strip()
            if dep:
                return f"Action: Upgrade {dep} to {first_ver}."
            return f"Action: Upgrade to {first_ver}."
    return f"Action: {ACTION_FALLBACK_NO_FIX}"


def _scope_hint_line(
    cluster: VulnerabilityCluster,
    affected_services: list[str],
) -> str:
    """Return short scope sentence (e.g. 'Scope: N service(s): a, b; dependency: X; path: Y') or empty."""
    parts: list[str] = []
    has_dep_or_path = bool(
        (cluster.dependency and str(cluster.dependency).strip())
        or (cluster.file_path and str(cluster.file_path).strip())
    )
    if affected_services and len(affected_services) > 0:
        n = len(affected_services)
        if n > 1 or has_dep_or_path:
            if n <= 3:
                parts.append(f"{n} service(s): " + ", ".join(affected_services))
            else:
                parts.append(f"{n} service(s): " + ", ".join(affected_services[:2]) + ", ...")
    if cluster.dependency and str(cluster.dependency).strip():
        parts.append("dependency: " + cluster.dependency.strip())
    if cluster.file_path and str(cluster.file_path).strip():
        parts.append("path: " + cluster.file_path.strip())
    if not parts:
        return ""
    line = "Scope: " + "; ".join(parts) + "."
    if len(line) > SCOPE_HINT_MAX_LENGTH:
        return line[: SCOPE_HINT_MAX_LENGTH - 3].rstrip() + "..."
    return line


def _build_evidence_remediation_narrative(
    cluster: VulnerabilityCluster,
    cluster_note: ClusterNote,
    affected_services: list[str],
) -> str:
    """Build recommended remediation from evidence only: Why now (KEV/EPSS), Action (fix or generic), Scope. Truncates to REMEDIATION_MAX_LENGTH."""
    rationale = _risk_rationale_sentence(cluster_note)
    action = _action_line_evidence_only(cluster, cluster_note)
    scope = _scope_hint_line(cluster, affected_services)
    parts: list[str] = [rationale] if rationale else []
    parts.append(action)
    if scope:
        parts.append(scope)
    return _truncate_remediation(" ".join(parts))


def _build_description(
    cluster: VulnerabilityCluster,
    cluster_note: ClusterNote | None = None,
) -> str:
    """Structured description: vulnerability_id, description, severity, CVSS (or n/a when missing/0), context.
    When cluster_note has enrichment, appends Exploitability evidence section."""
    lines = [
        f"Vulnerability: {cluster.vulnerability_id}",
        f"Description: {cluster.description}",
        f"Severity: {cluster.severity}",
        f"CVSS: {cvss_display(cluster.cvss_score)}",
        f"Finding count: {cluster.finding_count}",
        f"Affected services count: {cluster.affected_services_count}",
    ]
    if cluster.file_path and cluster.file_path.strip():
        lines.append(f"File path: {cluster.file_path.strip()}")
    if cluster.dependency and cluster.dependency.strip():
        lines.append(f"Dependency: {cluster.dependency.strip()}")

    if _has_enrichment_in_note(cluster_note):
        note = cluster_note
        kev_str = "KEV: Yes" if note.kev else "KEV: No"
        epss_short = _epss_text_for_note(note)
        fix_str = "—"
        if note.fixed_in_versions and len(note.fixed_in_versions) > 0:
            fix_str = ", ".join(note.fixed_in_versions[:5])
            if len(fix_str) > 80:
                fix_str = fix_str[:77] + "..."
        compact_line = f"Exploitability: {kev_str} | EPSS: {epss_short} | Fix: {fix_str}"
        lines.append("")
        lines.append(compact_line)

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

    # Recommended remediation: when enrichment (cluster_note) present, use evidence-only narrative (Why now, Action, Scope); else urgency prefix + cluster description or fallback.
    if cluster_note is not None:
        remediation = _build_evidence_remediation_narrative(cluster, cluster_note, services)
    else:
        if cluster.description and cluster.description.strip():
            base_remediation = cluster.description.strip()
        else:
            base_remediation = FALLBACK_REMEDIATION
        remediation = _remediation_with_urgency(base_remediation, None)

    title = _build_title(risk_tier_label, cluster)
    description = _build_description(cluster, cluster_note)
    acceptance_criteria = list(DEFAULT_ACCEPTANCE_CRITERIA)

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
    notes_by_key: dict[tuple[str, str], ClusterNote] | None = None,
    tier_by_id: dict[str, ClusterRiskTierResult] | None = None,
    affected_services_by_id: dict[str, list[str]] | None = None,
) -> list[DevTicketPayload]:
    """
    Convert multiple clusters to ticket payloads using optional per-cluster data.

    - notes_by_key: (vulnerability_id, dependency) -> ClusterNote (for recommended_remediation, EPSS/KEV).
    - tier_by_id: vulnerability_id -> ClusterRiskTierResult (for risk_tier_label).
    - affected_services_by_id: vulnerability_id -> list of repo names (for repo=="multiple").
    """
    notes = notes_by_key or {}
    tiers = tier_by_id or {}
    services_by_id = affected_services_by_id or {}
    return [
        cluster_to_ticket_payload(
            c,
            affected_services=services_by_id.get(c.vulnerability_id),
            cluster_note=notes.get((c.vulnerability_id, c.dependency or "")),
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
