"""Risk tier assignment: deterministic mapping of LLM output and cluster data to Tier 1/2/3 with override rules.

Final tier is always determined by this module (AI-assisted, not AI-dependent). LLM provides
priority and reasoning; override rules (e.g. CVSS > 9 → Tier 1 unless dev-only) take precedence.
"""

from app.schemas.findings import SEVERITY_VALUES, VulnerabilityCluster
from app.schemas.risk_tier import (
    ClusterRiskTierResult,
    RiskTier,
    RiskTierAssignmentInput,
)
from app.schemas.reasoning import ClusterNote, ReasoningResponse

# Override rule thresholds (tunable; no magic numbers in logic).
CVSS_TIER1_THRESHOLD = 9.0  # CVSS > this → Tier 1 unless dev-only
CVSS_TIER2_MIN = 7.0  # CVSS in [7, 9] → at least Tier 2
DEV_ONLY_TIER_WHEN_HIGH_CVSS: RiskTier = 2  # When CVSS > 9 and is_dev_only, assign this tier

# Default tier when priority/severity is missing or invalid (safe default).
DEFAULT_TIER_WHEN_UNKNOWN: RiskTier = 2

# Override identifiers for transparency.
OVERRIDE_CVSS_HIGH = "cvss_high"
OVERRIDE_DEV_ONLY_DOWNGRADE = "dev_only_downgrade"
OVERRIDE_CVSS_BAND_7_9 = "cvss_band_7_9"


def _normalize_priority(priority: str | None) -> str | None:
    """Normalize LLM priority to canonical form (critical, high, medium, low)."""
    if not priority or not isinstance(priority, str) or not priority.strip():
        return None
    normalized = priority.strip().lower()
    if normalized in ("critical", "crit"):
        return "critical"
    if normalized in ("high", "medium", "med", "moderate", "low"):
        return normalized if normalized in ("high", "medium", "low") else (
            "medium" if normalized in ("med", "moderate") else "low"
        )
    return normalized if normalized in ("critical", "high", "medium", "low") else None


def _llm_priority_to_suggested_tier(priority: str | None) -> RiskTier:
    """Map LLM priority to suggested tier (critical→1, high→2, medium/low→3). Unknown → default."""
    canonical = _normalize_priority(priority)
    if canonical == "critical":
        return 1
    if canonical == "high":
        return 2
    if canonical in ("medium", "low"):
        return 3
    return DEFAULT_TIER_WHEN_UNKNOWN


def _severity_to_suggested_tier(severity: str | None) -> RiskTier:
    """Map severity to suggested tier when no LLM output. critical→1, high→2, medium/low/info→3."""
    if not severity or not isinstance(severity, str):
        return DEFAULT_TIER_WHEN_UNKNOWN
    normalized = severity.strip().lower()
    if normalized not in SEVERITY_VALUES:
        return DEFAULT_TIER_WHEN_UNKNOWN
    if normalized == "critical":
        return 1
    if normalized == "high":
        return 2
    return 3  # medium, low, info


def _clamp_cvss(score: float) -> float:
    """Clamp CVSS to [0, 10] for rule evaluation."""
    return max(0.0, min(10.0, score))


def assign_risk_tier(
    cluster: VulnerabilityCluster | RiskTierAssignmentInput,
    llm_note: ClusterNote | None = None,
    is_dev_only: bool = False,
) -> ClusterRiskTierResult:
    """
    Assign Tier 1/2/3 to a single cluster. Override rules run first; then LLM or severity fallback.

    - cluster: VulnerabilityCluster or RiskTierAssignmentInput (must have vulnerability_id, cvss_score, severity).
    - llm_note: optional LLM output (priority, reasoning) for this cluster; used when cluster is VulnerabilityCluster.
    - is_dev_only: when True, CVSS > 9 yields Tier 2 instead of Tier 1; used when cluster is VulnerabilityCluster.
    """
    if isinstance(cluster, RiskTierAssignmentInput):
        vuln_id = cluster.vulnerability_id
        cvss = _clamp_cvss(cluster.cvss_score)
        severity = cluster.severity.strip().lower() if cluster.severity else "info"
        llm_priority = cluster.llm_priority
        llm_reasoning = cluster.llm_reasoning
        is_dev_only = cluster.is_dev_only
    else:
        vuln_id = cluster.vulnerability_id
        cvss = _clamp_cvss(cluster.cvss_score)
        severity = (
            cluster.severity.strip().lower()
            if isinstance(cluster.severity, str) and cluster.severity
            else "info"
        )
        llm_priority = llm_note.priority if llm_note else None
        llm_reasoning = llm_note.reasoning if llm_note else None

    if llm_priority is not None and _normalize_priority(llm_priority) is not None:
        suggested = _llm_priority_to_suggested_tier(llm_priority)
    else:
        suggested = _severity_to_suggested_tier(severity)

    # Apply overrides (order matters).
    if cvss > CVSS_TIER1_THRESHOLD:
        if is_dev_only:
            tier = DEV_ONLY_TIER_WHEN_HIGH_CVSS
            override = OVERRIDE_DEV_ONLY_DOWNGRADE
        else:
            tier = 1
            override = OVERRIDE_CVSS_HIGH
    elif cvss >= CVSS_TIER2_MIN and suggested > 2:
        tier = 2
        override = OVERRIDE_CVSS_BAND_7_9
    else:
        tier = suggested
        override = None

    return ClusterRiskTierResult(
        vulnerability_id=vuln_id,
        assigned_tier=tier,
        llm_reasoning=llm_reasoning,
        override_applied=override,
    )


def _note_by_vuln_id(notes: list[ClusterNote]) -> dict[str, ClusterNote]:
    """Build vulnerability_id -> ClusterNote map (first occurrence wins if duplicates)."""
    out: dict[str, ClusterNote] = {}
    for n in notes:
        if n.vulnerability_id and n.vulnerability_id not in out:
            out[n.vulnerability_id] = n
    return out


def assign_risk_tiers(
    clusters: list[VulnerabilityCluster],
    reasoning_response: ReasoningResponse | None = None,
    cluster_dev_only: dict[str, bool] | None = None,
) -> list[ClusterRiskTierResult]:
    """
    Assign risk tiers to all clusters. Optional LLM response and per-cluster dev-only map.

    - reasoning_response: if provided, cluster_notes are matched by vulnerability_id for priority/reasoning.
    - cluster_dev_only: optional map vulnerability_id -> is_dev_only; missing keys treated as False.
    """
    notes_by_id = _note_by_vuln_id(reasoning_response.cluster_notes) if reasoning_response else {}
    dev_only_map = cluster_dev_only or {}

    results: list[ClusterRiskTierResult] = []
    for c in clusters:
        vid = c.vulnerability_id
        note = notes_by_id.get(vid)
        is_dev = dev_only_map.get(vid, False)
        results.append(assign_risk_tier(c, llm_note=note, is_dev_only=is_dev))
    return results
