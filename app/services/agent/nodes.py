"""Agent nodes: enrich, assess, llm_finalize, validate."""

import json
import logging
from typing import TYPE_CHECKING, Any

import httpx

from app.schemas.exploitability import (
    ADJUSTED_RISK_TIER_VALUES,
    AdjustedRiskTier,
    ExploitabilityOutput,
)
from app.schemas.findings import VulnerabilityCluster
from app.services.enrichment import enrich_cluster
from app.services.enrichment.schemas import ClusterEnrichmentPayload
from app.services.reasoning import ReasoningServiceError, _extract_json_object
from app.services.risk_tier import (
    assess_tier_from_enrichment,
    validate_grounded_tier,
)

if TYPE_CHECKING:
    from app.core.config import Settings

from app.services.agent.state import ExploitabilityAgentState

logger = logging.getLogger(__name__)

DEBUG_LOG_PREFIX_LEN = 800

# Tier number to adjusted_risk_tier string for ExploitabilityOutput.
TIER_TO_ADJUSTED: dict[int, AdjustedRiskTier] = {
    1: "critical",
    2: "high",
    3: "medium",
}


def _normalize_adjusted_tier(value: str) -> AdjustedRiskTier:
    if not value or not isinstance(value, str):
        return "high"
    normalized = value.strip().lower()
    if normalized in ADJUSTED_RISK_TIER_VALUES:
        return normalized  # type: ignore[return-value]
    if normalized in ("crit", "critical"):
        return "critical"
    if normalized in ("med", "medium", "moderate"):
        return "medium"
    if normalized in ("informational", "info"):
        return "info"
    return "high"


async def enrich_node(
    state: ExploitabilityAgentState,
    *,
    settings: "Settings",
) -> ExploitabilityAgentState:
    """Run enrichment for the cluster; persist optional (caller can do it)."""
    cluster = state["cluster"]
    if not isinstance(cluster, VulnerabilityCluster):
        cluster = VulnerabilityCluster.model_validate(cluster)
    payload, raw = await enrich_cluster(cluster, settings)
    return {
        "enrichment_payload": payload,
        "enrichment_raw": raw,
    }


def assess_node(state: ExploitabilityAgentState) -> ExploitabilityAgentState:
    """Rules-first suggested tier from enrichment."""
    cluster = state["cluster"]
    if not isinstance(cluster, VulnerabilityCluster):
        cluster = VulnerabilityCluster.model_validate(cluster)
    payload: ClusterEnrichmentPayload = state["enrichment_payload"]
    tier, reason = assess_tier_from_enrichment(
        payload,
        cluster.cvss_score,
        cluster.severity,
        is_dev_only=False,
    )
    return {
        "assessed_tier": tier,
        "assessed_reason": reason,
    }


GROUNDED_PROMPT_TEMPLATE = """You are a security analyst. Use ONLY the evidence and inputs below. Do not invent facts.

Cluster:
- vulnerability_id: {vulnerability_id}
- severity: {severity}
- cvss_score: {cvss_score}
- repo: {repo}
- dependency: {dependency}
- description: {description}

Evidence (from KEV/EPSS/OSV):
- KEV listed: {kev}
- EPSS: {epss}
- Fix versions: {fixed_in_versions}
- Package ecosystem: {package_ecosystem}
- Evidence: {evidence}

Rules-based assessment: {assessed_reason} (suggested tier: {assessed_tier})

Output exactly one JSON object with no other text, no markdown:
{{
  "adjusted_risk_tier": "critical" | "high" | "medium" | "low" | "info",
  "reasoning": "1-3 sentences citing the evidence above.",
  "recommended_action": "One concrete action (e.g. upgrade to fixed version X)."
}}
"""


async def llm_finalize_node(
    state: ExploitabilityAgentState,
    *,
    settings: "Settings",
) -> ExploitabilityAgentState:
    """Call Ollama with grounded prompt; return parsed JSON."""
    cluster = state["cluster"]
    if not isinstance(cluster, VulnerabilityCluster):
        cluster = VulnerabilityCluster.model_validate(cluster)
    payload: ClusterEnrichmentPayload = state["enrichment_payload"]
    assessed_tier: int = state.get("assessed_tier") or 2
    assessed_reason: str = state.get("assessed_reason") or ""

    epss_str = f"{payload.epss:.2f}" if payload.epss is not None else "n/a"
    fixed_str = ", ".join(payload.fixed_in_versions[:10]) if payload.fixed_in_versions else "n/a"
    evidence_str = "; ".join(payload.evidence[:15]) if payload.evidence else "n/a"

    prompt = GROUNDED_PROMPT_TEMPLATE.format(
        vulnerability_id=cluster.vulnerability_id,
        severity=cluster.severity,
        cvss_score=cluster.cvss_score,
        repo=cluster.repo or "n/a",
        dependency=cluster.dependency or "n/a",
        description=(cluster.description or "")[:500],
        kev=payload.kev,
        epss=epss_str,
        fixed_in_versions=fixed_str,
        package_ecosystem=payload.package_ecosystem or "n/a",
        evidence=evidence_str,
        assessed_reason=assessed_reason,
        assessed_tier=assessed_tier,
    )
    base_url = settings.OLLAMA_BASE_URL.rstrip("/")
    url = f"{base_url}/api/generate"
    request_payload = {
        "model": settings.OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": settings.OLLAMA_TEMPERATURE,
            "top_p": settings.OLLAMA_TOP_P,
            "repeat_penalty": settings.OLLAMA_REPEAT_PENALTY,
            "seed": settings.OLLAMA_SEED,
        },
    }
    timeout = httpx.Timeout(settings.OLLAMA_REQUEST_TIMEOUT_SEC)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=request_payload)
    except (httpx.ConnectError, httpx.TimeoutException) as e:
        raise ReasoningServiceError(
            "Ollama is unreachable or timed out.",
            cause=e,
        ) from e
    if response.status_code != 200:
        raise ReasoningServiceError(
            f"Ollama returned status {response.status_code}.",
        )
    try:
        body = response.json()
    except json.JSONDecodeError as e:
        raise ReasoningServiceError("Ollama response not valid JSON.", cause=e) from e
    raw_response = body.get("response")
    if raw_response is None:
        raise ReasoningServiceError("Ollama response missing 'response'.")
    if isinstance(raw_response, str):
        try:
            parsed = json.loads(_extract_json_object(raw_response))
        except json.JSONDecodeError as e:
            logger.warning(
                "LLM returned invalid JSON",
                extra={"raw_prefix": raw_response[:DEBUG_LOG_PREFIX_LEN]},
            )
            raise ReasoningServiceError("Invalid JSON from model.", cause=e) from e
    else:
        parsed = raw_response
    if not isinstance(parsed, dict):
        raise ReasoningServiceError("Model output is not a JSON object.")
    tier_raw = parsed.get("adjusted_risk_tier")
    if isinstance(tier_raw, str):
        parsed["adjusted_risk_tier"] = _normalize_adjusted_tier(tier_raw)
    return {"llm_output": parsed}


def validate_node(state: ExploitabilityAgentState) -> ExploitabilityAgentState:
    """Schema + sanity checks; build ExploitabilityOutput with grounded fields."""
    cluster = state["cluster"]
    if not isinstance(cluster, VulnerabilityCluster):
        cluster = VulnerabilityCluster.model_validate(cluster)
    payload: ClusterEnrichmentPayload = state["enrichment_payload"]
    assessed_tier: int = state.get("assessed_tier") or 2
    llm_out: dict[str, Any] = state.get("llm_output") or {}
    llm_tier_str = llm_out.get("adjusted_risk_tier")

    final_tier, validation_notes = validate_grounded_tier(
        payload,
        assessed_tier,
        llm_tier_str,
        allow_tier1_without_evidence=False,
    )
    adjusted_tier_str: AdjustedRiskTier = TIER_TO_ADJUSTED.get(
        final_tier, "high"
    )
    reasoning = (llm_out.get("reasoning") or "").strip() or "No reasoning provided."
    recommended_action = (
        (llm_out.get("recommended_action") or "").strip()
        or "Review and remediate per security guidance."
    )
    if len(reasoning) > 500:
        reasoning = reasoning[:497] + "..."
    if len(recommended_action) > 300:
        recommended_action = recommended_action[:297] + "..."

    out = ExploitabilityOutput(
        adjusted_risk_tier=adjusted_tier_str,
        reasoning=reasoning,
        recommended_action=recommended_action,
        kev=payload.kev,
        epss=payload.epss,
        fixed_in_versions=payload.fixed_in_versions or None,
        package_ecosystem=payload.package_ecosystem,
        evidence=payload.evidence or None,
    )
    return {
        "validated_output": out,
        "validation_notes": validation_notes,
    }
