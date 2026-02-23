"""Typed state for the exploitability agent graph."""

from typing import Any, TypedDict

from app.schemas.exploitability import ExploitabilityOutput
from app.schemas.findings import VulnerabilityCluster
from app.services.enrichment.schemas import ClusterEnrichmentPayload


class ExploitabilityAgentState(TypedDict, total=False):
    """State passed through enrich → assess → llm_finalize → validate."""

    cluster: VulnerabilityCluster
    enrichment_payload: ClusterEnrichmentPayload
    enrichment_raw: dict[str, Any]
    assessed_tier: int  # 1, 2, or 3
    assessed_reason: str
    llm_output: dict[str, Any]  # reasoning, recommended_action, adjusted_risk_tier
    validated_output: ExploitabilityOutput
    validation_notes: list[str]
