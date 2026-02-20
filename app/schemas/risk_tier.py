"""Pydantic schemas for risk tier assignment: Tier 1/2/3 and input/output models."""

from typing import Literal

from pydantic import BaseModel, Field

# Tier 1 = highest risk, Tier 3 = lowest. Final tier is controlled by deterministic rules, not the LLM.
RiskTier = Literal[1, 2, 3]

RISK_TIER_VALUES: frozenset[int] = frozenset({1, 2, 3})


class RiskTierAssignmentInput(BaseModel):
    """Input for assigning a risk tier to a single cluster (inlined fields for the tier logic)."""

    vulnerability_id: str = Field(
        ...,
        min_length=1,
        description="Canonical identifier of the cluster (e.g. CVE, rule ID).",
    )
    cvss_score: float = Field(
        ...,
        ge=0,
        le=10,
        description="CVSS score in range 0.0–10.0.",
    )
    severity: str = Field(
        ...,
        min_length=1,
        description="Canonical severity: critical, high, medium, low, or info.",
    )
    llm_priority: str | None = Field(
        default=None,
        description="LLM-suggested priority (e.g. critical, high, medium, low); optional.",
    )
    llm_reasoning: str | None = Field(
        default=None,
        description="LLM reasoning text; optional, passthrough for display.",
    )
    is_dev_only: bool = Field(
        default=False,
        description="If True, override rules may downgrade (e.g. CVSS > 9 → Tier 2 instead of Tier 1).",
    )


class ClusterRiskTierResult(BaseModel):
    """Result of risk tier assignment for one cluster."""

    vulnerability_id: str = Field(
        ...,
        min_length=1,
        description="Canonical identifier of the cluster.",
    )
    assigned_tier: RiskTier = Field(
        ...,
        description="Final tier (1=highest risk, 3=lowest) after deterministic overrides.",
    )
    llm_reasoning: str | None = Field(
        default=None,
        description="LLM reasoning passthrough when available.",
    )
    override_applied: str | None = Field(
        default=None,
        description="Override rule that applied (e.g. cvss_high, dev_only_downgrade), or None.",
    )
