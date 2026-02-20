"""Pydantic schemas for the reasoning endpoint: request, response, and LLM output shape."""

from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.findings import VulnerabilityCluster


class ClusterNote(BaseModel):
    """Per-cluster note: LLM priority and reasoning, plus optional deterministic tier assignment."""

    vulnerability_id: str = Field(
        ...,
        min_length=1,
        description="Canonical identifier of the cluster (e.g. CVE, rule ID).",
    )
    priority: str = Field(
        ...,
        min_length=1,
        description="Suggested priority label from LLM (e.g. high, medium, low, critical).",
    )
    reasoning: str = Field(
        ...,
        description="Short explanation or remediation hint for this cluster from the LLM.",
    )
    assigned_tier: Literal[1, 2, 3] | None = Field(
        default=None,
        description="Final risk tier (1=highest, 3=lowest) from deterministic override rules; set when tier assignment runs.",
    )
    override_applied: str | None = Field(
        default=None,
        description="Override rule that applied (e.g. cvss_high, dev_only_downgrade), or None.",
    )


class ReasoningResponse(BaseModel):
    """Structured response from the reasoning service (LLM output)."""

    summary: str = Field(
        ...,
        description="Short overall assessment of the vulnerability clusters.",
    )
    cluster_notes: list[ClusterNote] = Field(
        ...,
        description="One entry per cluster (or notable clusters) with priority and reasoning.",
    )


class ReasoningRequest(BaseModel):
    """Request body for POST /api/v1/reasoning."""

    clusters: list[VulnerabilityCluster] = Field(
        ...,
        min_length=0,
        max_length=100,
        description="Vulnerability clusters to send to the LLM for reasoning.",
    )
    use_db: bool = Field(
        default=False,
        description="If true, ignore clusters in body and load current clusters from DB.",
    )
