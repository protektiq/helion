"""Pydantic schemas for the reasoning endpoint: request, response, and LLM output shape."""

from pydantic import BaseModel, Field

from app.schemas.findings import VulnerabilityCluster


class ClusterNote(BaseModel):
    """Per-cluster note returned by the LLM: priority and short reasoning."""

    vulnerability_id: str = Field(
        ...,
        min_length=1,
        description="Canonical identifier of the cluster (e.g. CVE, rule ID).",
    )
    priority: str = Field(
        ...,
        min_length=1,
        description="Suggested priority label (e.g. high, medium, low, critical).",
    )
    reasoning: str = Field(
        ...,
        description="Short explanation or remediation hint for this cluster.",
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
