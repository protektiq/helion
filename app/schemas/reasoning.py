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
    # Grounded evidence (optional; set when enrichment runs).
    kev: bool | None = Field(
        default=None,
        description="True if CISA KEV catalog lists this vulnerability.",
    )
    epss: float | None = Field(
        default=None,
        ge=0,
        le=1,
        description="EPSS exploit probability (0-1); None if not available.",
    )
    epss_display: str | None = Field(
        default=None,
        max_length=120,
        description="Human-readable EPSS line for tickets (e.g. '0.94 (99.99 percentile)', 'Not applicable (GHSA-only)').",
    )
    epss_percentile: float | None = Field(
        default=None,
        ge=0,
        le=1,
        description="EPSS percentile (0-1) when available; None otherwise.",
    )
    epss_status: Literal["AVAILABLE", "NOT_APPLICABLE", "NOT_FOUND", "ERROR"] | None = Field(
        default=None,
        description="EPSS state: AVAILABLE, NOT_APPLICABLE, NOT_FOUND, or ERROR.",
    )
    epss_reason: str | None = Field(
        default=None,
        max_length=64,
        description="Short reason when EPSS not available (e.g. GHSA-only, lookup failed).",
    )
    fixed_in_versions: list[str] | None = Field(
        default=None,
        max_length=50,
        description="Fix versions from OSV/advisories.",
    )
    package_ecosystem: str | None = Field(
        default=None,
        max_length=32,
        description="Package ecosystem (e.g. npm, pypi, maven).",
    )
    evidence: list[str] | None = Field(
        default=None,
        max_length=30,
        description="Short evidence strings (e.g. 'KEV listed', 'EPSS 0.12').",
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

    job_id: int = Field(
        ...,
        description="Upload job ID; required for enrichment persistence.",
    )
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
    max_clusters: int = Field(
        default=20,
        ge=1,
        le=100,
        description="Maximum number of clusters to assess; applied after loading or parsing.",
    )
