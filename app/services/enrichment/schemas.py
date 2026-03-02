"""Pydantic schemas for enrichment payload (JSONB shape and evidence)."""

from typing import Literal

from pydantic import BaseModel, Field

# EPSS state for enrichment/reasoning (distinct from client_epss EpssStatus).
EpssStateStatus = Literal["AVAILABLE", "NOT_APPLICABLE", "NOT_FOUND", "ERROR"]


class EpssState(BaseModel):
    """Typed EPSS state: score when available, or reason when not."""

    status: EpssStateStatus = Field(
        ...,
        description="AVAILABLE (score+percentile), NOT_APPLICABLE (GHSA/non-CVE), NOT_FOUND (no record), ERROR (lookup failed).",
    )
    score: float | None = Field(
        default=None,
        ge=0,
        le=1,
        description="EPSS score (0-1) when status is AVAILABLE.",
    )
    percentile: float | None = Field(
        default=None,
        ge=0,
        le=1,
        description="EPSS percentile (0-1) when status is AVAILABLE.",
    )
    reason: str | None = Field(
        default=None,
        max_length=64,
        description="Short reason when not AVAILABLE (e.g. GHSA-only, non-CVE, lookup failed).",
    )


class CvssCheck(BaseModel):
    """CVSS vs severity sanity check result."""

    expected_severity: str = Field(
        ...,
        description="Severity derived from CVSS or external source.",
    )
    mismatch: bool = Field(
        ...,
        description="True if cluster severity disagrees with expected.",
    )


class OsvEntry(BaseModel):
    """Single OSV advisory summary for a cluster."""

    ecosystem: str = Field(
        ...,
        description="Package ecosystem (e.g. npm, pypi, maven).",
    )
    summary: str = Field(
        default="",
        max_length=2000,
        description="Short advisory summary.",
    )
    fixed_in_versions: list[str] = Field(
        default_factory=list,
        max_length=50,
        description="Versions that fix this vulnerability.",
    )


class ClusterEnrichmentPayload(BaseModel):
    """
    Enrichment payload stored in JSONB and passed to assess/LLM.

    All list/string lengths are bounded for safe storage and validation.
    """

    kev: bool = Field(
        default=False,
        description="True if vulnerability is in CISA KEV catalog.",
    )
    epss: float | None = Field(
        default=None,
        ge=0,
        le=1,
        description="EPSS probability (0-1); None if not available (e.g. non-CVE).",
    )
    epss_percentile: float | None = Field(
        default=None,
        ge=0,
        le=1,
        description="EPSS percentile (0-1) when available; None otherwise.",
    )
    epss_display: str | None = Field(
        default=None,
        max_length=120,
        description="Human-readable EPSS line for tickets (e.g. '0.94 (99.99 percentile)', 'Not applicable (GHSA-only)').",
    )
    epss_status: EpssStateStatus | None = Field(
        default=None,
        description="EPSS state: AVAILABLE, NOT_APPLICABLE, NOT_FOUND, or ERROR.",
    )
    epss_reason: str | None = Field(
        default=None,
        max_length=64,
        description="Short reason when EPSS not available (e.g. GHSA-only, lookup failed).",
    )
    osv: list[OsvEntry] = Field(
        default_factory=list,
        max_length=20,
        description="OSV advisory entries (ecosystem, summary, fixed versions).",
    )
    fixed_in_versions: list[str] = Field(
        default_factory=list,
        max_length=50,
        description="Aggregated fix versions from OSV.",
    )
    package_ecosystem: str | None = Field(
        default=None,
        max_length=32,
        description="Detected package ecosystem (e.g. npm, pypi, maven).",
    )
    cvss_check: CvssCheck | None = Field(
        default=None,
        description="Optional CVSS/severity consistency check.",
    )
    evidence: list[str] = Field(
        default_factory=list,
        max_length=30,
        description="Short evidence strings for validator and UI (e.g. 'KEV listed', 'EPSS 0.12').",
    )
