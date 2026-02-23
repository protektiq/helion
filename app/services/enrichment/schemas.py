"""Pydantic schemas for enrichment payload (JSONB shape and evidence)."""

from pydantic import BaseModel, Field


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
