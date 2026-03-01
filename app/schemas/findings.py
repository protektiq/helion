"""Pydantic schemas for vulnerability findings: raw ingestion, normalized internal representation, and clusters."""

from typing import Literal

from pydantic import BaseModel, Field, field_validator

# Reusable severity levels for validation and type safety across schemas.
SeverityLevel = Literal["critical", "high", "medium", "low", "info"]

SEVERITY_VALUES: frozenset[str] = frozenset({"critical", "high", "medium", "low", "info"})


def _validate_severity(value: str) -> str:
    """Ensure severity is one of the allowed values (case-insensitive)."""
    if not value or not value.strip():
        raise ValueError("severity must be non-empty")
    normalized = value.strip().lower()
    if normalized not in SEVERITY_VALUES:
        raise ValueError(
            f"severity must be one of {sorted(SEVERITY_VALUES)}, got {value!r}"
        )
    return normalized


def _validate_cvss(value: float | None) -> float | None:
    """Ensure CVSS score is in [0, 10] when present."""
    if value is None:
        return None
    if not 0 <= value <= 10:
        raise ValueError("cvss_score must be between 0 and 10")
    return value


class RawFinding(BaseModel):
    """Scanner-agnostic raw finding for ingestion. All fields optional to accept varying scanner outputs."""

    model_config = {"extra": "ignore"}

    vulnerability_id: str | None = Field(
        default=None,
        description="Identifier for the vulnerability (e.g. CVE, GHSA).",
    )
    severity: str | None = Field(
        default=None,
        description="Severity level: critical, high, medium, low, or info.",
    )
    repo: str | None = Field(
        default=None,
        description="Repository identifier or path.",
    )
    file_path: str | None = Field(
        default=None,
        description="Path to the affected file within the repo.",
    )
    dependency: str | None = Field(
        default=None,
        description="Affected dependency name or coordinates (e.g. package@version).",
    )
    cvss_score: float | None = Field(
        default=None,
        ge=0,
        le=10,
        description="CVSS score in range 0.0–10.0.",
    )
    description: str | None = Field(
        default=None,
        description="Human-readable description of the vulnerability.",
    )
    scanner_source: str | None = Field(
        default=None,
        description="Identifier of the scanner that produced this finding.",
    )
    raw_payload: dict | None = Field(
        default=None,
        description="Original scanner payload for traceability.",
    )

    # Severity is not strictly validated here; the normalizer maps aliases/numeric/CVSS to canonical levels.

    @field_validator("cvss_score")
    @classmethod
    def validate_cvss_if_present(cls, v: float | None) -> float | None:
        return _validate_cvss(v)


class NormalizedFinding(BaseModel):
    """Unified internal representation of a single finding, regardless of scanner."""

    vulnerability_id: str = Field(
        ...,
        min_length=1,
        description="Identifier for the vulnerability (e.g. CVE, GHSA).",
    )
    severity: SeverityLevel = Field(
        ...,
        description="Severity level: critical, high, medium, low, or info.",
    )
    repo: str = Field(
        ...,
        min_length=1,
        description="Repository identifier or path.",
    )
    file_path: str = Field(
        default="",
        description="Path to the affected file within the repo; empty for repo-level or non-file findings.",
    )
    dependency: str = Field(
        default="",
        description="Affected dependency name or coordinates; empty for non-SCA findings.",
    )
    cvss_score: float = Field(
        ...,
        ge=0,
        le=10,
        description="CVSS score in range 0.0–10.0.",
    )
    description: str = Field(
        ...,
        min_length=1,
        description="Human-readable description of the vulnerability.",
    )


class VulnerabilityCluster(BaseModel):
    """One logical vulnerability (e.g. one CVE) that may appear in multiple repos/files, with canonical fields and references to normalized findings."""

    vulnerability_id: str = Field(
        ...,
        min_length=1,
        description="Canonical identifier for the vulnerability (e.g. CVE, GHSA).",
    )
    severity: SeverityLevel = Field(
        ...,
        description="Canonical severity for the cluster.",
    )
    repo: str = Field(
        ...,
        min_length=1,
        description="Single repository when affected_services_count is 1; 'multiple' when the cluster spans more than one repo.",
    )
    file_path: str = Field(
        default="",
        description="Primary or canonical file path for this cluster; empty if not file-specific.",
    )
    dependency: str = Field(
        default="",
        description="Affected dependency; empty if not dependency-related.",
    )
    cvss_score: float = Field(
        ...,
        ge=0,
        le=10,
        description="Canonical CVSS score in range 0.0–10.0.",
    )
    description: str = Field(
        ...,
        min_length=1,
        description="Canonical description of the vulnerability.",
    )
    finding_ids: list[str] = Field(
        ...,
        min_length=1,
        description="IDs of normalized findings that belong to this cluster.",
    )
    affected_services_count: int = Field(
        ...,
        ge=1,
        description="Count of distinct repositories (services) affected by this cluster.",
    )
    finding_count: int = Field(
        ...,
        ge=1,
        description="Number of findings in this cluster (len(finding_ids)).",
    )


class CompressionMetrics(BaseModel):
    """Metrics for clustering compression: raw finding count vs cluster count."""

    raw_finding_count: int = Field(
        ...,
        ge=0,
        description="Total number of findings (DB rows) before clustering.",
    )
    cluster_count: int = Field(
        ...,
        ge=0,
        description="Number of distinct vulnerability clusters.",
    )
    compression_ratio: float = Field(
        ...,
        ge=0,
        description="Raw findings per cluster (raw_finding_count / cluster_count); 0 when cluster_count is 0.",
    )


# --- Semgrep rule analytics (SAST triage / workshop credibility) ---

class RuleCount(BaseModel):
    """One rule and its finding count for 'top by volume' analytics."""

    rule_id: str = Field(
        ...,
        min_length=1,
        description="Semgrep rule id (check_id), stored as vulnerability_id on findings.",
    )
    count: int = Field(
        ...,
        ge=0,
        description="Number of findings for this rule.",
    )


class RuleSeverityDisagreement(BaseModel):
    """Rule that has more than one severity across its findings (noise / misconfiguration signal)."""

    rule_id: str = Field(
        ...,
        min_length=1,
        description="Semgrep rule id.",
    )
    severity_counts: dict[str, int] = Field(
        ...,
        description="Severity -> count for this rule (multiple keys indicate disagreement).",
    )


# Cap list sizes for rule summary to keep response bounded.
TOP_NOISY_RULES_LIMIT = 20
RULES_DISAGREEMENT_LIMIT = 20


class RuleSummary(BaseModel):
    """Rule-level analytics for Semgrep SAST: top noisy rules and rules with severity disagreement."""

    top_noisy_rules: list[RuleCount] = Field(
        default_factory=list,
        max_length=TOP_NOISY_RULES_LIMIT,
        description="Rules with highest finding count (top N).",
    )
    rules_with_severity_disagreement: list[RuleSeverityDisagreement] = Field(
        default_factory=list,
        max_length=RULES_DISAGREEMENT_LIMIT,
        description="Rules that have more than one severity across findings.",
    )


class ClustersResponse(BaseModel):
    """Response for GET /api/v1/clusters: clusters plus compression metrics."""

    clusters: list[VulnerabilityCluster] = Field(
        ...,
        description="Distinct vulnerability clusters (SCA by CVE+dependency, SAST by rule+path).",
    )
    metrics: CompressionMetrics = Field(
        ...,
        description="Compression metrics: raw_finding_count, cluster_count, compression_ratio.",
    )
    rule_summary: RuleSummary | None = Field(
        default=None,
        description="Rule-level analytics for Semgrep findings (top noisy rules, severity disagreement); None when no Semgrep data.",
    )
