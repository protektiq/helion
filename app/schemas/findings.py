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
        description="Primary or canonical repository for this cluster.",
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
