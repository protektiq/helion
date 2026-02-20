"""Normalize raw scanner findings to the unified internal representation."""

from app.schemas.findings import (
    NormalizedFinding,
    RawFinding,
    _validate_cvss,
    _validate_severity,
)


# Defaults for required NormalizedFinding fields when raw has missing/empty values.
_DEFAULT_VULN_ID = "unknown"
_DEFAULT_SEVERITY = "info"
_DEFAULT_REPO = "unknown"
_DEFAULT_CVSS = 0.0
_DEFAULT_DESCRIPTION = "No description"
_EMPTY_STR = ""


def normalize_finding(raw: RawFinding) -> NormalizedFinding:
    """
    Convert a validated RawFinding to NormalizedFinding using sensible defaults.

    Required NormalizedFinding fields (vulnerability_id, severity, repo,
    cvss_score, description) get default values when raw has None or empty.
    """
    vulnerability_id = raw.vulnerability_id if raw.vulnerability_id and raw.vulnerability_id.strip() else _DEFAULT_VULN_ID
    severity_raw = raw.severity if raw.severity and raw.severity.strip() else _DEFAULT_SEVERITY
    severity = _validate_severity(severity_raw)
    repo = raw.repo if raw.repo and raw.repo.strip() else _DEFAULT_REPO
    file_path = raw.file_path if raw.file_path is not None else _EMPTY_STR
    dependency = raw.dependency if raw.dependency is not None else _EMPTY_STR
    cvss_score = _validate_cvss(raw.cvss_score) if raw.cvss_score is not None else _DEFAULT_CVSS
    description = raw.description if raw.description and raw.description.strip() else _DEFAULT_DESCRIPTION

    return NormalizedFinding(
        vulnerability_id=vulnerability_id,
        severity=severity,
        repo=repo,
        file_path=file_path,
        dependency=dependency,
        cvss_score=cvss_score,
        description=description,
    )
