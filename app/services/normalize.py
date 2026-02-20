"""Normalize raw scanner findings to the unified internal representation."""

import json
import re
from typing import Literal

from app.schemas.findings import (
    NormalizedFinding,
    RawFinding,
    _validate_cvss,
    _validate_severity,
)

SeverityLevel = Literal["critical", "high", "medium", "low", "info"]

# Defaults for required NormalizedFinding fields when raw has missing/empty values.
_DEFAULT_VULN_ID = "unknown"
_DEFAULT_SEVERITY = "info"
_DEFAULT_REPO = "unknown"
_DEFAULT_CVSS = 0.0
_DEFAULT_DESCRIPTION = "No description"
_EMPTY_STR = ""

# Severity aliases (case-insensitive) -> canonical level.
_SEVERITY_ALIASES: dict[str, SeverityLevel] = {
    "critical": "critical",
    "crit": "critical",
    "1": "critical",
    "high": "high",
    "2": "high",
    "medium": "medium",
    "med": "medium",
    "moderate": "medium",
    "3": "medium",
    "low": "low",
    "4": "low",
    "info": "info",
    "informational": "info",
    "informative": "info",
    "0": "info",
    "5": "info",
}

# CVSS score bands -> severity (used when severity field is missing or invalid).
_CVSS_TO_SEVERITY: list[tuple[tuple[float, float], SeverityLevel]] = [
    ((9.0, 10.0), "critical"),
    ((7.0, 8.99), "high"),
    ((4.0, 6.99), "medium"),
    ((0.1, 3.99), "low"),
    ((0.0, 0.09), "info"),
]

# CVE: CVE-YEAR-NNNNN+ (4+ digits after second hyphen).
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
# GHSA: GHSA-xxxx-xxxx-xxxx (4 alphanumeric groups).
_GHSA_PATTERN = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.IGNORECASE)

MAX_VULN_ID_LENGTH = 255


def normalize_severity(raw_severity: str | None, raw_cvss: float | None) -> SeverityLevel:
    """
    Map raw severity string and/or CVSS score to canonical SeverityLevel.
    Tries aliases and numeric first, then CVSS bands when severity is missing or invalid.
    """
    if raw_severity and raw_severity.strip():
        normalized = raw_severity.strip().lower()
        if normalized in _SEVERITY_ALIASES:
            return _SEVERITY_ALIASES[normalized]
        # Numeric string 0-5
        if normalized.isdigit():
            n = int(normalized)
            if n <= 0 or n >= 5:
                return "info"
            if n == 1:
                return "critical"
            if n == 2:
                return "high"
            if n == 3:
                return "medium"
            return "low"
    # Fallback: derive from CVSS
    if raw_cvss is not None and 0 <= raw_cvss <= 10:
        for (lo, hi), sev in _CVSS_TO_SEVERITY:
            if lo <= raw_cvss <= hi:
                return sev
    return _DEFAULT_SEVERITY  # type: ignore[return-value]


def extract_cve(text: str | None) -> str | None:
    """Return the first CVE identifier found in text, or None. Bounded to MAX_VULN_ID_LENGTH."""
    if not text or not isinstance(text, str):
        return None
    match = _CVE_PATTERN.search(text)
    if not match:
        return None
    value = match.group(0)
    if len(value) > MAX_VULN_ID_LENGTH:
        return None
    return value


def extract_ghsa(text: str | None) -> str | None:
    """Return the first GHSA identifier found in text, or None. Bounded to MAX_VULN_ID_LENGTH."""
    if not text or not isinstance(text, str):
        return None
    match = _GHSA_PATTERN.search(text)
    if not match:
        return None
    value = match.group(0)
    if len(value) > MAX_VULN_ID_LENGTH:
        return None
    return value


def _is_cve_or_ghsa_like(value: str | None) -> bool:
    """True if value looks like a CVE or GHSA id (so we don't overwrite it)."""
    if not value or not value.strip():
        return False
    return _CVE_PATTERN.fullmatch(value.strip()) is not None or _GHSA_PATTERN.fullmatch(value.strip()) is not None


def _resolve_vulnerability_id(raw: RawFinding) -> str:
    """Resolve vulnerability_id: use raw if CVE/GHSA-like, else extract from text, else default."""
    raw_id = (raw.vulnerability_id or "").strip()
    if raw_id and _is_cve_or_ghsa_like(raw_id):
        return raw_id[:MAX_VULN_ID_LENGTH]
    # Concatenate candidate text for extraction.
    parts = [raw_id, raw.description or "",]
    if raw.raw_payload:
        try:
            parts.append(json.dumps(raw.raw_payload))
        except (TypeError, ValueError):
            parts.append(str(raw.raw_payload))
    text = " ".join(p for p in parts if p)
    extracted = extract_cve(text) or extract_ghsa(text)
    if extracted:
        return extracted
    return raw_id if raw_id else _DEFAULT_VULN_ID


def _canonical_key(
    vulnerability_id: str,
    repo: str,
    file_path: str,
    dependency: str,
) -> tuple[str, str, str, str]:
    """Build a canonical key for deduplication: stripped and path-normalized."""
    vid = (vulnerability_id or "").strip()
    r = (repo or "").strip()
    fp = (file_path or "").strip().replace("\\", "/")
    dep = (dependency or "").strip()
    return (vid, r, fp, dep)


def deduplicate_finding_pairs(
    pairs: list[tuple[RawFinding, NormalizedFinding]],
) -> list[tuple[RawFinding, NormalizedFinding]]:
    """
    Remove duplicates by canonical key (vulnerability_id, repo, file_path, dependency).
    Keeps the first occurrence of each key; preserves (raw, normalized) for traceability.
    """
    seen: set[tuple[str, str, str, str]] = set()
    result: list[tuple[RawFinding, NormalizedFinding]] = []
    for raw, norm in pairs:
        key = _canonical_key(
            norm.vulnerability_id,
            norm.repo,
            norm.file_path,
            norm.dependency,
        )
        if key in seen:
            continue
        seen.add(key)
        result.append((raw, norm))
    return result


def normalize_finding(raw: RawFinding) -> NormalizedFinding:
    """
    Convert a validated RawFinding to NormalizedFinding using sensible defaults.

    Standardizes severity (aliases, numeric, CVSS fallback), extracts CVE/GHSA
    when vulnerability_id is not already in that form, and fills missing fields.
    """
    vulnerability_id = _resolve_vulnerability_id(raw)
    severity = normalize_severity(raw.severity, raw.cvss_score)
    _validate_severity(severity)  # ensure type matches SeverityLevel
    repo = raw.repo if raw.repo and raw.repo.strip() else _DEFAULT_REPO
    file_path = (raw.file_path or "").strip() if raw.file_path is not None else _EMPTY_STR
    dependency = (raw.dependency or "").strip() if raw.dependency is not None else _EMPTY_STR
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
