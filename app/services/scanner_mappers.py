"""Map scanner-specific payload shapes to RawFinding field names for ingestion."""

from typing import Any

# RawFinding field names we map into.
RAWFINDING_KEYS = frozenset({
    "vulnerability_id", "severity", "repo", "file_path", "dependency",
    "cvss_score", "description", "scanner_source", "raw_payload",
})

# Generic alias: scanner field name -> RawFinding field name.
# Severity aliases are handled in the normalizer (normalize_severity).
GENERIC_ALIASES: dict[str, str] = {
    "cve_id": "vulnerability_id",
    "cve": "vulnerability_id",
    "id": "vulnerability_id",
    "vulnerability": "vulnerability_id",
    "VulnerabilityID": "vulnerability_id",
    "file": "file_path",
    "path": "file_path",
    "filepath": "file_path",
    "package": "dependency",
    "pkg": "dependency",
    "dependency_name": "dependency",
    "repository": "repo",
    "project": "repo",
    "cvss": "cvss_score",
    "score": "cvss_score",
    "message": "description",
    "title": "description",
    "summary": "description",
    "scanner": "scanner_source",
    "source": "scanner_source",
    "tool": "scanner_source",
}


def _is_trivy_like(obj: dict[str, Any]) -> bool:
    """Heuristic: Trivy often uses VulnerabilityID, Severity."""
    return "VulnerabilityID" in obj or ("Vulnerability" in obj and "ID" in str(obj.get("Vulnerability")))


def _is_snyk_like(obj: dict[str, Any]) -> bool:
    """Heuristic: Snyk often uses issue_id, severity."""
    return "issue_id" in obj and "severity" in obj


def _is_semgrep_like(obj: dict[str, Any]) -> bool:
    """Heuristic: Semgrep often uses check_id, path."""
    return "check_id" in obj and ("path" in obj or "metadata" in obj)


def _is_osv_scanner_like(obj: dict[str, Any]) -> bool:
    """Heuristic: OSV-Scanner flattened shape has package (dict with name+ecosystem) and vuln id."""
    pkg = obj.get("package")
    if not isinstance(pkg, dict) or "name" not in pkg or "ecosystem" not in pkg:
        return False
    vid = obj.get("id") or obj.get("vulnerability_id")
    return isinstance(vid, str) and bool(vid.strip())


def map_trivy_to_raw(obj: dict[str, Any]) -> dict[str, Any]:
    """Map Trivy-style dict to RawFinding-shaped dict. Preserve original in raw_payload."""
    out: dict[str, Any] = {}
    raw = dict(obj)
    # Trivy vuln format: VulnerabilityID, PkgName, Severity, Title, etc.
    if "VulnerabilityID" in obj:
        out["vulnerability_id"] = _str_or_none(obj.get("VulnerabilityID"))
    if "Vulnerability" in obj and isinstance(obj["Vulnerability"], dict):
        v = obj["Vulnerability"]
        out.setdefault("vulnerability_id", _str_or_none(v.get("VulnerabilityID")))
        out.setdefault("severity", _str_or_none(v.get("Severity")))
        out.setdefault("description", _str_or_none(v.get("Description")) or _str_or_none(v.get("Title")))
        if v.get("CVSS") and isinstance(v["CVSS"], dict):
            for k in ("nvd", "redhat", "ghsa"):
                if k in v["CVSS"] and isinstance(v["CVSS"][k], dict):
                    score = v["CVSS"][k].get("V3Score") or v["CVSS"][k].get("V2Score")
                    if score is not None:
                        try:
                            out["cvss_score"] = float(score)
                        except (TypeError, ValueError):
                            pass
                        break
    if "Severity" in obj:
        out.setdefault("severity", _str_or_none(obj.get("Severity")))
    if "PkgName" in obj:
        out.setdefault("dependency", _str_or_none(obj.get("PkgName")))
    if "Title" in obj and "description" not in out:
        out.setdefault("description", _str_or_none(obj.get("Title")))
    if "PrimaryURL" in obj and "vulnerability_id" not in out:
        out.setdefault("vulnerability_id", _str_or_none(obj.get("PrimaryURL")))
    out["scanner_source"] = out.get("scanner_source") or "trivy"
    out["raw_payload"] = raw
    return _merge_rawfinding_shape(out, obj)


def map_snyk_to_raw(obj: dict[str, Any]) -> dict[str, Any]:
    """Map Snyk-style dict to RawFinding-shaped dict. Preserve original in raw_payload."""
    out: dict[str, Any] = {}
    raw = dict(obj)
    if "issue_id" in obj:
        out["vulnerability_id"] = _str_or_none(obj.get("issue_id"))
    if "severity" in obj:
        out["severity"] = _str_or_none(obj.get("severity"))
    if "package" in obj:
        out["dependency"] = _str_or_none(obj.get("package")) if isinstance(obj["package"], str) else _str_or_none(obj.get("package", {}).get("name"))
    if "title" in obj:
        out["description"] = _str_or_none(obj.get("title"))
    if "cvss_score" in obj:
        try:
            out["cvss_score"] = float(obj["cvss_score"])
        except (TypeError, ValueError):
            pass
    out["scanner_source"] = out.get("scanner_source") or "snyk"
    out["raw_payload"] = raw
    return _merge_rawfinding_shape(out, obj)


def map_semgrep_to_raw(obj: dict[str, Any]) -> dict[str, Any]:
    """Map Semgrep-style dict to RawFinding-shaped dict. Preserve original in raw_payload."""
    out: dict[str, Any] = {}
    raw = dict(obj)
    if "check_id" in obj:
        out["vulnerability_id"] = _str_or_none(obj.get("check_id"))
    if "path" in obj:
        out["file_path"] = _str_or_none(obj.get("path"))
    if "extra" in obj and isinstance(obj["extra"], dict):
        extra = obj["extra"]
        out.setdefault("severity", _str_or_none(extra.get("severity")))
        out.setdefault("description", _str_or_none(extra.get("message")))
    if "metadata" in obj and isinstance(obj["metadata"], dict):
        meta = obj["metadata"]
        out.setdefault("severity", _str_or_none(meta.get("severity")))
        out.setdefault("description", out.get("description") or _str_or_none(meta.get("description")))
    out["scanner_source"] = out.get("scanner_source") or "semgrep"
    out["raw_payload"] = raw
    return _merge_rawfinding_shape(out, obj)


def _extract_osv_severity_and_cvss(obj: dict[str, Any]) -> tuple[str | None, float | None]:
    """Extract severity string and CVSS score from OSV-style vuln (severity[] or database_specific)."""
    severity_out: str | None = None
    cvss_out: float | None = None
    sev_list = obj.get("severity")
    if isinstance(sev_list, list) and sev_list:
        for s in sev_list:
            if not isinstance(s, dict):
                continue
            score = s.get("score")
            if score is not None:
                try:
                    cvss_out = float(score)
                except (TypeError, ValueError):
                    pass
                if cvss_out is not None:
                    break
            if severity_out is None:
                severity_out = _str_or_none(s.get("severity"))
    db = obj.get("database_specific")
    if isinstance(db, dict):
        if cvss_out is None:
            score = db.get("cvss_score") or db.get("severity")
            if score is not None:
                try:
                    cvss_out = float(score)
                except (TypeError, ValueError):
                    pass
        if severity_out is None:
            severity_out = _str_or_none(db.get("severity"))
    return (severity_out, cvss_out)


def map_osv_scanner_to_raw(obj: dict[str, Any]) -> dict[str, Any]:
    """Map OSV-Scanner flattened dict to RawFinding-shaped dict. Preserve original in raw_payload."""
    out: dict[str, Any] = {}
    raw = dict(obj)
    pkg = obj.get("package") or {}
    src = obj.get("source") or {}

    # Store package.ecosystem prominently in raw_payload for clustering/analytics grouping.
    if isinstance(pkg, dict) and pkg.get("ecosystem") is not None:
        eco = pkg.get("ecosystem")
        if isinstance(eco, str) and eco.strip():
            raw["package_ecosystem"] = eco.strip().lower()[:64]

    out["vulnerability_id"] = _str_or_none(obj.get("id")) or _str_or_none(obj.get("vulnerability_id"))
    if not out["vulnerability_id"] and isinstance(obj.get("aliases"), list):
        for a in obj["aliases"]:
            if isinstance(a, str) and a.strip().upper().startswith("CVE-"):
                out["vulnerability_id"] = a.strip()
                break

    if isinstance(pkg, dict) and pkg.get("name") is not None:
        out["dependency"] = _str_or_none(pkg.get("name"))
    if isinstance(src, dict) and src.get("path") is not None:
        out["file_path"] = _str_or_none(src.get("path"))

    sev, cvss = _extract_osv_severity_and_cvss(obj)
    if sev:
        out["severity"] = sev
    if cvss is not None and 0 <= cvss <= 10:
        out["cvss_score"] = cvss

    out["description"] = _str_or_none(obj.get("summary")) or _str_or_none(obj.get("details"))
    out["scanner_source"] = "osv-scanner"
    out["raw_payload"] = raw
    return _merge_rawfinding_shape(out, obj)


def _str_or_none(value: Any) -> str | None:
    """Return string or None; coerce non-str to str if sensible."""
    if value is None:
        return None
    if isinstance(value, str):
        return value.strip() or None
    return str(value).strip() or None


def _merge_rawfinding_shape(out: dict[str, Any], obj: dict[str, Any]) -> dict[str, Any]:
    """Ensure only RawFinding keys are present; copy any missing from obj via aliases."""
    result: dict[str, Any] = {}
    for k, v in out.items():
        if k in RAWFINDING_KEYS:
            result[k] = v
    for alias, target in GENERIC_ALIASES.items():
        if target in result:
            continue
        if alias in obj and obj[alias] is not None:
            val = obj[alias]
            if target == "cvss_score" and isinstance(val, (int, float)):
                result[target] = float(val)
            elif isinstance(val, str):
                result[target] = val.strip() or None
            else:
                result[target] = val
    return result


def apply_generic_aliases(obj: dict[str, Any]) -> dict[str, Any]:
    """
    Map known alias keys to RawFinding field names. Does not add raw_payload.
    Use when no scanner-specific mapper is detected.
    """
    result: dict[str, Any] = {}
    for key, value in obj.items():
        if key in RAWFINDING_KEYS:
            result[key] = value
            continue
        if key in GENERIC_ALIASES:
            target = GENERIC_ALIASES[key]
            if target == "cvss_score" and isinstance(value, (int, float)):
                result[target] = float(value)
            elif isinstance(value, str):
                result[target] = value.strip() or None
            else:
                result[target] = value
    if "raw_payload" not in result:
        result["raw_payload"] = dict(obj)
    return result


def normalize_shape_to_rawfinding(obj: dict[str, Any]) -> dict[str, Any]:
    """
    Convert a scanner payload (any dict) to a dict suitable for RawFinding.model_validate.
    Uses scanner heuristics when possible, otherwise generic aliases. Preserves original in raw_payload.
    """
    if not isinstance(obj, dict):
        return obj
    if _is_trivy_like(obj):
        return map_trivy_to_raw(obj)
    if _is_snyk_like(obj):
        return map_snyk_to_raw(obj)
    if _is_semgrep_like(obj):
        return map_semgrep_to_raw(obj)
    if _is_osv_scanner_like(obj):
        return map_osv_scanner_to_raw(obj)
    return apply_generic_aliases(obj)
