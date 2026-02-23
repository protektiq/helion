"""Cluster signature generator: deterministic keys for SCA/SAST (Layer A) and optional semantic id for Layer B."""

import hashlib
import re
from typing import TYPE_CHECKING

from app.services.normalize import _is_cve_or_ghsa_like

if TYPE_CHECKING:
    from app.models.finding import Finding

# Max length for signature components to avoid unbounded hashes.
_MAX_COMPONENT_LEN = 2048
# PURL prefix pattern: pkg:type/name@version
_PURL_ECOSYSTEM_RE = re.compile(r"^pkg:([^/]+)/", re.IGNORECASE)


def _normalize_package_name(name: str) -> str:
    """Lowercase, strip whitespace, strip common version suffix (e.g. @1.2.3)."""
    if not name or not isinstance(name, str):
        return ""
    s = name.strip().lower()
    if not s:
        return ""
    # Strip @version or @version-range at end.
    at = s.rfind("@")
    if at > 0:
        s = s[:at]
    return s[: _MAX_COMPONENT_LEN]


def _ecosystem_from_raw_payload(raw_payload: dict | None) -> str:
    """Extract ecosystem from Trivy/Snyk-style raw_payload. Returns normalized string or empty."""
    if not raw_payload or not isinstance(raw_payload, dict):
        return ""
    # Trivy: DataSource.ID (e.g. "ghsa" for npm) or PkgIdentifier.PURL
    ds = raw_payload.get("DataSource")
    if isinstance(ds, dict) and ds.get("ID"):
        id_val = ds.get("ID", "")
        if isinstance(id_val, str):
            return id_val.strip().lower()[:64]
    purl = raw_payload.get("PkgIdentifier") if isinstance(raw_payload.get("PkgIdentifier"), dict) else None
    if purl and purl.get("PURL"):
        purl_str = purl.get("PURL") or ""
        if isinstance(purl_str, str):
            m = _PURL_ECOSYSTEM_RE.match(purl_str.strip())
            if m:
                return m.group(1).strip().lower()[:64]
    # Snyk-style: package manager in payload
    if "packageManager" in raw_payload and isinstance(raw_payload["packageManager"], str):
        return raw_payload["packageManager"].strip().lower()[:64]
    return ""


def _sca_deterministic_key(
    vulnerability_id: str,
    dependency: str,
    raw_payload: dict | None,
) -> str:
    """
    Build deterministic SCA key: (vuln_id, ecosystem, package_name).
    Collapses transitive: same vuln + same package across lockfiles → one cluster.
    """
    vid = (vulnerability_id or "").strip()[: _MAX_COMPONENT_LEN]
    if not vid:
        vid = "unknown"
    ecosystem = _ecosystem_from_raw_payload(raw_payload)
    # Package name: from dependency field, or from raw (Trivy PkgName)
    pkg = (dependency or "").strip()
    if raw_payload and isinstance(raw_payload, dict) and raw_payload.get("PkgName"):
        pn = raw_payload.get("PkgName")
        if isinstance(pn, str) and pn.strip():
            pkg = pn.strip()
    pkg_normalized = _normalize_package_name(pkg)
    if not pkg_normalized:
        pkg_normalized = "unknown"
    # Key: vuln_id \0 ecosystem \0 package_name (ecosystem optional for grouping)
    return f"{vid}\0{ecosystem}\0{pkg_normalized}"


def _sast_signature_from_raw_payload(
    rule_id: str,
    description: str,
    raw_payload: dict | None,
) -> str:
    """
    Build stable SAST signature from rule_id + message + CWE (no file path).
    Same pattern in different files gets the same signature.
    """
    parts: list[str] = [rule_id or "unknown"]
    message = ""
    cwe = ""
    if raw_payload and isinstance(raw_payload, dict):
        extra = raw_payload.get("extra")
        if isinstance(extra, dict) and extra.get("message"):
            msg = extra.get("message")
            if isinstance(msg, str) and msg.strip():
                message = msg.strip()[: _MAX_COMPONENT_LEN]
        meta = raw_payload.get("metadata")
        if isinstance(meta, dict) and meta.get("cwe"):
            cwe_list = meta.get("cwe")
            if isinstance(cwe_list, list) and cwe_list:
                first = cwe_list[0]
                if isinstance(first, str) and first.strip():
                    cwe = first.strip()[:256]
    if not message and (description or "").strip():
        message = (description or "").strip()[: _MAX_COMPONENT_LEN]
    # Normalize: lowercase for consistency; remove line/column suffixes like "(path:line)"
    if message:
        message = re.sub(r"\s*\([^)]*:\d+\)\s*$", "", message).strip().lower()
    parts.append(message)
    parts.append(cwe.lower() if cwe else "")
    combined = "\0".join(parts)
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


def _file_path_pattern(repo: str, file_path: str) -> str:
    """Normalize file path for SAST fallback: strip repo prefix, normalize slashes."""
    if not file_path or not (file_path or "").strip():
        return ""
    path = (file_path or "").strip().replace("\\", "/")
    if not path:
        return ""
    repo_norm = (repo or "").strip().replace("\\", "/").strip("/")
    if repo_norm and path.startswith(repo_norm + "/"):
        path = path[len(repo_norm) + 1 :].lstrip("/")
    elif repo_norm and path == repo_norm:
        path = ""
    return path[: _MAX_COMPONENT_LEN]


def _sast_deterministic_key(
    vulnerability_id: str,
    repo: str,
    file_path: str,
    description: str,
    raw_payload: dict | None,
) -> str:
    """
    SAST key: (rule_id, normalized_sink/source_signature).
    When raw_payload has message/CWE, use hash of rule+message+CWE so same pattern across files merges.
    Else fall back to rule_id + file_path_pattern (current behavior: different files = different clusters).
    """
    rule_id = (vulnerability_id or "").strip()[: _MAX_COMPONENT_LEN]
    if not rule_id:
        rule_id = "unknown"
    # Only use semantic-style signature when we have message or CWE from raw_payload.
    has_semantic = False
    if raw_payload and isinstance(raw_payload, dict):
        extra = raw_payload.get("extra")
        if isinstance(extra, dict) and (extra.get("message") or "").strip():
            has_semantic = True
        if not has_semantic:
            meta = raw_payload.get("metadata")
            if isinstance(meta, dict) and meta.get("cwe") and isinstance(meta["cwe"], list) and meta["cwe"]:
                has_semantic = True
    if has_semantic:
        sig = _sast_signature_from_raw_payload(rule_id, description or "", raw_payload)
        return f"{rule_id}\0{sig}"
    pattern = _file_path_pattern(repo or "", file_path or "")
    return f"{rule_id}\0{pattern}"


def compute_deterministic_signature(finding: "Finding") -> str:
    """
    Produce a stable cluster key for the finding (Layer A).
    SCA: (vuln_id, ecosystem, package_name); SAST: (rule_id, normalized_signature).
    Returns a string suitable for grouping; same string → same cluster.
    """
    vid = (finding.vulnerability_id or "").strip()
    raw = finding.raw_payload if getattr(finding, "raw_payload", None) else None
    if _is_cve_or_ghsa_like(vid):
        return _sca_deterministic_key(
            finding.vulnerability_id or "",
            finding.dependency or "",
            raw,
        )
    return _sast_deterministic_key(
        finding.vulnerability_id or "",
        finding.repo or "",
        finding.file_path or "",
        finding.description or "",
        raw,
    )


def compute_semantic_signature_id(finding: "Finding") -> str | None:
    """
    Placeholder for Layer B: return embedding/Qdrant point id when available.
    For now returns None; Layer B will set this when embeddings are stored.
    """
    return None
