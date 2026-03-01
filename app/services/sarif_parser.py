"""Parse SARIF (e.g. CodeQL) reports into RawFinding-shaped dicts for ingestion."""

from urllib.parse import unquote

# SARIF result.level -> Helion canonical severity (case-insensitive).
_SARIF_LEVEL_TO_SEVERITY: dict[str, str] = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}


def _sarif_level_to_severity(level: str | None) -> str:
    """Map SARIF result.level to Helion severity. Default 'info' for none/missing."""
    if not level or not isinstance(level, str):
        return "info"
    normalized = level.strip().lower()
    return _SARIF_LEVEL_TO_SEVERITY.get(normalized, "info")


def _uri_to_file_path(uri: str | None) -> str | None:
    """Normalize SARIF artifact URI to a file path (strip file://, decode)."""
    if not uri or not isinstance(uri, str):
        return None
    s = uri.strip()
    if not s:
        return None
    if s.startswith("file://"):
        s = s[7:]
    return unquote(s) or None


def _get_artifact_uri(artifact_location: dict | None, artifacts: list | None) -> str | None:
    """Resolve artifact URI from artifactLocation (uri or index into run.artifacts)."""
    if not isinstance(artifact_location, dict):
        return None
    uri = artifact_location.get("uri")
    if isinstance(uri, str) and uri.strip():
        return uri.strip()
    idx = artifact_location.get("index")
    if isinstance(idx, int) and isinstance(artifacts, list) and 0 <= idx < len(artifacts):
        art = artifacts[idx]
        if isinstance(art, dict):
            loc = art.get("location")
            if isinstance(loc, dict):
                u = loc.get("uri")
                if isinstance(u, str) and u.strip():
                    return u.strip()
    return None


def _get_result_file_path(result: dict, run: dict) -> str | None:
    """Extract file path from first location of result, using run.artifacts if needed."""
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        return None
    loc = locations[0]
    if not isinstance(loc, dict):
        return None
    phys = loc.get("physicalLocation")
    if not isinstance(phys, dict):
        return None
    art_loc = phys.get("artifactLocation")
    artifacts = run.get("artifacts")
    uri = _get_artifact_uri(art_loc, artifacts)
    return _uri_to_file_path(uri) if uri else None


def _get_result_message(result: dict) -> str:
    """Extract message text from result.message (dict with .text or string)."""
    msg = result.get("message")
    if isinstance(msg, str):
        return msg.strip() or "No description"
    if isinstance(msg, dict):
        text = msg.get("text")
        if isinstance(text, str):
            return text.strip() or "No description"
    return "No description"


def _get_rule_metadata(rule_id: str | None, run: dict) -> dict:
    """Build rule metadata dict from run.tool.driver.rules for raw_payload."""
    meta: dict = {}
    driver = None
    tool = run.get("tool")
    if isinstance(tool, dict):
        driver = tool.get("driver")
    if not isinstance(driver, dict):
        return meta
    rules = driver.get("rules")
    if not isinstance(rules, list):
        return meta
    rule = None
    if rule_id:
        for r in rules:
            if isinstance(r, dict) and r.get("id") == rule_id:
                rule = r
                break
    if not isinstance(rule, dict):
        return meta
    for key in ("id", "name", "shortDescription", "fullDescription", "helpUri", "precision"):
        val = rule.get(key)
        if val is not None:
            if isinstance(val, dict) and "text" in val:
                meta[key] = val.get("text")
            else:
                meta[key] = val
    props = rule.get("properties")
    if isinstance(props, dict):
        for k, v in props.items():
            if k not in meta and v is not None:
                meta[k] = v
    return meta


def _get_vulnerability_id(result: dict, run: dict) -> str | None:
    """Result ruleId or rule.id from run.tool.driver.rules."""
    rule_id = result.get("ruleId")
    if isinstance(rule_id, str) and rule_id.strip():
        return rule_id.strip()
    rule_ref = result.get("rule")
    if isinstance(rule_ref, dict):
        rid = rule_ref.get("id")
        if isinstance(rid, str) and rid.strip():
            return rid.strip()
        idx = rule_ref.get("index")
        if isinstance(idx, int):
            tool = run.get("tool")
            if isinstance(tool, dict):
                driver = tool.get("driver")
                if isinstance(driver, dict):
                    rules = driver.get("rules")
                    if isinstance(rules, list) and 0 <= idx < len(rules):
                        r = rules[idx]
                        if isinstance(r, dict):
                            rid = r.get("id")
                            if isinstance(rid, str) and rid.strip():
                                return rid.strip()
    return None


def sarif_to_rawfindings(payload: dict) -> list[dict]:
    """
    Convert a SARIF root object to a list of RawFinding-shaped dicts.

    Extracts from each result: vulnerability_id (ruleId), file_path (artifact location),
    description (message text), severity (SARIF level mapped to Helion), raw_payload
    (rule metadata + result snippet), scanner_source="codeql".

    Returns empty list if payload is not a dict or has no runs list.
    """
    if not isinstance(payload, dict):
        return []
    runs = payload.get("runs")
    if not isinstance(runs, list):
        return []

    out: list[dict] = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            vulnerability_id = _get_vulnerability_id(result, run)
            if not vulnerability_id:
                continue

            file_path = _get_result_file_path(result, run)
            description = _get_result_message(result)
            level = result.get("level")
            severity = _sarif_level_to_severity(level)

            rule_meta = _get_rule_metadata(vulnerability_id, run)
            raw_payload: dict = dict(rule_meta)
            raw_payload["_sarif_result"] = {
                "ruleId": vulnerability_id,
                "message": result.get("message"),
                "level": level,
                "locations": result.get("locations", [])[:1],
            }

            out.append({
                "vulnerability_id": vulnerability_id,
                "file_path": file_path,
                "description": description,
                "severity": severity,
                "scanner_source": "codeql",
                "raw_payload": raw_payload,
            })
    return out
