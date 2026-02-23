"""Reasoning service: send vulnerability cluster data to a local LLM (Ollama) and return structured JSON."""

import json
import logging
import time
from typing import TYPE_CHECKING

import httpx

from app.schemas.findings import VulnerabilityCluster
from app.schemas.reasoning import ReasoningResponse

if TYPE_CHECKING:
    from app.core.config import Settings

logger = logging.getLogger(__name__)

# Max characters of raw model output to log on JSON parse failure (sanitized, not full payload)
DEBUG_LOG_PREFIX_LEN = 800

# Allowed priority values (must match prompt); invalid values are defaulted to "medium"
ALLOWED_PRIORITIES = frozenset(("critical", "high", "medium", "low", "info"))
PRIORITY_ALIASES: dict[str, str] = {
    "crit": "critical",
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
}


def _normalize_priority(raw: str | None) -> str:
    """Map priority/severity to an allowed value; default to 'medium' if invalid."""
    if raw is None or not isinstance(raw, str) or not raw.strip():
        return "medium"
    key = raw.strip().lower()
    normalized = PRIORITY_ALIASES.get(key)
    if normalized is not None:
        return normalized
    if key in ALLOWED_PRIORITIES:
        return key
    return "medium"


def _normalize_reasoning_output(
    parsed: dict, clusters: list[VulnerabilityCluster]
) -> dict:
    """
    Map common "almost-correct" LLM output shapes into the strict ReasoningResponse schema.

    - Normalizes top-level keys (notes/clusters -> cluster_notes, overall_summary -> summary).
    - Normalizes per-note keys (id -> vulnerability_id, remediation/recommendation -> reasoning, severity -> priority).
    - Enforces allowed priority values (aliases and lowercase); invalid -> "medium".
    - Filters out notes whose vulnerability_id is not in the input cluster ids.
    - Ensures cluster_notes is a list and summary is a string.
    """
    # Resolve cluster_notes
    cluster_notes = parsed.get("cluster_notes")
    if cluster_notes is None:
        cluster_notes = parsed.get("notes")
    if cluster_notes is None:
        cluster_notes = parsed.get("clusters")
    if not isinstance(cluster_notes, list):
        cluster_notes = []

    # Resolve summary
    summary = parsed.get("summary")
    if summary is None:
        summary = parsed.get("overall_summary")
    if not isinstance(summary, str):
        summary = str(summary) if summary is not None else "No summary provided."

    allowed_ids = {c.vulnerability_id for c in clusters}
    normalized_notes: list[dict[str, str]] = []

    for item in cluster_notes:
        if not isinstance(item, dict):
            continue
        vuln_id = item.get("vulnerability_id") or item.get("id")
        if not vuln_id or not isinstance(vuln_id, str) or vuln_id.strip() == "":
            continue
        vuln_id = vuln_id.strip()
        if vuln_id not in allowed_ids:
            continue
        reasoning = item.get("reasoning") or item.get("remediation") or item.get("recommendation")
        if not isinstance(reasoning, str):
            reasoning = str(reasoning) if reasoning is not None else "No reasoning provided."
        priority_raw = item.get("priority") or item.get("severity")
        priority = _normalize_priority(priority_raw)
        normalized_notes.append({
            "vulnerability_id": vuln_id,
            "priority": priority,
            "reasoning": reasoning,
        })

    return {"summary": summary, "cluster_notes": normalized_notes}


def _is_fence_line(line: str) -> bool:
    """True if the line is a markdown code fence (e.g. ``` or ```json)."""
    s = line.strip()
    return s == "```" or s.startswith("```")


def _extract_json_object(text: str) -> str:
    """
    Extract a JSON object from model output.

    Strips whitespace. If markdown code fences are present (e.g. ``` or
    ```json on one line, closing ``` on another), removes the first
    opening fence line and the last closing fence line so that content
    wrapped in "Here is the result:\\n\\n```json\\n{...}\\n```" is
    normalized. Then returns the substring from the first "{" to the
    last "}" when both exist and last > first; otherwise returns the
    stripped text. Does not unwrap or accept alternative shapes—validation
    into ReasoningResponse remains strict.
    """
    text = text.strip()
    if "```" in text:
        lines = text.split("\n")
        first_fence: int | None = None
        last_fence: int | None = None
        for i, line in enumerate(lines):
            if _is_fence_line(line):
                if first_fence is None:
                    first_fence = i
                last_fence = i
        if (
            first_fence is not None
            and last_fence is not None
            and last_fence > first_fence
        ):
            text = "\n".join(lines[first_fence + 1 : last_fence]).strip()
    first = text.find("{")
    last = text.rfind("}")
    if first != -1 and last != -1 and last > first:
        return text[first : last + 1]
    return text


class ReasoningServiceError(Exception):
    """Raised when the reasoning service cannot complete (Ollama unreachable, timeout, or invalid JSON)."""

    def __init__(self, message: str, cause: Exception | None = None) -> None:
        self.message = message
        self.cause = cause
        super().__init__(message)


def _build_prompt(clusters: list[VulnerabilityCluster]) -> str:
    """Build a prompt with cluster data and explicit JSON-only output rules."""
    MAX_DESC_LEN = 200
    clusters_data = [
        {
            "id": c.vulnerability_id,
            "sev": c.severity,
            "cvss": c.cvss_score,
            "repo": c.repo,
            "dep": c.dependency or "",
            "svc": c.affected_services_count,
            "findings": c.finding_count,
            "desc": (c.description or "")[:MAX_DESC_LEN],
        }
        for c in clusters
    ]
    clusters_json = json.dumps(clusters_data, separators=(",", ":"))
    instructions = (
        "Return ONLY valid JSON. No markdown. Response must start with { and end with }.\n"
        "Root object: only two keys—summary (string), cluster_notes (array). No other keys.\n"
        "cluster_notes: array of objects. Each object has only three keys:\n"
        "  vulnerability_id: string; must match one of the cluster id values from the Clusters list below.\n"
        "  priority: exactly one of [\"critical\",\"high\",\"medium\",\"low\",\"info\"].\n"
        "  reasoning: string, between 1 and 500 characters.\n"
        "No extra keys in the root or in any cluster_notes item."
    )
    return instructions + "\n\nClusters:\n" + clusters_json


async def run_reasoning(
    clusters: list[VulnerabilityCluster],
    settings: "Settings",
) -> ReasoningResponse:
    """
    Send cluster data to the local LLM (Ollama) and return parsed reasoning.

    Raises ReasoningServiceError on connection failure, timeout, or invalid JSON.
    """
    if not clusters:
        return ReasoningResponse(summary="No clusters provided.", cluster_notes=[])

    base_url = settings.OLLAMA_BASE_URL.rstrip("/")
    url = f"{base_url}/api/generate"
    payload = {
        "model": settings.OLLAMA_MODEL,
        "prompt": _build_prompt(clusters),
        "stream": False,
        "format": "json",
        "options": {
            "temperature": settings.OLLAMA_TEMPERATURE,
            "top_p": settings.OLLAMA_TOP_P,
            "repeat_penalty": settings.OLLAMA_REPEAT_PENALTY,
            "seed": settings.OLLAMA_SEED,
        },
    }
    timeout = httpx.Timeout(settings.OLLAMA_REQUEST_TIMEOUT_SEC)
    start = time.perf_counter()

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload)
        elapsed = time.perf_counter() - start
    except httpx.ConnectError as e:
        elapsed = time.perf_counter() - start
        logger.info(
            "LLM reasoning request failed",
            extra={
                "llm_latency_seconds": elapsed,
                "cluster_count": len(clusters),
                "model": settings.OLLAMA_MODEL,
                "status": "error",
            },
        )
        raise ReasoningServiceError(
            "Ollama is unreachable. Ensure Ollama is running and OLLAMA_BASE_URL is correct.",
            cause=e,
        ) from e
    except httpx.TimeoutException as e:
        elapsed = time.perf_counter() - start
        logger.info(
            "LLM reasoning request failed",
            extra={
                "llm_latency_seconds": elapsed,
                "cluster_count": len(clusters),
                "model": settings.OLLAMA_MODEL,
                "status": "error",
            },
        )
        raise ReasoningServiceError(
            "Ollama request timed out. Try increasing OLLAMA_REQUEST_TIMEOUT_SEC or reducing cluster count.",
            cause=e,
        ) from e
    except httpx.HTTPError as e:
        elapsed = time.perf_counter() - start
        logger.info(
            "LLM reasoning request failed",
            extra={
                "llm_latency_seconds": elapsed,
                "cluster_count": len(clusters),
                "model": settings.OLLAMA_MODEL,
                "status": "error",
            },
        )
        raise ReasoningServiceError(
            "Ollama request failed.",
            cause=e,
        ) from e

    if response.status_code != 200:
        raise ReasoningServiceError(
            f"Ollama returned status {response.status_code}. Check that the model is pulled (e.g. ollama pull {settings.OLLAMA_MODEL})."
        )

    try:
        body = response.json()
    except json.JSONDecodeError as e:
        raise ReasoningServiceError(
            "Ollama response body is not valid JSON.",
            cause=e,
        ) from e

    eval_duration_ns = body.get("eval_duration")
    log_extra: dict[str, float | int | str | None] = {
        "llm_latency_seconds": elapsed,
        "cluster_count": len(clusters),
        "model": settings.OLLAMA_MODEL,
    }
    if eval_duration_ns is not None:
        log_extra["eval_duration_nanoseconds"] = eval_duration_ns
    logger.info("LLM reasoning request completed", extra=log_extra)

    raw_response = body.get("response")
    if raw_response is None:
        raise ReasoningServiceError(
            "Ollama response missing 'response' field."
        )

    # Response may be a string (the generated text) or already parsed
    if isinstance(raw_response, str):
        try:
            parsed = json.loads(_extract_json_object(raw_response))
        except json.JSONDecodeError as e:
            prefix = raw_response[:DEBUG_LOG_PREFIX_LEN]
            sanitized = prefix.replace("\r", " ").replace("\n", " ")
            logger.warning(
                "Model returned invalid JSON; logging prefix of raw response",
                extra={
                    "model": settings.OLLAMA_MODEL,
                    "raw_response_prefix": sanitized,
                },
            )
            raise ReasoningServiceError(
                "Invalid JSON from model. The model must respond with only valid JSON.",
                cause=e,
            ) from e
    else:
        parsed = raw_response

    if not isinstance(parsed, dict):
        raise ReasoningServiceError(
            "Model output is not a JSON object."
        )

    parsed = _normalize_reasoning_output(parsed, clusters)

    try:
        return ReasoningResponse.model_validate(parsed)
    except Exception as e:
        raw_snippet = json.dumps(parsed)[:DEBUG_LOG_PREFIX_LEN]
        sanitized = raw_snippet.replace("\r", " ").replace("\n", " ")
        logger.debug(
            "Schema validation failed; logging prefix of model output",
            extra={
                "model": settings.OLLAMA_MODEL,
                "raw_output_prefix": sanitized,
            },
        )
        raise ReasoningServiceError(
            "Model output does not match expected schema (summary, cluster_notes with vulnerability_id, priority, reasoning).",
            cause=e,
        ) from e
