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


class ReasoningServiceError(Exception):
    """Raised when the reasoning service cannot complete (Ollama unreachable, timeout, or invalid JSON)."""

    def __init__(self, message: str, cause: Exception | None = None) -> None:
        self.message = message
        self.cause = cause
        super().__init__(message)


def _build_prompt(clusters: list[VulnerabilityCluster]) -> str:
    """Build a single prompt that includes cluster data and instructs the model to return only JSON."""
    clusters_data = [
        {
            "vulnerability_id": c.vulnerability_id,
            "severity": c.severity,
            "repo": c.repo,
            "file_path": c.file_path or "",
            "dependency": c.dependency or "",
            "cvss_score": c.cvss_score,
            "description": c.description,
            "affected_services_count": c.affected_services_count,
            "finding_count": c.finding_count,
        }
        for c in clusters
    ]
    clusters_json = json.dumps(clusters_data, indent=2)
    return f"""You are a security analyst. Below is a list of vulnerability clusters (grouped findings). For each cluster, provide a short priority label and reasoning/remediation hint.

Vulnerability clusters (JSON):
{clusters_json}

Respond with ONLY a single valid JSON object (no markdown, no code fence, no extra text). The JSON must have exactly this shape:
{{
  "summary": "One short overall assessment of these clusters (1-3 sentences).",
  "cluster_notes": [
    {{
      "vulnerability_id": "<same as in the list>",
      "priority": "critical|high|medium|low",
      "reasoning": "Short explanation or remediation hint for this cluster."
    }}
  ]
}}

Include one object in "cluster_notes" for each cluster in the input list, in the same order. Output only the JSON object."""


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
        raw_response = raw_response.strip()
        # Remove markdown code fence if present
        if raw_response.startswith("```"):
            lines = raw_response.split("\n")
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            raw_response = "\n".join(lines)
        try:
            parsed = json.loads(raw_response)
        except json.JSONDecodeError as e:
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

    try:
        return ReasoningResponse.model_validate(parsed)
    except Exception as e:
        raise ReasoningServiceError(
            "Model output does not match expected schema (summary, cluster_notes with vulnerability_id, priority, reasoning).",
            cause=e,
        ) from e
