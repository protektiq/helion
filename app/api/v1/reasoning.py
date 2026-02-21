"""Reasoning endpoint: send vulnerability clusters to local LLM (Ollama) and return structured reasoning plus deterministic risk tiers."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.v1.auth import get_current_user
from app.core.config import get_settings
from app.core.database import get_db
from app.models import Finding
from app.schemas.auth import CurrentUser
from app.schemas.reasoning import ClusterNote, ReasoningRequest, ReasoningResponse
from app.services.clustering import build_clusters, sort_clusters_by_severity_cvss
from app.services.reasoning import ReasoningServiceError, run_reasoning
from app.services.risk_tier import assign_risk_tiers

router = APIRouter()


@router.post("", response_model=ReasoningResponse)
async def post_reasoning(
    body: ReasoningRequest,
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[CurrentUser, Depends(get_current_user)],
) -> ReasoningResponse:
    """
    Run reasoning on vulnerability clusters via the local LLM (Ollama / Llama 3).

    Send a list of clusters in the request body, or set use_db=true to use current
    clusters from the database (same as GET /clusters). Returns a summary and
    per-cluster notes (priority and reasoning from the LLM). Assigned risk tiers
    (Tier 1/2/3) are computed deterministically by override rules (e.g. CVSS > 9
    → Tier 1 unless dev-only); final tier is AI-assisted, not AI-dependent.
    """
    settings = get_settings()

    reasoning_limited_note: str | None = None
    if body.use_db:
        findings = db.query(Finding).all()
        clusters = build_clusters(findings)
        if len(clusters) > 100:
            clusters = sort_clusters_by_severity_cvss(clusters)[:100]
            reasoning_limited_note = "Reasoning limited to top 100 clusters."
    else:
        clusters = body.clusters
        if len(clusters) > 100:
            raise HTTPException(
                status_code=422,
                detail="At most 100 clusters are allowed per request.",
            )

    try:
        result = await run_reasoning(clusters, settings)
    except ReasoningServiceError as e:
        if "unreachable" in e.message.lower() or "timed out" in e.message.lower():
            raise HTTPException(status_code=503, detail=e.message) from e
        if "status" in e.message or "Ollama returned" in e.message:
            raise HTTPException(status_code=502, detail=e.message) from e
        raise HTTPException(status_code=422, detail=e.message) from e

    # Deterministic risk tier assignment: overrides (e.g. CVSS > 9 → Tier 1) apply; LLM only informs.
    tier_results = assign_risk_tiers(clusters, reasoning_response=result, cluster_dev_only=None)
    tier_by_id = {r.vulnerability_id: r for r in tier_results}

    enriched_notes: list[ClusterNote] = []
    for note in result.cluster_notes:
        tr = tier_by_id.get(note.vulnerability_id)
        enriched_notes.append(
            ClusterNote(
                vulnerability_id=note.vulnerability_id,
                priority=note.priority,
                reasoning=note.reasoning,
                assigned_tier=tr.assigned_tier if tr else None,
                override_applied=tr.override_applied if tr else None,
            )
        )

    summary = result.summary
    if reasoning_limited_note:
        summary = result.summary + "\n\n" + reasoning_limited_note
    return ReasoningResponse(summary=summary, cluster_notes=enriched_notes)
