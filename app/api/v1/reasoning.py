"""Reasoning endpoint: send vulnerability clusters to local LLM (Ollama) and return structured reasoning."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.models import Finding
from app.schemas.reasoning import ReasoningRequest, ReasoningResponse
from app.services.clustering import build_clusters
from app.services.reasoning import ReasoningServiceError, run_reasoning

router = APIRouter()


@router.post("", response_model=ReasoningResponse)
async def post_reasoning(
    body: ReasoningRequest,
    db: Annotated[Session, Depends(get_db)],
) -> ReasoningResponse:
    """
    Run reasoning on vulnerability clusters via the local LLM (Ollama / Llama 3).

    Send a list of clusters in the request body, or set use_db=true to use current
    clusters from the database (same as GET /clusters). Returns a summary and
    per-cluster notes (priority and reasoning) from the model.
    """
    settings = get_settings()

    if body.use_db:
        findings = db.query(Finding).all()
        clusters = build_clusters(findings)
    else:
        clusters = body.clusters

    # Cap at 100 (schema already has max_length=100; enforce for use_db path)
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

    return result
