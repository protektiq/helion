"""Tickets endpoint: convert vulnerability clusters into Jira-ready ticket payloads."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.v1.auth import get_current_user
from app.core.config import get_settings
from app.core.database import get_db
from app.models import Finding
from app.schemas.auth import CurrentUser
from app.schemas.reasoning import ClusterNote
from app.schemas.risk_tier import ClusterRiskTierResult
from app.schemas.ticket import DevTicketPayload, TicketsRequest, TicketsResponse
from app.services.clustering import build_clusters
from app.services.reasoning import ReasoningServiceError, run_reasoning
from app.services.risk_tier import assign_risk_tiers
from app.services.ticket_generator import (
    clusters_to_ticket_payloads,
    resolve_affected_services,
)

router = APIRouter()


@router.post("", response_model=TicketsResponse)
async def post_tickets(
    body: TicketsRequest,
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[CurrentUser, Depends(get_current_user)],
) -> TicketsResponse:
    """
    Convert vulnerability clusters into Jira-ready ticket payloads.

    Send clusters in the request body, or set use_db=true to use current clusters
    from the database. Optionally set use_reasoning=true to run the reasoning
    service and risk tier assignment and attach remediation and tier to each ticket.

    Returns one ticket payload per cluster with title, description, affected
    services, acceptance criteria, recommended remediation, and risk tier label.
    """
    if body.use_db:
        findings = db.query(Finding).all()
        clusters = build_clusters(findings)
    else:
        clusters = body.clusters

    if len(clusters) > 100:
        raise HTTPException(
            status_code=422,
            detail="At most 100 clusters are allowed per request.",
        )

    notes_by_id: dict[str, ClusterNote] = {}
    tier_by_id: dict[str, ClusterRiskTierResult] = {}
    affected_services_by_id: dict[str, list[str]] = {}

    if body.use_reasoning and clusters:
        settings = get_settings()
        try:
            result = await run_reasoning(clusters, settings)
        except ReasoningServiceError as e:
            if "unreachable" in e.message.lower() or "timed out" in e.message.lower():
                raise HTTPException(status_code=503, detail=e.message) from e
            if "status" in e.message or "Ollama returned" in e.message:
                raise HTTPException(status_code=502, detail=e.message) from e
            raise HTTPException(status_code=422, detail=e.message) from e

        tier_results = assign_risk_tiers(
            clusters, reasoning_response=result, cluster_dev_only=None
        )
        for note in result.cluster_notes:
            notes_by_id[note.vulnerability_id] = note
        for tr in tier_results:
            tier_by_id[tr.vulnerability_id] = tr

    for cluster in clusters:
        if cluster.repo == "multiple":
            repos = resolve_affected_services(db, cluster.finding_ids)
            if repos:
                affected_services_by_id[cluster.vulnerability_id] = repos

    tickets = clusters_to_ticket_payloads(
        clusters,
        notes_by_id=notes_by_id if notes_by_id else None,
        tier_by_id=tier_by_id if tier_by_id else None,
        affected_services_by_id=affected_services_by_id if affected_services_by_id else None,
    )
    return TicketsResponse(tickets=tickets)
