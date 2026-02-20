"""Jira export endpoint: one-click export of vulnerability tickets to Jira (epics by risk tier + issues)."""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.v1.auth import get_current_user
from app.core.config import get_settings
from app.core.database import get_db
from app.models import Finding
from app.schemas.auth import CurrentUser
from app.schemas.jira import JiraExportResponse
from app.schemas.reasoning import ClusterNote
from app.schemas.risk_tier import ClusterRiskTierResult
from app.schemas.ticket import TicketsRequest
from app.services.clustering import build_clusters
from app.services.jira_export import JiraApiError, JiraNotConfiguredError, export_tickets_to_jira
from app.services.reasoning import ReasoningServiceError, run_reasoning
from app.services.risk_tier import assign_risk_tiers
from app.services.ticket_generator import (
    clusters_to_ticket_payloads,
    resolve_affected_services,
)

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/export", response_model=JiraExportResponse)
async def post_jira_export(
    body: TicketsRequest,
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[CurrentUser, Depends(get_current_user)],
) -> JiraExportResponse:
    """
    One-click export: create Jira epics (one per risk tier) and issues under them.

    Uses the same request as POST /tickets: clusters, use_db, use_reasoning.
    With use_db=true and use_reasoning=true, exports current DB clusters with
    reasoning and risk tiers. Requires JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN,
    JIRA_PROJECT_KEY to be set.
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

    if not tickets:
        return JiraExportResponse(epics={}, issues=[], errors=[])

    try:
        result = await export_tickets_to_jira(tickets, get_settings())
    except JiraNotConfiguredError as e:
        logger.error(
            "Jira export failed",
            extra={
                "export_status": "failure",
                "epic_count": 0,
                "issue_count": 0,
                "error_count": 1,
                "reason": (e.message or str(e))[:500],
            },
        )
        raise HTTPException(status_code=503, detail=e.message) from e
    except JiraApiError as e:
        logger.error(
            "Jira export failed",
            extra={
                "export_status": "failure",
                "epic_count": 0,
                "issue_count": 0,
                "error_count": 1,
                "reason": (e.message or str(e))[:500],
            },
        )
        status = 502 if (e.status_code or 500) >= 500 else 400
        raise HTTPException(status_code=status, detail=e.message) from e

    export_status = "success" if len(result.errors) == 0 else "partial"
    log_extra: dict[str, str | int] = {
        "export_status": export_status,
        "epic_count": len(result.epics),
        "issue_count": len(result.issues),
        "error_count": len(result.errors),
    }
    if result.errors:
        log_extra["first_error"] = result.errors[0][:200]
    logger.info("Jira export completed", extra=log_extra)
    return result
