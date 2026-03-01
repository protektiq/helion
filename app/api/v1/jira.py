"""Jira export endpoint: one-click export of vulnerability tickets to Jira (epics by risk tier + issues)."""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.v1.auth import get_current_user
from app.core.config import get_settings
from app.core.database import get_db
from app.schemas.auth import CurrentUser
from app.schemas.jira import JiraExportResponse
from app.schemas.reasoning import ClusterNote
from app.schemas.risk_tier import ClusterRiskTierResult
from app.schemas.ticket import TicketsRequest
from app.services.cluster_persistence import get_or_build_clusters_for_job, load_clusters_for_job
from app.schemas.exploitability import ExploitabilityOutput
from app.services.agent import run_exploitability_agent
from app.services.jira_export import JiraApiError, JiraNotConfiguredError, export_tickets_to_jira
from app.services.reasoning import ReasoningServiceError
from app.services.ticket_generator import (
    apply_tier_overrides,
    clusters_to_ticket_payloads,
    resolve_affected_services,
)

logger = logging.getLogger(__name__)
router = APIRouter()

_ADJUSTED_TO_TIER = {"critical": 1, "high": 2, "medium": 3, "low": 3, "info": 3}


def _agent_output_to_note_and_tier(
    vulnerability_id: str,
    output: ExploitabilityOutput,
) -> tuple[ClusterNote, ClusterRiskTierResult]:
    """Convert ExploitabilityOutput to ClusterNote and ClusterRiskTierResult."""
    tier = _ADJUSTED_TO_TIER.get(output.adjusted_risk_tier.strip().lower(), 2)
    note = ClusterNote(
        vulnerability_id=vulnerability_id,
        priority=output.adjusted_risk_tier,
        reasoning=output.reasoning,
        assigned_tier=tier,
        override_applied=None,
        kev=output.kev,
        epss=output.epss,
        fixed_in_versions=output.fixed_in_versions,
        package_ecosystem=output.package_ecosystem,
        evidence=output.evidence,
    )
    result = ClusterRiskTierResult(
        vulnerability_id=vulnerability_id,
        assigned_tier=tier,
        llm_reasoning=output.reasoning,
        override_applied=None,
    )
    return (note, result)


@router.post("/export", response_model=JiraExportResponse)
async def post_jira_export(
    body: TicketsRequest,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> JiraExportResponse:
    """
    One-click export: create Jira epics (one per risk tier) and issues under them.

    Uses the same request as POST /tickets: clusters, use_db, use_reasoning.
    With use_db=true and use_reasoning=true, exports current DB clusters with
    reasoning and risk tiers. When the user has more than one upload job,
    job_id is required when use_db is true; when omitted with multiple jobs,
    returns 422. Requires JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN,
    JIRA_PROJECT_KEY to be set.
    """
    if body.use_db:
        from app.services.job_findings import get_user_upload_job_count

        if body.job_id is None and get_user_upload_job_count(db, current_user.id) > 1:
            raise HTTPException(
                status_code=422,
                detail="Multiple upload jobs exist; include job_id in the request body to scope to one job.",
            )
        clusters = load_clusters_for_job(db, current_user.id, body.job_id)
        if not clusters:
            clusters, _, _ = get_or_build_clusters_for_job(db, current_user.id, body.job_id)
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

    if body.reasoning_response is not None:
        for note in body.reasoning_response.cluster_notes:
            notes_by_id[note.vulnerability_id] = note
            if note.assigned_tier is not None and note.assigned_tier in (1, 2, 3):
                tier_by_id[note.vulnerability_id] = ClusterRiskTierResult(
                    vulnerability_id=note.vulnerability_id,
                    assigned_tier=note.assigned_tier,
                    llm_reasoning=note.reasoning or None,
                    override_applied=note.override_applied,
                )
    elif body.use_reasoning and clusters:
        settings = get_settings()
        job_id = body.job_id if body.use_db else None
        for cluster in clusters:
            try:
                output: ExploitabilityOutput = await run_exploitability_agent(
                    cluster,
                    settings,
                    session=db,
                    upload_job_id=job_id,
                    persist_enrichment=True,
                )
            except (ReasoningServiceError, RuntimeError) as e:
                msg = e.message if hasattr(e, "message") else str(e)
                if "unreachable" in msg.lower() or "timed out" in msg.lower():
                    raise HTTPException(status_code=503, detail=msg) from e
                if "status" in msg or "Ollama returned" in msg:
                    raise HTTPException(status_code=502, detail=msg) from e
                raise HTTPException(status_code=422, detail=msg) from e
            note, tier_result = _agent_output_to_note_and_tier(
                cluster.vulnerability_id, output
            )
            notes_by_id[cluster.vulnerability_id] = note
            tier_by_id[cluster.vulnerability_id] = tier_result
        if db:
            db.commit()

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
    if body.tier_overrides:
        tickets = apply_tier_overrides(tickets, clusters, body.tier_overrides)

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
