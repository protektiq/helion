"""Tickets endpoint: convert vulnerability clusters into Jira-ready ticket payloads."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.v1.auth import get_current_user
from app.core.config import get_settings
from app.core.database import get_db
from app.schemas.auth import CurrentUser
from app.schemas.exploitability import ExploitabilityOutput
from app.schemas.reasoning import ClusterNote
from app.schemas.risk_tier import ClusterRiskTierResult
from app.schemas.ticket import DevTicketPayload, TicketsRequest, TicketsResponse
from app.services.agent import run_exploitability_agent
from app.services.clustering import build_clusters
from app.services.reasoning import ReasoningServiceError
from app.services.ticket_generator import (
    apply_tier_overrides,
    clusters_to_ticket_payloads,
    resolve_affected_services,
)

router = APIRouter()


@router.post("", response_model=TicketsResponse)
async def post_tickets(
    body: TicketsRequest,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> TicketsResponse:
    """
    Convert vulnerability clusters into Jira-ready ticket payloads.

    Send clusters in the request body, or set use_db=true to use current clusters
    from the database. Optionally set use_reasoning=true to run the reasoning
    service and risk tier assignment and attach remediation and tier to each ticket.

    Returns one ticket payload per cluster with title, description, affected
    services, acceptance criteria, recommended remediation, and risk tier label.
    When the user has more than one upload job, job_id is required when use_db is
    true; when omitted with multiple jobs, returns 422. When 0 or 1 job, job_id
    may be omitted.
    """
    if body.use_db:
        from app.services.job_findings import get_findings_for_user_job, get_user_upload_job_count

        if body.job_id is None and get_user_upload_job_count(db, current_user.id) > 1:
            raise HTTPException(
                status_code=422,
                detail="Multiple upload jobs exist; include job_id in the request body to scope to one job.",
            )
        findings = get_findings_for_user_job(db, current_user.id, body.job_id)
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
            tier_num = 1 if output.adjusted_risk_tier == "critical" else (
                2 if output.adjusted_risk_tier == "high" else 3
            )
            notes_by_id[cluster.vulnerability_id] = ClusterNote(
                vulnerability_id=cluster.vulnerability_id,
                priority=output.adjusted_risk_tier,
                reasoning=output.reasoning,
                assigned_tier=tier_num,
                override_applied=None,
                kev=output.kev,
                epss=output.epss,
                fixed_in_versions=output.fixed_in_versions,
                package_ecosystem=output.package_ecosystem,
                evidence=output.evidence,
            )
            tier_by_id[cluster.vulnerability_id] = ClusterRiskTierResult(
                vulnerability_id=cluster.vulnerability_id,
                assigned_tier=tier_num,
                llm_reasoning=output.reasoning,
                override_applied=None,
            )
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
    return TicketsResponse(tickets=tickets)
