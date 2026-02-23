"""Reasoning endpoint: grounded agent per cluster (KEV/EPSS/OSV + LLM) aggregated into reasoning response."""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.v1.auth import get_current_user
from app.core.config import get_settings
from app.core.database import get_db
from app.schemas.auth import CurrentUser
from app.schemas.exploitability import ExploitabilityOutput
from app.schemas.reasoning import ClusterNote, ReasoningRequest, ReasoningResponse
from app.services.agent import run_exploitability_agent
from app.services.cluster_persistence import get_or_build_clusters_for_job, load_clusters_for_job
from app.services.clustering import sort_clusters_by_severity_cvss
from app.services.reasoning import ReasoningServiceError

logger = logging.getLogger(__name__)

router = APIRouter()

# Map adjusted_risk_tier string to numeric tier and priority.
_ADJUSTED_TO_TIER = {"critical": 1, "high": 2, "medium": 3, "low": 3, "info": 3}


def _agent_output_to_cluster_note(
    vulnerability_id: str,
    output: ExploitabilityOutput,
) -> ClusterNote:
    """Convert one agent ExploitabilityOutput to ClusterNote."""
    tier = _ADJUSTED_TO_TIER.get(
        output.adjusted_risk_tier.strip().lower(), 2
    )
    return ClusterNote(
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


@router.post("", response_model=ReasoningResponse)
async def post_reasoning(
    body: ReasoningRequest,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> ReasoningResponse:
    """
    Run grounded exploitability agent per cluster and aggregate notes.

    When use_db=true, loads clusters from the database (job_id required if
    user has multiple jobs). Each cluster is run through the agent (enrich
    with KEV/EPSS/OSV → assess → LLM finalize → validate). Enrichment is
    persisted. Returns a summary and per-cluster notes with assigned tiers
    and optional evidence (kev, epss, fixed_in_versions, evidence).
    """
    settings = get_settings()

    reasoning_limited_note: str | None = None
    if body.use_db:
        from app.services.job_findings import get_user_upload_job_count

        if body.job_id is None and get_user_upload_job_count(db, current_user.id) > 1:
            raise HTTPException(
                status_code=422,
                detail="Multiple upload jobs exist; include job_id in the request body to scope to one job.",
            )
        clusters = load_clusters_for_job(db, current_user.id, body.job_id)
        if not clusters:
            clusters, _ = get_or_build_clusters_for_job(db, current_user.id, body.job_id)
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

    if not clusters:
        return ReasoningResponse(
            summary="No clusters provided.",
            cluster_notes=[],
        )

    job_id = body.job_id if body.use_db else None
    notes: list[ClusterNote] = []
    for i, cluster in enumerate(clusters):
        try:
            output = await run_exploitability_agent(
                cluster,
                settings,
                session=db,
                upload_job_id=job_id,
                persist_enrichment=True,
            )
            notes.append(
                _agent_output_to_cluster_note(cluster.vulnerability_id, output)
            )
        except ReasoningServiceError as e:
            logger.warning(
                "Agent failed for cluster %s: %s",
                cluster.vulnerability_id,
                e.message,
            )
            notes.append(
                ClusterNote(
                    vulnerability_id=cluster.vulnerability_id,
                    priority="medium",
                    reasoning=f"Assessment skipped: {e.message}",
                    assigned_tier=2,
                    override_applied=None,
                )
            )

    if db:
        db.commit()

    summary = f"Assessed {len(notes)} cluster(s) with grounded evidence (KEV/EPSS/OSV)."
    if reasoning_limited_note:
        summary = summary + "\n\n" + reasoning_limited_note
    return ReasoningResponse(summary=summary, cluster_notes=notes)
