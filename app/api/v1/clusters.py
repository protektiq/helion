"""Clusters endpoint: return findings grouped by CVE (SCA) or rule + path (SAST)."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.v1.auth import get_current_user
from app.core.database import get_db
from app.schemas.auth import CurrentUser
from app.schemas.findings import ClustersResponse, CompressionMetrics
from app.services.clustering import build_clusters
from app.services.job_findings import get_findings_for_user_job, get_user_upload_job_count

router = APIRouter()


@router.get("", response_model=ClustersResponse)
def get_clusters(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    job_id: int | None = None,
) -> ClustersResponse:
    """
    Return distinct vulnerability clusters plus compression metrics.

    Optional query job_id: when set, clusters are from that upload job only
    (and must belong to the current user). When the user has more than one
    upload job, job_id is required; if omitted, returns 422. When the user
    has 0 or 1 job, job_id may be omitted (uses that one job or empty).
    SCA grouped by CVE ID, SAST by rule ID + file path pattern.
    """
    if job_id is None and get_user_upload_job_count(db, current_user.id) > 1:
        raise HTTPException(
            status_code=422,
            detail="Multiple upload jobs exist; specify job_id to scope clusters (e.g. ?job_id=123).",
        )
    findings = get_findings_for_user_job(db, current_user.id, job_id)
    clusters = build_clusters(findings)
    raw_finding_count = len(findings)
    cluster_count = len(clusters)
    compression_ratio = (
        raw_finding_count / cluster_count if cluster_count else 0.0
    )
    metrics = CompressionMetrics(
        raw_finding_count=raw_finding_count,
        cluster_count=cluster_count,
        compression_ratio=compression_ratio,
    )
    return ClustersResponse(clusters=clusters, metrics=metrics)
