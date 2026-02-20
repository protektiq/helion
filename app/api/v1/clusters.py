"""Clusters endpoint: return findings grouped by CVE (SCA) or rule + path (SAST)."""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.v1.auth import get_current_user
from app.core.database import get_db
from app.models import Finding
from app.schemas.auth import CurrentUser
from app.schemas.findings import ClustersResponse, CompressionMetrics
from app.services.clustering import build_clusters

router = APIRouter()


@router.get("", response_model=ClustersResponse)
def get_clusters(
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[CurrentUser, Depends(get_current_user)],
) -> ClustersResponse:
    """
    Return distinct vulnerability clusters plus compression metrics.

    Clusters and metrics are from current DB findings only. SCA grouped by CVE ID,
    SAST by rule ID + file path pattern.
    """
    findings = db.query(Finding).all()
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
