"""Clusters endpoint: return findings grouped by CVE (SCA) or rule + path (SAST)."""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import Finding
from app.schemas.findings import ClustersResponse, CompressionMetrics, VulnerabilityCluster
from app.services.clustering import build_clusters

router = APIRouter()


@router.get("", response_model=ClustersResponse)
def get_clusters(
    db: Annotated[Session, Depends(get_db)],
) -> ClustersResponse:
    """
    Return distinct vulnerability clusters plus compression metrics.

    Clusters: SCA grouped by CVE ID, SAST by rule ID + file path pattern. Each cluster includes
    finding_ids, affected_services_count (distinct repos), and finding_count.

    Metrics: raw_finding_count (total DB findings), cluster_count (number of clusters), and
    compression_ratio (raw_finding_count / cluster_count) for instant visibility of compression.
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
