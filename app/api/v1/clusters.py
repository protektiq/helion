"""Clusters endpoint: return findings grouped by CVE (SCA) or rule + path (SAST)."""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import Finding
from app.schemas.findings import VulnerabilityCluster
from app.services.clustering import build_clusters

router = APIRouter()


@router.get("", response_model=list[VulnerabilityCluster])
def get_clusters(
    db: Annotated[Session, Depends(get_db)],
) -> list[VulnerabilityCluster]:
    """
    Return distinct vulnerability clusters: SCA grouped by CVE ID, SAST by rule ID + file path pattern.
    Each cluster includes finding_ids, affected_services_count (distinct repos), and finding_count.
    """
    findings = db.query(Finding).all()
    return build_clusters(findings)
