"""Persist and load cluster results per upload job so reasoning and Jira export use stable artifacts."""

from sqlalchemy.orm import Session

from app.models import Cluster, UploadJob
from app.schemas.findings import VulnerabilityCluster
from app.services.clustering import build_clusters_v2
from app.services.job_findings import get_findings_for_user_job


def save_clusters_for_job(
    db: Session,
    upload_job_id: int,
    clusters: list[VulnerabilityCluster],
) -> None:
    """
    Replace all cluster rows for the given upload job with the provided clusters.
    Deletes existing rows for upload_job_id, then bulk-inserts the new ones.
    """
    db.query(Cluster).filter(Cluster.upload_job_id == upload_job_id).delete()
    if not clusters:
        db.commit()
        return
    for c in clusters:
        row = Cluster(
            upload_job_id=upload_job_id,
            vulnerability_id=c.vulnerability_id,
            severity=c.severity,
            repo=c.repo,
            file_path=c.file_path or "",
            dependency=c.dependency or "",
            cvss_score=c.cvss_score,
            description=c.description,
            finding_ids=c.finding_ids,
            affected_services_count=c.affected_services_count,
            finding_count=c.finding_count,
        )
        db.add(row)
    db.commit()


def load_clusters_for_job(
    db: Session,
    user_id: int,
    job_id: int | None,
) -> list[VulnerabilityCluster]:
    """
    Load persisted clusters for the given user and job.

    - If job_id is set: return clusters for that job only if the job belongs to the user.
    - If job_id is None: resolve to the user's latest job (by created_at) and return its clusters.
    - If the job has no clusters or the job is not the user's, return empty list.
    """
    if job_id is not None:
        job = (
            db.query(UploadJob)
            .filter(UploadJob.id == job_id, UploadJob.user_id == user_id)
            .first()
        )
        if not job:
            return []
        upload_job_id = job.id
    else:
        latest = (
            db.query(UploadJob)
            .filter(UploadJob.user_id == user_id)
            .order_by(UploadJob.created_at.desc())
            .limit(1)
            .first()
        )
        if not latest:
            return []
        upload_job_id = latest.id

    rows = (
        db.query(Cluster)
        .filter(Cluster.upload_job_id == upload_job_id)
        .all()
    )
    return [
        VulnerabilityCluster(
            vulnerability_id=r.vulnerability_id,
            severity=r.severity,
            repo=r.repo,
            file_path=r.file_path or "",
            dependency=r.dependency or "",
            cvss_score=r.cvss_score,
            description=r.description,
            finding_ids=list(r.finding_ids) if r.finding_ids else [],
            affected_services_count=r.affected_services_count,
            finding_count=r.finding_count,
        )
        for r in rows
    ]


def get_or_build_clusters_for_job(
    db: Session,
    user_id: int,
    job_id: int | None,
    *,
    use_semantic: bool = False,
) -> tuple[list[VulnerabilityCluster], int]:
    """
    Load findings for the job, run clustering (Layer A + optional Layer B), persist to clusters
    table, and return (clusters, raw_finding_count). Used by GET /clusters so results are stored
    for tickets/reasoning/Jira.
    """
    findings = get_findings_for_user_job(db, user_id, job_id)
    if not findings:
        return [], 0
    clusters = build_clusters_v2(findings, use_semantic=use_semantic)
    upload_job_id = findings[0].upload_job_id
    save_clusters_for_job(db, upload_job_id, clusters)
    return clusters, len(findings)
