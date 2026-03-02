"""Persist and load cluster enrichment to/from Postgres for traceability."""

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.cluster_enrichment import ClusterEnrichment


def load_enrichments_for_job(session: Session, upload_job_id: int) -> list[ClusterEnrichment]:
    """
    Load all cluster enrichments for the given upload job.
    Used by tickets endpoint to merge EPSS/KEV evidence when reasoning did not run.
    """
    return (
        session.query(ClusterEnrichment)
        .filter(ClusterEnrichment.upload_job_id == upload_job_id)
        .all()
    )


def save_cluster_enrichment(
    session: Session,
    upload_job_id: int,
    vulnerability_id: str,
    enrichment: dict,
    *,
    dependency: str = "",
) -> None:
    """
    Store one enrichment result (UPSERT). Call after enrich_cluster() to persist for audit.
    If a row exists for (upload_job_id, vulnerability_id, dependency), the enrichment
    JSON is updated; otherwise a new row is inserted. Idempotent; does not crash on
    duplicate keys.
    upload_job_id is required so enrichments are always scoped to a job (no NULL in DB).
    Call only when a job context exists (e.g. reasoning/tickets with use_db).
    """
    if upload_job_id is None:
        raise ValueError("upload_job_id must not be None when persisting cluster enrichment")
    vuln = (vulnerability_id or "").strip()[:255]
    dep = (dependency or "")[:1024]
    stmt = insert(ClusterEnrichment).values(
        upload_job_id=upload_job_id,
        vulnerability_id=vuln,
        dependency=dep,
        enrichment=enrichment,
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["upload_job_id", "vulnerability_id", "dependency"],
        set_={"enrichment": stmt.excluded.enrichment},
    )
    session.execute(stmt)
