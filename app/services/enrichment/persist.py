"""Persist cluster enrichment to Postgres for traceability."""

from sqlalchemy.orm import Session

from app.models.cluster_enrichment import ClusterEnrichment


def save_cluster_enrichment(
    session: Session,
    vulnerability_id: str,
    enrichment: dict,
    *,
    upload_job_id: int | None = None,
    dependency: str = "",
) -> ClusterEnrichment:
    """
    Store one enrichment result. Call after enrich_cluster() to persist for audit.
    vulnerability_id and enrichment are required; upload_job_id is optional (e.g. single exploitability call has no job).
    """
    row = ClusterEnrichment(
        upload_job_id=upload_job_id,
        vulnerability_id=(vulnerability_id or "").strip()[:255],
        dependency=(dependency or "")[:1024],
        enrichment=enrichment,
    )
    session.add(row)
    session.flush()  # so caller can commit with other work
    return row
