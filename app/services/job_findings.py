"""Helpers to load findings scoped by upload job and user."""

from sqlalchemy.orm import Session

from app.models import Finding, UploadJob


def get_user_upload_job_count(db: Session, user_id: int) -> int:
    """Return the number of upload jobs for the given user."""
    return (
        db.query(UploadJob)
        .filter(UploadJob.user_id == user_id)
        .count()
    )


def get_findings_for_user_job(
    db: Session,
    user_id: int,
    job_id: int | None = None,
) -> list:
    """
    Return findings for the current user, optionally scoped to one upload job.

    - If job_id is set: return findings for that job (and enforce user_id).
    - If job_id is None: return findings for the user's latest job (by created_at).
    - If the user has no jobs or the specified job is not theirs, return empty list.
    """
    if job_id is not None:
        return (
            db.query(Finding)
            .filter(Finding.upload_job_id == job_id, Finding.user_id == user_id)
            .all()
        )
    # Latest job for user
    latest = (
        db.query(UploadJob)
        .filter(UploadJob.user_id == user_id)
        .order_by(UploadJob.created_at.desc())
        .limit(1)
        .first()
    )
    if latest is None:
        return []
    return (
        db.query(Finding)
        .filter(Finding.upload_job_id == latest.id, Finding.user_id == user_id)
        .all()
    )
