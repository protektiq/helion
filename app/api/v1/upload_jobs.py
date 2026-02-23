"""Upload jobs list endpoint: list jobs for the current user."""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.v1.auth import get_current_user
from app.core.database import get_db
from app.models import Finding, UploadJob
from app.schemas.auth import CurrentUser
from app.schemas.upload_job import UploadJobListItem, UploadJobsListResponse

router = APIRouter()


@router.get("", response_model=UploadJobsListResponse)
def list_upload_jobs(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> UploadJobsListResponse:
    """
    List upload jobs for the current user (newest first).

    Use the returned job ids with GET /clusters?job_id=... and POST reasoning/tickets/jira with job_id in body.
    """
    upload_jobs = (
        db.query(UploadJob)
        .filter(UploadJob.user_id == current_user.id)
        .order_by(UploadJob.created_at.desc())
        .all()
    )
    count_rows = (
        db.query(Finding.upload_job_id, func.count(Finding.id).label("cnt"))
        .filter(Finding.user_id == current_user.id)
        .group_by(Finding.upload_job_id)
        .all()
    )
    count_map = {row[0]: row[1] for row in count_rows}
    items = [
        UploadJobListItem(
            id=j.id,
            created_at=j.created_at,
            status=j.status,
            source=j.source,
            finding_count=count_map.get(j.id, 0),
        )
        for j in upload_jobs
    ]
    return UploadJobsListResponse(jobs=items)
