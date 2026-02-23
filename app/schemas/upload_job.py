"""Pydantic schemas for upload jobs list endpoint."""

from datetime import datetime

from pydantic import BaseModel, Field


class UploadJobListItem(BaseModel):
    """One upload job in the list for the current user."""

    id: int = Field(..., description="Upload job ID.")
    created_at: datetime = Field(..., description="When the job was created.")
    status: str = Field(..., description="Job status: pending, processing, completed, failed.")
    source: str = Field(..., description="Source: file or api.")
    finding_count: int = Field(..., ge=0, description="Number of findings in this job.")


class UploadJobsListResponse(BaseModel):
    """Response for GET /api/v1/upload-jobs."""

    jobs: list[UploadJobListItem] = Field(
        ...,
        description="Upload jobs for the current user, newest first.",
    )
