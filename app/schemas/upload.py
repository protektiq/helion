"""Request/response schemas for the upload endpoint."""

from pydantic import BaseModel, Field


class UploadResponse(BaseModel):
    """Response after successfully persisting findings."""

    accepted: int = Field(
        ...,
        ge=0,
        description="Number of findings accepted and persisted.",
    )
    ids: list[int] = Field(
        default_factory=list,
        description="Database IDs of the created finding rows.",
    )
