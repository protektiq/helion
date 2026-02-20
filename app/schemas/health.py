"""Pydantic schemas for health check responses."""

from typing import Literal

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Response body for the health check endpoint."""

    status: Literal["ok"] = Field(default="ok", description="Service status")
    environment: str = Field(description="Current app environment (e.g. dev, prod)")
    database: Literal["connected", "disconnected"] | None = Field(
        default=None,
        description="Database connectivity status when check is performed",
    )
