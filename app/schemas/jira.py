"""Pydantic schemas for Jira export API responses."""

from pydantic import BaseModel, Field


class JiraCreatedIssue(BaseModel):
    """One created Jira issue returned from export."""

    title: str = Field(..., description="Issue summary/title.")
    key: str = Field(..., min_length=1, description="Jira issue key (e.g. PROJ-123).")
    tier: str = Field(..., min_length=1, description="Risk tier label (e.g. Tier 1).")


class JiraExportResponse(BaseModel):
    """Response for POST /api/v1/jira/export."""

    epics: dict[str, str] = Field(
        default_factory=dict,
        description="Risk tier label → Jira epic issue key.",
    )
    issues: list[JiraCreatedIssue] = Field(
        default_factory=list,
        description="Created Jira issues, one per ticket.",
    )
    errors: list[str] = Field(
        default_factory=list,
        description="Per-issue or global error messages (partial success).",
    )
