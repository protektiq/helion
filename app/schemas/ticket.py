"""Pydantic schemas for Jira-ready ticket payloads produced from vulnerability clusters."""

from pydantic import BaseModel, Field

from app.schemas.findings import VulnerabilityCluster

# Jira-friendly limits: title 255, description typically 32k; we cap for safety and abuse prevention.
TITLE_MAX_LENGTH = 255
DESCRIPTION_MAX_LENGTH = 32_000
REMEDIATION_MAX_LENGTH = 2_000
RISK_TIER_LABEL_MAX_LENGTH = 32
AFFECTED_SERVICE_MAX_LENGTH = 1024
ACCEPTANCE_CRITERION_MAX_LENGTH = 500


class DevTicketPayload(BaseModel):
    """
    Jira-ready ticket payload for one vulnerability cluster.

    Suitable for manual ticket creation or downstream Jira API integration.
    """

    title: str = Field(
        ...,
        min_length=1,
        max_length=TITLE_MAX_LENGTH,
        description="Short ticket title (e.g. [Tier N] CVE-XXX).",
    )
    description: str = Field(
        ...,
        min_length=1,
        max_length=DESCRIPTION_MAX_LENGTH,
        description="Structured description: vulnerability_id, description, severity, CVSS, context.",
    )
    affected_services: list[str] = Field(
        ...,
        min_length=1,
        max_length=100,
        description="List of affected repositories/services.",
    )
    acceptance_criteria: list[str] = Field(
        ...,
        min_length=1,
        max_length=20,
        description="List of acceptance criteria for the ticket.",
    )
    recommended_remediation: str = Field(
        ...,
        min_length=1,
        max_length=REMEDIATION_MAX_LENGTH,
        description="Recommended remediation (from LLM or cluster description).",
    )
    risk_tier_label: str = Field(
        ...,
        min_length=1,
        max_length=RISK_TIER_LABEL_MAX_LENGTH,
        description="Human-readable risk tier (e.g. Tier 1, Tier 2, Tier 3).",
    )


class TicketsRequest(BaseModel):
    """Request body for POST /api/v1/tickets."""

    clusters: list[VulnerabilityCluster] = Field(
        default_factory=list,
        max_length=100,
        description="Clusters to convert to tickets; ignored when use_db is true.",
    )
    use_db: bool = Field(
        default=False,
        description="If true, load current clusters from the database (same as GET /clusters).",
    )
    use_reasoning: bool = Field(
        default=False,
        description="If true, run reasoning and risk tier assignment and attach to each ticket.",
    )


class TicketsResponse(BaseModel):
    """Response for POST /api/v1/tickets."""

    tickets: list[DevTicketPayload] = Field(
        ...,
        description="Jira-ready ticket payloads, one per cluster.",
    )
