"""Export vulnerability tickets to Jira Cloud: create epics by risk tier and issues under them."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import httpx

from app.schemas.jira import JiraCreatedIssue, JiraExportResponse
from app.schemas.ticket import DevTicketPayload

if TYPE_CHECKING:
    from app.core.config import Settings

# Risk tier labels we create epics for (order preserved for deterministic creation).
RISK_TIER_LABELS = ("Tier 1", "Tier 2", "Tier 3")

# Epic summary templates: tier label -> summary.
EPIC_SUMMARIES = {
    "Tier 1": "Helion – Tier 1 (Highest risk)",
    "Tier 2": "Helion – Tier 2",
    "Tier 3": "Helion – Tier 3",
}


class JiraNotConfiguredError(Exception):
    """Raised when Jira export is invoked but required settings are missing."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class JiraApiError(Exception):
    """Raised when Jira API returns an error (auth, project not found, validation)."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        self.message = message
        self.status_code = status_code
        super().__init__(message)


def _plain_text_to_adf(plain: str) -> dict[str, Any]:
    """Convert plain text to Atlassian Document Format (one paragraph per line)."""
    if not plain or not plain.strip():
        return {"type": "doc", "version": 1, "content": []}
    lines = plain.strip().split("\n")
    content = []
    for line in lines:
        text = line.strip() or " "
        content.append(
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": text}],
            }
        )
    return {"type": "doc", "version": 1, "content": content}


def _is_jira_configured(settings: Settings) -> bool:
    if not settings.JIRA_BASE_URL or not settings.JIRA_BASE_URL.strip():
        return False
    if not settings.JIRA_EMAIL or not settings.JIRA_EMAIL.strip():
        return False
    if settings.JIRA_API_TOKEN is None:
        return False
    try:
        token_val = settings.JIRA_API_TOKEN.get_secret_value()
        if not token_val or not token_val.strip():
            return False
    except Exception:
        return False
    if not settings.JIRA_PROJECT_KEY or not settings.JIRA_PROJECT_KEY.strip():
        return False
    return True


def _get_token(settings: Settings) -> str:
    if settings.JIRA_API_TOKEN is None:
        raise JiraNotConfiguredError("JIRA_API_TOKEN is not set.")
    return settings.JIRA_API_TOKEN.get_secret_value()


async def _create_issue(
    client: httpx.AsyncClient,
    base_url: str,
    project_key: str,
    issue_type: str,
    summary: str,
    description_adf: dict[str, Any],
    epic_key: str | None,
    epic_link_field_id: str | None,
    timeout: float,
) -> str:
    """Create one Jira issue. Returns the issue key. Raises JiraApiError on failure."""
    url = f"{base_url.rstrip('/')}/rest/api/3/issue"
    payload: dict[str, Any] = {
        "fields": {
            "project": {"key": project_key},
            "issuetype": {"name": issue_type},
            "summary": summary[:255],
            "description": description_adf,
        }
    }
    if epic_key:
        if epic_link_field_id and epic_link_field_id.strip():
            payload["fields"][epic_link_field_id.strip()] = epic_key
        else:
            payload["fields"]["parent"] = {"key": epic_key}
    resp = await client.post(url, json=payload, timeout=timeout)
    if resp.status_code == 401:
        raise JiraApiError("Jira authentication failed (invalid email or API token).", 401)
    if resp.status_code == 404:
        raise JiraApiError("Jira project or resource not found.", 404)
    if resp.status_code >= 400:
        try:
            body = resp.json()
            err_messages = body.get("errorMessages", [])
            errors = body.get("errors", {})
            detail = "; ".join(err_messages) if err_messages else json.dumps(errors)[:500]
        except Exception:
            detail = resp.text[:500] if resp.text else "Unknown error"
        raise JiraApiError(f"Jira returned {resp.status_code}: {detail}", resp.status_code)
    data = resp.json()
    key = data.get("key")
    if not key:
        raise JiraApiError("Jira response missing issue key.")
    return key


async def _create_epic(
    client: httpx.AsyncClient,
    base_url: str,
    project_key: str,
    epic_issue_type: str,
    summary: str,
    timeout: float,
) -> str:
    """Create one Jira epic. Returns the issue key."""
    url = f"{base_url.rstrip('/')}/rest/api/3/issue"
    payload = {
        "fields": {
            "project": {"key": project_key},
            "issuetype": {"name": epic_issue_type},
            "summary": summary,
        }
    }
    resp = await client.post(url, json=payload, timeout=timeout)
    if resp.status_code == 401:
        raise JiraApiError("Jira authentication failed (invalid email or API token).", 401)
    if resp.status_code == 404:
        raise JiraApiError("Jira project or resource not found.", 404)
    if resp.status_code >= 400:
        try:
            body = resp.json()
            err_messages = body.get("errorMessages", [])
            errors = body.get("errors", {})
            detail = "; ".join(err_messages) if err_messages else json.dumps(errors)[:500]
        except Exception:
            detail = resp.text[:500] if resp.text else "Unknown error"
        raise JiraApiError(f"Jira returned {resp.status_code}: {detail}", resp.status_code)
    data = resp.json()
    key = data.get("key")
    if not key:
        raise JiraApiError("Jira response missing epic key.")
    return key


async def export_tickets_to_jira(
    tickets: list[DevTicketPayload],
    settings: Settings,
) -> JiraExportResponse:
    """
    Create Jira epics (one per risk tier) and one issue per ticket under the matching epic.

    Requires JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY to be set.
    Raises JiraNotConfiguredError if any required setting is missing.
    On per-issue failure, appends to errors and continues (partial success).
    """
    if not _is_jira_configured(settings):
        raise JiraNotConfiguredError(
            "Jira is not configured; set JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY."
        )
    base_url = (settings.JIRA_BASE_URL or "").strip()
    email = (settings.JIRA_EMAIL or "").strip()
    token = _get_token(settings)
    project_key = (settings.JIRA_PROJECT_KEY or "").strip()
    issue_type = (settings.JIRA_ISSUE_TYPE or "Task").strip() or "Task"
    epic_issue_type = (settings.JIRA_EPIC_ISSUE_TYPE or "Epic").strip() or "Epic"
    epic_link_field_id = (
        (settings.JIRA_EPIC_LINK_FIELD_ID or "").strip() or None
    )
    timeout = max(1.0, min(120.0, settings.JIRA_REQUEST_TIMEOUT_SEC))

    epics: dict[str, str] = {}
    issues: list[JiraCreatedIssue] = []
    errors: list[str] = []

    auth = (email, token)
    async with httpx.AsyncClient(auth=auth) as client:
        # Create one epic per risk tier (only tiers that appear in tickets)
        tiers_in_use = {t.risk_tier_label for t in tickets}
        for tier in RISK_TIER_LABELS:
            if tier not in tiers_in_use:
                continue
            try:
                summary = EPIC_SUMMARIES.get(tier, f"Helion – {tier}")
                key = await _create_epic(
                    client, base_url, project_key, epic_issue_type, summary, timeout
                )
                epics[tier] = key
            except JiraApiError as e:
                # Fail fast on auth or project-not-found; no point continuing
                if e.status_code in (401, 404):
                    raise
                errors.append(f"Epic {tier}: {e.message}")
                continue

        # Normalize tier label to one of the three (for lookup)
        def epic_for_tier(label: str) -> str | None:
            normalized = (label or "").strip()
            if normalized in epics:
                return epics[normalized]
            for tier in RISK_TIER_LABELS:
                if normalized == tier:
                    return epics.get(tier)
            return epics.get("Tier 2") or (epics.get("Tier 1") or (epics.get("Tier 3")))

        for ticket in tickets:
            epic_key = epic_for_tier(ticket.risk_tier_label)
            if not epic_key:
                errors.append(f"Issue '{ticket.title[:50]}...': no epic for tier '{ticket.risk_tier_label}'")
                continue
            description_adf = _plain_text_to_adf(ticket.description)
            try:
                key = await _create_issue(
                    client,
                    base_url,
                    project_key,
                    issue_type,
                    ticket.title,
                    description_adf,
                    epic_key,
                    epic_link_field_id,
                    timeout,
                )
                issues.append(
                    JiraCreatedIssue(
                        title=ticket.title,
                        key=key,
                        tier=ticket.risk_tier_label,
                    )
                )
            except JiraApiError as e:
                errors.append(f"Issue '{ticket.title[:50]}...': {e.message}")

    return JiraExportResponse(epics=epics, issues=issues, errors=errors)
