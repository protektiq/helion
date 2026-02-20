"""Unit tests for app.services.jira_export: Jira API auth, epics by risk tier, issues under epics."""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from pydantic import SecretStr

from app.schemas.ticket import DevTicketPayload
from app.services.jira_export import (
    JiraApiError,
    JiraNotConfiguredError,
    _is_jira_configured,
    _plain_text_to_adf,
    export_tickets_to_jira,
)


def _ticket(
    title: str = "[Tier 1] CVE-2024-0001",
    description: str = "Vulnerability: CVE-2024-0001\nDescription: Test.",
    risk_tier_label: str = "Tier 1",
    **kwargs: object,
) -> DevTicketPayload:
    """Build a minimal DevTicketPayload for tests."""
    defaults = {
        "affected_services": ["my-repo"],
        "acceptance_criteria": ["Vulnerability remediated.", "No findings in rescans."],
        "recommended_remediation": "Upgrade dependency.",
    }
    defaults.update(kwargs)
    return DevTicketPayload(
        title=title,
        description=description,
        risk_tier_label=risk_tier_label,
        **defaults,
    )


class TestPlainTextToAdf(unittest.TestCase):
    """_plain_text_to_adf converts plain text to Atlassian Document Format."""

    def test_empty_string(self) -> None:
        out = _plain_text_to_adf("")
        self.assertEqual(out["type"], "doc")
        self.assertEqual(out["version"], 1)
        self.assertEqual(out["content"], [])

    def test_single_line(self) -> None:
        out = _plain_text_to_adf("Hello world")
        self.assertEqual(len(out["content"]), 1)
        self.assertEqual(out["content"][0]["type"], "paragraph")
        self.assertEqual(out["content"][0]["content"][0]["text"], "Hello world")

    def test_multiple_lines(self) -> None:
        out = _plain_text_to_adf("Line 1\nLine 2\nLine 3")
        self.assertEqual(len(out["content"]), 3)
        self.assertEqual(out["content"][0]["content"][0]["text"], "Line 1")
        self.assertEqual(out["content"][1]["content"][0]["text"], "Line 2")
        self.assertEqual(out["content"][2]["content"][0]["text"], "Line 3")


class TestIsJiraConfigured(unittest.TestCase):
    """_is_jira_configured returns True only when all required settings are set."""

    def test_missing_base_url(self) -> None:
        settings = MagicMock()
        settings.JIRA_BASE_URL = None
        settings.JIRA_EMAIL = "a@b.com"
        settings.JIRA_API_TOKEN = SecretStr("token")
        settings.JIRA_PROJECT_KEY = "HEL"
        self.assertFalse(_is_jira_configured(settings))

    def test_missing_email(self) -> None:
        settings = MagicMock()
        settings.JIRA_BASE_URL = "https://x.atlassian.net"
        settings.JIRA_EMAIL = ""
        settings.JIRA_API_TOKEN = SecretStr("token")
        settings.JIRA_PROJECT_KEY = "HEL"
        self.assertFalse(_is_jira_configured(settings))

    def test_missing_token(self) -> None:
        settings = MagicMock()
        settings.JIRA_BASE_URL = "https://x.atlassian.net"
        settings.JIRA_EMAIL = "a@b.com"
        settings.JIRA_API_TOKEN = None
        settings.JIRA_PROJECT_KEY = "HEL"
        self.assertFalse(_is_jira_configured(settings))

    def test_missing_project_key(self) -> None:
        settings = MagicMock()
        settings.JIRA_BASE_URL = "https://x.atlassian.net"
        settings.JIRA_EMAIL = "a@b.com"
        settings.JIRA_API_TOKEN = SecretStr("token")
        settings.JIRA_PROJECT_KEY = ""
        self.assertFalse(_is_jira_configured(settings))

    def test_configured(self) -> None:
        settings = MagicMock()
        settings.JIRA_BASE_URL = "https://x.atlassian.net"
        settings.JIRA_EMAIL = "a@b.com"
        settings.JIRA_API_TOKEN = SecretStr("secret")
        settings.JIRA_PROJECT_KEY = "HEL"
        self.assertTrue(_is_jira_configured(settings))


class TestExportNotConfigured(unittest.TestCase):
    """export_tickets_to_jira raises JiraNotConfiguredError when settings are missing."""

    @patch("app.services.jira_export._is_jira_configured")
    def test_raises_when_not_configured(self, mock_configured: MagicMock) -> None:
        mock_configured.return_value = False
        settings = MagicMock()
        tickets = [_ticket()]
        with self.assertRaises(JiraNotConfiguredError) as ctx:
            asyncio.run(export_tickets_to_jira(tickets, settings))
        self.assertIn("not configured", ctx.exception.message)


class TestExportToJira(unittest.TestCase):
    """export_tickets_to_jira with mocked httpx: creates epics and issues, groups by tier."""

    def _mock_post_responses(
        self,
        epic_keys: list[str],
        issue_keys: list[str],
    ) -> MagicMock:
        """Build a side_effect that returns 200 with key for each POST (epics first, then issues)."""
        keys = list(epic_keys) + list(issue_keys)
        responses = []
        for k in keys:
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"key": k}
            resp.text = ""
            responses.append(resp)
        async def post(*args: object, **kwargs: object) -> MagicMock:
            if responses:
                return responses.pop(0)
            resp = MagicMock()
            resp.status_code = 500
            resp.json.return_value = {}
            resp.text = "No mock"
            return resp
        return AsyncMock(side_effect=post)

    @patch("app.services.jira_export.httpx.AsyncClient")
    def test_creates_epics_then_issues_with_basic_auth(
        self,
        mock_client_class: MagicMock,
    ) -> None:
        # Only Tier 1 and Tier 2 appear in tickets, so only 2 epics are created.
        mock_post = self._mock_post_responses(
            epic_keys=["HEL-1", "HEL-2"],
            issue_keys=["HEL-10", "HEL-11"],
        )
        mock_instance = MagicMock()
        mock_instance.post = mock_post
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

        settings = MagicMock()
        settings.JIRA_BASE_URL = "https://test.atlassian.net"
        settings.JIRA_EMAIL = "u@test.com"
        settings.JIRA_API_TOKEN = SecretStr("token")
        settings.JIRA_PROJECT_KEY = "HEL"
        settings.JIRA_EPIC_LINK_FIELD_ID = None
        settings.JIRA_ISSUE_TYPE = "Task"
        settings.JIRA_EPIC_ISSUE_TYPE = "Epic"
        settings.JIRA_REQUEST_TIMEOUT_SEC = 30.0

        tickets = [
            _ticket(title="[Tier 1] CVE-A", risk_tier_label="Tier 1"),
            _ticket(title="[Tier 2] CVE-B", risk_tier_label="Tier 2"),
        ]

        import asyncio
        result = asyncio.run(export_tickets_to_jira(tickets, settings))

        self.assertEqual(len(result.epics), 2)  # Tier 1 and Tier 2 only (tiers in use)
        self.assertIn("Tier 1", result.epics)
        self.assertIn("Tier 2", result.epics)
        self.assertEqual(result.epics["Tier 1"], "HEL-1")
        self.assertEqual(result.epics["Tier 2"], "HEL-2")
        self.assertEqual(len(result.issues), 2)
        self.assertEqual(result.issues[0].key, "HEL-10")
        self.assertEqual(result.issues[0].tier, "Tier 1")
        self.assertEqual(result.issues[1].key, "HEL-11")
        self.assertEqual(result.issues[1].tier, "Tier 2")
        self.assertEqual(result.errors, [])

        # Client was called with Basic auth (email, token)
        mock_client_class.assert_called_once()
        call_kw = mock_client_class.call_args[1]
        self.assertEqual(call_kw["auth"], ("u@test.com", "token"))

        # POST was called: 2 epics + 2 issues = 4 times
        self.assertEqual(mock_post.call_count, 4)

        # First two calls: create epic (issuetype Epic, summary Helion – Tier N)
        call_0 = mock_post.call_args_list[0]
        body_0 = call_0[1]["json"]
        self.assertEqual(body_0["fields"]["issuetype"]["name"], "Epic")
        self.assertIn("Tier 1", body_0["fields"]["summary"])
        call_1 = mock_post.call_args_list[1]
        body_1 = call_1[1]["json"]
        self.assertIn("Tier 2", body_1["fields"]["summary"])

        # Third and fourth: create issue (parent key = epic key)
        call_2 = mock_post.call_args_list[2]
        body_2 = call_2[1]["json"]
        self.assertEqual(body_2["fields"]["issuetype"]["name"], "Task")
        self.assertEqual(body_2["fields"]["summary"], "[Tier 1] CVE-A")
        self.assertEqual(body_2["fields"]["parent"]["key"], "HEL-1")
        call_3 = mock_post.call_args_list[3]
        body_3 = call_3[1]["json"]
        self.assertEqual(body_3["fields"]["parent"]["key"], "HEL-2")

    @patch("app.services.jira_export.httpx.AsyncClient")
    def test_uses_epic_link_field_when_configured(
        self,
        mock_client_class: MagicMock,
    ) -> None:
        mock_post = self._mock_post_responses(
            epic_keys=["HEL-1"],
            issue_keys=["HEL-5"],
        )
        mock_instance = MagicMock()
        mock_instance.post = mock_post
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

        settings = MagicMock()
        settings.JIRA_BASE_URL = "https://test.atlassian.net"
        settings.JIRA_EMAIL = "u@test.com"
        settings.JIRA_API_TOKEN = SecretStr("token")
        settings.JIRA_PROJECT_KEY = "HEL"
        settings.JIRA_EPIC_LINK_FIELD_ID = "customfield_10014"
        settings.JIRA_ISSUE_TYPE = "Task"
        settings.JIRA_EPIC_ISSUE_TYPE = "Epic"
        settings.JIRA_REQUEST_TIMEOUT_SEC = 30.0

        tickets = [_ticket(risk_tier_label="Tier 1")]

        asyncio.run(export_tickets_to_jira(tickets, settings))

        # Second call is create issue: should have customfield_10014 = HEL-1, not parent
        call_1 = mock_post.call_args_list[1]
        body = call_1[1]["json"]
        self.assertIn("customfield_10014", body["fields"])
        self.assertEqual(body["fields"]["customfield_10014"], "HEL-1")
        self.assertNotIn("parent", body["fields"])

    @patch("app.services.jira_export.httpx.AsyncClient")
    def test_partial_success_on_issue_failure(
        self,
        mock_client_class: MagicMock,
    ) -> None:
        call_count = 0

        async def post(*args: object, **kwargs: object) -> MagicMock:
            nonlocal call_count
            call_count += 1
            if call_count <= 1:
                r = MagicMock()
                r.status_code = 200
                r.json.return_value = {"key": "HEL-1"}
                r.text = ""
                return r
            if call_count == 2:
                r = MagicMock()
                r.status_code = 200
                r.json.return_value = {"key": "HEL-10"}
                r.text = ""
                return r
            # Third call (second issue) fails
            r = MagicMock()
            r.status_code = 400
            r.json.return_value = {"errorMessages": ["Invalid field"]}
            r.text = "Bad request"
            return r

        mock_instance = MagicMock()
        mock_instance.post = AsyncMock(side_effect=post)
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

        settings = MagicMock()
        settings.JIRA_BASE_URL = "https://test.atlassian.net"
        settings.JIRA_EMAIL = "u@test.com"
        settings.JIRA_API_TOKEN = SecretStr("token")
        settings.JIRA_PROJECT_KEY = "HEL"
        settings.JIRA_EPIC_LINK_FIELD_ID = None
        settings.JIRA_ISSUE_TYPE = "Task"
        settings.JIRA_EPIC_ISSUE_TYPE = "Epic"
        settings.JIRA_REQUEST_TIMEOUT_SEC = 30.0

        tickets = [
            _ticket(title="First", risk_tier_label="Tier 1"),
            _ticket(title="Second", risk_tier_label="Tier 1"),
        ]

        result = asyncio.run(export_tickets_to_jira(tickets, settings))

        self.assertEqual(len(result.epics), 1)
        self.assertEqual(len(result.issues), 1)
        self.assertEqual(result.issues[0].key, "HEL-10")
        self.assertEqual(len(result.errors), 1)
        self.assertIn("Second", result.errors[0])
        self.assertIn("400", result.errors[0])


class TestJiraApiError(unittest.TestCase):
    """JiraApiError and 401/404 handling."""

    @patch("app.services.jira_export.httpx.AsyncClient")
    def test_401_raises_jira_api_error(self, mock_client_class: MagicMock) -> None:
        async def post(*args: object, **kwargs: object) -> MagicMock:
            r = MagicMock()
            r.status_code = 401
            r.json.return_value = {}
            r.text = "Unauthorized"
            return r

        mock_instance = MagicMock()
        mock_instance.post = AsyncMock(side_effect=post)
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

        settings = MagicMock()
        settings.JIRA_BASE_URL = "https://test.atlassian.net"
        settings.JIRA_EMAIL = "u@test.com"
        settings.JIRA_API_TOKEN = SecretStr("token")
        settings.JIRA_PROJECT_KEY = "HEL"
        settings.JIRA_EPIC_LINK_FIELD_ID = None
        settings.JIRA_ISSUE_TYPE = "Task"
        settings.JIRA_EPIC_ISSUE_TYPE = "Epic"
        settings.JIRA_REQUEST_TIMEOUT_SEC = 30.0

        tickets = [_ticket()]

        with self.assertRaises(JiraApiError) as ctx:
            asyncio.run(export_tickets_to_jira(tickets, settings))
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertIn("authentication", ctx.exception.message.lower())
