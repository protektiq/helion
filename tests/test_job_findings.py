"""Unit tests for job_findings: get_findings_for_user_job scoping."""

import unittest
from unittest.mock import MagicMock

from app.services.job_findings import get_findings_for_user_job


class TestGetFindingsForUserJob(unittest.TestCase):
    """get_findings_for_user_job filters by job_id and user_id or returns latest job's findings."""

    def test_job_id_specified_returns_filtered_findings(self) -> None:
        """When job_id is set, returns findings for that job and user."""
        mock_f1 = MagicMock()
        mock_f1.id = 1
        mock_db = MagicMock()
        mock_query = MagicMock()
        mock_filter = MagicMock()
        mock_filter.all.return_value = [mock_f1]
        mock_db.query.return_value = mock_query
        mock_query.filter.return_value = mock_filter

        result = get_findings_for_user_job(mock_db, user_id=10, job_id=5)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].id, 1)
        mock_query.filter.assert_called_once()
        mock_filter.all.assert_called_once()

    def test_job_id_none_uses_latest_job(self) -> None:
        """When job_id is None, loads latest UploadJob for user then findings for that job."""
        mock_job = MagicMock()
        mock_job.id = 3
        mock_f = MagicMock()
        mock_f.id = 99
        mock_db = MagicMock()
        job_chain = MagicMock()
        job_chain.filter.return_value = job_chain
        job_chain.order_by.return_value = job_chain
        job_chain.limit.return_value = job_chain
        job_chain.first.return_value = mock_job
        finding_chain = MagicMock()
        finding_chain.filter.return_value = finding_chain
        finding_chain.all.return_value = [mock_f]
        mock_db.query.side_effect = [job_chain, finding_chain]

        result = get_findings_for_user_job(mock_db, user_id=10, job_id=None)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].id, 99)

    def test_job_id_none_no_jobs_returns_empty(self) -> None:
        """When job_id is None and user has no jobs, returns empty list."""
        mock_db = MagicMock()
        job_chain = MagicMock()
        job_chain.filter.return_value = job_chain
        job_chain.order_by.return_value = job_chain
        job_chain.limit.return_value = job_chain
        job_chain.first.return_value = None
        mock_db.query.return_value = job_chain

        result = get_findings_for_user_job(mock_db, user_id=10, job_id=None)
        self.assertEqual(result, [])
