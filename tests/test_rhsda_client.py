"""Unit tests for RHSDA HTTP client."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from acs.config import Settings
from acs.http_client import RHSDA_HTTP_404, RHSDA_USER_AGENT, RhsdaClient


class TestRhsdaClient(unittest.TestCase):
    def setUp(self) -> None:
        self.client = RhsdaClient(Settings())

    @patch("acs.http_client.http_request")
    def test_get_cve_sends_user_agent(self, mock_request) -> None:
        mock_request.return_value = {"name": "CVE-TEST-1"}
        self.client.get_cve("CVE-TEST-1", quiet=True)
        mock_request.assert_called_once()
        headers = mock_request.call_args.kwargs.get("headers") or {}
        self.assertEqual(headers.get("User-Agent"), RHSDA_USER_AGENT)

    @patch("acs.http_client.http_request")
    def test_get_cve_quiet_logs_fetch_error(self, mock_request) -> None:
        mock_request.side_effect = OSError("certificate verify failed")
        with self.assertLogs("acs.http_client", level="WARNING") as logs:
            detail = self.client.get_cve("CVE-2026-32952", quiet=True)
        self.assertEqual(detail, {"_rhsda_fetch_error": "OSError: certificate verify failed"})
        self.assertTrue(any("RHSDA fetch failed" in msg for msg in logs.output))

    @patch("acs.http_client.http_request")
    def test_get_cve_http_404_marker_without_parsing_body(self, mock_request) -> None:
        mock_request.side_effect = RuntimeError(
            'HTTP 404 https://example/cve/CVE-2099.json: {"message":"Not Found"}'
        )
        detail = self.client.get_cve("CVE-2099-00001", quiet=True)
        self.assertEqual(detail, {RHSDA_HTTP_404: True})
        self.assertNotIn("_rhsda_fetch_error", detail)


if __name__ == "__main__":
    unittest.main()
