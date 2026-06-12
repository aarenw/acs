"""Unit tests for vulnerability exception purge."""

from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock, patch

from acs.purge_exceptions import (
    purge_action_for_status,
    purge_fp_defer_exceptions,
    should_purge_exception,
)


class TestPurgeExceptions(unittest.TestCase):
    def test_should_purge_fp_and_defer_active(self) -> None:
        self.assertTrue(
            should_purge_exception(
                {"id": "1", "targetState": "FALSE_POSITIVE", "status": "APPROVED"}
            )
        )
        self.assertTrue(
            should_purge_exception(
                {"id": "2", "target_state": "DEFERRED", "status": "PENDING"}
            )
        )
        self.assertFalse(
            should_purge_exception({"id": "3", "targetState": "FALSE_POSITIVE", "status": "CANCELLED"})
        )
        self.assertFalse(
            should_purge_exception({"id": "4", "targetState": "OBSERVED", "status": "APPROVED"})
        )

    def test_purge_action_for_status(self) -> None:
        self.assertEqual(purge_action_for_status("APPROVED"), "cancel")
        self.assertEqual(purge_action_for_status("PENDING"), "delete")
        self.assertEqual(purge_action_for_status("APPROVED_PENDING_UPDATE"), "delete")

    def test_purge_dry_run(self) -> None:
        from acs.config import Settings

        settings = Settings(dry_run=True)
        settings.rox_endpoint = "https://central.example.com"
        settings.rox_api_token = "token"
        client = MagicMock()
        client.request.return_value = {
            "exceptions": [
                {
                    "id": "fp-1",
                    "targetState": "FALSE_POSITIVE",
                    "status": "APPROVED",
                    "cves": ["CVE-1"],
                    "scope": {"imageScope": {"registry": "quay.io", "remote": "foo", "tag": ""}},
                },
                {
                    "id": "def-1",
                    "targetState": "DEFERRED",
                    "status": "PENDING",
                    "cves": ["CVE-2"],
                    "scope": {"imageScope": {"registry": "quay.io", "remote": "bar", "tag": "latest"}},
                },
            ]
        }

        out = settings.results_dir / "purge-test.json"
        with patch("acs.purge_exceptions.AcsClient", return_value=client):
            report_path = purge_fp_defer_exceptions(settings, out)
        data = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(data["purge_candidates"], 2)
        self.assertEqual(client.request.call_count, 1)
        self.assertTrue(all(a["result"] == "dry_run" for a in data["actions"]))

if __name__ == "__main__":
    unittest.main()
