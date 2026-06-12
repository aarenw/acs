"""Unit tests for ACS exception apply helpers."""

from __future__ import annotations

import unittest

from acs.apply import build_apply_groups
from acs.common import acs_image_scope_tag, defer_expiry_fields
from acs.config import Settings


class TestApplyHelpers(unittest.TestCase):
    def test_acs_image_scope_tag_digest_is_empty(self) -> None:
        digest = "sha256:070a5cd558a1891baa07f7427e8afb9eb0e9dfbbb162a99aced9009c45e2cb67"
        self.assertEqual(acs_image_scope_tag(digest), "")

    def test_acs_image_scope_tag_named_tag_unchanged(self) -> None:
        self.assertEqual(acs_image_scope_tag("4.20.0"), "4.20.0")
        self.assertEqual(acs_image_scope_tag("latest"), "latest")
        self.assertEqual(acs_image_scope_tag(""), "")

    def test_defer_expiry_fields_nested_exception_expiry(self) -> None:
        fields = defer_expiry_fields(Settings.from_env())
        self.assertEqual(fields["exceptionExpiry"]["expiryType"], "TIME")
        self.assertRegex(fields["exceptionExpiry"]["expiresOn"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_build_apply_groups_splits_by_reason(self) -> None:
        rows = [
            {
                "cve": "CVE-1",
                "decision": "candidate_fp",
                "registry": "quay.io",
                "remote": "foo",
                "tag": "sha256:abc",
                "reason": "Inherently not affected, Not Affected",
            },
            {
                "cve": "CVE-2",
                "decision": "candidate_fp",
                "registry": "quay.io",
                "remote": "foo",
                "tag": "sha256:abc",
                "reason": "This CVE does not affect Red Hat software, return 404.",
            },
            {
                "cve": "CVE-3",
                "decision": "candidate_defer",
                "registry": "quay.io",
                "remote": "foo",
                "tag": "sha256:abc",
                "reason": "RHSDA package_state Fix deferred (container track)",
            },
        ]
        groups = build_apply_groups(rows)
        self.assertEqual(len(groups), 3)
        fp_reasons = {
            key[4] for key in groups if key[0] == "candidate_fp"
        }
        self.assertEqual(
            fp_reasons,
            {
                "Inherently not affected, Not Affected",
                "This CVE does not affect Red Hat software, return 404.",
            },
        )


if __name__ == "__main__":
    unittest.main()
