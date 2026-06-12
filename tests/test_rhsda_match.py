"""Unit tests for RHSDA product/CPE matching helpers."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from acs.common import (
    cpe_product_score,
    is_ocp_major_umbrella_product,
    is_rhsda_cve_not_found,
    parse_container_fix_version,
    product_entry_score,
    derive_product_context,
    format_rhsda_exception_comment,
)
from acs.config import Settings
from acs.rhsda_check import evaluate_vuln_row

CVE_JSON = Path(__file__).resolve().parent.parent / "data" / "rhsda" / "CVE-2024-45337.json"


class TestRhsdaMatching(unittest.TestCase):
    def setUp(self) -> None:
        self.settings = Settings()
        self.ctx = derive_product_context(
            self.settings,
            "cpe:/a:redhat:openshift:4.20::el9",
            "openshift-release-dev/ocp-v4.0-art-dev",
        )

    def test_major_umbrella_product_detection(self) -> None:
        self.assertTrue(
            is_ocp_major_umbrella_product("Red Hat OpenShift Container Platform 4")
        )
        self.assertFalse(
            is_ocp_major_umbrella_product("Red Hat OpenShift Container Platform 4.19")
        )

    def test_cpe_major_umbrella_covers_minor(self) -> None:
        score = cpe_product_score(
            "cpe:/a:redhat:openshift:4.20::el9",
            "cpe:/a:redhat:openshift:4",
        )
        self.assertEqual(score, 2)

    def test_cpe_minor_compat_for_affected_release(self) -> None:
        score = cpe_product_score(
            "cpe:/a:redhat:openshift:4.20::el9",
            "cpe:/a:redhat:openshift:4.19::el9",
            allow_minor_compat=True,
        )
        self.assertEqual(score, 2)
        score_no_compat = cpe_product_score(
            "cpe:/a:redhat:openshift:4.20::el9",
            "cpe:/a:redhat:openshift:4.19::el9",
            allow_minor_compat=False,
        )
        self.assertEqual(score_no_compat, 0)

    def test_package_state_scores_major_umbrella(self) -> None:
        score = product_entry_score(
            self.settings,
            "Red Hat OpenShift Container Platform 4",
            "cpe:/a:redhat:openshift:4",
            self.ctx,
            entry_kind="package_state",
        )
        self.assertGreaterEqual(score, 2)

    def test_affected_release_parses_container_fix_version(self) -> None:
        pkg = (
            "openshift4/ose-oauth-apiserver-rhel9:"
            "v4.19.0-202507081507.p0.g7591406.assembly.stream.el9"
        )
        self.assertEqual(
            parse_container_fix_version(
                pkg,
                "Red Hat OpenShift Container Platform 4.19",
                "cpe:/a:redhat:openshift:4.19::el9",
            ),
            "4.19",
        )

    def test_evaluate_oauth_apiserver_affected_release_on_4_20(self) -> None:
        if not CVE_JSON.is_file():
            self.skipTest("local CVE fixture missing")
        detail = json.loads(CVE_JSON.read_text(encoding="utf-8"))
        client = MagicMock()
        client.get_cve.return_value = detail
        row = {
            "cve": "CVE-2024-45337",
            "component": "golang.org/x/crypto",
            "version": "v0.30.0",
            "registry": "quay.io",
            "remote": "openshift-release-dev/ocp-v4.0-art-dev",
            "tag": "sha256:abc",
            "product_cpe": "cpe:/a:redhat:openshift:4.20::el9",
            "ocp_version": "4.20.0",
            "label_name": "openshift/ose-oauth-apiserver-rhel9",
            "rhsda_container_ids": "openshift4/ose-oauth-apiserver-rhel9",
        }
        result = evaluate_vuln_row(self.settings, client, row)
        self.assertEqual(result["decision"], "tobeupgrade")
        self.assertEqual(result["match_track"], "container")
        self.assertEqual(result["rhsda_summary"].get("fixed_in_version"), "4.19")

    def test_evaluate_metallb_not_affected_via_major_umbrella(self) -> None:
        if not CVE_JSON.is_file():
            self.skipTest("local CVE fixture missing")
        detail = json.loads(CVE_JSON.read_text(encoding="utf-8"))
        client = MagicMock()
        client.get_cve.return_value = detail
        row = {
            "cve": "CVE-2024-45337",
            "component": "golang.org/x/crypto",
            "version": "v0.30.0",
            "registry": "quay.io",
            "remote": "openshift-release-dev/ocp-v4.0-art-dev",
            "tag": "sha256:abc",
            "product_cpe": "cpe:/a:redhat:openshift:4.20::el9",
            "ocp_version": "4.20.0",
            "label_name": "openshift/ose-metallb-rhel9",
            "rhsda_container_ids": "openshift4/metallb-rhel9",
        }
        result = evaluate_vuln_row(self.settings, client, row)
        self.assertEqual(result["decision"], "candidate_fp")
        self.assertEqual(result["rhsda_summary"].get("fix_state"), "Not affected")
        self.assertEqual(
            result["rhsda_summary"].get("product_name"),
            "Red Hat OpenShift Container Platform 4",
        )


    def test_evaluate_oauth_server_under_investigation(self) -> None:
        detail = {
            "package_state": [
                {
                    "product_name": "Red Hat OpenShift Container Platform 4",
                    "fix_state": "Under investigation",
                    "package_name": "openshift4/ose-oauth-server-rhel9",
                    "cpe": "cpe:/a:redhat:openshift:4",
                }
            ],
            "affected_release": [],
        }
        client = MagicMock()
        client.get_cve.return_value = detail
        row = {
            "cve": "CVE-2026-32952",
            "component": "github.com/Azure/go-ntlmssp",
            "version": "v0.0.0-20211209120228-48547f28849e",
            "registry": "quay.io",
            "remote": "openshift-release-dev/ocp-v4.0-art-dev",
            "tag": "sha256:abc",
            "product_cpe": "cpe:/a:redhat:openshift:4.20::el9",
            "ocp_version": "4.20.0",
            "label_name": "openshift/ose-oauth-server-rhel9",
            "rhsda_container_ids": "openshift4/ose-oauth-server-rhel9",
        }
        result = evaluate_vuln_row(self.settings, client, row)
        self.assertEqual(result["decision"], "skipped")
        self.assertIn("Under investigation", result["reason"])
        self.assertEqual(
            result["rhsda_summary"].get("package_name"),
            "openshift4/ose-oauth-server-rhel9",
        )

    def test_rhsda_cve_not_found_is_candidate_fp(self) -> None:
        self.assertTrue(is_rhsda_cve_not_found({"message": "Not Found"}))
        self.assertFalse(is_rhsda_cve_not_found({}))
        self.assertFalse(is_rhsda_cve_not_found({"name": "CVE-2024-1", "message": "Not Found"}))

        client = MagicMock()
        client.get_cve.return_value = {"message": "Not Found"}
        row = {
            "cve": "CVE-2099-00001",
            "component": "example.com/foo",
            "version": "1.0",
            "product_cpe": "cpe:/a:redhat:openshift:4.20::el9",
            "rhsda_container_ids": "openshift4/ose-foo-rhel9",
        }
        result = evaluate_vuln_row(self.settings, client, row)
        self.assertEqual(result["decision"], "candidate_fp")
        self.assertEqual(result["reason"], "CVE not found in Red Hat Security database")
        comment = format_rhsda_exception_comment(
            self.settings, result["rhsda_summary"], "false-positive"
        )
        self.assertIn("CVE not found in Red Hat Security database", comment)

    def test_rhsda_http_404_is_candidate_fp(self) -> None:
        from acs.http_client import RHSDA_HTTP_404

        client = MagicMock()
        client.get_cve.return_value = {RHSDA_HTTP_404: True}
        row = {
            "cve": "CVE-2099-40401",
            "component": "example.com/foo",
            "version": "1.0",
            "product_cpe": "cpe:/a:redhat:openshift:4.20::el9",
            "rhsda_container_ids": "openshift4/ose-foo-rhel9",
        }
        result = evaluate_vuln_row(self.settings, client, row)
        self.assertEqual(result["decision"], "candidate_fp")
        self.assertEqual(
            result["reason"],
            "This CVE does not affect Red Hat software, return 404.",
        )
        self.assertEqual(result["rhsda_summary"].get("match_kind"), "http_404")
        comment = format_rhsda_exception_comment(
            self.settings, result["rhsda_summary"], "false-positive"
        )
        self.assertIn("does not affect Red Hat software, return 404", comment)

    def test_rhsda_fetch_failure_reports_reason(self) -> None:
        client = MagicMock()
        client.get_cve.return_value = {
            "_rhsda_fetch_error": "URLError: certificate verify failed",
        }
        row = {
            "cve": "CVE-2026-32952",
            "component": "github.com/Azure/go-ntlmssp",
            "version": "v0.0.0",
            "product_cpe": "cpe:/a:redhat:openshift:4.20::el9",
            "rhsda_container_ids": "openshift4/ose-oauth-server-rhel9",
        }
        result = evaluate_vuln_row(self.settings, client, row)
        self.assertEqual(result["decision"], "skipped")
        self.assertIn("RHSDA fetch failed:", result["reason"])
        self.assertIn("certificate verify failed", result["reason"])

    def test_inherent_not_affected_when_no_versioned_rhsda_match(self) -> None:
        detail = {
            "name": "CVE-TEST-RHEL",
            "package_state": [
                {
                    "product_name": "Red Hat Enterprise Linux 9",
                    "fix_state": "Affected",
                    "package_name": "grafana",
                    "cpe": "cpe:/o:redhat:enterprise_linux:9",
                }
            ],
            "affected_release": [],
        }
        client = MagicMock()
        client.get_cve.return_value = detail
        row = {
            "cve": "CVE-TEST-RHEL",
            "component": "github.com/coredns/coredns",
            "version": "v1.11.1",
            "product_cpe": "cpe:/a:redhat:openshift:4.20::el9",
            "ocp_version": "4.20.0",
            "label_name": "openshift/ose-coredns-rhel9",
            "rhsda_container_ids": "openshift4/ose-coredns-rhel9",
            "tag": "sha256:abc",
        }
        result = evaluate_vuln_row(self.settings, client, row)
        self.assertEqual(result["decision"], "candidate_fp")
        self.assertEqual(result["reason"], "Inherently not affected, Not Affected")
        self.assertEqual(result["rhsda_summary"].get("match_kind"), "inherent_not_affected")

    def test_not_inherent_when_affected_release_matches_container(self) -> None:
        fixture = Path(__file__).resolve().parent / "fixtures" / "CVE-2024-0874.json"
        if not fixture.is_file():
            self.skipTest("CVE-2024-0874 fixture missing")
        detail = json.loads(fixture.read_text(encoding="utf-8"))
        client = MagicMock()
        client.get_cve.return_value = detail
        row = {
            "cve": "CVE-2024-0874",
            "component": "github.com/coredns/coredns",
            "version": "v1.11.1",
            "product_cpe": "cpe:/a:redhat:openshift:4.20::el9",
            "ocp_version": "4.20.0",
            "label_name": "openshift/ose-coredns-rhel9",
            "rhsda_container_ids": "openshift4/ose-coredns-rhel9",
            "tag": "sha256:abc",
        }
        result = evaluate_vuln_row(self.settings, client, row)
        self.assertEqual(result["decision"], "tobeupgrade")
        self.assertNotEqual(result["rhsda_summary"].get("match_kind"), "inherent_not_affected")
        self.assertEqual(result["rhsda_summary"].get("fixed_in_version"), "4.16")


if __name__ == "__main__":
    unittest.main()
