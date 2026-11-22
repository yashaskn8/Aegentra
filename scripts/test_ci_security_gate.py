"""Regression tests for fail-closed CI enforcement (stdlib only)."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ci_security_gate import (
    SecurityGateError, check_workflow_source, find_secrets, verify_junit,
)


class SecurityGateTests(unittest.TestCase):
    def test_realistic_credentials_detected_without_echo(self):
        self.assertIn(
            ("AWS access key ID", 1), find_secrets("AKIA" + "A" * 16)
        )
        self.assertIn(
            ("GitHub token", 1), find_secrets("ghp_" + "A" * 36)
        )
        self.assertEqual([], find_secrets("the usual ci-app-only placeholder"))

    def test_mutable_or_privileged_action_is_rejected(self):
        basic = (
            "on:\n  push:\n  pull_request:\n"
            "permissions:\n  contents: read\n"
            "jobs:\n  test:\n    steps:\n"
            "      - uses: actions/checkout@"
        )
        with self.assertRaises(SecurityGateError):
            check_workflow_source(Path("backend.yml"), basic + "v4\n")
        with self.assertRaises(SecurityGateError):
            check_workflow_source(
                Path("backend.yml"),
                basic + "a" * 40 + "\n  contents: write\n",
            )
        check_workflow_source(Path("backend.yml"), basic + "a" * 40 + "\n")

    def test_missing_or_skipped_adversarial_cases_are_fatal(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "junit.xml"
            report.write_text(
                '<testsuite><testcase classname="test_s2" name="fail_closed"/>'
                '</testsuite>', encoding="utf-8"
            )
            verify_junit(report, required_modules=("test_s2",), minimum_cases=1)
            with self.assertRaises(SecurityGateError):
                verify_junit(report, required_modules=("missing",), minimum_cases=1)
            report.write_text(
                '<testsuite><testcase classname="test_s2" name="ignored">'
                '<skipped/></testcase></testsuite>', encoding="utf-8",
            )
            with self.assertRaises(SecurityGateError):
                verify_junit(report, required_modules=("test_s2",), minimum_cases=1)

    def test_empty_xml_does_not_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.xml"
            report.write_text("<testsuite tests='0'/>", encoding="utf-8")
            with self.assertRaises(SecurityGateError):
                verify_junit(report, required_modules=(), minimum_cases=1)


if __name__ == "__main__":
    unittest.main()
