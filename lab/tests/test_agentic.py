"""Regressions for the deterministic agentic TTP chain and its verdicts."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentic import (canary_value, exec_variants, multipart_body, sqli_variants,
                     traversal_paths, upload_variants)
from evidence import judge_agentic, validate_agentic

CASES = [
    {"id": "agentic-sqli", "fixture": "dvwa", "exploit": "sqli",
     "expect": "block", "description": "UNION canary extraction."},
    {"id": "agentic-exec", "fixture": "dvwa", "exploit": "exec",
     "expect": "block", "description": "Command injection."},
    {"id": "agentic-upload", "fixture": "dvwa", "exploit": "upload",
     "expect": "block", "description": "PHP upload behind an image type."},
    {"id": "agentic-traversal", "fixture": "cve", "exploit": "traversal",
     "expect": "block", "description": "CVE traversal to the canary."},
]
PATHS = {
    "sqli": ["/vulnerabilities/sqli/"],
    "exec": ["/vulnerabilities/exec/"],
    "upload": ["/vulnerabilities/upload/", "/hackable/uploads/agentic.php"],
    "traversal": ["/icons/", "/cgi-bin/"],
}


def results(success, blocked):
    dvwa = {"exploits": {
        exploit: {"success": success[exploit], "blocked": blocked[exploit],
                  "paths": PATHS[exploit], "attempts": 2}
        for exploit in ("sqli", "exec", "upload")
    }}
    cve = {"exploits": {
        "traversal": {"success": success["traversal"],
                      "blocked": blocked["traversal"],
                      "paths": PATHS["traversal"], "attempts": 2}
    }}
    return dvwa, cve


def block_event(exploit, **extra):
    fields = {"message": "request blocked", "path": PATHS[exploit][0],
              "method": "GET", "rate_limited": False,
              "category": {"sqli": "sql-injection", "exec": "command-injection",
                           "upload": "upload", "traversal": "path-traversal"}[exploit],
              "rule": {"sqli": "union-select", "exec": "shell-metacharacters",
                       "upload": "declared-type", "traversal": "dot-dot-slash"}[exploit]}
    fields.update(extra)
    return {"fields": fields}


def waf_events():
    return ([block_event("sqli"), block_event("exec"),
             {"fields": {"message": "upload content rejected",
                         "path": "/vulnerabilities/upload/"}}],
            [block_event("traversal")])


class AgenticHelperTests(unittest.TestCase):
    def test_canary_values_are_fixture_specific(self):
        self.assertEqual(canary_value("dvwa", "abc"), "CANARY-abc")
        self.assertEqual(canary_value("cve", "abc"), "kunato-lab-canary-abc")
        with self.assertRaises(ValueError):
            canary_value("origin", "abc")

    def test_sqli_and_exec_variants_are_bounded_and_distinct(self):
        sql = sqli_variants()
        self.assertGreaterEqual(len(sql), 3)
        self.assertTrue(any("/**/" in payload for payload in sql))
        self.assertEqual(len(sql), len(set(sql)))
        commands = exec_variants()
        self.assertTrue(any(";" in payload for payload in commands))
        self.assertTrue(any("|" in payload for payload in commands))

    def test_upload_is_a_php_payload_behind_an_image_type(self):
        filename, content_type, payload = upload_variants()[0]
        self.assertEqual(filename, "agentic.php")
        self.assertEqual(content_type, "image/jpeg")
        self.assertIn(b"file_get_contents", payload)
        boundary, body = multipart_body(filename, content_type, payload)
        self.assertIn(boundary.encode(), body)
        self.assertIn(b'name="uploaded"', body)
        self.assertIn(b'name="Upload"', body)

    def test_traversal_variants_stay_on_the_icon_or_cgi_prefix(self):
        paths = traversal_paths()
        self.assertGreaterEqual(len(paths), 2)
        for path in paths:
            self.assertTrue(path.startswith("/icons/"))
            self.assertTrue("%2e" in path or "%2f" in path)


class AgenticValidationTests(unittest.TestCase):
    def test_valid_cases_cover_the_reviewed_chain(self):
        validate_agentic(CASES)

    def test_invalid_fixture_exploit_or_expectation_is_rejected(self):
        for change in ({"fixture": "origin"}, {"exploit": "ssrf"},
                       {"expect": "allow"}, {"description": ""}):
            cases = [dict(case) for case in CASES]
            cases[0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_agentic(cases)

    def test_missing_exploit_class_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_agentic(CASES[:-1])


class AgenticJudgeTests(unittest.TestCase):
    def judge(self, control_dvwa, control_cve, protected_dvwa, protected_cve,
              waf=None):
        waf_dvwa, waf_cve = waf if waf is not None else waf_events()
        return judge_agentic(CASES, control_dvwa, protected_dvwa,
                             control_cve, protected_cve, waf_dvwa, waf_cve)

    def test_blocked_and_observed_exploits_are_prevented(self):
        control_dvwa, control_cve = results(
            {key: True for key in PATHS}, {key: False for key in PATHS})
        protected_dvwa, protected_cve = results(
            {key: False for key in PATHS}, {key: True for key in PATHS})
        judged = self.judge(control_dvwa, control_cve, protected_dvwa, protected_cve)
        self.assertTrue(judged["passed"])
        self.assertEqual(judged["counts"], {"prevented": 4})

    def test_a_protected_canary_is_a_gap(self):
        control_dvwa, control_cve = results(
            {key: True for key in PATHS}, {key: False for key in PATHS})
        protected_dvwa, protected_cve = results(
            {key: False for key in PATHS}, {key: True for key in PATHS})
        protected_dvwa["exploits"]["sqli"]["success"] = True
        judged = self.judge(control_dvwa, control_cve, protected_dvwa, protected_cve)
        self.assertFalse(judged["passed"])
        self.assertEqual(judged["counts"], {"prevented": 3, "gap": 1})

    def test_a_failed_direct_control_is_inconclusive(self):
        control_dvwa, control_cve = results(
            {key: True for key in PATHS}, {key: False for key in PATHS})
        control_dvwa["exploits"]["exec"]["success"] = False
        protected_dvwa, protected_cve = results(
            {key: False for key in PATHS}, {key: True for key in PATHS})
        judged = self.judge(control_dvwa, control_cve, protected_dvwa, protected_cve)
        self.assertFalse(judged["passed"])
        self.assertEqual(judged["counts"], {"prevented": 3, "inconclusive": 1})

    def test_block_status_without_a_matching_waf_event_is_inconclusive(self):
        control_dvwa, control_cve = results(
            {key: True for key in PATHS}, {key: False for key in PATHS})
        protected_dvwa, protected_cve = results(
            {key: False for key in PATHS}, {key: True for key in PATHS})
        judged = self.judge(control_dvwa, control_cve, protected_dvwa, protected_cve,
                            waf=([], []))
        self.assertEqual(judged["counts"], {"inconclusive": 4})

    def test_rate_limited_events_are_not_signature_evidence(self):
        control_dvwa, control_cve = results(
            {key: True for key in PATHS}, {key: False for key in PATHS})
        protected_dvwa, protected_cve = results(
            {key: False for key in PATHS}, {key: True for key in PATHS})
        waf_dvwa = [block_event("sqli", rate_limited=True),
                    block_event("exec", rate_limited=True),
                    {"fields": {"message": "upload content rejected",
                                "path": "/vulnerabilities/upload/"}}]
        waf_cve = [block_event("traversal", rate_limited=True)]
        judged = self.judge(control_dvwa, control_cve, protected_dvwa, protected_cve,
                            waf=(waf_dvwa, waf_cve))
        self.assertEqual(judged["counts"], {"inconclusive": 3, "prevented": 1})

    def test_path_fallback_uses_the_rule_family(self):
        control_dvwa, control_cve = results(
            {key: True for key in PATHS}, {key: False for key in PATHS})
        protected_dvwa, protected_cve = results(
            {key: False for key in PATHS}, {key: True for key in PATHS})
        waf_dvwa, waf_cve = waf_events()
        waf_cve = [block_event("traversal", path="/opt/kunato-lab/canary.txt")]
        judged = self.judge(control_dvwa, control_cve, protected_dvwa, protected_cve,
                            waf=(waf_dvwa, waf_cve))
        self.assertTrue(judged["passed"])


if __name__ == "__main__":
    unittest.main()
