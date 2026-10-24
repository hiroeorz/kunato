"""Regressions for false success, missing evidence, and benign origin errors."""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from controller import make_config, write_gotestwaf_cases
from evidence import (USER_AGENT, judge_ffuf, judge_ffuf_behavior, judge_gotestwaf,
                      judge_nuclei, judge_replay, judge_sqlmap, judge_zap,
                      judge_zap_workflow, summarize)

class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.case = {"id": "sample", "expect": "block", "method": "GET", "target": "/search?q=attack"}
        self.control = {"id": "sample", "validated": True}
        self.response = {"id": "sample", "status": 403, "origin": None}
        self.events = [{"event": "ready", "nonce": "attempt"}]
        self.waf = [{"fields": {"message": "request blocked", "path": "/search",
                                "category": "injection", "rule": "payload", "rate_limited": False}}]

    def verdict(self):
        return judge_replay([self.case], [self.control], [self.response], self.events, self.waf, "attempt")[0]["verdict"]

    def test_known_rule_block_requires_origin_and_rule_evidence(self):
        self.assertEqual(self.verdict(), "prevented")
        self.waf = []
        self.assertEqual(self.verdict(), "inconclusive")

    def test_upstream_receipt_is_a_gap_even_with_403(self):
        self.events.append({"event": "received", "nonce": "attempt", "case_id": "sample"})
        self.assertEqual(self.verdict(), "gap")

    def test_transport_error_cannot_pass(self):
        self.response = {"id": "sample", "error": "connection reset"}
        self.assertEqual(self.verdict(), "inconclusive")

    def test_ban_cannot_masquerade_as_signature_detection(self):
        self.waf[0]["fields"]["rate_limited"] = True
        self.assertEqual(self.verdict(), "inconclusive")

    def test_failed_positive_control_cannot_pass(self):
        self.control["validated"] = False
        self.assertEqual(self.verdict(), "inconclusive")

    def test_missing_or_stale_observations_fail_closed(self):
        for events in ([], [{"event": "ready", "nonce": "previous"}]):
            with self.subTest(events=events), self.assertRaises(ValueError):
                judge_replay([self.case], [self.control], [self.response], events, self.waf, "attempt")

    def test_missing_probe_result_is_not_a_pass(self):
        with self.assertRaises(ValueError):
            judge_replay([self.case], [self.control], [], self.events, self.waf, "attempt")

    def test_origin_404_is_a_valid_normal_response(self):
        self.case.update(expect="allow", status=404)
        body = {"origin": "attempt", "case_id": "sample", "method": "GET", "target": self.case["target"],
                "user_agent": USER_AGENT,
                "body_sha256": hashlib.sha256(b"").hexdigest()}
        self.response.update(status=404, origin="attempt", response=json.dumps(body))
        self.events += [{"event": event, "nonce": "attempt", "case_id": "sample"}
                        for event in ("received", "completed")]
        self.assertEqual(self.verdict(), "passed")
        self.response["response"] = "Wrong application result"
        self.assertEqual(self.verdict(), "false-block")

    def test_empty_results_never_pass(self):
        self.assertFalse(summarize([])["passed"])

    def test_missing_gotestwaf_cases_never_pass(self):
        with self.assertRaises(ValueError):
            judge_gotestwaf({}, self.events, [], "attempt", {"sample": "block"})

    def test_gotestwaf_403_leak_is_a_gap(self):
        report = {"summary": {"true_positive_tests": {"test_sets": {
            "attacks": {"sample": {"sent": 1, "blocked": 1}}}}}}
        self.events.append({"event": "received", "nonce": "attempt", "target": "/case/sample?q=x"})
        result = judge_gotestwaf(report, self.events, [], "attempt", {"sample": "block"})
        self.assertEqual(result[0]["verdict"], "gap")

    def test_gotestwaf_successful_payload_details_can_be_absent(self):
        report = {"summary": {"true_negative_tests": {"test_sets": {
            "false-pos": {"sample": {"sent": 1, "bypassed": 1}}}}}}
        self.events += [{"event": event, "nonce": "attempt", "target": "/case/sample",
                         "user_agent": USER_AGENT} for event in ("received", "completed")]
        result = judge_gotestwaf(report, self.events, [], "attempt", {"sample": "allow"})
        self.assertEqual(result[0]["verdict"], "passed")

    def test_gotestwaf_payload_placement_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)
            write_gotestwaf_cases(destination, [self.case])
            template = json.loads((destination / "attacks/sample.yml").read_text())
            request = template["placeholder"][0]["RawRequest"]
            self.assertEqual(request["path"], "/case/sample?{{payload}}")
            self.assertEqual(request["body"], "")

    def test_gotestwaf_does_not_double_encode_the_preencoded_query(self):
        case = {**self.case, "target": "/search?q=O%27Reilly"}
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)
            write_gotestwaf_cases(destination, [case])
            template = json.loads((destination / "attacks/sample.yml").read_text())
            self.assertEqual(template["payload"], ["q=O'Reilly"])

    def test_private_test_sources_cannot_retain_allow_rule(self):
        original = (Path(__file__).resolve().parents[2] / "rules.example.yaml").read_text()
        config = make_config(original)
        self.assertNotIn("name: trusted-sources", config)
        self.assertNotIn("name: internal-networks", config)
        self.assertIn("name: scanners-and-bots", config)
        self.assertIn("upstream: http://origin:8080", config)
        self.assertIn("upstream: http://dvwa:80", make_config(original, "http://dvwa:80"))

    def test_sqlmap_extracted_canary_prevents_the_bounded_dump(self):
        control_nonce, protected_nonce = "a" * 32, "b" * 32
        control_output = f"Table: lab_canary\n| 1 | CANARY-{control_nonce} |\n"
        control_access = ('10.0.0.2 - - [24/Oct/2026:08:00:00 +0000] "GET '
                          '/vulnerabilities/sqli/?id=1%27%20UNION HTTP/1.1" 200 100 "-" "'
                          + USER_AGENT + '"\n')
        protected_access = ('10.0.0.3 - - [24/Oct/2026:08:00:01 +0000] "GET '
                            '/vulnerabilities/sqli/?id=1&Submit=Submit HTTP/1.1" 200 100 "-" "'
                            + USER_AGENT + '"\n')
        waf = [{"fields": {"message": "request blocked", "path": "/vulnerabilities/sqli/",
                           "category": "sql-injection", "rule": "union-select", "rate_limited": False}}]
        result = judge_sqlmap(control_output, "all tested parameters do not appear to be injectable\n403 (Forbidden) - 80 times",
                              control_access, protected_access, waf, protected_nonce, control_nonce)
        self.assertEqual([case["verdict"] for case in result["cases"]], ["passed", "prevented"])
        self.assertTrue(result["passed"])

    def test_sqlmap_protected_canary_is_a_gap(self):
        control_nonce, protected_nonce = "a" * 32, "b" * 32
        control_output = f"Table: lab_canary\n| 1 | CANARY-{control_nonce} |\n"
        control_access = ('10.0.0.2 - - [24/Oct/2026:08:00:00 +0000] "GET '
                          '/vulnerabilities/sqli/?id=1%27%20UNION HTTP/1.1" 200 100 "-" "'
                          + USER_AGENT + '"\n')
        protected_access = ('10.0.0.2 - - [24/Oct/2026:08:00:00 +0000] "GET '
                            '/vulnerabilities/sqli/?id=1%27%20UNION HTTP/1.1" 200 100 "-" "'
                            + USER_AGENT + '"\n')
        waf = [{"fields": {"message": "request blocked", "path": "/vulnerabilities/sqli/",
                           "rate_limited": False}}]
        result = judge_sqlmap(control_output, f"Table: lab_canary\n| 1 | CANARY-{protected_nonce} |\n",
                              control_access, protected_access, waf, protected_nonce, control_nonce)
        self.assertEqual(result["cases"][1]["verdict"], "gap")
        self.assertFalse(result["passed"])

    def test_sqlmap_control_failure_is_inconclusive(self):
        result = judge_sqlmap("not injectable", "not injectable", "", "", [],
                              "b" * 32, "a" * 32)
        self.assertEqual(result["cases"][0]["verdict"], "inconclusive")
        self.assertFalse(result["passed"])

    def test_nuclei_canary_prevents_the_bounded_exploit(self):
        control_nonce, protected_nonce = "a" * 32, "b" * 32
        control_result = json.dumps({
            "template-id": "kunato-lab-cve-2021-41773-canary",
            "matched-at": "http://cve:80/icons/.%2e/opt/kunato-lab/canary.txt",
            "request": "GET /icons/.%2e/opt/kunato-lab/canary.txt HTTP/1.1\r\n"
                       f"User-Agent: {USER_AGENT}\r\n\r\n",
            "response": f"HTTP/1.1 200 OK\r\n\r\nkunato-lab-canary-{control_nonce}\n",
            "matcher-status": True,
        })
        control_access = ('10.0.0.2 - - [24/Oct/2026:08:00:00 +0000] "GET '
                          '/icons/.%2e/.%2e/opt/kunato-lab/canary.txt HTTP/1.1" 200 52\n')
        waf = [{"fields": {"message": "request blocked",
                           "path": "/icons/.%2e/.%2e/opt/kunato-lab/canary.txt",
                           "category": "path-traversal", "rule": "dot-dot-slash", "rate_limited": False}}]
        result = judge_nuclei(control_result + "\n", "", control_access, "", waf,
                              protected_nonce, control_nonce)
        self.assertEqual([case["verdict"] for case in result["cases"]], ["passed", "prevented"])
        self.assertTrue(result["passed"])

    def test_nuclei_protected_canary_is_a_gap(self):
        control_nonce, protected_nonce = "a" * 32, "b" * 32
        control_result = json.dumps({
            "template-id": "kunato-lab-cve-2021-41773-canary",
            "request": f"GET /icons/.%2e/opt/kunato-lab/canary.txt HTTP/1.1\r\nUser-Agent: {USER_AGENT}\r\n\r\n",
            "response": f"HTTP/1.1 200 OK\r\n\r\nkunato-lab-canary-{control_nonce}\n",
        })
        protected_result = json.dumps({
            "template-id": "kunato-lab-cve-2021-41773-canary",
            "request": f"GET /icons/.%2e/opt/kunato-lab/canary.txt HTTP/1.1\r\nUser-Agent: {USER_AGENT}\r\n\r\n",
            "response": f"HTTP/1.1 200 OK\r\n\r\nkunato-lab-canary-{protected_nonce}\n",
        })
        control_access = ('10.0.0.2 - - [24/Oct/2026:08:00:00 +0000] "GET '
                          '/icons/.%2e/.%2e/opt/kunato-lab/canary.txt HTTP/1.1" 200 52\n')
        result = judge_nuclei(control_result + "\n", protected_result + "\n", control_access, "", [],
                              protected_nonce, control_nonce)
        self.assertEqual(result["cases"][1]["verdict"], "gap")
        self.assertFalse(result["passed"])

    def test_nuclei_origin_receipt_without_canary_is_inconclusive(self):
        control_nonce, protected_nonce = "a" * 32, "b" * 32
        control_result = json.dumps({
            "template-id": "kunato-lab-cve-2021-41773-canary",
            "request": f"GET /icons/.%2e/opt/kunato-lab/canary.txt HTTP/1.1\r\nUser-Agent: {USER_AGENT}\r\n\r\n",
            "response": f"HTTP/1.1 200 OK\r\n\r\nkunato-lab-canary-{control_nonce}\n",
        })
        control_access = ('10.0.0.2 - - [24/Oct/2026:08:00:00 +0000] "GET '
                          '/icons/.%2e/.%2e/opt/kunato-lab/canary.txt HTTP/1.1" 200 52\n')
        protected_access = ('10.0.0.3 - - [24/Oct/2026:08:00:01 +0000] "GET '
                            '/icons/.%2e/.%2e/opt/kunato-lab/canary.txt HTTP/1.1" 403 0\n')
        result = judge_nuclei(control_result + "\n", "", control_access, protected_access, [],
                              protected_nonce, control_nonce)
        self.assertEqual(result["cases"][1]["verdict"], "inconclusive")
        self.assertFalse(result["passed"])


class FfufAndZapTests(unittest.TestCase):
    @staticmethod
    def ffuf_report(*entries):
        return {"results": [{"input": {"FUZZ": path.lstrip("/")},
                             "url": f"http://lab{path}",
                             "status": status, "length": length}
                            for path, status, length in entries]}

    @staticmethod
    def access(*targets, status=404):
        return "".join(f'10.0.0.2 - - [24/Oct/2026:08:00:00 +0000] "GET {target} HTTP/1.1" '
                       f'{status} 1 "-" "{USER_AGENT}"\n' for target in targets)

    @staticmethod
    def block(path, rule="credentials-and-config"):
        return {"fields": {"message": "request blocked", "path": path, "rule": rule,
                           "rate_limited": False}}

    def test_ffuf_discovery_requires_receipts_blocks_and_logs(self):
        cases = [{"path": "/about", "expect": "allow"},
                 {"path": "/.env", "expect": "block"},
                 {"path": "/wp-admin/", "expect": "log"}]
        control = self.ffuf_report(("/about", 404, 306), ("/.env", 404, 306),
                                   ("/wp-admin/", 404, 306))
        protected = self.ffuf_report(("/about", 404, 306), ("/.env", 403, 9),
                                     ("/wp-admin/", 404, 306))
        waf = [self.block("/.env"),
               {"fields": {"action": "LOG", "path": "/wp-admin/", "rule": "common-admin-paths"}}]
        result = judge_ffuf(control, protected, self.access("/about", "/.env", "/wp-admin/"),
                            self.access("/about", "/wp-admin/"), waf, cases)
        self.assertEqual([case["verdict"] for case in result["cases"]],
                         ["passed", "prevented", "passed"])
        self.assertTrue(result["passed"])

    def test_ffuf_discovery_detects_false_block_and_missing_log(self):
        cases = [{"path": "/about", "expect": "allow"}, {"path": "/wp-admin/", "expect": "log"}]
        control = self.ffuf_report(("/about", 404, 306), ("/wp-admin/", 404, 306))
        protected = self.ffuf_report(("/about", 404, 306), ("/wp-admin/", 404, 306))
        result = judge_ffuf(control, protected, self.access("/about", "/wp-admin/"),
                            self.access("/wp-admin/"), [], cases)
        self.assertEqual([case["verdict"] for case in result["cases"]],
                         ["false-block", "inconclusive"])
        self.assertFalse(result["passed"])

    def test_ffuf_discovery_receipt_on_block_path_is_a_gap(self):
        cases = [{"path": "/.env", "expect": "block"}]
        control = self.ffuf_report(("/.env", 404, 306))
        protected = self.ffuf_report(("/.env", 403, 9))
        result = judge_ffuf(control, protected, self.access("/.env"),
                            self.access("/.env", status=403), [self.block("/.env")], cases)
        self.assertEqual(result["cases"][0]["verdict"], "gap")
        self.assertFalse(result["passed"])

    def test_ffuf_behavior_requires_a_ban_and_healthy_normal_client(self):
        report = self.ffuf_report(("/missing-01", 429, 0), ("/index.php", 200, 100))
        access = self.access("/index.php")
        prevented = judge_ffuf_behavior(report, access, [], {"status": 200})
        self.assertEqual(prevented["cases"][0]["verdict"], "prevented")
        self.assertTrue(prevented["passed"])
        false_block = judge_ffuf_behavior(report, access, [], {"status": 429})
        self.assertEqual(false_block["cases"][0]["verdict"], "false-block")
        gap = judge_ffuf_behavior(self.ffuf_report(("/index.php", 200, 100)), access, [],
                                  {"status": 200})
        self.assertEqual(gap["cases"][0]["verdict"], "gap")

    def test_zap_workflow_compares_authenticated_reach(self):
        report = {"site": [{"alerts": []}]}
        log = "Job spider found 120 URLs\n"
        passed = judge_zap_workflow(log, log, report, report, self.access("/index.php"),
                                    self.access("/index.php"), [])
        self.assertTrue(passed["passed"])
        short = judge_zap_workflow(log, "Job spider found 10 URLs\n", report, report,
                                   self.access("/index.php"), self.access("/index.php"), [])
        self.assertEqual(short["cases"][1]["verdict"], "false-block")
        self.assertFalse(short["passed"])

    def test_zap_workflow_without_control_fails_closed(self):
        result = judge_zap_workflow("", "Job spider found 10 URLs\n", {}, {"site": [{}]},
                                    "", "", [])
        self.assertEqual(result["cases"][0]["verdict"], "inconclusive")
        self.assertFalse(result["passed"])

    def test_zap_active_scan_detects_protected_open(self):
        control = {"site": [{"alerts": [{"pluginid": "40018", "alert": "SQL Injection",
                                        "instances": [{"uri": "http://dvwa/vulnerabilities/sqli/"}]}]}]}
        waf = [self.block("/vulnerabilities/sqli/", rule="union-select")]
        prevented = judge_zap(control, {"site": []}, "", "", waf)
        self.assertEqual(prevented["cases"][1]["verdict"], "prevented")
        self.assertTrue(prevented["passed"])
        gap = judge_zap(control, control, "", "", waf)
        self.assertEqual(gap["cases"][1]["verdict"], "gap")
        self.assertFalse(gap["passed"])


if __name__ == "__main__":
    unittest.main()
