"""Regressions for false success, missing evidence, and benign origin errors."""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from controller import make_config, write_gotestwaf_cases
from evidence import (USER_AGENT, judge_availability, judge_ban_recovery, judge_connect,
                      judge_crs, judge_ffuf, judge_ffuf_behavior, judge_gotestwaf, judge_h2,
                      judge_mutations, judge_nuclei, judge_load, judge_protocol,
                      judge_replay, judge_restart, judge_slow, judge_sqlmap,
                      judge_websocket_lifecycle, judge_zap, judge_zap_workflow,
                      read_jsonl, summarize,
                      validate_mutations, validate_protocol)

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

    def test_read_jsonl_skips_non_json_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text("Traceback (most recent call last):\n"
                            '{"event": "ready", "nonce": "attempt"}\n')
            self.assertEqual(read_jsonl(path), [{"event": "ready", "nonce": "attempt"}])

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


class MutationAndCrsTests(unittest.TestCase):
    @staticmethod
    def mutation(case_id, expect, target):
        return {"id": case_id, "expect": expect, "method": "GET", "target": target,
                "seed": "test-seed", "transform": "test-transform",
                "interpretation": "test interpretation"}

    def test_mutations_retain_seed_and_interpretation(self):
        cases = [self.mutation("mutation-block", "block", "/mut?q=1")]
        controls = [{"id": "mutation-block", "validated": True}]
        results = [{"id": "mutation-block", "status": 403, "origin": None}]
        origin = [{"event": "ready", "nonce": "n"}]
        waf = [{"fields": {"message": "request blocked", "path": "/mut", "rule": "rule",
                           "rate_limited": False}}]
        result = judge_mutations(cases, controls, results, origin, waf, "n")
        self.assertEqual(result["cases"][0]["verdict"], "prevented")
        self.assertEqual(result["cases"][0]["seed"], "test-seed")
        self.assertEqual(result["notes"]["transforms"], ["test-transform"])
        self.assertTrue(result["passed"])

    def test_mutations_require_provenance(self):
        cases = [{"id": "mutation-block", "expect": "block", "method": "GET",
                  "target": "/mut?q=1"}]
        with self.assertRaises(ValueError):
            validate_mutations(cases)

    def test_crs_comparison_records_agreement_and_false_blocks(self):
        cases = [self.mutation("attack", "block", "/attack?q=1"),
                 self.mutation("benign", "allow", "/benign?q=2")]
        nonce = "n"
        body = {"origin": nonce, "case_id": "benign", "target": "/benign?q=2",
                "method": "GET", "user_agent": USER_AGENT,
                "body_sha256": hashlib.sha256(b"").hexdigest()}
        crs_results = [{"id": "attack", "status": 403, "origin": None},
                       {"id": "benign", "status": 200, "origin": nonce,
                        "response": json.dumps(body)}]
        crs_origin = [{"event": "ready", "nonce": nonce},
                      {"event": "received", "nonce": nonce, "case_id": "benign"}]
        kunato = [{"id": "attack", "verdict": "prevented"},
                  {"id": "benign", "verdict": "passed"}]
        result = judge_crs(cases, crs_results, kunato, crs_origin, nonce)
        self.assertTrue(result["passed"])
        self.assertEqual(result["counts"], {"agree-block": 1, "agree-allow": 1})
        false_block = judge_crs(cases,
                                [{"id": "attack", "status": 403, "origin": None},
                                 {"id": "benign", "status": 403, "origin": None}],
                                kunato, [{"event": "ready", "nonce": nonce}], nonce)
        self.assertEqual(false_block["counts"], {"agree-block": 1, "crs-false-block": 1})
        self.assertTrue(false_block["passed"])


class LoadTests(unittest.TestCase):
    def summary(self, p95, p99, failed=0.0, checks=1.0, requests=3000):
        return {"metrics": {
            "http_reqs": {"count": requests},
            "http_req_failed": {"value": failed},
            "checks": {"value": checks},
            "http_req_duration": {"p(95)": p95, "p(99)": p99},
        }}

    def test_load_suite_passes_within_ceilings(self):
        result = judge_load(self.summary(50, 120), {"sent": 8, "closed": 8},
                            {"status": 200}, {"status": 200},
                            {"CPUPerc": "1.0%"}, {"CPUPerc": "50.0%"},
                            {"CPUPerc": "1.0%", "MemUsage": "21.4MiB / 256MiB"}, 0)
        self.assertTrue(result["passed"])
        self.assertEqual(result["notes"]["p95_ms"], 50)

    def test_load_suite_fails_on_latency(self):
        result = judge_load(self.summary(500, 900), {"sent": 8, "closed": 8},
                            {"status": 200}, {"status": 200}, {}, {}, {}, 0)
        self.assertFalse(result["passed"])
        self.assertEqual(result["cases"][0]["verdict"], "failed")

    def test_load_metrics_must_match_and_show_no_false_blocks(self):
        metrics = {"response": "\n".join([
            "# HELP kunato_requests_total Total HTTP requests handled.",
            "kunato_requests_total 3001",
            "kunato_blocked_total 0",
            "kunato_rate_limited_total 0",
            "kunato_overloaded_total 0",
            "kunato_upstream_timeouts_total 0",
        ])}
        result = judge_load(self.summary(50, 120), {"sent": 8, "closed": 8},
                            {"status": 200}, {"status": 200}, {}, {}, {}, 0, metrics)
        self.assertTrue(result["passed"])
        self.assertEqual(result["cases"][-1]["verdict"], "passed")
        self.assertEqual(result["notes"]["metric_requests"], 3001)
        metrics["response"] = metrics["response"].replace(
            "kunato_blocked_total 0", "kunato_blocked_total 1")
        result = judge_load(self.summary(50, 120), {"sent": 8, "closed": 8},
                            {"status": 200}, {"status": 200}, {}, {}, {}, 0, metrics)
        self.assertFalse(result["passed"])
        self.assertEqual(result["cases"][-1]["verdict"], "failed")
        missing = judge_load(self.summary(50, 120), {"sent": 8, "closed": 8},
                             {"status": 200}, {"status": 200}, {}, {}, {}, 0, {})
        self.assertFalse(missing["passed"])
        self.assertEqual(missing["cases"][-1]["verdict"], "failed")


class RestartTests(unittest.TestCase):
    def summary(self, requests=400, checks=0.9):
        return {"metrics": {"http_reqs": {"count": requests},
                            "checks": {"value": checks}}}

    def test_restart_suite_requires_graceful_exit_and_recovery(self):
        result = judge_restart(self.summary(), 0, 1200, {"status": 200},
                               {"status": 200}, {},
                               {"MemUsage": "22MiB / 256MiB"})
        self.assertTrue(result["passed"])
        self.assertEqual(result["notes"]["exit_code"], 0)

    def test_restart_suite_fails_on_a_signal_exit(self):
        result = judge_restart(self.summary(), 143, 100, {"status": 200},
                               {"status": 200}, {}, {})
        self.assertFalse(result["passed"])
        self.assertEqual(result["cases"][0]["verdict"], "failed")

    def test_restart_suite_fails_without_recovery(self):
        result = judge_restart(self.summary(), 0, 1200, {"status": 503},
                               {"status": 200}, {}, {})
        self.assertFalse(result["passed"])
        self.assertEqual(result["cases"][2]["verdict"], "failed")


class H2Tests(unittest.TestCase):
    def results(self):
        normal = {"ok": True}
        attack = {"normal": True}
        origin = [{"event": "received", "case_id": case}
                  for case in ("h2-normal", "h2-independent", "h2-rapid-reset-normal",
                               "h2-continuation-normal", "h2-hpack-normal")]
        return normal, attack, attack, attack, normal, origin

    def test_h2_suite_requires_post_attack_normal_requests(self):
        normal, rapid, continuation, hpack, independent, origin = self.results()
        result = judge_h2(normal, rapid, continuation, hpack, independent, origin, {},
                          {"MemUsage": "21MiB / 256MiB"}, 0,
                          {"response": "kunato_requests_total 10\n"})
        self.assertTrue(result["passed"])
        self.assertEqual(result["notes"]["receipts"]["h2-rapid-reset-normal"], 1)

    def test_h2_suite_fails_without_a_post_attack_normal_request(self):
        normal, rapid, continuation, hpack, independent, origin = self.results()
        origin = [event for event in origin
                  if event.get("case_id") != "h2-continuation-normal"]
        result = judge_h2(normal, rapid, continuation, hpack, independent, origin, {},
                          {"MemUsage": "21MiB / 256MiB"}, 0,
                          {"response": "kunato_requests_total 10\n"})
        self.assertFalse(result["passed"])
        self.assertEqual(result["cases"][2]["verdict"], "failed")


class SlowTests(unittest.TestCase):
    def test_slow_suite_requires_normal_health(self):
        slow = {"sent": 8, "closed": 8, "held_seconds": 2}
        normal = {"status": 200}
        before = {"CPUPerc": "1.0%", "MemUsage": "10MiB / 1GiB"}
        after = {"CPUPerc": "2.0%", "MemUsage": "12MiB / 1GiB"}
        result = judge_slow(slow, normal, before, after)
        self.assertTrue(result["passed"])
        self.assertEqual(result["cases"][1]["verdict"], "passed")
        blocked = judge_slow(slow, {"status": 429}, before, after)
        self.assertEqual(blocked["cases"][1]["verdict"], "false-block")


class AvailabilityTests(unittest.TestCase):
    def payloads(self):
        return ({"sent": 8, "closed": 0}, {"status": 408}, {"status": 200},
                {"status": 503}, {"status": 504}, {"status": 200},
                {"CPUPerc": "1.0%", "MemUsage": "10MiB / 256MiB"},
                {"CPUPerc": "2.0%", "MemUsage": "21MiB / 256MiB"}, 0)

    def test_availability_suite_bounds_each_probe(self):
        metrics = {"response": "kunato_requests_total 42\n"
                               "kunato_upstream_timeouts_total 1\n"}
        result = judge_availability(*self.payloads(), metrics)
        self.assertTrue(result["passed"])
        self.assertEqual(result["notes"]["connection_cap_status"], 503)
        self.assertEqual(result["notes"]["upstream_timeouts"], 1)

    def test_availability_suite_rejects_an_unbounded_body(self):
        slow, _, slow_read, exhaustion, upstream, normal, before, after, restarts = self.payloads()
        result = judge_availability(slow, {"status": 200}, slow_read, exhaustion,
                                    upstream, normal, before, after, restarts)
        self.assertFalse(result["passed"])
        self.assertEqual(result["cases"][1]["verdict"], "failed")

    def test_availability_suite_requires_a_upstream_timeout(self):
        slow, slow_body, slow_read, exhaustion, _, normal, before, after, restarts = self.payloads()
        result = judge_availability(slow, slow_body, slow_read, exhaustion, {"status": 504},
                                    normal, before, after, restarts,
                                    {"response": "kunato_requests_total 10\n"})
        self.assertFalse(result["passed"])
        self.assertEqual(result["cases"][-1]["verdict"], "failed")

    def test_availability_suite_bounds_global_exhaustion(self):
        metrics = {"response": "kunato_requests_total 42\n"
                               "kunato_upstream_timeouts_total 1\n"}
        result = judge_availability(*self.payloads(), metrics,
                                    global_cap={"status": 503, "active_connections": 16})
        self.assertTrue(result["passed"])
        self.assertEqual(result["notes"]["global_cap_status"], 503)
        self.assertEqual(result["notes"]["global_active_connections"], 16)
        self.assertEqual([case["id"] for case in result["cases"]].count("global-connection-cap"), 1)

    def test_availability_suite_rejects_global_exhaustion_without_active_connections(self):
        metrics = {"response": "kunato_requests_total 42\n"
                               "kunato_upstream_timeouts_total 1\n"}
        result = judge_availability(*self.payloads(), metrics,
                                    global_cap={"status": 503, "active_connections": 8})
        self.assertFalse(result["passed"])
        case = next(case for case in result["cases"] if case["id"] == "global-connection-cap")
        self.assertEqual(case["verdict"], "inconclusive")


class ConnectTests(unittest.TestCase):
    def test_connect_suite_requires_a_connect_timeout_and_metric(self):
        metrics = {"response": "kunato_upstream_connect_errors_total 1\n"}
        result = judge_connect({"status": 502}, {},
                               {"MemUsage": "21MiB / 256MiB"}, 0, metrics)
        self.assertTrue(result["passed"])
        self.assertEqual(result["notes"]["connect_status"], 502)
        self.assertEqual(result["notes"]["upstream_connect_errors"], 1)

    def test_connect_suite_rejects_a_forwarded_request(self):
        metrics = {"response": "kunato_upstream_connect_errors_total 1\n"}
        result = judge_connect({"status": 200}, {},
                               {"MemUsage": "21MiB / 256MiB"}, 0, metrics)
        self.assertFalse(result["passed"])
        self.assertEqual(result["cases"][0]["verdict"], "failed")

    def test_connect_suite_requires_the_connect_error_metric(self):
        metrics = {"response": "kunato_upstream_connect_errors_total 0\n"}
        result = judge_connect({"status": 502}, {},
                               {"MemUsage": "21MiB / 256MiB"}, 0, metrics)
        self.assertFalse(result["passed"])
        self.assertEqual(result["cases"][1]["verdict"], "failed")


class BanTests(unittest.TestCase):
    def test_ban_recovery_requires_a_ban_and_a_recovered_source(self):
        metrics = {"response": "kunato_requests_total 12\nkunato_banned_total 1\n"}
        result = judge_ban_recovery(
            {"statuses": [200, 429, 429, 429], "recovery_status": 200},
            {"status": 200}, {}, {"MemUsage": "21MiB / 256MiB"}, 0, metrics)
        self.assertTrue(result["passed"])
        self.assertEqual(result["cases"][-1]["verdict"], "passed")

    def test_ban_recovery_fails_without_a_ban_or_recovery(self):
        metrics = {"response": "kunato_requests_total 12\nkunato_banned_total 0\n"}
        result = judge_ban_recovery(
            {"statuses": [200, 200], "recovery_status": 429},
            {"status": 200}, {}, {"MemUsage": "21MiB / 256MiB"}, 0, metrics)
        self.assertFalse(result["passed"])
        self.assertEqual(result["cases"][0]["verdict"], "failed")
        self.assertEqual(result["cases"][1]["verdict"], "failed")


class WebSocketTests(unittest.TestCase):
    def complete(self):
        return {"status": 101, "pong": True, "echo": "echo:fragmented", "closed": True}

    def test_websocket_lifecycle_checks_ping_fragments_and_close(self):
        result = judge_websocket_lifecycle(self.complete(), self.complete(),
                                           {"status": 200})
        self.assertTrue(result["passed"])
        self.assertEqual(result["notes"]["echo"], "echo:fragmented")

    def test_websocket_lifecycle_fails_closed_without_a_valid_control(self):
        result = judge_websocket_lifecycle({"status": 101, "error": "reset"},
                                           self.complete(), {"status": 200})
        self.assertFalse(result["passed"])
        self.assertEqual(result["cases"][0]["verdict"], "failed")
        self.assertEqual(result["cases"][1]["verdict"], "inconclusive")

    def test_websocket_lifecycle_rejects_a_false_block(self):
        result = judge_websocket_lifecycle(self.complete(), self.complete(),
                                           {"status": 429})
        self.assertFalse(result["passed"])
        self.assertEqual(result["cases"][-1]["verdict"], "false-block")

    def payloads(self):
        return (
            {"status": 101, "echo": "echo:<script>alert(1)</script>",
             "benign_echo": "echo:benign payload"},
            {"status": 101, "blocked": True, "close_code": 1008,
             "benign_echo": "echo:benign payload"},
        )

    def test_websocket_payload_inspection_requires_a_controlled_block(self):
        control, protected = self.payloads()
        result = judge_websocket_lifecycle(self.complete(), self.complete(),
                                           {"status": 200}, control, protected)
        self.assertTrue(result["passed"])
        self.assertEqual(result["notes"]["payload_close_code"], 1008)

    def test_websocket_payload_inspection_rejects_a_missed_block(self):
        control, protected = self.payloads()
        protected["blocked"] = False
        result = judge_websocket_lifecycle(self.complete(), self.complete(),
                                           {"status": 200}, control, protected)
        self.assertFalse(result["passed"])
        case = next(case for case in result["cases"] if case["id"] == "ws-payload-block")
        self.assertEqual(case["verdict"], "failed")


class ProtocolTests(unittest.TestCase):
    @staticmethod
    def case(case_id, expect, framing="reject", smuggled=None):
        case = {"id": case_id, "expect": expect, "interpretation": "test",
                "direct_framing": framing, "raw": "GET / HTTP/1.1\r\n\r\n"}
        if smuggled:
            case["smuggled_case"] = smuggled
        return case

    def judged(self, protected_extra=None, direct_smuggled=True):
        cases = [self.case("valid", "allow"),
                 self.case("smuggle", "block", "te", "smuggle-2")]
        controls = [{"id": "valid", "status": 200}, {"id": "smuggle", "status": 200}]
        results = [{"id": "valid", "status": 200}, {"id": "smuggle", "status": 400}]
        direct = {
            "reject": [{"event": "ready", "nonce": "a"},
                       {"event": "received", "nonce": "a", "case_id": "valid"},
                       {"event": "completed", "nonce": "a", "case_id": "valid"}],
            "te": [{"event": "ready", "nonce": "b"},
                   {"event": "received", "nonce": "b", "case_id": "smuggle"}]
            + ([{"event": "received", "nonce": "b", "case_id": "smuggle-2"}]
               if direct_smuggled else []),
        }
        protected = [{"event": "ready", "nonce": "c"},
                     {"event": "received", "nonce": "c", "case_id": "valid"},
                     {"event": "completed", "nonce": "c", "case_id": "valid"}]
        if protected_extra:
            protected.append({"event": "received", "nonce": "c", "case_id": protected_extra})
        return judge_protocol(cases, controls, results, direct, protected,
                              {"reject": "a", "te": "b"}, "c")

    def test_protocol_smuggling_requires_direct_second_request(self):
        result = self.judged()
        self.assertEqual([case["verdict"] for case in result["cases"]],
                         ["passed", "prevented"])
        self.assertTrue(result["passed"])

    def test_protocol_protected_smuggled_receipt_is_gap(self):
        result = self.judged(protected_extra="smuggle-2")
        self.assertEqual(result["cases"][1]["verdict"], "gap")
        self.assertFalse(result["passed"])

    def test_protocol_direct_without_smuggled_is_inconclusive(self):
        result = self.judged(direct_smuggled=False)
        self.assertEqual(result["cases"][1]["verdict"], "inconclusive")
        self.assertFalse(result["passed"])

    def test_protocol_requires_interpretation(self):
        cases = [{"id": "valid", "expect": "allow", "raw": "GET / HTTP/1.1\r\n\r\n"}]
        with self.assertRaises(ValueError):
            validate_protocol(cases)


if __name__ == "__main__":
    unittest.main()
