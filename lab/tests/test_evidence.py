"""Regressions for false success, missing evidence, and benign origin errors."""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from controller import make_config, write_gotestwaf_cases
from evidence import USER_AGENT, judge_gotestwaf, judge_replay, summarize

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


if __name__ == "__main__":
    unittest.main()
