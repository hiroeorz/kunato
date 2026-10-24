"""Fail-closed verdicts for the bounded signature lab, independent of Docker."""

import hashlib
import json
from collections import Counter
from pathlib import Path

USER_AGENT = "Mozilla/5.0 KunatoLabClient/1.0"


def read_jsonl(path):
    lines = Path(path).read_text().splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def verify_origin(events, nonce):
    if not events or not any(event.get("event") == "ready" for event in events):
        raise ValueError("Origin startup evidence is missing")
    if any(event.get("nonce") != nonce for event in events):
        raise ValueError("Origin evidence belongs to another attempt")
    if any(event.get("event") == "error" for event in events):
        raise ValueError("Origin failed to consume a request")


def validate_cases(cases):
    ids = [case["id"] for case in cases]
    if not cases or len(ids) != len(set(ids)):
        raise ValueError("Cases must be nonempty with unique IDs")
    for case in cases:
        if case["expect"] not in {"allow", "block"}:
            raise ValueError("Invalid expectation")
        if not case["target"].startswith("/") or "\r" in case["target"] or "\n" in case["target"]:
            raise ValueError("Cases must use relative HTTP request targets")
        if case["method"] not in {"GET", "POST"}:
            raise ValueError("Unsupported method")


def origin_response(case, result, nonce):
    if result.get("error") or result.get("origin") != nonce:
        return False
    if result.get("status") != case.get("status", 200):
        return False
    try:
        body = json.loads(result["response"])
    except (ValueError, KeyError, TypeError):
        return False
    return (body.get("origin") == nonce and body.get("case_id") == case["id"]
            and body.get("target") == case["target"] and body.get("method") == case["method"]
            and body.get("user_agent") == USER_AGENT
            and body.get("body_sha256") == hashlib.sha256(case.get("body", "").encode()).hexdigest())


def judge_replay(cases, controls, results, origin, waf_events, nonce):
    validate_cases(cases)
    verify_origin(origin, nonce)
    expected_ids = {case["id"] for case in cases}
    for observations in (controls, results):
        ids = [result["id"] for result in observations]
        if len(ids) != len(set(ids)) or set(ids) != expected_ids:
            raise ValueError("Missing, duplicate, or unexpected probe results")
    controls = {result["id"]: result for result in controls}
    results = {result["id"]: result for result in results}
    receipts = Counter(event.get("case_id") for event in origin if event.get("event") == "received")
    completed = Counter(event.get("case_id") for event in origin if event.get("event") == "completed")
    verdicts = []
    for case in cases:
        result = results[case["id"]]
        control = controls[case["id"]]
        blocks = [event["fields"] for event in waf_events
                  if event.get("fields", {}).get("message") == "request blocked"
                  and event["fields"].get("path") == case["target"].split("?", 1)[0]
                  and event["fields"].get("rate_limited") is False]
        if not control.get("validated"):
            verdict = "inconclusive"
        elif case["expect"] == "block" and receipts[case["id"]]:
            verdict = "gap"
        elif result.get("error"):
            verdict = "inconclusive"
        elif case["expect"] == "allow":
            verdict = "passed" if (origin_response(case, result, nonce)
                                     and receipts[case["id"]] == completed[case["id"]] == 1) else "false-block"
        else:
            verdict = "prevented" if (result.get("status") == 403 and result.get("origin") is None
                                       and len(blocks) == 1) else "inconclusive"
        verdicts.append({"id": case["id"], "expect": case["expect"], "verdict": verdict,
                         "status": result.get("status"), "origin_receipts": receipts[case["id"]],
                         "rules": [{"category": b.get("category"), "rule": b.get("rule")} for b in blocks]})
    return verdicts


def judge_gotestwaf(report, origin, waf_events, nonce, planned, control=False):
    verify_origin(origin, nonce)
    verdicts = []
    # v0.5.8 omits successful payload details; per-case summary counters account
    # for every execution, while origin events independently establish receipt.
    for key, expectation in (("true_positive_tests", "block"), ("true_negative_tests", "allow")):
        group = report.get("summary", {}).get(key, {})
        for test_set in group.get("test_sets", {}).values():
            for case_id, result in test_set.items():
                outcomes = [name for name in ("blocked", "bypassed", "unresolved", "failed") if result.get(name) == 1]
                if result.get("sent") != 1 or len(outcomes) != 1 or sum(result.get(name, 0) for name in
                        ("blocked", "bypassed", "unresolved", "failed")) != 1:
                    raise ValueError("Expected exactly one goTestWAF execution per smoke case")
                result_name = outcomes[0]
                if planned.get(case_id) != expectation:
                    raise ValueError("goTestWAF case expectation differs from the input plan")
                matching = [event for event in origin if event.get("event") == "received"
                            and event.get("target", "").split("?", 1)[0] == f"/case/{case_id}"]
                completed = [event for event in origin if event.get("event") == "completed"
                             and event.get("target", "").split("?", 1)[0] == f"/case/{case_id}"]
                blocks = [event["fields"] for event in waf_events
                          if event.get("fields", {}).get("message") == "request blocked"
                          and event["fields"].get("path") == f"/case/{case_id}"
                          and event["fields"].get("rate_limited") is False]
                # Every smoke case has one payload, one placement, and one encoder.
                if result_name in {"failed", "unresolved"}:
                    verdict = "inconclusive"
                elif control:
                    verdict = "passed" if (result_name == "bypassed" and len(matching) == len(completed) == 1
                                             and matching[0].get("user_agent") == USER_AGENT) else "inconclusive"
                elif expectation == "block":
                    verdict = "gap" if matching else ("prevented" if result_name == "blocked"
                                                       and len(blocks) == 1 and blocks[0].get("status") == 403
                                                       else "inconclusive")
                else:
                    verdict = "passed" if result_name == "bypassed" and len(matching) == len(completed) == 1 else "false-block"
                verdicts.append({"id": case_id, "expect": expectation, "verdict": verdict,
                                 "tool_result": result_name, "origin_receipts": len(matching)})
    if Counter(result["id"] for result in verdicts) != Counter(planned.keys()):
        raise ValueError("goTestWAF did not account for every planned case exactly once")
    return verdicts


def summarize(verdicts):
    counts = dict(Counter(result["verdict"] for result in verdicts))
    return {"passed": bool(verdicts) and all(result["verdict"] in {"passed", "prevented"} for result in verdicts),
            "counts": counts, "cases": verdicts}
