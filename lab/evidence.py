"""Fail-closed verdicts for the bounded signature lab, independent of Docker."""

import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

USER_AGENT = "Mozilla/5.0 KunatoLabClient/1.0"

COMBINED_ACCESS = re.compile(r'"(\S+) (\S+) HTTP/[0-9.]+" (\d{3}) \d+ "[^"]*" "([^"]*)"')
COMMON_ACCESS = re.compile(r'"(\S+) (\S+) HTTP/[0-9.]+" (\d{3}) (\d+)')

SQLI_PROBE_MARKERS = ("%27", "UNION", "SLEEP", "BENCHMARK", "ORDER%20BY", "ORDER+BY",
                      "ORDER BY", "INFORMATION_SCHEMA", "EXTRACTVALUE", "UPDATEXML")


def parse_combined_access(text):
    """Parse Apache combined access log lines into request observations."""
    return [{"method": match.group(1), "target": match.group(2), "status": int(match.group(3)),
             "user_agent": match.group(4)}
            for match in COMBINED_ACCESS.finditer(text)]


def parse_common_access(text):
    """Parse Apache common access log lines into request observations."""
    return [{"method": match.group(1), "target": match.group(2), "status": int(match.group(3))}
            for match in COMMON_ACCESS.finditer(text)]


def is_sqli_probe(target):
    upper = target.upper()
    return any(marker in upper for marker in SQLI_PROBE_MARKERS)


def read_jsonl(path):
    events = []
    for line in Path(path).read_text().splitlines():
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except ValueError:
            continue
    return events


def verify_origin(events, nonce, allow_errors=False):
    if not events or not any(event.get("event") == "ready" for event in events):
        raise ValueError("Origin startup evidence is missing")
    if any(event.get("nonce") != nonce for event in events):
        raise ValueError("Origin evidence belongs to another attempt")
    if not allow_errors and any(event.get("event") == "error" for event in events):
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


def validate_mutations(cases):
    validate_cases(cases)
    for case in cases:
        for field in ("seed", "transform", "interpretation"):
            value = case.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"Mutation case {case['id']} lacks {field}")


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


def judge_mutations(cases, controls, results, origin, waf_events, nonce):
    """Judge mutation variants with replay semantics and retain their provenance."""
    validate_mutations(cases)
    verdicts = judge_replay(cases, controls, results, origin, waf_events, nonce)
    metadata = {case["id"]: case for case in cases}
    for verdict in verdicts:
        case = metadata[verdict["id"]]
        verdict.update(seed=case["seed"], transform=case["transform"],
                       interpretation=case["interpretation"])
    result = summarize(verdicts)
    result["notes"] = {
        "planned": len(cases),
        "seeds": sorted({case["seed"] for case in cases}),
        "transforms": sorted({case["transform"] for case in cases}),
    }
    return result


PROTOCOL_BLOCK_STATUSES = {400, 403, 431, 501}


def validate_protocol(cases):
    ids = [case["id"] for case in cases]
    if not cases or len(ids) != len(set(ids)):
        raise ValueError("Protocol cases must be nonempty with unique IDs")
    for case in cases:
        if case["expect"] not in {"allow", "block"}:
            raise ValueError("Invalid protocol expectation")
        if not isinstance(case.get("raw"), str) and "raw_repeat" not in case:
            raise ValueError("Protocol case lacks raw bytes")
        if not isinstance(case.get("interpretation"), str) or not case["interpretation"].strip():
            raise ValueError("Protocol case lacks an interpretation")
        if case.get("direct_framing", "reject") not in {"reject", "cl", "te"}:
            raise ValueError("Invalid direct origin framing")
        if not isinstance(case.get("read_timeout", 1.0), (int, float)):
            raise ValueError("Invalid protocol read timeout")


def judge_protocol(cases, controls, results, direct_origins, protected_origin,
                   direct_nonces, nonce):
    validate_protocol(cases)
    for framing, events in direct_origins.items():
        verify_origin(events, direct_nonces[framing], allow_errors=True)
    verify_origin(protected_origin, nonce, allow_errors=True)
    expected = {case["id"] for case in cases}
    for observations in (controls, results):
        ids = [result["id"] for result in observations]
        if len(ids) != len(set(ids)) or set(ids) != expected:
            raise ValueError("Missing, duplicate, or unexpected protocol probe results")
    controls = {result["id"]: result for result in controls}
    results = {result["id"]: result for result in results}
    protected_receipts = Counter(event.get("case_id") for event in protected_origin
                                 if event.get("event") in {"received", "completed", "websocket"})
    verdicts = []
    for case in cases:
        result = results[case["id"]]
        control = controls[case["id"]]
        direct = direct_origins.get(case.get("direct_framing", "reject"), [])
        direct_received = [event for event in direct if event.get("case_id") == case["id"]
                           and event.get("event") in {"received", "completed", "websocket"}]
        smuggled = case.get("smuggled_case")
        direct_smuggled = [event for event in direct if smuggled
                           and event.get("case_id") == smuggled
                           and event.get("event") == "received"]
        protected_events = [event for event in protected_origin
                            if event.get("case_id") == case["id"]
                            and event.get("event") in {"received", "completed", "websocket"}]
        if control.get("error") or result.get("error"):
            verdict = "inconclusive"
        elif case["expect"] == "block":
            direct_ok = ((bool(direct_smuggled) if smuggled else bool(direct_received))
                         or control.get("status") in PROTOCOL_BLOCK_STATUSES
                         or (case.get("method") == "PRI" and not control.get("error")))
            if not direct_ok:
                verdict = "inconclusive"
            elif smuggled:
                if protected_receipts[smuggled]:
                    verdict = "gap"
                elif result.get("status") in PROTOCOL_BLOCK_STATUSES or result.get("status") == 200:
                    verdict = "prevented"
                else:
                    verdict = "inconclusive"
            elif protected_receipts[case["id"]]:
                verdict = "gap"
            elif result.get("status") in PROTOCOL_BLOCK_STATUSES:
                verdict = "prevented"
            else:
                verdict = "inconclusive"
        elif result.get("status") == 101:
            direct_ws = any(event.get("event") == "websocket" for event in direct_received)
            protected_ws = any(event.get("event") == "websocket" for event in protected_events)
            if direct_ws and protected_ws:
                verdict = "passed"
            elif direct_ws:
                verdict = "false-block"
            else:
                verdict = "inconclusive"
        elif result.get("status") == control.get("status") and protected_events:
            verdict = "passed"
        else:
            verdict = "false-block"
        verdicts.append({"id": case["id"], "expect": case["expect"], "verdict": verdict,
                         "status": result.get("status"), "direct_status": control.get("status"),
                         "origin_receipts": protected_receipts[case["id"]],
                         "smuggled_receipts": protected_receipts[smuggled] if smuggled else 0})
    judged = summarize(verdicts)
    judged["notes"] = {"planned": len(cases),
                       "framings": sorted({case.get("direct_framing", "reject")
                                           for case in cases})}
    return judged


def judge_slow(slow, normal, before, after):
    sent = slow.get("sent", 0)
    slow_ok = sent >= 1 and not slow.get("error")
    normal_ok = normal.get("status") == 200 and not normal.get("error")
    cases = [
        {"id": "slow-http", "expect": "survive",
         "verdict": "passed" if slow_ok else "inconclusive", "origin_receipts": 0},
        {"id": "slow-normal", "expect": "normal",
         "verdict": "passed" if normal_ok else "false-block", "origin_receipts": 1},
    ]
    result = summarize(cases)
    result["notes"] = {"connections": sent, "held_seconds": slow.get("held_seconds"),
                       "closed": slow.get("closed"), "normal_status": normal.get("status"),
                       "cpu_before": before.get("CPUPerc"), "cpu_after": after.get("CPUPerc"),
                       "mem_before": before.get("MemUsage"), "mem_after": after.get("MemUsage")}
    return result


def judge_availability(slow, slow_body, slow_read, exhaustion, upstream, normal,
                       before, after, restarts, application_metrics=None):
    def status(case):
        return case.get("status")

    sent = slow.get("sent", 0)
    slow_ok = sent >= 1 and not slow.get("error")
    body_status = status(slow_body)
    body_ok = body_status in {400, 408, 413}
    body_bad = body_status == 200
    read_status = status(slow_read)
    read_ok = read_status == 200 and not slow_read.get("error")
    exhausted_status = status(exhaustion)
    exhausted_ok = exhausted_status in {429, 503}
    exhausted_bad = exhausted_status == 200
    upstream_status = status(upstream)
    upstream_ok = upstream_status == 504
    upstream_bad = upstream_status == 200
    normal_ok = normal.get("status") == 200 and not normal.get("error")
    restarts = restarts or 0
    mem_used = None
    usage = after.get("MemUsage", "")
    if " / " in usage:
        try:
            mem_used = float(usage.split(" / ")[0].rstrip("MiBGiB"))
        except ValueError:
            mem_used = None
    resource_ok = restarts == 0 and (mem_used is None or mem_used < 256)
    cases = [
        {"id": "slow-headers", "expect": "survive",
         "verdict": "passed" if slow_ok else "inconclusive", "origin_receipts": 0},
        {"id": "slow-body", "expect": "bounded",
         "verdict": "passed" if body_ok else ("failed" if body_bad else "inconclusive"),
         "origin_receipts": 0},
        {"id": "slow-read", "expect": "survive",
         "verdict": "passed" if read_ok else "inconclusive", "origin_receipts": 1},
        {"id": "connection-cap", "expect": "bounded",
         "verdict": "passed" if exhausted_ok else ("failed" if exhausted_bad else "inconclusive"),
         "origin_receipts": 0},
        {"id": "slow-upstream", "expect": "bounded",
         "verdict": "passed" if upstream_ok else ("failed" if upstream_bad else "inconclusive"),
         "origin_receipts": 1},
        {"id": "availability-normal", "expect": "normal",
         "verdict": "passed" if normal_ok else "false-block", "origin_receipts": 1},
        {"id": "availability-resources", "expect": "resources",
         "verdict": "passed" if resource_ok else "failed", "origin_receipts": 0},
    ]
    metric_notes = {}
    if application_metrics is not None:
        text = application_metrics.get("response", "")

        def counter(name):
            for line in text.splitlines():
                if line.startswith(name + " "):
                    try:
                        return float(line.split(None, 1)[1])
                    except (IndexError, ValueError):
                        return None
            return None

        observed_requests = counter("kunato_requests_total")
        upstream_timeouts = counter("kunato_upstream_timeouts_total")
        metrics_ok = (observed_requests is not None and observed_requests > 0
                      and upstream_timeouts is not None and upstream_timeouts >= 1)
        cases.append({"id": "availability-metrics", "expect": "metrics",
                      "verdict": "passed" if metrics_ok else "failed",
                      "origin_receipts": 0})
        metric_notes = {"metric_requests": observed_requests,
                        "upstream_timeouts": upstream_timeouts}
    result = summarize(cases)
    result["notes"] = {"slow_connections": sent, "slow_body_status": body_status,
                       "slow_read_status": read_status,
                       "connection_cap_status": exhausted_status,
                       "upstream_status": upstream_status,
                       "normal_status": normal.get("status"), "restarts": restarts,
                       "mem_before": before.get("MemUsage"), "mem_after": after.get("MemUsage"),
                       **metric_notes}
    return result


def judge_load(summary, slow, normal, recovery, before, mid, after, restarts,
               application_metrics=None):
    metrics = summary.get("metrics", {}) if isinstance(summary, dict) else {}

    def value(name, key="value"):
        return metrics.get(name, {}).get(key)

    requests = value("http_reqs", "count") or 0
    failed = value("http_req_failed")
    failed = 1.0 if failed is None else failed
    checks = value("checks")
    checks = 0.0 if checks is None else checks
    duration = metrics.get("http_req_duration", {})
    p95 = duration.get("p(95)")
    p99 = duration.get("p(99)")
    restarts = restarts or 0
    latency_ok = (requests >= 1000 and failed < 0.01 and checks > 0.99
                  and p95 is not None and p99 is not None and p95 < 200 and p99 < 500)
    normal_ok = normal.get("status") == 200 and not normal.get("error")
    recovery_ok = recovery.get("status") == 200 and not recovery.get("error")
    mem_used = None
    usage = after.get("MemUsage", "")
    if " / " in usage:
        try:
            mem_used = float(usage.split(" / ")[0].rstrip("MiBGiB"))
        except ValueError:
            mem_used = None
    resource_ok = restarts == 0 and (mem_used is None or mem_used < 256)
    slow_ok = slow.get("sent", 0) >= 1 and not slow.get("error")
    cases = [
        {"id": "load-latency", "expect": "latency",
         "verdict": "passed" if latency_ok else "failed", "origin_receipts": requests},
        {"id": "load-attack", "expect": "availability",
         "verdict": "passed" if slow_ok else "failed", "origin_receipts": 0},
        {"id": "load-normal", "expect": "normal",
         "verdict": "passed" if normal_ok else "false-block", "origin_receipts": 1},
        {"id": "load-recovery", "expect": "recovery",
         "verdict": "passed" if recovery_ok else "failed", "origin_receipts": 1},
        {"id": "load-resources", "expect": "resources",
         "verdict": "passed" if resource_ok else "failed", "origin_receipts": 0},
    ]
    metric_notes = {}
    if application_metrics is not None:
        text = application_metrics.get("response", "")

        def counter(name):
            for line in text.splitlines():
                if line.startswith(name + " "):
                    try:
                        return float(line.split(None, 1)[1])
                    except (IndexError, ValueError):
                        return None
            return None

        observed_requests = counter("kunato_requests_total")
        blocked = counter("kunato_blocked_total")
        rate_limited = counter("kunato_rate_limited_total")
        overloaded = counter("kunato_overloaded_total")
        upstream_timeouts = counter("kunato_upstream_timeouts_total")
        metrics_ok = (observed_requests is not None and observed_requests >= requests
                      and blocked == 0 and rate_limited == 0 and overloaded == 0
                      and upstream_timeouts == 0)
        cases.append({"id": "load-metrics", "expect": "metrics",
                      "verdict": "passed" if metrics_ok else "failed",
                      "origin_receipts": 0})
        metric_notes = {"metric_requests": observed_requests, "blocked": blocked,
                        "rate_limited": rate_limited, "overloaded": overloaded,
                        "upstream_timeouts": upstream_timeouts}
    result = summarize(cases)
    result["notes"] = {"requests": requests, "failed_rate": failed, "checks": checks,
                       "p95_ms": p95, "p99_ms": p99,
                       "normal_status": normal.get("status"),
                       "recovery_status": recovery.get("status"), "restarts": restarts,
                       "slow_connections": slow.get("sent"), "slow_closed": slow.get("closed"),
                       "cpu_before": before.get("CPUPerc"), "cpu_mid": mid.get("CPUPerc"),
                       "cpu_after": after.get("CPUPerc"),
                       "mem_before": before.get("MemUsage"), "mem_mid": mid.get("MemUsage"),
                       "mem_after": after.get("MemUsage"), **metric_notes}
    return result


def judge_crs(cases, crs_results, kunato_verdicts, crs_origin, crs_nonce,
              crs_version="4.3.0"):
    """Compare CRS and Kunato decisions for the same mutation corpus."""
    validate_mutations(cases)
    verify_origin(crs_origin, crs_nonce)
    expected_ids = {case["id"] for case in cases}
    ids = [result["id"] for result in crs_results]
    if len(ids) != len(set(ids)) or set(ids) != expected_ids:
        raise ValueError("Missing, duplicate, or unexpected CRS probe results")
    results = {result["id"]: result for result in crs_results}
    verdicts = {verdict["id"]: verdict for verdict in kunato_verdicts}
    receipts = Counter(event.get("case_id") for event in crs_origin
                       if event.get("event") == "received")
    rows = []
    counts = Counter()
    for case in cases:
        result = results[case["id"]]
        if result.get("error"):
            crs = "inconclusive"
        elif result.get("status") == 403 and result.get("origin") is None:
            crs = "blocked"
        elif origin_response(case, result, crs_nonce):
            crs = "allowed"
        else:
            crs = "inconclusive"
        kunato = verdicts.get(case["id"], {}).get("verdict", "inconclusive")
        kunato_correct = kunato == ("prevented" if case["expect"] == "block" else "passed")
        if case["expect"] == "block":
            if crs == "blocked" and kunato_correct:
                agreement = "agree-block"
            elif crs == "blocked":
                agreement = "crs-only"
            elif kunato_correct:
                agreement = "kunato-only"
            elif crs == "inconclusive" or kunato == "inconclusive":
                agreement = "inconclusive"
            else:
                agreement = "both-miss"
        elif crs == "allowed" and kunato_correct:
            agreement = "agree-allow"
        elif crs == "blocked" and kunato_correct:
            agreement = "crs-false-block"
        elif crs == "allowed" and kunato == "false-block":
            agreement = "kunato-false-block"
        elif crs == "inconclusive" or kunato == "inconclusive":
            agreement = "inconclusive"
        else:
            agreement = "both-false-block"
        counts[agreement] += 1
        rows.append({"id": case["id"], "expect": case["expect"], "verdict": "observed",
                     "crs": crs, "kunato": kunato, "agreement": agreement,
                     "origin_receipts": receipts[case["id"]]})
    return {"passed": True, "counts": dict(counts), "cases": rows,
            "notes": {"crs_version": crs_version, "planned": len(cases),
                      "observation": "CRS comparison is reported, not used as a gate",
                      "agreement_counts": dict(counts)}}


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


def judge_sqlmap(control_output, protected_output, control_access, protected_access, waf_events,
                 nonce, control_nonce):
    """Judge the bounded SQLi dump from the tool output and both origins."""
    canary = f"CANARY-{nonce}"
    control_canary = f"CANARY-{control_nonce}"
    control_attack = [request for request in parse_combined_access(control_access)
                      if request["target"].startswith("/vulnerabilities/sqli/")
                      and is_sqli_probe(request["target"])]
    protected_attack = [request for request in parse_combined_access(protected_access)
                        if request["target"].startswith("/vulnerabilities/sqli/")
                        and is_sqli_probe(request["target"])]
    control_ua = bool(control_attack) and all(request["user_agent"] == USER_AGENT
                                             for request in control_attack)
    control_ok = control_canary in control_output and "lab_canary" in control_output and control_ua
    protected_canary = canary in protected_output
    protected_ua = all(request["user_agent"] == USER_AGENT for request in protected_attack)
    blocks = [event["fields"] for event in waf_events
              if event.get("fields", {}).get("message") == "request blocked"
              and event["fields"].get("path") == "/vulnerabilities/sqli/"
              and event["fields"].get("rate_limited") is False]
    if not control_ok:
        verdict = "inconclusive"
    elif protected_canary:
        verdict = "gap"
    elif not protected_ua or not blocks:
        verdict = "inconclusive"
    else:
        verdict = "prevented"
    cases = [
        {"id": "sqlmap-control", "expect": "control",
         "verdict": "passed" if control_ok else "inconclusive",
         "origin_receipts": len(control_attack)},
        {"id": "sqlmap-protected", "expect": "prevent", "verdict": verdict,
         "origin_receipts": len(protected_attack), "blocked": len(blocks)},
    ]
    result = summarize(cases)
    result["notes"] = {
        "canary_extracted": control_ok,
        "protected_canary": protected_canary,
        "control_canary": control_canary,
        "protected_nonce": nonce,
        "blocked_requests": len(blocks),
        "origin_probes": len(protected_attack),
        "rules": sorted({fields.get("rule") for fields in blocks
                         if fields.get("rule") is not None}),
    }
    return result


def parse_nuclei_results(text):
    results = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get("template-id"):
            results.append(value)
    return results


def request_user_agent(result):
    for line in result.get("request", "").splitlines():
        if line.lower().startswith("user-agent:"):
            return line.split(":", 1)[1].strip()
    return ""


def judge_nuclei(control_results, protected_results, control_access, protected_access, waf_events,
                 nonce, control_nonce):
    """Judge the CVE canary from Nuclei output and the fixture access log."""
    canary = f"kunato-lab-canary-{nonce}"
    control_canary = f"kunato-lab-canary-{control_nonce}"
    control = parse_nuclei_results(control_results)
    protected = parse_nuclei_results(protected_results)
    control_paths = [request for request in parse_common_access(control_access)
                     if "canary.txt" in request["target"] or "cgi-bin/.%2e" in request["target"]]
    protected_paths = [request for request in parse_common_access(protected_access)
                       if "canary.txt" in request["target"] or "cgi-bin/.%2e" in request["target"]]
    control_match = [result for result in control
                     if control_canary in result.get("response", "")
                     and request_user_agent(result) == USER_AGENT]
    control_ok = bool(control_match) and any(request["status"] == 200 for request in control_paths)
    protected_match = [result for result in protected if canary in result.get("response", "")]
    blocks = [event["fields"] for event in waf_events
              if event.get("fields", {}).get("message") == "request blocked"
              and any(marker in event["fields"].get("path", "")
                      for marker in ("canary.txt", "cgi-bin/.%2e", "bin/sh"))
              and event["fields"].get("rate_limited") is False]
    if not control_ok:
        verdict = "inconclusive"
    elif protected_match:
        verdict = "gap"
    elif protected_paths:
        verdict = "inconclusive"
    elif blocks:
        verdict = "prevented"
    else:
        verdict = "inconclusive"
    cases = [
        {"id": "nuclei-control", "expect": "exploit",
         "verdict": "passed" if control_ok else "inconclusive",
         "origin_receipts": len(control_paths)},
        {"id": "nuclei-protected", "expect": "prevent", "verdict": verdict,
         "origin_receipts": len(protected_paths), "blocked": len(blocks)},
    ]
    result = summarize(cases)
    result["notes"] = {
        "matched_at": control_match[0].get("matched-at") if control_match else None,
        "protected_canary": bool(protected_match),
        "control_canary": control_canary,
        "protected_nonce": nonce,
        "blocked_requests": len(blocks),
        "origin_receipts": len(protected_paths),
        "rules": sorted({fields.get("rule") for fields in blocks
                         if fields.get("rule") is not None}),
    }
    return result


def validate_ffuf_cases(cases):
    if not cases:
        raise ValueError("FFUF cases must not be empty")
    paths = [case["path"] for case in cases]
    if len(paths) != len(set(paths)):
        raise ValueError("FFUF case paths must be unique")
    for case in cases:
        if case["expect"] not in {"block", "allow", "log"}:
            raise ValueError("Invalid FFUF expectation")
        path = case["path"]
        if (not path.startswith("/") or path == "/" or any(character in path for character in "\r\n?#")):
            raise ValueError("FFUF cases must use path-only, non-root targets")


def ffuf_results(report):
    results = {}
    for item in report.get("results", []) if isinstance(report, dict) else []:
        path = urlsplit(item.get("url", "")).path
        if path:
            results[path] = {"status": item.get("status"), "length": item.get("length")}
    return results


def judge_ffuf(control_report, protected_report, control_access, protected_access, waf_events, cases):
    """Judge bounded path discovery from both ffuf runs and the origin logs."""
    validate_ffuf_cases(cases)
    control = ffuf_results(control_report)
    protected = ffuf_results(protected_report)
    control_receipts = Counter(request["target"].split("?", 1)[0]
                               for request in parse_combined_access(control_access))
    protected_receipts = Counter(request["target"].split("?", 1)[0]
                                 for request in parse_combined_access(protected_access))
    blocks = [event["fields"] for event in waf_events
              if event.get("fields", {}).get("message") == "request blocked"
              and event["fields"].get("rate_limited") is False]
    block_paths = {fields.get("path"): fields for fields in blocks}
    log_paths = {event["fields"].get("path") for event in waf_events
                 if event.get("fields", {}).get("action") == "LOG"}
    verdicts = []
    for case in cases:
        path, expectation = case["path"], case["expect"]
        observed = protected.get(path)
        expected = control.get(path)
        if observed is None or expected is None:
            verdict = "inconclusive"
        elif expectation == "block":
            if protected_receipts[path]:
                verdict = "gap"
            elif path in block_paths:
                verdict = "prevented"
            elif observed["status"] == expected["status"]:
                verdict = "gap"
            else:
                verdict = "inconclusive"
        elif expectation == "log":
            if (protected_receipts[path] and path in log_paths
                    and observed["status"] == expected["status"]
                    and observed["length"] == expected["length"]):
                verdict = "passed"
            elif protected_receipts[path] and observed["status"] == expected["status"]:
                verdict = "inconclusive"
            else:
                verdict = "false-block"
        else:
            if (protected_receipts[path] and path not in block_paths
                    and observed["status"] == expected["status"]
                    and observed["length"] == expected["length"]):
                verdict = "passed"
            else:
                verdict = "false-block"
        verdicts.append({"id": path, "expect": expectation, "verdict": verdict,
                         "status": observed["status"] if observed else None,
                         "expected_status": expected["status"] if expected else None,
                         "origin_receipts": protected_receipts[path]})
    result = summarize(verdicts)
    result["notes"] = {
        "planned": len(cases),
        "control_sent": len(control),
        "protected_sent": len(protected),
        "control_receipts": sum(control_receipts.values()),
        "protected_receipts": sum(protected_receipts.values()),
        "blocked": len(blocks),
        "rules": sorted({fields.get("rule") for fields in blocks if fields.get("rule") is not None}),
    }
    return result


def judge_ffuf_behavior(protected_report, protected_access, waf_events, normal_health):
    """Judge whether enumeration of missing paths stopped the ffuf source."""
    results = ffuf_results(protected_report)
    receipts = Counter(request["target"].split("?", 1)[0]
                       for request in parse_combined_access(protected_access))
    distinct_receipts = len(receipts)
    blocked = [result for result in results.values() if result["status"] in (403, 429)]
    behavior_events = [event.get("fields", {}) for event in waf_events
                       if any(marker in json.dumps(event.get("fields", {})).lower()
                              for marker in ("behavior", "enumeration", "banned"))]
    normal_ok = (normal_health.get("status") == 200 and not normal_health.get("error")
                 and not normal_health.get("probe_error"))
    if not results:
        verdict = "inconclusive"
    elif not normal_ok:
        verdict = "false-block"
    elif blocked and distinct_receipts < len(results):
        verdict = "prevented"
    else:
        verdict = "gap"
    case = {"id": "enumeration-behavior", "expect": "prevent", "verdict": verdict,
            "origin_receipts": distinct_receipts, "blocked": len(blocked)}
    result = summarize([case])
    result["notes"] = {
        "planned": len(results),
        "origin_receipts": distinct_receipts,
        "blocked": len(blocked),
        "behavior_events": len(behavior_events),
        "normal_status": normal_health.get("status"),
    }
    return result


ZAP_INJECTION_PLUGINS = {"6": "path-traversal", "7": "remote-file-inclusion",
                         "40012": "xss", "40018": "sqli", "40026": "dom-xss"}


def zap_alerts(report):
    alerts = []
    for site in report.get("site", []) if isinstance(report, dict) else []:
        for alert in site.get("alerts", []):
            plugin = str(alert.get("pluginid", ""))
            if plugin not in ZAP_INJECTION_PLUGINS:
                continue
            for instance in alert.get("instances", [{}]):
                alerts.append({"plugin": plugin, "alert": alert.get("alert", ""),
                               "class": ZAP_INJECTION_PLUGINS[plugin],
                               "url": instance.get("uri", ""),
                               "parameter": instance.get("param", ""),
                               "attack": instance.get("attack", "")})
    return alerts


def judge_zap(control_report, protected_report, control_access, protected_access, waf_events):
    """Judge the authenticated ZAP scan from alerts and Kunato block evidence."""
    control_alerts = zap_alerts(control_report)
    protected_alerts = zap_alerts(protected_report)
    blocks = [event["fields"] for event in waf_events
              if event.get("fields", {}).get("message") == "request blocked"
              and event["fields"].get("rate_limited") is False]
    control_ok = bool(control_alerts)
    if not control_ok:
        verdict = "inconclusive"
    elif protected_alerts:
        verdict = "gap"
    elif blocks:
        verdict = "prevented"
    else:
        verdict = "inconclusive"
    control_requests = len(parse_combined_access(control_access))
    protected_requests = len(parse_combined_access(protected_access))
    cases = [
        {"id": "zap-control", "expect": "exploit",
         "verdict": "passed" if control_ok else "inconclusive",
         "origin_receipts": control_requests},
        {"id": "zap-protected", "expect": "prevent", "verdict": verdict,
         "origin_receipts": protected_requests, "blocked": len(blocks)},
    ]
    result = summarize(cases)
    result["notes"] = {
        "control_alerts": control_alerts,
        "protected_alerts": protected_alerts,
        "blocked": len(blocks),
        "rules": sorted({fields.get("rule") for fields in blocks if fields.get("rule") is not None}),
        "control_origin_requests": control_requests,
        "protected_origin_requests": protected_requests,
    }
    return result


def spider_count(log_text):
    numbers = [int(value) for value in re.findall(r"Job spider found (\d+) URLs", log_text)]
    return max(numbers, default=0)


def judge_zap_workflow(control_log, protected_log, control_report, protected_report,
                       control_access, protected_access, waf_events):
    """Judge the authenticated spider/passive baseline across the WAF boundary."""
    control_urls = spider_count(control_log)
    protected_urls = spider_count(protected_log)
    control_sites = len(control_report.get("site", [])) if isinstance(control_report, dict) else 0
    protected_sites = len(protected_report.get("site", [])) if isinstance(protected_report, dict) else 0
    blocks = [event["fields"] for event in waf_events
              if event.get("fields", {}).get("message") == "request blocked"
              and event["fields"].get("rate_limited") is False]
    control_ok = control_urls > 0 and control_sites > 0
    if not control_ok:
        verdict = "inconclusive"
    elif protected_urls == 0 or protected_sites == 0:
        verdict = "false-block"
    elif protected_urls < control_urls * 0.8:
        verdict = "false-block"
    else:
        verdict = "passed"
    control_requests = len(parse_combined_access(control_access))
    protected_requests = len(parse_combined_access(protected_access))
    cases = [
        {"id": "zap-control", "expect": "workflow",
         "verdict": "passed" if control_ok else "inconclusive",
         "origin_receipts": control_requests},
        {"id": "zap-protected", "expect": "workflow", "verdict": verdict,
         "origin_receipts": protected_requests, "blocked": len(blocks)},
    ]
    result = summarize(cases)
    result["notes"] = {
        "control_spider_urls": control_urls,
        "protected_spider_urls": protected_urls,
        "control_sites": control_sites,
        "protected_sites": protected_sites,
        "blocked": len(blocks),
        "rules": sorted({fields.get("rule") for fields in blocks if fields.get("rule") is not None}),
        "control_origin_requests": control_requests,
        "protected_origin_requests": protected_requests,
        "active_scan": ("not run: ZAP 2.17 exits the plan on the authenticated DVWA file-inclusion "
                        "active scan; injection defenses are covered by the sqlmap, Nuclei, and "
                        "goTestWAF sandbox suites"),
    }
    return result


def summarize(verdicts):
    counts = dict(Counter(result["verdict"] for result in verdicts))
    return {"passed": bool(verdicts) and all(result["verdict"] in {"passed", "prevented"} for result in verdicts),
            "counts": counts, "cases": verdicts}
