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
                        "goTestWAF campaigns"),
    }
    return result


def summarize(verdicts):
    counts = dict(Counter(result["verdict"] for result in verdicts))
    return {"passed": bool(verdicts) and all(result["verdict"] in {"passed", "prevented"} for result in verdicts),
            "counts": counts, "cases": verdicts}
