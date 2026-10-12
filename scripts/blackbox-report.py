#!/usr/bin/env python3
"""Colored pass/fail report for a kunato-blackbox run.

Usage:
    blackbox-report.py <blackbox.log> [--blocked FILE] [--allowed FILE]
                       [--upstream FILE] [--color auto|always|never]

Reads the log produced by `kunato-blackbox --blocked ... --allowed ...` and
classifies every request:

  allowed phase:  a 2xx status is a pass (forwarded); anything else is a
                  failure (a false positive);
  blocked phase:  any non-2xx response is a pass (stopped), a 2xx status is a
                  failure (a gap), and a transport error is reported as
                  "no response" (the upstream count check still catches leaks).

Prints allow/block pass and fail counts, min/avg/max latency per phase, the
status breakdown, failure details with source lines, and the upstream
access-count check. Exits non-zero when the run fails.
"""

import argparse
import collections
import re
import sys

LINE = re.compile(
    r"^\[(blocked|allowed)\]\s+(\d+)/(\d+)\s+(\S+)\s+(\S+)\s+->\s+(.*?)\s+\((\d+) ms\)$"
)
ANSI = re.compile(r"\x1b\[[0-9;]*m")
UPSTREAM_ACCESS = re.compile(r"\baccess\b")


class Style:
    def __init__(self, enabled):
        self.enabled = enabled

    def paint(self, code, text):
        if not self.enabled:
            return text
        return f"\x1b[{code}m{text}\x1b[0m"

    def bold(self, text):
        return self.paint("1", text)

    def dim(self, text):
        return self.paint("2", text)

    def red(self, text):
        return self.paint("31", text)

    def green(self, text):
        return self.paint("32", text)

    def yellow(self, text):
        return self.paint("33", text)

    def cyan(self, text):
        return self.paint("36", text)


def supports_color(mode):
    if mode == "always":
        return True
    if mode == "never":
        return False
    if not sys.stdout.isatty():
        return False
    return "NO_COLOR" not in __import__("os").environ


def load_requests(path):
    requests = []
    if not path:
        return requests
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if line and not line.startswith("#"):
                requests.append(line)
    return requests


def format_latency(samples):
    if not samples:
        return "no responses"
    average = sum(samples) / len(samples)
    return (
        f"min {min(samples)} ms   avg {average:.1f} ms   max {max(samples)} ms"
    )


def format_breakdown(counter):
    if not counter:
        return "-"
    return "  ".join(f"{status}\u00d7{count}" for status, count in sorted(counter.items()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", help="blackbox log to analyze")
    parser.add_argument("--blocked", help="blocked request list, for source lines")
    parser.add_argument("--allowed", help="allowed request list, for source lines")
    parser.add_argument("--upstream", help="upstream log for the access-count check")
    parser.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="colorize the report (default: auto)",
    )
    args = parser.parse_args()

    style = Style(supports_color(args.color))
    blocked_requests = load_requests(args.blocked)
    allowed_requests = load_requests(args.allowed)

    allowed_pass = allowed_fail = 0
    blocked_pass = blocked_fail = blocked_no_response = 0
    allowed_errors = 0
    allowed_status = collections.Counter()
    blocked_status = collections.Counter()
    allowed_latency = []
    blocked_latency = []
    failures = []

    with open(args.log, encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            match = LINE.match(raw.rstrip("\n"))
            if not match:
                continue
            phase, index, _, method, target, tail, ms = match.groups()
            index = int(index)
            milliseconds = int(ms)

            if tail.startswith("error:"):
                if phase == "blocked":
                    blocked_no_response += 1
                else:
                    allowed_errors += 1
                    failures.append(
                        ("allowed", index, method, target, "no response", tail)
                    )
                continue

            if phase == "allowed":
                allowed_status[tail] += 1
                allowed_latency.append(milliseconds)
                if tail.startswith("2"):
                    allowed_pass += 1
                else:
                    allowed_fail += 1
                    failures.append(("allowed", index, method, target, tail, ""))
            else:
                blocked_status[tail] += 1
                blocked_latency.append(milliseconds)
                if tail.startswith("2"):
                    blocked_fail += 1
                    failures.append(("blocked", index, method, target, tail, ""))
                else:
                    blocked_pass += 1

    expected_upstream = allowed_pass + blocked_fail
    upstream_ok = True
    upstream_count = None
    if args.upstream:
        upstream_count = 0
        with open(args.upstream, encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                if UPSTREAM_ACCESS.search(ANSI.sub("", raw)):
                    upstream_count += 1
        upstream_ok = upstream_count == expected_upstream

    failed = allowed_fail > 0 or blocked_fail > 0 or allowed_errors > 0 or not upstream_ok

    line = "\u2500" * 60
    print(style.bold("Kunato black-box report"))
    print(style.dim(line))
    print(
        f"{style.cyan('ALLOW')}   pass {style.green(str(allowed_pass))}"
        f"   fail {style.red(str(allowed_fail))}"
    )
    print(f"        latency  {style.dim(format_latency(allowed_latency))}")
    blocked_line = (
        f"{style.cyan('BLOCK')}   pass {style.green(str(blocked_pass))}"
        f"   fail {style.red(str(blocked_fail))}"
    )
    if blocked_no_response:
        blocked_line += (
            f"   no response {style.yellow(str(blocked_no_response))}"
        )
    print(blocked_line)
    print(f"        latency  {style.dim(format_latency(blocked_latency))}")
    print()
    print(f"{style.dim('status blocked:')} {format_breakdown(blocked_status)}")
    print(f"{style.dim('status allowed:')} {format_breakdown(allowed_status)}")

    if upstream_count is not None:
        if upstream_ok:
            check = style.green("OK")
        else:
            check = style.red(
                f"MISMATCH (leak or dropped request; inspect the logs)"
            )
        print()
        print(
            f"upstream accesses {upstream_count} "
            f"(expected {expected_upstream})  {check}"
        )

    if failures:
        print()
        print(style.bold("failures:"))
        for phase, index, method, target, status, detail in failures:
            source_list = blocked_requests if phase == "blocked" else allowed_requests
            source = ""
            if 0 < index <= len(source_list):
                source = source_list[index - 1]
            print(
                f"  {style.red('[' + phase + ']')} #{index} "
                f"{method} {target} -> {style.red(status)}"
            )
            if source:
                print(f"      {style.dim(source)}")
            if detail:
                print(f"      {style.dim(detail)}")

    print()
    if failed:
        print(f"result: {style.red(style.bold('FAIL'))}")
    else:
        print(f"result: {style.green(style.bold('PASS'))}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
