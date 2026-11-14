#!/usr/bin/env python3
"""Regression cases for the black-box pass condition.

The signing workflow only publishes a rule set when the black-box suite ran the
whole corpus and every request produced its expected result. These cases lock
in the two conditions that a failed driver used to defeat: an empty or partial
log must fail, and the shell must not discard the driver's exit status.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORT = ROOT / "scripts" / "blackbox-report.py"
RUNNER = ROOT / "scripts" / "blackbox-test.sh"
BLOCKED = ROOT / "blackbox" / "requests" / "blocked.txt"
ALLOWED = ROOT / "blackbox" / "requests" / "allowed.txt"


def request_count(path: Path) -> int:
    return sum(
        1
        for raw in path.read_text(encoding="utf-8").splitlines()
        if raw.strip() and not raw.strip().startswith("#")
    )


def run_report(log_text: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as directory:
        log = Path(directory) / "blackbox.log"
        log.write_text(log_text, encoding="utf-8")
        return subprocess.run(
            [
                sys.executable,
                str(REPORT),
                str(log),
                "--blocked",
                str(BLOCKED),
                "--allowed",
                str(ALLOWED),
                "--color",
                "never",
            ],
            capture_output=True,
            text=True,
            check=False,
        )


def complete_log() -> str:
    lines = []
    blocked = request_count(BLOCKED)
    allowed = request_count(ALLOWED)
    for index in range(1, blocked + 1):
        lines.append(f"[blocked] {index}/{blocked} GET /probe -> 403 (1 ms)")
    for index in range(1, allowed + 1):
        lines.append(f"[allowed] {index}/{allowed} GET /ok -> 200 (1 ms)")
    return "\n".join(lines) + "\n"


def main() -> int:
    failures: list[str] = []

    result = run_report("")
    if result.returncode == 0:
        failures.append("an empty log must fail the gate")
    elif "incomplete run" not in result.stdout:
        failures.append(f"an empty log: unexpected output: {result.stdout!r}{result.stderr!r}")

    blocked = request_count(BLOCKED)
    partial = f"[blocked] 1/{blocked} GET /probe -> 403 (1 ms)\n"
    result = run_report(partial)
    if result.returncode == 0:
        failures.append("a partial log must fail the gate")
    elif "incomplete run" not in result.stdout:
        failures.append(f"a partial log: unexpected output: {result.stdout!r}{result.stderr!r}")

    result = run_report(complete_log())
    if result.returncode != 0:
        failures.append(f"a complete run must pass: {result.stdout!r}{result.stderr!r}")
    elif "result: PASS" not in result.stdout:
        failures.append(f"a complete run: unexpected output: {result.stdout!r}")

    allowed = request_count(ALLOWED)
    leak = complete_log().replace(
        f"[allowed] 1/{allowed} GET /ok -> 200 (1 ms)",
        f"[allowed] 1/{allowed} GET /ok -> 500 (1 ms)",
    )
    result = run_report(leak)
    if result.returncode == 0:
        failures.append("an allowed-phase failure must fail the gate")

    runner = RUNNER.read_text(encoding="utf-8")
    if "driver_status" not in runner:
        failures.append("the runner must keep the driver exit status")
    if 'if [ "$driver_status" -ne 0 ]' not in runner:
        failures.append("the runner must fail on a non-zero driver status")

    workflow = (ROOT / ".github" / "workflows" / "daily-cve.yml").read_text(
        encoding="utf-8"
    )
    if "startswith(old)" not in workflow:
        failures.append("the corpus guard must compare bytes against HEAD")
    if "numstat" in workflow:
        failures.append("the corpus guard must not count text-diff deletions")
    if "--skip the_committed_rules_signature_is_valid" not in workflow:
        failures.append(
            "the verify job must skip the committed-pair test for the unsigned candidate"
        )

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    print("black-box gate self-test passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
