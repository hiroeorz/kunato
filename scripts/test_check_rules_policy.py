#!/usr/bin/env python3
"""Negative and positive cases for scripts/check-rules-policy.py."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check-rules-policy.py"
ALLOWLIST = ROOT / ".github" / "rules-policy-allowlist"

BASE = """categories:
  - name: trusted-sources
    enabled: false
    action: ALLOW
    rules:
      - name: internal
        match: { source_ip: 127.0.0.1/32 }
"""


def run(text: str, allowlist: str | None = None) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "rules.yaml"
        path.write_text(text, encoding="utf-8")
        allowlist_path = ALLOWLIST
        if allowlist is not None:
            allowlist_path = Path(directory) / "allowlist"
            allowlist_path.write_text(allowlist, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--allowlist", str(allowlist_path), str(path)],
            capture_output=True,
            text=True,
            check=False,
        )


def main() -> int:
    failures: list[str] = []

    result = run(BASE)
    if result.returncode != 0:
        failures.append(f"the reviewed baseline must pass: {result.stderr}")

    cases = {
        "an enabled ALLOW category is rejected": (
            BASE.replace("enabled: false", "enabled: true"),
            "must stay disabled",
        ),
        "a rule-level ALLOW is rejected": (
            BASE.replace(
                "      - name: internal\n        match: { source_ip: 127.0.0.1/32 }\n",
                "      - name: internal\n        match: { source_ip: 127.0.0.1/32 }\n"
                "      - name: probe\n        action: ALLOW\n"
                "        match: { headers: { X-Probe: allow } }\n",
            ),
            "rule-level ALLOW is never permitted",
        ),
        "an unreviewed ALLOW category is rejected": (
            BASE.replace("trusted-sources", "new-allow"),
            "uses ALLOW without a reviewed entry",
        ),
        "flow-style entries are rejected": (
            "categories:\n  - { name: trusted-sources, enabled: false, action: ALLOW }\n",
            "use block style",
        ),
        "an indentless ALLOW category is rejected": (
            "categories:\n"
            "- name: trusted-sources\n"
            "  enabled: true\n"
            "  action: ALLOW\n"
            "  rules:\n"
            "    - name: internal\n"
            "      match: { source_ip: 127.0.0.1/32 }\n",
            "indentless sequence entries",
        ),
        "a quoted category action is rejected": (
            BASE.replace("    action: ALLOW", '    "action": ALLOW'),
            "quoted mapping keys",
        ),
        "a quoted rule action is rejected": (
            BASE.replace(
                "      - name: internal\n",
                '      - name: internal\n        "action": ALLOW\n',
            ),
            "quoted mapping keys",
        ),
        "an explicit category action is rejected": (
            BASE.replace("    action: ALLOW", "    ? action\n    : ALLOW"),
            "explicit mapping keys",
        ),
        "a non-canonical category indent is rejected": (
            "categories:\n"
            "   - name: trusted-sources\n"
            "     enabled: true\n"
            "     action: ALLOW\n",
            "unexpected action field",
        ),
    }
    for label, (text, expected) in cases.items():
        result = run(text)
        if result.returncode == 0:
            failures.append(f"{label}: accepted")
        elif expected not in result.stderr:
            failures.append(f"{label}: unexpected output: {result.stderr}")

    rule_allow = BASE.replace(
        "      - name: internal\n",
        "      - name: internal\n        action: ALLOW\n",
    )
    result = run(rule_allow)
    if result.returncode == 0:
        failures.append("a rule-level ALLOW must be rejected even for an allowlisted category")
    elif "rule-level ALLOW is never permitted" not in result.stderr:
        failures.append(f"a rule-level ALLOW: unexpected output: {result.stderr}")

    result = run(BASE, allowlist="rule trusted-sources/internal\n")
    if result.returncode == 0:
        failures.append("a rule allowlist entry must be rejected")
    elif "expected `category NAME`" not in result.stderr:
        failures.append(f"a rule allowlist entry: unexpected output: {result.stderr}")

    positives = {
        "a quoted scalar value passes": BASE.replace(
            "    rules:", '    description: "operator notes: quoted value"\n    rules:'
        ),
        "an action-like description value passes": BASE.replace(
            "    rules:", '    description: "notes about action: ALLOW"\n    rules:'
        ),
        "a flow mapping with a quoted header name passes": BASE.replace(
            "match: { source_ip: 127.0.0.1/32 }",
            'match: { headers: { "X-Probe": allow } }',
        ),
    }
    for label, text in positives.items():
        result = run(text)
        if result.returncode != 0:
            failures.append(f"{label}: rejected: {result.stderr}")

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    print("rules policy self-test passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
