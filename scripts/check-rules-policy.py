#!/usr/bin/env python3
"""Reject unreviewed ALLOW actions in the published rule set.

The daily CVE workflow lets an LLM agent edit ``rules.example.yaml`` from
untrusted advisory text. The signed artifact is generated from that file, so an
enabled ALLOW category (or a rule-level ALLOW action) would become a signed
bypass for the bundled rules. This gate runs in the signing job before
``minisign`` and in the read-only verification job.

The rule file uses a deliberately small YAML subset. The parser below accepts
only the canonical block style used by ``rules.example.yaml``; a flow mapping,
a quoted or explicit mapping key, an indentless sequence entry, or an unusual
indentation is rejected instead of guessed. The config parser accepts those
spellings, so silently skipping one would let an ALLOW escape the gate. That
keeps the gate from being bypassed by a spelling the strict scanner does not
understand.

Usage:
    scripts/check-rules-policy.py [--allowlist FILE] FILE [FILE ...]

Entries in the allowlist:

    # comments are ignored
    category trusted-sources

An allowlisted ALLOW category is permitted only while it is disabled. A
rule-level ALLOW action is never permitted, and the allowlist has no rule
form.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

ALLOWED_ACTIONS = {"BLOCK", "ALLOW", "LOG"}

# Positive structural allowlist over the `categories:` block. The gate accepts
# exactly the canonical block style the managed rule set is generated in and
# rejects every other line shape instead of skipping it. The config parser is
# more permissive (tabs after the `-` indicator, deeper indentation, a bare `-`,
# a nested name scalar, quoted keys, flow collections), so a line this scanner
# does not positively recognise could otherwise carry an enabled ALLOW past the
# gate. Extending the rule-file schema requires extending these patterns.
CATEGORY_ENTRY_RE = re.compile(r"^  - name: (\S.*?)\s*$")
RULE_ENTRY_RE = re.compile(r"^      - name: (\S.*?)\s*$")
CATEGORY_KEY_RE = re.compile(
    r"^    (enabled|action|phase|threshold|description|response): (\S.*?)\s*$"
)
CATEGORY_RULES_RE = re.compile(r"^    rules:\s*$")
RULE_KEY_RE = re.compile(
    r"^        (enabled|action|match|description|response|limit):(?: (\S.*?))?\s*$"
)
MATCH_MAP_RE = re.compile(r"^          (headers|cookies|response_headers):\s*$")
MATCH_KEY_RE = re.compile(
    r"^          (path|method|source_ip|in|regex|status|headers|cookies|response_headers): "
    r"(\S.*?)\s*$"
)
HEADER_ENTRY_RE = re.compile(r"^            [A-Za-z0-9_][A-Za-z0-9_.-]*: (\S.*?)\s*$")


@dataclass
class Rule:
    name: str
    action: str | None = None


@dataclass
class Category:
    name: str
    enabled: bool = True
    action: str | None = None
    rules: list[Rule] = field(default_factory=list)


def strip_comment(line: str) -> str:
    """Drop a trailing comment while preserving `#` inside quoted scalars."""
    quote: str | None = None
    escaped = False
    for index, character in enumerate(line):
        if escaped:
            escaped = False
            continue
        if quote is not None:
            if character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in ("'", '"'):
            quote = character
            continue
        if character == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index]
    return line


def scalar(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def reject_shape(path: Path, number: int, stripped: str) -> None:
    raise ValueError(
        f"{path}:{number}: unrecognised rule-file structure {stripped!r}; "
        "the gate accepts only `  - name: NAME` category entries, "
        "`      - name: NAME` rule entries, and plain block keys at the "
        "canonical columns"
    )


def parse(path: Path) -> list[Category]:
    """Read the categories block through the structural allowlist."""
    categories: list[Category] = []
    current_category: Category | None = None
    current_rule: Rule | None = None
    in_match_map = False
    in_categories = False
    saw_categories = False

    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = strip_comment(raw)
        if not line.strip():
            continue
        leading = line[: len(line) - len(line.lstrip(" \t"))]
        if "\t" in leading:
            raise ValueError(f"{path}:{number}: tabs are not allowed for indentation")
        stripped = line.lstrip(" ")
        indent = len(line) - len(stripped)

        if not in_categories:
            if stripped.rstrip() == "categories:":
                if saw_categories:
                    raise ValueError(f"{path}:{number}: duplicate categories block")
                saw_categories = True
                in_categories = True
            continue
        if indent == 0:
            if stripped.startswith("-"):
                raise ValueError(
                    f"{path}:{number}: indentless sequence entries are not supported; "
                    "indent category entries by two spaces"
                )
            # A top-level key after the categories block ends it.
            break

        if indent == 2:
            match = CATEGORY_ENTRY_RE.match(line)
            if not match:
                reject_shape(path, number, stripped)
            current_category = Category(name=scalar(match.group(1)))
            categories.append(current_category)
            current_rule = None
            in_match_map = False
            continue

        if indent == 4:
            if CATEGORY_RULES_RE.match(line):
                if current_category is None:
                    reject_shape(path, number, stripped)
                in_match_map = False
                continue
            match = CATEGORY_KEY_RE.match(line)
            if not match or current_category is None:
                reject_shape(path, number, stripped)
            key, value = match.group(1), scalar(match.group(2))
            if key == "enabled":
                lowered = value.lower()
                if lowered not in ("true", "false"):
                    raise ValueError(f"{path}:{number}: invalid enabled value")
                current_category.enabled = lowered == "true"
            elif key == "action":
                action = value.upper()
                if action not in ALLOWED_ACTIONS:
                    raise ValueError(f"{path}:{number}: unknown action {action}")
                current_category.action = action
            continue

        if indent == 6:
            match = RULE_ENTRY_RE.match(line)
            if not match or current_category is None:
                reject_shape(path, number, stripped)
            current_rule = Rule(name=scalar(match.group(1)))
            current_category.rules.append(current_rule)
            in_match_map = False
            continue

        if indent == 8:
            match = RULE_KEY_RE.match(line)
            if not match or current_rule is None:
                reject_shape(path, number, stripped)
            key, value = match.group(1), match.group(2)
            if key == "action" and value is not None:
                action = scalar(value).upper()
                if action not in ALLOWED_ACTIONS:
                    raise ValueError(f"{path}:{number}: unknown action {action}")
                current_rule.action = action
            in_match_map = False
            continue

        if indent == 10:
            if MATCH_MAP_RE.match(line):
                in_match_map = True
                continue
            if not MATCH_KEY_RE.match(line):
                reject_shape(path, number, stripped)
            in_match_map = False
            continue

        if indent == 12:
            if not in_match_map or not HEADER_ENTRY_RE.match(line):
                reject_shape(path, number, stripped)
            continue

        reject_shape(path, number, stripped)

    if not saw_categories:
        raise ValueError(f"{path}: no categories block")
    return categories


def load_allowlist(path: Path) -> set[str]:
    """Read reviewed category names.

    A rule-level ALLOW is never permitted, so a ``rule`` entry is rejected
    instead of being accepted and ignored.
    """
    allowed: set[str] = set()
    if not path.exists():
        return allowed
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = strip_comment(raw).strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 2 or parts[0] != "category":
            raise ValueError(
                f"{path}:{number}: expected `category NAME`; rule-level ALLOW is never permitted"
            )
        allowed.add(parts[1])
    return allowed


def check(path: Path, allowed: set[str]) -> list[str]:
    problems: list[str] = []
    for category in parse(path):
        if category.action == "ALLOW":
            if category.name not in allowed:
                problems.append(
                    f"{path}: category `{category.name}` uses ALLOW without a reviewed entry"
                )
            if category.enabled:
                problems.append(
                    f"{path}: ALLOW category `{category.name}` must stay disabled"
                )
        for rule in category.rules:
            if rule.action == "ALLOW":
                problems.append(
                    f"{path}: rule `{category.name}/{rule.name}` uses ALLOW; "
                    "rule-level ALLOW is never permitted"
                )
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--allowlist",
        type=Path,
        default=Path(".github/rules-policy-allowlist"),
        help="reviewed ALLOW entries",
    )
    parser.add_argument("files", nargs="+", type=Path)
    args = parser.parse_args()

    try:
        allowed = load_allowlist(args.allowlist)
        problems: list[str] = []
        for path in args.files:
            problems.extend(check(path, allowed))
    except (OSError, ValueError) as error:
        print(f"rules policy check failed: {error}", file=sys.stderr)
        return 1

    if problems:
        print("rules policy check failed:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print("rules policy check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
