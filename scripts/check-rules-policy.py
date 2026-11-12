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
CATEGORY_RE = re.compile(r"^  - name:\s*(.+?)\s*$")
RULE_RE = re.compile(r"^      - name:\s*(.+?)\s*$")
CATEGORY_ENABLED_RE = re.compile(r"^    enabled\s*:\s*(.+?)\s*$")
CATEGORY_ACTION_RE = re.compile(r"^    action\s*:\s*(.+?)\s*$")
RULE_ACTION_RE = re.compile(r"^        action\s*:\s*(.+?)\s*$")
UNEXPECTED_ACTION_RE = re.compile(r"^(?:-\s+)?action\s*:")


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


def reject_noncanonical_key(path: Path, number: int, stripped: str) -> None:
    """Reject key spellings the line scanner would skip.

    The config parser also understands explicit ``?`` keys and quoted keys.
    This scanner does not, so accepting either would let a category or rule
    action hide in a spelling the gate never inspects. Fail closed instead.
    """
    if stripped.startswith("?"):
        raise ValueError(
            f"{path}:{number}: explicit mapping keys are not supported; use plain block keys"
        )
    candidate = stripped[2:].lstrip(" ") if stripped.startswith("- ") else stripped
    if not candidate.startswith(("'", '"')):
        return
    quote = candidate[0]
    end = candidate.find(quote, 1)
    if end == -1:
        raise ValueError(
            f"{path}:{number}: multi-line quoted keys are not supported; use plain block keys"
        )
    if candidate[end + 1 :].lstrip(" ").startswith(":"):
        raise ValueError(
            f"{path}:{number}: quoted mapping keys are not supported; use plain block keys"
        )


def parse(path: Path) -> list[Category]:
    categories: list[Category] = []
    current_category: Category | None = None
    current_rule: Rule | None = None
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

        if stripped == "categories:":
            if saw_categories:
                raise ValueError(f"{path}:{number}: duplicate categories block")
            saw_categories = True
            in_categories = True
            continue
        if not in_categories:
            continue
        if indent == 0 and stripped.startswith("-"):
            raise ValueError(
                f"{path}:{number}: indentless sequence entries are not supported; "
                "indent category entries by two spaces"
            )
        reject_noncanonical_key(path, number, stripped)
        if indent == 0:
            # A top-level key after the categories block ends it.
            break

        if stripped.startswith("- {") or stripped.startswith("- ["):
            raise ValueError(
                f"{path}:{number}: use block style for category and rule entries"
            )
        if re.match(r"^(action|enabled)\s*:\s*$", stripped):
            raise ValueError(
                f"{path}:{number}: action and enabled must be single-line scalars"
            )
        if "action:" in stripped and stripped.lstrip("- ").startswith("{"):
            raise ValueError(f"{path}:{number}: use block style for action fields")

        category_match = CATEGORY_RE.match(line)
        if category_match:
            current_category = Category(name=scalar(category_match.group(1)))
            categories.append(current_category)
            current_rule = None
            continue
        rule_match = RULE_RE.match(line)
        if rule_match:
            if current_category is None:
                raise ValueError(f"{path}:{number}: rule outside a category")
            current_rule = Rule(name=scalar(rule_match.group(1)))
            current_category.rules.append(current_rule)
            continue

        enabled_match = CATEGORY_ENABLED_RE.match(line)
        if enabled_match:
            if current_category is None:
                raise ValueError(f"{path}:{number}: enabled outside a category")
            value = scalar(enabled_match.group(1)).lower()
            if value not in ("true", "false"):
                raise ValueError(f"{path}:{number}: invalid enabled value")
            current_category.enabled = value == "true"
            continue
        action_match = CATEGORY_ACTION_RE.match(line)
        if action_match:
            if current_category is None:
                raise ValueError(f"{path}:{number}: action outside a category")
            action = scalar(action_match.group(1)).upper()
            if action not in ALLOWED_ACTIONS:
                raise ValueError(f"{path}:{number}: unknown action {action}")
            current_category.action = action
            continue
        rule_action_match = RULE_ACTION_RE.match(line)
        if rule_action_match:
            if current_rule is None:
                raise ValueError(f"{path}:{number}: rule action outside a rule")
            action = scalar(rule_action_match.group(1)).upper()
            if action not in ALLOWED_ACTIONS:
                raise ValueError(f"{path}:{number}: unknown action {action}")
            current_rule.action = action
            continue

        # An `action:` key at an unexpected indentation is not part of the
        # documented rule schema. Reject it rather than risk a second
        # interpretation.
        if indent <= 8 and UNEXPECTED_ACTION_RE.match(stripped):
            raise ValueError(f"{path}:{number}: unexpected action field")

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
