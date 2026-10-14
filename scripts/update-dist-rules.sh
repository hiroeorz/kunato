#!/bin/sh
# Regenerate dist/rules.yaml (categories only) from rules.example.yaml and
# refresh dist/rules.yaml.sha256. Run after every change to the rule set.
set -eu

root=$(cd -- "$(dirname -- "$0")/.." && pwd)
example="$root/rules.example.yaml"
dist="$root/dist/rules.yaml"

mkdir -p "$root/dist"
{
    printf '%s\n' \
        '# Kunato managed rule set (categories only).' \
        '# Generated from rules.example.yaml by scripts/update-dist-rules.sh; do not edit.' \
        '# Downloaded daily by installs with rules_update enabled and verified by sha256.' \
        ''
    awk '
        /^categories:/ { printing = 1 }
        printing && /^[a-z_]+:/ && !/^categories:/ { exit }
        printing { print }
    ' "$example"
} > "$dist"

(
    cd "$root/dist"
    sha256sum rules.yaml > rules.yaml.sha256
)
echo "updated $dist"
