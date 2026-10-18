#!/bin/sh
# Verify that the published rule set stays inside the rule-set format of the
# newest release.
#
# Installs with rules_update enabled download dist/rules.yaml every day, and an
# install rejects the whole candidate when it uses a construct its binary does
# not implement: it keeps its previous rules and silently stops receiving
# updates. The baseline is therefore the newest v* tag, and this check runs the
# baseline binary against the published file.
#
# Set KUNATO_RULES_BASELINE to check a different tag, or KUNATO_RULES_BIN to an
# already built binary of that tag to skip the build.
set -eu

root=$(cd -- "$(dirname -- "$0")/.." && pwd)
rules="$root/dist/rules.yaml"
scratch="$root/target/rules-compat"

baseline="${KUNATO_RULES_BASELINE:-}"
if [ -z "$baseline" ]; then
    baseline=$(git -C "$root" describe --tags --abbrev=0 --match 'v*' 2>/dev/null || true)
fi
if [ -z "$baseline" ]; then
    echo "no release tag yet; skipping the rules compatibility check"
    exit 0
fi

if [ -n "${KUNATO_RULES_BIN:-}" ]; then
    binary="$KUNATO_RULES_BIN"
else
    tree="$scratch/$baseline"
    binary="$tree/target/release/kunato"
    if [ ! -x "$binary" ]; then
        command -v cargo >/dev/null 2>&1 || {
            echo "cargo is required to build the $baseline baseline" >&2
            exit 1
        }
        rm -rf "$tree"
        mkdir -p "$tree"
        if ! archive_error=$(git -C "$root" archive --format=tar \
            --output "$scratch/$baseline.tar" "$baseline" 2>&1); then
            echo "cannot read the $baseline baseline: $archive_error" >&2
            echo "fetch the release tags (git fetch --tags) and retry" >&2
            exit 1
        fi
        tar -x -f "$scratch/$baseline.tar" -C "$tree"
        if ! build_output=$(cd "$tree" && CARGO_TARGET_DIR="$tree/target" \
            cargo build --release --locked 2>&1); then
            echo "failed to build the $baseline baseline:" >&2
            printf '%s\n' "$build_output" >&2
            exit 1
        fi
    fi
fi

config="$scratch/kunato-rules-compat.yaml"
mkdir -p "$scratch"
{
    printf '%s\n' 'listen: 127.0.0.1:18080'
    printf '%s\n' 'upstream: http://127.0.0.1:18081'
    printf 'rules_file: %s\n' "$rules"
} > "$config"

if output=$("$binary" --config "$config" --validate 2>&1); then
    echo "dist/rules.yaml is readable by the newest release ($baseline)"
    exit 0
fi

cat >&2 <<EOF
dist/rules.yaml is not readable by $baseline, the newest release:

$output

Installs running $baseline reject the whole published rule set and keep their
previous rules, so they stop receiving updates. Release a build that implements
the construct (a new v* tag moves this baseline and is the supported remedy), or
keep the published set inside the released format. See "Rule set format
compatibility" in docs/development.md.
EOF
exit 1
