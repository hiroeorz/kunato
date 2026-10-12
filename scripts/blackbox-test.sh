#!/usr/bin/env bash
# One-command black-box test for Kunato.
#
# Builds kunato, the example upstream, and the blackbox driver, starts the
# upstream and Kunato with a copy of rules.example.yaml that does not trust the
# test client, replays blackbox/requests/blocked.txt and allowed.txt, and prints
# a colored pass/fail report with latency statistics.
#
# Usage:
#   scripts/blackbox-test.sh [--skip-build] [--workdir DIR] [--parallelism N]
#                            [--color auto|always|never]
#
# Exit status: 0 when every allowed request is forwarded, every blocked request
# is stopped, and the upstream access count matches; 1 otherwise.

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/.." && pwd)
cd "$repo_root"

skip_build=0
workdir=""
parallelism=5
color="auto"

while [ $# -gt 0 ]; do
    case "$1" in
        --skip-build) skip_build=1 ;;
        --workdir)
            workdir=$2
            shift
            ;;
        --parallelism)
            parallelism=$2
            shift
            ;;
        --color)
            color=$2
            shift
            ;;
        *)
            echo "unknown argument: $1" >&2
            exit 2
            ;;
    esac
    shift
done

if [ -z "$workdir" ]; then
    workdir=$(mktemp -d /tmp/kunato-blackbox.XXXXXX)
fi
mkdir -p "$workdir"
config="$workdir/rules-test.yaml"
blackbox_log="$workdir/blackbox.log"
upstream_log="$workdir/upstream.log"
kunato_log="$workdir/kunato.log"

if [ "$skip_build" -eq 0 ]; then
    echo "building kunato, the example upstream, and the blackbox driver..."
    cargo build --release
    cargo build --release --example upstream
    cargo build --release --manifest-path blackbox/Cargo.toml
fi

# Remove the trusted-sources category so the test client is inspected.
python3 - "$repo_root/rules.example.yaml" "$config" <<'PY'
import re
import sys

source, destination = sys.argv[1], sys.argv[2]
lines = open(source, encoding="utf-8").read().splitlines(keepends=True)
result = []
skipping = False
for line in lines:
    if skipping:
        if re.match(r"^  - name: ", line) or re.match(r"^\S", line):
            skipping = False
        else:
            continue
    if re.match(r"^  - name: trusted-sources\s*$", line):
        skipping = True
        continue
    result.append(line)
open(destination, "w", encoding="utf-8").writelines(result)
PY

port_open() {
    local port=$1
    if command -v ss >/dev/null 2>&1; then
        ss -ltn 2>/dev/null | grep -q ":$port "
    else
        (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null
    fi
}

for port in 3000 8080 9090; do
    if port_open "$port"; then
        echo "port $port is already in use; stop the process using it first" >&2
        exit 1
    fi
done

cleanup() {
    if [ -n "${kunato_pid:-}" ]; then
        kill "$kunato_pid" 2>/dev/null || true
    fi
    if [ -n "${upstream_pid:-}" ]; then
        kill "$upstream_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT

setsid ./target/release/examples/upstream --listen 127.0.0.1:3000 \
    >"$upstream_log" 2>&1 </dev/null &
upstream_pid=$!
setsid ./target/release/kunato --config "$config" --disable-protection --log-level debug \
    >"$kunato_log" 2>&1 </dev/null &
kunato_pid=$!

ready=0
for _ in $(seq 1 100); do
    if ! kill -0 "$upstream_pid" 2>/dev/null; then
        echo "the example upstream exited during startup:" >&2
        tail -n 20 "$upstream_log" >&2 || true
        exit 1
    fi
    if ! kill -0 "$kunato_pid" 2>/dev/null; then
        echo "kunato exited during startup:" >&2
        tail -n 20 "$kunato_log" >&2 || true
        exit 1
    fi
    if port_open 8080 && port_open 3000; then
        ready=1
        break
    fi
    sleep 0.1
done
if [ "$ready" -ne 1 ]; then
    echo "kunato and the upstream did not become ready; see $kunato_log" >&2
    exit 1
fi

./blackbox/target/release/kunato-blackbox \
    --blocked blackbox/requests/blocked.txt \
    --allowed blackbox/requests/allowed.txt \
    --addr 127.0.0.1:8080 \
    --parallelism "$parallelism" >"$blackbox_log" 2>&1 || true

set +e
python3 "$script_dir/blackbox-report.py" "$blackbox_log" \
    --blocked blackbox/requests/blocked.txt \
    --allowed blackbox/requests/allowed.txt \
    --upstream "$upstream_log" \
    --color "$color"
status=$?
set -e

echo
echo "logs: blackbox=$blackbox_log kunato=$kunato_log upstream=$upstream_log"
echo "test config: $config"
exit "$status"
