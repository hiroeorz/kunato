#!/bin/sh
# Verify that the shipped systemd unit keeps its hardening defaults.
#
# The exposure score is a heuristic and its weights change between systemd
# releases. The exact directives below are the regression guard; review both
# after a systemd upgrade.
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

command -v systemd-analyze >/dev/null 2>&1 || {
    echo "systemd-analyze is required" >&2
    exit 1
}

check_unit() {
    unit=$1
    # --threshold is a percentage of the maximum exposure score.
    err=$(mktemp)
    trap 'rm -f "$err"' EXIT

    if ! report=$(systemd-analyze security --offline=yes --threshold=20 "$unit" 2>"$err"); then
        cat "$err" >&2
        printf '%s\n' "$report" >&2
        exit 1
    fi

    # systemd-analyze logs a typo in a setting and keeps going, so fail on any
    # parse warning instead of trusting the score alone.
    if grep -Eiq 'failed to parse|unknown (key|lvalue)|invalid' "$err"; then
        cat "$err" >&2
        exit 1
    fi

    for directive in \
        'AmbientCapabilities=CAP_NET_BIND_SERVICE' \
        'CapabilityBoundingSet=CAP_NET_BIND_SERVICE' \
        'NoNewPrivileges=true' \
        'ProtectSystem=strict' \
        'ProtectHome=true' \
        'PrivateTmp=true' \
        'ProtectProc=invisible' \
        'ProcSubset=pid' \
        'PrivateDevices=true' \
        'ProtectClock=true' \
        'ProtectKernelTunables=true' \
        'ProtectKernelModules=true' \
        'ProtectKernelLogs=true' \
        'ProtectControlGroups=true' \
        'ProtectHostname=true' \
        'RestrictNamespaces=true' \
        'RestrictRealtime=true' \
        'RestrictSUIDSGID=true' \
        'LockPersonality=true' \
        'MemoryDenyWriteExecute=true' \
        'SystemCallArchitectures=native' \
        'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX' \
        'SystemCallFilter=@system-service' \
        'UMask=0077' \
        'RemoveIPC=true'
    do
        if ! grep -qxF "$directive" "$unit"; then
            echo "missing hardening directive: $directive" >&2
            exit 1
        fi
    done

    echo "unit hardening OK: $unit"
}

if [ $# -gt 0 ]; then
    check_unit "$1"
else
    check_unit "$script_dir/../packaging/kunato.service"
    check_unit "$script_dir/../packaging/kunato-console.service"
fi
