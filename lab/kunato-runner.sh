#!/bin/sh
# Run the local Kunato binary with protection disabled for the signature
# sandbox suites, and with the protection profile for the behavior suite.
set -eu
for argument in "$@"; do
    if [ "$argument" = "--validate" ]; then
        exec /kunato "$@"
    fi
done
if [ "${LAB_DISABLE_PROTECTION:-1}" = "1" ]; then
    exec /kunato "$@" --disable-protection
fi
exec /kunato "$@"
