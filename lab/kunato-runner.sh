#!/bin/sh
# Run the local Kunato binary with protection disabled for the signature
# campaigns, and with the protection profile for the behavior campaign.
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
