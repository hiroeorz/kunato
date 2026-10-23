#!/bin/sh
# Run the ACME integration tests against a local Pebble test server.
#
# Pebble is Let's Encrypt's ACME test server. This script starts it in Docker
# with host networking, points its TLS-ALPN-01 validation port at the test
# listener (tests/acme_pebble.rs binds 127.0.0.1:15001), and runs the ignored
# integration tests.
#
# Usage: sh scripts/acme-pebble-test.sh [test-filter ...]
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
cleanup() {
    rm -rf "$TMP"
    docker rm -f kunato-pebble >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker rm -f kunato-pebble >/dev/null 2>&1 || true
docker run -d --name kunato-pebble --network host \
    --add-host www.localhost:127.0.0.1 \
    -e PEBBLE_VA_NOSLEEP=1 \
    -e PEBBLE_WFE_NONCEREJECT=0 \
    -v "$ROOT/tests/acme/pebble-config.json:/test/config/pebble-config.json:ro" \
    ghcr.io/letsencrypt/pebble:latest -config /test/config/pebble-config.json >/dev/null

i=0
while [ "$i" -lt 60 ]; do
    if curl -sk --max-time 2 https://localhost:14000/dir | grep -q newNonce; then
        break
    fi
    i=$((i + 1))
    sleep 0.5
done

docker cp kunato-pebble:/test/certs/pebble.minica.pem "$TMP/minica.pem" >/dev/null
curl -sk https://localhost:15000/roots/0 >"$TMP/roots.pem"
code=$(curl -sk -o "$TMP/intermediates.pem" -w '%{http_code}' \
    https://localhost:15000/intermediates/0)
cat "$TMP/roots.pem" >"$TMP/trust.pem"
if [ "$code" = "200" ]; then
    cat "$TMP/intermediates.pem" >>"$TMP/trust.pem"
fi

# The ACME API client trusts the native CA store; SSL_CERT_FILE makes
# rustls-native-certs trust only Pebble's minica root for this run.
cd "$ROOT"
SSL_CERT_FILE="$TMP/minica.pem" \
    PEBBLE_ROOT_CERTS="$TMP/trust.pem" \
    cargo test --test acme_pebble -- --ignored --nocapture --test-threads=1 "$@"
