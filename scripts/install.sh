#!/bin/sh
# Kunato installer for Linux servers. Run it through sudo:
#
#   curl -fsSL https://raw.githubusercontent.com/hiroeorz/kunato/main/scripts/install.sh | sudo sh
#
# Run with --help for all options.
set -eu

REPO="hiroeorz/kunato"
BASE_URL="${KUNATO_BASE_URL:-https://github.com/$REPO/releases/download}"
DEFAULT_RULES_URL="https://raw.githubusercontent.com/$REPO/main/dist/rules.yaml"
CONFIG_PATH="/etc/kunato/kunato.yaml"
CONFIG_DIR="/etc/kunato"
TLS_DIR="/etc/kunato/tls"
STATE_DIR="/var/lib/kunato"
RULES_FILE="$STATE_DIR/rules.yaml"
BIN_PATH="/usr/local/bin/kunato"
UNIT_PATH="/etc/systemd/system/kunato.service"

VERSION="${KUNATO_VERSION:-}"
UPSTREAM="${KUNATO_UPSTREAM:-}"
LISTEN="0.0.0.0:443"
TLS_CERT=""
TLS_KEY=""
RULES_URL="$DEFAULT_RULES_URL"
NO_START=0
ASSUME_YES=0
UNINSTALL=0
PURGE=0

log() { printf 'kunato-install: %s\n' "$*"; }
die() {
    printf 'kunato-install: error: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Kunato installer for Linux servers.

Usage:
  curl -fsSL https://raw.githubusercontent.com/hiroeorz/kunato/main/scripts/install.sh | sudo sh
  curl -fsSL ... | sudo sh -s -- --upstream http://127.0.0.1:3000 --tls-cert cert.pem --tls-key key.pem --yes

Options:
  --version TAG        Release tag to install (default: the latest release).
  --upstream URL       Upstream server the WAF forwards to (required on first install).
  --listen ADDR        Address to listen on (default: 0.0.0.0:443).
  --tls-cert PATH      PEM certificate chain; copied to /etc/kunato/tls/cert.pem.
  --tls-key PATH       PEM private key; copied to /etc/kunato/tls/key.pem.
  --rules-url URL      Managed rule set URL (default: dist/rules.yaml on main).
  --no-start           Install and validate, but do not enable/start the service.
  --yes                Never prompt; fail instead of asking.
  --uninstall          Stop the service and remove the binary and unit file.
  --purge              With --uninstall, also remove /etc/kunato and /var/lib/kunato.
  --help               Show this help.

Environment:
  KUNATO_BASE_URL      Override the release download base URL (for testing).
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version)
            [ $# -ge 2 ] || die "--version requires a value"
            VERSION="$2"
            shift 2
            ;;
        --upstream)
            [ $# -ge 2 ] || die "--upstream requires a value"
            UPSTREAM="$2"
            shift 2
            ;;
        --listen)
            [ $# -ge 2 ] || die "--listen requires a value"
            LISTEN="$2"
            shift 2
            ;;
        --tls-cert)
            [ $# -ge 2 ] || die "--tls-cert requires a value"
            TLS_CERT="$2"
            shift 2
            ;;
        --tls-key)
            [ $# -ge 2 ] || die "--tls-key requires a value"
            TLS_KEY="$2"
            shift 2
            ;;
        --rules-url)
            [ $# -ge 2 ] || die "--rules-url requires a value"
            RULES_URL="$2"
            shift 2
            ;;
        --no-start)
            NO_START=1
            shift
            ;;
        --yes)
            ASSUME_YES=1
            shift
            ;;
        --uninstall)
            UNINSTALL=1
            shift
            ;;
        --purge)
            PURGE=1
            shift
            ;;
        --help | -h)
            usage
            exit 0
            ;;
        *)
            die "unknown option: $1 (see --help)"
            ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "must run as root; pipe the script to sudo sh"
[ "$(uname -s)" = "Linux" ] || die "kunato targets Linux only"
command -v curl >/dev/null 2>&1 || die "curl is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"
if [ -n "$TLS_CERT" ] && [ -z "$TLS_KEY" ]; then
    die "--tls-key is required together with --tls-cert"
fi
if [ -n "$TLS_KEY" ] && [ -z "$TLS_CERT" ]; then
    die "--tls-cert is required together with --tls-key"
fi

detect_target() {
    case "$(uname -m)" in
        x86_64 | amd64) printf '%s' "x86_64-unknown-linux-musl" ;;
        aarch64 | arm64) printf '%s' "aarch64-unknown-linux-musl" ;;
        *) die "unsupported architecture: $(uname -m)" ;;
    esac
}

nologin_shell() {
    for shell in /usr/sbin/nologin /sbin/nologin /usr/bin/false /bin/false; do
        if [ -x "$shell" ]; then
            printf '%s' "$shell"
            return
        fi
    done
    printf '%s' "/bin/false"
}

ask() {
    question="$1"
    default="$2"
    if [ "$ASSUME_YES" -eq 1 ] || [ ! -r /dev/tty ]; then
        printf '%s' "$default"
        return
    fi
    printf '%s' "$question" >/dev/tty
    if IFS= read -r answer < /dev/tty; then
        :
    else
        answer=""
    fi
    if [ -n "$answer" ]; then
        printf '%s' "$answer"
    else
        printf '%s' "$default"
    fi
}

fetch_latest_version() {
    api="https://api.github.com/repos/$REPO/releases/latest"
    tag=$(curl -fsSL "$api" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
    [ -n "$tag" ] || die "could not determine the latest release; pass --version"
    printf '%s' "$tag"
}

stop_service_if_present() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop kunato 2>/dev/null || true
    fi
}

ensure_user() {
    if ! id -u kunato >/dev/null 2>&1; then
        log "creating the kunato system user"
        useradd --system --no-create-home --shell "$(nologin_shell)" kunato
    fi
}

copy_tls_material() {
    [ -n "$TLS_CERT" ] && [ -n "$TLS_KEY" ] || return 0
    [ -f "$TLS_CERT" ] || die "certificate file not found: $TLS_CERT"
    [ -f "$TLS_KEY" ] || die "key file not found: $TLS_KEY"
    log "installing TLS material into $TLS_DIR"
    install -d -m 0750 -o root -g kunato "$TLS_DIR"
    install -m 0640 -o root -g kunato "$TLS_CERT" "$TLS_DIR/cert.pem"
    install -m 0640 -o root -g kunato "$TLS_KEY" "$TLS_DIR/key.pem"
}

install_release() {
    TARGET=$(detect_target)
    if [ -z "$VERSION" ]; then
        log "resolving the latest release"
        VERSION=$(fetch_latest_version)
    fi
    case "$VERSION" in
        v*) ;;
        *) VERSION="v$VERSION" ;;
    esac

    tarball="kunato-$VERSION-$TARGET.tar.gz"
    workdir=$(mktemp -d)
    trap 'rm -rf "$workdir"' EXIT INT TERM

    log "downloading $tarball"
    curl -fsSL --retry 3 "$BASE_URL/$VERSION/$tarball" -o "$workdir/$tarball" ||
        die "failed to download $BASE_URL/$VERSION/$tarball"
    curl -fsSL --retry 3 "$BASE_URL/$VERSION/SHA256SUMS" -o "$workdir/SHA256SUMS" ||
        die "failed to download SHA256SUMS"

    log "verifying the checksum"
    (
        cd "$workdir"
        grep -E "  (\./)?$tarball\$" SHA256SUMS > checksum.txt ||
            die "SHA256SUMS does not list $tarball"
        sha256sum -c checksum.txt
    )

    log "extracting and installing $tarball"
    tar -xzf "$workdir/$tarball" -C "$workdir"
    binary=$(find "$workdir" -maxdepth 3 -type f -name kunato -print -quit)
    [ -n "$binary" ] || die "archive does not contain the kunato binary"
    install -m 0755 "$binary" "$BIN_PATH"

    unit=$(find "$workdir" -maxdepth 3 -type f -name kunato.service -print -quit)
    if [ -n "$unit" ]; then
        install -m 0644 "$unit" "$UNIT_PATH"
    elif [ ! -f "$UNIT_PATH" ]; then
        die "archive does not contain kunato.service and no unit file is installed"
    fi
}

initialize_configuration() {
    ensure_user
    copy_tls_material
    install -d -m 0750 -o kunato -g kunato "$STATE_DIR"

    if [ -f "$CONFIG_PATH" ]; then
        log "keeping the existing configuration at $CONFIG_PATH"
    else
        if [ -z "$UPSTREAM" ]; then
            UPSTREAM=$(ask "Upstream URL (for example http://127.0.0.1:3000): " "")
        fi
        [ -n "$UPSTREAM" ] || die "--upstream is required for a fresh install"
        if [ -z "$TLS_CERT" ] && [ "$LISTEN" != "${LISTEN#*:443}" ]; then
            TLS_CERT=$(ask "TLS certificate path (empty to listen without TLS): " "")
            if [ -n "$TLS_CERT" ]; then
                TLS_KEY=$(ask "TLS private key path: " "")
                [ -n "$TLS_KEY" ] || die "a private key is required when a certificate is configured"
                copy_tls_material
            fi
        fi
        if [ -z "$TLS_CERT" ] && [ "$ASSUME_YES" -eq 1 ] && [ "$LISTEN" != "${LISTEN#*:443}" ]; then
            die "--tls-cert and --tls-key are required when listening on :443; use --listen for setups behind another TLS-terminating proxy"
        fi
        if [ -z "$TLS_CERT" ]; then
            log "warning: listening without TLS material; ensure a proxy or load balancer terminates TLS"
        fi

        log "writing $CONFIG_PATH"
        install -d -m 0750 -o root -g kunato "$CONFIG_DIR"
        init_args="--upstream $UPSTREAM --listen $LISTEN --rules-url $RULES_URL --output $CONFIG_PATH"
        if [ -n "$TLS_CERT" ]; then
            init_args="$init_args --cert-file $TLS_DIR/cert.pem --key-file $TLS_DIR/key.pem"
        fi
        # shellcheck disable=SC2086 # init_args is a deliberately split argument list
        "$BIN_PATH" init $init_args
        chown root:kunato "$CONFIG_PATH"
        chmod 0640 "$CONFIG_PATH"
    fi

    if [ ! -f "$RULES_FILE" ]; then
        log "downloading the managed rule set"
        if ! "$BIN_PATH" update-rules --config "$CONFIG_PATH"; then
            log "warning: initial rules download failed; starting with an empty rule set"
            printf 'categories: []\n' >"$RULES_FILE"
        fi
        chown kunato:kunato "$RULES_FILE" 2>/dev/null || true
    fi

    "$BIN_PATH" validate --config "$CONFIG_PATH"
}

uninstall() {
    log "stopping and disabling the kunato service"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now kunato 2>/dev/null || true
        systemctl daemon-reload 2>/dev/null || true
    fi
    rm -f "$BIN_PATH" "$UNIT_PATH"
    if [ "$PURGE" -eq 1 ]; then
        rm -rf "$CONFIG_DIR" "$STATE_DIR"
        log "removed $CONFIG_DIR and $STATE_DIR"
    else
        log "kept $CONFIG_DIR and $STATE_DIR; pass --purge to remove them"
    fi
    log "uninstalled"
}

main() {
    if [ "$UNINSTALL" -eq 1 ]; then
        uninstall
        return
    fi
    command -v systemctl >/dev/null 2>&1 || die "systemd is required to install kunato"

    install_release
    initialize_configuration

    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload
    fi
    if [ "$NO_START" -eq 1 ]; then
        log "installed $VERSION; service not started (--no-start)"
        return
    fi

    log "enabling and starting kunato"
    systemctl enable --now kunato
    sleep 1
    if systemctl is-active --quiet kunato; then
        log "kunato $VERSION is running; metrics: curl http://127.0.0.1:9090/metrics"
    else
        stop_service_if_present
        die "kunato failed to start; inspect the logs with: journalctl -u kunato -e"
    fi
}

main
