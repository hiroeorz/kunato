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
DEFAULT_UPSTREAM="http://127.0.0.1:3000"
LISTEN="0.0.0.0:443"
TLS_CERT=""
TLS_KEY=""
ACME_DOMAINS=""
ACME_CONTACT=""
ACME_STAGING=0
ALLOWED_HOSTS=""
RULES_URL="$DEFAULT_RULES_URL"
NO_START=0
ALLOW_EMPTY_RULES=0
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
  --acme-domain DOMAIN Obtain Let's Encrypt certificates automatically (repeatable).
  --acme-contact EMAIL Contact email registered with the ACME account.
  --acme-staging       Use the Let's Encrypt staging directory (for testing).
  --allowed-host HOST  Host name or IP clients use to reach this server; added
                       to allowed_hosts (repeatable). ACME domains are added
                       automatically.
  --rules-url URL      Managed rule set URL (default: dist/rules.yaml on main).
  --no-start           Install and validate, but do not enable/start the service.
  --allow-empty-rules  Start kunato even when the initial rules download fails
                       (an empty rule set blocks nothing).
  --yes                Never prompt; fail instead of asking.
  --uninstall          Stop the service and remove the binary and unit file.
  --purge              With --uninstall, also remove /etc/kunato and /var/lib/kunato.
  --help               Show this help.

Environment:
  KUNATO_BASE_URL      Override the release download base URL (must be https://).
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
        --acme-domain)
            [ $# -ge 2 ] || die "--acme-domain requires a value"
            ACME_DOMAINS="${ACME_DOMAINS:+$ACME_DOMAINS }$2"
            shift 2
            ;;
        --acme-contact)
            [ $# -ge 2 ] || die "--acme-contact requires a value"
            ACME_CONTACT="$2"
            shift 2
            ;;
        --acme-staging)
            ACME_STAGING=1
            shift
            ;;
        --allowed-host)
            [ $# -ge 2 ] || die "--allowed-host requires a value"
            [ -n "$2" ] || die "--allowed-host must not be empty"
            case "$2" in
                *[[:space:]]*) die "--allowed-host must not contain whitespace" ;;
            esac
            ALLOWED_HOSTS="${ALLOWED_HOSTS:+$ALLOWED_HOSTS }$2"
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
        --allow-empty-rules)
            ALLOW_EMPTY_RULES=1
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
if [ -n "$TLS_CERT" ] && [ -n "$ACME_DOMAINS" ]; then
    die "--acme-domain cannot be combined with --tls-cert/--tls-key"
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
    if [ -n "$default" ]; then
        printf '%s [%s]: ' "$question" "$default" >/dev/tty
    else
        printf '%s: ' "$question" >/dev/tty
    fi
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
    tag=$(curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 "$api" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
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
    case "$VERSION" in
        "" | *[!A-Za-z0-9._-]*) die "invalid version tag: $VERSION" ;;
    esac

    tarball="kunato-$VERSION-$TARGET.tar.gz"
    workdir=$(mktemp -d)
    trap 'rm -rf "$workdir"' EXIT INT TERM

    log "downloading $tarball"
    curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 \
        "$BASE_URL/$VERSION/$tarball" -o "$workdir/$tarball" ||
        die "failed to download $BASE_URL/$VERSION/$tarball"
    curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 \
        "$BASE_URL/$VERSION/SHA256SUMS" -o "$workdir/SHA256SUMS" ||
        die "failed to download SHA256SUMS"

    log "verifying the checksum"
    (
        cd "$workdir"
        grep -E "  (\./)?$tarball\$" SHA256SUMS > checksum.txt ||
            die "SHA256SUMS does not list $tarball"
        sha256sum -c checksum.txt
    )

    log "extracting and installing $tarball"
    tar --no-same-owner --no-same-permissions -xzf "$workdir/$tarball" -C "$workdir"
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
            if [ "$ASSUME_YES" -eq 1 ] || [ ! -r /dev/tty ]; then
                die "--upstream is required for a fresh install"
            fi
            UPSTREAM=$(ask "Upstream URL (the web server Kunato protects)" "$DEFAULT_UPSTREAM")
        fi
        if [ -z "$TLS_CERT" ] && [ -z "$ACME_DOMAINS" ] && [ "$LISTEN" != "${LISTEN#*:443}" ]; then
            answer=$(ask "Let's Encrypt domain(s), comma separated (also added to allowed_hosts; empty to provide a certificate)" "")
            ACME_DOMAINS=$(printf '%s' "$answer" | tr ',' ' ')
            if [ -z "$ACME_DOMAINS" ]; then
                TLS_CERT=$(ask "TLS certificate path (empty to listen without TLS)" "")
                if [ -n "$TLS_CERT" ]; then
                    TLS_KEY=$(ask "TLS private key path" "")
                    [ -n "$TLS_KEY" ] || die "a private key is required when a certificate is configured"
                    copy_tls_material
                fi
            fi
        fi
        if [ -z "$TLS_CERT" ] && [ -z "$ACME_DOMAINS" ] && [ "$ASSUME_YES" -eq 1 ] && [ "$LISTEN" != "${LISTEN#*:443}" ]; then
            die "--tls-cert/--tls-key or --acme-domain is required when listening on :443; use --listen for setups behind another TLS-terminating proxy"
        fi
        if [ -z "$TLS_CERT" ] && [ -z "$ACME_DOMAINS" ]; then
            log "warning: listening without TLS material; ensure a proxy or load balancer terminates TLS"
        fi

        log "writing $CONFIG_PATH"
        install -d -m 0750 -o root -g kunato "$CONFIG_DIR"
        set -- --upstream "$UPSTREAM" --listen "$LISTEN" --rules-url "$RULES_URL" --output "$CONFIG_PATH"
        if [ -n "$TLS_CERT" ]; then
            set -- "$@" --cert-file "$TLS_DIR/cert.pem" --key-file "$TLS_DIR/key.pem"
        fi
        # Entries may contain shell glob characters (`*.example.com`, `[::1]`).
        # Disable pathname expansion so they reach `init` verbatim.
        set -f
        for domain in $ACME_DOMAINS; do
            set -- "$@" --acme-domain "$domain"
        done
        for host in $ALLOWED_HOSTS; do
            set -- "$@" --allowed-host "$host"
        done
        set +f
        if [ -n "$ACME_CONTACT" ]; then
            set -- "$@" --acme-contact "$ACME_CONTACT"
        fi
        if [ "$ACME_STAGING" -eq 1 ]; then
            set -- "$@" --acme-staging
        fi
        "$BIN_PATH" init "$@"
        chown root:kunato "$CONFIG_PATH"
        chmod 0640 "$CONFIG_PATH"
    fi

    if [ ! -f "$RULES_FILE" ]; then
        log "downloading the managed rule set"
        if "$BIN_PATH" update-rules --config "$CONFIG_PATH"; then
            :
        elif [ "$ALLOW_EMPTY_RULES" -eq 1 ]; then
            log "warning: initial rules download failed; starting with an empty rule set per --allow-empty-rules"
            printf 'categories: []\n' >"$RULES_FILE"
        else
            die "the initial rules download failed; fix the network or --rules-url and re-run the installer (kunato update-rules --config $CONFIG_PATH retries it; --allow-empty-rules starts without rules anyway)"
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

    log "enabling kunato and (re)starting the service"
    systemctl enable kunato
    # restart also starts a stopped service; it always picks up the binary
    # installed above, which a running process would otherwise keep serving
    # from the deleted inode until the next manual restart.
    systemctl restart kunato || true
    sleep 1
    if systemctl is-active --quiet kunato; then
        log "kunato $VERSION is running; metrics: curl http://127.0.0.1:9090/metrics"
    else
        stop_service_if_present
        die "kunato failed to start; inspect the logs with: journalctl -u kunato -e"
    fi
}

main
