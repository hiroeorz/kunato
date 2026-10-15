# Kunato

[![CI](https://github.com/hiroeorz/kunato/actions/workflows/ci.yml/badge.svg)](https://github.com/hiroeorz/kunato/actions/workflows/ci.yml)

Kunato is a lightweight Web Application Firewall (WAF) written in Rust, built for
personal users who want an easy-to-deploy protection layer in front of their web
applications.

It runs as a reverse proxy between clients (browsers, apps) and your HTTP server,
inspects incoming requests against categorized, YAML-defined rules, and applies one
of three actions: **BLOCK**, **ALLOW**, or **LOG**.

> **Status:** Early development. The configuration format and public interfaces are
> not yet stable and may change without notice.

## Features

- **Reverse proxy** — Sits between browsers/apps and your HTTP server, forwarding
  traffic while inspecting every request.
- **HTTP/2, HTTP/3, and HTTP/1.1** — Accepts HTTP/2 over TLS (ALPN) and
  cleartext h2c (prior knowledge), plus optional HTTP/3 over QUIC, falling back
  to HTTP/1.1 automatically. Upstream requests are sent over HTTP/1.1.
- **WebSocket proxying** — Forwards HTTP/1.1 upgrade handshakes to the upstream
  and tunnels the connection both ways. The handshake passes through the rule
  engine and protection budgets; idle tunnels are closed automatically.
- **Categorized rule sets** — Rules are grouped into named categories (for example
  `sql-injection` or `xss`). Each category defines a default action, and individual
  rules can override it.
- **Daily CVE-driven rule updates** — An optional updater automatically refreshes
  the managed rule set once a day with signatures for the latest exploited CVEs,
  using conditional requests, SHA256 verification, and full validation before an
  atomic swap.
- **Response header rewriting** — Removes or replaces identifying response headers
  such as `Server` and `X-Powered-By` on upstream responses and Kunato's own
  block/error responses alike.
- **Response inspection** — Response-phase categories match upstream responses on
  status, headers, and body (up to a size limit) and can block, log, or pass them
  through. The remainder of oversized responses is streamed uninspected.
- **Encoded body inspection** — Bodies compressed with gzip, deflate, or brotli are
  decompressed for matching, and request bodies are additionally decoded by content
  type (`application/x-www-form-urlencoded` and JSON escapes). Forwarded traffic is
  never modified.
- **YAML rules with hot reload** — Rules are written in YAML. Changes to the rule
  file are detected at runtime and reloaded on the fly without restarting the
  process or dropping connections.
- **High fault tolerance** — Keeps serving with the last known good configuration,
  isolates failures, and avoids disrupting traffic during reloads.
- **Guided install** — One `curl | sudo sh` command installs the static binary,
  the systemd service, the configuration, and the initial rule set on a Linux
  server.
- **DoS / DDoS detection and mitigation** — Detects abnormal request patterns and
  automatically throttles or blocks abusive sources.
- **Simple deployment** — One binary and one YAML configuration file. No database,
  no external services, no complex setup.
- **Rust implementation** — Memory safety and predictable performance in a single
  static binary with no runtime dependencies.

## How It Works

```
                 inspect & apply rules
Client ──────►  ┌───────────────────┐  ──────►  Upstream HTTP server
(browser/app)   │  Kunato (WAF)     │
                │  reverse proxy    │  ◄──────  (response)
                └───────────────────┘
```

1. A request arrives at Kunato.
2. Categories are evaluated in the order they appear in the configuration, and
   rules within each category in their order.
3. The first rule whose conditions all match is handled according to its effective
   action:
   - `ALLOW` — forwards the request and stops evaluation.
   - `BLOCK` — rejects the request immediately (default: `403 Forbidden`).
   - `LOG` — records the match and continues evaluation.
4. If no rule matches, the request is forwarded to the upstream (pass-through).
5. Response-phase categories run on the upstream response the same way. `BLOCK`
   replaces the upstream response with the configured response; `ALLOW` stops
   response evaluation and passes the response through unchanged.

## Getting Started

Kunato ships as a single static binary for Linux. On a server with systemd, one
command installs the binary, the service, the configuration, and the initial rule
set:

```sh
curl -fsSL https://raw.githubusercontent.com/hiroeorz/kunato/main/scripts/install.sh | sudo sh
```

The installer asks for the upstream URL (default `http://127.0.0.1:3000`;
press Enter to accept) and, when listening on `:443`, for a certificate and key.
Pass every answer as a flag together with `--yes` for unattended installs:

```sh
curl -fsSL https://raw.githubusercontent.com/hiroeorz/kunato/main/scripts/install.sh \
  | sudo sh -s -- \
      --upstream http://127.0.0.1:3000 \
      --tls-cert /etc/letsencrypt/live/example.com/fullchain.pem \
      --tls-key /etc/letsencrypt/live/example.com/privkey.pem \
      --yes
```

The service starts automatically. Confirm it is running, then edit
`/etc/kunato/kunato.yaml`; changes are applied without a restart:

```sh
systemctl status kunato
sudo journalctl -u kunato -e
curl -s http://127.0.0.1:9090/metrics | head
sudo kunato validate
```

Rerunning the installer upgrades the binary and unit while keeping the
configuration, and `--uninstall` removes them. See
[Managed Rules and Automatic Updates](#managed-rules-and-automatic-updates) for
what is refreshed after installation, and [Deployment](#deployment) for installer
details and building from source.

## Managed Rules and Automatic Updates

The installer enables `rules_update`, so the rule set stays current without
manual work. Every `interval` (default `24h`, randomized by `jitter_percent`,
default 10%) Kunato:

1. sends a conditional request (`If-None-Match` / `If-Modified-Since`) and stops
   immediately on `304 Not Modified`;
2. downloads the rule file and verifies its SHA256 digest against `checksum_url`;
3. parses and fully validates it — regex compilation, ReDoS guards, action
   resolution, size limits — before replacing anything;
4. swaps the file in atomically, and the configuration watcher hot-reloads it.

Any failure (network, checksum mismatch, invalid rules, size limit) leaves the
current rules active; failures are logged and counted in the
`kunato_rules_update_*` metrics. `kunato update-rules` performs a single check
and exits, and is what the installer uses for the first download. The full field
reference lives in
[Rule sources and updates](#rule-sources-and-updates).

Local changes are never overwritten: exemptions and rule disables belong in
`overrides_file` (`/etc/kunato/overrides.yaml` when configured), which is
evaluated before the managed set. The updater writes exactly one file — the
managed rules file — and nothing else.

### Installed files and directories

```text
/
├── usr/
│   └── local/
│       └── bin/
│           └── kunato                         # binary (0755 root:root)
├── etc/
│   ├── systemd/
│   │   └── system/
│   │       ├── kunato.service                 # unit (0644)
│   │       └── multi-user.target.wants/
│   │           └── kunato.service -> ../kunato.service
│   └── kunato/                                # settings (0750 root:kunato)
│       ├── kunato.yaml                        # main configuration (0640 root:kunato)
│       ├── overrides.yaml                     # only when configured (0640 root:kunato)
│       └── tls/                               # only with --tls-cert/--tls-key (0750 root:kunato)
│           ├── cert.pem                       # (0640 root:kunato)
│           └── key.pem                        # (0640 root:kunato)
└── var/
    └── lib/
        └── kunato/                            # StateDirectory (0750 kunato:kunato)
            ├── rules.yaml                     # managed rule set (auto-updated)
            └── rules.yaml.update-state        # updater bookkeeping (auto-updated)
```

Auto-updated: `/var/lib/kunato/rules.yaml` and its `rules.yaml.update-state`
sidecar (last success timestamp, HTTP validators). Never touched by the updater:
everything under `/etc/kunato/`. The service runs as the `kunato` user (created
by the installer, no home directory) and only needs write access to
`/var/lib/kunato/`.

## Trying It Locally

Running from source requires Rust 1.89 or later (edition 2024). The repository
includes a small example upstream that logs every request to stdout:

```sh
cargo run --example upstream -- --listen 127.0.0.1:3000
cargo run -- --config rules.example.yaml
```

Open `http://127.0.0.1:8080/` in a browser or use `curl -v`. The response reports
the method, target, headers, and body as seen by the upstream, including the
`X-Forwarded-*` headers Kunato adds. The bundled example configuration trusts
`127.0.0.1`, so remove `127.0.0.1/32` from `trusted-sources` to exercise the block
rules locally.

## Black-Box Testing

Run the whole test with one command: it builds the binaries, starts the example
upstream and Kunato with a test configuration that does not trust the client,
replays both request lists, and prints a colored report with allow/block
pass and fail counts plus per-phase latency (min/avg/max):

```sh
./scripts/blackbox-test.sh
```

The report exits non-zero when an allowed request is not forwarded, a blocked
request reaches the upstream, or the upstream access count does not match.
`--skip-build`, `--parallelism N`, `--color auto|always|never`, and
`--workdir DIR` adjust the run; the log and test-config paths are printed at
the end.

`blackbox/` itself is a dependency-free driver that replays request lists in
parallel and prints the response status of each request:

```sh
cargo run --release --manifest-path blackbox/Cargo.toml -- \
  --blocked blackbox/requests/blocked.txt \
  --allowed blackbox/requests/allowed.txt \
  --addr 127.0.0.1:8080 \
  --parallelism 5
```

The request-list format supports HTTP/2 cleartext probes with `proto=h2c`,
including HPACK compression bombs (`hpack_bomb=N`) and oversized header blocks
(`pad_header=N`); see `--help` and the header of `blocked.txt`.

`--parallelism` defaults to 5. The two lists are split by expectation; correctness
is judged from the logs: the upstream access log should contain only the allowed
requests, and the Kunato log should show the blocked requests as blocked. Run it
against a configuration that does not trust the test client, otherwise
`trusted-sources` forwards everything. If the configuration has strict protection
limits, start Kunato with `--disable-protection` so rate limits and bans do not
interfere with the driver.

`blocked.txt` doubles as a CVE regression corpus. CVE coverage targets
vulnerabilities with a CVSS base score of 7.0 or higher, and only attacks that
can be expressed as an HTTP request are listed. Classes that need TLS-internal
state, raw connection framing, or a malicious upstream are recorded as comments
at the end of the list instead.

## Deployment

The installer used in [Getting Started](#getting-started) downloads the release
for your architecture, verifies its SHA256 checksum, installs the binary to
`/usr/local/bin/kunato` and the systemd unit, writes `/etc/kunato/kunato.yaml`,
fetches the managed rule set, validates the configuration, and enables the
service. Key options:

| Option                    | Description                                                              |
| ------------------------- | ------------------------------------------------------------------------ |
| `--version TAG`           | Install a specific release (default: the latest).                        |
| `--upstream URL`          | Upstream server the WAF forwards to; required on first install.          |
| `--listen ADDR`           | Listen address (default `0.0.0.0:443`).                                   |
| `--tls-cert`/`--tls-key`  | PEM certificate chain and key; copied to `/etc/kunato/tls/`.             |
| `--rules-url URL`         | Managed rule set URL (see Managed Rules and Automatic Updates).          |
| `--no-start`              | Install and validate without enabling or starting the service.            |
| `--yes`                   | Never prompt; fail instead of asking.                                    |
| `--uninstall`             | Stop and remove the service and binary.                                  |
| `--purge`                 | With `--uninstall`, also remove `/etc/kunato` and `/var/lib/kunato`.      |

TLS material passed with `--tls-cert`/`--tls-key` is copied to `/etc/kunato/tls/`
so the service user can read it. Re-copy it and restart the service when the
certificate is renewed; as a certbot deploy hook
(`/etc/letsencrypt/renewal-hooks/deploy/kunato`):

```sh
#!/bin/sh
install -m 0640 -o root -g kunato /etc/letsencrypt/live/example.com/fullchain.pem /etc/kunato/tls/cert.pem
install -m 0640 -o root -g kunato /etc/letsencrypt/live/example.com/privkey.pem /etc/kunato/tls/key.pem
systemctl restart kunato
```

Running the installer again upgrades the binary and unit while keeping the
existing configuration.

Without network access, or to build a custom binary, build from source (Rust
1.89 or later, edition 2024):

```sh
sudo apt-get install musl-tools   # Debian/Ubuntu; provides musl-gcc
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

Install the binary to `/usr/local/bin/kunato`, generate a configuration with
`kunato init --upstream <url> --tls-cert <pem> --tls-key <pem> --output
/etc/kunato/kunato.yaml`, download the first rules file with `kunato
update-rules`, and enable `packaging/kunato.service`. `rules.example.yaml` is a
practical starting point with rules for SQL/NoSQL injection, XSS, path traversal,
command injection, SSRF, XXE, malicious uploads, scanners, sensitive files, and
more. Tagging a release
(`v*`) builds and uploads static musl tarballs, checksums, and the installer
through GitHub Actions.

## Configuration

Kunato is configured through a single YAML file. The file defines where Kunato
listens, which upstream server it forwards to, and a list of rule **categories**.
All commands read `/etc/kunato/kunato.yaml` by default; pass `--config PATH` to
use a different file (for example `rules.example.yaml` when running from source):

- `listen` — address and port to bind.
- `upstream` — base URL of the upstream HTTP server.
- `categories` — ordered list of rule categories.
- `rules_file` — optional categories-only file refreshed by the daily rules updater.
- `overrides_file` — optional categories-only file with local exceptions,
  evaluated before every other rule source.
- `rules_update` — daily refresh of `rules_file` (see Managed rules and updates).

Each category groups related rules (for example SQL injection or XSS signatures)
and defines a default action that its rules inherit. Individual rules can override
the category defaults.

Rules are written in a compact form: `name` on one line, followed by a flow-style
`match` mapping on the next. Rules that override category defaults add one line per
extra field (`action`, `enabled`, `description`, `response`), and larger match
mappings can fall back to block style. Both forms are plain YAML and can be mixed.

### Example

```yaml
listen: 0.0.0.0:8080
upstream: http://127.0.0.1:3000

categories:
  # Trusted clients: matching rules forward the request immediately and skip
  # all remaining categories.
  - name: trusted-sources
    action: ALLOW
    rules:
      - name: internal-networks
        match: { source_ip: [10.0.0.0/8, 192.168.0.0/16] }
      - name: uptime-monitor
        match: { source_ip: 203.0.113.10, path: ^/health$ }

  # SQL injection: the category default blocks matching requests.
  - name: sql-injection
    action: BLOCK
    response: { status: 403, body: Forbidden }
    rules:
      - name: union-select
        match: { regex: '(?i)\bunion\b.{0,40}\bselect\b', in: [query, body] }
      - name: comment-obfuscation
        match: { regex: '(?i)(/\*!|--\s|#\s)', in: [query, body] }
      - name: tuning-heuristics         # disabled while false positives are investigated
        enabled: false
        match: { regex: '(?i)\bor\s+1\s*=\s*1\b', in: [query, body] }
      - name: detection-only            # logs instead of blocking while tuning
        action: LOG
        match: { regex: '(?i)(sleep\s*\(|benchmark\s*\()', in: [query, body] }

  # Cross-site scripting: also blocks by default.
  - name: xss
    action: BLOCK
    rules:
      - name: script-tags
        match: { regex: '(?i)<\s*script\b', in: [query, body, headers] }
      - name: event-handlers
        match: { regex: '(?i)\bon(error|load|click|mouseover)\s*=', in: [query, body] }
      - name: javascript-uri
        match: { regex: '(?i)javascript\s*:', in: [query, body] }

  # Path traversal: blocks by default. Larger match mappings may use block style.
  - name: path-traversal
    action: BLOCK
    rules:
      - name: dot-dot-slash
        match:
          regex: ['\.\./', '(?i)%2e%2e%2f', '(?i)%2e%2e/']
          in: [path, query, body]
      - name: encoded-backslash
        match: { regex: '(?i)(%5c|\.\.\\)', in: [path] }

  # Scanners and sensitive endpoints: logged by default, but individual rules
  # override the category action and block.
  - name: scanners
    action: LOG
    rules:
      - name: scanner-user-agents
        match:
          headers:
            User-Agent: ['(?i)sqlmap', '(?i)nikto', '(?i)(nmap|masscan|zgrab)']
      - name: sensitive-files            # overrides the category default
        action: BLOCK
        match: { path: '(?i)(^|/)(\.env|\.git/|wp-admin|phpmyadmin)' }

  # Response inspection: runs on the upstream response after it arrives. The
  # default `in` target in a response category is `response_body`.
  - name: response-leaks
    phase: response
    action: LOG
    rules:
      - name: private-key-material
        action: BLOCK
        match: { regex: '-----BEGIN [A-Z ]*PRIVATE KEY-----' }
      - name: versioned-server
        match: { response_headers: { Server: '(?i)(apache|nginx)/[0-9]' } }
      - name: upstream-error
        match: { status: 5xx }
```

### Evaluation

1. Request-phase categories (`phase: request`, the default) are evaluated in the
   order they appear in the file, and rules within a category in their order. A
   category with `enabled: false` is skipped entirely.
2. The first rule whose conditions all match wins. Its effective action and
   response are resolved with rule-level values taking precedence over
   category-level defaults.
3. The effective action is applied:
   - `ALLOW` — forwards the request and stops evaluation.
   - `BLOCK` — rejects the request with the effective response (default:
     `403 Forbidden`) and stops evaluation.
   - `LOG` — records the match and continues evaluation.
4. If no rule matches, the request is forwarded (pass-through).
5. After the upstream responds, response-phase categories (`phase: response`) run
   in document order. They match the upstream response plus the request context;
   `BLOCK` replaces the response with the effective response, `ALLOW` stops
   response evaluation and passes the response through unchanged, and `LOG`
   records the match and continues.

Every rule must resolve to an effective action: a rule without its own `action`
requires the category to define one. The configuration is rejected at load time
otherwise.

### Rule sources and updates

Rules can come from three places. Sources are concatenated in this order, and
evaluation starts with the first source, so earlier sources win:

1. `overrides_file` — a categories-only YAML document for local exceptions and
   tuning.
2. categories written directly in the configuration file.
3. `rules_file` — the managed rule set refreshed by `rules_update`.

```yaml
rules_file: /var/lib/kunato/rules.yaml
overrides_file: /etc/kunato/overrides.yaml
```

```yaml
# /etc/kunato/overrides.yaml
disabled_rules: [union-select]      # drop these rule names from every other source

categories:
  # Fix a false positive before the managed rules run: ALLOW wins over later BLOCKs.
  - name: local-exceptions
    action: ALLOW
    rules:
      - name: admin-search
        match: { path: ^/admin/search$, source_ip: 192.168.0.0/16 }
```

The external files are categories-only: `categories`, plus `disabled_rules` in
the overrides file (listing it in `rules_file` is rejected, so a downloaded file
can never weaken local overrides). Relative paths are resolved against the
directory of the configuration file. Missing files fail validation; a running
instance keeps its last known good rules if a reload fails.

`rules_update` keeps `rules_file` fresh without manual downloads:

```yaml
rules_update:
  enabled: true
  url: https://raw.githubusercontent.com/hiroeorz/kunato/main/dist/rules.yaml
  checksum_url: https://raw.githubusercontent.com/hiroeorz/kunato/main/dist/rules.yaml.sha256
  interval: 24h        # default
  jitter_percent: 10   # randomize the next check by ±10% (default 10, max 50)
  max_bytes: 1048576   # download size limit (default 1 MiB)
```

The URL must use https; plain http is accepted only for loopback hosts, which is
handy for tests and local mirrors. Every `interval` the updater sends a
conditional request (`If-None-Match`/`If-Modified-Since`), downloads any new
file, verifies its SHA256 digest against `checksum_url`, validates it with the
full rule compiler (regex and ReDoS guards included), replaces the file
atomically, and lets the hot reload path apply it. Any failure — network,
checksum mismatch, invalid rules, size limit — leaves the current rules
untouched and is reported in the logs and metrics. The updater state (last
success, HTTP validators) is stored next to the rules file.
`kunato update-rules` performs a single check and exits; the installer uses it
for the first download.

The SHA256 digest guards against corrupted or truncated downloads; it is
fetched over the same TLS connection as the rules file, so it does not add
authenticity. Detached signatures (minisign) are planned as a hardening step.

### Category fields

| Field         | Description                                                                                          |
| ------------- | ---------------------------------------------------------------------------------------------------- |
| `name`        | Unique category name.                                                                                |
| `description` | Optional free-text description.                                                                      |
| `enabled`     | Set to `false` to skip the category. Defaults to `true`.                                             |
| `phase`       | `request` (default) or `response`; selects when the category is evaluated.                            |
| `action`      | Default action (`BLOCK`, `ALLOW`, or `LOG`) for the category's rules.                                |
| `response`    | Default response for `BLOCK` rules. Defaults to `403 Forbidden`.                                      |
| `rules`       | Ordered list of rules.                                                                               |

### Rule fields

| Field         | Description                                                     |
| ------------- | --------------------------------------------------------------- |
| `name`        | Rule name, unique within the category.                          |
| `description` | Optional free-text description.                                 |
| `enabled`     | Set to `false` to skip the rule. Defaults to `true`.            |
| `action`      | Overrides the category default action.                          |
| `match`       | Conditions that must all hold for the rule to apply (required). |
| `response`    | Overrides the category response for `BLOCK` rules.              |
| `limit`       | Request-phase per-source rate limit, `{ requests: N, window: 60s }`. |

A rule with `limit` is a burst guard: the first `requests` matching requests per
`window` from one source pass through as if the rule had not matched, and later
matches take the rule's effective action (which cannot be `ALLOW`). Sources are
tracked like the automatic per-IP limits (IPv6 aggregated by
`protection.aggregate_ipv6_prefix`), allowlisted sources and
`--disable-protection` are exempt, and the state is bounded by
`protection.max_tracked_ips`.

### Match fields

Match conditions are combined with logical AND; a list value means OR within that
field. At least one condition must be specified. Regular expressions are compiled
once at load time, and an invalid pattern rejects the configuration. Path and query
values are matched raw and through up to two percent-decode passes, so
`%253Cscript%253E`, `%3Cscript%3E`, and `<script>` all match. Bodies are matched raw
and decoded by `Content-Type` (`application/x-www-form-urlencoded`, JSON string
escapes such as `\u0075`, and `multipart/form-data` flattened to field values and
file names), then through the same percent-decode passes, and are decompressed
first when `Content-Encoding` is `gzip`, `deflate`, or `br`. Multipart parsing is
bounded to 64 parts with 1 KiB names and file names; malformed multipart bodies
are inspected raw only. No other normalization (Unicode folding, HTML entity
decoding) is performed.

| Field              | Description                                                                                                             |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------- |
| `path`             | Regex(es) matched against the request path.                                                                             |
| `method`           | One or more HTTP methods (for example `GET` or `[POST, PUT]`).                                                          |
| `source_ip`        | IP address(es) or CIDR range(s) the client must come from.                                                              |
| `headers`          | Map of request header name to regex(es); header names are case-insensitive.                                             |
| `cookies`          | Map of cookie name to regex(es).                                                                                        |
| `in`               | Parts searched by `regex`: `query`, `body`, `cookies`, `headers`, `path`, or `response_body`. Defaults to `[query, body, cookies]`, or `[response_body]` in a response-phase category. |
| `regex`            | Signature regex(es) searched in the parts listed by `in`.                                                               |
| `status`           | Response-phase only: status code(s) or ranges, for example `404`, `500-599`, or `5xx`.                                  |
| `response_headers` | Response-phase only: map of response header name to regex(es); header names are case-insensitive.                       |

Response-phase rules may combine request conditions (`path`, `method`, `source_ip`,
`headers`, `cookies`, and `in` targets) with the response-specific ones, so a rule
can require a path and a response body signature. `status`, `response_headers`, and
the `response_body` target are rejected in request-phase categories. Response
bodies with `Content-Encoding: gzip`, `deflate`, or `br` are decompressed for
matching, and only the first `limits.max_response_body_bytes` are inspected (the
decoded output is bounded by the same limit). Stacked or unknown encodings are
inspected as received. Decoding is inspection-only: the bytes forwarded to the
upstream and to the client are never modified.

### Timeouts and limits

Durations accept `ms`, `s`, `m`, and `h` suffixes (plain numbers are seconds).
Defaults:

| Timeout             | Default | Limit                     | Default |
| ------------------- | ------- | ------------------------- | ------- |
| `header_read`       | `10s`   | `max_path_bytes`          | 8 KiB   |
| `body_read`         | `30s`   | `max_header_bytes`        | 32 KiB  |
| `upstream_connect`  | `5s`    | `max_headers`             | 100     |
| `upstream_response` | `30s`   | `max_body_bytes`          | 1 MiB   |
| `shutdown_grace`    | `10s`   | `max_response_body_bytes` | 1 MiB   |
| `websocket_idle`    | `10m`   |                           |         |

```yaml
timeouts: { header_read: 10s, body_read: 30s }
limits: { max_body_bytes: 1048576 }
```

Bodies decoded for inspection (see Match fields) are bounded by `max_body_bytes`
for requests and `max_response_body_bytes` for responses, so decompression bombs
cannot exceed the configured buffer sizes.

### Response headers

`response_headers` rewrites the headers of every response Kunato sends — upstream
responses and its own block/error responses alike — after hop-by-hop headers are
filtered. Removing identifying headers is the recommended default; replacing them
with a fixed, version-less value is the alternative:

```yaml
response_headers:
  remove: [server, x-powered-by, via]
  # set:
  #   server: webserver
```

Header names are case-insensitive, `remove` runs before `set`, and a name listed in
both is replaced rather than deleted. Hop-by-hop headers, `content-length`, and
`alt-svc` are managed by the proxy and rejected in the policy. A value in `set`
must be non-empty; use `remove` to drop a header.

### Admin and metrics

An optional admin listener exposes Prometheus metrics on a loopback address:

```yaml
admin:
  enabled: true
  listen: 127.0.0.1:9090
```

`GET /metrics` returns the text exposition format. Counters cover total requests,
BLOCK rule hits, LOG matches, rate-limit and ban decisions, global load shedding,
upstream failures, configuration reloads, and rules update outcomes; gauges cover
active connections, uptime, and the time of the last successful rules update.
Non-loopback addresses are rejected at validation time, and if the port is
already in use Kunato logs a warning and continues without the admin endpoint.

### TLS

Set a certificate and private key (PEM) to terminate HTTPS directly:

```yaml
tls:
  cert_file: /etc/kunato/cert.pem
  key_file: /etc/kunato/key.pem
```

Without this block Kunato serves plain HTTP. When TLS is enabled, forwarded
requests carry `X-Forwarded-Proto: https`. TLS settings are applied at startup;
changing them requires a restart (the running instance keeps the active
certificate and key). Invalid or unreadable files fail startup.

With TLS, Kunato negotiates the protocol through ALPN and prefers `h2`;
cleartext clients may use h2c prior knowledge. HTTP/1.1 clients are always
accepted, and requests are forwarded to the upstream over HTTP/1.1. Automatic
certificate rotation is not supported yet.

### HTTP/3

HTTP/3 over QUIC is opt-in and requires a `tls` block:

```yaml
http3:
  enabled: true
  listen: 127.0.0.1:8443   # optional; defaults to `listen`
```

When enabled, Kunato binds a UDP socket and terminates HTTP/3 with the same
certificate and key. The UDP address defaults to the TCP `listen` address, so
under normal deployments both share one port. TCP responses then carry an
`Alt-Svc: h3=":<port>"; ma=86400` header so clients can discover HTTP/3.

HTTP/3 requests pass through the same protection, limits, and rule evaluation
as TCP requests. Settings are applied at startup (like TLS); changing or
disabling them requires a restart. If the UDP socket cannot be bound, Kunato
logs a warning and keeps serving over TCP.

### WebSocket

Kunato forwards HTTP/1.1 WebSocket handshakes (`Upgrade: websocket`) to the
upstream. The handshake request is evaluated by the same protection budgets and
rules as any other request, and is blocked like one; when the upstream answers
`101 Switching Protocols`, Kunato opens a bidirectional tunnel between client
and upstream.

The tunnel itself is opaque: payload bytes are not inspected and
`max_body_bytes` does not apply. Tunnels with no traffic in either direction
are closed after `timeouts.websocket_idle` (default `10m`), and all tunnels are
closed on shutdown. WebSocket over HTTP/2 or HTTP/3 (extended CONNECT) is not
supported yet.

### Hot reload

Kunato watches the configuration file plus the configured `rules_file` and
`overrides_file` for changes. When any of them is updated:

- The new configuration is parsed and validated **before** it is applied.
- A valid configuration is swapped in atomically; in-flight requests are unaffected.
- An invalid configuration is rejected and the last known good rules remain active,
  with the error reported in the logs.

## DoS / DDoS Protection

Kunato monitors connection and request rates to detect abusive traffic. When a
source exceeds the configured thresholds, it is automatically throttled and, after
repeated violations, temporarily banned. Detection and mitigation run without
manual intervention and are independent of the YAML rule set.

```yaml
protection:
  enabled: true
  allowlist: [10.0.0.0/8, 192.168.0.0/16]
  max_connections_per_ip: 32
  max_connections: 1024
  requests_per_second: 20
  burst: 60
  global_requests_per_second: 2000
  max_tracked_ips: 100000
  aggregate_ipv6_prefix: 64
  ban:
    violations: 5
    window: 10s
    duration: 60s
    max_duration: 1h
```

The per-IP limiter uses a token bucket (`requests_per_second` refill rate, `burst`
capacity). Exceeding it returns `429 Too Many Requests` with a `Retry-After`
header; exceeding the global rate or connection budget returns `503 Service
Unavailable`. Repeated violations trigger a ban that doubles on each recurrence up
to `max_duration`. Addresses in `allowlist` bypass all protection limits.

IPv6 clients are tracked by the `aggregate_ipv6_prefix` prefix (default 64) rather
than by full address, so rotating within a prefix cannot bypass rate limits, bans,
or per-IP connection budgets. Set it to 128 to track each address separately;
IPv4-mapped addresses (`::ffff:a.b.c.d`) are always treated as IPv4.

Protection can be turned off entirely with `protection.enabled: false`, or at
runtime with `--disable-protection`. The flag also survives configuration reloads,
so it is a convenient way to run load or black-box tests without rate limits and
bans interfering.

## Fault Tolerance

- Invalid rule reloads never take down a running instance.
- A failed rules update (network, checksum, validation) always keeps the current
  rule set active.
- Upstream failures and timeouts are handled gracefully.
- Request handling paths avoid panics and unbounded resource usage.
- Graceful shutdown drains in-flight connections.

## Roadmap

- [x] Project scaffolding
- [x] Reverse proxy core
- [x] Rule engine (`BLOCK` / `ALLOW` / `LOG`)
- [x] YAML loader and hot reload
- [x] DoS / DDoS detection and mitigation
- [x] Metrics endpoint and admin listener
- [x] Example configuration, systemd unit, and static musl builds
- [x] Optional TLS termination
- [x] HTTP/2 (ALPN over TLS, h2c prior knowledge)
- [x] HTTP/3 over QUIC (opt-in, Alt-Svc advertisement)
- [x] Response-phase rules (status, response headers, response body)
- [x] curl installer and managed rule set with daily updates
- [ ] Detached signatures (minisign) for rules updates

## Contributing

This is a personal project, but issues and pull requests are welcome. Please keep
all code, comments, and documentation in English. Before opening a pull request,
run `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, `cargo deny check`,
and `cargo test`.

## License

Kunato is provided "as is", without warranty of any kind, express or implied,
including but not limited to the warranties of merchantability, fitness for a
particular purpose, and non-infringement. In no event shall the authors or
copyright holders be liable for any claim, damages, or other liability, whether
in an action of contract, tort, or otherwise, arising from, out of, or in
connection with the software or the use or other dealings in the software. You
use it at your own risk, and you remain responsible for keeping your applications
updated and securely configured.

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
