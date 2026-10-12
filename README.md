# Kunato

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
- **Categorized rule sets** — Rules are grouped into named categories (for example
  `sql-injection` or `xss`). Each category defines a default action, and individual
  rules can override it.
- **YAML rules with hot reload** — Rules are written in YAML. Changes to the rule
  file are detected at runtime and reloaded on the fly without restarting the
  process or dropping connections.
- **High fault tolerance** — Keeps serving with the last known good configuration,
  isolates failures, and avoids disrupting traffic during reloads.
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

## Getting Started

### Prerequisites

- Rust 1.89 or later (edition 2024)

### Build

```sh
git clone <repository-url>
cd kunato
cargo build --release
```

The binary is produced at `target/release/kunato`.

### Run

```sh
./target/release/kunato --config rules.yaml
```

## Trying It Locally

The repository includes a small example upstream that logs every request to
stdout:

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

`blackbox/` is a dependency-free driver that replays request lists in parallel
and prints the response status of each request:

```sh
cargo run --release --manifest-path blackbox/Cargo.toml -- \
  --blocked blackbox/requests/blocked.txt \
  --allowed blackbox/requests/allowed.txt \
  --addr 127.0.0.1:8080 \
  --parallelism 5
```

`--parallelism` defaults to 5. The two lists are split by expectation; correctness
is judged from the logs: the upstream access log should contain only the allowed
requests, and the Kunato log should show the blocked requests as blocked. Run it
against a configuration that does not trust the test client, otherwise
`trusted-sources` forwards everything. If the configuration has strict protection
limits, start Kunato with `--disable-protection` so rate limits and bans do not
interfere with the driver.

## Deployment

Kunato ships as a single static binary:

```sh
sudo apt-get install musl-tools   # Debian/Ubuntu; provides musl-gcc
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

Install the binary to `/usr/local/bin/kunato` and the configuration to
`/etc/kunato/rules.yaml`, then use the provided systemd unit
(`packaging/kunato.service`). `rules.example.yaml` is a practical starting point
with rules for SQL/NoSQL injection, XSS, path traversal, command injection, SSRF,
XXE, malicious uploads, scanners, sensitive files, and more.
Tagging a release (`v*`) builds and uploads the static binary through GitHub
Actions.

## Configuration

Kunato is configured through a single YAML file. The file defines where Kunato
listens, which upstream server it forwards to, and a list of rule **categories**:

- `listen` — address and port to bind.
- `upstream` — base URL of the upstream HTTP server.
- `categories` — ordered list of rule categories.

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
```

### Evaluation

1. Categories are evaluated in the order they appear in the file, and rules within
   a category in their order. A category with `enabled: false` is skipped entirely.
2. The first rule whose conditions all match wins. Its effective action and
   response are resolved with rule-level values taking precedence over
   category-level defaults.
3. The effective action is applied:
   - `ALLOW` — forwards the request and stops evaluation.
   - `BLOCK` — rejects the request with the effective response (default:
     `403 Forbidden`) and stops evaluation.
   - `LOG` — records the match and continues evaluation.
4. If no rule matches, the request is forwarded (pass-through).

Every rule must resolve to an effective action: a rule without its own `action`
requires the category to define one. The configuration is rejected at load time
otherwise.

### Category fields

| Field         | Description                                                           |
| ------------- | --------------------------------------------------------------------- |
| `name`        | Unique category name.                                                 |
| `description` | Optional free-text description.                                       |
| `enabled`     | Set to `false` to skip the category. Defaults to `true`.              |
| `action`      | Default action (`BLOCK`, `ALLOW`, or `LOG`) for the category's rules. |
| `response`    | Default response for `BLOCK` rules. Defaults to `403 Forbidden`.      |
| `rules`       | Ordered list of rules.                                                |

### Rule fields

| Field         | Description                                                     |
| ------------- | --------------------------------------------------------------- |
| `name`        | Rule name, unique within the category.                          |
| `description` | Optional free-text description.                                 |
| `enabled`     | Set to `false` to skip the rule. Defaults to `true`.            |
| `action`      | Overrides the category default action.                          |
| `match`       | Conditions that must all hold for the rule to apply (required). |
| `response`    | Overrides the category response for `BLOCK` rules.              |

### Match fields

Match conditions are combined with logical AND; a list value means OR within that
field. At least one condition must be specified. Regular expressions are compiled
once at load time, and an invalid pattern rejects the configuration. Path and query
values are matched both raw and percent-decoded, so `%3Cscript%3E` and `<script>`
both match.

| Field       | Description                                                                                                             |
| ----------- | ----------------------------------------------------------------------------------------------------------------------- |
| `path`      | Regex(es) matched against the request path.                                                                             |
| `method`    | One or more HTTP methods (for example `GET` or `[POST, PUT]`).                                                          |
| `source_ip` | IP address(es) or CIDR range(s) the client must come from.                                                              |
| `headers`   | Map of header name to regex(es); header names are case-insensitive.                                                     |
| `cookies`   | Map of cookie name to regex(es).                                                                                        |
| `in`        | Request parts searched by `regex`: `query`, `body`, `cookies`, `headers`, or `path`. Defaults to `[query, body, cookies]`. |
| `regex`     | Signature regex(es) searched in the parts listed by `in`.                                                               |

### Timeouts and limits

Durations accept `ms`, `s`, `m`, and `h` suffixes (plain numbers are seconds).
Defaults:

| Timeout             | Default | Limit              | Default |
| ------------------- | ------- | ------------------ | ------- |
| `header_read`       | `10s`   | `max_path_bytes`   | 8 KiB   |
| `body_read`         | `30s`   | `max_header_bytes` | 32 KiB  |
| `upstream_connect`  | `5s`    | `max_headers`      | 100     |
| `upstream_response` | `30s`   | `max_body_bytes`   | 1 MiB   |
| `shutdown_grace`    | `10s`   |                    |         |

```yaml
timeouts: { header_read: 10s, body_read: 30s }
limits: { max_body_bytes: 1048576 }
```

### Admin and metrics

An optional admin listener exposes Prometheus metrics on a loopback address:

```yaml
admin:
  enabled: true
  listen: 127.0.0.1:9090
```

`GET /metrics` returns the text exposition format. Counters cover total requests,
BLOCK rule hits, LOG matches, rate-limit and ban decisions, global load shedding,
upstream failures, and configuration reloads; gauges cover active connections and
uptime. Non-loopback addresses are rejected at validation time, and if the port is
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
certificate and key). Invalid or unreadable files fail startup. HTTP/2 and
automatic certificate rotation are not supported yet.

### Hot reload

Kunato watches the rule file for changes. When the file is updated:

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

Protection can be turned off entirely with `protection.enabled: false`, or at
runtime with `--disable-protection`. The flag also survives configuration reloads,
so it is a convenient way to run load or black-box tests without rate limits and
bans interfering.

## Fault Tolerance

- Invalid rule reloads never take down a running instance.
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

## Contributing

This is a personal project, but issues and pull requests are welcome. Please keep
all code, comments, and documentation in English. Before opening a pull request,
run `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, `cargo deny check`,
and `cargo test`.

## License

License information will be added before the first public release.
