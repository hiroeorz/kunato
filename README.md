# Kunato

Kunato is a lightweight Web Application Firewall (WAF) written in Rust, built for
personal users who want an easy-to-deploy protection layer in front of their web
applications.

It runs as a reverse proxy between clients (browsers, apps) and your HTTP server,
inspects incoming requests against a set of YAML-defined rules, and applies one of
three actions: **BLOCK**, **ALLOW**, or **LOG**.

> **Status:** Early development. The configuration format and public interfaces are
> not yet stable and may change without notice.

## Features

- **Reverse proxy** — Sits between browsers/apps and your HTTP server, forwarding
  traffic while inspecting every request.
- **Rule-based request handling** — Requests are evaluated against preconfigured
  `BLOCK`, `ALLOW`, and `LOG` rules, and handled according to the verdict.
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
2. Rules are evaluated in ascending order of `priority` (lower value first).
3. The first matching rule decides how the request is handled:
   - `ALLOW` — forward the request to the upstream and skip remaining rules.
   - `BLOCK` — reject the request immediately (default: `403 Forbidden`).
   - `LOG` — record the match and continue evaluating the remaining rules.
4. If no rule matches, the request is forwarded to the upstream (default pass-through).

## Getting Started

### Prerequisites

- Rust 1.85 or later (edition 2024)

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

## Configuration

Kunato is configured through a single YAML file. An example:

```yaml
listen: 0.0.0.0:8080
upstream: http://127.0.0.1:3000

rules:
  # Health checks are always allowed and skip further inspection.
  - name: allow-health-checks
    priority: 10
    action: ALLOW
    match:
      path_prefix: /health

  # Suspicious scanners are logged, then evaluation continues.
  - name: log-scanners
    priority: 50
    action: LOG
    match:
      header_regex:
        User-Agent: '(?i)(sqlmap|nikto|nmap)'

  # SQL injection attempts are blocked outright.
  - name: block-sql-injection
    priority: 100
    action: BLOCK
    match:
      path_regex: '(?i)^/api/.*'
      method: [POST, PUT, PATCH]
      body_regex: '(?i)(union\s+select|drop\s+table)'
    response:
      status: 403
      body: Forbidden
```

### Rule fields

| Field      | Description                                                        |
| ---------- | ------------------------------------------------------------------ |
| `name`     | Unique, human-readable rule name.                                  |
| `priority` | Evaluation order. Lower values are evaluated first.                |
| `action`   | One of `BLOCK`, `ALLOW`, or `LOG`.                                 |
| `match`    | Conditions the request must satisfy for the rule to apply.         |
| `response` | Optional custom response for `BLOCK` rules.                        |

### Hot reload

Kunato watches the rule file for changes. When the file is updated:

- The new configuration is parsed and validated **before** it is applied.
- A valid configuration is swapped in atomically; in-flight requests are unaffected.
- An invalid configuration is rejected and the last known good rules remain active,
  with the error reported in the logs.

## DoS / DDoS Protection

Kunato monitors request rates and connection patterns to detect abusive traffic.
When a source exceeds the configured thresholds, it is automatically throttled or
temporarily banned. Detection and mitigation run without manual intervention and
are independent of the YAML rule set.

## Fault Tolerance

- Invalid rule reloads never take down a running instance.
- Upstream failures and timeouts are handled gracefully.
- Request handling paths avoid panics and unbounded resource usage.
- Graceful shutdown drains in-flight connections.

## Roadmap

- [x] Project scaffolding
- [ ] Reverse proxy core
- [ ] Rule engine (`BLOCK` / `ALLOW` / `LOG`)
- [ ] YAML loader and hot reload
- [ ] DoS / DDoS detection and mitigation
- [ ] Metrics and structured logging
- [ ] Packaging and release binaries

## Contributing

This is a personal project, but issues and pull requests are welcome. Please keep
all code, comments, and documentation in English.

## License

License information will be added before the first public release.
