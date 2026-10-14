# AGENTS.md

Guidance for AI coding agents working in this repository.

## Language Policy

- **Chat:** Respond to the user in Japanese.
- **Repository artifacts:** Write everything in English — code, identifiers, comments,
  doc comments, commit messages, README, AGENTS.md, docs, skill definitions, and
  example configurations.

## Project Overview

Kunato is a personal-use Web Application Firewall (WAF) written in Rust. It operates
as a reverse proxy between clients and an upstream HTTP server, evaluates requests
against YAML-defined rules (`BLOCK`, `ALLOW`, `LOG`), supports hot reloading of rules,
is designed for high fault tolerance, and includes automatic DoS / DDoS detection
and mitigation. It targets easy personal deployment: one binary and one YAML
configuration file, with no external services required.

## Tech Stack

- Rust, edition 2024 (requires Rust 1.89+)
- Cargo for build, test, and dependency management
- YAML for configuration

Check `Cargo.toml` before using any crate. Do not add dependencies without
justification; prefer the standard library where practical.

## Repository Layout (planned)

```text
src/
  main.rs          # Entry point: startup, signal handling, graceful shutdown
  cli.rs           # Command-line argument parsing
  error.rs         # Error types
  telemetry.rs     # Logging setup
  admin.rs         # Loopback admin listener exposing /metrics
  metrics.rs       # Prometheus counters and gauges
  request_view.rs  # Borrowed request representation for the rule engine
  config/
    mod.rs         # YAML schema, loading, validation, compilation
    watcher.rs     # File watching and hot reload
  rules/           # Category/rule model, matcher, and evaluation engine
  proxy/           # Listener, upstream client, forwarding, TLS termination, HTTP/3, WebSocket
  protection/      # DoS / DDoS detection, rate limiting, bans
blackbox/          # External black-box test driver (separate crate)
  requests/        # Request lists (blocked.txt / allowed.txt)
dist/
  rules.yaml       # Managed rule set for daily updates (generated; keep in sync)
  rules.yaml.sha256
examples/
  upstream.rs      # Manual test upstream with access logs
scripts/           # curl installer, dist-rules regeneration, black-box test runner
tests/             # Integration tests (mock upstream, reload scenarios, rules update)
docs/
  DESIGN.md        # Overall design
packaging/
  kunato.service   # systemd unit
rules.example.yaml # Example configuration
deny.toml          # Dependency, license, and advisory policy
```

See `docs/DESIGN.md` for the full architecture. Update this section as the layout
becomes real. Keep module responsibilities separated: configuration, rule
evaluation, proxying, and protection logic must not bleed into each other.

## Configuration Schema

- The YAML config uses a two-level model: `categories` → `rules`. A category's
  `action` and `response` are defaults that individual rules may override.
- Rules can also come from `rules_file` (managed, refreshed by `rules_update`)
  and `overrides_file` (local exceptions plus `disabled_rules`). Evaluation order
  is overrides → inline categories → rules file; the external files are
  categories-only. Relative paths resolve against the config file's directory.
- Categories carry a `phase` (`request` by default, or `response`). Response-phase
  rules match upstream status, response headers, and the response body prefix
  (`limits.max_response_body_bytes`); `status`, `response_headers`, and the
  `response_body` target are rejected in request-phase categories.
- Evaluation order is document order; `enabled: false` disables a category or rule.
- Write rules in the compact style shown in `README.md`: `name` on one line and a
  flow-style `match` mapping on the next, falling back to block style only for
  larger match mappings.
- `README.md` is the source of truth for the full field reference. Keep it in sync
  with any schema change.

## Commands

```sh
cargo build                      # Debug build
cargo build --release            # Release build
cargo run -- --config rules.yaml # Run locally
cargo test                       # Run all tests
cargo fmt                        # Format code
cargo clippy --all-targets -- -D warnings  # Lint; warnings are errors
cargo deny check                 # Dependency, license, advisory, and source audit
cargo fmt --manifest-path blackbox/Cargo.toml
cargo clippy --manifest-path blackbox/Cargo.toml --all-targets -- -D warnings
./scripts/blackbox-test.sh       # End-to-end black-box test with colored report
```

Before finishing any task, always run `cargo fmt`, `cargo clippy --all-targets -- -D warnings`,
`cargo deny check`, and `cargo test`, in that order. When touching `blackbox/`, run
its `cargo fmt` and `cargo clippy` variants as well. If a command is unavailable or
fails for environmental reasons, report it instead of ignoring it. The dependency
policy lives in `deny.toml`; do not loosen it without an explicit reason.

## Design Invariants

1. **Rule evaluation order:** Rules are grouped into categories and evaluated in
   document order — categories in the order they appear, then rules within each
   category. Categories have a `phase` (`request` by default, or `response`);
   the two phases are evaluated independently and in document order within each
   phase. A rule's `action` and `response` override the category defaults, and
   every rule must resolve to an effective action at load time. `ALLOW` stops
   evaluation within its phase (`request`: forward; `response`: pass the upstream
   response through unchanged); `BLOCK` responds and stops; `LOG` records the
   match and continues evaluation. If no rule matches, the request or response
   is passed through. Match conditions are combined with logical AND, while list
   values are ORed within a field.
2. **Hot reload safety:** A new configuration must be parsed and validated before it
   replaces the active one. Apply it atomically. If it is invalid, keep the last
   known good configuration and log the error.
3. **Request path robustness:** Never panic while handling a request. Avoid
   `unwrap()` / `expect()` in request-handling paths. All client input is untrusted.
4. **Bounded resources:** Bound queues, buffers, and per-source state. Compile
   regexes once at load time and guard against pathological patterns (ReDoS).
5. **Fault tolerance first:** Upstream timeouts, malformed requests, and reload
   failures must degrade gracefully, never crash the process.
6. **DoS / DDoS mitigation is automatic:** Detection and throttling operate without
   manual intervention and stay independent of user-defined rules.
7. **Simple deployment:** Keep the deployment surface minimal — one binary and one
   configuration file. Do not require a database, external services, or runtime
   dependencies.

## Testing Guidelines

- Add unit tests alongside the modules they cover.
- Add integration tests using a mock upstream HTTP server.
- Required scenarios include: rule precedence, each action type, invalid
  configuration reload retaining previous rules, and rate-limit behavior.
- Keep tests deterministic; avoid network access to external hosts.
- CVE coverage in `blackbox/requests/`: only add requests for vulnerabilities
  with a CVSS base score of 7.0 or higher, and only when the attack is
  reproducible with an HTTP request.

## Commit Conventions

- Write commit messages in English, in the imperative mood (e.g. `Add YAML rule loader`).
- Only commit when the user explicitly asks.
- Do not commit secrets or credentials.

## Do Not

- Do not write comments, documentation, or identifiers in Japanese.
- Do not add unnecessary comments; prefer self-explanatory code.
- Do not introduce a dependency or framework without checking `Cargo.toml` first.
- Do not weaken the design invariants above for convenience.
