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
  allowed_hosts.rs # Host/authority allowlist enforced before rule evaluation
  client_ip.rs     # Bounded trusted-proxy client identity resolution
  cidr.rs          # IPv4/IPv6 CIDR parsing and matching
  metrics.rs       # Prometheus counters and gauges
  acme/            # RFC 8555 client, TLS-ALPN-01 resolver, and certificate cache
  graphql.rs       # Bounded GraphQL document analysis for the complexity limit
  form.rs          # Origin-facing multipart and URL-encoded resource limits
  php.rs           # Opt-in scoped PHP lifecycle and session-cookie mitigations
  upload.rs        # Bounded multipart upload declared-type/content inspection
  request_view.rs  # Borrowed request representation for the rule engine
  snapshot.rs      # Immutable config and runtime snapshots
  yaml/            # In-tree YAML parser and serde deserializer
  config/
    mod.rs         # YAML schema, loading, validation, compilation
    watcher.rs     # File watching and hot reload
  rules/           # Category/rule model, matcher, and evaluation engine
  logs/            # `kunato log`: journalctl reader, parsing, filters, attack classes
  proxy/           # Listener, upstream client, forwarding, TLS termination, HTTP/3, WebSocket
  protection/      # DoS / DDoS detection, rate limiting, bans, behavioral signals
blackbox/          # External black-box test driver (separate crate)
  requests/        # Request lists (blocked.txt / allowed.txt)
lab/               # Isolated WAF lab with fixtures, pinned tools, and sandbox protocol/slow/load suites
  cases/           # Replay, ffuf discovery, and deterministic mutation cases
  fixtures/        # DVWA bootstrap and the lab-only CVE fixture
  templates/       # Reviewed Nuclei adaptation and the authenticated ZAP plan template
  tool-runner-*.sh # Bounded wrappers for detached lab scanners
dist/
  rules.yaml       # Managed rule set for daily updates (generated; keep in sync)
  rules.yaml.sha256
examples/
  upstream.rs      # Manual test upstream with access logs
scripts/           # curl installer, dist-rules regeneration, NVD delta fetch, black-box and lab runners
tests/             # Integration tests (mock upstream, reload scenarios, rules update)
docs/
  DESIGN.md           # Overall design
  attack-coverage.md  # Attack-coverage tracker (covered / partial / gap per attack class)
  behavioral-detection.md # Behavioral bot and authentication-abuse detection
  behavioral-readiness.md # Deployment and authentication observation checklist
  cve-coverage.md     # Daily CVE intake tracker (one row per reviewed candidate)
  development.md      # Development, deployment, and the full configuration reference
  rule-updates.md     # Daily rule updates and binary version compatibility
  security-lab-testing-model.md # Lab control/evidence model, verdicts, and diagrams
  security-testing.md # Local attack-tool lab design and verification process
packaging/
  kunato.service   # systemd unit
rules.example.yaml # Example configuration
deny.toml          # Dependency, license, and advisory policy
```

See `docs/DESIGN.md` for the full architecture. Update this section as the layout
becomes real. Keep module responsibilities separated: configuration, rule
evaluation, proxying, and protection logic must not bleed into each other.

## Attack Coverage Tracking

`docs/attack-coverage.md` tracks which attack classes the bundled rules and
engine mechanisms cover, which are partial, and which are gaps, with the
evidence (rule category names, mechanisms) behind every verdict. Update it
whenever coverage changes:

- new, removed, or renamed categories or rules in `rules.example.yaml` (and the
  regenerated `dist/rules.yaml`),
- new or changed engine capabilities (match fields, decoding, protection,
  protocol limits, response handling),
- a gap closed with a local YAML rule pattern worth documenting,
- a verdict that the black-box suite contradicts.

Keep statuses honest: a bundled rule or built-in mechanism is `Covered`, a
CVE-specific signature or mitigation-only behavior is `Partial`, and absence of
any mechanism is `Gap`. Refresh the snapshot date and re-check the counts after
rule-set updates.

## Configuration Schema

- Configuration and rule files use a YAML subset: block/flow collections,
  plain/quoted/block scalars, comments, explicit `?` mapping keys, flow pairs,
  and multi-line flow/quoted scalars. Anchors, aliases, merge keys, explicit
  tags, directives, multiple documents, and complex mapping keys are rejected,
  as are tabs used for indentation or inside plain scalars and duplicate mapping
  keys. Tabs are allowed in quoted scalars and block scalar content. The
  in-tree parser and deserializer live in `src/yaml/`.
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
- `limits.max_body_bytes` defaults to 8 MiB. `limits.body_inspection: strict`
  (the default) evaluates the inspected prefix first: a matching ALLOW forwards
  the request, a matching BLOCK uses its response, and otherwise an over-limit
  body is rejected with `413` when body rules, a GraphQL endpoint, or upload
  inspection need it. `stream` inspects the prefix and forwards the rest, and
  logs a warning while body rules or upload inspection are enabled.
- `limits.upload_inspection` defaults to `mismatch`: multipart file parts are
  checked against their declared type (or safe filename extension) and rejected
  with `403` when executable, script, or markup content hides behind an image,
  PDF, office, media, or font claim. `strict` also covers generic binary claims;
  `off` disables the check. It runs before rule evaluation, so `ALLOW` does not
  bypass it.
- `limits.form` defaults to enabled: decoded multipart and URL-encoded bodies
  must be complete and pass field/part/header/name/nesting/complexity limits
  before ALLOW or forwarding. This also applies in body `stream` mode; explicitly
  disable the form guard to stream larger forms, accepting incomplete inspection.
  `php` is an opt-in, explicitly host/path-scoped profile that always applies
  form limits in scope, optionally rejects multipart or upload-progress fields,
  and validates only configured PHP session response cookies before body reads
  and response ALLOW. Neither mechanism replaces PHP security updates.
- `allowed_hosts` is an optional Host/authority allowlist. When set, a missing,
  malformed, duplicate, or unlisted Host (HTTP/1.1) or `:authority`
  (HTTP/2 / HTTP/3) is rejected with `400`/`421` before rule evaluation, and
  `ALLOW` rules cannot bypass it. A leading `*.` matches subdomains but not the
  apex; an entry without a port matches any port; IPv4 and bracketed IPv6
  literals are accepted. An empty list or null value is invalid; omit the field
  to disable the check. `kunato init` seeds `--acme-domain` values and accepts
  `--allowed-host`; the installer passes it through.
- `client_ip` optionally declares `trusted_proxies` (1..64 IPs/CIDRs) and an
  identity `header` (default `x-forwarded-for`). Only trusted direct peers may
  supply identity; their header is required, bounded to 4096 bytes/16 addresses,
  and invalid or entirely trusted chains get `400` before body reads and ALLOW.
  XFF is walked from right to left to the first untrusted address. Other
  supported headers (`x-real-ip`, `cf-connecting-ip`, `true-client-ip`) require
  one address. Resolved IPs key request limits, rules, behavioral signals, bans,
  and request allowlists; connection caps use the transport peer. Upstream XFF
  contains only the resolved IP. The policy remains active without protection.
- `content_routes` declares authoring endpoints (for example CMS article
  editors) whose request body is authored content rather than parameters. Body
  targets are skipped for matching requests; path, query, cookie, header,
  form/upload, GraphQL, DoS, and response checks remain active. The path must
  match every decoded and normalized form, methods default to all and use
  uppercase tokens (an empty list is rejected), and up to 64 entries are
  accepted. See `docs/development.md`, "Content routes"; the exemption is a
  local policy and must not be used for public parameter endpoints.
- `protection.behavior` enables per-source behavioral detection over upstream
  responses: enumeration (`404` ratio and distinct paths) and authentication
  failures (`401`/`403` on login/token/session/MFA/SSO paths), plus a global
  authentication-failure log for distributed attempts. Per-source signals
  default to `LOG` and accept `action: BLOCK`; the global signal is `LOG` only.
  It is disabled by `protection.enabled: false` and `--disable-protection`, and
  `protection.allowlist` (not an `ALLOW` rule) exempts a source. See
  `docs/behavioral-detection.md`.
- `tls.acme` enables automatic certificates through ACME with TLS-ALPN-01
  challenges; it replaces `tls.cert_file`/`tls.key_file`, is validated at load
  time (no wildcards, no IPs), and is applied at startup like the rest of the
  `tls` block. Issued material is cached under `tls.acme.cache_dir` (default
  `/var/lib/kunato/acme`, mode 0600 files in a 0700 directory).
- Evaluation order is document order; `enabled: false` disables a category or rule.
- Write rules in the compact style shown in `docs/development.md`: `name` on one
  line and a flow-style `match` mapping on the next, falling back to block style
  only for larger match mappings.
- `dist/rules.yaml` is the artifact every install with `rules_update` downloads
  every day, and `main` publishes the newest rule set to installs of every
  release. Rules in `rules.example.yaml` (and therefore in the generated
  `dist/rules.yaml`) must stay inside the rule-set format of the newest release:
  a new field, match target, action, or phase makes every installed release
  reject the whole candidate and freeze its updates, so it needs a release
  rather than a rule update. `scripts/check-rules-compat.sh` is the gate (it
  builds the newest tag and validates the published file with it); see
  `docs/rule-updates.md` for the mechanism and `docs/development.md`, "Rule set
  format compatibility", for the policy.
- `docs/development.md` is the source of truth for the full field reference. Keep
  it in sync with any schema change.

## Commands

```sh
cargo build                      # Debug build
cargo build --release            # Release build
cargo run -- --config rules.yaml # Run locally
cargo test                       # Run all tests
cargo fmt                        # Format code
cargo clippy --all-targets -- -D warnings  # Lint; warnings are errors
./scripts/check-deny.sh          # Dependency, license, advisory, and source audit (read-only-safe)
cargo fmt --manifest-path blackbox/Cargo.toml
cargo clippy --manifest-path blackbox/Cargo.toml --all-targets -- -D warnings
./scripts/blackbox-test.sh       # End-to-end black-box test with colored report
./scripts/security-lab.sh prepare             # Prepare pinned lab images and fixtures
./scripts/security-lab.sh run --sandbox-suite all  # Isolated WAF sandbox suites with evidence
./scripts/security-lab.sh run --sandbox-suite protocol  # Raw protocol and WebSocket cases
./scripts/security-lab.sh run --sandbox-suite slow     # Bounded slow-HTTP availability
./scripts/security-lab.sh run --sandbox-suite load     # k6 mixed load with recovery
./scripts/check-rules-compat.sh  # Published rules vs. the newest release binary
./scripts/release.sh X.Y.Z       # Cut a release: bump, commit, tag, and push
```

Before finishing any task, always run `cargo fmt`, `cargo clippy --all-targets -- -D warnings`,
`./scripts/check-deny.sh`, and `cargo test`, in that order. The wrapper runs
`cargo deny check` with a writable temporary advisory database, so it also works when
`$CARGO_HOME` is read-only; use it instead of invoking `cargo deny check` directly.
When touching `blackbox/`, run its `cargo fmt` and `cargo clippy` variants as well.
If a command is unavailable or fails for environmental reasons, report it instead of
ignoring it. The dependency policy lives in `deny.toml`; do not loosen it without an
explicit reason.

## Design Invariants

1. **Rule evaluation order:** Rules are grouped into categories and evaluated in
   document order — categories in the order they appear, then rules within each
   category. Categories have a `phase` (`request` by default, or `response`);
   the two phases are evaluated independently and in document order within each
   phase. A rule's `action` and `response` override the category defaults, and
   every rule must resolve to an effective action at load time (a `threshold`
   category instead scores matching rules and applies the category action once
   the threshold is reached). `ALLOW` stops
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
