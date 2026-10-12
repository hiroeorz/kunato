# Kunato Design

Status: **Draft** — milestones M0 through M10 are implemented and covered by unit
and integration tests. TLS termination is provided through `rustls`; HTTP/2 is
served over TLS (ALPN) and cleartext (h2c prior knowledge), HTTP/3 is served
over QUIC when enabled, and HTTP/1.1 WebSocket upgrades are tunneled. Certificate
rotation remains future work.

Audience: contributors and AI coding agents. The YAML field reference lives in
`README.md`; this document covers the system as a whole.

## 1. Goals and Non-Goals

### Goals

- Personal-use WAF: one reverse proxy in front of one upstream HTTP server.
- Categorized YAML rules with `BLOCK`, `ALLOW`, and `LOG` actions, hot reloadable.
- Automatic DoS / DDoS detection and mitigation, independent of user rules.
- High fault tolerance: bad input, bad config, and upstream failures never crash
  the process; all resources are bounded.
- Simple deployment: one binary and one configuration file, no external services.

### Non-Goals (initial)

- Multi-tenant hosting, multiple upstreams, or load balancing.
- Response body inspection or rewriting.
- Layer 4 filtering or TLS interception (Kunato may terminate TLS, but does not
  decrypt intercepted traffic).
- Distributed state or clustering.
- Administrative GUI.

## 2. High-Level Architecture

```text
             ┌──────────────────────────── Kunato ─────────────────────────────┐
             │                                                                 │
 Client ────►│  acceptor ──► connection task ──► protection ──► rule engine    │────► upstream
             │                    │                  │              │          │
             │                    │            limit/ban state   compiled     │
             │                    │                                  config    │
             │                    │                                    ▲       │
             │                    └── body buffering                  │       │
             │                                                     │       │
             │  config watcher ──► parse ──► validate ──► compile ──┘       │
             └─────────────────────────────────────────────────────────────────┘
```

Components:

| Component    | Responsibility                                                        |
| ------------ | --------------------------------------------------------------------- |
| Acceptor     | TCP listener, connection budgets, hands sockets to hyper.             |
| Connection   | Per-connection task: HTTP parsing, timeouts, request lifecycle.       |
| Protection   | Connection/rate limits, bans, load shedding; bounded per-IP state.    |
| Rule engine  | Evaluates a request view against the compiled rule set.               |
| Proxy client | Forwards requests upstream and streams responses back.                |
| Config       | Loads, validates, and compiles YAML into an immutable snapshot.       |
| Watcher      | Detects config changes and drives the reload pipeline.                |

## 3. Runtime and Concurrency Model

- Async runtime: `tokio` multi-threaded, worker threads = CPU cores.
- One task per connection; hyper handles keep-alive on both sides. Downstream
  connections serve HTTP/1.1 or HTTP/2 (ALPN over TLS, h2c prior knowledge over
  cleartext) on the TCP listener, and optionally HTTP/3 over QUIC on a UDP
  socket bound when `http3.enabled` is set; upstream connections always use
  HTTP/1.1.
- HTTP/3 connections are accepted from a `quinn` endpoint; each QUIC connection
  is one task driving an `h3` server connection, and each request stream is a
  task. QUIC connections count against the same per-IP and global connection
  budgets as TCP connections.
- A successful HTTP/1.1 upgrade moves both sockets into a detached tunnel task;
  the upstream TCP connection is opened per tunnel and the connection guard is
  transferred from the HTTP connection task to the tunnel so budgets stay
  accurate. Tunnels are closed by an idle watchdog or by the shutdown signal.
- Active configuration: `ArcSwap<CompiledConfig>`. The request path performs one
  lock-free `load()`; reloads swap the whole immutable snapshot atomically.
- Protection state: sharded maps (`shards = num_cpus * 4`, rounded to a power of
  two), each a `Mutex<HashMap<IpAddr, Bucket>>`. Critical sections are tiny.
- Global counters (connections, RPS window): atomics, no locks.
- No unbounded channels or queues. Shutdown is coordinated with a `watch` channel.
- A periodic GC task (every 30 s) evicts stale per-IP state and expired bans.

## 4. Request Lifecycle

1. **Accept** — check per-IP connection count and global connection budget. Over
   budget: respond `503` (when an HTTP response is still possible) or close.
2. **Detect protocol and parse head** — cleartext connections are sniffed for the
   HTTP/2 preface within the header read timeout; TLS connections use the ALPN
   result; QUIC connections carry `h3` in ALPN. hyper (or `h3` for HTTP/3) then
   parses the request line and headers with a header read timeout, header
   size/count limits, and URL length limit. Malformed input: `400`.
3. **Protection** — ban check, per-IP token bucket, global RPS guard. Rate/ban
   violations produce `429` or `503` with `Retry-After`.
4. **Buffer body** — read up to `limits.max_body_bytes`. Larger bodies: `413`.
   Buffer only because rules may inspect `body`; responses are always streamed.
5. **Rule evaluation** — build a borrowed `RequestView` and evaluate the compiled
   categories/rules. Produces `Allow` (default), `Block(response)`, or `Log` +
   continuation.
6. **Forward** — send to the upstream over a pooled hyper client connection with
   connect/response timeouts. `502` on connect failure, `504` on timeout.
7. **Stream response** — pass status, headers, and body through unchanged (minus
   hop-by-hop headers) and emit an access log entry.
8. **Tunnel upgrades** — a WebSocket handshake is evaluated like any other
   request, then forwarded over a dedicated upstream connection. On `101`, both
   sides are upgraded and a bidirectional tunnel is held until EOF, the idle
   timeout, or shutdown.

### Body policy

Phase 1 buffers the full request body up to `max_body_bytes` (default 1 MiB) so
that `in: [body]` rules always see the complete payload. Phase 2 adds prefix
inspection with streaming pass-through for large uploads (inspect the first N
bytes, stream the rest uninspected, log `body_truncated`).

### Request normalization

- Header names are case-insensitive (hyper). Header values are matched verbatim.
- `path` and `query` are matched **both raw and percent-decoded** in a single pass,
  so `%3Cscript%3E` and `<script>` both match. Body and cookies are matched raw.
- No other normalization is performed (no Unicode folding, no double decoding).

### Forwarding rules

- Preserve method, path, query, and body; preserve the `Host` header.
- Forward upstream requests as HTTP/1.1 regardless of the downstream protocol.
- Strip hop-by-hop headers (`Connection`, `Keep-Alive`, `TE`, `Trailer`,
  `Transfer-Encoding`, `Upgrade`, `Proxy-*`) plus headers named by `Connection`.
- Set `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host`. If the peer
  is in `trusted_proxies`, append to an existing `X-Forwarded-For`; otherwise
  overwrite it with the direct peer address.
- WebSocket handshakes keep `Connection` and `Upgrade` (normalized to
  `Connection: Upgrade` and `Upgrade: websocket`) while all other hop-by-hop
  headers are stripped both ways.

## 5. Configuration and Hot Reload

### Validation (reject the whole file on any error)

- Category and rule names are non-empty; rule names are unique within a category.
- Every rule resolves to an effective action (`rule.action` or `category.action`).
- All regexes compile; `source_ip` entries parse as IP or CIDR; `method` values
  are valid tokens; `in` targets are known; every `match` has at least one
  condition.
- Unknown YAML fields are rejected (`deny_unknown_fields`) so typos fail loudly.
- Numeric and duration bounds are enforced (durations like `10s` or `1m` are
  parsed into `Duration`).

### Startup

Read, parse, validate, and compile the config. Any failure exits with code 1 and a
descriptive message (fail fast).

### Reload

The watcher listens on the config file **and its parent directory** (editors often
replace files via rename). Events are debounced (250 ms). A reload re-runs the
parse → validate → compile pipeline; on success the snapshot is swapped with
`ArcSwap::store`; on failure the previous snapshot stays active and the error is
logged. In-flight requests keep using the snapshot they loaded.

Reloadable: categories/rules, protection, timeouts, limits, upstream.
Restart-only: `listen` address, `tls`, and `http3`. Changing them during reload
logs a warning and keeps the current listener.

Watcher implementation: `notify` crate, with an mtime polling fallback (2 s) if the
platform watcher fails. Tests drive the reload function directly.

## 6. Rule Engine

### Compiled model (sketch)

```rust
struct CompiledConfig {
    categories: Vec<CompiledCategory>,
    upstream: Upstream,
    protection: ProtectionConfig,
    timeouts: Timeouts,
    limits: Limits,
}

struct CompiledCategory {
    name: String,
    enabled: bool,
    action: Option<Action>,             // category default
    response: Option<ResponseSpec>,     // category default (BLOCK)
    rules: Vec<CompiledRule>,
}

struct CompiledRule {
    name: String,
    enabled: bool,
    action: Option<Action>,             // overrides the category default
    response: Option<ResponseSpec>,     // overrides the category default
    matcher: Matcher,
}

struct Matcher {
    paths: Vec<Regex>,                      // OR within the field
    methods: Option<MethodSet>,
    source_ips: Option<IpSet>,
    headers: Vec<(HeaderName, Vec<Regex>)>, // name case-insensitive
    cookies: Vec<(String, Vec<Regex>)>,
    payload: Option<PayloadMatcher>,        // regex + target set
}
```

### Evaluation

Categories are evaluated in document order, then rules within a category. The
first rule whose conditions all match wins. Effective action and response resolve
rule-first, then category. `ALLOW` forwards and stops; `BLOCK` responds and stops;
`LOG` records and continues. No match means pass-through. See AGENTS.md invariant
1 for the contract.

### Matching semantics

- Conditions are ANDed; list values are ORed within a field.
- `targets` is a bitset of `path | query | body | cookies | headers`; `regex`
  patterns run against each selected part, and any part matching counts.
- Evaluation short-circuits on the first failing condition to keep the hot path
  cheap.
- Defaults: `in` is `[query, body, cookies]` when `regex` is present.

### Security limits

- The `regex` crate is used (linear time, no backtracking → no ReDoS).
- Per-pattern length cap (4 KiB), per-rule pattern count cap (64), and
  `size_limit` / `dfa_size_limit` set on compilation to bound memory.
- `response.body` is capped at 8 KiB at load time.
- Default block response: `403 Forbidden`, `text/plain`.

## 7. DoS / DDoS Protection

Protection is automatic and independent of the rule set. It consists of:

1. **Connection budgets** — per-IP concurrent connections (default 32) and global
   concurrent connections (default 1024). Excess connections receive `503` or are
   closed.
2. **Per-IP request rate** — token bucket with `requests_per_second` (default 20)
   and `burst` (default 60). Exceeding it returns `429` with `Retry-After` and
   records a violation.
3. **Global request rate guard** — a coarse windowed counter (default 2000 rps).
   When exceeded, new requests are shed with `503` until the window recovers.
4. **Ban manager** — `violations` (default 5) within `window` (default 10 s) bans
   the source for `duration` (default 60 s). Repeat bans double the duration up to
   `max_duration` (default 1 h). Bans are held in a TTL map with a bounded size.
5. **Timeouts** — header/body/idle timeouts mitigate slowloris-style attacks (see
   Section 8).

State is bounded: `max_tracked_ips` (default 100 000). When full, stale entries are
evicted first; if still full, new addresses fall back to the global limiter.
`protection.allowlist` CIDRs are exempt from rate limits and bans.

Proposed config block:

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

Adaptive tightening (lowering per-IP burst under global pressure) is future work.

For testing, `--disable-protection` forces `enabled` to false at startup and is
reapplied after every hot reload.

## 8. Fault Tolerance and Error Handling

- No `unwrap()` / `expect()` in request-handling paths; all fallible operations
  are matched or propagated.
- Error types are explicit (`thiserror`), with per-request errors mapped to HTTP
  statuses and internal errors answered with a generic `500` plus a detailed log.
- Upstream failures: connect errors → `502`, response timeout → `504`. No
  automatic retries by default (avoids duplicating non-idempotent requests).
- Config reload failures never affect the running instance.
- All memory and concurrency is bounded: body size, header size/count, URL length,
  regex size, per-IP state, connection count, ban table.
- Graceful shutdown: stop accepting, drain in-flight requests up to
  `shutdown_grace` (default 10 s), then exit.

Default timeouts:

| Setting            | Default |
| ------------------ | ------- |
| `header_read`      | 10 s    |
| `body_read`        | 30 s    |
| `idle`             | 60 s    |
| `upstream_connect` | 5 s     |
| `upstream_response`| 30 s    |
| `shutdown_grace`   | 10 s    |

Default limits:

| Setting            | Default |
| ------------------ | ------- |
| `max_path_bytes`   | 8 KiB   |
| `max_header_bytes` | 32 KiB  |
| `max_headers`      | 100     |
| `max_body_bytes`   | 1 MiB   |

## 9. Observability

- Structured logging via `tracing` + `tracing-subscriber`, controlled by
  `RUST_LOG`; `--log-format json` switches to JSON lines.
- Levels: `error` (invalid config at startup, upstream failure), `warn` (reload
  failure, ban issued), `info` (startup, successful reload, shutdown), `debug` /
  `trace` (rule evaluation detail, protection decisions).
- Access log entry: timestamp, client IP, method, path, status, bytes,
  duration_ms, verdict, matched `category.rule` + action list, protection actions,
  upstream address, error.
- Request bodies are never logged; paths are truncated to a bounded length.
- Metrics are exposed in Prometheus text format by the loopback-only admin
  listener (`admin.listen`, default `127.0.0.1:9090`) at `GET /metrics`. Counters
  cover requests, rule verdicts, protection decisions, upstream failures, and
  reloads; gauges cover active connections and uptime. The listener refuses
  non-loopback addresses at validation time, and a bind failure is logged and
  non-fatal.

## 10. CLI and Deployment

- Usage: `kunato --config <path>` (default `rules.yaml`).
- Flags: `--config`, `--validate` (parse/validate and exit, for CI and manual
  checks), `--disable-protection` (turn off DoS/DDoS protection for load and
  black-box testing), `--log-level`, `--log-format`, `--version`.
- Exit codes: `0` success, `1` configuration error, `2` usage error.
- Signals: `SIGINT` / `SIGTERM` trigger graceful shutdown; `SIGHUP` triggers a
  reload.
- Distribution: single static binary (musl target), no runtime dependencies.
- An example configuration is shipped as `rules.example.yaml`.
- Optional TLS termination via `rustls` when a `tls` block is configured.

## 11. Module Layout

```text
src/
  main.rs          # Startup, runtime setup, signal handling, shutdown
  cli.rs           # Argument parsing
  error.rs         # Error types
  telemetry.rs     # Logging setup
  admin.rs         # Loopback admin listener exposing /metrics
  metrics.rs       # Prometheus counters and gauges
  config/
    mod.rs         # Schema types, load, validate, compile
    watcher.rs     # File watching and reload
  rules/
    mod.rs
    matcher.rs     # Request matching
    eval.rs        # Evaluation and verdicts
  protection/
    mod.rs         # Sharded per-IP state, token bucket, bans, connection budgets
  proxy/
    mod.rs
    server.rs      # TCP listener, protocol detection, and shared request processing
    client.rs      # Upstream client
    forward.rs     # Header and body forwarding
    tls.rs         # Certificate loading and rustls server configuration
    http3.rs       # QUIC endpoint and HTTP/3 request handling
  request_view.rs  # Borrowed request representation for the rule engine
blackbox/          # External black-box test driver (separate crate)
  requests/        # Request lists (blocked.txt / allowed.txt)
examples/
  upstream.rs      # Manual test upstream with access logs
tests/
  proxy.rs         # Pass-through, rules, limits, protection, metrics
docs/
  DESIGN.md
packaging/
  kunato.service   # systemd unit
rules.example.yaml # Example configuration
```

## 12. Dependencies (proposed)

Every dependency must be justified in its commit message, per AGENTS.md.

| Crate                     | Purpose                        | Justification                                              |
| ------------------------- | ------------------------------ | ---------------------------------------------------------- |
| `tokio`                   | Async runtime                  | Required by hyper; mature, standard choice.                |
| `hyper`, `hyper-util`     | HTTP server and client         | Streaming-friendly HTTP/1.1 and HTTP/2; no framework overhead. |
| `http`                    | Shared HTTP types              | Core request/response types used across the proxy.         |
| `http-body-util`, `bytes` | Body utilities and buffers     | Companion crates for hyper; bounded-body helpers.          |
| `serde`, `serde-saphyr`   | YAML deserialization           | Typed config with `deny_unknown_fields`; safe-Rust YAML 1.2 parser. |
| `regex`                   | Signature matching             | Linear-time engine; immune to catastrophic backtracking.   |
| `arc-swap`                | Lock-free config snapshot      | Hot-path reads without locks or reference counting churn.  |
| `notify`                  | Config file watching           | Cross-platform filesystem events; polling fallback.        |
| `clap` (derive)           | CLI parsing                    | Conventional, low-boilerplate argument handling.           |
| `tracing`, `tracing-subscriber` | Structured logging       | Levels, spans, JSON output without custom code.            |
| `ipnet`                   | IP / CIDR parsing and matching | Correct IPv4/IPv6 CIDR semantics.                          |
| `rustls`, `tokio-rustls`  | TLS termination                | Pure-Rust TLS 1.2/1.3 with the ring provider.              |
| `quinn`, `h3`, `h3-quinn` | HTTP/3 over QUIC               | Mature Rust QUIC stack and the hyperium HTTP/3 implementation. |
| `thiserror`               | Error types                    | Explicit, low-boilerplate error enums.                     |
| `tempfile` (dev)          | Test fixtures                  | Writing config files for reload tests.                     |
| `rcgen` (dev)             | Test certificates              | Self-signed certificates for the TLS integration test.     |

Optional later: `rustls`, `tokio-rustls`, `rustls-pemfile` for TLS termination.

## 13. Testing Strategy

- Unit tests live beside modules: config validation, effective-action resolution,
  matcher per field type, AND/OR semantics, percent-decoding, token bucket (with
  `tokio::time::pause`), ban escalation, header stripping, body limit handling.
- Integration tests in `tests/` start Kunato on `127.0.0.1:0` with an in-process
  mock upstream and cover: pass-through, each action, category override,
  `ALLOW` short-circuit, `LOG` continuation, reload success, reload failure
  retention, `413` / `429` / `503` / `502` / `504`, graceful shutdown, h2c
  prior knowledge, rule evaluation over HTTP/2, ALPN `h2` over TLS, HTTP/3
  pass-through and rule evaluation over QUIC, `Alt-Svc` advertisement, and
  WebSocket tunneling, blocking, upstream rejection, and idle teardown.
- Tests are deterministic: paused time for limiter tests, no external network
  access, ephemeral ports, temporary config files.
- Later: fuzz targets for the config parser and matcher to assert no panics.
- `examples/upstream.rs` is a standalone upstream with access logs for manual
  browser and `curl` testing.
- `blackbox/` is an external driver that replays blocked/allowed request lists in
  parallel against a running instance; correctness is judged from the upstream
  and Kunato logs.

## 14. Security Considerations

- **ReDoS** — avoided structurally by the `regex` crate plus size/length caps.
- **Request smuggling** — hyper's strict HTTP/1.1 parser and HTTP/2 framing are
  relied upon; hop-by-hop headers are stripped; ambiguous framing is rejected
  rather than forwarded.
- **Header injection** — forwarding headers are constructed from validated values,
  never by string concatenation of untrusted input.
- **Slowloris** — header/body/idle timeouts and connection budgets, on TCP and
  QUIC alike.
- **QUIC abuse** — TLS 1.3 is required by QUIC; `quinn` handles anti-amplification
  and connection limits, while connection budgets, request limits, and rules
  apply to HTTP/3 exactly as they do to TCP.
- **Resource exhaustion** — every buffer, map, and counter is bounded; body size
  is limited before buffering. HTTP/3 field sections are capped by
  `limits.max_header_bytes`, and WebSocket tunnels are closed after
  `timeouts.websocket_idle` without traffic in either direction.
- **Opaque tunnels** — only the WebSocket handshake is inspected; tunnel payload
  is not evaluated by rules, not logged, and not bounded by `max_body_bytes`.
- **Obfuscation** — path/query are matched raw and percent-decoded; encoded
  traversal and XSS payloads are covered by rules.
- **Logging** — no secrets or full request bodies are logged.
- **Supply chain** — minimal dependency set; `cargo audit` in CI is planned.

## 15. Implementation Milestones

| Milestone | Scope                                                        | Acceptance criteria                                             |
| --------- | ------------------------------------------------------------ | --------------------------------------------------------------- |
| M0        | Scaffold: CLI, error type, logging, dependency setup.        | `--validate` runs; `cargo clippy` and tests pass.               |
| M1        | Proxy core: listener, HTTP/1.1 pass-through, timeouts.       | Integration test proxies to a mock upstream, streams responses. |
| M2        | Config: schema types, loading, validation, compilation.      | Invalid configs are rejected with actionable errors.            |
| M3        | Rule engine: matcher, evaluation, actions, responses.        | Tests cover precedence, each action, AND/OR semantics.          |
| M4        | Hot reload: watcher, debounce, atomic swap.                  | Reload tests pass, including failure retention.                 |
| M5        | Protection: token bucket, bans, connection budgets.          | Rate/ban/limit tests pass deterministically.                    |
| M6        | Hardening and packaging: limits, shutdown, musl release.     | All invariants tested; example config shipped.                  |
| M7        | Optional TLS termination behind config.                      | TLS integration test passes.                                    |
| M8        | HTTP/2: ALPN over TLS, h2c prior knowledge, protocol detect. | HTTP/2 integration tests pass; HTTP/1.1 behavior unchanged.     |
| M9        | HTTP/3: opt-in QUIC listener, Alt-Svc advertisement.         | HTTP/3 requests are proxied and rule-checked; Alt-Svc is sent.  |
| M10       | WebSocket: HTTP/1.1 upgrade forwarding and tunneling.        | Handshake rules, tunnel I/O, and idle timeout tests pass.       |

M0 through M10 are implemented: metrics and the admin listener, the example
configuration, the systemd unit, musl static builds, CI, a tag-triggered release
workflow, optional TLS termination, HTTP/2, HTTP/3, and WebSocket upgrades.

## 16. Open Questions and Future Work

- TLS: certificate hot reload.
- WebSocket over HTTP/2 and HTTP/3 (RFC 8441 / RFC 9220 extended CONNECT).
- Pluggable tunnel payload inspection (currently upgrades are opaque).
- Streaming body inspection for large uploads (prefix inspection).
- Response header inspection (rules currently match requests only).
- Multiple upstreams and load balancing.
- Admin API beyond the `/metrics` endpoint.
- IPv6 rate-limit aggregation (e.g., per /64) to resist address-rotation floods.
- Config includes/anchors for large rule sets.
- Container image recipe (the systemd unit and musl builds are shipped).
