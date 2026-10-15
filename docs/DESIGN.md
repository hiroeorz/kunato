# Kunato Design

Status: **Draft** — milestones M0 through M10 are implemented and covered by unit
and integration tests. TLS termination is provided through `rustls`; HTTP/2 is
served over TLS (ALPN) and cleartext (h2c prior knowledge), HTTP/3 is served
over QUIC when enabled, and HTTP/1.1 WebSocket upgrades are tunneled. Rules can
also run in a response phase that inspects upstream responses (status, headers,
body prefix). Certificate rotation remains future work.

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
- Response body rewriting (responses can be inspected and replaced wholesale, but
  their contents are never modified).
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
| Rule engine  | Evaluates request and response views against the compiled rule set.   |
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
- Response inspection is opt-in per configuration: when no response-phase rules
  exist, upstream responses stream through untouched. When they do, the response
  prefix up to `limits.max_response_body_bytes` is buffered for evaluation and the
  remainder (if any) streams through behind it.
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
4. **Buffer body prefix** — read up to `limits.max_body_bytes` into a bounded
   prefix. Larger bodies stream to the upstream after rule evaluation, with a
   truncation log and metric. Buffer only because rules may inspect `body`;
   responses are always streamed. Encoded bodies are decompressed and
   content-type decoded for inspection when body-targeting rules exist;
   forwarded bytes stay unchanged.
5. **Rule evaluation** — build a borrowed `RequestView` and evaluate the compiled
   categories/rules. Produces `Allow` (default), `Block(response)`, or `Log` +
   continuation.
6. **Forward** — send to the upstream over a pooled hyper client connection with
   connect/response timeouts. `502` on connect failure, `504` on timeout.
7. **Evaluate response rules** — if response-phase categories exist, buffer the
   response prefix up to `limits.max_response_body_bytes` under
   `timeouts.upstream_response` (a stalled upstream yields `504`) and evaluate
   the response view. `BLOCK` replaces the upstream response with the effective
   response; `LOG` records the match; otherwise the buffered prefix and the
   remaining stream are forwarded. Responses generated by Kunato itself (block
   and error responses) are never re-inspected.
8. **Stream response** — pass status, headers, and body through unchanged (minus
   hop-by-hop headers) and emit an access log entry.
9. **Tunnel upgrades** — a WebSocket handshake is evaluated like any other
   request, then forwarded over a dedicated upstream connection. On `101`, both
   sides are upgraded and a bidirectional tunnel is held until EOF, the idle
   timeout, or shutdown. Upgrade responses bypass response-rule inspection.

### Body policy

The first `max_body_bytes` of a request body (default 1 MiB) are buffered so
that `in: [body]` rules always see a bounded prefix; content decoding applies to
that prefix. When the body is larger, the remainder streams to the upstream
uninspected: the request is logged and counted as truncated
(`kunato_request_truncated_total`), and the exchange runs under
`timeouts.body_read` instead of `timeouts.upstream_response`. To reject
oversized bodies instead, add an explicit rule (for example a `content-length`
header regex). Responses already buffer only a prefix
(`max_response_body_bytes`) and stream the rest.

### Request normalization

- Header names are case-insensitive (hyper). Header values are matched verbatim
  after lossy UTF-8 decoding, so invalid bytes cannot hide a matching value.
- `path` and `query` are matched raw and through up to two percent-decode passes
  (a compile-time constant), so `%253Cscript%253E`, `%3Cscript%3E`, and
  `<script>` all match. Paths are additionally matched in normalized form (dot
  segments resolved, duplicate slashes merged) to mirror upstream
  canonicalization. Cookies are matched raw.
- Request bodies are matched raw, then content-type decoded
  (`application/x-www-form-urlencoded`, JSON string escapes such as `\u0075`,
  and `multipart/form-data` flattened to field values and file names), then
  through the same percent-decode passes. Multipart parsing is bounded (64
  parts, 1 KiB names/file names); malformed or oversized multipart bodies fall
  back to raw inspection.
- Bodies with `Content-Encoding: gzip`, `deflate`, or `br` are decompressed for
  inspection only; forwarded bytes are never modified. Decoding is bounded by
  `limits.max_body_bytes` / `limits.max_response_body_bytes`, and a decoded body
  cut off at the limit raises its own log entry and counter
  (`kunato_request_decode_truncated_total` /
  `kunato_response_decode_truncated_total`); stacked or unknown encodings are
  inspected as received.
- No other normalization is performed (no Unicode folding, no HTML entity
  decoding). Entity and fullwidth folding are deferred until anomaly scoring
  can absorb their false positives.

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

### Rule sources and managed updates

Categories can be split across three documents: `overrides_file`, inline
`categories`, and `rules_file`. They are merged in that order before compilation,
so override categories are evaluated first and names must be globally unique. The
external files are categories-only; `overrides_file` additionally accepts
`disabled_rules`, which drops matching rule names from every source.

`rules_update` optionally refreshes `rules_file` on an interval: a conditional
HTTPS request, a SHA256 check against `checksum_url`, full parse/compile
validation, and an atomic rename. The file watcher then swaps in the new
snapshot; any failure leaves the previous rules in place. `kunato update-rules`
runs a single check for the installer and for manual use.

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
    phase: Phase,                       // request | response
    action: Option<Action>,             // category default / threshold action
    response: Option<ResponseSpec>,     // category default (BLOCK)
    threshold: Option<u32>,             // scoring mode when set
    rules: Vec<CompiledRule>,
}

struct CompiledRule {
    name: String,
    enabled: bool,
    action: Option<Action>,             // overrides the category default
    response: Option<ResponseSpec>,     // overrides the category default
    limit: Option<RuleLimit>,           // per-source rate limit (request phase)
    limit_key: u32,                     // stable bucket key for limit
    matcher: Matcher,
}

struct Matcher {
    paths: Vec<Regex>,                      // OR within the field
    methods: Option<MethodSet>,
    source_ips: Option<IpSet>,
    headers: Vec<(HeaderName, Vec<Regex>)>, // name case-insensitive
    cookies: Vec<(String, Vec<Regex>)>,
    statuses: Vec<StatusRange>,             // response phase only
    response_headers: Vec<(HeaderName, Vec<Regex>)>, // response phase only
    payload: Option<PayloadMatcher>,        // regex + target set
}
```

### Evaluation

Categories are evaluated in document order, then rules within a category. Phase
selects the pass: request-phase categories run before forwarding, response-phase
categories run on the buffered upstream response. The first rule whose conditions
all match wins. A rule with `limit` skips itself while its source is within
budget (see Section 7). Effective action and response resolve rule-first, then
category.

A category with `threshold: N` runs in scoring mode instead: every matching rule
adds one point, rules never carry `action`, `response`, or `limit`, and the
category action (`BLOCK` or `LOG`, required) applies once the score reaches `N`.
Below the threshold the category is transparent and evaluation continues. The
blocked/log record names the last matching rule.
`ALLOW` stops evaluating further categories of that phase (request: forward;
response: pass through unchanged); `BLOCK` responds and stops; `LOG` records and
continues. No match means pass-through. See AGENTS.md invariant 1 for the request
contract; response rules follow the same contract with the response view.

### Matching semantics

- Conditions are ANDed; list values are ORed within a field.
- `targets` is a bitset of `path | query | body | cookies | headers |
  response_body`; `regex` patterns run against each selected part, and any part
  matching counts.
- `response_body` is only valid in response-phase rules; the default target is
  `[query, body, cookies]` for requests and `[response_body]` for responses.
- Response-phase rules may also match request conditions (`path`, `method`,
  `source_ip`, `headers`, `cookies`, and request-body targets), allowing
  response verdicts that depend on who sent what.
- `status` accepts codes, ranges (`500-599`), and classes (`5xx`);
  `response_headers` maps a case-insensitive header name to regexes.
- Evaluation short-circuits on the first failing condition to keep the hot path
  cheap.

### Security limits

- The `regex` crate is used (linear time, no backtracking → no ReDoS).
- Per-pattern length cap (4 KiB), per-rule pattern count cap (64), and
  `size_limit` / `dfa_size_limit` set on compilation to bound memory.
- `response.body` is capped at 8 KiB at load time.
- Buffered response bodies are capped at `limits.max_response_body_bytes`; only
  the prefix is evaluated, and the remainder streams through uninspected.
  Request bodies are buffered up to `limits.max_body_bytes`; the remainder
  streams to the upstream uninspected and is logged as truncated.
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
6. **Rule rate limits** — a rule may carry `limit: { requests, window }`. Matching
   requests are counted per source with the same tracking key, allowlist, and
   bounds as the per-IP limits; below the budget the rule is transparent and
   evaluation continues, at or above it the rule fires (`BLOCK` or `LOG` only).
   Limits are bucketed per rule identity (a stable hash of category and rule
   name, so hot reloads keep the counters) and are evaluated during the request
   phase only.

State is bounded: `max_tracked_ips` (default 100 000). When full, stale entries are
evicted first; if still full, new addresses fall back to the global limiter.
`protection.allowlist` CIDRs are exempt from rate limits and bans. IPv6 addresses
are aggregated by `aggregate_ipv6_prefix` (default 64) for rate limits, bans, and
per-IP connection budgets, so rotating within a prefix cannot bypass them;
IPv4-mapped addresses are treated as IPv4.

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
  aggregate_ipv6_prefix: 64
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
  cover requests, rule verdicts (request and response phase), protection
  decisions, upstream failures, truncated response inspection, and reloads;
  gauges cover active connections and uptime. The listener refuses non-loopback
  addresses at validation time, and a bind failure is logged and non-fatal.

## 10. CLI and Deployment

- Usage: `kunato --config <path>` (default `/etc/kunato/kunato.yaml`).
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
    response.rs    # Response buffering and response-phase inspection
    tls.rs         # Certificate loading and rustls server configuration
    http3.rs       # QUIC endpoint and HTTP/3 request handling
  request_view.rs  # Borrowed request and response representations for the rule engine
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
| `flate2` (rust backend)   | gzip / deflate decoding        | Pure-Rust backend; no C toolchain for musl builds.         |
| `brotli-decompressor`     | Brotli decoding                | Pure-Rust decompressor; the encoder is not needed.         |
| `rustls`, `tokio-rustls`  | TLS termination                | Pure-Rust TLS 1.2/1.3 with the ring provider.              |
| `quinn`, `h3`, `h3-quinn` | HTTP/3 over QUIC               | Mature Rust QUIC stack and the hyperium HTTP/3 implementation. |
| `thiserror`               | Error types                    | Explicit, low-boilerplate error enums.                     |
| `tempfile` (dev)          | Test fixtures                  | Writing config files for reload tests.                     |
| `rcgen` (dev)             | Test certificates              | Self-signed certificates for the TLS integration test.     |
| `brotli` (dev)            | Compressed test fixtures       | Encoder used to build brotli payloads in tests.            |

Optional later: `rustls`, `tokio-rustls`, `rustls-pemfile` for TLS termination.

## 13. Testing Strategy

- Unit tests live beside modules: config validation, effective-action resolution,
  matcher per field type, AND/OR semantics, percent-decoding, response phase and
  status/header matching, token bucket (with `tokio::time::pause`), ban
  escalation, header stripping, body limit handling.
- Integration tests in `tests/` start Kunato on `127.0.0.1:0` with an in-process
  mock upstream and cover: pass-through, each action, category override,
  `ALLOW` short-circuit, `LOG` continuation, response-phase blocking and
  logging, response status/header matching, oversized response prefix handling,
  reload success, reload failure retention, `413` / `429` / `503` / `502` /
  `504`, graceful shutdown, h2c prior knowledge, rule evaluation over HTTP/2
  including response rules, ALPN `h2` over TLS, HTTP/3 pass-through and rule
  evaluation over QUIC, `Alt-Svc` advertisement, and WebSocket tunneling,
  blocking, upstream rejection, and idle teardown.
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
- **Response inspection** — response rules see at most
  `limits.max_response_body_bytes` of each response; larger bodies stream through
  after the prefix is evaluated. Inspection never modifies response contents;
  `BLOCK` replaces the whole response. Responses generated by Kunato itself are
  not re-inspected, so block responses cannot recurse.
- **Opaque tunnels** — only the WebSocket handshake is inspected; tunnel payload
  is not evaluated by rules, not logged, and not bounded by `max_body_bytes`.
- **Obfuscation** — path/query are matched raw and through up to two
  percent-decode passes, bodies are matched raw plus content-type decoded
  (forms, JSON escapes, multipart field values and file names) and then
  percent-decoded again, and gzip/deflate/br bodies are decompressed for
  matching; encoded traversal, XSS, and compressed payloads are covered by
  rules. Multipart flattening and decode passes are bounded, and no decoding
  ever changes the forwarded bytes.
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
| M11       | Response inspection: response-phase categories, status/header/body matching, bounded buffering. | Response rules block/log; oversized bodies stream through after prefix inspection. |

M0 through M11 are implemented: metrics and the admin listener, the example
configuration, the systemd unit, musl static builds, CI, a tag-triggered release
workflow, optional TLS termination, HTTP/2, HTTP/3, WebSocket upgrades, and
response-phase rules.

## 16. Open Questions and Future Work

- TLS: certificate hot reload.
- WebSocket over HTTP/2 and HTTP/3 (RFC 8441 / RFC 9220 extended CONNECT).
- Pluggable tunnel payload inspection (currently upgrades are opaque).
- HTTP/3 request body streaming (TCP listeners stream bodies past the prefix;
  HTTP/3 bodies above `max_body_bytes` are still rejected with `413`).
- Multiple upstreams and load balancing.
- Admin API beyond the `/metrics` endpoint.
- Config includes/anchors for large rule sets.
- Container image recipe (the systemd unit and musl builds are shipped).
