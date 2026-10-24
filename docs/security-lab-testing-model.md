# Local security lab testing model

The lab is a differential test: the same request bytes are sent with and without
Kunato, and the recording origin decides what actually happened. Kunato's logs,
status codes, and rule names corroborate a result; the origin's receipt is the
ground truth. The model below is implemented by `lab/controller.py`,
`lab/probe.py`, `lab/origin.py`, `lab/evidence.py`, and `lab/compose.yaml`.

## Topology

```text
┌─────────────────────────── host ─────────────────────────────────┐
│ scripts/security-lab.sh -> lab/controller.py (Python)             │
│     | docker compose (project = kunato-lab-<run-id>)              │
│     v                                                             │
│ ┌──────────── front network ───────────────────────────────────┐  │
│ │ kunato (K)   client   normal   load (k6)                     │  │
│ │ gotestwaf    ffuf     zap                                   │  │
│ └──────────────┬───────────────────────────────────────────────┘  │
│                │ back network                                     │
│ ┌──────────────v───────────────────────────────────────────────┐  │
│ │ kunato (K)   origin (app.test)   control   dvwa/db/cve      │  │
│ └──────────────────────────────────────────────────────────────┘  │
│ data network: database fixtures                                   │
└───────────────────────────────────────────────────────────────────┘
```

- **front** carries attack clients, the independent normal client, and the k6
  load generator. It is the untrusted side of Kunato.
- **back** carries Kunato's upstream path. The recording origin listens there
  as `app.test` and writes one JSONL event per request.
- **control** is a WAF-less client on the back network. It sends the same bytes
  directly to the origin to prove that a case is meaningful before the
  protected result is trusted.
- **data** is reserved for database fixtures (DVWA and the SQL-injection
  sandbox suite).
- No lab service publishes ports. Containers are read-only where possible,
  have CPU, memory, and pid ceilings, and use internal Docker networks.

## Run lifecycle

```text
run --sandbox-suite <name>
  prepare (first run): pin image digests, build Kunato, build fixtures
  new_run: copy lab/ into an immutable input, write manifest
  preflight/isolation: internal networks, no published ports, DNS,
                       forbidden host/IP checks
  reset_origin: recreate origin and Kunato, issue a nonce, require health 200
  direct control: control -> origin (WAF-less), verify the origin receipt
  protected run: client/tool -> Kunato -> origin
  collect: origin.jsonl, kunato.jsonl, metrics, tool reports, docker stats
  judge: compare direct and protected evidence, produce per-case verdicts
  report.md/report.json -> cleanup
```

Each run starts from the current worktree snapshot, so edits made during a run
cannot change its input. The origin, Kunato, and every tool container are
removed afterwards, including on ordinary failure; `cleanup.json` records that
no project containers, networks, or volumes remain.

## Verdict model

```text
          direct control                 protected run
          (no WAF)                       (through Kunato)
  [control] --same bytes--> [origin]   [client] --> [K] --> [origin]
       |                        |                       |
       | receipt?               | receipt?              | block?
       v                        v                       v
  is the test valid?     did the attack arrive?   did the WAF prevent it?
```

| Direct control | Case `expect` | Kunato result | Origin receipt via Kunato | Verdict |
| --- | --- | --- | --- | --- |
| valid | `block` | any | yes | **gap** |
| valid | `block` | blocked with evidence | no | **prevented** |
| valid | `block` | allowed | no | **inconclusive** |
| valid | `allow` | allowed | yes | **passed** |
| valid | `allow` | blocked or no receipt | any | **false-block** |
| invalid | any | - | - | **inconclusive** |

A protected result is never trusted unless the direct control proved the case
is valid. For a `block` case, `prevented` requires corroborating block evidence
(status, log, or rule record), not merely a failed or timed-out request. In a
protocol smuggling case, a forwarded first request is still `prevented` when the
origin records no smuggled second request. The `summarize()` helper marks a
sandbox suite passed only when every case is `passed` or `prevented`;
`inconclusive`, `false-block`, `gap`, and `failed` all fail the run. This
fail-closed rule prevents missing evidence from being reported as defense
success.

## Sandbox suite measurements

### Replay and deterministic mutations

The replay corpus pairs SQL injection, XSS, traversal, and comment-obfuscated
UNION probes with benign counterparts and legitimate 302/401/404 responses. The
25 deterministic mutations expand the seeds with case, comment, newline, body
format, parameter pollution, tag, padding, shell-metacharacter, and header-value
variants. Each case is sent directly to the origin and then through Kunato; the
origin proves receipt, method, target, body hash, and nonce.

### Benign workflows

The `benign` suite sends a JSON API request, a multipart PDF upload, a
percent-encoded Japanese query, a 16 KiB text body, and a chunked response
through the same direct-control and protected path. Every case must preserve the
origin's case ID, method, target, body hash, and nonce, and the protected run
must return the expected status without a block. These cases exercise the form
guard, upload inspection, content-type decoding, and chunked response
forwarding; they are not a full application workflow corpus.

### Raw protocol and WebSocket

Twelve reviewed cases cover a valid request with `Connection: close`, a chunked
body, CL+TE and TE+CL ambiguity, duplicate Content-Length, obs-fold, a benign
CRLF pair, duplicate Host, an invalid chunk, an oversized header, an HTTP/2
preface, and a WebSocket handshake. Direct controls use the origin framing modes
(`reject`, `cl`, `te`) to show what the origin would parse; the protected run
must not deliver a smuggled second request. The WebSocket probe sends the
handshake, reads the response headers, sends one masked frame, and requires a
`101` status plus the origin's `websocket` event; the origin's echo is recorded
but not asserted. A handshake check does not imply inspection of later tunnel
messages.

### WebSocket lifecycle

The `websocket` suite runs a direct control and a protected WebSocket handshake,
then sends a masked PING and requires the matching PONG, a fragmented text
message and requires the origin's concatenated echo, and a close frame and
requires the close handshake. The independent normal client must stay at `200`.
This covers tunnel pass-through for control, fragmentation, and close frames;
inspecting application payloads inside the tunnel remains a separate feature.

### Pinned tools

goTestWAF, sqlmap, Nuclei, ffuf, and ZAP run the same bounded scan against the
direct control and through Kunato. Their reports, the origin receipts, and
Kunato's block records are joined per case. ZAP runs the authenticated
spider/passive baseline; its active scan is not part of the passing plan. A
scoped, observation-only active plan was attempted with SQLi and reflected XSS
only, file-inclusion/setup/security/logout excluded, and `failOnError: false`;
ZAP 2.17.0 still exited at `Job activeScan started` with code 2 and an empty
report. The pinned image and Docker Hub `latest` share the same 2.17.0 digest,
so active ZAP scanning stays deferred.

### Bounded slow HTTP

`--sandbox-suite slow` opens 8 partial-header connections, holds them for
2 seconds, and checks that the independent normal client still receives `200`.
Kunato's CPU and RSS are recorded before and after, and the containers run under
the 256 MiB and 64-pid ceilings, but this suite does not assert resource
thresholds or restarts; the mixed-load suite does. The probe is the lab's own
raw-socket mode, not slowhttptest.

### Availability boundaries

`--sandbox-suite availability` runs against a dedicated configuration with a
2-second body-read timeout, a 1-second upstream-response timeout, and an
8-connection per-source cap. It sends a partial request body and expects `408`,
opens a large response without reading it, fills the per-source connection
budget so the next connection gets `503` while the independent normal client
stays `200`, and requests an origin that sleeps past the upstream timeout so the
client gets `504`. The same suite checks RSS, restarts, the normal client, and
the upstream-timeout metric. Slow upstream connect and multi-source exhaustion
remain outside the suite.

### Ban recovery

The `ban` suite uses a dedicated configuration with one request per second, a
burst of one, two ban violations, and a two-second ban. It sends ten requests
from one source, requires a `429` ban, waits for the ban to expire, and requires
a `200` recovery from the same source. The independent normal client must stay
at `200`, and the `kunato_banned_total` counter must reflect the ban.

### Mixed availability load

```text
 t=0   stats before; start k6 (50 rps, 60 s)
 t=2   open 8 slow connections (held 2 s); normal health; stats mid
 t=60  k6 ends; summary (p95/p99, failure rate, checks)
 t=62  stats after; recovery health; restart count
       judge: latency / attack / normal / recovery / resources
```

The k6 constant-arrival-rate scenario runs 50 requests per second for 60
seconds. Its thresholds are at least 1,000 requests, p95 < 200 ms,
p99 < 500 ms, failed requests < 1%, and checks > 99%. While it runs, the slow
connections and the normal probe are executed from separate containers. The
judge also requires the normal and recovery probes to return `200`, no Kunato
restart, and RSS under the 256 MiB ceiling. Recovery is checked immediately
after the load stops. A metrics case requires the request counter to cover the
k6 workload and the block, rate-limit, overload, and upstream-timeout counters
to remain at zero.

## Why this design

1. **Differential testing.** The same bytes are sent with and without Kunato, so
   the only difference is the WAF's handling.
2. **Origin-boundary evidence.** The origin's receipt, not Kunato's self-report,
   decides whether an attack reached the application.
3. **Valid direct controls.** A case without a valid direct receipt is
   inconclusive, not prevented.
4. **Independent normal client.** Normal workflows are measured during attacks,
   during load, and after load stop to catch false blocks and poor recovery.
5. **Fail-closed reporting.** Missing evidence, inconclusive cases, normal-client
   failures, resource overruns, and restarts fail the run.
6. **Bounded and pinned inputs.** Image digests, tool versions, rates, durations,
   VU counts, memory, pids, and timeouts are fixed before execution.
7. **Immutable input snapshots.** The run copies the lab directory and the
   binary at start, keeping evidence reproducible.
8. **Cleanup.** Containers, networks, and volumes are removed and verified after
   every run.

## Current operation

- `scripts/security-lab.sh prepare` pins images, builds the CVE fixture and the
  current release binary, and writes `prepared/manifest.json`.
- The `all` sandbox suite is run locally before committing and pushing, together
  with the optional, observation-only `crs` comparison; individual suites can
  also be run separately. CI runs only the lab observation unit tests and the
  shellcheck wrappers.
- The last `all` run, `20261025T003757-8e7d00e3`, passed 14 sandbox suites:
  replay, benign, mutations, protocol, slow, availability, ban, websocket, load,
  goTestWAF, sqlmap, Nuclei, ffuf, and ZAP. The mixed load recorded 3000
  requests, p95 49.9 ms, p99 53.2 ms, 100% success, normal/recovery `200`, RSS
  21.8 MiB of 256 MiB, no restart, and matching metrics. The availability suite
  recorded a slow-body `408`, slow-read `200`, connection-cap `503`, upstream
  `504`, and 23.6 MiB RSS. The ban suite recorded a `429` ban and `200`
  recovery; the websocket suite recorded PONG, the fragmented echo, and the
  close handshake.
- Evidence stays under `target/security-lab/<run-id>/`: the per-phase probes,
  origin and Kunato logs, tool reports, `report.md`, and `report.json`.
- The sandbox suite list, commands, and limits are documented in
  [lab usage](../lab/README.md); the target design and cadence are in
  [the adversarial testing design](security-testing.md).

## Remaining coverage

The implemented sandbox suites are a bounded regression harness, not a
certification. The [attack coverage tracker](attack-coverage.md) still marks many
classes as partial or absent, and the following areas are not exercised by the
current suites.

### Attack and engine coverage

- The tracker lists HPP, Content-Type spoofing, API version/schema abuse,
  session-ID anomalies, business-logic classes (IDOR, coupon/carding, scalping),
  and rule-bypass payloads as absent; JWT tampering and algorithm confusion are
  partial. HTTP request smuggling, desync, response splitting, upload
  inspection, and GraphQL abuse are partial.
- The WebSocket suite now proves the handshake, PING/PONG, fragmented echo, and
  close handshake; it still does not inspect application payloads after the
  upgrade. The 25 mutations and the tool corpora are reviewed samples, not the
  full scanner catalogs.

### Protocol coverage

- The lab's HTTP/2 client coverage is limited to the connection preface. Rust
  integration tests add Rapid Reset, CONTINUATION, and an oversized HPACK header
  block; the lab does not exercise SETTINGS/CONTINUATION under load, HPACK
  resource pressure, stream-state abuse, GOAWAY, priority, or h2c.
- HTTP/3, QUIC, and TLS termination/ACME are not exercised in the lab, although
  the Rust proxy tests cover functional H3 requests and a malformed raw H3
  request-stream case. HTTP/1.0, pipelining, CONNECT, chunked trailers, and very
  large chunks are not exercised beyond the 12 reviewed cases; the single
  obs-fold case has no variants.
- The rules that would apply to WebSocket application payloads after the
  upgrade are not tested; the suite covers control, fragmentation, and close
  frames only.

### Availability coverage

- The slow suite holds 8 partial-header connections for 2 seconds. The
  availability suite adds a slow-body `408`, a slow-read probe, a per-source
  connection cap with `503`, and an upstream-response timeout with `504`. Slow
  upstream connect, multi-source and global exhaustion, queue/backpressure,
  and inspection-budget pressure are not exercised. The ban suite adds a
  short-window ban trigger, a recovery request, a normal-client check, and the
  `kunato_banned_total` counter.
- The load suite is a fixed 50 requests/second run and now checks Kunato's
  request, block, rate-limit, overload, and upstream-timeout counters. H2 Rapid
  Reset, CONTINUATION floods, and HPACK bombs are not attempted in the lab;
  ban/rate-limit recovery windows and distributed sources (impossible in one
  lab) remain untested. OOM, restart, and graceful-shutdown behavior under
  pressure are not part of the passing suites.

### Workflows and false positives

- ZAP active scanning is deferred: a scoped plan still exited at activeScan
  start with ZAP 2.17.0, and no newer stable image is published. Only the
  spider/passive baseline runs. The benign suite covers a JSON API request,
  a multipart PDF upload, a percent-encoded Japanese query, a 16 KiB text body,
  and a chunked response. Authenticated API flows, GraphQL workflows, i18n edge
  cases, sustained streaming, and legitimate WebSocket workloads remain outside
  the corpus.
- goTestWAF, sqlmap, Nuclei, ffuf, ZAP, and CRS run bounded plans. The full
  scanner corpora and additional tamper/template/paranoia variants are not.

### Operations

- Rust proxy tests cover hot reload under load, rules update plus reload under
  load, and HTTP/3 malformed request streams. Rules-update failures and format
  compatibility have unit tests. `allowed_hosts`/`client_ip`/trusted-proxy
  combinations, logs/audit, restart state, and multi-worker or HTTP/2/HTTP/3
  upstream translation remain outside the suites. The load suite asserts
  request, block, rate-limit, overload, and upstream-timeout counters.

### Priorities

1. Availability: slow upstream connect, multi-source and global exhaustion, and
   queue/backpressure. The slow-body, slow-read, per-source connection-cap,
   upstream-response-timeout, and ban-recovery cases are implemented.
2. Benign workflow breadth: authenticated APIs, GraphQL, upload variants, i18n
   edge cases, and sustained streaming. The initial JSON, upload, i18n,
   large-body, and streamed-response cases are implemented.
3. HTTP/2 hardening and HTTP/3: Rapid Reset, CONTINUATION, oversized HPACK, and
   a malformed raw H3 request stream are covered by Rust integration tests; add
   lab resource variants after a TLS/QUIC fixture.
4. Restart behavior under load. Hot reload, rules update plus reload under load,
   and load metrics are covered by Rust tests and the load suite.
5. WebSocket application-payload inspection after the handshake. Fragmentation,
   close, and PING/PONG lifecycle are covered by the websocket suite.
6. ZAP active scanning, scoped and observation-only. A separate plan was
   attempted but ZAP 2.17.0 exits at activeScan start even after scoping the
   endpoints and setting `failOnError: false`; revisit when a fixed image or
   add-on is available.
7. Full scanner corpora on a nightly or weekly cadence.

### Limits

A fixed single host and fixed runner make the load numbers trends, not capacity
or distributed-attack claims. The fixtures cover only their bounded scenarios,
and a zero-finding run means the executed cases passed, not that the application
is protected against every bypass. The lab's value is the reproducible
regression loop; the coverage list above is the backlog that keeps it honest.
