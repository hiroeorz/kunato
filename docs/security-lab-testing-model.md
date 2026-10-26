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

- **front** carries attack clients, the independent normal client, the k6 load
  generator, and the scalable `exhaust` probes used to fill the global
  connection budget from independent source addresses. It is the untrusted side
  of Kunato.
- **back** carries Kunato's upstream path. The recording origin listens there
  as `app.test` and writes one JSONL event per request.
- **control** is a WAF-less client on the back network. It sends the same bytes
  directly to the origin to prove that a case is meaningful before the
  protected result is trusted.
- **data** is reserved for database fixtures (DVWA and the SQL-injection
  sandbox suite).
- A dedicated internal `blackhole` network gives the slow-connect suite an
  unassigned upstream address; Kunato's TCP connect times out without a
  reachable peer.
- A lab-only CA/leaf certificate, a small `h3probe` binary built from
  `examples/h3probe.rs`, and a low-rate protection profile exercise TLS/HTTP/3
  termination and rate-guard backpressure.
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

### Manual shell

`scripts/security-lab.sh shell` reuses the same prepared input snapshot and
Compose project to keep one configuration and fixture running for interactive
tools. It runs no direct control, writes no case verdicts or `report.json`, and
is not evidence for a security claim. The shell container joins only `front`
and runs unprivileged with a read-only root filesystem. `--publish` starts a
bounded loopback relay from the controller to the Kunato container's `front`
address; this is the only host exposure, because Docker does not publish ports
from an `internal` network. Fixture and database ports remain unpublished.
Container logs, metrics, the manual attempt record, and `cleanup.json` are
retained in the run directory. Promote a finding to `lab/cases/` or the
black-box corpus before using it as a regression. See
[lab/MANUAL-SHELL.md](../lab/MANUAL-SHELL.md) for the step-by-step commands.

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
sandbox suite passed when every case is `passed`, `prevented`, or `observed`;
`inconclusive`, `false-block`, `gap`, and `failed` all fail the run. An
`observed` case must complete a direct control and records whether the protected
request reached the origin or was stopped; it is an explicit discovery result,
never a defense claim. This keeps gap discovery runnable without weakening the
fail-closed rule for cases that declare `block` or `allow`.

## Sandbox suite measurements

### Replay and deterministic mutations

The replay corpus pairs SQL injection, XSS, traversal, and comment-obfuscated
UNION probes with benign counterparts and legitimate 302/401/404 responses. The
25 deterministic mutations expand the seeds with case, comment, newline, body
format, parameter pollution, tag, padding, shell-metacharacter, and header-value
variants. Each case is sent directly to the origin and then through Kunato; the
origin proves receipt, method, target, body hash, and nonce.

### Common and recent attack surfaces

The `common` suite adds 44 reviewed cases for classes the replay and mutation
corpora did not cover: SSTI, NoSQL, LDAP, XPath, PHP/Java/Python/Ruby
deserialization, CRLF, SSRF, XXE, JWT header attacks, and API behaviours
(mass assignment, OAuth `redirect_uri`, BOLA, HPP, duplicate JSON keys, GraphQL
introspection). Each case has a direct origin control; 26 attacks are blocked,
13 benign cases pass, and 5 discovery cases are observed at the origin. The
`parameter-pollution` rules block duplicate privilege and redirect fields.

The `recent` suite adds 21 cases for 2025-2026 CVE and AI-era traffic:
React2Shell, Next.js middleware/RSC variants, PHP2Shell, the Rack multipart
escape flood, GitLab repository file read, Jenkins script console, TeamCity
agent protocol, MCP tool arguments, AI crawler and API-client user agents, and
benign MCP/upload traffic. Eleven attacks are blocked, seven benign cases pass,
and three discovery cases (prompt injection, forwarded-host cache poisoning,
registry catalog) are observed at the origin. The `cache-deception` rule blocks
an authenticated request addressed as a static asset.

The observed cases are deliberately not counted as blocked: the JWT
algorithm-confusion, mass-assignment, OAuth redirect, BOLA, HPP, duplicate JSON,
GraphQL introspection, prompt-injection, cache, and registry shapes remain
gaps or application-side concerns. MCP file and system-file arguments are
stopped by the generic `remote-file-inclusion` and `path-traversal` rules, not by an MCP-aware
signature.

### Response-phase leaks

The `response` suite serves a private-key body, a MySQL syntax error, a Django
DEBUG page, a long PHPSESSID cookie, a Python stack trace, a versioned `Server`
header, and benign 404/500 responses from the recording origin. The direct
control must receive each leak. The protected run must produce `response blocked`
events for the four BLOCK rules and must not forward the marker; the LOG-only
stack trace and server version are observed, and the benign bodies must pass
unchanged. The current result is 4 prevented, 2 observed, and 2 benign passes.

### GraphQL complexity

The `graphql` suite sends a 25-level selection, a 1001-alias document, and a
cyclic fragment document, plus a deep GET query and an `application/graphql`
alias flood. The engine rejects all five with `400` and no origin receipt; a
normal query with variables reaches the origin. The result is 5 prevented and 1
benign pass. Shallow GET and `application/graphql` probes reach the origin as
observations, and introspection is logged by
`api-discovery.graphql-introspection`.

### SSRF and XXE canaries

The `ssrf-xxe` suite uses a lab-only fixture on the back network with an
in-process loopback sink and a per-attempt canary file. The direct control must
fetch the sink, read the canary through `file://`, and expand an external entity
to an internal URL; the protected run must not. The result is 4 prevented and 2
benign passes. The single-label host rule (`ssrf.single-label-host`) blocks the
internal DNS-name target `http://vuln:8080/safe`.

### Credential stuffing and password spraying

The `credential-stuffing` suite sends 12 form logins for distinct users with the
same password from one source. The direct control reaches the origin 12 times.
With protection enabled, `login-throttle` allows 10 and blocks the last two with
`403` and `rate_limited` events; the normal client stays healthy. The result is
10 allowed and 2 throttled. The separate `global-auth` suite exercises the
opt-in signed global block for failures spread across sources.

### JWT algorithm policy

The `jwt` suite uses `rules-jwt.yaml` with
`limits.jwt.allowed_algorithms: [RS256]`. A bearer token with `alg: HS256` is
rejected with `403` before rule evaluation; an RS256 token and an opaque bearer
token reach the origin. The result is 1 prevented and 2 benign passes. This is
an explicit local policy, not a generic algorithm-confusion signature.

### Global authentication abuse

The `global-auth` suite uses a protection profile with
`behavior.global_auth.action: BLOCK`, a six-failure window, and a ten-second
ban. Six `401` responses from two independent front sources cross the threshold;
the next auth request from a fresh source gets `429` with no origin receipt and
the mitigation log. The normal client stays at `200`. The result is 2 passed and
1 prevented.

### Agentic TTP chain

The `agentic` suite runs a deterministic Goals/Planner/Worker loop over DVWA and
the CVE-2021-41773 fixture. It does not run the ARTEX tool or an LLM; it models
the reported staged behavior with reviewed requests: recon, exploit selection,
bounded variant adaptation, and canary extraction. DVWA cases cover UNION SQL
injection, command injection through the ping page, and a PHP webshell upload
behind an image content type. The CVE case covers traversal to the lab canary.
The direct control must extract the canary for each exploit; the protected run
must not, and a non-rate-limited WAF block event or the upload-inspection
rejection must corroborate the block. The suite keeps the first-run finding: a
newline command separator bypassed `shell-metacharacters`, so the
`newline-command` rule now covers that shape. The chain is deterministic and
reproducible; it is not a substitute for running the real ARTEX tool or
arbitrary agentic software.

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
but not asserted. The protocol case checks the handshake only; the separate
`websocket` suite exercises post-upgrade payload inspection.

### WebSocket lifecycle and payloads

The `websocket` suite runs a direct control and a protected WebSocket handshake,
then sends a masked PING and requires the matching PONG, a fragmented text
message and requires the origin's concatenated echo, and a close frame and
requires the close handshake. It then sends an XSS message: the direct control
must echo it, while the protected tunnel must close with code `1008` and no
origin echo; a benign message must still be echoed. A separate pair of
connections asks the origin to push a private-key marker right after the `101`:
the direct control must receive it, while the protected tunnel must close with
`1008` and deliver no message; a benign push must still arrive. The independent
normal client must stay at `200`. Messages are reassembled in both directions up
to `limits.websocket_message_bytes`. Client-to-server messages are matched
against body-target rules; server-to-client messages are matched against
response-phase rules that inspect `response_body`, scoped by the `101` handshake
response. WebSocket extensions are not negotiated, so frames stay uncompressed.
Inspection reserves from the process-wide inspection budget in both directions
and closes with `1013` when it is exhausted. Compressed extensions and binary
payload semantics remain outside this suite.

### Pinned tools

goTestWAF, sqlmap, Nuclei, ffuf, and ZAP run the same bounded scan against the
direct control and through Kunato. Their reports, the origin receipts, and
Kunato's block records are joined per case. ZAP runs the authenticated
spider/passive baseline; its active scan is not part of the passing plan. An
endpoint-scoped, observation-only active plan was attempted (SQLi and reflected
XSS paths; file-inclusion/setup/security/logout excluded; `failOnError: false`),
and ZAP 2.17.0 exited at `Job activeScan started` with code 2 and an empty
report. A further attempt to restrict active rules to SQL injection and
reflected XSS supplied `policyDefinition` to the `activeScan` job; ZAP 2.17
rejected it as an unrecognised parameter, so rule-level scoping was not applied.
The plan is not kept in the tree. The pinned image and Docker Hub `latest` share
the same 2.17.0 digest, so active ZAP scanning stays deferred.

### Bounded slow HTTP

`--sandbox-suite slow` opens 8 partial-header connections, holds them for
2 seconds, and checks that the independent normal client still receives `200`.
Kunato's CPU and RSS are recorded before and after, and the containers run under
the 256 MiB and 64-pid ceilings, but this suite does not assert resource
thresholds or restarts; the mixed-load suite does. The probe is the lab's own
raw-socket mode, not slowhttptest.

### Availability boundaries

`--sandbox-suite availability` runs against a dedicated configuration with a
2-second body-read timeout, a 1-second upstream-response timeout, an
8-connection per-source cap, and a 32-connection global cap. It sends a partial
request body and expects `408`, opens a large response without reading it, fills
the per-source connection budget so the next connection gets `503`, then fills
the global budget from four independent `exhaust` sources and requires a fifth
source to get `503` after 2 seconds while `kunato_active_connections` is 32. The
fillers are stopped and the independent normal client must recover to `200`. It then
requests an origin that sleeps past the upstream timeout so the client gets
`504`. The same suite checks RSS, restarts, the normal client, the global
rejection, and the upstream-timeout metric.

### Slow upstream connect

`--sandbox-suite connect` starts Kunato with a dedicated configuration whose
upstream is an unassigned address on the internal `blackhole` network. The TCP
connect exceeds `timeouts.upstream_connect` (1 second), so the client gets `502`
and `kunato_upstream_connect_errors_total` increments. The suite checks RSS and
restarts and requires no origin receipt. This is a connect timeout, not the
upstream-response timeout covered by `availability`.

### Rate-guard backpressure

`--sandbox-suite backpressure` runs against a profile with 20 requests per second
per source, a burst of 20, and a 20-request global rate guard. It sends 100
requests from one source: some must be allowed and the rest shed with `429` or
`503`. After a 1.2-second recovery wait the independent normal client must get
`200`, and the rate-limit or overload counter must move. Accept-queue depth is not
inspected.

### TLS HTTP/3 resource variants

`--sandbox-suite h3` uses a TLS configuration with `http3: { enabled: true }` on
port 8443. A small `h3probe` binary, built from `examples/h3probe.rs` by
`prepare`, sends a normal HTTP/3 request, a malformed-stream flood, and a storm of
reset streams over separate QUIC connections. After each attack a fresh HTTP/3
connection must obtain an origin receipt for `/health`; the independent normal
client, RSS, and restart checks must pass. The probe trusts the lab CA
(`fixtures/tls/ca.pem`).

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

### Restart under load

`--sandbox-suite restart` runs the k6 restart scenario at 20 requests per
second for 25 seconds, sends SIGTERM to Kunato after 5 seconds, and requires
exit code 0 within 12 seconds. It restarts the same container and requires a
`200` recovery from the independent normal client; the k6 summary must retain at
least 100 requests and a check rate above 50%. The report records the exit code,
shutdown time, request count, check rate, recovery, RSS, and normal status. OOM
and forced-kill behavior are not exercised.

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
- The latest full `all` run, `20261027T064248-eb018801`, passed 28 sandbox
  suites: replay, benign, mutations, protocol, common, recent, response,
  graphql, jwt, ssrf-xxe, credential-stuffing, global-auth, agentic, slow,
  availability, connect, h2, h3, backpressure, ban, websocket, load, restart,
  goTestWAF, sqlmap, Nuclei, ffuf, and ZAP. The mixed load recorded 3001
  requests, p95 45.8 ms, p99 46.4 ms, 100% success, normal/recovery `200`, RSS
  28.2 MiB of 256 MiB, no restart, and matching metrics. The restart suite
  recorded exit code 0, a 364 ms shutdown, 501 requests, and a 98.8% check rate.
  The credential-stuffing suite allowed 10 of 12 logins and blocked 2 with
  `rate_limited` events. The global-auth suite counted six failures from two
  front sources and blocked the next auth request with `429`. The SSRF/XXE
  canaries blocked the loopback sink, `file://`, the single-label host, and the
  external entity. The response suite blocked the four response rules and left
  the two LOG-only leaks observable. The GraphQL suite rejected the deep,
  alias-flood, cyclic, deep-GET, and `application/graphql` documents. The h2
  suite passed the bounded server-reset pressure variant. The agentic suite
  prevented all four cases, sqlmap extracted no protected canary, Nuclei and
  ffuf retained their controls, and the authenticated ZAP baseline completed.
  The earlier 2026-10-25 and 2026-10-26 runs remain in the retained evidence
  directories.
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

- The tracker lists Content-Type spoofing, API version/schema abuse,
  session-ID anomalies, business-logic classes (IDOR, coupon/carding, scalping),
  and rule-bypass payloads as absent; HPP, cache deception, JWT tampering and
  algorithm confusion, and distributed authentication abuse are partial. HTTP request smuggling, desync, response splitting, upload
  inspection, and GraphQL abuse are partial. The common/recent suites now
  exercise SSTI, NoSQL, LDAP, XPath, deserialization, CRLF, JWT header attacks,
  response leaks, GraphQL depth/field limits, JWT algorithm policy, SSRF/XXE
  canaries, per-source login throttling, and a two-source global auth block, but
  do not close the absent classes above.
- The WebSocket suite proves the handshake, PING/PONG, fragmented echo, close
  handshake, client-to-server payload block, benign payload echo, and
  server-to-client push block with a benign push delivered. Compressed
  extensions remain unsupported. The 25 mutations and the tool corpora are
  reviewed samples, not the full scanner catalogs.

### Protocol coverage

- The `h2` suite adds TLS-level Rapid Reset, CONTINUATION-flood, oversized
  HPACK, and a bounded server-reset pressure variant (invalid `WINDOW_UPDATE`
  frames on many streams), with a fresh normal HTTP/2 connection after each
  attack. The reset-pressure case is a regression, not an exact MadeYouReset
  reproduction; hyper is listed as not affected. The lab still does not exercise
  SETTINGS floods, stream-state abuse, GOAWAY, priority, h2c, or HTTP/2 resource
  pressure under sustained load.
- TLS termination and HTTP/2 are exercised by the `h2` suite. The `h3` suite adds
  a normal HTTP/3 request, a malformed-stream flood, and reset streams through
  the `h3probe` binary; the lab still does not exercise HTTP/3 stream limits
  under sustained load. HTTP/1.0, pipelining, CONNECT, chunked trailers, and very
  large chunks are not exercised beyond the 12 reviewed cases; the single
  obs-fold case has no variants.
- WebSocket application payloads are inspected in both directions: client
  messages with body-target rules and server messages with response-phase
  `response_body` rules (close `1008` on a match, `1013` on inspection-budget
  exhaustion). Compressed extensions and binary payload semantics are not
  covered.

### Availability coverage

- The slow suite holds 8 partial-header connections for 2 seconds. The
  availability suite adds a slow-body `408`, a slow-read probe, a per-source
  connection cap with `503`, a four-source global cap with `503`, and an
  upstream-response timeout with `504`. The connect suite adds a slow upstream
  TCP connect with `502` and the connect-error metric. The backpressure suite
  adds a low-rate burst with `429`/`503` shedding and recovery. Accept-queue
  depth, true distributed-source exhaustion, and inspection-budget pressure are
  not exercised. The ban suite adds a short-window ban trigger, a recovery request,
  a normal-client check, and the `kunato_banned_total` counter. The restart
  suite adds SIGTERM under load, graceful exit, restart, and recovery.
- The load suite is a fixed 50 requests/second run and now checks Kunato's
  request, block, rate-limit, overload, and upstream-timeout counters. The h2
  suite covers Rapid Reset, CONTINUATION, HPACK, and a reset-pressure variant,
  but SETTINGS floods, GOAWAY/priority abuse, and h2c remain untested.
  Rate-limit window recovery, longer ban windows, and true distributed sources
  remain untested; the global-auth suite uses two front sources, and the
  credential-stuffing suite uses one. OOM and forced-kill behavior under
  pressure are not part of the passing suites.

### Workflows and false positives

- ZAP active scanning is deferred: an endpoint-scoped plan still exited at
  activeScan start with ZAP 2.17.0, and no newer stable image is published. Only
  the spider/passive baseline runs. The benign suite covers a JSON API request,
  a multipart PDF upload, a percent-encoded Japanese query, a 16 KiB text body,
  a chunked response, a GraphQL query with variables, an authenticated API
  request, and a slow chunked stream. Upload variants, i18n edge cases, longer
  streams, authenticated journeys beyond one request, and legitimate WebSocket
  workloads remain outside the corpus.
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

1. Availability: accept-queue depth and true multi-source exhaustion. The
   slow-body, slow-read, per-source and global connection caps, rate-guard
   backpressure, slow upstream connect, upstream-response-timeout,
   ban-recovery, and restart cases are implemented.
2. Benign workflow breadth: upload variants, i18n edge cases, and longer
   streams. The JSON, upload, i18n, large-body, streamed-response, GraphQL,
   authenticated-API, and slow-stream cases are implemented.
3. HTTP/3 lab variants: the `h3` suite now covers normal requests, malformed
   streams, and reset streams; sustained stream-limit pressure remains outside.
4. Restart behavior under load: SIGTERM, graceful exit, restart, and recovery
   are covered by the restart suite; OOM and forced-kill behavior remain
   outside.
5. WebSocket payload coverage: client-to-server body-target inspection and
   server-to-client `response_body` inspection are implemented and lab-tested;
   compressed extensions and binary payload semantics remain outside.
6. ZAP active scanning, endpoint-scoped and observation-only. A separate plan
   was attempted but ZAP 2.17.0 exits at activeScan start even after scoping
   the endpoints and setting `failOnError: false`; revisit when a fixed image or
   add-on is available.
7. Full scanner corpora on a nightly or weekly cadence.

### Limits

A fixed single host and fixed runner make the load numbers trends, not capacity
or distributed-attack claims. The fixtures cover only their bounded scenarios,
and a zero-finding run means the executed cases passed, not that the application
is protected against every bypass. The lab's value is the reproducible
regression loop; the coverage list above is the backlog that keeps it honest.
