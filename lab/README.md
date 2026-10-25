# Local security lab

This covers the first four milestones of the [adversarial testing design](../docs/security-testing.md):
an isolated recording origin, direct receipt controls, and seventeen bounded
sandbox suites (the optional CRS comparison is not part of `all`). It runs curated
goTestWAF probes, a DVWA/sqlmap SQL-injection comparison, a Nuclei canary
against an Apache 2.4.49 CVE-2021-41773 fixture, an ffuf
path-discovery/enumeration comparison, an authenticated ZAP spider/passive
baseline, 25 deterministic mutation variants, 12 raw protocol/WebSocket cases,
TLS/HTTP/2 resource variants, benign JSON/upload/i18n/large-body/streaming
workflows, bounded slow-HTTP, availability, slow-connect, ban-recovery, and
WebSocket lifecycle and payload probes, a pinned
k6 v2.3.0 mixed availability load, a restart-under-load probe, and a pinned
OWASP CRS 4.3.0 comparison. It measures
request rejection, bounded exploit prevention, and availability on a fixed
runner; the fixtures do not prove protection for arbitrary applications or
capacity. The
[testing model](../docs/security-lab-testing-model.md) explains the control and
evidence flow, the verdict rules, and the sandbox suite diagrams. ZAP active
scanning is deferred: ZAP 2.17.0 exits at activeScan start even in an endpoint-scoped plan
(code 2, empty report), and no newer stable image is published, so
active-injection coverage stays with sqlmap, Nuclei, and goTestWAF.

## Run locally

Requirements: a Linux amd64 host, Docker Engine with Compose 2.24.4 or later,
Python 3.11 or later, and the repository's Rust toolchain. Use a disposable VM
for adversarial work. The Compose environment has no published ports, host
networking, privileged containers, or Docker-socket mounts. Internal Docker
networks do not by themselves establish isolation from every host service.

```sh
# Preparation may download the locked images, build the CVE fixture, and build
# the current Rust source.
scripts/security-lab.sh prepare

# Verify cached images, fixture, template, and source hashes without downloads.
scripts/security-lab.sh verify

# Direct controls, followed by WAF inspection of attacks and benign guards.
scripts/security-lab.sh run

# Add one sandbox suite, or run every sandbox suite in sequence.
scripts/security-lab.sh run --sandbox-suite benign
scripts/security-lab.sh run --sandbox-suite gotestwaf
scripts/security-lab.sh run --sandbox-suite sqlmap
scripts/security-lab.sh run --sandbox-suite nuclei
scripts/security-lab.sh run --sandbox-suite ffuf
scripts/security-lab.sh run --sandbox-suite zap
scripts/security-lab.sh run --sandbox-suite mutations
scripts/security-lab.sh run --sandbox-suite protocol
scripts/security-lab.sh run --sandbox-suite h2
scripts/security-lab.sh run --sandbox-suite slow
scripts/security-lab.sh run --sandbox-suite availability
scripts/security-lab.sh run --sandbox-suite connect
scripts/security-lab.sh run --sandbox-suite ban
scripts/security-lab.sh run --sandbox-suite websocket
scripts/security-lab.sh run --sandbox-suite load
scripts/security-lab.sh run --sandbox-suite restart
scripts/security-lab.sh run --sandbox-suite crs   # optional CRS comparison, observation only
scripts/security-lab.sh run --sandbox-suite all
```

Execution always uses local image IDs with `pull_policy: never`; it does not
install or update scanners, rules, or templates. `prepare` must be repeated after
a Rust source, image-lock, fixture, or template change. Rules, cases, fixtures,
and templates are copied from the current worktree into an immutable input
snapshot at the beginning of each run.

## Isolation and fixtures

The Compose environment uses three `internal: true` networks:

- `front`: the client and attack tools, plus Kunato's listening side;
- `back`: the recording origin, Kunato's upstream side, temporary direct-control
  runners, and the vulnerable fixtures;
- `data`: the DVWA database and DVWA only.

Kunato joins `front` and `back`; the protected client joins only `front`; the
direct controls join `back` for one short-lived container per attempt. The
preflight confirms that every active network is internal, no service publishes a
port, and the protected client cannot resolve or reach the active fixture or
database IPs. Fixture ports are never published. Tools run as an unprivileged
user with a read-only root filesystem; the intentionally vulnerable DVWA,
MariaDB, and Apache fixtures keep their upstream users and only the capabilities
their startup needs. They are disposable, have no host mounts, and must never be
exposed outside this lab.

The prepared inputs are pinned in `artifacts.lock.json`:

| Input | Purpose |
| --- | --- |
| `python` image | recording origin, probes, and Kunato's runtime base |
| `gotestwaf` image | curated payload/placement/encoding sweep |
| `mariadb` image | DVWA database, recreated from tmpfs for every phase |
| `dvwa` image | SQL-injection, path-discovery, and benign-page fixture; authentication disabled except for ZAP, security level low |
| `sqlmap` image | direct and protected SQL-injection dump |
| `nuclei` image | CVE-2021-41773 template execution |
| `ffuf` v2.3.0 binary | bounded path discovery and enumeration behavior |
| `zap` image | authenticated spider/passive baseline |
| `grafana/k6` image | pinned k6 v2.3.0 mixed availability load |
| `crs` image | optional OWASP CRS 4.3.0 reference comparison |
| `httpd` image | base for the lab-only CVE-2021-41773 fixture |

The CVE fixture is built during `prepare` from the pinned `httpd` base and the
Dockerfile in `fixtures/httpd-cve-2021-41773/`. It enables the traversal surface
and writes a per-attempt canary under `/opt/kunato-lab/`. The Nuclei template in
`templates/cve-2021-41773-canary.yaml` is a local canary adaptation of the
upstream CVE template; it is not an upstream-signed template. The fixture keeps
the Apache event MPM inside a 64-pid budget.

## Sandbox suites

### Replay and goTestWAF

`cases/smoke.json` pairs SQLi, XSS, traversal, and comment-obfuscated UNION
probes with benign counterparts and includes legitimate 302/401/404 responses.
The recording origin proves receipt, method, target, body hash, and nonce. The
goTestWAF plan derives one payload, encoder, and placement per applicable case
and uses the fixed lab User-Agent. Direct controls must receive every planned
case before the protected results are evaluated. Every case executes with an
ordinary fixed User-Agent; scanner-fingerprint recognition is deliberately not
claimed here. The lab removes the whole private-source `trusted-sources`
category and disables automatic protection.

### Benign workflows

`cases/benign.json` adds a legitimate JSON API request, a multipart PDF upload,
a percent-encoded Japanese query, a 16 KiB text body, a chunked response, a
GraphQL query with variables, an authenticated API request, and a slow chunked
stream. The direct control must receive every case, and the protected run must
forward it with the exact origin metadata, status, and body hash. These cases
exercise the default form guard, upload inspection, content-type decoding,
GraphQL limits, auth header/cookie forwarding, chunked response forwarding, and a
sustained chunked stream without relying on an attack signature. They are
included in `all` and fail the suite on any false block.

### sqlmap

`sqlmap` compares a direct DVWA SQL-injection dump with the same bounded dump
through Kunato. Each phase recreates the MariaDB tmpfs and the DVWA container,
runs the setup, and seeds a fresh `lab_canary` row. The direct control must dump
that canary; the protected phase uses a second canary and must not retrieve it.
The verdict is exploit prevention, not request rejection: the report records
blocked requests, requests that reached the origin, and the rule names. On the
current rule set the protected run blocked the UNION dump but some column-count
and parameter probes reached the origin; no canary was extracted. Those probes
remain visible in the report rather than being presented as a clean sweep. A
confirmed bypass of the older fixed-gap `union-select` rule was found with a
padded `/*...*/` comment and is now fixed and retained as an attack/benign pair.

### Nuclei

`nuclei` runs a pinned canary template against the CVE-2021-41773 fixture. The
direct control must read the canary and match with the lab User-Agent; the
protected phase must not extract it. The report requires no fixture receipt for
the blocked paths and records the rule names. The current rules stop both the
`/icons` traversal and the `/cgi-bin` command with `dot-dot-slash` and
`shell-metacharacters`, with no origin receipt. The template is run with update
checks and interactsh disabled; the wrapper creates an empty templates
directory so Nuclei never tries to download the default catalog.

### ffuf

`ffuf` runs the same 29-path wordlist directly against DVWA and through Kunato.
The discovery phase compares status and body length, requires an origin receipt
for allow/log paths, requires no protected receipt plus a matching block event
for block paths, and requires a LOG event for logged admin paths. The behavior
phase enables the lab protection, lets the ffuf source enumerate missing paths
until the enumeration threshold fires, and then requires 403/429 responses,
fewer distinct origin receipts, and a healthy normal client from a separate
source. The normal client is a long-lived container so its address cannot reuse
the banned ffuf source. The direct control sends the lab `Host` header so the
fixture's host-dependent 404 and setup pages compare like for like.

### ZAP authenticated baseline

The ZAP plan authenticates to DVWA with the seeded `admin`/`password` account,
spiders the authenticated application, runs the passive scan, and writes a JSON
report. The direct control and the protected run must both discover the
authenticated pages (at least 80% of the control count) and produce a report;
the normal client must stay healthy and the protected run records any blocked
requests. This verifies the authenticated workflow across the WAF; it does not
claim active-scan defense. The plan intentionally omits `activeScan`. A scoped
observation-only plan was also attempted: it limited scope to SQLi and reflected
XSS, excluded file-inclusion/setup/security/logout, and set `failOnError: false`,
but ZAP 2.17.0 still exited at `Job activeScan started` with code 2 and no
report. Active injection defenses remain covered by the sqlmap, Nuclei, and
goTestWAF sandbox suites.

### Deterministic mutations

`cases/mutations.json` contains 25 reviewed variants derived from the replay
and black-box seeds. Every entry records the seed, deterministic transform, and
interpretation. The direct control must receive every variant with the exact
method, target, body hash, and User-Agent; the protected run must block all 15
attacks with a matching Kunato rule and no origin receipt, and pass all 10
benign near-misses. The cases cover keyword case, block comments, newlines,
body formats, parameter pollution, alternative XSS tags, dot padding, shell
metacharacters, and header values. The mutation table in the report retains the
seed, transform, and interpretation through `report.json`.

### Protocol boundaries

`cases/protocol.json` contains 12 reviewed raw HTTP/1.1 and WebSocket cases: a
valid request with `Connection: close`, a chunked body, CL+TE and TE+CL
ambiguity, duplicate Content-Length, obs-fold, a benign CRLF pair, duplicate
Host, an invalid chunk, an oversized header, an HTTP/2 preface, and a WebSocket
handshake plus echo. Each case has a WAF-less direct control and a protected
run. The direct controls use the origin framing modes (`reject`, `cl`, `te`) to
prove how the origin parses the bytes; the protected run must not deliver a
smuggled request, must block or reject malformed framing, and must allow the
benign and WebSocket exchanges. The WebSocket check sends the handshake, reads
the response headers, sends one masked frame, and requires a `101` status plus
the origin `websocket` event; the echo is recorded but not asserted. Kunato's
request-head checks reject duplicate Host, duplicate Content-Length, CL+TE, and
non-chunked Transfer-Encoding before forwarding. The current result is 4 passed
and 8 prevented. The `h2` suite below adds TLS-level HTTP/2 resource variants;
HTTP/3 remains in the Rust proxy tests.

### WebSocket lifecycle and payloads

`--sandbox-suite websocket` runs a direct control and a protected WebSocket
handshake. It sends a masked PING and requires the matching PONG, sends a
fragmented text message and requires the origin's concatenated echo, and sends a
close frame and requires the close handshake. It then sends an XSS message
through a separate connection: the direct control must echo it, while the
protected tunnel must close with `1008` and no origin echo. A benign message must
still be echoed on the protected path. The independent normal client must stay at
`200`. The current result is 8 passed with PONG, the `echo:fragmented` response,
the close handshake, a `1008` payload block, and the benign payload echo.

### TLS HTTP/2 resource variants

`--sandbox-suite h2` uses `rules-h2.yaml` with TLS on port 8443 and the lab
certificate under `fixtures/tls/`. It runs a normal HTTP/2 request, then Rapid
Reset, a CONTINUATION flood, and an oversized HPACK header block on separate TLS
connections. After each attack a fresh HTTP/2 connection must obtain an origin
receipt for `/health`, while the independent normal client and RSS/restart checks
must pass. The attack connection may be closed or reset by Kunato. HTTP/3/QUIC is
not part of the container suite: no pinned QUIC client is available, and the Rust
proxy tests cover a malformed raw HTTP/3 request stream. The current result is
7 passed: normal, Rapid Reset, CONTINUATION, HPACK, independent, resources, and
metrics; 21.1 MiB RSS and no restart.

### Slow HTTP

`--sandbox-suite slow` opens 8 bounded slow connections with partial headers,
holds them for 2 seconds, and checks that the independent normal client still
receives `200` and that Kunato stays up. CPU and RSS are recorded before and
after, and the containers run under the 256 MiB / 64-pid ceilings, but this
suite does not assert resource thresholds or restarts; the mixed-load suite
does. The probe is the lab's own raw-socket mode (`lab/probe.py slow`), not
slowhttptest. The current result is 2 passed: 8 connections held, normal 200,
CPU 0.01-0.03%, RSS 21.1-21.4 MiB.

### Availability boundaries

`--sandbox-suite availability` uses `rules-availability.yaml` with a 2-second
body-read timeout, a 1-second upstream-response timeout, an 8-connection
per-source cap, and a 16-connection global cap. It holds partial request bodies
(expecting `408`), opens a large response without reading it, fills the
per-source connection budget (the next connection must get `503` while the
independent normal client stays `200`), fills the global budget from two
independent `exhaust` sources (a third source must get `503` with
`kunato_active_connections` at 16), requests an origin that sleeps beyond the
upstream timeout (expecting `504`), and asserts the normal probe, RSS, restarts,
the global rejection, and the upstream-timeout metric. The fillers are stopped
and the normal client must recover to `200`. The current result is 9 passed:
slow-body `408`, slow-read `200`, per-source and global caps at `503` (16 active
connections), upstream `504`, normal `200`, no restart, and RSS 23.2 MiB.

### Slow upstream connect

`--sandbox-suite connect` uses `rules-connect.yaml`, whose upstream is an
unassigned address on the internal `blackhole` network. Kunato's TCP connect
exceeds `timeouts.upstream_connect` (1 second), so the client gets `502` and
`kunato_upstream_connect_errors_total` increments. The suite checks RSS and
restarts and requires no origin receipt. This is a connect timeout; the
upstream-response timeout remains covered by `availability`. The current result
is 3 passed: status `502`, one upstream connect error, no restart, and RSS
21.0 MiB.

### Ban recovery

`--sandbox-suite ban` uses `rules-ban.yaml` with one request per second, a burst
of one, two ban violations, and a two-second ban. The probe sends ten requests
from one source, requires a `429` ban, waits for the ban to expire, and requires
a `200` recovery. The independent normal client must stay at `200`, and the
`kunato_banned_total` counter must reflect the ban. A distinct probe suite keeps
ban recovery separate from the availability boundaries. The current result is
5 passed: the trigger statuses include `429`, recovery is `200`, and the normal
client stays at `200`.

### Mixed load

`--sandbox-suite load` runs a pinned k6 v2.3.0 constant-arrival-rate scenario
(50 requests/second for 60 seconds) from the `load` service, concurrently opens
the bounded slow connections from the `client` service, and probes the normal
path from the same independent client. The k6 thresholds are at least 1,000
requests, p95 < 200 ms, p99 < 500 ms, failed requests < 1%, and checks > 99%;
the judge also requires the normal and recovery probes to return 200, no Kunato
restart, and RSS under the 256 MiB ceiling. Recovery is checked immediately
after the load stops. The `load-metrics` case also checks that Kunato's request
counter covers the k6 workload and that no block, rate-limit, overload, or
upstream-timeout counter moved. The current result is 6 passed: 3001 requests,
p95 48.1 ms, p99 48.4 ms, 100% success, 8 slow connections held, normal and
recovery 200, RSS 21.8 MiB, no restart, and matching metrics.

### Restart under load

`--sandbox-suite restart` starts a 20 requests/second k6 run for 25 seconds,
sends SIGTERM to Kunato after 5 seconds, and requires a graceful exit (code 0)
within 12 seconds. It restarts the same container and requires a `200` recovery
from the independent normal client; the k6 summary must retain at least 100
requests and a check rate above 50%. The report records the exit code, shutdown
time, request count, check rate, recovery, RSS, and normal status. OOM and
forced-kill behavior are not exercised. The current result is 4 passed: exit
code 0, a 389 ms shutdown, 500 requests, a 98.6% check rate, recovery and normal
`200`, and RSS 21.4 MiB.

### OWASP CRS comparison

`--sandbox-suite crs` runs the same 25 mutation cases directly through a pinned
OWASP CRS 4.3.0 reverse proxy and through Kunato, then reports the per-case
agreement. The 2026-10-24 comparison agreed on all 15 attacks (`agree-block`)
and all 10 benign cases (`agree-allow`). This is an observation, not a gate:
CRS rule IDs, paranoia, and fixture-specific behavior are not Kunato's
specification. The CRS service joins the front and back networks; its image's
unprivileged `httpd` user writes the rendered config and logs, so this
comparison fixture has an exception to the read-only tool filesystem rule.

## Evidence and case changes

Each run prints its directory under `target/security-lab/`. It retains:

- `manifest.json`: commit, source/binary hashes, image and fixture IDs, and input
  hashes;
- `input/`: exact rules, case definitions, scanner plans, fixtures, templates,
  code, and binary;
- `control/` and `replay/`: fresh attempt IDs, health probes, client exchanges,
  origin events, Kunato JSON logs, and metrics;
- `benign-control/` and `benign/`: direct and protected JSON, upload, i18n,
  large-body, streamed-response, GraphQL, authenticated-API, and slow-stream
  exchanges;
- `gotestwaf-control/` and `gotestwaf/`: direct/protected scanner reports and
  origin observations;
- `sqlmap-control/` and `sqlmap/`: dump output, exit codes, DVWA access logs,
  health probes, and Kunato logs;
- `nuclei-control/` and `nuclei/`: Nuclei JSONL, runner logs, CVE access logs,
  health probes, and Kunato logs;
- `ffuf-control/`, `ffuf/`, and `ffuf-behavior/`: ffuf JSON reports, runner logs,
  DVWA access logs, health probes, and Kunato logs;
- `zap-control/` and `zap/`: authenticated ZAP plan logs and JSON reports, DVWA
  access logs, health probes, and Kunato logs;
- `mutations-control/` and `mutations/`: direct and protected mutation probes,
  origin logs, and Kunato logs;
- `crs-control/`, `crs-kunato/`, and `crs/`: CRS-comparison direct control,
  Kunato baseline, CRS probe results, origin logs, and the ModSecurity audit;
- `protocol-control-*/` and `protocol/`: direct and protected protocol probes,
  per-framing origin receipts, and Kunato logs;
- `slow/` and `load/`: slow-connection probes, k6 summary and logs, health
  probes, metrics, and Kunato logs;
- `availability/`: slow-body, slow-read, per-source connection-cap,
  global-connection-cap, and slow-upstream probes, health probes, metrics, and
  Kunato logs;
- `connect/`: the blackhole-upstream request, connect-error metrics, health
  checks, and Kunato logs;
- `h2/`: TLS/HTTP/2 normal, Rapid Reset, CONTINUATION, and HPACK probes, origin
  receipts, health checks, metrics, and Kunato logs;
- `ban/`: ban-trigger statuses, recovery probe, health, metrics, and Kunato
  logs;
- `websocket-control/` and `websocket/`: direct and protected PING/PONG,
  fragmented echo, close-handshake, XSS payload-block, and benign payload probes,
  plus health;
- `restart/` and `restart-recovery/`: SIGTERM shutdown, k6 summary and logs,
  restart exit code, recovery probes, and normal-client health;
- `report.json` and `report.md`: case verdicts, counts, rule names, notes, and
  diagnostics;
- `commands.jsonl` and `cleanup.json`: executed commands and verification that
  the run's containers, networks, and named volumes have been removed.

```sh
scripts/security-lab.sh report target/security-lab/<run-id>
scripts/security-lab.sh down target/security-lab/<run-id>
```

Reports exit with failure when a required control or observation is missing, a
tool fails, an attack reaches the origin in a replay case, a legitimate exchange
changes, or a sandbox suite is inconclusive. Containers and project networks are
removed after the run, including on ordinary failure. `down` cleans only the
identified lab project if a controller was forcibly interrupted; evidence is
retained.

Validate collector and verdict failures locally:

```sh
python3 -m unittest discover -s lab/tests -v
```

The separate security-lab workflow runs these observation tests and the
shellcheck wrappers. Run the `all` sandbox suite and the optional CRS comparison
locally before committing and pushing; CI does not execute the bounded
sandbox suites. The daily CVE publishing workflow is unchanged. The CVE-2021-41773
canary rows are also in `blackbox/requests/` so the ordinary black-box gate
retains the request shapes.

## Limits

The recording origin cannot prove exploit prevention, and the DVWA/CVE fixtures
prove only their bounded scenarios. A missing signature, a fixture mismatch, a
blocked tool, or an inconclusive collection fails the run; it is never counted
as defense success. The lab does not test arbitrary applications, distributed
sources, Internet link saturation, or capacity; the slow and load results are
fixed-runner trends with explicit ceilings, not proof against a botnet. The
authenticated ZAP baseline covers login, spider, and passive discovery; active
scanning is not part of the passing plan, and the active injection defenses
remain the sqlmap/Nuclei/goTestWAF sandbox suites. The mutation corpus, the protocol
cases, and the CRS comparison are bounded to the reviewed seeds, fixtures, and
framing interpretations. The benign corpus has one case per selected workflow
(eight total), the availability suite covers body-read timeout, slow reads, the
per-source and global connection caps, and upstream-response timeout, the
connect suite covers slow upstream connection establishment, the ban suite
covers ban recovery with a short window, and the restart suite covers graceful
SIGTERM under load. Queue/backpressure, true distributed-source exhaustion, OOM
or forced-kill behavior, server-to-client WebSocket frames, and compressed
WebSocket extensions are not covered. The Rust proxy tests add HTTP/3 malformed
request streams, hot reload under load, and rules update plus reload under load;
HTTP/3/QUIC is not exercised in the container lab. Those paths are not part of
this container suite.

The fixtures and tools retain their upstream licenses and provenance: the DVWA
image and source, MariaDB, Apache httpd 2.4.49, sqlmap, Nuclei, goTestWAF,
ffuf, ZAP, the OWASP CRS image, and the upstream [nuclei-templates CVE-2021-41773
template](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-41773.yaml)
and [Vulhub reproduction](https://github.com/vulhub/vulhub/tree/master/httpd/CVE-2021-41773).
The canary template and fixture configuration are lab adaptations; their hashes
are recorded in `artifacts.lock.json` and the run manifest.
