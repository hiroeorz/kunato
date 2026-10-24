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

| Direct control | Kunato result | Origin receipt via Kunato | Verdict |
| --- | --- | --- | --- |
| valid | blocked | no | **prevented** |
| valid | allowed | yes | **passed** |
| valid | allowed | no | **gap / failed** |
| invalid | - | - | **inconclusive** |
| - | blocked | - | **false-block** |

A protected result is never trusted unless the direct control proved the case
is valid. The `summarize()` helper marks a sandbox suite passed only when every case
is `passed` or `prevented`; `inconclusive`, `false-block`, `gap`, and `failed`
all fail the run. This fail-closed rule prevents missing evidence from being
reported as defense success.

## Sandbox suite measurements

### Replay and deterministic mutations

The replay corpus pairs SQL injection, XSS, traversal, and comment-obfuscated
UNION probes with benign counterparts and legitimate 302/401/404 responses. The
25 deterministic mutations expand the seeds with case, comment, newline, body
format, parameter pollution, tag, padding, shell-metacharacter, and header-value
variants. Each case is sent directly to the origin and then through Kunato; the
origin proves receipt, method, target, body hash, and nonce.

### Raw protocol and WebSocket

Twelve reviewed cases cover valid keep-alive and chunked exchanges, CL+TE and
TE+CL ambiguity, duplicate Content-Length, obs-fold, a benign CRLF pair,
duplicate Host, an invalid chunk, an oversized header, an HTTP/2 preface, and a
WebSocket handshake. Direct controls use the origin framing modes (`reject`,
`cl`, `te`) to show what the origin would parse; the protected run must not
deliver a smuggled second request. The WebSocket probe sends the handshake,
waits for `101`, sends one masked frame, and requires the origin's `websocket`
event and echo. A handshake check does not imply inspection of later tunnel
messages.

### Pinned tools

goTestWAF, sqlmap, Nuclei, ffuf, and ZAP run the same bounded scan against the
direct control and through Kunato. Their reports, the origin receipts, and
Kunato's block records are joined per case. ZAP runs the authenticated
spider/passive baseline; its active scan is not part of the passing plan.

### Bounded slow HTTP

`--sandbox-suite slow` opens 8 partial-header connections, holds them for 2 seconds,
and checks that the independent normal client still receives `200`. Kunato's
CPU, RSS, restarts, and response are measured against the configured 256 MiB and
64-pid ceilings. The probe is the lab's own raw-socket mode, not slowhttptest.

### Mixed availability load

```text
 t=0   stats before; start k6 (50 rps, 60 s)
 t=2   open 8 slow connections (held 2 s); normal health; stats mid
 t=60  k6 ends; summary (p95/p99, failure rate, checks)
 t=62  stats after; recovery health; restart count
       judge: latency / attack / normal / recovery / resources
```

The k6 constant-arrival-rate scenario runs 50 requests per second for 60
seconds. Its thresholds are p95 < 200 ms, p99 < 500 ms, failed requests < 1%,
and checks > 99%. While it runs, the slow connections and the normal probe are
executed from separate containers. The judge also requires the normal and
recovery probes to return `200`, no Kunato restart, and RSS under the 256 MiB
ceiling. Recovery is checked immediately after the load stops.

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
- The bounded sandbox suites (`all`, `crs`, `protocol`, `slow`, `load`) are run
  locally before committing and pushing. CI runs only the lab observation unit
  tests and the shellcheck wrappers.
- The last `all` run, `20261024T220844-52156979`, passed 10 sandbox suites: replay,
  mutations, protocol, slow, load, goTestWAF, sqlmap, Nuclei, ffuf, and ZAP.
  The mixed load recorded 3001 requests, p95 48.8 ms, p99 48.9 ms, 100%
  success, normal/recovery `200`, RSS 21.8 MiB of 256 MiB, and no restart.
- Evidence stays under `target/security-lab/<run-id>/`: the per-phase probes,
  origin and Kunato logs, tool reports, `report.md`, and `report.json`.
- The sandbox suite list, commands, and limits are documented in
  [lab usage](../lab/README.md); the target design and cadence are in
  [the adversarial testing design](security-testing.md).
