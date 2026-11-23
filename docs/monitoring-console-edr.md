# Monitoring console: EDR view

Date: 2026-11-23

Status: Implemented as a read-only view in the delivered console UI. The view
shows the console's live in-memory EDR (`console.edr`) over the latest hourly
evaluation. It does not run the SQLite-backed `kunato edr` command and does not
create a second analyzer process.

Related: [console design](monitoring-console.md),
[console storage](monitoring-console-storage.md),
[EDR verification](edr-verification.md), and
[live EDR verification](edr-live-verification.md).

## 1. Questions the view answers

The view is designed for four operator questions:

| Question | What the view shows |
| --- | --- |
| When did it start? | The finding's `first_seen_ms` and `episode_started_ms` (hourly detection time) plus the failure range inside the evaluated window |
| How often? | `observed_windows`, `episodes`, failures, active minutes, span, and per-minute maximum in the latest window |
| What is it doing? | The detector kind, the targeted authentication path where the analyzer retains it, failure/success counts, and the successful response time |
| Which country? | The GeoIP country of a single-source finding, and of the successful source in a campaign-success finding |

The view cannot answer account-level questions. Kunato does not retain
usernames, passwords, request bodies, query strings, or per-request rows. A
reverse brute force and a campaign success are inferred from source diversity,
endpoint concentration, and the configured success outcome.

## 2. Data path

```text
WAF accepted snapshots
  -> console collector (one-second channel)
  -> LiveEdr (retained minutes and hourly baseline)
  -> live.report(until) every hour at :05
  -> live.record_report(report, detected_at_ms)
       - caps the view report at 50 findings / 20 notes
       - updates the 7-day, 256-record finding ring
  -> edr::build(view) (GeoIP country lookup, detector states)
  -> watch channel
  -> GET /api/v1/edr
  -> console EDR view (60-second refresh while visible)
```

The report itself is unchanged from the offline analyzer: the four detectors,
their evidence, severity, and recommendations. The view adds the ring metadata
(age, observed evaluations, episodes) and the country codes.

## 3. API

`GET /api/v1/edr` is read-only, requires the same session/authentication as the
other console APIs, and returns a bounded JSON object:

```json
{
  "version": 1,
  "now_ms": 1700000300000,
  "enabled": true,
  "stale": false,
  "config": {
    "window_ms": 3600000,
    "baseline_ms": 604800000,
    "report_delay_ms": 300000
  },
  "view": {
    "version": 1,
    "state": "running",
    "error": null,
    "schedule": {},
    "task": {},
    "telemetry": {},
    "detectors": [],
    "findings": [],
    "notes": []
  }
}
```

- `state` is `starting`, `running`, `failed`, or `stopped`. A disabled EDR is
  represented by top-level `enabled: false` with no view.
- `detectors` always contains the four implemented kinds in display order.
- Each detector has `state` (`detected`, `quiet`, `unknown`), `count`,
  `severity`, `last_detected_at_ms`, and a `reason` for `unknown`.
- `findings` contains at most 50 entries. Detector counts come from the full
  report and stay exact when the list is capped.
- `now_ms` is the server clock used for the overdue check. `stale` is computed
  by the server with a 15-minute grace: the last data window is older than the
  window that should have been reported, the next evaluation is more than 15
  minutes overdue, or the report is older than the configured window plus delay
  plus the grace. The UI does not use the browser clock for freshness.
- A disabled EDR returns `enabled: false`, `view: null`, and the schedule. The
  page explains how to enable it instead of showing gray lamps.

The response is guarded by a 1 MiB outer bound. The view itself is bounded by
its construction: 50 findings, 20 notes, four detectors, and fixed evidence
fields.

## 4. Lamp semantics

| State | Appearance | Meaning |
| --- | --- | --- |
| `detected` | Red lamp with a slow pulse | At least one finding of that kind in the latest evaluated window |
| `quiet` | Gray unlit lamp | The window was evaluated and the detector's telemetry is complete, with no finding |
| `unknown` | Amber, dashed card | The detector could not be evaluated: EDR disabled, no report, failed/stopped task, overdue evaluation, or missing/incomplete telemetry |

An `unknown` lamp is never rendered as gray. In particular, the success
detectors are `unknown` when `protection.behavior.auth.success` is unset,
because the analyzer cannot distinguish "no successful login" from "success was
not observed." This is the main safety property of the view.

The lamps describe the **last completed hourly window**, not a live alarm. A red
lamp therefore remains red until the next hourly evaluation. The page shows the
evaluation time, the data window, and the next evaluation time. When the API
marks the view `stale` — the last window is older than expected, the next
evaluation is more than 15 minutes overdue, or the report exceeded the window
plus delay plus grace — all lamps switch to `unknown` while the last received
findings remain visible with a note. This also covers a console restarted after
missing a report window.

## 5. Finding presentation

Each finding carries:

- severity and kind;
- source IP and country for a single-source finding, or the successful source
  and country for a campaign-success finding;
- `first_seen_ms`, `episode_started_ms`, `last_seen_ms`, `observed_windows`, and
  `episodes` from the ring;
- structured evidence, including first/last failure times for all four kinds;
- the analyzer recommendation.

Country codes are resolved from the console's GeoIP database at view-build time
and rendered with the browser's English region names. They are geolocation, not
attribution: DB-IP Lite, VPNs, proxies, CDNs, and shared NAT can make them
misleading. The page states this.

The campaign and reverse detectors have no single source. Their country display
is limited to the campaign-success source when present; the source population's
country distribution is not retained in the current telemetry.

## 6. Persistence and bounds

The latest report and the finding ring are stored in the existing
`<storage_dir>/edr-state.json` (mode 0600). The state version is 2; version-1
files load with an empty view history. The ring:

- keeps the most recent 7 days of findings;
- holds at most 256 records;
- follows the capped 50-finding view list, while detector counts remain exact;
- increments `observed_windows` for every hourly evaluation that contains the
  finding;
- starts a new episode when a finding is absent from the immediately preceding
  report and later reappears, and increments `episodes`.

The full state file remains bounded by the existing 16 MiB guard. Reports are
capped before storage; the ring is pruned on every report.

## 7. Timing and freshness

- The report covers the last complete UTC hour and is generated five minutes
  after the hour (`:05`). A finding near the start of the window can be up to
  about 65 minutes old when it first appears.
- The browser fetches the API when the EDR view opens, when the tab becomes
  visible, and every 60 seconds while the view is visible.
- The API computes `stale` against its own clock; the UI does not compare
  browser time with the report. `now_ms` is informational for diagnostics.
- A missed report window is logged and skipped by the task; the view reports
  the last completed evaluation, not a synthetic catch-up.

## 8. UI structure

The sidebar adds **EDR** under **Observe**, after Real-time monitor and Metrics.
The page contains:

1. a status strip with task state, last evaluation and window, next evaluation,
   and the configured window/baseline;
2. the four lamp cards;
3. the latest findings with evidence and recommendations;
4. telemetry/evaluation health (failure and success telemetry, window summary,
   task retention, and analyzer notes);
5. a footnote covering hourly cadence, LOG-only findings, and the GeoIP
   limitation.

The page is read-only. It has no controls for running the offline analyzer,
changing thresholds, acknowledging findings, or banning sources.

## 9. Limits

- The console must be running and `console.edr.enabled: true`. The WAF's admin
  listener must be reachable as configured.
- Success findings need `protection.behavior.auth.success`. Without it the two
  success lamps are `unknown` and the page says why.
- The view is hourly, not streaming. Fast attacks remain the responsibility of
  rules, rate limits, behavioral bans, and the WAF's other controls.
- The latest window's finding list is capped at 50; the four detector counts are
  exact. Older or non-displayed findings are not browsable in this version.
- The ring tracks the displayed finding list, not every possible finding.
- Reverse/campaign country distribution, per-source paths for slow or success
  findings, and account identity are not available.
- The view never bans, reloads, or changes the WAF. Findings remain LOG-only.

## 10. Verification

```sh
cargo test --lib console::edr
cargo test --lib edr::live
cargo test --lib edr::tests
cargo test --test console_server edr_api_serves_the_published_view_and_rejects_writes
cargo test --test edr_evaluation -- --nocapture
node --check ui/console-web/app.js
```

The tests cover detector-state selection (including missing success telemetry),
the ring's age/episode/cap behavior, state round-trip and version-1 migration, the
API's disabled and failed shapes, and the read-only method guard. The UI check
covers JavaScript syntax without installing Node.js packages.
