# Live in-memory EDR source: verification

Date: 2026-11-23

Status: Implemented as an opt-in console task (`console.edr`). A standalone
daemon is not implemented. The SQLite-backed `kunato edr` command remains the
supported offline analyzer. This document covers the evaluation that led to
the console integration.

## 1. Proposed change

Replace the EDR's SQLite source with a resident process that, like the console,
polls the WAF's bounded `/console/snapshot` endpoint. A five-minute poll was
proposed. The process would:

1. receive only the bounded authentication-failure measurements;
2. keep a rolling window in memory;
3. maintain hourly evidence for the baseline;
4. run the existing detection rules once per hour.

The state machine is `src/edr/live.rs`; the simulation is
`tests/edr_live.rs`; the console task is `run_edr` in
`src/console/runtime.rs`. It uses the existing WAF snapshot, so no WAF endpoint
or telemetry change is required. The console task uses the collector's
one-second accepted stream, so the five-minute gap analysis below applies only
to a standalone poller.

## 2. Verdict

| Question | Result |
| --- | --- |
| Is the in-memory source viable? | Yes for the hot path. The state is small and the detection rules are the same code used by the SQLite analyzer. |
| Does it match the SQLite findings? | In the 18-hour simulation, all 16 hourly windows produced the same finding set as the SQLite analyzer over the same traffic. |
| How much memory does it use? | 143 KB of measured payload for 18 hours; 156 KB for a full seven-day baseline with 73 retained minutes. The 7-day state is bounded at roughly 169 hourly aggregates and 73 minute buckets. |
| Is five-minute polling safe? | In steady state, yes. But the WAF snapshot ring holds ten minutes and a five-minute cadence gives each minute only one completion opportunity. One skipped five-minute poll loses the boundary minute; the prototype reports the gap and marks the window incomplete. |
| What is the safe cadence? | Four minutes tolerates one skipped poll. One minute (the console cadence) gives more margin but increases snapshot traffic. The console polls every second and is unaffected. |
| What happens on an EDR restart? | The window and baseline are lost. The first report after a restart contains only the minutes from the latest snapshot (four complete minutes in the test), no slow finding, and a warm-up note. |
| Should it block automatically? | Not from this prototype. The earlier caveats about hourly latency, shared NAT, and the control-plane surface still apply. |

## 3. State model

`LiveEdr` keeps two bounded maps.

| State | Contents | Bound in the test |
| --- | --- | --- |
| `minutes` | Per WAF generation and UTC minute: the bounded `MetricBucket` with `AdditionalMeasurements` authentication fields | Detection window plus the 12-minute rolling margin. A one-hour window retained 73 buckets. |
| `hours` | Per UTC hour: total authentication failures, top-16 sources, top-16 paths, and the distinct-source sketch | Baseline duration, seven days. The test retained 169 hourly aggregates. |

Additional state: a set of minutes already folded into the hourly baseline, a
bounded list of collection gaps, the last observed snapshot time, the last
generation and missed-update counter, and a clock-discontinuity flag.

The hot path is SQLite-free:

```text
GET /console/snapshot (bounded JSON)
  -> validate StatisticsSnapshot
  -> replace each (generation, minute) with a higher revision
  -> keep the last window + ring minutes
  -> fold minutes older than the ring into one HourAuth
  -> every hour, build WindowData + Baseline and run the existing rules
```

Only the bounded authentication measurements are retained. The state does not
keep raw requests, usernames, passwords, bodies, or query strings. The WAF
snapshot's 256 KB envelope and ten minute buckets bound each input.

## 4. Poll cadence: the important finding

The WAF keeps ten minute slots (`MINUTE_SLOTS`) and includes the current partial
minute in the snapshot. For a minute `m`:

- the minute is complete at the first poll after `m + 1 minute`;
- it remains in the ring until a poll at `m + 9 minutes`;
- a five-minute cadence gives polls at roughly `m + 5` and `m + 10`; the second
  one already excludes `m`.

Therefore a five-minute cadence has **one opportunity** to capture each
minute. A skipped poll loses the boundary minute. The simulation skips one
five-minute poll and observes:

```text
last snapshot: 12:00 (12:00 minute partial)
next snapshot: 12:15 (minutes 12:06..12:15)
gap:            12:00 .. 12:01
report:         incomplete, with a collection-gap note
```

A four-minute cadence has two opportunities (`m + 4` and `m + 8`) inside the
ten-minute ring, so one skipped poll is covered. The test skips the middle poll
at a four-minute cadence and observes no gap.

Options if five minutes is required:

1. Increase `MINUTE_SLOTS` from 10 to 12 or more. This increases the WAF's
   snapshot size and every snapshot consumer's payload; it is a shared change.
2. Accept one-minute boundary gaps and keep them visible. The detector already
   marks the window incomplete, but the lost minute cannot be reconstructed.
3. Use the console's one-second stream (integration) or a four-minute EDR
   cadence. This is the least invasive option.

Five-minute polling is still fine for detection quality; it is a **gap
tolerance** question, not a detection-window question. The 72–73 minute retention
(60-minute window plus the rolling margin) is unaffected.

## 5. Simulation results

The simulation generates 18 hours of one-minute traffic and feeds the live
state at five-minute intervals. It covers:

- 3 background requests per minute;
- a five-source benign failure pattern;
- a shared-egress probe: 12 failures in one hour;
- a slow source: one failure every six minutes for four hours;
- a distributed campaign: 60 sources, one failure each, on `/login`;
- a 20-source benign reset wave;
- a single-source 20-failure burst.

The observed 206 snapshots retained 73 minutes and 18 hourly aggregates, about
143 KB of measured payload. There were no gaps.

| Traffic hour | Report ends at | Ground truth | Live finding |
| --- | --- | --- | --- |
| 1–8 | next hour | benign | none |
| 9 | 10:00 | shared egress | slow `198.51.100.10` (false positive) |
| 10 | 11:00 | slow attack starts | slow `203.0.113.7` |
| 11–13 | 12:00–14:00 | slow attack continues | slow `203.0.113.7` in every window |
| 14 | 15:00 | distributed campaign | reverse campaign |
| 15 | 16:00 | benign reset wave | none |

The slow source was detected in all four attack windows. The distributed
campaign was detected in its window. The shared-egress probe remained the known
false positive.

The test also builds the same traffic into a temporary `history.sqlite3` and
runs the SQLite analyzer for every one of the 16 report windows. The live and
SQLite finding sets were identical. The detection code is shared; the test
confirms that the live source's revision handling, rolling aggregation, and
baseline view do not change the verdicts in this corpus.

Seven days of benign polling retained 169 hourly aggregates and 73 minute
buckets, about 156 KB of measured payload. With top-16 source and path entries
in every hour, the hourly map remains in the low hundreds of kilobytes; the
bound is fixed by the baseline duration and the ranking caps.

## 6. Restart behavior

Without a restored state, a new `LiveEdr` starts with no window and no
baseline. This is the cold-start behavior; the console task mitigates it by
saving and loading a compact state file. At 11:05, the first
snapshot contains only the last ten minutes. The report for 10:00–11:00:

- covers four complete minutes (10:56–10:59);
- contains no slow finding, because the state did not see the earlier failures;
- reports a baseline of zero hours;
- carries a "window is still warming up" note.

After one hour the state has a full detection window. After 24 hours it has a
useful baseline. A reverse campaign with enough volume can still be flagged
without a baseline because the campaign rule's baseline branch is optional when
no baseline exists; a slow *known* source loses its per-source baseline and is
treated as a new source until the baseline warms.

Without the state file, this is the main cost of removing SQLite. The console
task persists a compact state file, not the full history:

- the last seven days of hourly `HourAuth`;
- the last window plus ring of minute buckets;
- generation, last observed time, missed-update counter, and gaps.

The file is small (low hundreds of kilobytes), does not use SQLite, and is
written atomically every five minutes, after each hourly report, and on
shutdown with mode 0600 in the storage directory. It restores the baseline and
window after a restart. It does not recover minutes lost while the console was
down; those still appear as gaps. A corrupt or oversized file is logged and
ignored, and the task starts empty.

## 7. Other operational findings

- **Generation changes.** The minute key includes the WAF generation. A WAF
  restart does not overwrite the previous generation's buckets; the report sums
  the partial minute across both generations. The live state does not need the
  WAF's sequence to be monotonic across restarts.
- **Revisions.** Repeated snapshot buckets are replaced only by a higher
  revision. A late revision after the rolling cutoff is ignored and marks the
  window incomplete; it is not counted twice.
- **Gaps.** A gap is recorded when the next snapshot's earliest minute is
  later than the last observed timestamp, or when the WAF reports an increase
  in missed updates. The report filters gaps to the current window and adds a
  note.
- **Clock changes.** A backwards step or a WAF clock discontinuity marks the
  affected windows incomplete. The flag clears after the baseline/window
  retention horizon instead of poisoning every later report.
- **Memory/CPU.** Ingest is O(number of snapshot buckets) with small bounded
  maps. The 206-snapshot simulation, including 16 SQLite comparisons, finished
  in well under a second on the development machine.
- **No per-site attribution.** The WAF's authentication measurements are
  global for the source-minute. A live EDR report cannot split failures by
  site; the existing SQLite analyzer has the same limitation for these fields.
- **No immediate enforcement.** The console task produces the same `Report`
  and findings as the offline analyzer. It does not call the WAF's ban state.

## 8. Recommended architecture

### Option A: separate resident EDR (matches the proposal)

- Poll every **four minutes** by default, not five, unless the WAF ring is
  increased. Four minutes gives one-missed-poll tolerance without a WAF change.
- Run the hourly report at five minutes past the UTC hour, using the last
  complete hour.
- Persist the compact state file every hour; load it at startup.
- Expose health: last successful poll, last successful report, snapshot gaps,
  retained minutes/hours, finding count, and state-file write result.
- Run as the `kunato` user with a hardened systemd unit; no SQLite dependency
  for the EDR.
- Keep findings at LOG. If enforcement is added later, use a separate
  loopback-only control plane with TTL, allowlist, and audit, not direct writes
  to the WAF state.

### Option B: integrate with the console

The console already polls every second, owns the snapshot stream, and has a
dedicated storage worker. Feeding the same snapshots into `LiveEdr` in-process
removes the poll-gap problem and avoids a third process. The tradeoff is that
the console becomes the owner of EDR state and findings; if findings are stored
in the console database, the console's read-only contract and schema change.
If they are stored in a separate state file, the contract is easier to keep.

### Option C: keep SQLite for history

Keep the SQLite analyzer for investigations and backfill, and use the live
source only for the hourly hot path. This gives the best of both: no polling
gap for the live state, and durable history for replay and baseline recovery.
The console already pays the SQLite cost; the EDR need not duplicate it.

**Recommendation:** Option B is implemented as the opt-in `console.edr` task.
Option C remains the right role for the SQLite analyzer (history, backfill, and
investigation). Option A is still available as a future standalone design, but
it needs a four-minute cadence and a compact state file; five-minute polling
alone is not sufficient for one-missed-poll tolerance.

## 9. Limits

- The application must still return `401`/`403` on failed authentication.
- The default authentication path list must cover the application's login
  endpoint, or `protection.behavior.auth.paths` must be extended.
- The WAF snapshot is global; per-site attribution is not available.
- Top-16 per minute and the 64-register distinct sketch bound accuracy.
- The console task has a compact durable state, not full history. A standalone
  daemon would need to schedule the same `save`/`load` calls itself.
- A restart restores the last saved state; minutes lost before that save, or
  while the console was down, remain gaps.
- A report must run within the retention margin (window plus ring, 72–73
  minutes for a one-hour window). A report delayed beyond that loses its
  earliest minutes and is marked incomplete.
- The console task is not a standalone daemon; it runs only while the console
  is enabled. Findings are journald-only, and enforcement is out of scope.
- The state file survives a console restart, but minutes lost while the console
  was down remain gaps.

## 10. Reproduction

```sh
cargo test --test edr_live -- --nocapture
cargo test --lib edr::live
cargo test --test console_server runtime_runs_the_console_edr_task_and_saves_its_state
cargo test --test edr --test edr_evaluation
```

The first command prints the retained state sizes and the per-window findings.
The tests cover:

- five-minute steady-state ingestion and finding parity with SQLite;
- one missed five-minute poll producing a gap;
- four-minute cadence surviving one missed poll;
- restart warm-up;
- seven-day retention size.
