# Monitoring console: UTC aggregates and retention

Date: 2026-11-16

Status: Implemented in the storage library, writer, collector reader, and
development runner. This phase implements the adopted policy in
[storage and retention](monitoring-console-storage.md). HTTP delivery, SSE,
authentication, HTTPS, and installation remain later work. The subsequent
[Phase 4](monitoring-console-phase4.md) extends measurements and implements
bounded compact decoy evidence. The browser still uses fictional data.

## Implemented measurements

| Data age | Stored grain |
| --- | --- |
| Less than 1 hour | 1 minute |
| 1 hour to less than 3 hours 30 minutes | 5 minutes |
| 3 hours 30 minutes to less than 6 hours | 10 minutes |
| 6 hours to less than 12 hours | 20 minutes |
| 12 hours to less than 30 days | 1 hour |
| 30 days or older | Expired |

All boundaries use UTC Unix milliseconds. A parent must reach its age threshold
in full before promotion. Finer input can remain across that threshold until
the next bounded maintenance pass. Daily charts sum retained UTC hours.

`src/console/history.rs` defines grains, sixteen fixed scalar count metrics,
merge inputs, gauges, and compatible status/latency distributions.
`src/console/history_store.rs` owns SQL materialization, coarsening, reads, and
expiry. No new dependency or WAF request-path measurement is introduced.

Overall totals and the existing 22 primary rejection reasons are independent
series. A rejection contributes to its single terminal mechanism, not every
matching rule. Attack classes, arbitrary site/rule dimensions, and reason-specific
latency are not inferred from detail events.

Count statistics retain known sum, known minute count, complete-minute sum/count,
and eligible minimum/maximum one-minute counts. `total()` is unavailable when
no contribution was measured. A partial sum retains incomplete coverage and
known/expected minute counts. `complete_minute_mean()` describes complete
minutes only. Full-interval rates and reason percentages require compatible
complete populations. Missing/partial minutes are excluded from extrema;
measured zero remains eligible. Overall extrema are computed independently.
Latency count/sum/histograms and connection-time numerators survive coarsening.
This phase did not measure exact latency minima/maxima or connection minima;
Phase 4 adds those fields without inventing values for older history.

## Schema and recovery

Schema version 3 adds:

| Table | Purpose |
| --- | --- |
| `history_buckets` | Disjoint overall intervals per instance/scope with explicit grain |
| `rejection_buckets` | Fixed-reason statistics linked to overall intervals by a cascading foreign key |
| `history_dirty` | Materialization work committed with raw input and source checkpoints |
| `history_state` | Nondecreasing statistics/detail expiry watermarks and read revision |
| `history_sources` | Generation progress for eventual old-checkpoint cleanup |

Migration from application-owned versions 1 and 2 is transactional. It preserves
raw rows/checkpoints and queues existing minutes for incremental materialization.
Missing old measurements remain unknown. Initialization failure rolls back
instead of rebuilding history. The larger schema can exceed unusually small
configured budgets; capacity tests use 512 KiB to fit initialization and exercise
subsequent failure. The default database/journal budget remains 1 GiB.

Input is absolute and revisioned. Materialization merges generation contributions
into one UTC minute before computing temporal extrema. Shared-minute generations
remain incomplete when observation overlap/downtime cannot be established;
they do not become several base minutes.

Coarsening writes overall/reason replacements and removes their children/raw
input in one transaction. The replacement row is durable interval progress.
A dirty minute prevents its parent from advancing ahead of pending input.
Restart resumes pending work without an in-memory rollup cursor.

The source retains ten minute slots; raw history survives at least an hour.
Revisions can replace retained raw minutes. A new revision of an already
compacted minute returns `CompactedInput` without advancing its checkpoint,
because discarded input cannot reconstruct corrected extrema. Expired input
is skipped with explicit `expired_metrics`/`expired_events` accounting and
cannot recreate history after checkpoint cleanup.

## Expiry and worker bounds

Statistics expire at the next UTC hour at or after `now - 30 days`. Discarding
the oldest straddling hour keeps observations within the strict age limit;
the available oldest boundary can be less than one hour newer than the nominal
cutoff. Reads expose effective expiry/availability and never prorate a partial
hour. The watermark survives restart and cannot move backward with the clock.

The owned writer performs maintenance at startup, after ingestion, and about
every five minutes when idle. Backlog work interleaves with ingestion using
the configured minimum commit interval, with at least 10 ms between repeated
normal maintenance steps. Each transaction materializes one minute or coarsens
one parent, alongside bounded cleanup. Health exposes progress, pending minutes,
effective expiry, oldest still-expired statistics, and storage errors. A normal
bounded shutdown drains admitted input and maintenance; OS-level blocked I/O
retains the Phase 1 timeout limitations.

Selected detail has independent `StorageConfig.event_retention`, default seven
days, configurable from one millisecond through 30 days. Deleting detail never
changes authoritative traffic totals. Optional compact decoy summaries are not
implemented in this phase.

| Work | Bound |
| --- | --- |
| Overall history payload | 64 KiB encoded |
| Minute provenance read | 64 generations; excess fails explicitly |
| Coarsening parent | At most five same-grain children |
| Maintenance transaction | At most 1,000 changed rows including cascades; overflow rolls back |
| History page | 1..128 whole intervals with fixed reason/metric maps |
| Reader | Four queued requests and one owned database thread |
| Async read wait | 750 ms; timeout does not forcibly cancel OS I/O |
| Checkpoint contention | At most eight attempts within the read deadline |
| Writer busy recovery | At most three retries while another lock wait fits the outer operation deadline |

SQL progress/cancellation checks and a pre-commit deadline retain the configured
operation budget. Transient maintenance busy/timeouts are retried later. Other
storage errors preserve the stop-admission contract.

## Query contract

`Store::history(&HistoryQuery)` is synchronous and intended for a worker/test
caller. It returns disjoint whole buckets, pending work, effective expiry,
oldest availability, and continuation start/revision. A range cutting a coarse
bucket excludes it rather than fabricating a partial total. Callers disclose
the returned boundaries and gaps.

`Collector::history_reader()` returns a cloneable `HistoryReader`. Its async
`history(query)` runs on the bounded database thread. Ordinary queries read
the existing watermark without a write lock; only a new hourly cutoff advances
it. Reuse the first page's revision for pagination. Changed history returns
`HistoryChanged`; an in-read concurrent change returns Busy instead of mixing
old overall values with new reason rows.

An ingestion receipt acknowledges raw input/checkpoint COMMIT, not completion
of background materialization. Queries and health expose that distinction.
Use mixed-grain history for historical reads; the earlier raw-minute API loses
input as coarsening succeeds and also filters logically expired data.

## Verification and review

`tests/console_history.rs` exercises all grains and exact promotion edges,
22 reasons, independent overall/reason peaks, zero/unknown/partial values,
weighted means, status/histogram/gauge merging, absolute revision replay,
generation contributions, restart, schema migration, pagination, logical versus
physical expiry, clock rollback, expired replay, transactional rollback,
arithmetic overflow, dense generation/row budgets, detail expiry, bounded busy
recovery, and final maintenance flush.

Collector tests exercise the bounded reader under a reserved database lock and
generation changes during background work. The real loopback proxy/collector
test reads reason rows after actual HTTP requests. Existing capacity, queue,
lock, cancellation, and WAF observation tests remain required checks.

Review checked population boundaries, late-correction provenance, cross-generation
extrema, parent/child atomicity, resource bounds, stored-field privacy, database
contention, and restart watermarks. It led to bounded lock retries, read-only
steady-state queries, stable page revisions, and explicit rollback/error behavior.
This phase implements history storage/collection, not a web-console release.

Final verification ran `cargo fmt`, `cargo clippy --all-targets -- -D warnings`,
`./scripts/check-deny.sh`, and `cargo test` in that order. All 1,206 tests passed;
three existing external ACME tests remained ignored. Dependency checks passed
for all three configured targets with the existing duplicate-crate and unused
license-allowance warnings. `git diff --check` also passed.
