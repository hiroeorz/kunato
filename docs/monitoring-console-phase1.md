# Monitoring console: bottom-up Phase 1

Date: 2026-11-15

Status: Implemented as library foundations under `src/console/`, with integration
tests in `tests/console_storage.rs`. This document records the initial phase.
The [Phase 2 extension](monitoring-console-phase2.md) adds WAF source measurement,
a development collector runner, and schema version 2. Its version-1 migration
preserves saved rows; newly introduced fields remain unknown for old history.
The subsequent [Phase 3](monitoring-console-phase3.md) adds schema version 3,
UTC aggregates, separate reason rows, bounded history reads, and expiry.
The browser prototype continues to show fictional data. This phase follows the
user's decision to build from lower layers before making the console usable.

Related: [architecture](monitoring-console.md),
[product requirements](monitoring-console-requirements.md), and
[future collection, aggregation, and retention](monitoring-console-storage.md).

## Scope

| Layer | Implemented contract |
| --- | --- |
| Observation model | Version-one counters, absolute minute buckets, typed events, decoy evidence, collection gaps, and explicit missing measurements |
| Database | Embedded SQLite, application identity, transactional schema initialization, schema version 1 |
| Store | Atomic batch/checkpoint writes, idempotent replay, bounded chronological reads |
| Background persistence | Dedicated OS thread, bounded FIFO admission, count/byte/time batching, bounded shutdown |
| Health | Pending and in-flight items, retained bytes, admission/commit/replay/failure counts, oldest pending age, last successful persistence time, and bounded errors |

Excluded from Phase 1: WAF instrumentation, real metrics/journal collectors, counter deltas,
minute-bucket calculation, hourly rollups, expiry/deletion, vacuum, live
delivery, HTTP APIs, SSE, authentication, TLS, CLI commands, YAML fields,
service units, installer changes, and UI integration. No WAF startup or request
handler opens the database or starts a writer. `src/lib.rs` only exports the
module for future console callers and tests.

## Version-one observations

All timestamps are UTC Unix milliseconds, bounded to SQLite's signed integer
range. All source positions are positive and fit the same range.

`SourceIdentity` contains an explicit instance/stream identity and generation.
Each identity has exactly one ordered producer. Different streams, such as
journal events and counter snapshots, must use separate identities unless a
collector assigns them one shared sequence. Generation changes are explicit;
counter decreases alone cannot identify WAF restarts. This library neither
discovers a generation nor generates source sequence numbers.

`Counters` uses `Option<u64>`: `None` means unavailable, while `Some(0)` means
measured zero. It includes requests, rejected/logged requests, rule matches,
response blocks, rate limits, bans, overload, upstream failures/timeouts, and
separate decoy credential-use/occurrence/block counters. Counter relationships
are not inferred from non-atomic WAF snapshots or recorded event totals.

`MetricBucket` is a caller-supplied absolute bucket, aligned to a UTC minute,
scoped globally or to a site. Its revision belongs to the source's sequence.
Updating a bucket replaces its prior values; replay never adds them again.
Coverage records observed duration, incompleteness, and known/unknown omitted
events. Connection gauges preserve a time-weighted numerator, observed
duration, and observed maximum for later aggregation. This phase computes no
rates, distinct-source totals, percentiles, or rollups.

`EventRecord` preserves a stable identity, source position, event time, kind,
disposition, phase, optional site and IP addresses, bounded method/path/status,
and optional rule/reason/evidence. Decoy events require `DecoyEvidence`, and
collection-gap events require `GapEvidence`. A decoy identifier is exactly 32
hexadecimal digits: the existing protocol's 128-bit hash, never a raw token.
Credential use and passive occurrence remain distinct contexts. Existing
decoy signing-key lifetime and enforcement behavior are unchanged.

Bodies, headers, cookies, authorization values, and raw credentials have no
storage fields. Paths omit query strings and fragments; token-bearing paths
are rejected using the existing decoy redaction helper. Bounded text rejects
control characters and raw or encoded decoy-token markers. Callers still own
redaction of arbitrary application secrets embedded in otherwise valid paths
or reason text. Event data must eventually be rendered as text in the UI.

## Database and atomic progress

`StorageConfig::new(directory)` chooses `history.sqlite3` inside an explicitly
provided private directory. On Unix, newly created directories are 0700 and
the database is 0600. Existing group/world-accessible paths, symbolic links,
and multiply linked database files are rejected; permissions are not silently
changed. The supported owner is one console process with one writer per
directory. This is not a cross-process coordination protocol.

The application ID is `0x4b554e43` and `user_version` is 1. An empty database
gets these markers and the tables in one transaction. Unrelated databases and
unsupported versions fail without deletion or automatic reconstruction.
Schema upgrades beyond version 1 are future work.

| Table | Identity and purpose |
| --- | --- |
| `events` | `(source, generation, sequence)`, with unique event ID per generation; bounded JSON payload and indexed occurrence time |
| `metric_buckets` | `(source, generation, site, start_ms)`; latest absolute revision and bounded JSON payload |
| `checkpoints` | `(source, generation)`; latest source position, opaque cursor, optional counter snapshot, and SHA-256 batch fingerprint |

Data and checkpoint changes commit in one transaction. For a newer checkpoint,
records at or below the prior committed position are skipped, new event
identities must be unique, and higher bucket revisions replace prior values.
Replaying the same checkpoint and fingerprint succeeds without duplication.
Conflicting content at the current position fails. Older checkpoints are
reported as stale and skipped entirely. Several queued submissions may share
one transaction; any failing submission rolls back the entire group, including
its checkpoints. Producers must never advance their durable progress merely
because queue admission succeeded.

`Store::checkpoint` restores committed source state. `events` and `metrics`
require a source, an inclusive start, an exclusive end, and 1..256 records.
Results are chronological with deterministic tie ordering. These are synchronous
lower-layer APIs for a worker/test caller; an eventual HTTP handler must not
execute them on its async runtime thread. Query pagination and a separate
bounded query worker are future work.

## Writer and initial bounds

`Writer::start` opens SQLite on its owned OS thread and awaits a bounded startup
notification. `try_submit` validates and encodes a bounded batch, takes the
queue mutex with `try_lock`, and returns immediately on contention, capacity,
or closed admission. It never waits for a database lock or free queue space.
No database operation holds the queue mutex.

| Limit | Initial library default / hard bound |
| --- | --- |
| Queue | 1,024 submissions and 4 MiB of retained encoded data plus admission overhead; in-flight submissions remain charged |
| One record | 16 KiB encoded; individual string fields also have smaller limits |
| One input batch | At most 256 records including its checkpoint, at most 1 MiB encoded |
| One worker transaction | 200 records including checkpoints, 512 KiB of charged submissions; configurable up to the input hard bounds |
| Event/checkpoint-only flush | 1 second, or count/byte pressure |
| Metric-only flush | 10 seconds, or count/byte pressure |
| Write attempt interval | At least 100 ms during normal operation |
| Database lock wait | 25 ms |
| SQLite execution deadline | 250 ms, checked between submissions and before commit, plus SQLite's progress hook |
| Startup notification | 5 seconds |
| Shutdown | Caller-provided positive deadline, at most 30 seconds |
| Persistence receipt wait | Caller-provided positive deadline, at most 60 seconds |

Queue bounds count submissions rather than individual events. Transaction
limits count events, buckets, and checkpoints together. A submission exceeding
the configured transaction limits is rejected without partial acceptance.
An event-containing submission carries its buckets/checkpoint into the same
earlier flush. Pending FIFO work is drained in bounded transaction groups.
Shutdown bypasses ordinary batching delays and attempts to flush the remaining
finite queue. The queue byte accounting covers retained prepared submissions;
it is not an RSS limit. Thread stacks, SQLite's cache, caller-owned batches,
and bounded temporary encoding/decoding allocations are additional memory.

A successful `Receipt` means SQLite COMMIT returned successfully. Admission,
live observation, committed history, and replayed/stale input are distinct.
A receipt timeout does not cancel pending work and leaves its outcome unknown.
On a storage error, the worker closes admission, reports affected receipts,
and exposes `Failed` or `AtCapacity`. It does not silently skip failed input
and then advance later checkpoints. Recovery starts a new worker and reads the
last committed checkpoint; retry/backoff and priority shedding are future work.
Rejected submission and failed batch counts do not claim exact lost-event
counts, since a future collector may replay them successfully.

## Durability and disk budget

Phase 1 selects DELETE rollback journaling, `synchronous=EXTRA`, in-memory
SQLite temporary storage, and disabled cache spilling. This avoids introducing
a growing WAL/checkpoint lifecycle before reader and retention workers exist.
The default combined database/journal budget is 1 GiB, configurable from
256 KiB to 1 TiB. `max_page_count` conservatively allocates approximately half
the budget to the database, reserving space for one rollback copy of its pages,
per-page journal overhead, and 64 KiB of journal/header margin. Fixed database
and journal/WAL/SHM file sizes are checked before writes. Reaching the page
limit rolls back the current transaction; saved history is retained and the
writer stops accepting input. There is no automatic eviction in this phase.
The budget is not a filesystem quota, does not count unrelated files or
filesystem allocation overhead, and assumes exclusive ownership of the
directory. Do not run concurrent writers or place unrelated data there.

SQLite deadlines can stop SQL execution and bound busy waits. An OS-level
blocked read/write/fsync cannot be forcibly canceled safely. Shutdown stops
admission, requests cancellation when its deadline expires, and returns without
joining a still-running storage thread. Such a thread can finish later; its
in-flight commit outcome must be resolved by reopening the database after it
exits. Never start a second writer over a timed-out worker still using the same
directory. `Drop` requests shutdown and does not wait for SQLite or join.

An abrupt process exit can lose all uncommitted queue data. EXTRA requests
stronger filesystem synchronization but does not guarantee faulty hardware,
every filesystem, or every power-loss scenario. SQLite atomicity, source replay
availability, queue loss, and host durability remain separate guarantees.

## Dependency review

`rusqlite` 0.43 with only `bundled`, `hooks`, and `limits` is added after checking
`Cargo.toml`. Its MSRV is Rust 1.89; `libsqlite3-sys` 0.40 supports Rust 1.88.
The bundled version is SQLite 3.54.1. It provides an embedded database without
a service, runtime SQLite package, CLI tool, custom unsafe FFI, or external
runtime requirement. Existing `ring`, `serde_json`, and Tokio supply hashing,
encoding, and notifications.

The reviewed `libsqlite3-sys` build script compiles the packaged SQLite C source
with `cc` and copies packaged bindings. The enabled path downloads no source
or generator. SQLCipher, loadable extensions, and build-time bindgen are not
enabled. It is the sole new build-script allowlist entry in `deny.toml`.
As with other native crates, environment/toolchain overrides can change the
build; release environments must not opt into system SQLite through
`LIBSQLITE3_SYS_USE_PKG_CONFIG`. See the
[upstream crate manifest](https://github.com/rusqlite/rusqlite/blob/v0.43.0/Cargo.toml)
and [build script](https://github.com/rusqlite/rusqlite/blob/v0.43.0/libsqlite3-sys/build.rs).

## Verification and remaining work

`tests/console_storage.rs` exercises restart readback; unknown versus zero;
hashed decoy evidence; time/site/read bounds; replay, stale and conflicting
positions; absolute bucket updates; separate generations; atomic rollback
including checkpoints; input privacy/size checks; private paths; foreign/future
schema rejection; capacity exhaustion and recovery; pending versus committed
health; timer/count batching; queue item/byte limits; in-flight accounting
under a real SQLite lock; and bounded shutdown with pending cancellation.

Later phases must add source collection and gap/recovery policy, counter-to-minute
calculation, rollups/retention, operational resource budgets, query delivery,
SSE, access security, packaging, and the final connection to both UI views.
The current library is not a user-facing monitoring feature or a release claim.
