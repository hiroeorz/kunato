# Monitoring console update-cadence evaluation

Date: 2026-11-15

Status: Pre-implementation measurement and specification recommendation.
This document records the pre-implementation experiment. The subsequent
[Phase 2 implementation](monitoring-console-phase2.md) adds the real collection
layer; its performance runner is `examples/observations_bench.rs`. The original
raw source hashes identify the earlier experiment, rather than asserting that
the present source files still match. Prototype behavior remains unchanged.

Related: [Phase 2 counter-based proposal](monitoring-console-phase2.md),
[storage policy](monitoring-console-storage.md), and
[raw measurements and source hashes](evidence/console-cadence-2026-11-15.json).

## Recommendation

Increment WAF counters immediately for every applicable request. Use a **shared
one-second statistics collection/publish tick** for the real-time console,
coalescing all intervening increments into one latest-state update. Retain the
proposed ten-second SQLite submission interval and minute storage grain.

Five-second display updates introduce several seconds of avoidable feedback
delay. Per-request delivery makes publication and browser work grow with
attack traffic. A one-second cap improves visibility while keeping update
work bounded independently of request volume. This recommendation is an
engineering inference from the partial measurements below, not a measured
end-to-end production service-level guarantee.

## Measurement boundaries

The layers have different clocks:

| Layer | Recommended behavior |
| --- | --- |
| WAF count update | Immediate bounded memory increments at the measurement point |
| WAF minute attribution | Source-time minute, independent of publication timing |
| Source to console | One shared statistics snapshot per second, subject to bounded export budgets |
| Console to visible real-time view | Publish changed statistics from that tick immediately through SSE; at most one aggregate update per second per subscriber |
| Browser rendering | Apply/coalesce the received state on the next available animation frame; do not introduce a second independent one-second polling delay |
| Historical metrics view | Refresh an active overview about every five seconds, or on a user query; use the same collected history |
| Console to SQLite | Coalesce absolute minute revisions and submit about every ten seconds, subject to existing bounds |

Neither console publication nor SQLite persistence is a prerequisite for a
WAF counter increment or protective verdict. Closing the browser does not stop
collection/persistence. Several browsers share one source collector rather
than causing one WAF poll per browser.

Five seconds was previously the proposed statistics collection default. This
evaluation recommends changing it to one second; it does not recommend
per-request snapshot serialization, network sends, or database writes.

## Existing-code microbenchmarks

Environment: x86-64 WSL2 Linux, Rust 1.99.1, optimized standalone harness,
Chromium 151. Exact versions and source hashes are in the evidence file.

The Rust harness includes the actual `src/metrics.rs` and decoy metrics module
and uses their existing `AtomicU64` updates and `Metrics::render`. Each result
is the median of seven warmed runs, expressed per operation. The three-update
case uses existing independent counters as stand-ins; it does not implement
or validate the proposed once-per-request rejection instrumentation.

| Operation | Measured median |
| --- | --- |
| One relaxed atomic counter increment | 7.45 ns |
| Three independent increments | 14.09 ns per group |
| Existing complete Prometheus metrics serialization | 3.685 microseconds |
| Illustrative two-counter SSE string formatting | 30.35 ns |

The existing metrics payload in this fixture is 11,288 bytes. Its serialization
component corresponds to approximately 0.74 microseconds per second at a
five-second interval and 3.68 microseconds per second at a one-second interval.
Its uncompressed payload is about 2.26 kB/s versus 11.29 kB/s for one collector.
These figures exclude HTTP, async scheduling, socket operations, TLS,
contention, and the future historical export contract. Compact future
snapshots will have different costs. Do not treat the atomic measurements as
full request-path latency or as a contention/load benchmark.

For a deliberately small 65-byte illustrative counter SSE message, notifying
every request at 10,000 requests/s would still produce 10,000 messages/s and
650,000 payload bytes/s per recipient. That is an arithmetic model, not a
network throughput test. Rendering only once per frame at the browser would
not remove that network and event-reception work. Coalesce before delivery.

## Actual prototype update measurements

The browser harness uses the actual prototype functions through an injected,
test-only closure export. It disables the fictional two-second generator in
that browser context and leaves repository UI assets unchanged. The fixture
retains 500 events and 900 chart samples, displays 35 table rows, and uses a
1440 by 1100 viewport.

After five warmups, 100 synchronous calls measured the following update and
forced-layout times:

| Operation | Median | p95 |
| --- | --- | --- |
| Summary cards/rankings | 0.80 ms | 1.20 ms |
| Full real-time view | 11.70 ms | 19.60 ms |

This measures JavaScript/DOM/layout work, not pixel presentation, animation
completion, GPU cost, mobile hardware, or a production-optimized UI.

### Controlled arrival-to-DOM comparison

Each mode ran for approximately ten seconds with 137 synthetic arrivals in
the browser, spaced 73 ms apart after an initial 37 ms offset. Each arrival
increments the same in-memory request field. The selected cadence publishes
the accumulated value using the actual full-view renderer, checks that the
displayed total matches all received input, and measures time from arrival
to updated DOM/forced layout. All four modes displayed all 137 increments.

| Publication cadence | Mean arrival-to-DOM | p95 | View updates | Time in update/layout calls |
| --- | --- | --- | --- | --- |
| Every 5 seconds | 2,528 ms | 4,791 ms | 2 | 0.21% |
| Every 1 second | 514 ms | 968 ms | 10 | 1.16% |
| Every 100 ms | 59 ms | 98 ms | 100 | 10.89% |
| Every synthetic arrival | 11 ms | 12 ms | 137 | 14.99% |

These percentages are measured synchronous-call time divided by elapsed test
time, not operating-system CPU-utilization readings. Every-arrival results
apply to approximately 13.7 arrivals/s, not an attack-scale sustained input.
The experiment contains no WAF-to-console connection or SSE transport; those
will add latency and work. Its input runs on the browser event loop and cannot
prove behavior under independently generated saturated input.

In an ideal periodic publisher with uniformly phased arrivals, publication
waiting averages half the interval: 2.5 s at five seconds and 0.5 s at one
second, before transport/rendering. The controlled result is consistent with
that expectation. Independent collection and display timers can compound
delays; a fast SSE transport alone cannot fix a five-second collection tick.

## Consequences for the specification

- Use immediate request counters in every mode. Changing publication cadence
  must not turn request counting into a sampled approximation.
- Recommend a fixed one-second source/aggregate-publication tick initially;
  avoid subscriber-dependent collector lifetimes and per-request fan-out.
- Send absolute latest values with generation/sequence, or another explicitly
  idempotent contract. Intermediate aggregate publications may be coalesced;
  counted requests and minute attribution must remain intact.
- Publish changed statistics; unchanged state needs no repeated UI rebuild.
  Apply bounded subscriber buffers and replace an obsolete pending aggregate
  with the newest compatible state rather than queue every intermediate tick.
  Do not coalesce across generations without a reset marker.
- Investigation events retain independent bounded delivery and omission
  semantics. Replacing an aggregate snapshot does not authorize silently
  discarding selected event detail. Event batches should have an explicit
  publication budget instead of one message per attack occurrence.
- Trigger the rejection-card effect once for a new positive counter change
  in a batch. Do not restart an active effect for each request, treat a reused
  historical bucket as new activity, or replay backlog effects after reconnect.
- A short attack can be counted accurately at either cadence, but a rate
  averaged over five seconds smooths it more than a one-second rate. Label the
  rate window; neither observation proves an instantaneous peak rate.
- Retain ten-second database batching. Repeatedly observed values for one
  minute replace/coalesce that minute's absolute value; faster live publication
  does not require more database commits.

## Reproduction and remaining validation

No new runtime dependencies are added. The counter harness requires Python 3
and Cargo/Rust; the updated counter harness builds the real crate in release
mode. The optional browser harness uses an already installed Playwright
package and Chromium and does not download them.

```sh
python3 scripts/bench-console-cadence.py --output /tmp/kunato-cadence-counters.json
node scripts/bench-console-cadence.cjs /absolute/path/to/playwright /absolute/path/to/chromium /tmp/kunato-cadence-browser.json --timed
```

Before shipping the future collector, measure actual WAF throughput/latency
with one-second export under concurrent normal and attack traffic, complete
SSE delivery latency with network delay, bounded slow-subscriber behavior,
multiple browsers, background-tab pause/resume, and database stalls. Recheck
packet/dimension limits and ring export/rotation contention. No current
microbenchmark proves those integration properties; they remain in the
Phase 2 implementation verification gate.
