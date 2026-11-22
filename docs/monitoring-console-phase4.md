# Monitoring console: additional source measurements

Date: 2026-11-16

Status: Implemented in WAF observations, the collector, and SQLite history.
This extends [Phase 3](monitoring-console-phase3.md).
[Phase 5](monitoring-console-phase5.md) adds HTTP/SSE delivery and the console
runtime; [Phase 6](monitoring-console-phase6.md) adds remote access.
Distribution and service integration remain future work.

## Measurement contract

The loopback snapshot now publishes version 3, accepting version 2 input for
compatibility. Each source minute can carry optional `additional` version-one
measurements. Absence means unavailable, including pre-instrumentation history;
it never means measured zero. Primary request/rejection totals retain their
existing atomic source and remain independent of optional detail.

| Measurement | Meaning |
| --- | --- |
| Site | Request endings, including aborts; rejected/logged requests; upstream failures/timeouts; header-decision latency |
| Country | Bounded per-minute request and rejection counts by resolved source country; unknown lookup results use `ZZ` |
| Attack class/category/rule | Separate ALLOW, LOG, and BLOCK outcome-match counts, split by request/response phase |
| Upstream statuses | Status received from the upstream before response rules or PHP response checks replace it; includes WebSocket handshakes |
| Rejection-reason latency | Count, microsecond sum, exact observed minimum/maximum for requests that produced headers, using their single primary reason |
| Overall latency | Existing count/sum/histogram plus exact observed minimum/maximum; excludes aborts without headers |
| Connections | Existing sampled maximum and time integral plus sampled minimum; does not assert an unsampled instantaneous minimum |
| Sources/paths | Bounded request-frequency summaries, observed rejected/logged lower bounds, and mergeable distinct-count estimates |
| Credentials | Distinct verified credential IDs in authentication contexts, independent of selected-detail emission |
| Operations | Runtime rule-update checks/results, reload successes/failures, certificate cache/deployment/failure outcomes, and last observed state |

Latency ends when response headers are produced. It includes WAF and upstream
work before headers; it is neither pure upstream duration nor complete body
delivery time. Means always use summed duration/count. Exact extrema refer to
captured requests; incomplete coverage must be shown alongside them.

Site identities come from configured `allowed_hosts` entries, choosing exact
names before wildcards and then the most specific matching entry. Wildcard
subdomains share a series. Invalid/unlisted hosts use `unattributed`; without
an allowlist, requests use `default`. Raw arbitrary Host values do not create
series. This is host-policy attribution, not a new virtual-host configuration.

Category/rule IDs include a fingerprint of the compiled host/rule catalog, so
a changed rule does not silently share its old identity. This is an observation
catalog ID, not a hash of all runtime configuration. Attack classification uses
the existing category-based log classifier. A request may have several LOG
matches and a terminal ALLOW/BLOCK; match counts are not unique-request counts.
Threshold outcomes describe the evaluator's reported composite outcome.

## Bounds, estimates, and omissions

Supplementary capture uses eight fixed partitions with ten UTC minute slots
each. Request handlers only try the partition lock; contention drops optional
updates and increments the cumulative `additional_missed_updates`. Affected
minute ranges retain `incomplete` and unknown per-minute `missed_updates` when
an exact allocation of lost updates is unavailable. Collector health exposes
the cumulative source loss separately from basic atomic attribution loss.

Per merged interval the dimension quotas are 16 sites, 24 attack classes,
32 categories, and 56 rules. Overflow increments `dimension_overflow` and
marks the contribution incomplete. This is a bounded breakdown, with no
claim that every configured rule/site is represented under high cardinality.
Country counts retain at most 64 distinct ISO codes per interval; additional
codes are counted in `country_overflow`, mark the contribution incomplete, and
are not presented as exact zero. Pre-instrumentation intervals have no country
map and remain unavailable.

IP and path frequency summaries retain at most 16 entries each using
Space-Saving estimates. For a retained key, its captured frequency lies in
`[estimate - error, estimate]`. `observed_rejected` and `observed_logged` are
recorded lower bounds, not exact disposition fractions. `omitted_upper_bound`
bounds the captured frequency of an absent key; it is not an aggregate "other"
count. Summary merges preserve error bounds. Results need sorting by estimate
for display; ties and near-equal frequencies do not establish an exact rank.

Distinct sketches use 64 HyperLogLog registers and SHA-256 domain-separated
hashing, with about 13% relative standard error before capture loss. Registers
merge by maximum; estimates are never summed across minutes or generations.
These are observed-source/path/credential estimates, not attacker counts.
Sources use resolved client IPs. Paths exclude query strings, have bounded
redacted ranking labels, and use hashes of the original path for distinctness.
Long segments and common secret-bearing route shapes are redacted; these
heuristics do not classify every application-specific sensitive path. Raw
credentials, queries, headers, and bodies are not added to the summaries.

Source records stay within 16 KiB and packets within 256 KiB. Optional detail
is trimmed in priority order with `export_omissions` and `incomplete`; fixed
request totals are preserved. Stored aggregate payloads have a 64 KiB bound.
An enclosing incomplete flag applies to estimates, dimensions, and sparse
status/reason maps: an omitted entry must not be presented as an exact zero.

Operational state records the latest known configuration flags/catalog sizes,
certificate expiry, successful deployment/check timestamps, per-generation
operation totals, and last operation times. Time-series operation counts are
separate from that state; cumulative state must not be summed across buckets.
Snapshots do not backdate a newer state into an already observed older minute.
Rejected reloads keep the active catalog. Static TLS expiry uses the existing
DER parser; unavailable metadata stays unknown. Rule-update metrics describe
runtime checks, not offline CLI update commands.

## Persistence, correlation, and retention

Schema version 4 adds `decoy_correlations` and `correlation_state` through a
transactional migration from versions 1, 2, or 3. Existing payloads/checkpoints
remain intact; missing supplementary fields and old exact extrema remain
unknown. Mixed old/new history preserves known contributions and marks
supplementary coverage incomplete. Extrema become unknown when an old
nonempty contributing latency population lacks them.

Country counts merge by summing request and rejection counts and are trimmed
last when an oversized record must be shrunk, after the optional dimension,
ranking, status, and reason-latency detail. The console renders them as a
country-coloured traffic/rejection chart and a top-10 request table; the
underlying counts are not decoy-specific.

Additional values travel with absolute minute revisions through the existing
collector and atomic parent replacement. They use the same UTC 1/5/10/20/60
minute tiers, 30-day maximum age, and effective oldest-hour cutoff. Counts
sum, latency weights/extrema merge, ranking bounds merge, and sketches union.
Independent primary-reason count rows and overall totals retain their Phase 3
contracts. There is no extra daily-only retention tier.

Compact decoy correlation is optional evidence derived from admitted selected
events in the same transaction as their source checkpoint. Its key includes
source generation, configured decoy site, and hashed credential ID. Replayed
events do not increase evidence counts. A summary retains issuance when
observed, first/last credential evidence, occurrence/block evidence counts,
and at most four addresses for each issuance/reuse/transport role. Address
overflow and incomplete inspection are explicit. Different addresses do not
prove different people or ownership of an address.

Issuance evidence may be missing, and event admission/suppression may omit
reuse. Evidence counts never replace authoritative request counters. The
summary does not infer an issuance trail from a token's reported age. It keeps
its original first-seen expiry even when updated, lasts at most 30 days, and
is bounded globally to 4,096 records / 4 MiB of payload. Capacity evicts oldest
summaries with an explicit eviction counter. Detailed event retention remains
independent (seven days by default).

`Store::correlations` and the bounded `HistoryReader::correlations` return at
most 128 summaries by first-seen time plus a `has_more` indicator; pagination beyond that initial
bounded window remains future API work. Database reads stay on the owned
reader thread with the existing four-request queue and 750 ms response bound.
No WAF request writes to SQLite or requires the console process.

## Verification

Tests cover HTTP/1, HTTP/2, HTTP/3, WebSocket status origin, response replacement,
match multiplicity, site attribution, exact latency weights/extrema, source
contention and cardinality limits, sketch unions, ranking error bounds through
multilevel merges, runtime operation state, accepted/rejected reloads, schema
migration, persistence/reopen/coarsening, missing historical values, decoy
replay/address/capacity bounds, and expiry without extending summary lifetime.
The local release benchmark additionally exports optional-update loss and
export-trimming counters. It measures an eight-client development workload,
not a production capacity guarantee.

Release benchmark on the development host: three alternating paired trials,
two seconds each, eight HTTP/1 clients, protection disabled equally, and
one-second snapshot attempts. Values compare all observation instrumentation
enabled against disabled; they do not isolate Phase 4's incremental cost.

| Workload | Disabled median requests/s | Enabled median requests/s | Disabled/enabled median p99 |
| --- | ---: | ---: | ---: |
| Forwarded requests | 98,635 | 95,594 | 158 / 160 microseconds |
| BLOCK requests | 211,883 | 188,698 | 85 / 97 microseconds |

Enabled trials reported zero snapshot-export failures and no export trimming
for this low-cardinality input. Supplementary missed-update totals were
64–79 per forwarded trial and 1,091–1,256 per BLOCK trial. Basic minute-update
loss was zero except for one update in one BLOCK trial; cumulative basic
request/rejection totals matched generated traffic. Update losses are not
unique lost-request counts. Disabled trials reject snapshot reads by design.
High-cardinality behavior is checked separately by deterministic tests.
