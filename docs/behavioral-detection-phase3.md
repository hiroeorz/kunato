# Behavioral detection Phase 3: content scraping and distributed abuse

Status: **Design spike** — not implemented. Phase 1 (per-source enumeration,
per-source authentication abuse, and a global authentication-failure log) is
implemented; see [behavioral-detection.md](behavioral-detection.md). This
document evaluates the Phase 3 follow-ups and recommends a scoped implementation.

## 1. Summary

The remaining behavioral gaps are classes where every individual request looks
legitimate and no YAML signature can express the pattern:

- **`200`-only content scraping.** A crawler walks distinct pages that all
  return `200`. The existing enumeration signal counts only `404`s, so it never
  fires.
- **Configurable static assets.** Enumeration currently uses a fixed list of
  asset prefixes and extensions. Deployments with application-specific asset
  paths cannot add them without a code change.
- **Distributed authentication abuse.** The global window already observes
  distributed `401`/`403` traffic, but it is log-only. A global action would let
  an attacker deny authentication to every user, so this document recommends
  keeping it log-only until a challenge or identity mechanism exists.

Recommendation:

1. **Phase 3a (implement).** Add a configurable static-asset policy and a
   per-source `scraping` signal over `200` responses on non-static paths. The
   default is `LOG`; `BLOCK` is opt-in after a tuning period.
2. **Phase 3b (design only).** Keep the global authentication signal log-only.
   Document the conditions under which a safe global throttle could be added
   later; do not add a global action field now.
3. **Defer.** Account-creation failure bursts, `403`/`400` probing, and a
   sliding window. Each needs its own false-positive analysis and is not
   required to close the scraping gap.

The rest of this document specifies Phase 3a and records the rejected
alternatives.

## 2. Current state

Phase 1 keeps a tumbling per-source window inside the existing tracked-source
table (`src/protection/mod.rs`):

```rust
struct BehaviorEntry {
    window_start: Instant,
    requests: u32,
    not_found: u32,
    auth_failures: u32,
    not_found_paths: [u64; 4], // 256-bit Bloom filter of 404 paths
    flags: u8,
}
```

Observation runs after the upstream response, before response-phase rules, in
`record_behavior` (`src/proxy/server.rs`). Local responses (rule blocks, host
policy, rate limits, errors) are not observed. The observation currently uses
the status and path only:

```rust
observe_response(ip, path, status, config)
```

The enumeration signal counts `404`s on paths that `is_static_asset` does not
exclude; the authentication signal counts `401`/`403` on a compiled
authentication-path set. Both default to `LOG`.

The fixed static list is a hard-coded helper:

- prefixes: `/static/`, `/assets/`, `/build/`, `/dist/`, `/_next/static/`,
  `/images/`, `/img/`, `/fonts/`, `/media/`;
- exact paths: `/favicon.ico`, `/robots.txt`, `/sitemap.xml`,
  `/sitemap.xml.gz`, `/manifest.json`, `/site.webmanifest`;
- extensions: `css`, `js`, `mjs`, `map`, `png`, `jpg`, `jpeg`, `gif`, `webp`,
  `avif`, `svg`, `ico`, `woff`, `woff2`, `ttf`, `otf`, `eot`, `mp4`, `webm`,
  `mp3`, `wav`, `ogg`, `flac`, `m4a`.

## 3. Goals and non-goals

### Goals

- Detect a source that fetches many distinct `200` content paths in a window,
  with no requirement that any response is an error.
- Let operators declare application-specific static assets without recompiling.
- Keep the default observation-only and the state fixed-size.
- Reuse the existing tracking table, `client_ip` identity, IPv6 aggregation,
  allowlist, ban escalation, and metrics/logging conventions.
- Keep the feature independent of the YAML rule set.
- Add no dependencies and no per-response allocations.

### Non-goals

- JavaScript challenges, CAPTCHAs, or proof-of-work.
- Per-user, per-session, or cookie-based identity.
- Content classification, HTML parsing, or response-body inspection.
- Blocking the response that triggered a flag. A `BLOCK` flag bans the source
  for subsequent requests, like the existing behavior signals.
- A global ban, global throttle, or global challenge.
- Distributed scraping detection.
- Persisting state across restarts.

## 4. Phase 3a: `200`-only scraping

### 4.1 Signal definition

A **content response** is a request that satisfies all of the following:

```text
method == GET
status == 200
path is not a configured static asset
```

A source is flagged for scraping when:

```text
content_responses >= behavior.min_requests
distinct_content_paths >= scraping.distinct_paths
```

`distinct_content_paths` is the estimated cardinality of the set of normalized
content paths in the window, using a second 256-bit Bloom filter with the same
parameters as the enumeration signal. Query strings are not part of the hash;
`?page=2` and `?page=3` count as the same path (see Section 7).

Defaults:

| Setting | Default | Rationale |
| --- | --- | --- |
| `scraping.enabled` | `true` | Observation-only; the log/metric is cheap and bounded |
| `scraping.action` | `LOG` | `BLOCK` is opt-in after tuning |
| `scraping.distinct_paths` | `40` | A human rarely reads 40 distinct pages per minute; a crawler does |
| `behavior.window` | `60s` | Reused from Phase 1 |
| `behavior.min_requests` | `30` | Reused; the distinct-path threshold already implies more than 30 content responses |

The flag is emitted once per source per window. A `BLOCK` action reuses the
existing ban path: it applies `ban.duration` (with escalation up to
`ban.max_duration`), resets the behavior window, and the next request receives
`429` with `Retry-After`. The triggering response is forwarded unchanged.

The window is shared with Phase 1. A slower crawler, for example one that reads
20 distinct pages per minute, stays below the threshold. A separate longer
scraping window (for example 300 s) would catch it, but it needs a second
timestamp and a second window roll per source. Phase 3a keeps the shared window
and accepts the slow-crawler gap; a longer window is a tuning option recorded in
Section 14.

### 4.2 Why not count all `200`s

Static assets are fetched in bulk by every page load. Counting them would make
a single browser session look like a crawler and would let any site with hashed
bundle names dominate the distinct-path count. Excluding static assets is the
minimum viable filter; the configurable list in Section 4.4 makes it practical.

### 4.3 Why GET only

`POST`, `PUT`, and `PATCH` requests create or mutate state; a client making many
distinct writes is an API-abuse concern, not content scraping. `HEAD` is
sometimes used by monitoring and link checkers and returns no content. Counting
only `GET` keeps the signal focused. `HEAD` can be added later if operators
observe a crawler that uses it.

### 4.4 Static asset policy

Replace the hard-coded helper with a compiled policy under
`protection.behavior.static_assets`:

```yaml
protection:
  behavior:
    static_assets:
      prefixes: ["/static/", "/assets/"]
      paths: ["/favicon.ico", "/robots.txt"]
      extensions: ["css", "js", "png"]
```

Semantics:

- Omitting `static_assets` entirely uses the built-in defaults from Section 2.
- Omitting one of the three fields keeps that field's defaults.
- Providing a list replaces the default list for that field. An explicit empty
  list disables that category. This mirrors `behavior.auth.paths`, where a
  provided list replaces the built-in set.
- Matching runs on the normalized path used by enumeration (dot segments and
  duplicate slashes resolved). If normalization fails, the raw path is used,
  matching the existing enumeration behavior:
  - prefixes use `starts_with`;
  - exact paths use an ASCII-case-insensitive comparison;
  - extensions are compared case-insensitively after the last `.` in the last
    path segment.
- The policy applies to the enumeration numerator and to the scraping content
  count. Static requests remain in the enumeration denominator, so a normal
  page load still dilutes the `404` ratio.
- Matching is a linear scan over at most 64 entries per list. The compiled
  policy stores lowercased extensions and does not allocate per response.

Validation:

| Field | Rule |
| --- | --- |
| `static_assets.prefixes`, `paths` | at most 64 entries; each 1..1024 bytes; starts with `/`; no ASCII control characters or spaces |
| `static_assets.extensions` | at most 64 entries; each 1..32 bytes; ASCII alphanumeric plus `+`, `-`, `_`; no leading dot; stored lowercase |

An invalid entry rejects the whole configuration, and a failed reload keeps the
previous policy, consistent with every other configuration error.

### 4.5 Observation interface

The observation function gains the request method:

```rust
pub fn observe_response(
    &self,
    ip: IpAddr,
    method: &Method,
    path: &str,
    status: StatusCode,
    config: &Protection,
) -> BehaviorOutcome
```

`record_behavior` already receives `parts`, so the call site passes
`&parts.method`. No response headers or body are needed. This keeps the hot
path to a method comparison, a status comparison, a path lookup in the static
policy, and a hash.

If response content-type filtering turns out to be necessary (Section 7), the
signature can grow a small response-metadata argument later; it is deliberately
not part of Phase 3a.

### 4.6 State

`BehaviorEntry` gains a content counter and a second Bloom filter:

```rust
struct BehaviorEntry {
    window_start: Instant,
    requests: u32,
    not_found: u32,
    auth_failures: u32,
    content: u32,              // 200 GET responses on non-static paths
    not_found_paths: [u64; 4], // 404 paths
    content_paths: [u64; 4],   // 200 GET paths
    flags: u8,                 // bit 0: enumeration, 1: auth, 2: scraping
}
```

The per-source state grows by 36 bytes of fields (about 40 with alignment):
one `u32` and one 32-byte filter. At the default 100 000 tracked sources that is
about 4 MB of additional behavior state (roughly 11 MB total). The growth is
bounded by `max_tracked_ips` and reset in place; no allocation occurs per
response.

The hash and estimate are shared with the enumeration filter:

```rust
fn add_path(path: &str, filter: &mut [u64; 4]);
fn estimate_paths(filter: &[u64; 4]) -> u32;
```

`add_path` uses the existing FNV-1a plus SplitMix64 finalizer and sets two bits.
`estimate_paths` uses the standard Bloom formula with `m = 256`, `k = 2`, and
caps at 256. Collisions normally under-count, which makes the detector
conservative and can delay a flag. A fully saturated filter returns the 256 cap;
the threshold is capped at 256 and the default is low, so saturation is an edge
case rather than a false-positive source at normal thresholds.

### 4.7 Flags, bans, and outcomes

- `BehaviorSignal` gains `Scraping` (`as_str() == "scraping"`).
- `BehaviorFlag` gains `content: u32` and `content_paths: u32` for the log line.
- `BehaviorOutcome` gains `observed_content: bool`; `record_behavior` increments
  `kunato_behavior_content_total` when it is set.
- The scraping flag is set once per window. A `BLOCK` flag applies a ban with
  the same escalation as enumeration and authentication, and resets the
  behavior window.
- A source may produce more than one signal type in a window (for example,
  enumeration and scraping). Each signal has its own flag bit, threshold, and
  `BehaviorFlag`; an individual response produces at most one source flag
  because it is either a `404`, an authentication failure, or a content `200`.
  The proxy layer logs each transition separately.
- A source with no tracked entry is a no-op, as in Phase 1.
- `protection.enabled: false`, `--disable-protection`, and
  `protection.allowlist` exempt the source from both observation and bans.

### 4.8 Metrics and logs

New counter:

| Metric | Meaning |
| --- | --- |
| `kunato_behavior_content_total` | `200` `GET` responses on non-static paths |
| `kunato_behavior_scraping_flags_total` | sources flagged for scraping |

`kunato_behavior_blocked_total` already counts every behavior flag that applied
a ban, including scraping. The existing counters remain unchanged.

Log line:

```text
WARN behavior threshold reached
     client=203.0.113.7 signal=scraping path=/articles/42
     content=57 content_paths=44 threshold=40 action=LOG
```

The log is emitted once per source, signal, and window, after the shard lock is
released. The path is included only on that deduplicated line, matching the
existing enumeration and authentication logs.

## 5. Phase 3b: global authentication mitigation

The global window is deliberately log-only in Phase 1. The open question is
whether a global throttle or challenge can be added without letting an attacker
deny authentication to everyone.

Options considered:

| Option | Benefit | Problem |
| --- | --- | --- |
| Global throttle on authentication paths | Slows a distributed spray | An attacker who reaches the threshold blocks every legitimate login for the cooldown |
| Global ban of failing sources | Removes the noisy sources | Distributed sources each stay below the per-source threshold; banning everyone with one failure is worse |
| Global challenge (JS/PoW) | Distinguishes browsers from scripts | No challenge mechanism exists; it breaks API clients and non-browser flows |
| Keep log-only | No availability risk | Does not stop the spray |

Recommendation: **keep the global signal log-only in Phase 3**. The existing
per-source ban and the bundled login throttle remain the enforcement points.
A safe global action needs an identity or challenge mechanism that this project
does not have; adding a global `action: BLOCK` would trade a detection gap for
an attacker-controlled outage.

If a future release adds a challenge, the likely shape is an opt-in
`global_auth.action: THROTTLE` with a short cooldown, a maximum cooldown, an
allowlist, and metrics for "would have throttled" before enforcement. That is a
separate design with its own readiness checklist; it is not part of Phase 3a.

## 6. Rejected and deferred alternatives

### 6.1 Content-type filtering

Counting only `200` responses with `Content-Type: text/html` would reduce false
positives from JSON APIs and SPA polling. It was rejected for Phase 3a because:

- it requires passing response headers into the observation function;
- it misses API scraping, which is a real concern for personal services;
- a site can return HTML with a generic or missing content type, causing false
  negatives;
- the distinct-path threshold is already a strong signal and the default is
  `LOG`.

It remains a tuning option if operators report false positives from JSON APIs.
If added, it should be a separate `scraping.content_types` list rather than a
hard-coded rule.

### 6.2 Query-string hashing

Including the query in the path hash would catch `/list?page=1`, `/list?page=2`
pagination. It was rejected because ordinary search, filters, and tracking
parameters produce many query variants from one session, and the same query
space is already covered by rate limits and the rule set. The limitation is
documented in Section 7.

### 6.3 Account-creation failure bursts

`POST /register` failures are a useful abuse signal, but they need their own
path list and status taxonomy (validation errors return `4xx` for legitimate
users too). Defer until there is a concrete deployment requesting it.

### 6.4 `403`/`400` probing

Including `403` or `400` in the enumeration numerator would flag WAF blocks and
normal form validation. It is not worth the false-positive cost; the existing
`404` signal plus rules remain the probing controls.

### 6.5 Sliding window

A two-bucket window reduces the boundary effect where an attacker splits a
burst across two windows. It doubles the counter state and complicates the
tests. Defer until operators observe boundary evasion.

## 7. Security and false-positive analysis

### 7.1 False positives

| Source | Mitigation |
| --- | --- |
| Search-engine crawlers and link checkers | `LOG` default; allowlist known crawler addresses before enabling `BLOCK`; robots-aware crawling is not distinguishable from scraping without content or identity |
| A monitoring service checking many distinct health endpoints | Usually a small fixed set; a large set is allowlistable; `LOG` default |
| A SPA or mobile client that calls many distinct API endpoints in one session | `LOG` default; raise `distinct_paths` or disable `scraping` for that deployment |
| A power user browsing a large site quickly | 40 distinct pages per minute is unusual; `LOG` default |
| A shared NAT or office egress | The source is shared; a busy user can flag the egress. `LOG` default; allowlist the egress if needed |
| A CDN or load balancer without `client_ip` | All users share the proxy address and aggregate into one source; configure `client_ip` before enabling `BLOCK` |
| Hashed asset names that are not in the static list | Add the application's prefixes/extensions to `static_assets`; the built-in list covers common frameworks |

Because the default is `LOG`, a false positive produces a log line and a metric,
not a blocked user. The [readiness checklist](behavioral-readiness.md) still
applies before `BLOCK`.

### 7.2 Evasion

- **Distributed sources.** Per-source thresholds are bypassed by spreading the
  crawl across addresses. A global scraping signal would flag normal traffic;
  it is not attempted. Rate limits and the global request guard remain the outer
  bound.
- **Slow scraping.** A crawler below 40 distinct pages per minute is not
  detected. This is accepted; faster crawlers are the ones that stress a
  personal upstream.
- **Query-based pagination.** Path-only hashing misses `?page=N` sequences.
  Rate limits and rules remain responsible; adding query hashing would create
  more false positives than it removes.
- **Static camouflage.** Fetching static assets does not increase the content
  count, so it cannot dilute the signal; it only spends the source's rate
  budget. Fetching real content pages is the behavior being detected.
- **IPv6 rotation.** The source key is aggregated by `aggregate_ipv6_prefix`
  (default `/64`). A host with a larger allocation can rotate prefixes; this is
  the same limitation as Phase 1. The global request guard remains the backstop.
- **User-Agent and Referer spoofing.** The signal does not depend on either, so
  spoofing them gains nothing. It also means legitimate crawler identification
  relies on source allowlisting, not on a UA exemption.

### 7.3 Detector as a DoS target

- State is fixed-size per tracked source and bounded by `max_tracked_ips`.
- Observation is O(path length) for hashing and O(1) for counters; the static
  policy is a linear scan over at most 192 short entries.
- No path map, response body, header, or per-path list is retained.
- A saturated Bloom filter returns the 256-path cap; the threshold is capped at
  256 and the default is 40, so saturation does not create a false positive at
  normal thresholds. Saturation stores only bits and cannot grow memory.
- A missing entry is a no-op; behavior observation never turns tracking
  exhaustion into a rejection path.

### 7.4 Privacy

Only path hashes and counters are retained. The flag log includes the path that
triggered the flag, once per window, like the existing signals. Response
content, request headers, and query strings are not stored or exported.

## 8. Configuration

Proposed YAML:

```yaml
protection:
  behavior:
    enabled: true
    window: 60s
    min_requests: 30
    # Omit to use the built-in list. A provided list replaces that field's
    # default; an empty list disables that category.
    static_assets:
      prefixes: ["/static/", "/assets/", "/build/", "/dist/", "/_next/static/",
                 "/images/", "/img/", "/fonts/", "/media/"]
      paths: ["/favicon.ico", "/robots.txt", "/sitemap.xml", "/sitemap.xml.gz",
              "/manifest.json", "/site.webmanifest"]
      extensions: ["css", "js", "mjs", "map", "png", "jpg", "jpeg", "gif",
                   "webp", "avif", "svg", "ico", "woff", "woff2", "ttf", "otf",
                   "eot", "mp4", "webm", "mp3", "wav", "ogg", "flac", "m4a"]
    scraping:
      enabled: true
      action: LOG          # LOG (default) or BLOCK
      distinct_paths: 40
    enumeration:
      enabled: true
      action: LOG
      not_found_ratio: 0.5
      distinct_paths: 40
    auth:
      enabled: true
      action: LOG
      min_failures: 20
    global_auth:
      enabled: true
      window: 60s
      min_failures: 100
```

Backward compatibility:

- An existing configuration without `static_assets` or `scraping` gets the
  built-in defaults and the observation-only signal. No traffic changes.
- `ProtectionSpec` denies unknown fields, so an older binary rejects a
  configuration that contains the new blocks instead of silently ignoring them.
  The same rule that applies to the Phase 1 `behavior` block applies here.
- `rules.example.yaml` and `dist/rules.yaml` compatibility is unaffected: these
  fields live in the configuration, not in the managed rule set. The daily rule
  update never sees them.
- A failed reload keeps the previous compiled static policy and thresholds.

## 9. State and concurrency

The observation path keeps the existing lock discipline:

1. Lock the source shard, update counters and the Bloom filters, evaluate the
   flags, and apply a ban if configured.
2. Release the shard lock.
3. Return a `BehaviorOutcome`; the proxy layer increments metrics and logs.

No lock is held across an `await`, no I/O happens under the lock, and the global
authentication window is updated after the shard lock is released. The static
policy is immutable for the lifetime of a compiled configuration, so it needs no
lock.

A configuration reload swaps the compiled `Protection` (and therefore the static
policy) atomically through the existing `ArcSwap`; in-flight requests keep the
old policy until they finish, which is the same behavior as rule reloads.

## 10. Testing

### Unit tests (`src/protection/mod.rs`)

- A source with 40 distinct `200` `GET` paths in a window is flagged; 39 is not.
- Static paths do not count toward the content total or the distinct estimate.
- A custom static policy replaces the default for a field; an empty list
  disables that category.
- `POST`, `PUT`, `PATCH`, and `DELETE` `200`s do not count.
- `404` and `401` responses do not count as content responses.
- A `200` with a query-only difference is one path, not two.
- The flag is emitted once per window; window rollover resets the counters and
  both Bloom filters.
- `scraping.action: BLOCK` applies a ban, resets the behavior window, and the
  next request is rejected with `429`.
- An allowlisted source and `enabled: false` observe nothing.
- A source with no tracked entry is a no-op.
- A saturated content filter returns the 256-path cap and does not panic.

### Configuration tests (`src/config/mod.rs`)

- The block parses with defaults when omitted.
- A custom static policy parses and compiles; prefixes, paths, and extensions
  are matched as specified.
- Invalid entries are rejected: empty list entries, prefix/path entries without
  a leading `/`, whitespace/control characters, overlong entries, too many
  entries, extensions with a dot, and more than 32 extension bytes.
- Invalid `scraping` values are rejected: zero or greater than 256 distinct
  paths, unknown action, unknown field.
- A failed reload keeps the previous compiled policy and thresholds.

### Integration tests (`tests/proxy.rs`)

- A mock upstream returns `200` for 40 distinct paths; the
  `kunato_behavior_scraping_flags_total` and `kunato_behavior_content_total`
  counters move.
- Static paths do not move the scraping counter.
- A `POST` path does not move the content counter.
- `scraping.action: BLOCK` bans the source; the next request receives `429` and
  the upstream access count stops.
- A rule `BLOCK` response and a rate-limit rejection do not count as content.
- The signal works over HTTP/1.1 and HTTP/2; the existing HTTP/3 harness can be
  reused if the upstream status is controllable there.
- Hot reload changes `distinct_paths` and the static policy without restarting.
- `protection.enabled: false` and `--disable-protection` disable observation.

### Black-box suite

The runner starts Kunato with `--disable-protection`, so behavior detection is
inactive there. The black-box corpus is not the right place for a behavioral
assertion; integration tests are authoritative. Near-miss `allowed.txt` entries
for ordinary `200` browsing can guard against a future default `BLOCK`, but
they do not exercise the detector today.

## 11. Documentation and rollout

Phase 3a updates:

- `docs/behavioral-detection.md`: add the scraping signal, the static policy,
  the new metrics, and the limitations; point Phase 3 to this document.
- `docs/development.md`: configuration reference and tuning guidance.
- `docs/DESIGN.md`: Section 7 (behavioral detection state and observation) and
  Section 16 (move "200-only scraping" from future work to Phase 3a).
- `README.md`: mention `200`-only scraping observation in the behavioral
  detection feature.
- `rules.example.yaml`: a commented `scraping` block with `action: LOG` and a
  tuning note.
- `docs/attack-coverage.md`: update the Bot row and the Notable Gaps text. The
  row stays `Partial` while the bundled default is `LOG`; a signal is not
  `Covered` unless the default stops the attack.
- `docs/cve-coverage.md`: no change; CVEs remain the intake path for signatures.

Rollout:

1. Land the static policy and the scraping signal with `LOG`.
2. Run on a representative deployment and inspect
   `kunato_behavior_content_total`, `kunato_behavior_scraping_flags_total`, and
   the flag logs.
3. Raise `scraping.action` to `BLOCK` only after the false-positive rate is
   known and known crawlers are allowlisted.
4. Revisit global authentication mitigation only if a challenge or identity
   mechanism is designed.

## 12. Acceptance criteria

- The default configuration is observation-only; no request is blocked by the
  new signal unless `scraping.action: BLOCK` is set.
- A source fetching 40 distinct non-static `200` `GET` paths in the window is
  flagged; static assets, non-`GET` methods, `404`s, and `401`s do not count.
- The static policy is validated at load time, applies to both enumeration and
  scraping, and survives a failed reload with the previous value.
- State grows by a fixed amount per tracked source and stays within
  `max_tracked_ips`; observation allocates nothing per response.
- A scraping `BLOCK` uses the existing ban escalation and returns `429` on the
  next request.
- Metrics and logs are deduplicated per source, signal, and window.
- `cargo fmt`, `cargo clippy --all-targets -- -D warnings`,
  `./scripts/check-deny.sh`, and `cargo test` pass; no dependency is added.
- The black-box suite is unaffected.
- `docs/attack-coverage.md` reflects the honest status (`Partial` while the
  default is `LOG`).

## 13. Implementation map

| Area | Change |
| --- | --- |
| `src/config/mod.rs` | `StaticAssetsSpec`, `StaticAssets` (compiled), `ScrapingSpec`, `ScrapingConfig`; validation; defaults; parse and reload tests |
| `src/protection/mod.rs` | `BehaviorEntry` fields; shared path-filter helpers; `BehaviorSignal::Scraping`; `observe_response` method argument; scraping flag/ban; unit tests |
| `src/proxy/server.rs` | Pass `&parts.method`; add the scraping log branch and `content` metrics; integration tests in `tests/proxy.rs` |
| `src/metrics.rs` | `kunato_behavior_content_total`, `kunato_behavior_scraping_flags_total`; render/help tests |
| `src/cli.rs` / `rules.example.yaml` | Commented `static_assets` and `scraping` examples |
| `docs/*`, `README.md` | Documentation and attack-coverage update |

## 14. Open questions

1. **Default enabled or opt-in?** The recommendation is `enabled: true` with
   `LOG` and a threshold of 40. If early deployments show log noise from SPA or
   API clients, change the default to `enabled: false` before the release; the
   state cost is paid either way.
2. **Is 40 distinct paths per 60 s the right default?** It is high enough that a
   human browsing session rarely reaches it and low enough to catch a crawler
   within a minute. Tune after measuring a real site.
3. **GET only or GET+HEAD?** The recommendation is GET only. Add HEAD if a
   deployment observes a crawler that uses it.
4. **Should query strings count?** The recommendation is no. Query pagination
   remains a documented evasion; rate limits and rules cover it.
5. **Should static lists replace or extend defaults?** The recommendation is
   per-field replacement, consistent with `auth.paths`. The docs must show the
   defaults so operators can copy them.
6. **Is a global scraping signal worth it?** No. A global distinct-path count
   would flag normal traffic and a global ban would be an availability lever.
7. **When can global authentication mitigation ship?** Only with a challenge or
   identity mechanism that distinguishes a browser from a spray. Keep the
   current log-only signal until then.
8. **Should scraping use a longer window?** Start with the shared 60 s window.
   If slow crawlers are the dominant case, add a separate 300 s scraping window
   at the cost of one more `Instant` per tracked source and a second roll.
