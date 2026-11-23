# Offline EDR verification: slow authentication and reverse brute force

Date: 2026-11-23

Status: Offline proof of concept implemented and evaluated. The analyzer
(`kunato edr`) reads the console's `history.sqlite3` read-only, reports
evidence, and never bans or changes the WAF configuration. Automatic blocking
is not implemented; Section 8 explains the safe integration options.

## 1. Question

The console already stores rule detections, rejections, and minute aggregates
in SQLite. Can an hourly investigation of that history detect attack classes
that a per-request rule cannot see?

Two classes were selected:

1. **Slow authentication attempts.** One source sends a few login failures per
   hour, spread across the hour, so the bundled `login-throttle`
   (10 requests/60 s) never fires and the per-minute behavioral window stays
   below its threshold.
2. **Reverse brute force / distributed spraying.** Many distinct sources each
   try a small number of credentials against the same authentication endpoint,
   so no source-local threshold is reached.

## 2. Verdict

| Question | Result |
| --- | --- |
| Was the existing SQLite data sufficient? | No. The event table records rule matches, local rejections, decoys, and upstream failures; an ordinary upstream `401` on a login path was not stored per source. The minute buckets had status totals but no per-source authentication outcomes. |
| What was added? | Bounded authentication-failure measurements in the existing minute payload: total failures, top failing sources, top failing paths, and an estimated distinct-source sketch. No new table and no new dependency. |
| Can a slow source be detected from hourly history? | Yes, in the synthetic evaluation: a source failing once every six minutes (10/hour, below the 10/60 s throttle) was found in all six attack hours. Detection latency was the first hourly window (at most one hour). |
| Can a distributed campaign be detected? | Yes, in the synthetic evaluation: 60 sources with one failure each on `/login` were flagged in the same hourly window. The distinct-source estimate was 48 because the bounded sketch has a 64-register accuracy limit. |
| What did it cost in false positives? | One: a shared egress address with 12 failures spread over one hour was reported as slow authentication. It is evidence for review, not an automatic ban. |
| Can it block automatically? | Not in this work. The finding identifies a source or a campaign, but a campaign-wide block risks shared NAT and legitimate users. Section 8 lists the safe enforcement path. |

## 3. What the console already stores

`history.sqlite3` (schema version 4) contains:

- `events`: selected detail for rule matches, local rejections, decoys, upstream
  failures, and service gaps. Each row carries the client, site, redacted path,
  status, category/rule, and disposition. Ordinary access rows are not stored.
- `metric_buckets`: per-minute counters, client-visible status histogram,
  latency, connection gauge, and bounded supplementary measurements (top
  sources, top paths, countries, dimensions, unique-source sketch). The WAF
  currently writes the source-global bucket; authentication measurements are
  global for the minute.
- `history_buckets` and `rejection_buckets`: coarsened history and
  reason-separated statistics.

The important gap for this question is that an upstream `401` on `/login` is
only counted in the aggregate status histogram unless a LOG or BLOCK rule also
matches it. A slow attacker deliberately avoids those matches. The console did
not retain the source/path of an ordinary authentication failure.

## 4. Added telemetry

`AdditionalMeasurements` now has an authentication-failure section. The
payload version is 2; version-1 records remain readable and are reported as
missing telemetry, never as zero failures. A binary that predates version 2
cannot decode new records (`deny_unknown_fields`), so upgrade the WAF and
console together and do not downgrade a console that has written version-2
rows.

| Field | Meaning | Bound |
| --- | --- | --- |
| `auth_failures` | Upstream `401`/`403` responses on configured authentication paths in this source-minute | One `u64` |
| `auth_sources` | Top failing sources with counts and an omission bound | 16 entries per source-minute |
| `auth_paths` | Top failing paths with counts and an omission bound | 16 entries per source-minute |
| `unique_auth_sources` | Mergeable distinct-source estimate | 64-register HyperLogLog, 64 bytes |

The observation point is the existing behavioral hook after forwarding:

```text
upstream response 401/403
  -> behavior.auth / behavior.global_auth path matching
  -> observations::auth_failure()
  -> source-minute additional measurement
  -> console snapshot, SQLite metric bucket, coarsened history
```

Consequences and limits:

- Only upstream outcomes are recorded. A local rule `BLOCK`, rate-limit `429`,
  maintenance page, or upstream connect failure is not an authentication
  failure.
- The source is the resolved client identity (`client_ip`), the same key used
  by rules, rate limits, and behavioral bans.
- The path is the redacted path already used by the console; query strings and
  fragments are never stored.
- No username, password, token, request body, or cookie is recorded. The
  analyzer infers a reverse brute force from source diversity, not from account
  names.
- If behavioral detection is disabled, the source is allowlisted, or the
  request is already banned, the failure is not observed. This is the same
  boundary as the existing behavioral signal. A version-2 bucket with zero
  failures is therefore ambiguous: it can mean "no failures" or "observation
  disabled". The analyzer adds a note when a present-telemetry window has no
  failures; confirm `protection.behavior.auth` or `global_auth` and the path
  list before treating zero as quiet.
- Authentication-path matching uses `protection.behavior.auth.paths`. The
  default list covers the bundled login/token/session/SSO shapes; add an
  application-specific login endpoint there or the analyzer will not see it.
- The top-16 rankings bound storage and CPU. A campaign with more than 16
  distinct failing sources per minute under-counts individual sources; the
  total and the distinct sketch still describe the campaign.
- When a record exceeds the 16 KiB supplementary budget, the shrink order drops
  legacy dimension/path/source detail before it drops authentication sources,
  so the EDR evidence is the last optional detail to go.

## 5. Analyzer

### 5.1 Inputs and window

`kunato edr` opens the database with read-only, no-follow flags, validates the
Kunato application ID and schema version, and reads at most 100,000 buckets per
range. It never writes to the database or to the WAF.

- Window: the last complete hour by default (`--window 1h`), or an explicit
  UTC range ending at `--until`. A longer window (for example `6h` or `24h`)
  trades latency for sensitivity to very slow sources.
- Baseline: the preceding 168 hours by default (`--baseline 168h`). The
  baseline uses a median and median absolute deviation, so a sustained attack
  that occupies a minority of baseline hours does not become its own normal.
- Coarse history: metric buckets are preferred over the history copy of the
  same interval. Coarser buckets are accepted when the minute rows have already
  been compacted; activity and gap estimates are then marked conservative.

### 5.2 Slow-authentication rule

For each source, with failures counted from the per-minute `auth_sources`
ranking:

```text
failures >= 6
active buckets >= 4
span >= 30 minutes
max failures per minute <= 3
```

Then one of:

- **New source:** the source has no baseline failures, the inter-arrival
  coefficient of variation is at most 1.0, and `failures >= 8`.
- **Known source:** the current hour is at least 4 failures above the baseline
  median and the median-based z-score is at least 3.0; an irregular source also
  needs at least 6 active buckets.

The rate ceiling deliberately stays below the bundled 10/60 s login throttle:
the detector is looking for behavior that the throttle is designed not to
punish. A source that bursts faster is expected to be handled by the existing
throttle, rate limiter, and behavioral signals.

### 5.3 Reverse-brute-force rule

With the campaign totals and the merged distinct-source estimate:

```text
failures >= 30
distinct failing sources >= 10
mean failures per source <= 4
top authentication path share >= 0.5
hourly failures at least 15 above the baseline median and z >= 3
```

The path-share condition distinguishes a campaign aimed at one login endpoint
from broad probing. The per-source mean condition distinguishes many sources
with one or two attempts from one noisy source; the latter is handled by the
slow rule or the existing throttle.

### 5.4 Output

The table format prints the window, telemetry state, totals, top paths, each
finding with its evidence, and the recommendation. The JSON format is the
stable machine-readable form:

```sh
kunato edr --database /var/lib/kunato/console/history.sqlite3 \
  --window 1h --until 2026-11-23T15:00:00Z --format json
```

`--fail-on-findings` exits non-zero when at least one finding is reported, so a
systemd timer or cron wrapper can raise an alert.

## 6. Synthetic evaluation

The evaluation lives in `tests/edr_evaluation.rs`. It writes 1,440 one-minute
metric buckets (24 hours) through the real `Store` and then calls the same
analyzer the CLI uses.

Population:

| Traffic | Shape |
| --- | --- |
| Background | 3 requests/minute to a normal page |
| Benign users | 5 sources with one infrequent failure each |
| Shared egress probe | 12 failures over one hour from one source (deliberate false-positive probe) |
| Burst probe | 8 failures in 8 minutes from one source |
| Slower source | 1 failure every 15 minutes for 7 hours (28 failures) |
| Slow target | 1 failure every 6 minutes for 6 hours (60 failures) |
| Reverse target | 60 sources, 1 failure each, in one hour on `/login` |
| Benign reset wave | 20 sources, 1 failure each, in one hour |
| Single-source retry | 20 failures in 20 minutes from one source |

Results with the default one-hour window and a 24-hour baseline:

| Hour | Ground truth | Finding |
| --- | --- | --- |
| 00–04, 06–09 | benign | none |
| 05 | benign shared egress | slow `198.51.100.10` (12 failures, CV 0.24) — **false positive** |
| 10–15 | slow attack | slow `203.0.113.7` in all six hours (10 failures/hour, 10 active buckets, 55-minute span, max 1/minute, CV 0) |
| 16–17 | benign | none |
| 18 | reverse brute force | reverse campaign: 60 failures, 48 estimated distinct sources, mean 1.24/source, top path share 1.00 |
| 19–23 | benign | none |

Summary:

```text
slow:    6/6 attack hours detected, 1 false positive, first detection in the
         first attack window (latency <= 1 hour)
reverse: 1/1 attack hour detected, 0 false positives, first detection in the
         same window
```

The 15-minute source (4 failures/hour) is below the one-hour volume and active
bucket thresholds. The second test analyzes a six-hour window over the same
corpus and detects it with 24 failures, 24 active buckets, and 1 failure per
minute. The same six-hour window also reports the shared-egress probe; it is the
same known false positive, not a second independent one. This is the intended
tuning path for slower sources:

```sh
kunato edr --window 6h --baseline 168h
```

The 64-register distinct-source sketch estimated 48 for 60 true sources. The
HyperLogLog relative standard error is about 13%; the campaign threshold of 10
is far below the estimate, so the error does not change the verdict. A
high-cardinality campaign near the threshold needs more headroom or a larger
sketch in a future schema version.

The two tests finish in about one second on the development machine,
including creating and reading the 1,440-row database. The analyzer performs
24 separate hourly reads in that run.

## 7. What is still not detected

- **Sub-threshold slow sources.** One failure every 15 minutes is invisible to
  a one-hour window; a six-hour window catches it. One failure every 30 minutes
  needs an even longer window and will conflict with the baseline if the source
  is also a legitimate user.
- **Jittered new sources.** A new source with randomized gaps is not flagged by
  the regularity branch. It is flagged from a later hour if the baseline
  elevation condition is met; a first-hour jittered attack can be missed.
- **Usernames and passwords.** The WAF does not see account identity. A
  reverse brute force is inferred from source diversity and endpoint
  concentration. A single source trying one password against many accounts
  looks like ordinary brute force and is handled by the existing throttle.
- **Successful logins.** The telemetry counts failures only. A campaign that
  succeeds on the first attempt leaves no failure trail. Application-side
  authentication success/failure correlation is out of scope.
- **Application status semantics.** The telemetry counts `401`/`403` only. A
  login form that returns `200` with an error message, or `302` back to the
  form, produces no authentication-failure evidence. Confirm the application's
  failure status before relying on the analyzer, or add a response rule that
  normalizes the failure shape where that is safe.
- **Shared egress and automated clients.** A NAT, office egress, or monitoring
  client can produce a regular failure pattern. The evaluation shows this
  explicitly. Keep the finding at LOG until the address population is known,
  and use `protection.allowlist` for trusted sources.
- **Collection gaps.** The analyzer marks incomplete telemetry and coarsened
  buckets. It does not reconstruct requests that the collector never received.
- **Campaign attribution.** The distinct-source estimate merges minutes; it
  cannot prove that the sources are one actor. The finding is a campaign
  signal, not an attribution.
- **Multiple authentication endpoints.** The campaign rule needs at least half
  of the failures on one path. A campaign that splits attempts evenly across
  `/login`, `/api/login`, and an SSO endpoint can keep each path's share below
  the threshold.

## 8. Blocking analysis

The WAF already has the mechanisms needed to enforce a decision:

- per-source bans with escalation and `protection.allowlist`;
- the global authentication block, which requires a recent source-local
  failure before rejecting that source;
- rate limits and connection budgets.

The analyzer does not call any of them. A safe sequence is:

1. **Observe.** Run `kunato edr` hourly with the default thresholds and keep
   the JSON output. Compare the findings with the application's own login logs.
   The first day has a weak baseline; wait for at least 24 hours.
2. **Source-scoped slow bans.** After confirming that the flagged address is
   not shared egress, apply a short source ban through the existing ban
   mechanism. A one-hour ban would have stopped the synthetic attacker's next
   10 attempts and no benign requests; it would also have blocked the shared
   egress probe, which is the false positive to review first.
3. **Campaign response.** Do not ban every source in a distributed campaign.
   Attackers rotate addresses, and a blanket block is a denial-of-service
   against shared NAT users. Prefer the existing global authentication block
   (which still requires a source-local failure), a step-up challenge, or an
   operator-approved short ban for the highest-volume sources only.
4. **Optional control-plane integration.** If automatic enforcement is needed
   later, add a loopback-only admin command that accepts a bounded list of
   source addresses, an expiry, and an allowlist check, and records who applied
   it. Do not let the analyzer write the WAF's in-memory state directly, and do
   not reuse `admin_access` for this purpose.

Until that work is done, `--fail-on-findings` is the notification boundary:
the timer fails, journald records it, and an operator decides.

## 9. Hourly operation

Example systemd timer (run as the user that owns the console database):

```ini
# /etc/systemd/system/kunato-edr.service
[Unit]
Description=Kunato offline authentication-abuse analysis
After=kunato-console.service

[Service]
Type=oneshot
User=kunato
ExecStart=/usr/local/bin/kunato edr \
  --database /var/lib/kunato/console/history.sqlite3 \
  --window 1h --baseline 168h --format json --fail-on-findings
StandardOutput=journal
StandardError=journal
```

```ini
# /etc/systemd/system/kunato-edr.timer
[Unit]
Description=Run Kunato EDR analysis every hour

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
```

The database is created with mode 0600 in a 0700 directory. The timer's user
needs read access; do not make the database world-readable to run the timer as
another user.

## 10. Reproduction

```sh
cargo test --lib edr::tests
cargo test --test edr
cargo test --test proxy authentication_failures_are_attributed_to_the_source_minute
cargo test --test edr_evaluation -- --nocapture
```

The last command prints the per-hour table and summary used in Section 6.

For a real database, the analyzer opens `history.sqlite3` read-only and can run
while the console is collecting. If you need a stable file copy, stop the
console first or use SQLite's backup interface; copying only the main file while
a transaction is in progress is not a consistent snapshot.

```sh
kunato edr --database /var/lib/kunato/console/history.sqlite3 \
  --window 1h --format table
```

A version-1 database (before the telemetry change) reports `telemetry:
missing`; run the updated WAF and console for at least one hour before
expecting findings.

## 11. Recommendation

A separate [live in-memory source verification](edr-live-verification.md)
evaluates keeping the state in memory and feeding it from the WAF snapshot
directly. The chosen implementation is an opt-in console task that subscribes
to the console's one-second accepted stream, so it has no polling gap and no
second SQLite connection. A standalone poller remains a four-minute-cadence
option because a five-minute poll has no one-missed-poll margin against the
WAF's ten-minute snapshot ring.

Adopt the offline analyzer as a LOG-only investigation tool and keep the
existing behavioral and rate-limit controls as the enforcement layer. The
synthetic evidence supports detection of the two target patterns, but the
shared-egress false positive and the bounded distinct-source estimate mean
that automatic blocking is not justified yet. Re-evaluate after collecting a
week of real findings alongside the application's authentication logs.
