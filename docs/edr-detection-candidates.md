# EDR detection candidates

Date: 2026-11-23

Status: Candidate B (success after sustained failures) is implemented and
evaluated; see Sections 4.1, 5.5, 6.1, and 7 of
[the offline verification](edr-verification.md). Candidates A and C–G remain
proposals. The current detectors are `slow_authentication`,
`reverse_brute_force`, `auth_success_after_failures`, and `campaign_success`;
the live source runs the same four rules, see
[the live source verification](edr-live-verification.md).

## 1. Purpose

This document records the detection classes worth adding after the first EDR
release, why each matters for a personal or small self-hosted service, what
data it needs, and how it should be validated.

The current implementation deliberately covers only two patterns:

| Detector | Pattern | Boundary |
| --- | --- | --- |
| `slow_authentication` | One source keeps failing authentication below the burst throttle | Upstream `401`/`403` on configured authentication paths |
| `reverse_brute_force` | Many sources each fail a few times on the same authentication endpoint | Estimated distinct sources, failure volume, endpoint concentration |

Fast brute force from one source remains the responsibility of `login-throttle`,
rate limits, bans, and `protection.behavior.auth`. Enumeration bursts,
scraping, and cross-request continuity remain with
[behavioral detection](behavioral-detection.md).

A new EDR detector is justified only when it answers a question that the
per-minute controls cannot:

- activity spread over hours or days,
- many sources acting together,
- success or failure outcome changes,
- a long-term baseline that is not available in a small per-minute window.

## 2. Evaluation criteria

Every candidate should be judged on:

1. **Evidence strength.** Does it identify behavior, not just a signature that
   a rule could match?
2. **Data availability.** Can it use the existing minute buckets and selected
   events, or does it need a new bounded measurement?
3. **False-positive cost.** What benign behavior looks the same?
4. **Actionability.** What should an operator do after the finding?
5. **Bounded cost.** Fixed memory, bounded storage, no unbounded per-source or
   per-path map.
6. **Privacy.** No usernames, passwords, request bodies, query strings, raw
   cookies, or per-request access history.

A candidate that cannot name a safe operator action should stay as a metric or
a log line, not a finding.

## 3. Candidate summary

| ID | Candidate | Data | Effort | Priority | Proposed action |
| --- | --- | --- | --- | --- | --- |
| A | Authentication endpoint-family campaign | Existing `auth_paths` / `auth_sources` | Small | High | LOG, optional short source ban after review |
| B | Success after sustained failures | Version-3 authentication-success telemetry | Medium | High (implemented) | LOG only; operator investigation |
| C | Slow 404/403 enumeration | New per-source path/status telemetry | Medium | High | LOG; source rate limit after review |
| D | Sensitive-action abuse (reset/OTP/MFA) | New sensitive-path telemetry | Medium | Medium-high | LOG; step-up or short source throttle |
| E | Distributed admin/API reconnaissance | Existing events, limited to matched paths | Small-medium | Medium | LOG; operator review |
| F | Availability and error anomaly | Existing global metrics | Small | Medium | LOG; distinguish outage from attack |
| G | Multi-day campaign and IP rotation | Hourly path/source sketches | Large | Later | Campaign summary, not blanket ban |

The order is deliberate. A closes a known evasion of the current reverse
detector without new telemetry. B, C, and D need bounded telemetry but address
high-value outcomes. E and F provide value with the data already stored. G
should wait for operational evidence from A through D.

## 4. Candidate details

### A. Authentication endpoint-family campaign

**Problem.** The current reverse-brute-force rule requires at least half of the
failures on one path. An attacker can split attempts across `/login`,
`/wp-login.php`, `/api/v1/auth`, and an SSO endpoint and keep each individual
path below the share threshold.

**Signal.** Classify authentication paths into families and aggregate the
campaign at the family level:

```text
login      /login, /logon, /signin, /wp-login.php, /xmlrpc.php,
           /users/sign_in, /admin/login
token      /api/.../(auth|login|token|session|oauth)
sso        /saml, /realms, /openid-connect
mfa        /mfa, /otp, /totp
```

The existing checks then apply to the family total:

```text
family failures >= 30
distinct failing sources >= 10
mean failures per source <= 4
largest family share >= 0.5
hourly failures >= baseline median + 15 and z >= 3
```

**Data.** The existing `auth_paths` ranking is enough to classify paths into
families. No new telemetry is needed. The offline analyzer and the console task
share the same aggregation code, so both can add this.

**False positives.** Path classification must not treat unrelated endpoints as
one family. A busy site with several legitimate login methods may look like one
family; keep the volume and baseline conditions.

**Action.** Same as the current campaign finding: LOG, investigate, and use the
existing global-auth throttle if enforcement is needed. Do not ban every source
in the family.

**Verification.** Re-run the synthetic 60-source campaign split evenly across
three login paths and compare with the unsplit campaign. The expected result is
that the split campaign is reported at the family level, while a benign mix of
login methods stays below the threshold.

### B. Success after sustained authentication failures

**Status: implemented.** The offline analyzer and the console's live EDR report
`auth_success_after_failures` and `campaign_success` findings. The implemented
rules keep the per-source six-failure / 60-minute / 15-minute shape below. The
campaign variant also requires the success source to be within 15 minutes of
its last failure, which this proposal left implicit. Success statuses are
restricted to `200`..`399`, the configuration is opt-in per endpoint, and the
findings are HIGH severity but LOG only. The telemetry is the version-3
`auth_successes` counter and top-16 `auth_success_sources` ranking.

**Problem.** The current telemetry counts only failures. A reverse brute force
or credential-stuffing campaign can eventually succeed, but the WAF has no
success signal and the EDR cannot report a possible compromise.

**Signal.** Per-source, and optionally globally:

```text
source failures >= 6 within one hour
  followed by a successful authentication response within 15 minutes
  -> possible credential compromise

global failures >= 30 and distinct sources >= 10
  followed by any success from a source that contributed a failure
  -> possible campaign success
```

**Data.** New bounded telemetry is required:

- per-source authentication successes in the minute;
- the success status/method scope, because a `200` login page is not a
  successful login;
- a configured set of success statuses and methods per authentication family.

A practical default is `POST` with `2xx`/`3xx` on a configured authentication
path, but the application's semantics must be confirmed. A login that returns
`200` with an error body is indistinguishable without a response-body rule and
should not be treated as success.

**False positives.** A legitimate user who mistypes a password and then
succeeds is the normal case. Use the finding only after a sustained failure
pattern, mark it high severity but LOG-only, and never auto-ban. Without
username visibility this is "the source changed from failing to succeeding,"
not proof of account compromise.

**Action.** Operator reviews the application's authentication logs for that
source/time range. If the application supports it, force a password reset or
step-up challenge.

**Verification.** Synthetic scenarios:

- user fails twice then succeeds: no finding;
- slow attacker fails ten times then succeeds: finding;
- distributed campaign with one success: global finding;
- `200` error page: no finding unless explicitly configured.

### C. Slow 404/403 enumeration

**Problem.** The per-minute behavioral enumeration signal catches bursts. A
scanner that requests one missing path every few minutes for hours stays below
the per-minute distinct-path and ratio thresholds. The existing continuity
score sees some of this, but a long, low-rate exploration does not cross its
action threshold.

**Signal.** Per source over a six- or twenty-four-hour window:

```text
distinct 404/403 paths >= 30
404/403 count >= 20
max 404/403 per minute <= 3
span >= 2 hours
404/403 ratio relative to the source's requests above a configured value
```

The distinct-path estimate needs a bounded sketch, not a path map. Exclude
static assets using the same helper as the behavioral enumeration signal.

**Data.** New telemetry:

- per-source `not_found` and `forbidden` counts;
- a per-source 64- or 256-bit path sketch;
- enough requests to compute a ratio;
- optional path-class counts for admin, config, backup, and upload paths.

A top-16 source ranking alone is not enough: a slow scanner may not be in the
top 16 by total requests. The per-source sketch must be bounded and mergeable
across minutes.

**False positives.** Broken links, SPA client routes, stale source maps, API
clients probing optional endpoints, and web crawlers. Use static exclusions,
allowlists, a baseline for the source, and require both distinct paths and a
ratio. A site with a deliberately public 404-heavy API needs a local override.

**Action.** LOG first. After confirming the source is not a crawler or a
monitoring client, apply a source-scoped rate limit or short ban with the
existing ban mechanism.

**Verification.** Build a corpus with benign 404s (broken links, SPA routes,
favicon/source maps) and slow scanners with different path distributions and
timing. Measure precision/recall over six- and twenty-four-hour windows, and
check that the state remains bounded for a scanner that uses ten thousand
distinct paths.

### D. Sensitive-action abuse (password reset, OTP, MFA, signup)

**Problem.** Authentication is not the only credential surface. Password-reset
token guessing, OTP guessing, MFA retry abuse, and signup/invite probing can be
slow enough to avoid per-minute limits, and some of them return `400`, `403`, or
`200` rather than `401`.

**Signal.** Treat configured sensitive path classes like the authentication
surface:

```text
sensitive class = reset | otp | mfa | signup | invite
per-source failures >= 5
active minutes >= 4
span >= 30 minutes
max failures per minute <= 3
```

Optional higher-confidence variants:

- success after failures on a reset/OTP class;
- many distinct sensitive paths per source;
- one source touching reset and OTP classes in the same window.

**Data.** New telemetry with path classes and status classes. A reset form that
returns `200` on an invalid token needs a configured failure status or a
response-body rule; otherwise the WAF cannot see the failure. OTP failures are
more likely to be `401`/`403`/`400`.

**False positives.** Users retrying a reset or OTP, support staff, and
monitoring. Keep the finding at LOG and require a configured path class so a
normal API 400 is not counted.

**Action.** LOG; consider a short source throttle or step-up only after the
application confirms the failures. Do not block the whole reset/OTP endpoint
globally.

**Verification.** Synthetic benign reset retries and slow OTP guessing, plus a
`200`-error form to confirm the detector does not invent failures.

### E. Distributed administrative/API reconnaissance

**Problem.** Many internet scanners and targeted campaigns probe the same
administrative or API paths from many source addresses. Per-source thresholds
miss the campaign; the current global authentication window only covers
authentication failures.

**Signal.** Aggregate selected events by path over a rolling window:

```text
distinct sources for one path >= 10
and the path's baseline is near zero (for example, fewer than one request/day)
and the sources are not already explained by a known scanner population
```

For paths that are common internet noise (`/.env`, `/wp-login.php`,
`/phpmyadmin`), require a much higher volume or a site-specific path. A path
that is unique to the deployment is the strongest signal.

**Data.** The existing event table contains rule matches and local rejections
with client, path, category, and status. Admin-interface and API-discovery
categories are already LOG by default, and blocked sensitive paths produce
rejection events. Coverage is therefore limited to paths that a rule or local
policy already matches; ordinary upstream `404` responses are not stored.

This candidate is a good first step because it needs no schema change, but it
must be described as **event-based** reconnaissance, not complete enumeration.

**False positives.** Internet background scanning, search-engine crawlers, and
a newly deployed public API that suddenly receives traffic. Use a long baseline,
path rarity, and an allowlist for known scanner populations.

**Action.** LOG; operator examines the path and source distribution. A targeted
campaign against a site-specific admin path may justify a temporary maintenance
or administrative gate, but not a blanket source ban.

**Verification.** Replay a synthetic mix of background scanner traffic,
distributed probes against a rare site-specific path, and a new public API
launch. Measure false positives per day and the effect of excluding common
scanner paths.

### F. Availability and error anomaly

**Problem.** Low-rate resource exhaustion, an endpoint that starts returning
`5xx`, and a slow upstream degradation can evade simple rate limits. The
per-minute counters show the symptom but not a sustained anomaly.

**Signal.** Use the existing metric buckets:

- `5xx` ratio and upstream timeout/failure counts;
- p95 latency from the retained histogram;
- request volume and top paths;
- number of distinct sources.

Detect a sustained shift over several buckets against the trailing baseline,
and report the affected path and status class where available. Distinguish:

- client-error probing (`4xx`) from server failure (`5xx`);
- an upstream outage (timeouts/connection failures, all sources) from an
  attack (a path/source concentration, a sudden 5xx burst on one endpoint);
- a deployment (a new version, a new certificate) from hostile traffic.

**Data.** Existing global metrics are enough for a first version. A per-path
5xx breakdown is not stored; the top-path ranking is global and not
status-specific. A stronger version needs per-path status telemetry.

**False positives.** Deployments, certificate changes, upstream database
maintenance, and unrelated internet outages. The finding should say
"availability anomaly" and include the evidence; it should not claim an attack.

**Action.** LOG and operator review. This is an investigation trigger, not an
automatic block.

**Verification.** Synthetic scenarios for a normal deploy, an upstream outage,
a single path returning 5xx under load, and a distributed low-rate request
increase. Confirm that the detector distinguishes outage from attack and does
not fire on a normal restart.

### G. Multi-day campaign and IP rotation

**Problem.** A campaign can rotate source addresses and stay below every
hourly and per-source threshold for days. The current telemetry keeps only
short source/path rankings and a 24-hour sequence score.

**Signal.** Maintain hourly, bounded path/source sketches for a longer horizon
(for example, seven days) and look for:

- the same rare path set observed from many source addresses;
- the same timing pattern or country/ASN cluster;
- a source returning with the same path/timing after a ban;
- a decoy token or session identifier connecting attempts across addresses.

**Data.** This is the most expensive candidate. It needs either:

- a per-path HLL of sources plus a per-source path Bloom, both bounded and
  mergeable; or
- a compact hourly campaign fingerprint derived from the existing auth and
  future enumeration telemetry.

The existing decoy correlation table can connect token use, but it does not
replace a general campaign fingerprint.

**False positives.** Shared egress, CDN ranges, cloud scanners, and normal
seasonal traffic. A campaign finding should be a summary with evidence, not an
automatic ban.

**Action.** Operator review, longer retention of relevant events, and possibly
a temporary administrative gate. Do not ban an ASN or a country automatically.

**Verification.** Simulate a multi-day campaign with address rotation, a benign
cloud workload with similar volume, and a shared NAT. Measure whether the
campaign is distinguishable from the benign populations.

## 5. Shared telemetry proposal

Candidates B, C, and D need a bounded **source-outcome** measurement. Rather
than three unrelated additions, one version-3 supplementary section can carry
the minimum needed by all three:

```text
source_outcomes (top 16 sources per minute)
  source
  requests
  status_class_2xx / 3xx / 4xx / 5xx
  not_found / forbidden
  auth_failures / auth_successes
  path_bloom (64 or 256 bits)
  sensitive_class_counts (login/reset/otp/mfa/signup)
```

Additional bounded detail:

```text
path_outcomes (top 16 paths per minute)
  path
  status_class counts
  source_hll (64 registers)
```

Estimated cost, per source-minute:

- 16 sources x (counters + 64-bit/two-word path Bloom) is roughly 1 KiB;
- 16 paths x (counters + 64-register HLL) is roughly 1 KiB;
- the existing authentication section remains.

This is larger than the current authentication telemetry but still bounded. It
must be subjected to the existing record-size shrink path and a 30-day storage
budget calculation before implementation. If the budget is tight, split the
addition into two versions: success/failure outcomes first, path sketches
second.

The measurement must remain aggregate:

- no raw path map per source;
- no query string, body, cookie, username, or per-request row;
- paths hashed or redacted with the existing path rules;
- top-16 and fixed-size sketches only.

The console's `LiveEdr` and the offline analyzer should share the same
aggregation and detection code, as the current authentication detectors do.
Version-2 records stay readable; the analyzer reports missing fields rather
than zero.

## 6. Phasing

### Phase 1: existing data, no schema change

- **A** authentication endpoint-family aggregation;
- **E** event-based distributed administrative/API reconnaissance;
- **F** availability and error anomaly.

This phase can be verified with the current SQLite history and the console's
accepted snapshot stream. It should be released as LOG-only findings.

### Phase 2: bounded source-outcome telemetry

- **B** success after sustained failures — implemented with a smaller
  authentication-success section rather than the full source-outcome payload;
- **C** slow 404/403 enumeration;
- **D** sensitive-action abuse.

This phase needs the version-3 supplementary measurement, schema compatibility
work, storage-budget measurements, and a new synthetic corpus. It also needs
application-side confirmation of success/failure semantics for each configured
endpoint.

### Phase 3: campaign correlation

- **G** multi-day campaign and IP rotation;
- a campaign summary that combines decoy evidence, authentication outcomes, and
  enumeration sketches.

This phase should start only after Phase 1 and 2 have produced real findings
and false-positive data.

## 7. Verification requirements

Every new detector needs:

- a deterministic synthetic corpus with benign background:
  - broken links and SPA 404s,
  - legitimate password retries and resets,
  - monitoring clients and crawlers,
  - shared NAT and cloud egress,
  - a normal deployment and an upstream outage;
- attack variants:
  - slow and bursty,
  - single-source and distributed,
  - path-split and single-endpoint,
  - success after failure and failure-only,
  - address rotation;
- reported precision, recall, detection latency, and false positives per day;
- a memory/state-size bound and a restart/gap test;
- a test that the console collection path and SQLite writer are unaffected;
- a test that malformed or version-1 records produce a missing-telemetry note,
  not a false clean result.

A detector that cannot demonstrate a useful precision/recall tradeoff against
the benign corpus should remain a metric or be removed rather than shipped.

## 8. Non-goals

- Per-account, per-username, or per-password tracking without application
  identity.
- Raw request/response logging, query strings, bodies, cookies, or credentials.
- Replacing real-time rate limits, bans, protocol limits, or rules.
- Automatic campaign-wide bans or country/ASN bans from EDR findings.
- Proving that a specific person or account was compromised.
- A machine-learning dependency or an external service. The deployment remains
  one binary and one configuration file.

## 9. Open questions

1. Which success statuses and methods identify a successful login for the
   supported application profiles (WordPress, Rails, Laravel, generic APIs)?
   Resolved operationally: the operator records the success status, method,
   and intermediate redirects in the
   [behavioral readiness checklist](behavioral-readiness.md) and configures
   `protection.behavior.auth.success`; no profile defaults are shipped.
2. Should authentication families and sensitive path classes be built-in,
   configured, or both?
3. Is a 64-register HLL sufficient for slow enumeration, or does the path
   sketch need 256 bits?
4. Can the version-3 source-outcome section fit the existing 16 KiB/minute
   record budget at 30 days, or does it need a separate history table? The
   implemented success section is small (one counter and one top-16 ranking) and
   uses the existing shrink path. The full source-outcome payload in Section 5
   is still unmeasured.
5. Should path/source outcomes be global or split per site? The current
   authentication telemetry is global; a per-site split multiplies state.
6. How long should campaign fingerprints be retained, and how are they
   expired?
7. Which findings should be visible in the console UI, and which remain
   journald-only?
8. Should an operator be able to acknowledge a finding so it is not repeated
   every hour?

## 10. References

- [Offline EDR verification](edr-verification.md)
- [Live in-memory EDR verification](edr-live-verification.md)
- [Behavioral detection](behavioral-detection.md)
- [Console storage](monitoring-console-storage.md)
- [Attack coverage](attack-coverage.md)
