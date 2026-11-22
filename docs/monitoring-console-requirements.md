# Monitoring console requirements

Date: 2026-11-16

Status: Product and UI requirements. The fictional-data prototype implements
the interaction design; Phases 1 through 4 implement persistence, collection,
UTC history, retention, and supplementary measurements.
[Phase 5](monitoring-console-phase5.md) delivers the read-only console process,
HTTP/SSE APIs, and an embedded real-data UI.
[Phase 6](monitoring-console-phase6.md) adds the source allowlist, Host
validation, authentication, and TLS. Requirement identifiers describe intended
behavior; a delivered endpoint does not imply that every requirement below is
fully implemented.

See [design and implementation status](monitoring-console.md),
[storage and retention](monitoring-console-storage.md), and
[remaining work](monitoring-console-remaining.md). The interaction review
surface remains [the console prototype](../ui/console-prototype/README.md);
the delivered UI is the smaller read-only page served by the console binary.
The [revised Phase 2 proposal](monitoring-console-phase2.md) makes bounded
in-memory WAF measurements authoritative for statistics; normal-access logs
and retained event rows are not prerequisites for counting requests.
The [cadence evaluation](monitoring-console-cadence.md) recommends one-second
coalesced live statistics updates with independent ten-second persistence.

## 1. Shared console requirements

| ID | Requirement |
| --- | --- |
| UI-01 | Use one application shell with a left sidebar switching between Metrics and Real-time monitor. Both views belong to the same optional console. |
| UI-02 | Show WAF state, collection/connection state, and the latest data-update time separately. A disconnected collector must not look like zero traffic or prove the WAF has stopped. |
| UI-03 | Use UTC for initial reporting and show UTC, the selected site, effective time range, and aggregation grain. Make the scope of event-only filters distinct from whole-view request totals. |
| UI-04 | Keep browser navigation and display pause independent of server collection, storage, aggregation, and expiry. |
| UI-05 | Support desktop and mobile layouts. On narrow screens, use accessible navigation and contain wide-table scrolling within the table. |
| UI-06 | Support keyboard navigation, readable event details, clear focus, and reduced-motion preferences. Color must have labels or other supporting context. |
| UI-07 | Keep initial functionality read-only. Do not include protective-policy changes or administrative write operations. |
| UI-08 | Render source-controlled event values as text. Do not display raw credentials, request bodies, authorization values, or query strings. Redact token-bearing paths. |
| UI-09 | Show unavailable, expired, incomplete, estimated, and missing information honestly; do not replace it with zero or fictional precision. |
| UI-10 | Clearly identify fictional preview data and simulated connection state. Prototype controls must not imply a connection to the user's WAF. |

The prototype uses English for repository-artifact consistency and offers JST
and UTC display. The delivered UI uses UTC, the adopted reporting policy, and
offers 1 hour, 24 hours, 7 days, and 30 days; the fictional prototype still
shows JST and the superseded 90-day/one-year options. Final
language-localization policy is not decided by this document.

## 2. Metrics view

Purpose: review traffic, protection, and service impact across a selected
historical period. Arrange period controls and summary cards first, then trends
and decoy signals, breakdowns/rankings, service health, and operational/data
quality information.

### MET-01: Reporting period and comparison

- Offer 24 hours, 7 days, 30 days, and a custom date range within retained data.
  The prototype's 90-day and one-year options are superseded for real data.
- Default to the last 7 days.
- Reject invalid or reversed custom ranges and disclose retained-range limits.
- Select an appropriate aggregation grain and show it to the operator.
- Preserve the adopted 1/5/10/20/60-minute precision tiers in the
  [storage policy](monitoring-console-storage.md#5-adopted-statistics-retention-policy).
  Daily charts derive from retained UTC hours. Show changes of grain and do
  not prorate coarse bucket counts into unsupported subintervals; disclose any
  snapped effective bounds and the available oldest boundary.
- Support comparison with the immediately preceding equal-duration period
  when its scope, boundaries, coverage, and retained input support it. A
  30-day selection has no retained preceding 30-day comparison; show it as
  unavailable rather than zero or a synthetic estimate.
- Show UTC and mark incomplete comparison periods.
- When site attribution is supported, allow all sites or a selected site.
  Do not present synthetic host statistics as measured data.

### MET-02: Summary cards

Show the selected-period values for:

- Total observed HTTP requests.
- Requests rejected by the WAF, counted once per request.
- Rejection rate with a denominator from the same measurement scope.
- Requests with LOG detections, with overlap rules documented.
- Upstream connection failures and timeouts, with their components clear.
- Decoy credential-use attempts and observed distinct credential identifiers.

Show the previous-period change where a valid comparison exists. Distinguish
percentage changes from percentage-point changes, and treat a zero or missing
comparison denominator explicitly.

### MET-03: Trends

- Traffic volume and average request rate.
- Rejected requests and rejection rate.
- LOG-detected requests.
- Active connections, using appropriate average/maximum gauges.
- Upstream errors and overload-related admission rejection.
- Mark collection gaps and notable decoy-use observations on the time axis.
- Permit inspection of individual intervals with a chart tooltip or equivalent.
- Do not stack overlapping LOG and BLOCK counts as disjoint traffic.

### MET-04: Rejection reasons

Provide counts, proportions, and trends for the applicable mechanisms:

- YAML rule blocks, including an explicitly identified rule-rate-limit subset.
- Source rate limiting and requests rejected while a source is banned.
- Global load shedding or inspection-budget exhaustion.
- Host/authority, body size, decoding, form, upload, GraphQL, SAML, and other
  applicable built-in inspection rejection.
- Closed administrative access gates.
- Qualified decoy credential-use rejection.

Track response-phase replacement separately from request-phase rejection.
Keep configured policy denial, service overload, and attack classification
distinguishable even when the HTTP status is similar.

Persist a separate statistics series per supported primary terminal reason,
using the 22 fixed identifiers defined in `RejectionReason`. Each rejected
request contributes once to one reason. Preserve independently measured
overall totals and the same UTC precision/expiry policy for every reason.
Show reason rejection rate against all matching requests separately from
reason share among matching rejected requests. Missing reason measurements
remain unavailable, including old history without the field.

Show count-series extrema on a common complete-one-minute basis and average
rates from compatible count/duration inputs. Do not add reason maxima/minima
to obtain overall extrema. These reason series are mechanism breakdowns;
Phase 4 adds bounded attack-class/category/rule measurements with independent
match populations and explicit omissions.

### MET-05: Detection breakdowns and rankings

- Show attack-class, category, and rule breakdowns with BLOCK and LOG separated.
- Initially show up to ten leading entries, with remaining entries grouped.
- Label log-derived statistics as recorded detections/matches.
- Prefer bounded source counters for configured category/rule statistics when
  instrumented; disclose recorded-event-only or approximate breakdowns.
- Preserve event phase and mechanism where needed to explain a count.
- Make underlying totals and potential overlap understandable.

### MET-06: Sources and targets

- Rank observed source IPs and target paths for the selected period.
- Show recorded counts, primary detection classes, and BLOCK/LOG breakdowns.
- Show observed unique sources only when supported by retained evidence or an
  explicitly labeled approximation.
- Do not call the number of IPs the number of attackers.
- Explain when source/target details expired while coarse totals remain.
- Bound the dimensions and retained entries. Do not create unlimited metric
  series for arbitrary client IPs, paths, or token IDs.

### MET-07: Service impact

- Show connection failures, timeouts, and load-shedding trends.
- Show HTTP status distributions and trends.
- Separate upstream statuses from responses generated by Kunato.
- Show median, p95, and p99 latency only after suitable measurements exist.
- State what the latency measures and what requests contribute to it.

Phase 2 supplies overall client-visible statuses and header-decision latency
histograms. [Phase 4](monitoring-console-phase4.md) adds upstream-only status
history, reason-specific latency, and exact observed latency extrema with
incomplete-coverage metadata. Historical missing fields remain unavailable;
histogram bin edges are not exact extrema. The prototype still demonstrates
fictional values.

### MET-08: Protection and maintenance

- Show rules-update checks, applied updates, and failures.
- Distinguish a successful check from a newly applied rule version.
- Surface compatibility and signature failures.
- Show successful/failed configuration reloads and continued use of valid
  configuration after a failed reload.
- Show certificate expiry and acquisition/renewal errors.
- Surface inspection truncation, decoding failures, and incomplete inspection.
- Show behavioral and decoy details when the relevant feature is enabled.

### MET-09: History quality and availability

- Show the most recent collection time and present collection state.
- Mark gaps, counter-generation changes, suppressed logs, and known dropped
  observations. Unknown loss must remain unknown.
- Keep existing history across restarts of the console and WAF, subject to the
  documented persistence and retention limits.
- Explain available detail and aggregation periods for the selected range.
- Display observation coverage alongside rates affected by missing samples.
- Enforce the 30-day logical statistics horizon independently of bounded
  physical cleanup. Show retention/cleanup lag and the oldest available
  aligned interval; detailed event retention is a separate policy.

### MET-10: Export and drill-down

- The prototype exports the selected fictional metrics summary as CSV.
- Preserve relevant site/filter context when opening related recorded events.
- Make any transition from a historical period to a live rolling window
  explicit; the live list is not a complete historical drill-down.
- The final scope of CSV exports and historical event drill-down remains a
  product detail to finalize before backend implementation.

### Metrics delivery priority

The initial proposed priority is summary cards, traffic/rejection trends,
rejection reasons, category/rule rankings, decoy evidence, and collection
quality. Deeper IP/path analysis and latency analysis follow when collection
and instrumentation support them. A visible prototype widget does not override
these prerequisites or imply measured data is already available.

## 3. Real-time monitor

Purpose: follow recent activity and investigate significant observations while
collection continues. Use the selected rolling window consistently across
whole-view panels; identify filters that only affect recorded events.

### LIVE-01: Time window and delivery

- Offer rolling windows of 1, 5, and 15 minutes, defaulting to 5 minutes.
- Receive live updates with SSE from the console process.
- Use ordinary HTTP APIs for history, searches, and authentication operations.
- Update at a bounded cadence and aggregate bursts rather than render every
  incoming request independently.
- The prototype's two-second local generator is simulated delivery; the real
  SSE cadence and protocol have not been implemented.

### LIVE-02: Current summary

Show request volume/rate, rejected requests/rate, LOG-detected requests,
current active connections, upstream connection errors/timeouts, and decoy
credential-use attempts. A rate may appear under its related count rather than
occupying another card. Clearly distinguish latest-sample gauges from
rolling-window counts.

### LIVE-03: Rolling trends and leading signals

- Chart recent requests and rejections over the selected window.
- Make upstream errors, load shedding, and decoy-use observations discoverable.
- Show leading detection classes, observed sources, and target paths.
- Keep credential-use evidence prominent even when other event types dominate.
- Do not equate a recorded-event ranking with complete request statistics.

### LIVE-04: Event stream and details

Show recorded detections and service events, including:

- Event time and type.
- Resolved source IP and, in details, transport peer when recorded.
- Target site/host, HTTP method, redacted path, and status when recorded.
- Category/rule or built-in mechanism/reason.
- Actual disposition, such as BLOCK, LOG, rejection, or service error.
- An identifier sufficient for supported correlation and replay/deduplication.

Differentiate rule blocks, rule matches, rate limits, bans, behavioral signals,
decoy credential presentation, passive decoy occurrences, upstream errors, and
administrative gates. Show absent fields as unrecorded. A selected row opens a
detail panel without replacing the entire monitoring view.

### LIVE-05: Filters

- Support IP/CIDR, host/site, path, method, event kind, classification, rule,
  action, and status filtering where source data supports it.
- Combine conditions and show active filters with a clear reset action.
- Provide an immediate credential-use-only filter.
- Allow ranking entries to become event filters.
- The prototype's text search supports IPv4 CIDR and searches source, path,
  rule, classification, site, and credential ID. This does not establish full
  production IPv6 or structured-query support.

### LIVE-06: Pause and inspection

- Permit display pause while collection/storage continues.
- Show the number of new events received during pause within bounded limits.
- On resume, retain the reading position when its events remain available.
- Keep selected event details stable while the live list updates.
- Explain when replay/retention bounds prevent restoring the displayed period.

### LIVE-07: Follow behavior and scroll preservation

- When Follow latest is enabled and the list is at the top, keep following new
  events.
- When an operator scrolls into older rows, automatic redraw must preserve the
  same visible event and its pixel offset. Keeping the old numeric `scrollTop`
  alone is insufficient when new rows are inserted above it.
- Preserve horizontal scroll as well as vertical position.
- Retain enough rendered rows, within the bounded event buffer, so new entries
  do not push the reading viewport out of the rendered subset.
- Compensate for fractional-pixel rounding across repeated updates.
- Disabling Follow latest preserves the current row even from the former top.
- Explicitly enabling it returns to the newest events. Returning manually to
  the top resumes following when that option remains enabled.
- Preserve position across pause/resume and normal re-rendering. A source row
  that expires or leaves bounded retention cannot be guaranteed to remain;
  final replay/gap behavior must explain such cases.

### LIVE-08: Connection state and loss

- Show connected, reconnecting, interrupted, and stale collection separately
  from observed traffic levels.
- Use heartbeats or equivalent liveness information so no events is not
  mistaken for disconnection.
- Resume from a known event identifier where bounded replay permits it.
- Clearly mark unfillable replay gaps, suppressed events, and storage/delivery
  loss. Do not silently represent them as no attacks.
- Bound per-browser queues and disconnect or resynchronize slow consumers
  without delaying WAF processing.

### LIVE-09: Arrival effects

The prototype implements these agreed visual behaviors:

| Observation | Arrival emphasis |
| --- | --- |
| Rejections and errors | Brief red glow on the relevant card and arriving row |
| LOG observations | Amber glow |
| Qualified decoy credential use | Orange flare on its card and row |
| Any newly displayed arrival | Temporary NOW label |

The implemented animation lasts about 1.65 seconds; the NOW marker and
highlight state are removed after about 1.7 seconds. They are one-shot effects,
not looping alarms. They identify new observations rather than prove malicious
intent. Service errors retain their service-event classification.

Only newly received activity triggers the effect. Initial history, filter
changes, navigation back to existing events, and resumed backlog must not replay
it. Respect reduced-motion preferences with brief static emphasis and the NOW
label. Avoid layout movement caused by the effect itself.

### LIVE-10: Event-age backgrounds

After the arrival effect fades, keep a subtle row background based on elapsed
time since the event:

| Event age | Background |
| --- | --- |
| 0 through 60 seconds | Pale red |
| More than 60 through 180 seconds | Pale orange |
| More than 180 through 300 seconds | Pale yellow |
| More than 300 seconds | Normal background |

Apply age coloring across event types, including decoys. This color encodes
recency, not severity. Keep a labeled legend above the table. Update age as
displayed time advances; freeze it while the display is paused. Hover,
selection, and arrival effects must remain distinguishable without permanently
erasing the age color.

### LIVE-11: Behavior during bursts

- Bound rendered rows, update frequency, payload sizes, and retained browser
  history.
- Group repeated observations where needed, including their recorded count and
  first/last times. Do not conflate a representative row with every affected
  request, source, or path.
- Distinguish request counters, recorded events, displayed rows, and known
  omitted observations.
- Maintain readable/interactive controls during high activity.

## 4. Shared decoy requirements

Decoy credential-use attempts are a first-release console requirement, not a
secondary optional visualization. They can indicate that issued information
was used in follow-up activity, which is useful when assessing possible
adaptive automation or targeted activity. They do not establish either.

| ID | Requirement |
| --- | --- |
| DEC-01 | Count verified credential presentations to the owned fake API regardless of whether policy is LOG or BLOCK. |
| DEC-02 | Count verified passive occurrences separately from accepted authentication-context evidence. Invalid, expired, wrong-site, and unverified candidates are not reuse evidence. |
| DEC-03 | Show decoy-caused rejected requests separately from reuse observations. Show issue/reuse/occurrence trends and first/last observed reuse times. |
| DEC-04 | Where retained evidence permits, show distinct credential IDs and separate repeated use of one credential from use of different credentials. |
| DEC-05 | Correlate issuance and reuse with hashed token ID, site/lure/template, timestamps, elapsed time, source/peer, redacted destination, context, and disposition. Support different source IPs without asserting the same person. |
| DEC-06 | Never display or store raw decoy credentials. Show an unknown issuance trail when issuance was not recorded, rather than fabricate a link. Issuance itself is not confirmed delivery. |
| DEC-07 | Show activation, incomplete inspection, logging suppression, and recognition limits alongside interpretation of zero or incomplete counts. |
| DEC-08 | Do not label these as confirmed AI attacks, confirmed targeted attacks, or successful exploitation. Do not change decoy bans, behavioral scoring, or request verdicts through the console. |

Existing decoy recognition is process-local and time/site scoped. Valid reloads
retain keys; a WAF restart invalidates previous tokens. Historical SQLite
records must not make an expired or restart-invalidated token valid again.
Logging/inspection limits can leave an incomplete trail. See the
[decoy design](decoy-design.md) for the authoritative enforcement semantics.

## 5. Measurement semantics

| ID | Required interpretation |
| --- | --- |
| COUNT-01 | Define the observed-request scope and use it consistently in totals, numerators, and denominators. Network/TLS failures before an HTTP request is measured are not automatically part of that total. |
| COUNT-02 | Count a request once in overall rejection, even if several mechanisms or subset counters describe it. Existing `blocked` is rule rejection, not the total of all WAF rejection mechanisms. |
| COUNT-03 | LOG and BLOCK may both apply to one request. LOG counts do not imply only forwarded traffic, and unblocked traffic is not proven benign traffic. |
| COUNT-04 | A request may produce multiple rule matches and request/response events. Keep match/event counts distinct from unique requests. |
| COUNT-05 | Keep source bans issued, flagged-source transitions, and requests rejected during an active ban distinct. An upstream 403 is not automatically a WAF block. |
| COUNT-06 | Existing decoy reuse counters count requests with a verified context. One request can have credential and occurrence contexts; do not add these as unique requests or count every repeated token string as another request. |
| COUNT-07 | Use counters for supported request totals and logs for recorded context. `suppressed` records and log line counts do not provide a complete per-request breakdown. |
| COUNT-08 | Counter resets require a source generation; a decreasing value alone is not sufficient restart identification. Missing observations remain missing. |
| COUNT-09 | Ratios, rates, averages, peaks, quantiles, and distinct counts require the aggregation rules in the storage design. Do not sum precomputed rates or average percentiles. |
| COUNT-10 | Basic traffic/protection totals must continue with normal-access logging absent and detail logs suppressed, dropped, or expired. Count with WAF memory measurements and persist absolute minute aggregates. |
| COUNT-11 | A sampled cumulative difference spanning a minute boundary does not prove exact minute placement. Source-minute measurements, provisional revisions, and coverage metadata must support any such precision claim. |
| COUNT-12 | Primary rejection reasons partition complete stable rejected-request counts. Do not add overlapping diagnostic subsets or multiply shared request denominators by the number of reasons. |
| COUNT-13 | Retain count/duration and supported base-minute extrema inputs for repeated aggregation. Preserve missing/partial populations; never average precomputed averages or sum reason extrema as overall extrema. |
| COUNT-14 | Use UTC interval identities and the adopted precision/30-day policy. Deduplicate source revisions, merge supported generation contributions, and select disjoint grains; replay and source restarts must not extend expiry. |

## 6. Review and acceptance checks

These checks define expected behavior for the real implementation as well as
review targets for the prototype where applicable:

1. Switch between the two views without stopping collection.
2. Change periods, custom ranges, sites, comparison, and available chart series.
3. Distinguish missing data from zero; expose available aggregation grain.
4. Filter the event stream, inspect a record, and return without accidental
   navigation or loss of reading position.
5. Trace one credential across multiple uses and different IPs using only its
   hashed ID. Keep passive occurrences separate.
6. Trigger a new observation, observe the arrival effect and NOW label, and
   verify that both expire without replay on filtering/resume.
7. Advance event ages across 60, 180, and 300 seconds; check the backgrounds and
   their legend, including reduced-motion operation.
8. Pause while events arrive; verify frozen display/age, continuing collection,
   bounded new-event count, and correct resume behavior.
9. Read partially visible older rows during repeated insertion. Preserve the
   event and vertical offset to within one CSS pixel, and preserve horizontal
   position on a narrow screen.
10. Receive enough events to exceed the original rendered subset and retain
    the reading viewport within the documented retention bounds.
11. Verify top-of-list following, disabled following, and explicit re-enable.
12. Interrupt and restore collection; mark any unrecoverable interval.
13. Verify keyboard details, focus restoration, mobile navigation, contained
    table overflow, and rendering of untrusted values as text.
14. For the future backend, additionally test SSE reconnect/replay, slow
    consumers, restart generations, durable history, buffer/storage pressure,
    retention jobs, and independence of WAF forwarding from these failures.

Local browser checks exercised the prototype's interaction, effect, age, and
scroll behaviors during development. They do not validate an SSE server,
database, source allowlist, authentication, certificates, or production load.
