# Kunato console web UI

The read-only console page served by `kunato console`. The assets are embedded
into the binary with `include_str!` (`src/console/server/assets.rs`), so there
is no build step, Node.js runtime, external font, or network request.

| File | Purpose |
| --- | --- |
| `index.html` | Console shell with the Real-time monitor, Metrics, and EDR views |
| `app.js` | SSE state, history/correlation/EDR fetches, rendering, sign-out |
| `login.html`, `login.js` | Token sign-in used when `console.auth.enabled` is set |
| `world-map.js` | Pre-projected Natural Earth 1:50m country paths and small-country markers |
| `styles.css` | Shared styles for both pages |
| `favicon.svg` | Embedded icon |

Data comes from the loopback `/console/snapshot` source through the console's
own `/api/v1/health`, `/api/v1/history`, `/api/v1/correlations`, `/api/v1/edr`,
`/api/v1/ip-info`, and `/api/v1/live` endpoints. All event values are rendered
with `textContent`; the page makes no external requests. The ASN lookup is
served entirely from the embedded or configured local DB-IP database.

## EDR view

The sidebar adds **EDR** under Observe. The page shows the console's live
in-memory EDR (`console.edr`) over the latest complete hour; it does not run the
offline `kunato edr` command.

- **Detection lamps.** Four cards: slow authentication, reverse brute force,
  success after failures, and campaign success. A finding in the latest
  evaluated window gives a red pulsing lamp; a complete evaluation with no
  finding gives a gray unlit lamp; a detector that cannot be evaluated gives an
  amber dashed card with the reason. `unknown` is deliberately distinct from
  `quiet`: the success detectors are unknown unless
  `protection.behavior.auth.success` is configured, and the page never implies
  that missing success telemetry means "no successful login."
- **Status strip.** Task state, last evaluation and data window, next
  evaluation, and the configured window/baseline. When the API marks the view
  `stale` (last window older than expected, next evaluation overdue, or a
  restored report past the window plus delay plus grace), every lamp becomes
  `unknown` while the last findings remain visible with a note.
- **Latest findings.** Severity, source IP and GeoIP country (for
  single-source findings and the campaign-success source), first/last failure
  times, occurrence and episode counts from the persisted ring, structured
  evidence, and the analyzer recommendation. The list is capped at 50; the four
  detector counts remain exact.
- **Telemetry and health.** Failure/success telemetry states, the window
  summary, task retention, and analyzer notes. Missing telemetry renders as
  unavailable, never zero.
- **Refresh.** The page fetches `/api/v1/edr` when it opens, when the tab
  becomes visible, and every 60 seconds while visible. It uses the server clock
  in `now_ms` for freshness and makes no external requests.

Country codes come from the console's GeoIP database and are rendered with the
browser's English region names. They are geolocation, not attribution; shared
NAT, VPNs, and proxies can make them misleading. Findings are LOG-only and the
page has no control that changes the WAF or the EDR configuration.

## Live edge shield topology

The Real-time monitor includes a light-theme **edge shield topology** above the
event table. It reads from the same snapshot and makes no additional requests:

- A circular blue-gradient **internet globe** marks the untrusted ingress
  side, with the INTERNET / PUBLIC NETWORK labels above the globe icon.
  Traffic leaves the globe through the **Country Gate** on the request side.
  The top track continues through **Admin Gate**, **Rate / Ban**, and **YAML
  Rules**; the lower track groups **Decoy Ward**, **Payload Guards**, and
  **Behavior**. Six defense layers sit inside a faintly red-washed, dotted
  defense fabric that marks the inspection boundary, with trusted upstream
  origins on the right. A right-pointing arrow on the top edge and a
  left-pointing arrow on the bottom edge mark the request and response
  directions; the response return does not pass through the country gate.
- **Real-time mode** is the default. Each newly received event sends a packet
  along the route from the internet globe to the layer derived from its kind,
  reason, and disposition. A colored spark bursts at that layer, the node keeps
  a short colored highlight, and the route edges pulse in the layer color.
  Forwarded LOG detections at YAML Rules or Payload Guards continue with a
  dashed path to the upstream; rejected requests show a stop marker instead.
  Multiple events in one update light different layers in their own colors.
  Initial snapshots, backlog, older events, and navigation back to the view do
  not replay the animation.
- **Log mode** focuses one selected event. Clicking or pressing Enter/Space on a
  row in Recent detections and service events switches the topology switch to
  Log with its sliding animation, dims unrelated nodes, colors the route to the
  layer that handled the event, and marks the point as a defense or detection
  point. Blocked and rejected requests end with a stop marker; logged
  observations continue to upstream with a dashed pass-through path. Service
  events keep a neutral focus card because no defense layer applies.
- **New** counts the events that arrived while a log is focused. Selecting an
  event resets it, and Return to live or the switch restores real-time mode.
  The selected row remains marked while its event is in the retained window.
- On narrow screens the map scrolls horizontally, shows a scroll hint, and
  automatically centers the focused layer. Reduced-motion preferences use
  static highlights instead of packets and sparks.

Node counters describe the retained browser event window, not lifetime totals.
The mapping is illustrative: it shows where the recorded event was handled and
does not prove malicious intent or a successful compromise.

## Source detail drawer

The Client column in Recent detections and service events is a button. Opening
it shows a read-only **Source detail** drawer from the right at roughly one
third of the viewport; the table remains visible and interactive behind it.
The drawer is non-modal, moves focus to its close button, closes with Escape or
the close button, and returns focus to the source button that opened it.
Refresh re-reads the retained event window and the ASN result. The drawer
freezes its activity snapshot until Refresh; the header shows the `as of` time.

The **Network operator (BGP)** section is populated by
`GET /api/v1/ip-info?ip=...` from the DB-IP ASN Lite database embedded in the
binary. It shows the ASN, organization, database build date, and the source
(`embedded` or `external`). The database has no registrant, allocation range,
registration date, or abuse contact; RDAP lookup is not implemented. An address
can have no record, and a record does not identify the attacker: the operator
may be an upstream, anycasting CDN, reseller, or an ISP whose customer is the
source. Private, loopback, CGNAT, documentation, and other non-global addresses
are reported as not applicable rather than looked up. The section carries the
DB-IP attribution and a warning when the database is more than 45 days old.
`console.ip_info.asn_database` can point at a newer local `.mmdb` or `.mmdb.gz`;
the console loads it at startup and falls back to the embedded copy when the
file is unreadable.

The drawer also summarizes the retained records for that address: country,
first and last recorded time, disposition counts, and the eight most recent
events. When the table shows the transport peer because no resolved client was
recorded, the drawer treats the address as the transport peer and says so.

## Rejection detail

Below the summary cards, the Real-time monitor shows a recessed **Rejection
detail** strip. Each card is one attack type or built-in rejection cause for
rejections measured since the source generation started. Rule blocks use the
same category-based attack classes as `kunato log` (SQL injection, XSS, path
traversal, CVE signatures, and so on); built-in guards use their cause, such as
rate limit, form guard, or response inspection. A request contributes once, and
the cards show its share of all rejected requests. Unrecorded causes are shown
separately rather than silently omitted.

The Recent detections table has an Attack type column populated from the same
classification. Rejected rule events also retain their category and rule name,
and the topology focus summary shows the attack type with the matched rule. The
Client column is paired with a Country column when the WAF recorded an ISO
country code for the resolved client address. The globe also shows a country
badge near its lower half for the selected log event, using the browser's
English region display names when available. In real-time mode the badge follows
the latest country-bearing event for 20 seconds and then clears; returning from
a selected log to real-time hides the selected log's badge immediately.

The sidebar footer credits the embedded DB-IP Lite data and the Natural Earth
map geometry. The links are ordinary anchors and are not fetched until the
operator clicks them.

The Metrics view keeps the terminal-mechanism table and adds an **Attack type
and cause** table from the retained per-minute class counters. Older intervals
that predate the class counters remain unavailable or unrecorded, never
zero. The live snapshot reports the cumulative map as
`counters.rejection_classes`; history intervals report per-class count
statistics as `rejection_classes`.

The page follows the prototype's visual language (light theme, warm accent,
dark sidebar) while keeping the minimal read-only feature set. Event rows carry
the prototype's event-age backgrounds (pale red through pale yellow for the
first five minutes) with a labeled legend above the table. Ages are computed
against the snapshot clock and refreshed at most every ten seconds while the
stream is idle.

The Metrics view opens with the last seven days selected. The chart uses UTC
display intervals chosen for the range: one minute for the one-hour view, one
hour for the 24-hour view, three hours for the seven-day view, and one UTC day
for the 30-day view. Bars show requests and rejections per minute, averaged
over complete minutes in each display interval, so retained 1-minute and
1-hour storage intervals are comparable; the tooltip also shows interval
totals, storage grain, and coverage. Bars are capped at a fixed maximum width
and centered in their display interval, so every range uses the same bar
thickness; the seven-day view groups hourly history into three-hour bars to
keep that width. The time axis always spans the selected range; bars are drawn
only for intervals that history has retained, so the 30-day view keeps a
30-day axis even when fewer days are available. The chart is focusable: the
left and right arrow keys move between intervals, Home and End jump to the
edges, and Escape hides the tooltip. A second chart below it uses the same UTC
intervals and per-minute rates, with each interval's requests and rejections
stacked by country; the top eight countries keep stable colours and the rest
are grouped as OTHER. A world map below it colours countries by all
WAF-rejected requests in the selected range on a logarithmic scale, separates
no data from zero, and uses point markers for small countries. When no country
detail exists, the map still renders with every country in the no-data colour.
Small islands, territories, and other countries without map geometry remain in
the top-10 table. A top-10 country table immediately below the map shows
request, rejection, and rejection-rate totals for the fetched range; it takes
two thirds of the row, and a pie chart beside it shows each country's share of
requests in the same ten colours, with the remaining countries grouped as
OTHER. Country detail comes from bounded per-minute supplementary
measurements, so older intervals without it remain explicitly unavailable.

The UI is intentionally smaller than the fictional interaction prototype in
`../console-prototype/`. Table-row arrival flares, pause/resume, scroll
preservation, CSV export, comparison periods, and historical event drill-down
remain future work; the topology's packet, spark, and focus effects are
implemented; see `docs/monitoring-console-remaining.md`.

## Editing

Change the files here, then rebuild Kunato so the embedded copies update:

```sh
cargo build --bin kunato
```

`node --check app.js && node --check login.js` catches script syntax errors
without any package installation. The topology SVG is generated at runtime and
uses only embedded styles and `textContent`; no external font, image, or request
is added. The server sets a `default-src 'self'` CSP, so
do not add inline scripts or styles, external fonts, or third-party assets.

## Limits

- The browser keeps at most 200 selected events and renders newest first.
- Topology counters and selections use that same retained window; an evicted
  event can remain focused in the focus card but has no row in the table.
- History reads page at 128 buckets per request, follow `next_start_ms` while
  reusing the first page's `revision`, and stop after 64 pages. A page may also
  be cut at 4 MiB; the next start continues the read. A remaining
  `next_start_ms` is reported as an incomplete range instead of being hidden.
- Rates are derived from two consecutive live samples and labeled as such; a
  source generation change resets them.
- Event-age backgrounds use the latest snapshot clock, so browser clock skew
  does not change the classification.
- Unavailable values render as `Unavailable`, never as zero.
- The EDR view shows the latest evaluated hourly window only. The ring keeps
  age, observed-evaluation, and episode counters across restarts; browsing older
  findings, filtering, acknowledging, and source drill-down remain future work.
- The EDR view requires `console.edr.enabled: true`; success lamps additionally
  require configured `protection.behavior.auth.success` endpoints.
