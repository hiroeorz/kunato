# Kunato console web UI

The read-only console page served by `kunato console`. The assets are embedded
into the binary with `include_str!` (`src/console/server/assets.rs`), so there
is no build step, Node.js runtime, external font, or network request.

| File | Purpose |
| --- | --- |
| `index.html` | Console shell with the Real-time monitor and Metrics views |
| `app.js` | SSE state, history/correlation fetches, rendering, sign-out |
| `login.html`, `login.js` | Token sign-in used when `console.auth.enabled` is set |
| `styles.css` | Shared styles for both pages |
| `favicon.svg` | Embedded icon |

Data comes from the loopback `/console/snapshot` source through the console's
own `/api/v1/health`, `/api/v1/history`, `/api/v1/correlations`, and
`/api/v1/live` endpoints. All event values are rendered with `textContent`; the
page makes no external requests.

## Live edge shield topology

The Real-time monitor includes a light-theme **edge shield topology** above the
event table. It reads from the same snapshot and makes no additional requests:

- A dark **internet edge** marks the untrusted ingress side with a globe,
  public-network labeling, source address, and transport notes. Six defense
  layers (Admin Gate, Rate / Ban, YAML Rules, Decoy Ward, Payload Guards, and
  Behavior) sit inside a dotted defense fabric, with trusted upstream origins on
  the right.
- **Real-time mode** is the default. Each newly received event sends a packet
  along the route from the internet edge to the layer derived from its kind,
  reason, and disposition. A colored spark bursts at that layer, the node keeps
  a short colored highlight, and the route edges pulse in the layer color.
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

The page follows the prototype's visual language (light theme, warm accent,
dark sidebar) while keeping the minimal read-only feature set. Event rows carry
the prototype's event-age backgrounds (pale red through pale yellow for the
first five minutes) with a labeled legend above the table. Ages are computed
against the snapshot clock and refreshed at most every ten seconds while the
stream is idle.

The Metrics chart uses UTC display intervals chosen for the range: one minute
for the one-hour view, one hour for the 24-hour view, three hours for the
seven-day view, and one UTC day for the 30-day view. Bars show requests and
rejections per minute, averaged over complete minutes in each display interval,
so retained 1-minute and 1-hour storage intervals are comparable; the tooltip
also shows interval totals, storage grain, and coverage. Bars are capped at a
fixed maximum width and centered in their display interval, so every range uses
the same bar thickness; the seven-day view groups hourly history into
three-hour bars to keep that width. The time axis always spans the selected
range; bars are drawn only for intervals that history has retained, so the
30-day view keeps a 30-day axis even when fewer days are available. The chart is
focusable: the left and right arrow keys move between intervals, Home and End
jump to the edges, and Escape hides the tooltip.

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
