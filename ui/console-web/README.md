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
`../console-prototype/`. Arrival effects, pause/resume, scroll preservation,
CSV export, comparison periods, and historical event drill-down remain future
work; see `docs/monitoring-console-remaining.md`.

## Editing

Change the files here, then rebuild Kunato so the embedded copies update:

```sh
cargo build --bin kunato
```

`node --check app.js && node --check login.js` catches script syntax errors
without any package installation. The server sets a `default-src 'self'` CSP, so
do not add inline scripts or styles, external fonts, or third-party assets.

## Limits

- The browser keeps at most 200 selected events and renders newest first.
- History reads page at 128 buckets per request, follow `next_start_ms` while
  reusing the first page's `revision`, and stop after 64 pages. A page may also
  be cut at 4 MiB; the next start continues the read. A remaining
  `next_start_ms` is reported as an incomplete range instead of being hidden.
- Rates are derived from two consecutive live samples and labeled as such; a
  source generation change resets them.
- Event-age backgrounds use the latest snapshot clock, so browser clock skew
  does not change the classification.
- Unavailable values render as `Unavailable`, never as zero.
