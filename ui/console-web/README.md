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
dark sidebar) while keeping the minimal read-only feature set.

The UI is intentionally smaller than the fictional interaction prototype in
`../console-prototype/`. Arrival effects, event-age backgrounds, pause/resume,
scroll preservation, CSV export, comparison periods, and historical event
drill-down remain future work; see `docs/monitoring-console-remaining.md`.

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
- History requests use at most 128 buckets; the server also caps a response at
  4 MiB and reports a truncation instead of silently dropping data.
- Rates are derived from two consecutive live samples and labeled as such; a
  source generation change resets them.
- Unavailable values render as `Unavailable`, never as zero.
