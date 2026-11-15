# Kunato console prototype

A buildless, browser-only prototype for reviewing the Metrics and Real-time
monitoring views. All traffic, events, credentials, service states, and history
are fictional. The prototype does not contact Kunato, collect logs, implement
authentication, establish SSE connections, or modify WAF configuration.

Run from the repository root:

```sh
python3 -m http.server 8765 --bind 127.0.0.1 --directory ui/console-prototype
```

Open <http://127.0.0.1:8765>. Alternatively, open `index.html` directly; the
prototype has no build step, external dependencies, fonts, or network requests.

## Review interactions

- Switch between Metrics and Real-time monitoring using the sidebar.
- Select a site, reporting period, custom dates, and comparison mode.
- Inspect chart values and switch the traffic chart's series.
- Export the currently selected metrics as a CSV file.
- Inspect rejection reasons, detection categories, sources, and targets.
- Follow the decoy card into filtered real-time activity and open an event.
- Filter events by text, type, method, action, or status; IPv4 CIDR search is supported.
- Switch the recent activity ranking between signals, sources, and targets.
- Pause the display while simulated collection continues, then resume it.
- Watch new rejections ignite the rejection card and new event rows briefly glow.
  Rejections and errors use red, LOG observations use amber, and decoy credential
  use has an orange flare. New rows carry a temporary NOW label. Historical
  events, filter changes, and resumed backlog do not replay the arrival effects.
  Reduced-motion preferences use a brief static highlight instead of animation.
- Read persistent event-age backgrounds separately from the arrival flare:
  up to one minute is pale red, over one to three minutes is pale orange,
  over three to five minutes is pale yellow, and older events use the normal
  background. Age colors follow the displayed clock and freeze while paused.
- Change the rolling window and toggle automatic following. New events are
  followed only while the list is at the top. Reading older events preserves
  the visible rows and their offsets, including during resumed collection;
  horizontal scrolling is preserved too. Enabling Follow latest returns to the
  newest events. Reading positions are retained while their events remain in
  the selected time window and bounded demo retention.
- Use the Demo data menu to simulate a collection interruption or reset the demo.
- Review the responsive layout with the mobile navigation button.

Live activity is generated locally every two seconds and retained in a bounded
in-memory list. Reloading resets the fictional session. The drawer labels
credential presentation separately from passive token occurrence; a returned
credential does not establish AI use, malicious intent, or attacker identity.

The UI uses English to follow the repository's artifact language policy.
No backend implementation is included.
