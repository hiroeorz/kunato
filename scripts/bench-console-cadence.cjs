// Measure the actual prototype's synchronous update/layout work with bounded fixture data.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { pathToFileURL } = require('node:url');

async function main() {
  const root = path.resolve(__dirname, '..');
  const [playwrightPath, executablePath, output, timedFlag] = process.argv.slice(2);
  if (!playwrightPath || !executablePath || !output) {
    throw new Error('Usage: node scripts/bench-console-cadence.cjs PLAYWRIGHT_MODULE CHROMIUM_EXECUTABLE OUTPUT_JSON [--timed]');
  }
  const { chromium } = require(path.resolve(playwrightPath));
  const browser = await chromium.launch({ headless: true, executablePath });
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1100 } });
    const errors = [];
    const page = await context.newPage();
    page.on('pageerror', error => errors.push(error.message));
    const source = fs.readFileSync(path.join(root, 'ui/console-prototype/app.js'), 'utf8');
    assert(source.endsWith('})();\n'), 'Expected the prototype closure boundary');
    const instrumented = source.slice(0, -6) + `
      window.consoleCadenceBench = { state, renderLive, renderLiveCards, newEvent, sample };
    })();\n`;
    await context.route('**/app.js', route => route.fulfill({ contentType: 'application/javascript', body: instrumented }));
    await page.addInitScript(() => { window.setInterval = () => 0; });
    await page.goto(pathToFileURL(path.join(root, 'ui/console-prototype/index.html')).href + '#live');
    await page.waitForFunction(() => window.consoleCadenceBench);
    const result = await page.evaluate(async () => {
      const { state, renderLive, renderLiveCards, newEvent, sample } = window.consoleCadenceBench;
      state.view = 'live';
      state.clock = Date.now();
      state.events = Array.from({ length: 500 }, (_, i) => newEvent(state.clock - i * 1000, i + 1));
      state.samples = Array.from({ length: 900 }, (_, i) => sample(state.clock - (899 - i) * 2000, i));
      state.limit = 35;
      const flushLayout = () => document.querySelector('#event-table-scroll').getBoundingClientRect().height;
      function measure(operation) {
        for (let i = 0; i < 5; i++) { operation(); flushLayout(); }
        const timings = [];
        for (let i = 0; i < 100; i++) {
          const start = performance.now();
          operation(); flushLayout();
          timings.push(performance.now() - start);
        }
        timings.sort((a, b) => a - b);
        return { median_ms: timings[50], p95_ms: timings[94], max_ms: timings[99] };
      }
      const cards = measure(renderLiveCards);
      const full = measure(renderLive);
      await new Promise(requestAnimationFrame);
      return { cards, full, retained_events: state.events.length, retained_samples: state.samples.length,
        rendered_rows: document.querySelectorAll('#event-table-body tr').length, viewport: [innerWidth, innerHeight] };
    });
    assert.equal(errors.length, 0, errors.join('\n'));
    assert.equal(result.rendered_rows, 35);
    const timed = timedFlag === '--timed' ? await page.evaluate(async () => {
      const { state, renderLive } = window.consoleCadenceBench;
      const reports = [];
      state.site = 'all';
      for (const interval of [5000, 1000, 100, 0]) {
        state.samples.forEach(sample => { sample.requests = 0; });
        const arrivals = [];
        const latencies = [];
        let generated = 0;
        let renders = 0;
        let renderMs = 0;
        const start = performance.now();
        const schedule = (at, callback) => new Promise(resolve => {
          setTimeout(() => { callback(); resolve(); }, Math.max(0, start + at - performance.now()));
        });
        const flush = () => {
          const before = performance.now();
          renderLive();
          document.querySelector('#event-table-scroll').getBoundingClientRect();
          const shown = Number(document.querySelector('#live-cards .stat-value').textContent.replaceAll(',', ''));
          if (shown !== generated) throw new Error(`Counter mismatch: ${shown} != ${generated}`);
          const end = performance.now();
          renders++;
          renderMs += end - before;
          while (arrivals.length) latencies.push(end - arrivals.shift());
        };
        const jobs = [];
        for (let at = 37; at < 10000; at += 73) jobs.push(schedule(at, () => {
          generated++;
          state.samples.at(-1).requests++;
          arrivals.push(performance.now());
          if (interval === 0) flush();
        }));
        if (interval > 0) {
          for (let at = interval; at <= 10000; at += interval) jobs.push(schedule(at, flush));
        } else jobs.push(schedule(10000, () => {}));
        await Promise.all(jobs);
        if (arrivals.length) throw new Error('Unpublished input remained at the end');
        latencies.sort((a, b) => a - b);
        reports.push({ interval_ms: interval, input_events: generated, published_events: latencies.length,
          renders, render_ms: renderMs, elapsed_ms: performance.now() - start,
          latency_mean_ms: latencies.reduce((a, b) => a + b, 0) / latencies.length,
          latency_p95_ms: latencies[Math.ceil(latencies.length * .95) - 1], latency_max_ms: latencies.at(-1) });
      }
      return reports;
    }) : null;
    const report = { method: '100 synchronous prototype updates including forced layout, after five warmups',
      limitations: 'No actual network collection, SSE, animation/presentation latency, production UI optimization, or concurrent WAF load. Timed inputs are synthetic browser-local arrivals.',
      chromium: browser.version(), desktop: result, browser_local_cadence: timed };
    fs.writeFileSync(output, JSON.stringify(report, null, 2) + '\n');
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } finally {
    await browser.close();
  }
}

main().catch(error => { process.stderr.write(String(error.stack || error) + '\n'); process.exitCode = 1; });
