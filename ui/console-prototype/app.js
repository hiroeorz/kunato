"use strict";

(() => {
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);
  const number = (value) => new Intl.NumberFormat("en-US").format(Math.round(value));
  const shortNumber = (value) => value >= 1000000 ? `${(value / 1000000).toFixed(1)}m` : value >= 1000 ? `${(value / 1000).toFixed(value >= 10000 ? 0 : 1)}k` : `${Math.round(value)}`;
  const paths = {
    chart: '<path d="M4 17V9m6 8V4m6 13v-6m-14 9h18"/>',
    activity: '<path d="M2 12h4l3-8 5 16 3-8h5"/>',
    shield: '<path d="m12 3 8 3v6c0 5-4 8-8 10-4-2-8-5-8-10V6l8-3Z"/><path d="m8.5 12 2.5 2.5 4.5-5"/>',
    lock: '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2"/>',
    menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
    close: '<path d="m6 6 12 12M18 6 6 18"/>',
    flask: '<path d="M9 3h6m-5 0v6l-6 10a1 1 0 0 0 1 2h14a1 1 0 0 0 1-2L14 9V3M7 15h10"/>',
    chevronDown: '<path d="m7 10 5 5 5-5"/>',
    chevronRight: '<path d="m10 7 5 5-5 5"/>',
    arrowRight: '<path d="M4 12h15m-6-6 6 6-6 6"/>',
    arrowUpRight: '<path d="M6 18 18 6M7 6h11v11"/>',
    download: '<path d="M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5"/>',
    layers: '<path d="m12 3 9 5-9 5-9-5 9-5Zm-9 9 9 5 9-5m-18 5 9 5 9-5"/>',
    calendar: '<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M7 3v4m10-4v4M3 10h18"/>',
    globe: '<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10v.1"/>',
    fingerprint: '<path d="M4 11a8 8 0 0 1 16 0m-13 2v-2a5 5 0 0 1 10 0v3m-7 4v-7a2 2 0 0 1 4 0v6m-10-2v2m3-1v3m3 1v1m4-1v1m3-4v2m3-6v3"/>',
    database: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 4 16 4 16 0V5M4 12c0 4 16 4 16 0"/>',
    server: '<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.1M7 17.5h.1m4-11h6m-6 11h6"/>',
    refresh: '<path d="M20 10a8 8 0 0 0-14-5L3 8m0-5v5h5m-4 6a8 8 0 0 0 14 5l3-3m0 5v-5h-5"/>',
    search: '<circle cx="10" cy="10" r="6"/><path d="m15 15 6 6"/>',
    pause: '<path d="M8 5v14M16 5v14"/>',
    play: '<path d="m8 4 12 8-12 8V4Z"/>',
    unplug: '<path d="m4 4 16 16M8 3v4m8-4v4M6 7h12v3a6 6 0 0 1-6 6v5"/>',
    radar: '<circle cx="12" cy="12" r="9"/><path d="M7 16a6 6 0 0 1 1-9m8 9a6 6 0 0 1-8 1m4-5 7-7"/><circle cx="12" cy="12" r="2"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 6v6l4 2"/>',
    file: '<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9l-6-6Zm0 0v6h6M8 13h8m-8 4h5"/>',
    bolt: '<path d="m13 2-9 12h7l-1 8 10-13h-7l0-7Z"/>',
    code: '<path d="m8 7-5 5 5 5m8-10 5 5-5 5m-3-14-2 18"/>',
    flag: '<path d="M5 22V3c5-3 9 3 14 0v11c-5 3-9-3-14 0"/>',
  };
  const icon = (name) => `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.activity}</svg>`;
  function hydrateIcons(root = document) {
    $$('[data-icon]', root).forEach((element) => { element.innerHTML = icon(element.dataset.icon); });
  }
  function applyStyles(root) {
    $$('[data-width]', root).forEach((element) => { element.style.width = `${Number(element.dataset.width)}%`; });
    $$('[data-height]', root).forEach((element) => { element.style.height = `${Number(element.dataset.height)}%`; });
    $$('[data-background]', root).forEach((element) => { element.style.background = element.dataset.background; });
  }

  const startedAt = Date.now();
  const periods = {
    "24h": { days: 1, factor: 1, label: "30-minute intervals" },
    "7d": { days: 7, factor: 6.8, label: "4-hour intervals" },
    "30d": { days: 30, factor: 29.3, label: "Daily intervals" },
    "90d": { days: 90, factor: 86.9, label: "2-day intervals" },
    "1y": { days: 365, factor: 354, label: "Weekly intervals" },
  };
  const state = {
    view: "metrics", period: "24h", site: "all", compare: true,
    chart: "traffic", detection: "BLOCK", ranking: "sources", timezone: "Asia/Tokyo",
    window: 5, paused: false, pausedAt: null, pausedNew: 0, follow: true,
    online: true, gapStarted: null, gaps: [], search: "", eventType: "all", method: "all", action: "all",
    limit: 35, events: [], samples: [], tick: 0, selectedId: null, focusReturn: null,
    status: 'all', liveRanking: 'signals', eventScrollTop: 0, eventScrollRemainder: 0,
    customFrom: null, customTo: null, clock: startedAt,
  };
  const palette = ["#d6a078", "#95a9be", "#b4bdcc", "#cac2d0", "#e9b681"];
  function dateString(time, options = {}) {
    return new Intl.DateTimeFormat("en-US", { timeZone: state.timezone, ...options }).format(time);
  }
  const timeLabel = (time) => dateString(time, { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
  const minuteLabel = (time) => dateString(time, { hour: "2-digit", minute: "2-digit", hour12: false });
  const fullDate = (time) => dateString(time, { month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
  const dateLabel = (time) => dateString(time, { month: "short", day: "numeric" });
  const localDay = (time) => new Date(time).toISOString().slice(0, 10);
  function toast(message) {
    $('#toast').textContent = message;
    $('#toast').hidden = false;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => { $('#toast').hidden = true; }, 3500);
  }
  function setPressed(selector, attribute, value) {
    $$(selector).forEach((button) => {
      const selected = button.getAttribute(attribute) === value;
      button.classList.toggle("selected", selected);
      button.setAttribute("aria-pressed", String(selected));
    });
  }
  function seeded(index, salt = 0) {
    const value = Math.sin(index * 127.1 + salt * 311.7) * 43758.5453;
    return value - Math.floor(value);
  }
  function siteFactor() { return state.site === "blog" ? .72 : state.site === "notes" ? .28 : 1; }
  function periodInfo() {
    if (state.period !== "custom") return periods[state.period];
    const days = Math.round((state.customTo - state.customFrom) / 86400000) + 1;
    return { days, factor: days * .97, label: days <= 2 ? "30-minute intervals" : days <= 14 ? "4-hour intervals" : days <= 60 ? "Daily intervals" : "Weekly intervals" };
  }
  function metricsData() {
    const period = periodInfo();
    const factor = period.factor * siteFactor();
    const total = Math.round(128462 * factor);
    const rejected = Math.round(4281 * factor);
    const decoys = state.period === "24h" ? (state.site === "all" ? 3 : state.site === "blog" ? 2 : 1) : Math.max(1, Math.round(3 * Math.pow(period.factor, .73) * siteFactor()));
    const unique = Math.max(1, Math.round(decoys * .62));
    const rules = Math.round(rejected * .65);
    const rate = Math.round(rejected * .22);
    const inspection = Math.round(rejected * .099);
    const admin = rejected - rules - rate - inspection - decoys;
    return { total, rejected, ratio: (rejected / total * 100).toFixed(2), logs: Math.round(736 * factor), errors: Math.round(12 * factor), timeouts: Math.round(3 * factor), decoys, unique, passive: Math.round(7 * factor), rules, rate, inspection, admin, responseBlocked: Math.round(17 * factor), factor };
  }
  function sparkline(index, orange = false) {
    const points = Array.from({ length: 13 }, (_, point) => `${point * 4},${18 - (seeded(point, index) * 11 + point * .3)}`).join(" ");
    return `<svg class="stat-spark" viewBox="0 0 48 23" aria-hidden="true"><polyline points="${points}" fill="none" stroke="${orange ? '#d9a173' : '#aab9c8'}" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
  }
  function statCard(label, value, symbol, bottom, options = {}) {
    const longValue = String(value).length > 9;
    const content = longValue ? `<span class="full-number">${escapeHtml(value)}</span><span class="compact-number" aria-hidden="true">${shortNumber(Number(String(value).replaceAll(',', '')))}</span>` : escapeHtml(value);
    return `<article class="stat-card${options.featured ? ' featured' : ''}"${options.signal ? ` data-signal="${escapeHtml(options.signal)}"` : ''}><div class="stat-label"><span>${escapeHtml(label)}</span>${icon(symbol)}</div><strong class="stat-value${longValue ? ' long-value' : ''}" title="${escapeHtml(value)}" aria-label="${escapeHtml(value)}">${content}</strong><div class="stat-bottom">${bottom}</div>${options.spark ? sparkline(options.spark, options.featured) : ''}</article>`;
  }
  function renderMetrics() {
    const data = metricsData();
    const info = periodInfo();
    const trend = (value, neutral = false) => state.compare ? `<span class="stat-trend${neutral ? ' neutral' : ''}">${value}</span><span class="comparison-copy">vs. previous</span>` : '<span>Selected period</span>';
    $('#metrics-cards').innerHTML = [
      statCard("Total requests", number(data.total), "activity", trend("↗ 12.8%", true)),
      statCard("Rejected requests", number(data.rejected), "shield", trend("↘ 8.2%")),
      statCard("Rejection rate", `${data.ratio}%`, "chart", trend("↘ 0.76 pp")),
      statCard("Log detections", number(data.logs), "flag", state.compare ? '<span class="stat-trend warning">↗ 14.2%</span><span class="comparison-copy">vs. previous</span>' : '<span>Requests with LOG matches</span>'),
      statCard("Upstream failures", number(data.errors + data.timeouts), "server", `<span>${number(data.errors)} connection · ${number(data.timeouts)} timeout</span>`),
      statCard("Decoy credential use", number(data.decoys), "fingerprint", `<span>${number(data.unique)} unique observed credentials</span>`, { featured: true }),
    ].join("");
    const until = state.period === "custom" ? state.customTo + 86399999 : startedAt;
    const since = state.period === "custom" ? state.customFrom : until - info.days * 86400000;
    $('#metrics-date-range').textContent = `${fullDate(since).replace(/, \d{2}:\d{2}:\d{2}$/, '')} — ${fullDate(until).replace(/, \d{2}:\d{2}:\d{2}$/, '')}`;
    $('#metrics-granularity').textContent = info.label;
    renderMetricsChart(since, until, data);
    $('#decoy-summary').innerHTML = `<div class="decoy-value"><strong>${number(data.decoys)}</strong><span>credential-use attempts</span></div><p class="decoy-description">Issued information appeared in follow-up requests.</p><div class="decoy-facts"><span><strong>${number(data.unique)}</strong> observed credentials</span><span><strong>${number(data.passive)}</strong> passive occurrences</span></div>`;
    $('#decoy-bars').innerHTML = Array.from({ length: 25 }, (_, index) => `<span class="${[6, 13, 19, 22].includes(index) ? 'active' : ''}" data-height="${[6, 13, 19, 22].includes(index) ? 35 + seeded(index) * 60 : 8 + seeded(index) * 18}"></span>`).join("");
    applyStyles($('#decoy-bars'));
    const reasons = [["Rule blocks", data.rules], ["Rate limits / bans", data.rate], ["Inspection limits", data.inspection], ["Admin access gate", data.admin], ["Decoy credential use", data.decoys]];
    let offset = 0;
    const gradient = reasons.map(([, value], index) => {
      const start = offset;
      offset += value / data.rejected * 100;
      return `${palette[index]} ${start}% ${offset}%`;
    }).join(",");
    $('#rejection-breakdown').innerHTML = `<div class="donut"><div class="donut-inner"><strong>${number(data.rejected)}</strong><span>rejected requests</span></div></div><div class="breakdown-list">${reasons.map(([name, value], index) => `<div class="breakdown-row"><i data-background="${palette[index]}"></i><span>${name}</span><strong>${number(value)}</strong><small>${(value / data.rejected * 100).toFixed(1)}%</small></div>`).join("")}</div>`;
    $('.donut').style.background = `conic-gradient(${gradient})`;
    applyStyles($('#rejection-breakdown'));
    $('#response-block-note').textContent = `${number(data.responseBlocked)} upstream responses were also blocked, tracked separately from request rejections.`;
    renderDetection(data);
    renderRanking(data);
    $('#service-health').innerHTML = `<div class="health-stats"><div><span>Median response</span><strong>18<small>ms</small></strong></div><div><span>p95 response</span><strong>94<small>ms</small></strong></div><div><span>p99 response</span><strong>186<small>ms</small></strong></div></div><div class="health-status-heading"><span>Upstream HTTP responses</span><span>97.8% successful</span></div><div class="status-code-bar"><span data-width="84" data-background="#99b6a5"></span><span data-width="13.8" data-background="#b3c0d0"></span><span data-width="1.8" data-background="#d9b78d"></span><span data-width=".4" data-background="#cf9290"></span></div><div class="status-code-legend"><span><i data-background="#99b6a5"></i>2xx · 84.0%</span><span><i data-background="#b3c0d0"></i>3xx · 13.8%</span><span><i data-background="#d9b78d"></i>4xx · 1.8%</span><span><i data-background="#cf9290"></i>5xx · 0.4%</span></div>`;
    applyStyles($('#service-health'));
    const expiration = dateLabel(startedAt + 38 * 86400000);
    $('#operations-grid').innerHTML = [
      ["refresh", "Managed rules", "Up to date", `Last checked ${minuteLabel(startedAt - 38 * 60000)}`, "Signature verified"],
      ["file", "Configuration", "Last valid reload retained", "No reload failures in this period", "Configuration valid"],
      ["lock", "TLS certificate", "38 days remaining", `Expires ${expiration} · automatic renewal`, "Certificate valid"],
    ].map(([symbol, title, value, description, status]) => `<div class="operation"><span class="operation-symbol">${icon(symbol)}</span><div><h3>${title}</h3><strong>${value}</strong><p>${description}</p><span class="operation-status"><span class="status-dot"></span>${status}</span></div></div>`).join("");
  }
  function renderDetection(data = metricsData()) {
    const isBlock = state.detection === "BLOCK";
    const values = isBlock ? [988, 836, 487, 281, 191] : [263, 186, 142, 83, 62];
    const labels = ["SQL injection", "Path traversal", "Scanner activity", "Cross-site scripting", "Other detections"];
    const glyphs = ["⌘", "↳", "⌕", "⌁", "···"];
    $('#detection-breakdown').innerHTML = values.map((value, index) => `<div class="detection-row"><span class="detection-label"><span class="category-icon">${glyphs[index]}</span>${labels[index]}</span><div class="bar-track"><div class="bar-fill" data-width="${value / Math.max(...values) * 100}"></div></div><strong>${number(value * data.factor)}</strong></div>`).join("");
    applyStyles($('#detection-breakdown'));
  }
  function renderRanking(data = metricsData()) {
    const list = state.ranking === "paths" ? [["/.env", 892, "Exposure"], ["/wp-login.php", 647, "Auth abuse"], ["/api/search", 423, "SQL injection"], ["/.git/config", 306, "Exposure"]]
      : state.ranking === "rules" ? [["union-select", 677, "SQL injection"], ["dot-dot-slash", 529, "Traversal"], ["sensitive-files", 438, "Exposure"], ["script-tag", 281, "XSS"]]
        : [["203.0.113.42", 847, "SQL injection"], ["198.51.100.17", 623, "Traversal"], ["192.0.2.86", 418, "Scanner"], ["203.0.113.91", 291, "Auth abuse"]];
    const label = state.ranking === "paths" ? "Target path" : state.ranking === "rules" ? "Rule" : "Observed source";
    $('#source-ranking').innerHTML = `<table class="ranking-table"><thead><tr><th scope="col">${label}</th><th scope="col">Recorded matches</th><th scope="col">Primary signal</th></tr></thead><tbody>${list.map(([name, count, category]) => `<tr><td class="mono"><button class="ranking-link" data-search="${escapeHtml(name)}">${escapeHtml(name)}</button></td><td>${number(count * data.factor)}</td><td><span class="badge badge-muted">${category}</span></td></tr>`).join("")}</tbody></table>`;
  }

  function lineChart(container, series, options) {
    const width = 1000;
    const height = options.compact ? 180 : 260;
    const left = 48, right = 14, top = 14, bottom = height - 31;
    const graphWidth = width - left - right;
    const allValues = series.flatMap((item) => item.values.filter((value) => value !== null));
    const max = Math.max(4, Math.ceil(Math.max(...allValues) / 4) * 4);
    const length = series[0].values.length;
    const x = (index) => left + index / Math.max(1, length - 1) * graphWidth;
    const y = (value) => bottom - value / max * (bottom - top);
    const segments = (values) => {
      const result = [];
      let current = [];
      values.forEach((value, index) => {
        if (value === null) { if (current.length) result.push(current); current = []; }
        else current.push([x(index), y(value)]);
      });
      if (current.length) result.push(current);
      return result;
    };
    const chartId = container.id;
    const grids = Array.from({ length: 5 }, (_, index) => {
      const value = max * index / 4;
      return `<line x1="${left}" y1="${y(value)}" x2="${width - right}" y2="${y(value)}" stroke="#edf0f4" stroke-dasharray="3 4"/><text class="chart-axis" x="${left - 13}" y="${y(value) + 3}" text-anchor="end">${options.percent ? `${value}%` : shortNumber(value)}</text>`;
    }).join("");
    const missing = options.gaps || [];
    const gapRects = missing.map(([a, b]) => `<rect x="${x(a)}" y="${top}" width="${Math.max(8, x(b) - x(a))}" height="${bottom - top}" fill="url(#${chartId}-gap)"/><line x1="${x(a)}" y1="${top}" x2="${x(a)}" y2="${bottom}" stroke="#dce2e9" stroke-dasharray="2 3"/>`).join("");
    const rendered = series.map((item, seriesIndex) => segments(item.values).map((points) => {
      const path = points.map(([px, py], index) => `${index ? 'L' : 'M'}${px.toFixed(2)},${py.toFixed(2)}`).join(" ");
      const area = seriesIndex === 0 ? `<path d="${path} L${points.at(-1)[0]},${bottom} L${points[0][0]},${bottom} Z" fill="url(#${chartId}-area)"/>` : '';
      return `${area}<path d="${path}" fill="none" stroke="${item.color}" stroke-width="${item.dashed ? 1.3 : 2}" ${item.dashed ? 'stroke-dasharray="5 5"' : ''} stroke-linecap="round" stroke-linejoin="round"/>`;
    }).join("")).join("");
    const labels = Array.from({ length: 7 }, (_, index) => {
      const point = Math.round(index / 6 * (length - 1));
      return `<text class="chart-axis" x="${x(point)}" y="${height - 6}" text-anchor="${index === 0 ? 'start' : index === 6 ? 'end' : 'middle'}">${escapeHtml(options.labels[point])}</text>`;
    }).join("");
    container.innerHTML = `<svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" role="img" aria-label="${escapeHtml(options.description)}"><defs><linearGradient id="${chartId}-area" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="${series[0].color}" stop-opacity=".13"/><stop offset="100%" stop-color="${series[0].color}" stop-opacity=".01"/></linearGradient><pattern id="${chartId}-gap" patternUnits="userSpaceOnUse" width="5" height="5" patternTransform="rotate(35)"><rect width="5" height="5" fill="#f6f7f9"/><line x1="0" y1="0" x2="0" y2="5" stroke="#e4e8ee" stroke-width="1"/></pattern></defs>${grids}${gapRects}${rendered}${labels}<g class="chart-crosshair" visibility="hidden"><line y1="${top}" y2="${bottom}" stroke="#bbc5d1" stroke-dasharray="3 3"/><circle r="3.5" fill="${series[0].color}" stroke="white" stroke-width="2"/></g></svg><div class="chart-tooltip" hidden></div>`;
    const svg = $('svg', container), tooltip = $('.chart-tooltip', container), crosshair = $('.chart-crosshair', container);
    svg.addEventListener("pointermove", (event) => {
      const box = svg.getBoundingClientRect();
      const position = (event.clientX - box.left) / box.width * width;
      const index = Math.max(0, Math.min(length - 1, Math.round((position - left) / graphWidth * (length - 1))));
      crosshair.setAttribute("visibility", "visible");
      $('line', crosshair).setAttribute("x1", x(index));
      $('line', crosshair).setAttribute("x2", x(index));
      const circle = $('circle', crosshair);
      circle.setAttribute("cx", x(index));
      circle.setAttribute("cy", y(series[0].values[index] || 0));
      circle.setAttribute("visibility", series[0].values[index] === null ? "hidden" : "visible");
      const inGap = series[0].values[index] === null;
      tooltip.innerHTML = `<strong>${escapeHtml(options.tooltips?.[index] || options.labels[index])}</strong>${inGap ? '<div>Collection unavailable</div>' : series.map((item) => `<div><span>${escapeHtml(item.name)}</span><b>${item.values[index] === null ? 'Unknown' : options.percent ? `${item.values[index].toFixed(2)}%` : number(item.values[index])}${options.unit ? ` ${options.unit}` : ''}</b></div>`).join('')}`;
      tooltip.hidden = false;
      tooltip.style.left = `${Math.max(4, Math.min(box.width - 180, event.clientX - box.left + 12))}px`;
      tooltip.style.top = options.compact ? '12px' : '20px';
    });
    svg.addEventListener("pointerleave", () => { crosshair.setAttribute("visibility", "hidden"); tooltip.hidden = true; });
  }
  function renderMetricsChart(since, until, data) {
    const values = Array.from({ length: 49 }, (_, index) => {
      const wave = 1.15 + .36 * Math.sin(index * .18 - 2) + .14 * Math.sin(index * .64) + seeded(index, 4) * .24;
      return Math.round((index > 21 && index < 25 ? wave * 1.4 : wave) * 2100 * data.factor);
    });
    const previous = values.map((value, index) => value * (.79 + seeded(index, 11) * .16));
    const rejected = values.map((value, index) => Math.round(value * (.016 + seeded(index, 3) * .033)));
    const connections = values.map((value, index) => Math.round(20 + value / Math.max(1, data.factor) * .01 + seeded(index, 8) * 15));
    const labels = values.map((_, index) => {
      const time = since + index / 48 * (until - since);
      return periodInfo().days <= 2 ? minuteLabel(time) : dateLabel(time);
    });
    const tooltips = values.map((_, index) => fullDate(since + index / 48 * (until - since)));
    const chosen = state.chart === "rejections" ? rejected : state.chart === "connections" ? connections : values;
    const primaryName = state.chart === "rejections" ? "Rejected requests" : state.chart === "connections" ? "Active connections · average" : "Requests";
    const color = state.chart === "rejections" ? "#d49a70" : "#829ab3";
    const series = [{ name: primaryName, values: chosen.map((value, index) => index === 36 ? null : value), color }];
    if (state.chart === "traffic") series.push({ name: "Rejected", values: rejected.map((value, index) => index === 36 ? null : value), color: "#dc9b6c" });
    if (state.compare) series.push({ name: "Previous period", values: state.chart === "traffic" ? previous : chosen.map((value, index) => value * (.9 + seeded(index, 18) * .3)), color: "#c0c7d0", dashed: true });
    $('#metrics-chart-legend').innerHTML = `<span><i class="legend-dot" data-background="${color}"></i>${primaryName}</span>${state.chart === 'traffic' ? '<span><i class="legend-dot orange-dot"></i>Rejected</span>' : ''}${state.compare ? '<span><i class="legend-dash"></i>Previous period</span>' : ''}`;
    applyStyles($('#metrics-chart-legend'));
    lineChart($('#metrics-chart'), series, { labels, tooltips, description: `${primaryName} over the selected reporting period, including a marked collection gap.`, gaps: [[35.7, 36.3]] });
    $('#traffic-peak').textContent = `Peak interval ${number(Math.max(...chosen))}`;
    $('#traffic-subtitle').textContent = state.chart === "connections" ? "Average active connections per interval." : "A little context for every request.";
  }

  const eventKinds = {
    block: { label: "Rule block", icon: "shield", action: "BLOCK", status: 403 },
    log: { label: "Rule match", icon: "flag", action: "LOG", status: 200 },
    decoy: { label: "Decoy credential use", icon: "fingerprint", action: "BLOCK", status: 403 },
    occurrence: { label: "Decoy occurrence", icon: "fingerprint", action: "LOG", status: 200 },
    "rate-limit": { label: "Rate limit", icon: "clock", action: "REJECT", status: 429 },
    ban: { label: "Ban active", icon: "shield", action: "REJECT", status: 429 },
    behavior: { label: "Behavioral signal", icon: "radar", action: "LOG", status: null },
    upstream: { label: "Upstream error", icon: "server", action: "ERROR", status: 502 },
    admin: { label: "Admin gate", icon: "lock", action: "REJECT", status: 404 },
  };
  const templates = [
    ["block", "GET", "/api/search", "sql-injection.union-select", "SQL injection", "203.0.113.42"],
    ["block", "GET", "/assets/../../etc/passwd", "path-traversal.dot-dot-slash", "Path traversal", "198.51.100.17"],
    ["log", "GET", "/.env", "exposure.sensitive-files", "Exposure", "192.0.2.86"],
    ["rate-limit", "POST", "/wp-login.php", "protection.rate_limit", "Rate limit", "203.0.113.91"],
    ["block", "POST", "/contact", "xss.script-tag", "Cross-site scripting", "198.51.100.23"],
    ["behavior", "POST", "/api/session", "behavior.authentication", "Authentication abuse", "203.0.113.91"],
    ["block", "GET", "/api/search", "sql-injection.union-select", "SQL injection", "203.0.113.42"],
    ["ban", "GET", "/wp-login.php", "protection.ban", "Ban", "198.51.100.17"],
    ["log", "GET", "/.git/config", "scanners-and-bots.sensitive-files", "Scanner activity", "192.0.2.86"],
    ["block", "PUT", "/uploads/avatar.png", "upload.content-mismatch", "Upload inspection", "198.51.100.23"],
    ["admin", "GET", "/admin", "admin_access.closed", "Admin access gate", "192.0.2.18"],
    ["upstream", "GET", "/notes", "upstream.connect_error", "Upstream error", "192.0.2.110"],
    ["log", "HEAD", "/health", "scanner.unusual-user-agent", "Scanner activity", "203.0.113.77"],
  ];
  let eventSequence = 1000;
  let decoyIssueClock = startedAt;
  function newEvent(time, index) {
    const [kind, method, path, rule, category, source] = templates[index % templates.length];
    return { id: `evt_${++eventSequence}`, time, kind, method, path, rule, category, source, site: index % 4 === 0 ? "notes" : "blog", peer: "10.0.0.2", ...eventKinds[kind] };
  }
  function decoyEvent(time, variant = 0, occurrence = false) {
    const kind = occurrence ? "occurrence" : "decoy";
    const repeated = variant % 3 !== 2;
    const site = repeated ? "blog" : "notes";
    const tokenId = repeated ? "dc_74b8e2a9f031c52d" : "dc_c90f7d13a8e042be";
    const issuedAt = decoyIssueClock - (repeated ? 126000 : 279000);
    const age = Math.max(0, Math.floor((time - issuedAt) / 1000));
    const source = repeated ? (variant % 3 === 0 ? "203.0.113.64" : "198.51.100.89") : "192.0.2.44";
    return {
      id: `evt_${++eventSequence}`, time, kind, method: "GET", path: occurrence ? "/preview/shared-link" : "/_decoy/api/v1/storage/list",
      rule: occurrence ? "decoy.occurrence" : "decoy.credential", category: "Decoy credential reuse", source, site,
      peer: "10.0.0.2", ...eventKinds[kind], tokenId, age, issuedAt,
      issuedSource: repeated ? "203.0.113.64" : "192.0.2.44", lure: repeated ? "/.env" : "/.git/config",
      template: repeated ? "dotenv" : "git-config", context: occurrence ? "Passive token occurrence" : "Authorization: Bearer [redacted]",
    };
  }
  function sample(time, index) {
    const requests = Math.round(35 + Math.sin(index * .16) * 12 + seeded(index, 5) * 24 + (index % 47 < 4 ? 20 : 0));
    const rejected = Math.round(requests * (.025 + seeded(index, 8) * .07));
    return { time, requests, rejected, logs: Math.round(seeded(index, 17) * 2), connections: Math.round(38 + seeded(index, 12) * 21), errors: index % 151 === 0 ? 1 : 0 };
  }
  function seedData() {
    const now = Date.now();
    decoyIssueClock = now;
    state.events = Array.from({ length: 128 }, (_, index) => newEvent(now - index * 7000 - 1500, index));
    state.events.push(decoyEvent(now - 112000, 0), decoyEvent(now - 42000, 1), decoyEvent(now - 248000, 2), decoyEvent(now - 18000, 0, true));
    state.events.sort((a, b) => b.time - a.time);
    state.samples = Array.from({ length: 451 }, (_, index) => sample(now - (450 - index) * 2000, index));
    state.clock = now;
  }
  function displayTime() { return state.paused ? state.pausedAt : state.clock; }
  function eventRecency(time) {
    const age = Math.max(0, displayTime() - time);
    if (age <= 60000) return '1m';
    if (age <= 180000) return '3m';
    if (age <= 300000) return '5m';
    return 'older';
  }
  function siteMatches(item) { return state.site === "all" || item.site === state.site; }
  function windowEvents() {
    const end = displayTime();
    return state.events.filter((event) => event.time >= end - state.window * 60000 && event.time <= end && siteMatches(event));
  }
  function matchesIpv4Cidr(ip, cidr) {
    const match = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(cidr);
    if (!match || Number(match[2]) > 32) return false;
    const toNumber = (address) => {
      const parts = address.split(".").map(Number);
      if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
      return parts.reduce((result, part) => result * 256 + part, 0) >>> 0;
    };
    const source = toNumber(ip), network = toNumber(match[1]);
    if (source === null || network === null) return false;
    const mask = Number(match[2]) === 0 ? 0 : (0xffffffff << (32 - Number(match[2]))) >>> 0;
    return (source & mask) === (network & mask);
  }
  function filteredEvents() {
    const search = state.search.trim().toLowerCase();
    return windowEvents().filter((event) => {
      if (state.eventType !== "all" && event.kind !== state.eventType) return false;
      if (state.method !== "all" && event.method !== state.method) return false;
      if (state.action !== "all" && event.action !== state.action) return false;
      if (state.status !== "all" && String(event.status) !== state.status) return false;
      if (!search) return true;
      if (/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(search)) return matchesIpv4Cidr(event.source, search);
      return [event.source, event.path, event.rule, event.category, event.tokenId || '', `${event.site}.example.test`].some((value) => value.toLowerCase().includes(search));
    });
  }
  function renderLiveCards() {
    const end = displayTime();
    const samples = state.samples.filter((item) => item.time >= end - state.window * 60000 && item.time <= end);
    const sum = (key) => Math.round(samples.reduce((total, item) => total + item[key], 0) * siteFactor());
    const total = sum("requests"), rejected = sum("rejected"), errors = sum("errors"), logs = sum("logs");
    const decoys = windowEvents().filter((event) => event.kind === "decoy");
    const rps = total / Math.max(1, samples.length * 2);
    $('#live-cards').innerHTML = [
      statCard("Total requests", number(total), "activity", `<span>${rps.toFixed(1)} req/s average</span>`),
      statCard("Rejected requests", number(rejected), "shield", `<span>${(total ? rejected / total * 100 : 0).toFixed(2)}% of requests</span>`, { signal: 'rejected' }),
      statCard("Log detections", number(logs), "flag", '<span>Requests with LOG matches</span>', { signal: 'logged' }),
      statCard("Active connections", number((samples.at(-1)?.connections || 0) * siteFactor()), "layers", '<span>Most recent sample</span>'),
      statCard("Upstream failures", number(errors), "server", '<span>Connection errors</span>', { signal: 'upstream' }),
      statCard("Decoy credential use", number(decoys.length), "fingerprint", `<span>${new Set(decoys.map((event) => event.tokenId)).size} observed credentials</span>`, { featured: true, signal: 'decoy' }),
    ].join("");
    $('#decoy-filter-count').textContent = decoys.length;
    $('#nav-signal-count').textContent = decoys.length;
    const groups = new Map();
    windowEvents().filter((event) => !['decoy', 'occurrence', 'upstream', 'admin'].includes(event.kind)).forEach((event) => {
      const key = state.liveRanking === 'sources' ? event.source : state.liveRanking === 'paths' ? event.path : event.category;
      groups.set(key, (groups.get(key) || 0) + 1);
    });
    const leaders = [...groups].sort((a, b) => b[1] - a[1]).slice(0, 2);
    $('#active-signals').innerHTML = `<div class="active-signal decoy"><span class="active-signal-icon">${icon('fingerprint')}</span><div><p>Decoy credential use</p><small>${decoys.length ? 'Follow-up use observed' : 'No recorded use in this window'}</small></div><strong>${decoys.length}</strong></div>${leaders.map(([category, count]) => `<div class="active-signal"><span class="active-signal-icon">${icon('radar')}</span><div><p>${escapeHtml(category)}</p><small>Recorded detections</small></div><strong>${count}</strong></div>`).join('')}`;
  }
  function renderLiveChart() {
    const end = displayTime(), start = end - state.window * 60000;
    const buckets = 45;
    const times = Array.from({ length: buckets }, (_, index) => start + index / (buckets - 1) * (end - start));
    const values = [], rejections = [];
    times.forEach((time, index) => {
      const interval = (end - start) / buckets;
      const items = state.samples.filter((item) => Math.abs(item.time - time) < Math.max(1100, interval / 2));
      const gap = !items.length || state.gaps.some(([a, b]) => time >= a && time <= b) || (!state.online && time >= state.gapStarted);
      values.push(gap ? null : items.reduce((sum, item) => sum + item.requests, 0) / items.length / 2 * siteFactor());
      rejections.push(gap ? null : items.reduce((sum, item) => sum + item.rejected, 0) / items.length / 2 * siteFactor());
    });
    const gaps = [];
    values.forEach((value, index) => { if (value === null) gaps.push([Math.max(0, index - .4), Math.min(buckets - 1, index + .4)]); });
    lineChart($('#live-chart'), [{ name: "Requests", color: "#829ab3", values }, { name: "Rejected", color: "#dc9b6c", values: rejections }], { labels: times.map(minuteLabel), tooltips: times.map(fullDate), compact: true, unit: "req/s", gaps, description: `Simulated requests and rejections per second over the last ${state.window} minutes.` });
    $('#live-chart-subtitle').textContent = `Requests per second in the last ${state.window} ${state.window === 1 ? 'minute' : 'minutes'}.`;
  }
  function renderEventTable() {
    const events = filteredEvents();
    const scroll = $('#event-table-scroll');
    const oldScroll = scroll.scrollTop;
    const oldLeft = scroll.scrollLeft;
    if (oldScroll !== state.eventScrollTop) state.eventScrollRemainder = 0;
    const followLatest = state.follow && !state.paused && oldScroll <= 2;
    const viewport = scroll.getBoundingClientRect();
    const contentTop = viewport.top + $('.event-table thead').getBoundingClientRect().height;
    const anchors = followLatest ? [] : $$('#event-table-body tr').filter((row) => {
      const bounds = row.getBoundingClientRect();
      return bounds.bottom > contentTop && bounds.top < viewport.bottom;
    }).map((row) => ({ id: row.dataset.event, offset: row.getBoundingClientRect().top - viewport.top }));
    const eventIndexes = new Map(events.map((event, index) => [event.id, index]));
    const retainedAnchors = anchors.filter((anchor) => eventIndexes.has(anchor.id));
    if (retainedAnchors.length) {
      const lastVisibleIndex = eventIndexes.get(retainedAnchors.at(-1).id);
      state.limit = Math.min(500, Math.max(state.limit, lastVisibleIndex + 1));
    }
    const visible = events.slice(0, state.limit);
    $('#event-count').textContent = events.length;
    $('#event-count-caption').textContent = `${events.length} matching recorded events`;
    $('#event-table-body').innerHTML = visible.map((event) => `<tr tabindex="0" role="button" aria-label="Inspect ${escapeHtml(event.label)} from ${escapeHtml(event.source)} at ${timeLabel(event.time)}" data-event="${event.id}" data-recency="${eventRecency(event.time)}" class="${event.kind === 'decoy' ? 'decoy-row ' : ''}${state.selectedId === event.id ? 'selected' : ''}"><td class="mono">${timeLabel(event.time)}</td><td><span class="event-type-label ${event.kind}">${icon(eventKinds[event.kind].icon)}${escapeHtml(event.label)}</span></td><td class="mono">${escapeHtml(event.source)}</td><td><span class="method-tag">${event.method}</span><span class="request-path mono" title="${escapeHtml(event.path)}">${escapeHtml(event.path)}</span></td><td><span class="decision ${event.action}">${event.action}${event.status ? `<span class="status-number">${event.status}</span>` : ''}</span></td><td class="rule-cell" title="${escapeHtml(event.rule)}">${escapeHtml(event.rule)}</td><td class="row-arrow">${icon('chevronRight')}</td></tr>`).join("");
    $('#event-empty').hidden = events.length > 0;
    $('#event-footer-summary').textContent = `Showing ${visible.length} of ${events.length} recorded events · newest first`;
    $('#show-more').hidden = events.length <= state.limit;
    const filtered = Boolean(state.search || state.eventType !== "all" || state.method !== "all" || state.action !== "all" || state.status !== "all");
    $('#clear-filters').hidden = !filtered;
    $('#decoy-filter').classList.toggle("active", state.eventType === "decoy");
    $('#decoy-filter').setAttribute("aria-pressed", String(state.eventType === "decoy"));
    scroll.scrollTop = followLatest ? 0 : oldScroll;
    const anchor = retainedAnchors[0];
    if (anchor) {
      const row = $(`#event-table-body [data-event="${anchor.id}"]`);
      // Carry fractional scroll rounding so repeated insertions do not drift.
      const target = scroll.scrollTop + row.getBoundingClientRect().top - scroll.getBoundingClientRect().top - anchor.offset + state.eventScrollRemainder;
      const boundedTarget = Math.max(0, Math.min(target, scroll.scrollHeight - scroll.clientHeight));
      scroll.scrollTop = boundedTarget;
      state.eventScrollRemainder = boundedTarget - scroll.scrollTop;
    } else state.eventScrollRemainder = 0;
    state.eventScrollTop = scroll.scrollTop;
    scroll.scrollLeft = oldLeft;
  }
  function finishActivityFlash(element) {
    element.classList.remove('activity-flash', 'event-arrived');
    delete element.dataset.activityTone;
    $('.arrival-label', element)?.remove();
  }
  function flashActivity(element, tone, isRow = false) {
    if (!element) return;
    element.dataset.activityTone = tone;
    element.classList.add(isRow ? 'event-arrived' : 'activity-flash');
    if (isRow) {
      const label = document.createElement('span');
      label.className = 'arrival-label';
      label.textContent = 'NOW';
      label.setAttribute('aria-label', 'New event just received');
      $('td', element).append(label);
    }
    setTimeout(() => finishActivityFlash(element), 1700);
  }
  function highlightLiveActivity({ event, sample: latest }) {
    if (state.view !== 'live' || state.paused || !state.online || document.hidden) return;
    if (latest.rejected > 0) flashActivity($('#live-cards [data-signal="rejected"]'), 'danger');
    if (latest.errors > 0) flashActivity($('#live-cards [data-signal="upstream"]'), 'danger');
    if (!siteMatches(event)) return;
    const tone = event.kind === 'decoy' ? 'decoy' : event.action === 'LOG' ? 'notice' : 'danger';
    flashActivity($(`#event-table-body [data-event="${event.id}"]`), tone, true);
    if (event.action === 'LOG') flashActivity($('#live-cards [data-signal="logged"]'), 'notice');
    if (event.kind === 'decoy') flashActivity($('#live-cards [data-signal="decoy"]'), 'decoy');
    if (event.kind === 'upstream' && !latest.errors) flashActivity($('#live-cards [data-signal="upstream"]'), 'danger');
  }
  function renderLive(activity = null) {
    renderLiveCards();
    renderLiveChart();
    renderEventTable();
    if (activity) highlightLiveActivity(activity);
  }
  function updatePauseButton() {
    const button = $('#pause-button');
    button.classList.toggle("paused", state.paused);
    button.innerHTML = state.paused ? `${icon('play')}<span>Resume${state.pausedNew ? ` · ${state.pausedNew} new` : ''}</span>` : `${icon('pause')}<span>Pause display</span>`;
    $('#live-update-label').textContent = state.paused ? "Display paused · simulated collection continues" : state.online ? `Demo updates every 2s · Latest ${timeLabel(state.samples.at(-1)?.time || state.clock)}` : "Demo collection interrupted";
  }
  function updateFeedStatus() {
    const status = $('#collection-state');
    status.classList.toggle("offline", !state.online);
    status.innerHTML = `<span class="status-dot"></span><span>${state.online ? 'Demo feed running' : 'Demo feed interrupted'}</span>`;
    $('#interrupt-demo').innerHTML = `${icon(state.online ? 'unplug' : 'refresh')}<span>${state.online ? 'Simulate collection loss' : 'Restore demo collection'}</span>`;
    const notice = $('#feed-notice');
    notice.hidden = state.online && !state.gaps.length;
    notice.classList.toggle("recovered", state.online);
    notice.innerHTML = `${icon(state.online ? 'info' : 'unplug')}<span>${state.online ? 'Collection restored. The interrupted interval is marked as missing, not zero.' : 'Simulated collection loss. The most recent samples remain visible; missing intervals are not zero traffic.'}</span>`;
    updatePauseButton();
  }

  function setView(view) {
    state.view = view === "live" ? "live" : "metrics";
    $('#metrics-view').hidden = state.view !== "metrics";
    $('#live-view').hidden = state.view !== "live";
    $('#export-button').hidden = state.view !== "metrics";
    $('#pause-button').hidden = state.view !== "live";
    const title = state.view === "metrics" ? "Metrics" : "Real-time monitor";
    document.title = `${title} · Kunato`;
    $('#page-title').textContent = title;
    $('#breadcrumb-page').textContent = title;
    $('#page-eyebrow').textContent = state.view === "metrics" ? "THE BIGGER PICTURE" : "YOUR EDGE, RIGHT NOW";
    $('#page-description').textContent = state.view === "metrics" ? "Understand your traffic. See what your firewall is protecting." : "Follow the signals. See the story behind each request.";
    $$('[data-nav]').forEach((link) => {
      const active = link.dataset.nav === state.view;
      link.classList.toggle("active", active);
      if (active) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current");
    });
    closeNav();
    if (state.view === "metrics") renderMetrics(); else renderLive();
    updatePauseButton();
  }
  function syncFilters() {
    $('#event-search').value = state.search;
    $('#event-type').value = state.eventType;
    $('#event-method').value = state.method;
    $('#event-action').value = state.action;
    $('#event-status').value = state.status;
  }
  function clearFilters() {
    state.search = ""; state.eventType = "all"; state.method = "all"; state.action = "all"; state.status = "all"; state.limit = 35;
    syncFilters();
    renderLive();
  }
  function inspectDecoys() {
    state.search = ""; state.eventType = "decoy"; state.method = "all"; state.action = "all"; state.status = "all"; state.window = 5;
    setPressed('[data-window]', 'data-window', '5');
    syncFilters();
    if (location.hash !== '#live') location.hash = 'live';
    else setView('live');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
  function openEvent(id) {
    const event = state.events.find((item) => item.id === id);
    if (!event) return;
    if ($('#event-drawer').hidden) state.focusReturn = document.activeElement;
    state.selectedId = id;
    const rows = [
      ["Occurred at", `${fullDate(event.time)} ${state.timezone === 'Asia/Tokyo' ? 'JST' : 'UTC'}`],
      ["Observed source", event.source], ["Transport peer", event.peer], ["Site", `${event.site}.example.test`],
      ["Method", event.method], ["Path", event.path], ["HTTP status", event.status || "Not recorded"],
      ["Rule / signal", event.rule], ["Event ID", event.id],
    ];
    const isDecoy = Boolean(event.tokenId);
    const related = isDecoy ? state.events.filter((item) => item.tokenId === event.tokenId && item.id !== event.id).slice(0, 5) : state.events.filter((item) => item.source === event.source && item.id !== event.id).slice(0, 4);
    $('#drawer-content').innerHTML = `<h2 id="drawer-title" class="drawer-title">${escapeHtml(event.label)}</h2><p class="drawer-subtitle">${escapeHtml(event.category)} · Fictional event</p><div class="drawer-badges"><span class="decision ${event.action}">${event.action}${event.status ? `<span class="status-number">${event.status}</span>` : ''}</span><span class="badge badge-muted">${event.method}</span>${isDecoy ? `<span class="badge badge-orange">${event.kind === 'decoy' ? 'Credential presentation' : 'Passive occurrence'}</span>` : ''}</div><dl class="detail-list">${rows.map(([label, value]) => `<div class="detail-row"><dt>${label}</dt><dd class="${['Observed source', 'Transport peer', 'Path', 'Rule / signal', 'Event ID'].includes(label) ? 'mono' : ''}">${escapeHtml(value)}</dd></div>`).join('')}</dl>${isDecoy ? `<h3 class="drawer-section-heading">Decoy evidence trail</h3><dl class="detail-list"><div class="detail-row"><dt>Hashed credential ID</dt><dd class="mono">${event.tokenId}</dd></div><div class="detail-row"><dt>Observed context</dt><dd>${escapeHtml(event.context)}</dd></div><div class="detail-row"><dt>Time since issuance</dt><dd>${event.age} seconds</dd></div></dl><div class="timeline"><div class="timeline-item"><strong>Decoy response issued</strong><span class="timeline-time">${timeLabel(event.issuedAt)}</span><p><span class="mono">${event.issuedSource}</span> requested <span class="mono">${event.lure}</span></p><p>Template: ${event.template}. Issuance does not confirm receipt.</p></div><div class="timeline-item"><strong>${event.kind === 'decoy' ? 'Credential presented to the owned API' : 'Token observed outside authentication'}</strong><span class="timeline-time">${timeLabel(event.time)} · ${event.age}s after issuance</span><p><span class="mono">${event.source}</span>${event.source !== event.issuedSource ? ' · a different source IP' : ' · same observed source IP'}</p><p>${event.kind === 'decoy' ? 'This request was blocked locally. No upstream request was made.' : 'Passive observation only. No token-based block was applied.'}</p></div></div><div class="evidence-note">${icon('info')}<span>This establishes a returned decoy credential. It does not establish AI use, malicious intent, the same person, or confirmed delivery of the original response.</span></div>` : `<div class="evidence-note">${icon('info')}<span>${event.kind === 'upstream' ? 'This is a service error, not an attack classification.' : event.kind === 'admin' ? 'The administrative function was closed by policy. This does not establish malicious intent.' : 'A rule match or protective action records an observation. It does not establish attacker identity or successful exploitation.'}</span></div>`}<h3 class="drawer-section-heading">${isDecoy ? 'Related credential observations' : 'Other recorded events from this source'}</h3>${related.length ? related.map((item) => `<button class="related-event" data-related="${item.id}"><span>${escapeHtml(item.label)}<br><span class="mono">${item.source}</span></span><span>${timeLabel(item.time)}</span></button>`).join('') : '<p class="drawer-subtitle">No other observations in the retained demo events.</p>'}<div class="drawer-footer">All data is simulated. Credentials, authorization headers, and request bodies are not exposed.</div>`;
    $('#event-drawer').hidden = false;
    $('#event-drawer').scrollTop = 0;
    $('#drawer-scrim').hidden = false;
    $('.app-shell').inert = true;
    $('#sidebar').inert = true;
    document.body.style.overflow = 'hidden';
    $('#close-drawer').focus();
    $$('tr[data-event]').forEach((row) => row.classList.toggle('selected', row.dataset.event === id));
  }
  function closeDrawer() {
    if ($('#event-drawer').hidden) return;
    $('#event-drawer').hidden = true;
    $('#drawer-scrim').hidden = true;
    $('.app-shell').inert = false;
    $('#sidebar').inert = false;
    document.body.style.overflow = '';
    state.selectedId = null;
    if (state.focusReturn?.isConnected) state.focusReturn.focus();
    else $('#main').focus({ preventScroll: true });
    $$('tr.selected').forEach((row) => row.classList.remove('selected'));
  }
  function closeNav() {
    $('#sidebar').classList.remove('open');
    $('#nav-scrim').hidden = true;
    $('#mobile-menu').setAttribute('aria-expanded', 'false');
    if ($('#event-drawer').hidden) document.body.style.overflow = '';
  }
  function toggleNav() {
    const open = !$('#sidebar').classList.contains('open');
    $('#sidebar').classList.toggle('open', open);
    $('#nav-scrim').hidden = !open;
    $('#mobile-menu').setAttribute('aria-expanded', String(open));
    document.body.style.overflow = open ? 'hidden' : '';
  }
  function exportMetrics() {
    const data = metricsData();
    const rows = [
      ['dataset', 'fictional prototype data'], ['period', state.period], ['site', state.site], ['timezone', state.timezone],
      ['total_requests', data.total], ['rejected_requests', data.rejected], ['rejection_rate_percent', data.ratio],
      ['log_detected_requests', data.logs], ['upstream_connection_failures', data.errors], ['upstream_timeouts', data.timeouts],
      ['decoy_credential_use_requests', data.decoys], ['observed_reused_credential_ids', data.unique], ['decoy_passive_occurrences', data.passive],
    ];
    if (state.period === 'custom') rows.splice(2, 0, ['from', localDay(state.customFrom)], ['to', localDay(state.customTo)]);
    const csv = [['metric', 'value'], ...rows].map((row) => row.map((value) => `"${String(value).replaceAll('"', '""')}"`).join(',')).join('\r\n');
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = `kunato-demo-metrics-${state.period}.csv`;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast('Fictional metrics exported as CSV.');
  }

  hydrateIcons();
  seedData();
  $('#custom-from').value = localDay(startedAt - 7 * 86400000);
  $('#custom-to').value = localDay(startedAt);
  $('#custom-from').max = localDay(startedAt);
  $('#custom-to').max = localDay(startedAt);

  window.addEventListener('hashchange', () => { closeDrawer(); setView(location.hash.slice(1)); window.scrollTo(0, 0); });
  $$('[data-period]').forEach((button) => button.addEventListener('click', () => {
    if (button.dataset.period === 'custom') {
      $('#custom-range').hidden = !$('#custom-range').hidden;
      if (!$('#custom-range').hidden) $('#custom-from').focus();
      return;
    }
    state.period = button.dataset.period;
    $('#custom-range').hidden = true;
    setPressed('[data-period]', 'data-period', state.period);
    renderMetrics();
  }));
  $('#apply-range').addEventListener('click', () => {
    const from = Date.parse(`${$('#custom-from').value}T00:00:00Z`);
    const to = Date.parse(`${$('#custom-to').value}T00:00:00Z`);
    const max = Date.parse(`${localDay(startedAt)}T00:00:00Z`);
    if (!Number.isFinite(from) || !Number.isFinite(to) || from > to || to > max || to - from > 3650 * 86400000) {
      $('#range-error').textContent = 'Choose valid past dates, up to 10 years apart.';
      return;
    }
    $('#range-error').textContent = '';
    state.customFrom = from; state.customTo = to; state.period = 'custom';
    setPressed('[data-period]', 'data-period', 'custom');
    renderMetrics();
  });
  $('#compare-toggle').addEventListener('change', (event) => { state.compare = event.target.checked; renderMetrics(); });
  $('#site-select').addEventListener('change', (event) => { state.site = event.target.value; if (state.view === 'metrics') renderMetrics(); else renderLive(); });
  $$('[data-chart]').forEach((button) => button.addEventListener('click', () => { state.chart = button.dataset.chart; setPressed('[data-chart]', 'data-chart', state.chart); renderMetrics(); }));
  $$('[data-detection]').forEach((button) => button.addEventListener('click', () => { state.detection = button.dataset.detection; setPressed('[data-detection]', 'data-detection', state.detection); renderDetection(); }));
  $$('[data-ranking]').forEach((button) => button.addEventListener('click', () => { state.ranking = button.dataset.ranking; setPressed('[data-ranking]', 'data-ranking', state.ranking); renderRanking(); }));
  $('#source-ranking').addEventListener('click', (event) => {
    const button = event.target.closest('[data-search]');
    if (!button) return;
    state.search = button.dataset.search; state.eventType = 'all'; state.method = 'all'; state.action = 'all'; state.status = 'all';
    syncFilters();
    if (location.hash !== '#live') location.hash = 'live'; else setView('live');
  });
  $('#inspect-decoys').addEventListener('click', inspectDecoys);
  $('#export-button').addEventListener('click', exportMetrics);
  $('#pause-button').addEventListener('click', () => {
    state.paused = !state.paused;
    if (state.paused) {
      state.pausedAt = state.clock; state.pausedNew = 0;
      $$('.activity-flash, .event-arrived').forEach(finishActivityFlash);
    }
    else { state.pausedAt = null; state.pausedNew = 0; renderLive(); }
    updatePauseButton();
  });
  $$('[data-window]').forEach((button) => button.addEventListener('click', () => { state.window = Number(button.dataset.window); state.limit = 35; setPressed('[data-window]', 'data-window', button.dataset.window); renderLive(); }));
  $('#follow-toggle').addEventListener('change', (event) => {
    state.follow = event.target.checked;
    if (state.follow) $('#event-table-scroll').scrollTop = 0;
  });
  $('#event-search').addEventListener('input', (event) => { state.search = event.target.value.slice(0, 512); state.limit = 35; renderEventTable(); });
  [['#event-type', 'eventType'], ['#event-method', 'method'], ['#event-action', 'action'], ['#event-status', 'status']].forEach(([selector, key]) => {
    $(selector).addEventListener('change', (event) => { state[key] = event.target.value; state.limit = 35; renderEventTable(); });
  });
  $$('[data-live-ranking]').forEach((button) => button.addEventListener('click', () => {
    state.liveRanking = button.dataset.liveRanking;
    setPressed('[data-live-ranking]', 'data-live-ranking', state.liveRanking);
    renderLiveCards();
  }));
  $('#decoy-filter').addEventListener('click', () => { state.eventType = state.eventType === 'decoy' ? 'all' : 'decoy'; $('#event-type').value = state.eventType; renderEventTable(); });
  $('#clear-filters').addEventListener('click', clearFilters);
  $('#empty-clear').addEventListener('click', clearFilters);
  $('#show-more').addEventListener('click', () => { state.limit = Math.min(500, state.limit + 35); renderEventTable(); });
  $('#event-table-body').addEventListener('click', (event) => { const row = event.target.closest('[data-event]'); if (row) openEvent(row.dataset.event); });
  $('#event-table-body').addEventListener('keydown', (event) => { if (['Enter', ' '].includes(event.key)) { const row = event.target.closest('[data-event]'); if (row) { event.preventDefault(); openEvent(row.dataset.event); } } });
  $('#close-drawer').addEventListener('click', closeDrawer);
  $('#drawer-scrim').addEventListener('click', closeDrawer);
  $('#drawer-content').addEventListener('click', (event) => { const button = event.target.closest('[data-related]'); if (button) openEvent(button.dataset.related); });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') { closeDrawer(); closeNav(); $('#demo-menu').hidden = true; $('#demo-menu-button').setAttribute('aria-expanded', 'false'); }
    if (event.key === 'Tab' && !$('#event-drawer').hidden) {
      const controls = $$('button, [tabindex="0"]', $('#event-drawer'));
      const first = controls[0], last = controls.at(-1);
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    }
  });
  $('#mobile-menu').addEventListener('click', toggleNav);
  $('#nav-scrim').addEventListener('click', closeNav);
  $('#timezone-toggle').addEventListener('click', () => {
    state.timezone = state.timezone === 'Asia/Tokyo' ? 'UTC' : 'Asia/Tokyo';
    const zone = state.timezone === 'Asia/Tokyo' ? 'JST' : 'UTC';
    $('#timezone-toggle').innerHTML = `${zone} ${icon('globe')}`;
    $('#table-timezone').textContent = zone;
    if (state.view === 'metrics') renderMetrics(); else renderLive();
    if (state.selectedId) openEvent(state.selectedId);
  });
  $('#demo-menu-button').addEventListener('click', () => { $('#demo-menu').hidden = !$('#demo-menu').hidden; $('#demo-menu-button').setAttribute('aria-expanded', String(!$('#demo-menu').hidden)); });
  document.addEventListener('click', (event) => { if (!event.target.closest('.demo-menu-wrap')) { $('#demo-menu').hidden = true; $('#demo-menu-button').setAttribute('aria-expanded', 'false'); } });
  $('#interrupt-demo').addEventListener('click', () => {
    state.online = !state.online;
    if (!state.online) state.gapStarted = Date.now();
    else { state.gaps.push([state.gapStarted, Date.now()]); state.gaps = state.gaps.slice(-12); state.gapStarted = null; }
    $('#demo-menu').hidden = true;
    $('#demo-menu-button').setAttribute('aria-expanded', 'false');
    updateFeedStatus();
    if (state.view === 'live' && !state.paused) renderLive();
    toast(state.online ? 'Demo collection restored.' : 'Collection interruption simulated.');
  });
  $('#reset-demo').addEventListener('click', () => {
    state.online = true; state.paused = false; state.pausedAt = null; state.pausedNew = 0; state.gaps = []; state.gapStarted = null; state.tick = 0;
    seedData(); closeDrawer(); clearFilters(); updateFeedStatus();
    $('#demo-menu').hidden = true; $('#demo-menu-button').setAttribute('aria-expanded', 'false');
    toast('Fictional traffic and events reset.');
  });
  setView(location.hash.slice(1));
  updateFeedStatus();

  setInterval(() => {
    state.clock = Date.now();
    state.tick += 1;
    let activity = null;
    if (state.online) {
      const latest = sample(state.clock, state.tick + 450);
      state.samples.push(latest);
      const next = state.tick % 37 === 0 ? decoyEvent(state.clock, Math.floor(state.tick / 37)) : newEvent(state.clock, state.tick * 3 + 2);
      activity = { event: next, sample: latest };
      state.events.unshift(next);
      state.events = state.events.slice(0, 500);
      state.samples = state.samples.slice(-900);
      if (state.paused && siteMatches(next)) state.pausedNew = Math.min(500, state.pausedNew + 1);
    }
    updatePauseButton();
    if (state.view === 'live' && !state.paused) renderLive(activity);
  }, 2000);
})();
