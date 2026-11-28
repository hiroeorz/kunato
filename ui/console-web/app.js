"use strict";

(function () {
  var state = {
    view: "live",
    session: { enabled: false, authenticated: true },
    latest: null,
    previous: null,
    events: new Map(),
    generation: null,
    rangeMs: 604800000,
    metrics: null,
    correlations: null,
    connected: false,
    source: null,
    clockOffsetMs: 0,
    edr: null,
    edrRequest: 0,
    sourceDetail: {
      open: false,
      ip: null,
      role: "client",
      eventKey: null,
      peer: null,
      openedAt: null,
      events: [],
      info: null,
      loading: false,
      error: null,
      rdap: null,
      rdapLoading: false,
      rdapError: null,
      request: 0,
      returnFocus: null,
    },
  };

  var view = {
    live: document.getElementById("live-view"),
    metrics: document.getElementById("metrics-view"),
    edr: document.getElementById("edr-view"),
  };

  var SVG_NS = "http://www.w3.org/2000/svg";
  var COUNTRY_DISPLAY_NAMES = null;
  try {
    COUNTRY_DISPLAY_NAMES = new Intl.DisplayNames(["en"], { type: "region" });
  } catch (error) {
    COUNTRY_DISPLAY_NAMES = null;
  }

  var COUNTRY_COLORS = [
    "#3f6f9e", "#c56b47", "#5f8f63", "#9a6aac", "#b79a3f",
    "#4f9aa4", "#ad5e70", "#7581bb", "#8c6e50", "#4c8d7b",
    "#b36d9b", "#82904b",
  ];
  var COUNTRY_OTHER_COLOR = "#9aa6b2";
  var COUNTRY_RANKING_LIMIT = 10;
  var REJECTION_SHARE_COLORS = [
    "#46618f", "#b7623f", "#5d8259", "#8e639f", "#a98c39",
    "#4c8b95", "#a85c70", "#6f7ab0",
  ];
  var REJECTION_OTHER_COLOR = "#9aa6b2";
  var REJECTION_UNRECORDED_COLOR = "#c9d1da";
  var REJECTION_SHARE_LIMIT = 8;
  var WORLD_MAP_NO_DATA = "#e7ecf1";
  var WORLD_MAP_ZERO = "#f7f9fb";
  var WORLD_MAP_COLORS = [
    "#fde8d8", "#f9c9a8", "#f2a47c", "#dd7048", "#b94b35", "#7f2a2a",
  ];

  var EDR_DETECTOR_KINDS = [
    "slow_authentication",
    "reverse_brute_force",
    "auth_success_after_failures",
    "campaign_success",
  ];

  var EDR_DETECTOR_LABELS = {
    slow_authentication: {
      title: "Slow authentication",
      detail: "One source failing authentication below the per-minute controls.",
    },
    reverse_brute_force: {
      title: "Reverse brute force",
      detail: "Many sources failing on the same authentication endpoint.",
    },
    auth_success_after_failures: {
      title: "Success after failures",
      detail: "A source authenticated after sustained failures.",
    },
    campaign_success: {
      title: "Campaign success",
      detail: "A distributed campaign produced a successful response.",
    },
  };

  var TOPO_LAYERS = [
    {
      id: "country",
      name: "Country Gate",
      title: "COUNTRY GATE",
      color: "#557a8a",
      x: 225,
      y: 42,
      width: 126,
      height: 56,
      icon: '<circle cx="10" cy="10" r="7.2"/><path d="M2.8 10h14.4M10 2.8c2.2 2.2 3.2 4.6 3.2 7.2s-1 5-3.2 7.2C7.8 15 6.8 12.6 6.8 10s1-5 3.2-7.2z"/>',
    },
    {
      id: "admin",
      name: "Admin Gate",
      title: "ADMIN GATE",
      color: "#b8811f",
      x: 363,
      y: 42,
      width: 126,
      height: 56,
      icon: '<circle cx="6" cy="6" r="3.4"/><path d="M8.5 8.5 17 17M13 13l2-2M15.5 15.5l2-2"/>',
    },
    {
      id: "rate",
      name: "Rate / Ban",
      title: "RATE / BAN",
      color: "#c66361",
      x: 501,
      y: 42,
      width: 126,
      height: 56,
      icon: '<path d="M2.5 15.5a7.5 7.5 0 1 1 15 0"/><path d="M10 15.5 14.8 9.5"/><circle cx="10" cy="15.5" r="1.1"/>',
    },
    {
      id: "rules",
      name: "YAML Rules",
      title: "YAML RULES",
      color: "#4f7fa8",
      x: 639,
      y: 42,
      width: 126,
      height: 56,
      icon: '<path d="M5 2.5h7.2L16.5 6v11.5H5z"/><path d="M12 2.5V6.2h4.3M8 9.5h5.5M8 12.5h5.5M8 15.5h3.4"/>',
    },
    {
      id: "decoy",
      name: "Decoy Ward",
      title: "DECOY WARD",
      color: "#e88336",
      x: 225,
      y: 162,
      width: 138,
      height: 56,
      icon: '<path d="M10 2.5 17.5 10 10 17.5 2.5 10z"/><circle cx="10" cy="10" r="2.1"/>',
    },
    {
      id: "guards",
      name: "Payload Guards",
      title: "PAYLOAD GUARDS",
      color: "#9a6bb8",
      x: 423,
      y: 162,
      width: 138,
      height: 56,
      icon: '<path d="M10 2.5 17.5 6.4 10 10.3 2.5 6.4z"/><path d="M2.8 10.2 10 14l7.2-3.8M2.8 14 10 17.8l7.2-3.8"/>',
    },
    {
      id: "behavior",
      name: "Behavior",
      title: "BEHAVIOR",
      color: "#3c8b70",
      x: 621,
      y: 162,
      width: 138,
      height: 56,
      icon: '<path d="M2 10h3.6l2.1-5 4.1 10 2.1-5H18"/>',
    },
  ];

  TOPO_LAYERS.forEach(function (layer) {
    layer.cx = layer.x + layer.width / 2;
    layer.cy = layer.y + layer.height / 2;
  });

  var TOPO_LAYER_BY_ID = {};
  TOPO_LAYERS.forEach(function (layer) {
    TOPO_LAYER_BY_ID[layer.id] = layer;
  });

  var TOPO_EDGES = [
    { id: "ingress-country", d: "M176 130 C198 130 206 70 225 70" },
    { id: "country-admin", d: "M351 70 H363" },
    { id: "decoy-internet", d: "M176 130 C198 130 206 190 225 190" },
    { id: "admin-rate", d: "M489 70 H501" },
    { id: "decoy-guards", d: "M363 190 H423" },
    { id: "rate-rules", d: "M627 70 H639" },
    { id: "guards-behavior", d: "M561 190 H621" },
    { id: "rules-upstream", d: "M765 70 C800 70 808 130 840 130" },
    { id: "behavior-upstream", d: "M759 190 C792 190 802 130 840 130" },
  ];

  var TOPO_ROUTES = {
    country: {
      edges: ["ingress-country"],
      d: "M176 130 C198 130 206 70 225 70 L288 70",
    },
    admin: {
      edges: ["ingress-country", "country-admin"],
      d: "M176 130 C198 130 206 70 225 70 L288 70 L426 70",
    },
    rate: {
      edges: ["ingress-country", "country-admin", "admin-rate"],
      d: "M176 130 C198 130 206 70 225 70 L288 70 L426 70 L564 70",
    },
    rules: {
      edges: ["ingress-country", "country-admin", "admin-rate", "rate-rules"],
      d: "M176 130 C198 130 206 70 225 70 L288 70 L426 70 L564 70 L702 70",
    },
    decoy: {
      edges: ["decoy-internet"],
      d: "M176 130 C198 130 206 190 225 190 L294 190",
    },
    guards: {
      edges: ["decoy-internet", "decoy-guards"],
      d: "M176 130 C198 130 206 190 225 190 L294 190 L363 190 L492 190",
    },
    behavior: {
      edges: ["decoy-internet", "decoy-guards", "guards-behavior"],
      d: "M176 130 C198 130 206 190 225 190 L294 190 L363 190 L492 190 L690 190",
    },
    upstream: {
      edges: ["ingress-country", "country-admin", "admin-rate", "rate-rules", "rules-upstream"],
      d: "M176 130 C198 130 206 70 225 70 L288 70 L426 70 L564 70 L702 70 C800 70 808 130 840 130 L911 130",
    },
  };

  var TOPO_KIND_LAYER = {
    rulematch: "rules",
    ratelimit: "rate",
    ban: "rate",
    behavior: "behavior",
    decoy: "decoy",
    upstreamfailure: "upstream",
  };

  var TOPO_LAYER_INK = {
    admin: "#7a5314",
    rate: "#a34442",
    rules: "#396a92",
    decoy: "#a95d18",
    guards: "#7d4e9b",
    behavior: "#2f7159",
    country: "#3f6273",
    upstream: "#a34442",
  };

  var TOPO_SPARK_COLOR = {
    admin: "#e3a13c",
    rate: "#f07182",
    rules: "#5aa7d8",
    decoy: "#fb923c",
    guards: "#bd86e0",
    behavior: "#4db392",
    country: "#7fb7c9",
    upstream: "#f07182",
  };

  var TOPO_REASON_LAYER = {
    adminaccess: "admin",
    rule: "rules",
    responserule: "rules",
    responseinspection: "rules",
    ratelimit: "rate",
    ban: "rate",
    overload: "rate",
    clientidentity: "rate",
    host: "rate",
    protocol: "rate",
    upload: "guards",
    graphql: "guards",
    saml: "guards",
    form: "guards",
    body: "guards",
    decode: "guards",
    phprequest: "guards",
    phpresponse: "guards",
    hardening: "guards",
    jwt: "guards",
    decoy: "decoy",
    behavior: "behavior",
    countrypolicy: "country",
  };

  var topo = {
    built: false,
    mode: "realtime",
    selectedKey: null,
    selected: null,
    lastSequence: null,
    newSinceFocus: 0,
    counts: {},
    nodes: {},
    edges: {},
    upstream: null,
    internet: null,
    countryBadge: null,
    geometry: {},
    routeLength: {},
    packets: null,
    sparks: null,
    stop: null,
    forward: null,
    epoch: 0,
    packetCount: 0,
    edgeTimers: {},
    internetTimer: null,
    focusTimer: null,
    panelTimer: null,
    revealTimer: null,
    forwardTimer: null,
    stopTimer: null,
  };

  function $(id) {
    return document.getElementById(id);
  }

  function number(value) {
    if (value === null || value === undefined) {
      return "Unavailable";
    }
    return new Intl.NumberFormat().format(value);
  }

  function percent(numerator, denominator) {
    if (numerator === null || numerator === undefined) {
      return "Unavailable";
    }
    if (!denominator) {
      return "Unavailable";
    }
    return ((100 * numerator) / denominator).toFixed(1) + "%";
  }

  function utc(ms) {
    if (ms === null || ms === undefined) {
      return "unavailable";
    }
    return new Date(ms).toISOString().replace("T", " ").slice(0, 19) + " UTC";
  }

  function utcClock(ms) {
    if (ms === null || ms === undefined) {
      return "unavailable";
    }
    return new Date(ms).toISOString().slice(11, 19) + " UTC";
  }

  function utcDate(ms) {
    if (ms === null || ms === undefined) {
      return "unavailable";
    }
    return new Date(ms).toISOString().slice(0, 10);
  }

  function emptyNode(node) {
    if (!node) {
      return;
    }
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function formatDurationMs(ms) {
    if (ms === null || ms === undefined || ms <= 0) {
      return "unavailable";
    }
    var minutes = Math.round(ms / 60000);
    if (minutes >= 1440) {
      return Math.round(minutes / 1440) + "d";
    }
    if (minutes >= 60) {
      return Math.round(minutes / 60) + "h";
    }
    return minutes + "m";
  }

  function formatDecimal(value, digits) {
    if (value === null || value === undefined || !isFinite(value)) {
      return "n/a";
    }
    return Number(value).toFixed(digits);
  }

  function countryName(code) {
    if (!code) {
      return null;
    }
    try {
      return COUNTRY_DISPLAY_NAMES ? COUNTRY_DISPLAY_NAMES.of(code) : code;
    } catch (error) {
      return code;
    }
  }

  var GRAIN_MS = {
    minute: 60000,
    five_minutes: 300000,
    ten_minutes: 600000,
    twenty_minutes: 1200000,
    hour: 3600000,
  };

  function utcMinute(ms) {
    return new Date(ms).toISOString().slice(0, 16).replace("T", " ");
  }

  var DAY_MS = 86400000;
  var THREE_HOURS_MS = 3 * GRAIN_MS.hour;
  var SIX_HOURS_MS = 6 * GRAIN_MS.hour;
  var TWELVE_HOURS_MS = 12 * GRAIN_MS.hour;
  var MAX_BAR_WIDTH = 12;
  var REQUESTS_BAR_COLOR = "#3c8b70";
  var REJECTED_BAR_COLOR = "#c66361";
  var COUNTRY_BADGE_VISIBLE_MS = 20000;

  function displayGrainMs(rangeMs, buckets) {
    var maxGrain = 0;
    buckets.forEach(function (bucket) {
      maxGrain = Math.max(maxGrain, GRAIN_MS[bucket.grain] || 0);
    });
    var width = THREE_HOURS_MS;
    if (rangeMs > 8 * DAY_MS) {
      width = rangeMs <= 16 * DAY_MS ? SIX_HOURS_MS : TWELVE_HOURS_MS;
    }
    return Math.max(width, maxGrain);
  }

  function displayGrainLabel(widthMs) {
    if (widthMs >= DAY_MS) {
      return "1 UTC day";
    }
    if (widthMs >= GRAIN_MS.hour) {
      var hours = Math.round(widthMs / GRAIN_MS.hour);
      return hours === 1 ? "1 hour" : hours + " hours";
    }
    var minutes = Math.round(widthMs / GRAIN_MS.minute);
    return minutes === 1 ? "1 minute" : minutes + " minutes";
  }

  function syncPeriodButtons() {
    document.querySelectorAll("[data-period-ms]").forEach(function (button) {
      button.setAttribute("aria-pressed", String(Number(button.dataset.periodMs) === state.rangeMs));
    });
  }

  function grainLabel(grain) {
    return String(grain || "unknown").replace(/_/g, " ");
  }

  function grainShortLabel(grain) {
    var milliseconds = GRAIN_MS[grain] || 0;
    if (milliseconds >= DAY_MS) {
      return "1d";
    }
    if (milliseconds >= GRAIN_MS.hour) {
      return Math.round(milliseconds / GRAIN_MS.hour) + "h";
    }
    if (milliseconds >= GRAIN_MS.minute) {
      return Math.round(milliseconds / GRAIN_MS.minute) + "m";
    }
    return "?";
  }

  function formatRate(value) {
    if (value === null || value === undefined) {
      return "Unavailable";
    }
    var digits = Math.abs(value) >= 10 ? 0 : Math.abs(value) >= 1 ? 1 : 2;
    return new Intl.NumberFormat(undefined, {
      minimumFractionDigits: 0,
      maximumFractionDigits: digits,
    }).format(value);
  }

  function counterTotal(group, name) {
    var stats = group.counters[name];
    return stats && stats.known_minutes ? stats.sum : null;
  }

  function counterRate(group, name) {
    var stats = group.counters[name];
    return stats && stats.complete_minutes ? stats.complete_sum / stats.complete_minutes : null;
  }

  function addCounter(target, stats) {
    if (!stats || typeof stats.sum !== "number") {
      return;
    }
    target.sum += stats.sum || 0;
    target.known_minutes += stats.known_minutes || 0;
    target.complete_minutes += stats.complete_minutes || 0;
    target.complete_sum += stats.complete_sum || 0;
  }

  function addCountryCount(target, code, counts) {
    if (!counts) {
      return;
    }
    if (!target[code]) {
      target[code] = { requests: 0, rejected: 0 };
    }
    target[code].requests += Number(counts.requests) || 0;
    target[code].rejected += Number(counts.rejected) || 0;
  }

  // Storage grain changes with age; group stored buckets into a range-specific
  // display grain so every bar covers a comparable interval. Never split a
  // stored bucket: the display grain is always at least as wide as storage.
  function groupBuckets(buckets, widthMs) {
    var groups = [];
    var byStart = new Map();
    buckets.forEach(function (bucket) {
      var key = Math.floor(bucket.start_ms / widthMs) * widthMs;
      var end = bucket.start_ms + (GRAIN_MS[bucket.grain] || 0);
      var group = byStart.get(key);
      if (!group) {
        group = {
          start_ms: bucket.start_ms,
          end_ms: end,
          counters: {},
          grains: {},
          incomplete: false,
          observed_minutes: 0,
          countries: {},
          countries_complete: {},
          country_known: false,
          country_incomplete: false,
        };
        byStart.set(key, group);
        groups.push(group);
      }
      group.start_ms = Math.min(group.start_ms, bucket.start_ms);
      group.end_ms = Math.max(group.end_ms, end);
      group.incomplete = group.incomplete || Boolean(bucket.coverage && bucket.coverage.incomplete);
      group.observed_minutes += Number(bucket.coverage && bucket.coverage.represented_minutes) || 0;
      group.grains[bucket.grain] = true;
      var counters = bucket.counters || {};
      Object.keys(counters).forEach(function (name) {
        if (!group.counters[name]) {
          group.counters[name] = {
            sum: 0,
            known_minutes: 0,
            complete_minutes: 0,
            complete_sum: 0,
          };
        }
        addCounter(group.counters[name], counters[name]);
      });
      var countryCounts = bucket.additional && bucket.additional.countries;
      if (countryCounts) {
        var completeCountryData =
          !(bucket.coverage && bucket.coverage.incomplete) &&
          !(bucket.additional && bucket.additional.country_overflow);
        Object.keys(countryCounts).forEach(function (code) {
          var counts = countryCounts[code];
          if (!counts) {
            return;
          }
          group.country_known = true;
          addCountryCount(group.countries, code, counts);
          if (completeCountryData) {
            addCountryCount(group.countries_complete, code, counts);
          }
        });
      }
      if (!bucket.additional || (bucket.additional.country_overflow || 0) > 0) {
        group.country_incomplete = true;
      }
    });
    groups.sort(function (a, b) {
      return a.start_ms - b.start_ms;
    });
    return groups;
  }

  function displayLabel(group) {
    var start = utcMinute(group.start_ms);
    var end = utcMinute(group.end_ms);
    if (start.slice(0, 10) === end.slice(0, 10)) {
      return start + "–" + end.slice(11) + " UTC";
    }
    return start + " – " + end + " UTC";
  }

  function displayTimeLabel(ms, widthMs) {
    return widthMs >= DAY_MS ? new Date(ms).toISOString().slice(0, 10) : utcMinute(ms);
  }

  function now() {
    return Date.now() + state.clockOffsetMs;
  }

  function ageClass(occurredAt) {
    var age = Math.max(0, now() - occurredAt);
    if (age <= 60000) {
      return "age-1m";
    }
    if (age <= 180000) {
      return "age-3m";
    }
    if (age <= 300000) {
      return "age-5m";
    }
    return "age-older";
  }

  function updateEventAges() {
    var rows = $("live-events").querySelectorAll("tr[data-occurred-at]");
    for (var index = 0; index < rows.length; index += 1) {
      var row = rows[index];
      var className = ageClass(Number(row.getAttribute("data-occurred-at")));
      if (row.className !== className) {
        row.className = className;
      }
    }
  }

  function normalizeToken(value) {
    return String(value === null || value === undefined ? "" : value)
      .toLowerCase()
      .replace(/[^a-z0-9]/g, "");
  }

  function humanToken(value) {
    var textValue = String(value === null || value === undefined ? "" : value)
      .replace(/_/g, " ")
      .replace(/([a-z])([A-Z])/g, "$1 $2");
    if (!textValue) {
      return "event";
    }
    return textValue.charAt(0).toUpperCase() + textValue.slice(1);
  }

  function layerById(layerId) {
    return layerId ? TOPO_LAYER_BY_ID[layerId] || null : null;
  }

  function layerForEvent(event) {
    if (!event) {
      return null;
    }
    var kind = normalizeToken(event.kind);
    if (kind === "rejection") {
      var rejectionReason = normalizeToken(event.reason);
      if (TOPO_REASON_LAYER[rejectionReason]) {
        return TOPO_REASON_LAYER[rejectionReason];
      }
      return "guards";
    }
    if (TOPO_KIND_LAYER[kind]) {
      return TOPO_KIND_LAYER[kind];
    }
    var reason = normalizeToken(event.reason);
    if (TOPO_REASON_LAYER[reason]) {
      return TOPO_REASON_LAYER[reason];
    }
    return null;
  }

  function layerName(layerId) {
    if (layerId === "upstream") {
      return "Upstream Origins";
    }
    var layer = layerById(layerId);
    return layer ? layer.name : "service event";
  }

  function layerColor(layerId) {
    if (layerId === "upstream") {
      return "#c66361";
    }
    var layer = layerById(layerId);
    return layer ? layer.color : "#828994";
  }

  function sparkColor(layerId) {
    return TOPO_SPARK_COLOR[layerId] || "#e88336";
  }

  function layerInk(layerId) {
    return TOPO_LAYER_INK[layerId] || "#596271";
  }

  function focusColor(event) {
    return layerColor(layerForEvent(event));
  }

  function isForwarded(event) {
    var disposition = normalizeToken(event && event.disposition);
    return disposition === "log" || disposition === "observe";
  }

  function isStopped(event) {
    var disposition = normalizeToken(event && event.disposition);
    return disposition === "block" || disposition === "reject";
  }

  function actionLabel(event) {
    var disposition = normalizeToken(event && event.disposition);
    if (disposition === "block") {
      return "INTERCEPT";
    }
    if (disposition === "reject") {
      return "STOPPED";
    }
    if (disposition === "log") {
      return "DETECTED";
    }
    if (disposition === "observe") {
      return "OBSERVED";
    }
    if (disposition === "error") {
      return "FAILED";
    }
    return "EVENT";
  }

  function actionWord(event) {
    var disposition = normalizeToken(event && event.disposition);
    if (disposition === "block") {
      return "Blocked";
    }
    if (disposition === "reject") {
      return "Rejected";
    }
    if (disposition === "log") {
      return "Logged";
    }
    if (disposition === "observe") {
      return "Observed";
    }
    if (disposition === "error") {
      return "Failed";
    }
    return "Handled";
  }

  function ruleSummary(event) {
    if (!event) {
      return "";
    }
    var attack = event.attack_class ? rejectClassLabel(event.attack_class) : "";
    var category = event.category ? String(event.category) : "";
    var rule = event.rule ? String(event.rule) : "";
    if (category && rule) {
      var qualified = rule.indexOf(category + "/") === 0;
      var detail = qualified ? rule.slice(category.length + 1) : rule;
      if (attack) {
        return attack + " · " + detail;
      }
      return qualified ? rule : category + " / " + rule;
    }
    if (rule) {
      return attack ? attack + " · " + rule : rule;
    }
    if (category) {
      return attack ? attack + " · " + category : category;
    }
    var reason = event.reason ? humanToken(event.reason) : "";
    if (attack && reason && normalizeToken(attack) !== normalizeToken(reason)) {
      return attack + " · " + reason;
    }
    return attack || reason;
  }

  function requestSummary(event) {
    if (!event) {
      return "";
    }
    var request = [event.method, event.path].filter(Boolean).join(" ").trim();
    if (event.status !== null && event.status !== undefined) {
      request += (request ? " " : "") + "(" + event.status + ")";
    }
    return request.trim();
  }

  function shorten(value, maximum) {
    var textValue = String(value === null || value === undefined ? "" : value);
    return textValue.length > maximum ? textValue.slice(0, maximum - 1) + "…" : textValue;
  }

  function eventKey(event) {
    return (state.generation || "generation") + ":" + event.sequence;
  }

  function copyEvent(event) {
    var copy = {};
    Object.keys(event || {}).forEach(function (key) {
      copy[key] = event[key];
    });
    return copy;
  }

  function latestRetainedEvent() {
    var latest = null;
    state.events.forEach(function (event) {
      if (!latest || event.sequence > latest.sequence) {
        latest = event;
      }
    });
    return latest;
  }

  function uniqueSites() {
    var seen = {};
    var sites = [];
    state.events.forEach(function (event) {
      if (!event.site || seen[event.site]) {
        return;
      }
      seen[event.site] = true;
      sites.push(event.site);
    });
    sites.sort();
    return sites;
  }

  function prefersReducedMotion() {
    return Boolean(
      window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches
    );
  }

  function routeCenter(layerId) {
    if (layerId === "upstream") {
      return { x: 911, y: 130 };
    }
    var layer = layerById(layerId);
    return layer ? { x: layer.cx, y: layer.cy } : { x: 500, y: 130 };
  }

  function countLayers() {
    var counts = {
      admin: 0,
      rate: 0,
      rules: 0,
      decoy: 0,
      guards: 0,
      behavior: 0,
      country: 0,
      upstream: 0,
    };
    state.events.forEach(function (event) {
      var layerId = layerForEvent(event);
      if (layerId && counts[layerId] !== undefined) {
        counts[layerId] += 1;
      }
    });
    return counts;
  }

  function nodeStatusText(count) {
    if (!count) {
      return "ARMED";
    }
    return count + (count === 1 ? " EVENT" : " EVENTS");
  }

  function updateNodeStatus(layerId) {
    if (!topo.built) {
      return;
    }
    var node = topo.nodes[layerId];
    if (!node) {
      return;
    }
    if (node.group.classList.contains("is-hit")) {
      return;
    }
    if (topo.mode === "log" && topo.selected && layerForEvent(topo.selected) === layerId) {
      return;
    }
    node.sub.textContent = nodeStatusText(topo.counts[layerId] || 0);
  }

  function updateUpstreamChrome() {
    if (!topo.built || !topo.upstream || !topo.upstream.group) {
      return;
    }
    var status = document.getElementById("topo-upstream-status");
    var sites = document.getElementById("topo-upstream-sites");
    var count = topo.counts.upstream || 0;
    var focusedOnUpstream =
      topo.mode === "log" && topo.selected && layerForEvent(topo.selected) === "upstream";
    if (status && !topo.upstream.group.classList.contains("is-hit") && !focusedOnUpstream) {
      status.textContent = count ? count + (count === 1 ? " ERROR" : " ERRORS") : "NO ERRORS";
    }
    if (status) {
      status.classList.toggle("has-errors", count > 0);
    }
    var siteList = uniqueSites();
    var siteText = "trusted origins";
    if (siteList.length === 1) {
      siteText = shorten(siteList[0], 22);
    } else if (siteList.length > 1) {
      siteText = shorten(siteList[0], 15) + " +" + (siteList.length - 1);
    }
    if (sites) {
      sites.textContent = siteText;
    }
  }

  function countryLabel(code) {
    var normalized = String(code || "").toUpperCase();
    if (!/^[A-Z]{2}$/.test(normalized)) {
      return "";
    }
    if (normalized === "ZZ") {
      return "UNKNOWN";
    }
    if (COUNTRY_DISPLAY_NAMES) {
      try {
        var name = COUNTRY_DISPLAY_NAMES.of(normalized);
        if (name && name.toUpperCase() !== normalized) {
          return name.toUpperCase();
        }
      } catch (error) {
        // Fall through to the ISO code for browsers or locales that do not
        // recognize a region code.
      }
    }
    return normalized;
  }

  function latestCountryEvent() {
    var latest = null;
    state.events.forEach(function (event) {
      if (!event.country) {
        return;
      }
      if (!latest || event.sequence > latest.sequence) {
        latest = event;
      }
    });
    return latest;
  }

  function hideCountryBadge() {
    if (!topo.countryBadge) {
      return;
    }
    clearTimeout(topo.countryBadge.timer);
    topo.countryBadge.timer = null;
    if (topo.countryBadge.group) {
      topo.countryBadge.group.setAttribute("visibility", "hidden");
      topo.countryBadge.group.classList.remove("is-pulsing");
    }
    topo.countryBadge.lastKey = null;
  }

  function markCountryBadgeSeen() {
    if (!topo.countryBadge) {
      return;
    }
    hideCountryBadge();
    var latest = latestCountryEvent();
    topo.countryBadge.lastSequence = latest && latest.sequence !== undefined ? latest.sequence : null;
  }

  function showCountryBadge(label, key) {
    var width = Math.max(60, Math.min(150, label.length * 5.4 + 18));
    topo.countryBadge.text.textContent = label;
    topo.countryBadge.bg.setAttribute("x", String(100 - width / 2));
    topo.countryBadge.bg.setAttribute("width", String(width));
    topo.countryBadge.group.setAttribute("visibility", "visible");
    if (topo.countryBadge.lastKey !== key) {
      topo.countryBadge.lastKey = key;
      topo.countryBadge.group.classList.remove("is-pulsing");
      void topo.countryBadge.group.getBoundingClientRect();
      topo.countryBadge.group.classList.add("is-pulsing");
    }
  }

  function updateCountryBadge() {
    if (!topo.built || !topo.countryBadge || !topo.countryBadge.group) {
      return;
    }
    if (topo.mode === "log") {
      clearTimeout(topo.countryBadge.timer);
      topo.countryBadge.timer = null;
      var selected = topo.selected;
      var label = countryLabel(selected && selected.country);
      if (!label) {
        hideCountryBadge();
        return;
      }
      showCountryBadge(
        label,
        (selected.sequence === undefined ? "" : selected.sequence) + ":" + label
      );
      return;
    }

    var event = latestCountryEvent();
    var sequence = event && event.sequence !== undefined ? event.sequence : null;
    var realtimeLabel = countryLabel(event && event.country);
    if (!realtimeLabel || sequence === null) {
      hideCountryBadge();
      return;
    }
    if (
      topo.countryBadge.lastSequence !== null &&
      sequence <= topo.countryBadge.lastSequence
    ) {
      return;
    }
    topo.countryBadge.lastSequence = sequence;
    showCountryBadge(realtimeLabel, sequence + ":" + realtimeLabel);
    clearTimeout(topo.countryBadge.timer);
    topo.countryBadge.timer = setTimeout(function () {
      if (topo.mode !== "realtime" || topo.countryBadge.lastSequence !== sequence) {
        return;
      }
      hideCountryBadge();
    }, COUNTRY_BADGE_VISIBLE_MS);
  }

  function updateInternetChrome() {
    if (!topo.built || !topo.internet || !topo.internet.group) {
      return;
    }
    var origin =
      topo.mode === "log" && topo.selected ? topo.selected.client || topo.selected.peer || "" : "";
    topo.internet.group.classList.toggle("is-source", Boolean(origin));
    updateCountryBadge();
  }

  function updateNewBadge() {
    var badge = $("topo-new");
    if (!badge) {
      return;
    }
    var show = topo.mode === "log" && topo.newSinceFocus > 0;
    badge.hidden = !show;
    if (!show) {
      badge.textContent = "0 new";
      return;
    }
    badge.textContent = topo.newSinceFocus + " new";
    badge.setAttribute(
      "aria-label",
      topo.newSinceFocus +
        " new events since the focused log; switch to real-time to watch them"
    );
    badge.classList.remove("is-pulsing");
    void badge.offsetWidth;
    badge.classList.add("is-pulsing");
  }

  function updateTopologyModeUI() {
    var panel = $("topo-panel");
    var holder = $("topo-mode");
    if (panel) {
      panel.setAttribute("data-mode", topo.mode);
    }
    if (holder) {
      holder.setAttribute("data-mode", topo.mode);
    }
    document.querySelectorAll("[data-topo-mode]").forEach(function (button) {
      var active = button.getAttribute("data-topo-mode") === topo.mode;
      button.classList.toggle("is-active", active);
      button.setAttribute("aria-pressed", active ? "true" : "false");
    });
  }

  function updateTopologyMeta() {
    var latest = latestRetainedEvent();
    var line = "";
    if (topo.mode === "log") {
      if (!topo.selected) {
        line =
          "Log mode. Select a row in Recent detections and service events to trace the path to its defense point.";
      } else {
        var layerId = layerForEvent(topo.selected);
        var fate = "no defense layer applies to this service event";
        if (layerId === "upstream") {
          fate = "the request reached the origin";
        } else if (layerId && isStopped(topo.selected)) {
          fate = "the request stopped before upstream";
        } else if (layerId && isForwarded(topo.selected)) {
          fate = "the request continued to upstream";
        }
        line =
          "Log focus " +
          utcClock(topo.selected.occurred_at_ms) +
          " · " +
          layerName(layerId) +
          " · " +
          fate +
          ".";
      }
    } else if (!state.connected) {
      line = "Live stream disconnected. The topology resumes with the next snapshot.";
    } else if (latest) {
      var latestLayer = layerForEvent(latest);
      var detail = ruleSummary(latest) || humanToken(latest.kind);
      var summary =
        normalizeToken(latest.disposition) === "error"
          ? "upstream failure (" + shorten(detail, 42) + ")"
          : actionWord(latest) + " " + shorten(detail, 54);
      line =
        "Last detection " +
        utcClock(latest.occurred_at_ms) +
        " · " +
        layerName(latestLayer) +
        " · " +
        summary +
        ".";
    } else {
      line =
        "Waiting for the first detection. New packets travel from the internet globe and spark at the layer that handles them.";
    }
    text($("topo-last"), line);
  }

  function updateTopologySummary() {
    var parts = [];
    TOPO_LAYERS.forEach(function (layer) {
      parts.push(layer.name + " " + (topo.counts[layer.id] || 0));
    });
    parts.push("Upstream Origins " + (topo.counts.upstream || 0));
    var focus = "";
    if (topo.mode === "log" && topo.selected) {
      focus =
        " Log focus: " +
        actionWord(topo.selected) +
        " " +
        (ruleSummary(topo.selected) || humanToken(topo.selected.kind)) +
        " at " +
        layerName(layerForEvent(topo.selected)) +
        ".";
    } else if (topo.mode === "log") {
      focus = " Log mode with no event selected.";
    }
    text(
      $("topo-summary"),
      "Edge shield topology. The country gate is checked on request admission only; the top track shows the request path and the bottom track shows the response return. Mode " +
        (topo.mode === "log" ? "log" : "real-time") +
        ". Retained events by layer: " +
        parts.join(", ") +
        "." +
        focus
    );
  }

  function updateTopology() {
    if (!topo.built) {
      buildTopology();
    }
    if (!topo.built) {
      return;
    }
    topo.counts = countLayers();
    TOPO_LAYERS.forEach(function (layer) {
      updateNodeStatus(layer.id);
    });
    updateUpstreamChrome();
    updateInternetChrome();
    updateTopologyMeta();
    updateTopologySummary();
  }

  function buildTopology() {
    if (topo.built) {
      return;
    }
    var canvas = $("topo-canvas");
    if (!canvas) {
      return;
    }
    var nodes = TOPO_LAYERS.map(function (layer) {
      return (
        '<g class="topo-node" data-layer="' +
        layer.id +
        '">' +
        '<rect class="topo-node-halo" x="' +
        (layer.x - 5) +
        '" y="' +
        (layer.y - 5) +
        '" width="' +
        (layer.width + 10) +
        '" height="' +
        (layer.height + 10) +
        '" rx="14"/>' +
        '<rect class="topo-node-card" x="' +
        layer.x +
        '" y="' +
        layer.y +
        '" width="' +
        layer.width +
        '" height="' +
        layer.height +
        '" rx="10"/>' +
        '<rect class="topo-node-wash" x="' +
        layer.x +
        '" y="' +
        layer.y +
        '" width="' +
        layer.width +
        '" height="' +
        layer.height +
        '" rx="10"/>' +
        '<rect class="topo-node-outline" x="' +
        layer.x +
        '" y="' +
        layer.y +
        '" width="' +
        layer.width +
        '" height="' +
        layer.height +
        '" rx="10"/>' +
        '<rect class="topo-node-accent" x="' +
        layer.x +
        '" y="' +
        (layer.y + 12) +
        '" width="2.5" height="32" rx="1.25"/>' +
        '<g class="topo-node-icon" transform="translate(' +
        (layer.x + 16) +
        " " +
        (layer.y + 18) +
        ')" aria-hidden="true">' +
        layer.icon +
        "</g>" +
        '<text class="topo-node-title" x="' +
        (layer.x + 40) +
        '" y="' +
        (layer.y + 24) +
        '">' +
        layer.title +
        "</text>" +
        '<text class="topo-node-sub" x="' +
        (layer.x + 40) +
        '" y="' +
        (layer.y + 40) +
        '">ARMED</text>' +
        "</g>"
      );
    }).join("");
    var edges = TOPO_EDGES.map(function (edge) {
      return '<path class="topo-edge" data-edge="' + edge.id + '" d="' + edge.d + '"/>';
    }).join("");
    canvas.innerHTML =
      '<svg id="topo-svg" viewBox="0 0 1000 260" role="img" aria-labelledby="topo-title" aria-describedby="topo-summary" preserveAspectRatio="xMidYMid meet">' +
      "<defs>" +
      '<pattern id="topo-dot-grid" width="18" height="18" patternUnits="userSpaceOnUse">' +
      '<circle cx="2" cy="2" r="0.8" fill="#e4e9f0"/>' +
      "</pattern>" +
      '<radialGradient id="topo-internet-disk" cx="0.35" cy="0.28" r="0.85">' +
      '<stop offset="0" stop-color="#356a9b"/>' +
      '<stop offset="0.55" stop-color="#1f466d"/>' +
      '<stop offset="1" stop-color="#0d1b30"/>' +
      "</radialGradient>" +
      '<linearGradient id="topo-upstream-fill" x1="0" y1="0" x2="0" y2="1">' +
      '<stop offset="0" stop-color="#f5fbf8"/>' +
      '<stop offset="1" stop-color="#eef7f2"/>' +
      "</linearGradient>" +
      '<marker id="topo-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto">' +
      '<path d="M0 0L8 4L0 8z" fill="#3c8b70"/>' +
      "</marker>" +
      '<marker id="topo-phase-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto">' +
      '<path d="M0 0L8 4L0 8z" fill="#aeb5bf"/>' +
      "</marker>" +
      "</defs>" +
      '<rect class="topo-fabric-wash" x="202" y="18" width="570" height="226" rx="18"/>' +
      '<rect class="topo-fabric" x="202" y="18" width="570" height="226" rx="18"/>' +
      '<text class="topo-phase-label" x="250" y="15">REQUEST</text>' +
      '<path class="topo-phase-arrow" d="M310 12H680" marker-end="url(#topo-phase-arrow)"/>' +
      '<path class="topo-phase-arrow" d="M680 249H310" marker-end="url(#topo-phase-arrow)"/>' +
      '<text class="topo-phase-label" x="690" y="252">RESPONSE</text>' +
      '<text class="topo-fabric-label" x="220" y="31">KUNATO DEFENSE FABRIC</text>' +
      '<text class="topo-fabric-meta" x="758" y="31">COUNTRY GATE + 6 LAYERS</text>' +
      '<g class="topo-internet" id="topo-internet">' +
      '<circle class="topo-internet-halo" cx="100" cy="130" r="80"/>' +
      '<circle class="topo-internet-disk" cx="100" cy="130" r="76"/>' +
      '<text class="topo-internet-title" x="100" y="82" text-anchor="middle">INTERNET</text>' +
      '<text class="topo-internet-sub" x="100" y="97" text-anchor="middle">PUBLIC NETWORK</text>' +
      '<g class="topo-globe" transform="translate(100 143) scale(1.4)" aria-hidden="true">' +
      '<circle cx="0" cy="0" r="24"/>' +
      '<ellipse cx="0" cy="0" rx="10" ry="24"/>' +
      '<path d="M-24 0H24M-22 -9H22M-22 9H22"/>' +
      '<circle class="topo-globe-dot" cx="16" cy="-13" r="2.3"/>' +
      "</g>" +
      '<g class="topo-country-badge" id="topo-country-badge" visibility="hidden" aria-hidden="true">' +
      '<rect id="topo-country-badge-bg" x="68" y="156" width="64" height="18" rx="9"/>' +
      '<text id="topo-country-badge-text" x="100" y="168" text-anchor="middle">COUNTRY</text>' +
      "</g>" +
      "</g>" +
      '<g class="topo-edges" aria-hidden="true">' +
      edges +
      "</g>" +
      '<path class="topo-forward" id="topo-forward" d="" marker-end="url(#topo-arrow)"/>' +
      '<g class="topo-nodes">' +
      nodes +
      "</g>" +
      '<g class="topo-upstream" id="topo-upstream">' +
      '<rect class="topo-upstream-halo" x="834" y="76" width="154" height="108" rx="18"/>' +
      '<rect class="topo-upstream-card" x="840" y="82" width="142" height="96" rx="14"/>' +
      '<g class="topo-upstream-icon" transform="translate(856 96)" aria-hidden="true">' +
      '<rect x="2" y="2" width="16" height="6" rx="1.5"/>' +
      '<rect x="2" y="12" width="16" height="6" rx="1.5"/>' +
      '<path d="M5 5h.01M5 15h.01M9 5h4M9 15h4"/>' +
      "</g>" +
      '<text class="topo-upstream-kicker" x="884" y="105">UPSTREAM</text>' +
      '<text class="topo-upstream-trusted" x="884" y="118">TRUSTED ZONE</text>' +
      '<text class="topo-upstream-status" id="topo-upstream-status" x="856" y="147">NO ERRORS</text>' +
      '<text class="topo-upstream-sites" id="topo-upstream-sites" x="856" y="164">trusted origins</text>' +
      "</g>" +
      '<g class="topo-stop" id="topo-stop" visibility="hidden">' +
      '<circle cx="0" cy="0" r="8"/>' +
      '<path d="M-2.8 -2.8L2.8 2.8M2.8 -2.8L-2.8 2.8"/>' +
      "</g>" +
      '<g class="topo-packets" id="topo-packets" aria-hidden="true"></g>' +
      '<g class="topo-sparks" id="topo-sparks" aria-hidden="true"></g>' +
      "</svg>";

    var svg = canvas.querySelector("svg");
    if (!svg) {
      return;
    }
    topo.packets = svg.querySelector("#topo-packets");
    topo.sparks = svg.querySelector("#topo-sparks");
    topo.stop = svg.querySelector("#topo-stop");
    topo.forward = svg.querySelector("#topo-forward");
    topo.internet = { group: svg.querySelector("#topo-internet"), timer: null };
    topo.countryBadge = {
      group: svg.querySelector("#topo-country-badge"),
      bg: svg.querySelector("#topo-country-badge-bg"),
      text: svg.querySelector("#topo-country-badge-text"),
      timer: null,
      lastSequence: null,
      lastKey: null,
    };
    topo.upstream = { group: svg.querySelector("#topo-upstream"), timer: null };
    if (topo.upstream.group) {
      topo.upstream.group.style.setProperty("--layer", "#3c8b70");
      topo.upstream.group.style.setProperty("--layer-ink", layerInk("upstream"));
    }

    TOPO_LAYERS.forEach(function (layer) {
      var group = svg.querySelector('.topo-node[data-layer="' + layer.id + '"]');
      if (!group) {
        return;
      }
      group.style.setProperty("--layer", layer.color);
      group.style.setProperty("--layer-ink", layerInk(layer.id));
      topo.nodes[layer.id] = {
        group: group,
        sub: group.querySelector(".topo-node-sub"),
        timer: null,
      };
    });

    TOPO_EDGES.forEach(function (edge) {
      var element = svg.querySelector('[data-edge="' + edge.id + '"]');
      if (element) {
        topo.edges[edge.id] = element;
      }
    });

    var geometry = document.createElementNS(SVG_NS, "g");
    geometry.setAttribute("class", "topo-geometry");
    geometry.setAttribute("aria-hidden", "true");
    Object.keys(TOPO_ROUTES).forEach(function (layerId) {
      var path = document.createElementNS(SVG_NS, "path");
      path.setAttribute("d", TOPO_ROUTES[layerId].d);
      geometry.appendChild(path);
      topo.geometry[layerId] = path;
      topo.routeLength[layerId] = 0;
    });
    svg.appendChild(geometry);
    Object.keys(topo.geometry).forEach(function (layerId) {
      try {
        topo.routeLength[layerId] = topo.geometry[layerId].getTotalLength();
      } catch (error) {
        topo.routeLength[layerId] = 0;
      }
    });

    topo.built = true;
    updateTopologyModeUI();
    updateNewBadge();
    TOPO_LAYERS.forEach(function (layer) {
      updateNodeStatus(layer.id);
    });
    updateUpstreamChrome();
    updateInternetChrome();
    updateTopologySummary();
  }

  function activateEdges(edgeIds, color, duration) {
    edgeIds.forEach(function (edgeId) {
      var edge = topo.edges[edgeId];
      if (!edge) {
        return;
      }
      clearTimeout(topo.edgeTimers[edgeId]);
      edge.style.setProperty("--edge-color", color);
      edge.classList.add("is-route-hit");
      topo.edgeTimers[edgeId] = setTimeout(function () {
        edge.classList.remove("is-route-hit");
        edge.style.removeProperty("--edge-color");
        delete topo.edgeTimers[edgeId];
      }, duration);
    });
  }

  function pulseInternet() {
    if (!topo.internet || !topo.internet.group) {
      return;
    }
    topo.internet.group.classList.add("is-receiving");
    clearTimeout(topo.internetTimer);
    topo.internetTimer = setTimeout(function () {
      topo.internet.group.classList.remove("is-receiving");
    }, 950);
  }

  function burstSpark(layerId, color, strong) {
    if (prefersReducedMotion() || !topo.sparks) {
      return;
    }
    var center = routeCenter(layerId);
    while (topo.sparks.childNodes.length >= 10) {
      topo.sparks.removeChild(topo.sparks.firstChild);
    }
    var group = document.createElementNS(SVG_NS, "g");
    group.setAttribute("class", "topo-spark");
    var ring = document.createElementNS(SVG_NS, "circle");
    ring.setAttribute("cx", String(center.x));
    ring.setAttribute("cy", String(center.y));
    var flash = document.createElementNS(SVG_NS, "circle");
    flash.setAttribute("cx", String(center.x));
    flash.setAttribute("cy", String(center.y));
    flash.setAttribute("r", "10");
    flash.setAttribute("fill", color);
    flash.setAttribute("opacity", "0.8");
    group.appendChild(flash);
    ring.setAttribute("r", "7");
    ring.setAttribute("fill", "none");
    ring.setAttribute("stroke", color);
    ring.setAttribute("stroke-width", "2.6");
    ring.setAttribute("opacity", "1");
    group.appendChild(ring);

    var particles = [];
    var count = strong ? 18 : 12;
    for (var index = 0; index < count; index += 1) {
      var angle = (Math.PI * 2 * index) / count + (Math.random() * 0.28 - 0.14);
      var reach = (strong ? 34 : 24) + Math.random() * (strong ? 24 : 16);
      var line = document.createElementNS(SVG_NS, "line");
      line.setAttribute("x1", String(center.x));
      line.setAttribute("y1", String(center.y));
      line.setAttribute("x2", String(center.x));
      line.setAttribute("y2", String(center.y));
      line.setAttribute("stroke", color);
      line.setAttribute("stroke-width", strong ? "2.3" : "1.8");
      line.setAttribute("stroke-linecap", "round");
      line.setAttribute("opacity", "0");
      group.appendChild(line);
      particles.push({
        element: line,
        angle: angle,
        reach: reach,
        delay: Math.random() * 0.08,
      });
    }
    var core = document.createElementNS(SVG_NS, "circle");
    core.setAttribute("cx", String(center.x));
    core.setAttribute("cy", String(center.y));
    core.setAttribute("r", strong ? "5" : "3.8");
    core.setAttribute("fill", "#ffffff");
    core.setAttribute("opacity", "1");
    group.appendChild(core);
    var innerRing = document.createElementNS(SVG_NS, "circle");
    innerRing.setAttribute("cx", String(center.x));
    innerRing.setAttribute("cy", String(center.y));
    innerRing.setAttribute("r", "4");
    innerRing.setAttribute("fill", "none");
    innerRing.setAttribute("stroke", "#ffffff");
    innerRing.setAttribute("stroke-width", "1");
    innerRing.setAttribute("opacity", "0.8");
    group.appendChild(innerRing);
    topo.sparks.appendChild(group);

    var duration = strong ? 940 : 720;
    var start = null;
    function frame(time) {
      if (start === null) {
        start = time;
      }
      var progress = Math.min(1, (time - start) / duration);
      var expansion = Math.min(1, progress * 2.4);
      ring.setAttribute("r", String(7 + (strong ? 48 : 36) * expansion));
      ring.setAttribute("opacity", String(Math.max(0, 1 - progress * 1.15)));
      flash.setAttribute("r", String(10 + 10 * progress));
      flash.setAttribute("opacity", String(Math.max(0, 0.8 - progress * 2.2)));
      core.setAttribute("opacity", String(Math.max(0, 1 - progress * 1.5)));
      innerRing.setAttribute("r", String(4 + (strong ? 18 : 13) * expansion));
      innerRing.setAttribute("opacity", String(Math.max(0, 0.8 * (1 - progress * 1.3))));
      particles.forEach(function (particle) {
        var local = Math.max(
          0,
          Math.min(1, (progress - particle.delay) / Math.max(0.01, 1 - particle.delay))
        );
        var outward = Math.min(1, local * 2.4);
        var begin = 7;
        var end = 7 + particle.reach * outward;
        particle.element.setAttribute(
          "x1",
          String(center.x + Math.cos(particle.angle) * begin)
        );
        particle.element.setAttribute(
          "y1",
          String(center.y + Math.sin(particle.angle) * begin)
        );
        particle.element.setAttribute("x2", String(center.x + Math.cos(particle.angle) * end));
        particle.element.setAttribute("y2", String(center.y + Math.sin(particle.angle) * end));
        particle.element.setAttribute("opacity", String(Math.max(0, 1 - local)));
      });
      if (progress < 1 && group.parentNode) {
        requestAnimationFrame(frame);
      } else if (group.parentNode) {
        group.parentNode.removeChild(group);
      }
    }
    requestAnimationFrame(frame);
  }

  function flashNode(layerId, event, withSpark) {
    if (layerId === "upstream") {
      if (!topo.upstream || !topo.upstream.group) {
        return;
      }
      topo.upstream.group.classList.add("is-hit");
      text($("topo-upstream-status"), "UPSTREAM ERROR");
      clearTimeout(topo.upstream.timer);
      topo.upstream.timer = setTimeout(function () {
        topo.upstream.group.classList.remove("is-hit");
        if (topo.mode === "log" && topo.selected && layerForEvent(topo.selected) === "upstream") {
          text($("topo-upstream-status"), "UPSTREAM ERROR");
        } else {
          updateUpstreamChrome();
        }
      }, 1500);
    } else {
      var node = topo.nodes[layerId];
      if (!node) {
        return;
      }
      node.group.classList.add("is-hit");
      node.sub.textContent = actionLabel(event);
      clearTimeout(node.timer);
      node.timer = setTimeout(function () {
        node.group.classList.remove("is-hit");
        updateNodeStatus(layerId);
      }, 1500);
    }
    if (withSpark) {
      burstSpark(layerId, sparkColor(layerId), false);
    }
    if (topo.mode === "realtime" && layerId !== "upstream") {
      clearTimeout(topo.forwardTimer);
      clearTimeout(topo.stopTimer);
      hideForwardPath();
      hideStopMarker();
      if (topo.upstream) {
        topo.upstream.group.classList.remove("is-reaching", "is-dimmed");
      }
      if (isStopped(event)) {
        showStopMarker(layerId, layerColor(layerId));
        topo.stopTimer = setTimeout(hideStopMarker, 1500);
      } else if ((layerId === "rules" || layerId === "guards") && isForwarded(event)) {
        showForwardPath(layerId);
        if (topo.upstream) {
          topo.upstream.group.classList.add("is-reaching");
        }
        topo.forwardTimer = setTimeout(function () {
          hideForwardPath();
          if (topo.upstream) {
            topo.upstream.group.classList.remove("is-reaching");
          }
        }, 1400);
      } else if (topo.upstream) {
        topo.upstream.group.classList.add("is-dimmed");
      }
    }
    if (topo.mode === "realtime") {
      updateTopologyMeta();
    }
  }

  function launchPacket(layerId, event) {
    var geometry = topo.geometry[layerId];
    var color = layerColor(layerId);
    var length = topo.routeLength[layerId] || 0;
    if (!geometry || !topo.packets || !length) {
      flashNode(layerId, event, true);
      return;
    }
    var epoch = topo.epoch;
    var group = document.createElementNS(SVG_NS, "g");
    group.setAttribute("class", "topo-packet");
    var glow = document.createElementNS(SVG_NS, "circle");
    var trailOne = document.createElementNS(SVG_NS, "circle");
    var trailTwo = document.createElementNS(SVG_NS, "circle");
    var trailThree = document.createElementNS(SVG_NS, "circle");
    var core = document.createElementNS(SVG_NS, "circle");
    var head = document.createElementNS(SVG_NS, "circle");
    var streak = document.createElementNS(SVG_NS, "line");
    [
      [glow, "9", "0.2"],
      [trailThree, "2.4", "0.1"],
      [trailTwo, "2.8", "0.2"],
      [trailOne, "3.2", "0.36"],
      [core, "3.8", "1"],
    ].forEach(function (item) {
      item[0].setAttribute("cx", "176");
      item[0].setAttribute("cy", "130");
      item[0].setAttribute("r", item[1]);
      item[0].setAttribute("fill", color);
      item[0].setAttribute("opacity", item[2]);
      group.appendChild(item[0]);
    });
    streak.setAttribute("x1", "176");
    streak.setAttribute("y1", "130");
    streak.setAttribute("x2", "176");
    streak.setAttribute("y2", "130");
    streak.setAttribute("stroke", color);
    streak.setAttribute("stroke-width", "2");
    streak.setAttribute("stroke-linecap", "round");
    streak.setAttribute("opacity", "0.42");
    group.appendChild(streak);
    head.setAttribute("cx", "176");
    head.setAttribute("cy", "130");
    head.setAttribute("r", "2.4");
    head.setAttribute("fill", "#ffffff");
    head.setAttribute("opacity", "0.98");
    group.appendChild(head);
    topo.packets.appendChild(group);
    topo.packetCount += 1;
    activateEdges(TOPO_ROUTES[layerId].edges, color, 1400);
    var duration = Math.max(500, Math.min(1040, length * 0.7 + 220));
    var start = null;
    var finished = false;

    function finish() {
      if (finished) {
        return;
      }
      finished = true;
      if (group.parentNode) {
        group.parentNode.removeChild(group);
      }
      topo.packetCount = Math.max(0, topo.packetCount - 1);
    }

    function pointAt(progress) {
      return geometry.getPointAtLength(length * Math.max(0, Math.min(1, progress)));
    }

    function place(element, progress) {
      var point = pointAt(progress);
      element.setAttribute("cx", String(point.x));
      element.setAttribute("cy", String(point.y));
    }

    function frame(time) {
      if (finished) {
        return;
      }
      if (epoch !== topo.epoch || topo.mode !== "realtime" || !group.parentNode) {
        finish();
        return;
      }
      if (start === null) {
        start = time;
      }
      var progress = Math.min(1, (time - start) / duration);
      var eased = 1 - Math.pow(1 - progress, 2);
      var headPoint = pointAt(eased);
      var tailPoint = pointAt(eased - 0.055);
      [core, head, glow].forEach(function (element) {
        element.setAttribute("cx", String(headPoint.x));
        element.setAttribute("cy", String(headPoint.y));
      });
      streak.setAttribute("x1", String(tailPoint.x));
      streak.setAttribute("y1", String(tailPoint.y));
      streak.setAttribute("x2", String(headPoint.x));
      streak.setAttribute("y2", String(headPoint.y));
      place(trailOne, eased - 0.03);
      place(trailTwo, eased - 0.06);
      place(trailThree, eased - 0.09);
      if (progress < 1) {
        requestAnimationFrame(frame);
      } else {
        finish();
        if (epoch === topo.epoch && topo.mode === "realtime") {
          flashNode(layerId, event, true);
        }
      }
    }

    requestAnimationFrame(frame);
  }

  function processFreshEvents(events) {
    if (!events.length) {
      return;
    }
    if (topo.mode === "log") {
      topo.newSinceFocus += events.length;
      updateNewBadge();
      return;
    }
    var byLayer = {};
    var order = [];
    events.forEach(function (event) {
      var layerId = layerForEvent(event);
      if (!layerId) {
        return;
      }
      if (!byLayer[layerId]) {
        byLayer[layerId] = [];
        order.push(layerId);
      }
      byLayer[layerId].push(event);
    });
    var epoch = topo.epoch;
    order.forEach(function (layerId, index) {
      var event = byLayer[layerId][byLayer[layerId].length - 1];
      window.setTimeout(
        function () {
          if (topo.mode !== "realtime" || epoch !== topo.epoch) {
            return;
          }
          pulseInternet();
          if (prefersReducedMotion() || topo.packetCount >= 6) {
            flashNode(layerId, event, true);
          } else {
            launchPacket(layerId, event);
          }
        },
        prefersReducedMotion() ? 0 : index * 70
      );
    });
  }

  function setFocusTheme(color) {
    var bar = $("topo-focus");
    if (!bar) {
      return;
    }
    if (!color) {
      bar.style.removeProperty("--focus-color");
      bar.style.removeProperty("--focus-ink");
      bar.style.removeProperty("--focus-wash");
      bar.style.removeProperty("--focus-border");
      return;
    }
    bar.style.setProperty("--focus-color", color);
    bar.style.setProperty("--focus-ink", focusInkFromColor(color));
    bar.style.setProperty("--focus-wash", rgbaFromHex(color, 0.07));
    bar.style.setProperty("--focus-border", rgbaFromHex(color, 0.33));
  }

  function focusInkFromColor(color) {
    var found = "#596271";
    Object.keys(TOPO_LAYER_INK).forEach(function (layerId) {
      if (layerColor(layerId) === color) {
        found = TOPO_LAYER_INK[layerId];
      }
    });
    return found;
  }

  function rgbaFromHex(color, alpha) {
    var value = String(color || "").replace("#", "");
    if (value.length !== 6) {
      return "rgba(130, 137, 148, " + alpha + ")";
    }
    var red = parseInt(value.slice(0, 2), 16);
    var green = parseInt(value.slice(2, 4), 16);
    var blue = parseInt(value.slice(4, 6), 16);
    return "rgba(" + red + ", " + green + ", " + blue + ", " + alpha + ")";
  }

  function clearFocusEdges() {
    TOPO_EDGES.forEach(function (edge) {
      var element = topo.edges[edge.id];
      if (!element) {
        return;
      }
      element.classList.remove("is-route-focus");
      element.style.removeProperty("--edge-color");
    });
  }

  function setFocusEdges(edgeIds, color) {
    edgeIds.forEach(function (edgeId) {
      var edge = topo.edges[edgeId];
      if (!edge) {
        return;
      }
      edge.style.setProperty("--edge-color", color);
      edge.classList.add("is-route-focus");
    });
  }

  function showStopMarker(layerId, color) {
    if (!topo.stop) {
      return;
    }
    var layer = layerById(layerId);
    if (!layer) {
      return;
    }
    topo.stop.style.setProperty("--layer", color);
    topo.stop.setAttribute(
      "transform",
      "translate(" + (layer.x + layer.width + 11) + " " + (layer.y + layer.height / 2) + ")"
    );
    topo.stop.setAttribute("visibility", "visible");
  }

  function hideStopMarker() {
    if (topo.stop) {
      topo.stop.setAttribute("visibility", "hidden");
    }
  }

  function showForwardPath(layerId) {
    if (!topo.forward) {
      return;
    }
    var layer = layerById(layerId);
    if (!layer) {
      return;
    }
    var x1 = layer.x + layer.width;
    var y1 = layer.y + layer.height / 2;
    var arcY = layer.y < 100 ? 34 : 226;
    var x2 = Math.min(x1 + 90, 810);
    var d =
      "M" +
      x1 +
      " " +
      y1 +
      " C" +
      (x1 + 30) +
      " " +
      y1 +
      " " +
      x2 +
      " " +
      arcY +
      " 840 130";
    topo.forward.setAttribute("d", d);
    topo.forward.classList.add("is-visible");
  }

  function hideForwardPath() {
    if (topo.forward) {
      topo.forward.classList.remove("is-visible");
    }
  }

  function animateFocusBar() {
    var bar = $("topo-focus");
    if (!bar || bar.hidden) {
      return;
    }
    bar.classList.remove("is-entering");
    void bar.offsetWidth;
    bar.classList.add("is-entering");
    clearTimeout(topo.focusTimer);
    topo.focusTimer = setTimeout(function () {
      bar.classList.remove("is-entering");
    }, 400);
  }

  function focusTitle(event, layerId) {
    if (layerId === "upstream" && normalizeToken(event.kind) === "upstreamfailure") {
      return "Upstream error at Upstream Origins";
    }
    if (layerId) {
      return actionWord(event) + " at " + layerName(layerId);
    }
    return humanToken(event.kind) + " event";
  }

  function focusDetail(event, layerId) {
    var parts = [];
    var rule = ruleSummary(event);
    var request = requestSummary(event);
    var client = event.client || event.peer;
    if (rule) {
      parts.push(rule);
    }
    if (request) {
      parts.push(request);
    }
    if (client) {
      parts.push("client " + client + (event.country ? " (" + event.country + ")" : ""));
    }
    if (event.site) {
      parts.push(event.site);
    }
    if (layerId === "upstream") {
      parts.push("upstream did not complete the request");
    } else if (layerId && isStopped(event)) {
      parts.push("stopped before upstream");
    } else if (layerId && isForwarded(event)) {
      parts.push("forwarded to upstream");
    } else if (!layerId) {
      parts.push("no defense layer applies");
    }
    return parts.length ? parts.join(" · ") : "No request metadata was recorded for this event.";
  }

  function clearLiveEffects() {
    TOPO_LAYERS.forEach(function (layer) {
      var node = topo.nodes[layer.id];
      if (!node) {
        return;
      }
      node.group.classList.remove("is-hit");
      clearTimeout(node.timer);
      node.timer = null;
    });
    if (topo.upstream) {
      topo.upstream.group.classList.remove("is-hit", "is-reaching", "is-dimmed");
      clearTimeout(topo.upstream.timer);
      topo.upstream.timer = null;
    }
    TOPO_EDGES.forEach(function (edge) {
      var element = topo.edges[edge.id];
      clearTimeout(topo.edgeTimers[edge.id]);
      delete topo.edgeTimers[edge.id];
      if (element) {
        element.classList.remove("is-route-hit", "is-route-focus");
        element.style.removeProperty("--edge-color");
      }
    });
    if (topo.packets) {
      topo.packets.textContent = "";
    }
    if (topo.sparks) {
      topo.sparks.textContent = "";
    }
    clearTimeout(topo.forwardTimer);
    clearTimeout(topo.stopTimer);
    topo.forwardTimer = null;
    topo.stopTimer = null;
    hideStopMarker();
    hideForwardPath();
    if (topo.internet) {
      topo.internet.group.classList.remove("is-receiving");
      clearTimeout(topo.internetTimer);
      topo.internetTimer = null;
    }
    hideCountryBadge();
    topo.packetCount = 0;
  }

  function renderTopologyFocus() {
    if (!topo.built) {
      return;
    }
    TOPO_LAYERS.forEach(function (layer) {
      var node = topo.nodes[layer.id];
      if (node) {
        node.group.classList.remove("is-focused");
      }
    });
    if (topo.upstream) {
      topo.upstream.group.classList.remove("is-focused", "is-reaching", "is-dimmed", "is-error");
    }
    clearFocusEdges();
    hideStopMarker();
    hideForwardPath();
    var panel = $("topo-panel");
    var bar = $("topo-focus");
    if (!panel || !bar) {
      return;
    }
    if (topo.mode !== "log") {
      bar.hidden = true;
      panel.setAttribute("data-focus", "none");
      TOPO_LAYERS.forEach(function (layer) {
        updateNodeStatus(layer.id);
      });
      updateUpstreamChrome();
      updateInternetChrome();
      updateTopologyMeta();
      updateTopologySummary();
      return;
    }
    bar.hidden = false;
    animateFocusBar();
    var event = topo.selected;
    if (!event) {
      panel.setAttribute("data-focus", "none");
      bar.classList.add("is-empty");
      setFocusTheme(null);
      text($("topo-focus-badge"), "LOG");
      text($("topo-focus-title"), "Select an event");
      text(
        $("topo-focus-detail"),
        "Choose a row in Recent detections and service events to trace the request path and the layer that handled it."
      );
      text($("topo-focus-time"), "");
      $("topo-focus-time").removeAttribute("datetime");
      TOPO_LAYERS.forEach(function (layer) {
        updateNodeStatus(layer.id);
      });
      updateUpstreamChrome();
      updateInternetChrome();
      updateTopologyMeta();
      updateTopologySummary();
      return;
    }

    bar.classList.remove("is-empty");
    var layerId = layerForEvent(event);
    var color = focusColor(event);
    setFocusTheme(color);
    text($("topo-focus-badge"), String(event.disposition || "event").toUpperCase());
    text($("topo-focus-title"), focusTitle(event, layerId));
    text($("topo-focus-detail"), focusDetail(event, layerId));
    text($("topo-focus-time"), utc(event.occurred_at_ms));
    $("topo-focus-time").setAttribute("datetime", new Date(event.occurred_at_ms).toISOString());

    if (layerId === "upstream") {
      panel.setAttribute("data-focus", "layer");
      topo.upstream.group.classList.add("is-focused", "is-error");
      text($("topo-upstream-status"), "UPSTREAM ERROR");
      setFocusEdges(TOPO_ROUTES.upstream.edges, "#c66361");
    } else if (layerId) {
      panel.setAttribute("data-focus", "layer");
      var node = topo.nodes[layerId];
      if (node) {
        node.group.classList.add("is-focused");
        node.sub.textContent = isForwarded(event) ? "DETECTION POINT" : "DEFENSE POINT";
      }
      setFocusEdges(TOPO_ROUTES[layerId].edges, color);
      if (isStopped(event)) {
        showStopMarker(layerId, color);
        if (topo.upstream) {
          topo.upstream.group.classList.add("is-dimmed");
        }
      } else if (isForwarded(event)) {
        showForwardPath(layerId);
        if (topo.upstream) {
          topo.upstream.group.classList.add("is-reaching");
        }
      } else if (topo.upstream) {
        topo.upstream.group.classList.add("is-dimmed");
      }
    } else {
      panel.setAttribute("data-focus", "none");
    }

    TOPO_LAYERS.forEach(function (layer) {
      if (layer.id !== layerId) {
        updateNodeStatus(layer.id);
      }
    });
    updateInternetChrome();
    updateUpstreamChrome();
    updateTopologyMeta();
    updateTopologySummary();
    if (layerId) {
      window.requestAnimationFrame(function () {
        revealFocusedLayer(layerId);
      });
    }
  }

  function updateTopologyScrollHint() {
    var hint = $("topo-scroll-hint");
    var canvas = $("topo-canvas");
    if (!hint || !canvas) {
      return;
    }
    hint.classList.toggle("is-visible", canvas.scrollWidth > canvas.clientWidth + 1);
  }

  function revealLiveStart() {
    var canvas = $("topo-canvas");
    if (!canvas || canvas.scrollWidth <= canvas.clientWidth + 1 || canvas.scrollLeft < 4) {
      return;
    }
    if (canvas.scrollTo) {
      canvas.scrollTo({
        left: 0,
        behavior: prefersReducedMotion() ? "auto" : "smooth",
      });
    } else {
      canvas.scrollLeft = 0;
    }
  }

  function revealFocusedLayer(layerId) {
    if (!layerId) {
      return;
    }
    var canvas = $("topo-canvas");
    var svg = canvas ? canvas.querySelector("svg") : null;
    if (!canvas || !svg || canvas.scrollWidth <= canvas.clientWidth + 1) {
      return;
    }
    var width = svg.getBoundingClientRect().width || canvas.scrollWidth;
    var center = routeCenter(layerId).x;
    var target = (center / 1000) * width;
    var left = Math.max(
      0,
      Math.min(canvas.scrollWidth - canvas.clientWidth, target - canvas.clientWidth / 2)
    );
    if (Math.abs(canvas.scrollLeft - left) > 4) {
      if (canvas.scrollTo) {
        canvas.scrollTo({
          left: left,
          behavior: prefersReducedMotion() ? "auto" : "smooth",
        });
      } else {
        canvas.scrollLeft = left;
      }
    }
  }

  function setTopologyMode(mode, options) {
    options = options || {};
    if (mode !== "realtime" && mode !== "log") {
      return;
    }
    if (topo.mode === mode && !options.force) {
      return;
    }
    topo.epoch += 1;
    clearLiveEffects();
    topo.mode = mode;
    if (mode === "realtime") {
      markCountryBadgeSeen();
    }
    if (mode === "log") {
      if (!topo.selected) {
        var latest = latestRetainedEvent();
        if (latest) {
          topo.selectedKey = eventKey(latest);
          topo.selected = copyEvent(latest);
        }
      }
      topo.newSinceFocus = 0;
    } else {
      topo.newSinceFocus = 0;
      revealLiveStart();
    }
    updateTopologyModeUI();
    updateNewBadge();
    syncSelectedRows();
    renderTopologyFocus();
    updateTopologyMeta();
    var panel = $("topo-panel");
    if (panel) {
      panel.classList.add("is-switching");
      clearTimeout(topo.panelTimer);
      topo.panelTimer = setTimeout(function () {
        panel.classList.remove("is-switching");
      }, 450);
    }
  }

  function selectEvent(event) {
    if (!event) {
      return;
    }
    topo.selectedKey = eventKey(event);
    topo.selected = copyEvent(event);
    topo.newSinceFocus = 0;
    setTopologyMode("log", { force: true });
    syncSelectedRows();
    var layerId = layerForEvent(event);
    if (layerId) {
      window.setTimeout(function () {
        if (topo.mode === "log" && topo.selectedKey === eventKey(event)) {
          burstSpark(layerId, sparkColor(layerId), true);
        }
      }, 90);
    }
    revealTopology();
  }

  function syncSelectedRows() {
    var body = $("live-events");
    if (!body) {
      return;
    }
    var rows = body.querySelectorAll("tr[data-event-key]");
    var color = topo.selected ? focusColor(topo.selected) : "#828994";
    for (var index = 0; index < rows.length; index += 1) {
      var row = rows[index];
      var selected = row.getAttribute("data-event-key") === topo.selectedKey;
      row.classList.toggle("is-selected", selected);
      row.setAttribute("aria-selected", selected ? "true" : "false");
      if (selected) {
        row.style.setProperty("--row-accent", color);
      } else {
        row.style.removeProperty("--row-accent");
      }
    }
  }

  function revealTopology() {
    var panel = $("topo-panel");
    if (!panel) {
      return;
    }
    var rect = panel.getBoundingClientRect();
    if (rect.top < 0 || rect.bottom > window.innerHeight - 48) {
      panel.scrollIntoView({
        behavior: prefersReducedMotion() ? "auto" : "smooth",
        block: "nearest",
      });
    }
    panel.classList.remove("is-revealed");
    void panel.offsetWidth;
    panel.classList.add("is-revealed");
    clearTimeout(topo.revealTimer);
    topo.revealTimer = setTimeout(function () {
      panel.classList.remove("is-revealed");
    }, 1200);
  }

  function resetTopology() {
    topo.epoch += 1;
    clearLiveEffects();
    topo.mode = "realtime";
    topo.selectedKey = null;
    topo.selected = null;
    topo.lastSequence = null;
    topo.newSinceFocus = 0;
    topo.counts = {};
    markCountryBadgeSeen();
    updateTopologyModeUI();
    updateNewBadge();
    revealLiveStart();
    syncSelectedRows();
    renderTopologyFocus();
    updateTopologyMeta();
  }

  function text(node, value) {
    if (node) {
      node.textContent = value;
    }
  }

  function banner(message, level) {
    var node = $("banner");
    if (!message) {
      node.hidden = true;
      node.textContent = "";
      return;
    }
    node.hidden = false;
    node.textContent = message;
    node.className = "banner" + (level === "bad" ? " level-bad" : "");
  }

  function plural(count, singular, many) {
    return count + " " + (count === 1 ? singular : many);
  }

  function metricValue(id, value) {
    text($(id), value);
    $(id).classList.toggle("is-unavailable", value === "Unavailable");
  }

  function setConnection(connected) {
    state.connected = connected;
    var dot = $("collection-dot");
    var label = $("collection-text");
    var snapshot = state.latest;
    var collection = snapshot ? snapshot.collection : null;
    if (!connected) {
      dot.className = "dot dot-bad";
      label.textContent = "Live stream disconnected";
    } else if (!collection) {
      dot.className = "dot dot-unknown";
      label.textContent = "Waiting for collection";
    } else if (!collection.connected) {
      dot.className = "dot dot-bad";
      label.textContent = "WAF snapshot source unavailable";
    } else if (collection.storage_error) {
      dot.className = "dot dot-warn";
      label.textContent = "Collecting; storage error";
    } else {
      dot.className = "dot dot-ok";
      label.textContent = "Collecting";
    }
    if (topo.built) {
      updateTopologyMeta();
    }
  }

  function updateHeader() {
    var latest = state.latest;
    if (!latest) {
      return;
    }
    var snapshot = latest.snapshot;
    var chip = $("source-generation");
    if (snapshot && snapshot.source) {
      chip.textContent = "generation " + snapshot.source.generation.slice(0, 8);
    }
    if (snapshot) {
      text($("last-update"), "updated " + utc(snapshot.observed_at_ms));
    }
    if (state.session.enabled) {
      $("sign-out").hidden = false;
    }
  }

  function counter(snapshot, name) {
    if (!snapshot || !snapshot.counters) {
      return null;
    }
    var value = snapshot.counters[name];
    return value === undefined ? null : value;
  }

  function updateRates(snapshot) {
    if (!snapshot) {
      return { requestsPerSecond: null, rejectedPerSecond: null };
    }
    var at = snapshot.observed_at_ms;
    var requests = counter(snapshot, "requests");
    var rejected = counter(snapshot, "rejected_requests");
    var previous = state.previous;
    var rates = { requestsPerSecond: null, rejectedPerSecond: null };
    if (
      previous &&
      previous.generation === snapshot.source.generation &&
      at > previous.at &&
      at - previous.at <= 10000 &&
      requests !== null &&
      previous.requests !== null
    ) {
      var seconds = (at - previous.at) / 1000;
      rates.requestsPerSecond = Math.max(0, (requests - previous.requests) / seconds);
      if (rejected !== null && previous.rejected !== null) {
        rates.rejectedPerSecond = Math.max(0, (rejected - previous.rejected) / seconds);
      }
    }
    state.previous = {
      at: at,
      generation: snapshot.source.generation,
      requests: requests,
      rejected: rejected,
    };
    return rates;
  }

  function rejectClassEntries(snapshot) {
    var classes = counter(snapshot, "rejection_classes");
    if (classes === null || typeof classes !== "object") {
      return null;
    }
    var entries = [];
    Object.keys(classes).forEach(function (key) {
      var count = Number(classes[key]);
      if (isFinite(count) && count > 0) {
        entries.push({ key: key, count: count });
      }
    });
    return entries;
  }

  function renderRejectDetail(snapshot) {
    var host = $("live-reject-cards");
    var note = $("live-reject-detail-note");
    if (!host) {
      return;
    }
    host.innerHTML = "";
    function message(value) {
      var empty = document.createElement("p");
      empty.className = "reject-detail-empty";
      empty.textContent = value;
      host.appendChild(empty);
    }
    if (!snapshot) {
      text(note, "Waiting for the first snapshot.");
      message("Waiting for the first snapshot.");
      return;
    }
    var rejected = counter(snapshot, "rejected_requests");
    var entries = rejectClassEntries(snapshot);
    if (entries === null) {
      text(note, "Detailed causes are unavailable from this source.");
      message("Detailed causes are unavailable; this source did not report them.");
      return;
    }
    if (!entries.length && (rejected === null || rejected === 0)) {
      text(note, "No rejections recorded since this source started.");
      message("No rejections recorded since this source started.");
      return;
    }
    var measured = 0;
    entries.forEach(function (entry) {
      measured += entry.count;
    });
    if (rejected !== null && rejected > measured) {
      entries.push({ key: "unrecorded", count: rejected - measured, unrecorded: true });
    }
    entries.sort(function (a, b) {
      if (Boolean(a.unrecorded) !== Boolean(b.unrecorded)) {
        return a.unrecorded ? 1 : -1;
      }
      return b.count - a.count || a.key.localeCompare(b.key);
    });
    if (!entries.length) {
      text(note, "No detailed rejection classes recorded in this snapshot.");
      message("No detailed rejection classes recorded in this snapshot.");
      return;
    }
    var denominator = rejected === null ? measured : rejected;
    text(
      note,
      "Counted once per rejected request; shares use all " +
        number(denominator) +
        " rejections."
    );
    entries.forEach(function (entry) {
      var card = document.createElement("div");
      card.className = "reject-detail-card" + (entry.unrecorded ? " is-unrecorded" : "");
      var count = document.createElement("strong");
      count.textContent = number(entry.count);
      var label = document.createElement("span");
      label.textContent = entry.unrecorded ? "Unrecorded cause" : rejectClassLabel(entry.key);
      var share = document.createElement("small");
      share.textContent = denominator
        ? ((100 * entry.count) / denominator).toFixed(1) + "% of rejections"
        : "share unavailable";
      card.appendChild(count);
      card.appendChild(label);
      card.appendChild(share);
      host.appendChild(card);
    });
  }

  function renderLive() {
    var latest = state.latest;
    var snapshot = latest ? latest.snapshot : null;
    var rates = updateRates(snapshot);

    if (!snapshot) {
      ["live-requests", "live-rejected", "live-logged", "live-connections", "live-upstream", "live-decoy"].forEach(function (id) {
        text($(id), "Unavailable");
      });
      text($("live-rate"), "waiting for the first snapshot");
      text($("live-rejected-rate"), "waiting for the first snapshot");
    } else {
      var requests = counter(snapshot, "requests");
      var rejected = counter(snapshot, "rejected_requests");
      var logged = counter(snapshot, "log_requests");
      var failures = counter(snapshot, "upstream_connection_failures");
      var timeouts = counter(snapshot, "upstream_timeouts");
      var decoy = counter(snapshot, "decoy_credential_use_requests");
      metricValue("live-requests", number(requests));
      metricValue("live-rejected", number(rejected));
      metricValue("live-logged", number(logged));
      metricValue("live-connections", number(snapshot.active_connections));
      metricValue("live-upstream", number(failures === null && timeouts === null ? null : (failures || 0) + (timeouts || 0)));
      metricValue("live-decoy", number(decoy));
      text(
        $("live-rate"),
        rates.requestsPerSecond === null
          ? "rate needs a previous sample"
          : rates.requestsPerSecond.toFixed(1) + " req/s over the last sample"
      );
      text(
        $("live-rejected-rate"),
        rates.rejectedPerSecond === null
          ? "rate unavailable"
          : rates.rejectedPerSecond.toFixed(1) + " rejections/s over the last sample"
      );
      text(
        $("live-upstream-detail"),
        "failures " + number(failures) + ", timeouts " + number(timeouts)
      );
      if (snapshot.clock_discontinuity) {
        banner("The WAF reported a clock discontinuity; minute attribution in that interval is incomplete.", "warn");
      }
    }

    renderRejectDetail(snapshot);

    var collection = latest ? latest.collection : null;
    var writer = latest ? latest.writer : null;
    var health = $("live-health");
    health.innerHTML = "";
    function row(name, value, level) {
      var item = document.createElement("div");
      item.className = "health-item";
      var dt = document.createElement("dt");
      dt.textContent = name;
      var dd = document.createElement("dd");
      dd.textContent = value;
      if (level) {
        dd.className = level;
      }
      item.appendChild(dt);
      item.appendChild(dd);
      health.appendChild(item);
    }
    if (!collection) {
      row("state", "waiting for the first snapshot");
    } else {
      row("source", collection.connected ? "connected" : "disconnected", collection.connected ? "level-ok" : "level-bad");
      row("last observed", utc(collection.last_observed_at_ms));
      row("last committed", utc(collection.last_committed_at_ms));
      row("persistence lag", collection.persistence_lag_ms === null ? "unknown" : collection.persistence_lag_ms + " ms");
      row("pending minutes", number(collection.pending_minutes));
      row("pending events", number(collection.pending_events));
      row("omitted events", number(collection.omitted_events));
      row("omitted minutes", number(collection.omitted_metric_minutes));
      row("missed minute updates", number(collection.source_missed_updates));
      if (collection.source_gap) {
        row("source gap", utc(collection.source_gap[0]) + " to " + utc(collection.source_gap[1]), "level-warn");
      }
      if (collection.source_error) {
        row("source error", collection.source_error, "level-bad");
      }
      if (collection.batch_error) {
        row("batch error", collection.batch_error, "level-warn");
      }
      if (collection.checkpoint_error) {
        row("checkpoint error", collection.checkpoint_error, "level-warn");
      }
      if (collection.storage_error) {
        row("storage error", collection.storage_error, "level-bad");
      }
      if (writer) {
        row("writer", writer.state + " (" + number(writer.queued_items) + " queued)");
        row("committed batches", number(writer.committed_batches));
        row("failed batches", number(writer.failed_batches), writer.failed_batches ? "level-bad" : null);
      }
    }
    renderEvents();
    updateTopology();
  }

  function renderEvents() {
    var body = $("live-events");
    body.innerHTML = "";
    var events = Array.from(state.events.values()).sort(function (a, b) {
      return b.sequence - a.sequence;
    });
    if (events.length === 0) {
      var empty = document.createElement("tr");
      var cell = document.createElement("td");
      cell.colSpan = 10;
      cell.className = "muted";
      cell.textContent = "No events received yet.";
      empty.appendChild(cell);
      body.appendChild(empty);
      syncSelectedRows();
      return;
    }
    events.slice(0, 200).forEach(function (event) {
      var row = document.createElement("tr");
      var key = eventKey(event);
      row.className = ageClass(event.occurred_at_ms);
      row.setAttribute("data-occurred-at", String(event.occurred_at_ms));
      row.setAttribute("data-event-key", key);
      row.setAttribute("aria-selected", topo.selectedKey === key ? "true" : "false");
      row.tabIndex = 0;
      row.title = "Trace this event in the edge topology";
      if (topo.selectedKey === key) {
        row.classList.add("is-selected");
        row.style.setProperty("--row-accent", focusColor(event));
      }
      function add(value, className) {
        var cell = document.createElement("td");
        cell.textContent = value === null || value === undefined || value === "" ? "unrecorded" : String(value);
        if (className) {
          cell.className = className;
        }
        row.appendChild(cell);
      }
      function addSource(address, role) {
        if (!address) {
          add(null);
          return;
        }
        var cell = document.createElement("td");
        var button = document.createElement("button");
        button.type = "button";
        button.className = "source-link";
        button.textContent = String(address);
        button.title = "Open source details";
        button.setAttribute("data-source-ip", String(address));
        button.setAttribute("data-source-role", role);
        button.setAttribute("aria-haspopup", "dialog");
        button.setAttribute("aria-controls", "source-drawer");
        button.setAttribute(
          "aria-expanded",
          state.sourceDetail.open &&
            state.sourceDetail.ip === String(address) &&
            state.sourceDetail.role === role
            ? "true"
            : "false"
        );
        button.addEventListener("click", function (clickEvent) {
          clickEvent.stopPropagation();
          openSourceDetail(role, String(address), key);
        });
        button.addEventListener("keydown", function (keyboardEvent) {
          if (
            keyboardEvent.key === "Enter" ||
            keyboardEvent.key === " " ||
            keyboardEvent.key === "Spacebar"
          ) {
            keyboardEvent.stopPropagation();
          }
        });
        cell.appendChild(button);
        row.appendChild(cell);
      }
      add(utc(event.occurred_at_ms));
      add(String(event.kind).replace(/_/g, " "));
      add(String(event.disposition).toUpperCase());
      add(event.attack_class ? rejectClassLabel(event.attack_class) : null);
      var matched = event.category ? event.category + (event.rule ? "/" + event.rule : "") : event.rule || null;
      add(event.reason && matched ? event.reason + " · " + matched : event.reason || matched);
      add(event.method);
      add(event.path);
      add(event.site);
      addSource(event.client, event.client ? "client" : "peer");
      add(event.country);
      row.addEventListener("click", function () {
        selectEvent(event);
      });
      row.addEventListener("keydown", function (keyboardEvent) {
        if (keyboardEvent.key === "Enter" || keyboardEvent.key === " " || keyboardEvent.key === "Spacebar") {
          keyboardEvent.preventDefault();
          selectEvent(event);
        }
      });
      body.appendChild(row);
    });
    syncSelectedRows();
    syncSourceLinks();
  }

  function sourceEvents(role, ip) {
    var events = [];
    state.events.forEach(function (event) {
      if (role === "client" ? event.client === ip : !event.client && event.peer === ip) {
        events.push(event);
      }
    });
    events.sort(function (a, b) {
      return b.occurred_at_ms - a.occurred_at_ms;
    });
    return events;
  }

  function sourceNode(tag, className, value) {
    var node = document.createElement(tag);
    if (className) {
      node.className = className;
    }
    if (value !== undefined && value !== null && value !== "") {
      node.textContent = String(value);
    }
    return node;
  }

  function sourceSection(title) {
    var section = sourceNode("section", "source-section");
    section.appendChild(sourceNode("h3", null, title));
    return section;
  }

  function sourceRow(list, term, value, mono) {
    list.appendChild(sourceNode("dt", null, term));
    var display = value === null || value === undefined || value === "" ? "unrecorded" : value;
    list.appendChild(sourceNode("dd", mono ? "source-mono" : null, display));
  }

  function sourceDatabaseLine(info) {
    var parts = [];
    if (info.database) {
      parts.push(info.database);
    }
    if (info.built_at_ms) {
      parts.push(utcDate(info.built_at_ms));
    }
    if (info.source) {
      parts.push(info.source);
    }
    return parts.join(" · ");
  }

  function renderSourceAsn(container, info) {
    if (info.state === "not_global") {
      container.appendChild(
        sourceNode(
          "p",
          "source-state",
          "Private, loopback, or reserved address. ASN lookup is not applicable."
        )
      );
      return;
    }
    if (info.state === "unavailable") {
      container.appendChild(
        sourceNode("p", "source-state", "The ASN database is unavailable.")
      );
      return;
    }
    var databaseLine = sourceDatabaseLine(info);
    if (info.state === "no_data") {
      container.appendChild(
        sourceNode(
          "p",
          "source-state",
          "No ASN record in " + (info.database || "the ASN database") + " for this address."
        )
      );
      if (databaseLine) {
        container.appendChild(sourceNode("p", "source-source", databaseLine));
      }
      return;
    }
    if (info.state !== "ok" || info.asn === null || info.asn === undefined) {
      container.appendChild(sourceNode("p", "source-state", "ASN lookup unavailable."));
      return;
    }
    var row = sourceNode("div", "source-asn");
    row.appendChild(sourceNode("span", "source-asn-number", "AS" + info.asn));
    if (info.organization) {
      row.appendChild(sourceNode("span", "source-asn-org", info.organization));
    }
    container.appendChild(row);
    if (databaseLine) {
      container.appendChild(sourceNode("p", "source-source", "Source: " + databaseLine));
    }
    if (info.stale) {
      container.appendChild(
        sourceNode(
          "p",
          "source-alert",
          "This ASN database is more than 45 days old; the recorded operator may have changed."
        )
      );
    }
  }

  function sourceDate(value) {
    if (!value) {
      return null;
    }
    var parsed = Date.parse(value);
    return isNaN(parsed) ? String(value) : new Date(parsed).toISOString().slice(0, 10);
  }

  function sourceContactLabel(contact) {
    if (!contact) {
      return null;
    }
    return contact.organization || contact.name || contact.email || null;
  }

  function sourceRegistrySection() {
    var detail = state.sourceDetail;
    var section = sourceSection("Registry record (RDAP)");
    if (detail.rdapLoading) {
      section.appendChild(sourceNode("p", "source-state", "Looking up the registry…"));
      return section;
    }
    if (detail.rdapError) {
      section.appendChild(
        sourceNode("p", "source-alert", "Registry lookup unavailable: " + detail.rdapError)
      );
      return section;
    }
    var data = detail.rdap;
    if (!data) {
      section.appendChild(sourceNode("p", "source-state", "Registry lookup has not completed."));
      return section;
    }
    if (data.state === "disabled") {
      section.appendChild(
        sourceNode(
          "p",
          "source-state",
          "RDAP lookup is disabled. Enable console.ip_info.rdap.enabled to show the registry owner and abuse contact."
        )
      );
      return section;
    }
    if (data.state === "not_global") {
      section.appendChild(
        sourceNode("p", "source-state", "Not applicable to private or reserved addresses.")
      );
      return section;
    }
    if (data.state === "no_bootstrap") {
      section.appendChild(
        sourceNode("p", "source-state", "No RDAP service is mapped for this address.")
      );
      return section;
    }
    if (data.state === "not_found") {
      section.appendChild(
        sourceNode("p", "source-state", "No registry record was found for this address.")
      );
      return section;
    }
    if (data.state === "rate_limited") {
      var retry = data.retry_after_ms ? Math.ceil(data.retry_after_ms / 1000) + "s" : "later";
      section.appendChild(
        sourceNode("p", "source-alert", "Registry lookup is rate limited; retry after " + retry + ".")
      );
      return section;
    }
    if (data.state === "timeout") {
      section.appendChild(sourceNode("p", "source-alert", "Registry lookup timed out."));
      return section;
    }
    if (data.state === "invalid") {
      section.appendChild(
        sourceNode("p", "source-alert", "The registry returned an unreadable record.")
      );
      return section;
    }
    if (data.state === "unavailable") {
      section.appendChild(
        sourceNode("p", "source-alert", "Registry lookup is unavailable.")
      );
      return section;
    }
    var record = data.record;
    if (data.state !== "ok" || !record) {
      section.appendChild(sourceNode("p", "source-state", "Registry lookup is unavailable."));
      return section;
    }
    var registrants = (record.registrant || []).map(sourceContactLabel).filter(Boolean);
    var abuseEmails = (record.abuse || []).map(function (contact) {
      return contact.email;
    }).filter(Boolean);
    if (!abuseEmails.length) {
      abuseEmails = (record.abuse || []).map(sourceContactLabel).filter(Boolean);
    }
    var network = [record.name, record.handle].filter(Boolean).join(" · ");
    var range = record.cidrs && record.cidrs.length
      ? record.cidrs.join(", ")
      : [record.start_address, record.end_address].filter(Boolean).join(" – ");
    var list = sourceNode("dl", "source-kv");
    sourceRow(
      list,
      "Registrant",
      registrants.length ? registrants.slice(0, 2).join(" · ") : "Not published or redacted"
    );
    sourceRow(
      list,
      "Abuse contact",
      abuseEmails.length ? abuseEmails.slice(0, 2).join(" · ") : "Not published"
    );
    sourceRow(list, "Registry", data.registry);
    sourceRow(list, "Network", network);
    sourceRow(list, "Range", range);
    sourceRow(list, "Network type", record.network_type);
    sourceRow(list, "Registration country", record.country);
    sourceRow(list, "Registered", sourceDate(record.registered_at));
    sourceRow(list, "Last changed", sourceDate(record.last_changed_at));
    if (record.status && record.status.length) {
      sourceRow(list, "Status", record.status.join(", "));
    }
    section.appendChild(list);
    var sourceLine = "RDAP " + (data.registry || "registry");
    if (data.cached && data.fetched_at_ms) {
      var cacheAge = now() - data.fetched_at_ms;
      sourceLine += " · cached " + (cacheAge >= 60000 ? formatDurationMs(cacheAge) : "just now");
    } else {
      sourceLine += " · fetched now";
    }
    section.appendChild(sourceNode("p", "source-source", sourceLine));
    if (record.remarks && record.remarks.length) {
      record.remarks.forEach(function (remark) {
        section.appendChild(sourceNode("p", "source-note", remark));
      });
    }
    if (record.record_url && /^https:\/\//i.test(record.record_url)) {
      var link = sourceNode("a", "source-record-link", "Open registry record");
      link.href = record.record_url;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      section.appendChild(link);
    }
    if (record.redacted) {
      section.appendChild(
        sourceNode("p", "source-note", "Some registrant fields are redacted by the registry.")
      );
    }
    section.appendChild(
      sourceNode(
        "p",
        "source-note",
        "The registrant is often an ISP, hosting provider, VPN, or reseller and may be a victim or stepping stone; it is not proof of the attacker."
      )
    );
    return section;
  }

  function renderSourceDetail() {
    var detail = state.sourceDetail;
    if (!detail.open || !detail.ip) {
      return;
    }
    var body = $("source-drawer-body");
    emptyNode(body);
    var events = detail.events || [];
    var latest = events.length ? events[0] : null;
    var earliest = events.length ? events[events.length - 1] : null;
    var countryCode = null;
    for (var countryIndex = 0; countryIndex < events.length; countryIndex += 1) {
      if (events[countryIndex].country) {
        countryCode = String(events[countryIndex].country);
        break;
      }
    }
    var country = countryName(countryCode);

    text($("source-drawer-title"), detail.ip);
    var meta = [detail.role === "peer" ? "Transport peer" : "Resolved client"];
    if (country) {
      meta.push(country + " (" + countryCode + ")");
    }
    if (detail.openedAt) {
      meta.push("as of " + utc(detail.openedAt));
    }
    text($("source-drawer-meta"), meta.join(" · "));

    var network = sourceSection("Network operator (BGP)");
    if (detail.loading) {
      network.appendChild(sourceNode("p", "source-state", "Looking up the ASN database…"));
    } else if (detail.error) {
      network.appendChild(
        sourceNode("p", "source-alert", "ASN lookup unavailable: " + detail.error)
      );
    } else if (detail.info) {
      renderSourceAsn(network, detail.info);
    } else {
      network.appendChild(sourceNode("p", "source-state", "ASN lookup has not completed."));
    }
    network.appendChild(
      sourceNode(
        "p",
        "source-note",
        "BGP operator recorded by DB-IP; not the IP holder, end user, or attacker. It may be an upstream, anycast network, or reseller, and organization names can lag."
      )
    );
    if (detail.role === "peer") {
      network.appendChild(
        sourceNode(
          "p",
          "source-note",
          "This is the transport peer. The WAF did not record a resolved client address for these events."
        )
      );
    }
    body.appendChild(network);
    body.appendChild(sourceRegistrySection());

    var activity = sourceSection("Recorded activity");
    var list = sourceNode("dl", "source-kv");
    sourceRow(list, "Address", detail.ip, true);
    sourceRow(
      list,
      "Role",
      detail.role === "peer" ? "Transport peer" : "Resolved client"
    );
    if (detail.role === "client" && detail.peer && detail.peer !== detail.ip) {
      sourceRow(list, "Transport peer", detail.peer, true);
    }
    sourceRow(list, "Country", country ? country + " (" + countryCode + ")" : null);
    sourceRow(list, "First recorded", earliest ? utc(earliest.occurred_at_ms) : null);
    sourceRow(list, "Last recorded", latest ? utc(latest.occurred_at_ms) : null);
    sourceRow(list, "Recorded events", events.length ? number(events.length) : null);
    activity.appendChild(list);
    if (events.length) {
      var counts = {};
      events.forEach(function (event) {
        var key = String(event.disposition || "unknown").toUpperCase();
        counts[key] = (counts[key] || 0) + 1;
      });
      var dispositions = sourceNode("div", "source-dispositions");
      Object.keys(counts)
        .sort()
        .forEach(function (key) {
          dispositions.appendChild(
            sourceNode("span", "source-chip", key + " " + number(counts[key]))
          );
        });
      activity.appendChild(dispositions);
    } else {
      activity.appendChild(
        sourceNode("p", "source-note", "No retained events for this address.")
      );
    }
    body.appendChild(activity);

    var recent = sourceSection("Recent recorded events");
    if (!events.length) {
      recent.appendChild(
        sourceNode("p", "source-state", "No retained events for this address.")
      );
    } else {
      var eventList = sourceNode("ul", "source-events");
      events.slice(0, 8).forEach(function (event) {
        var item = sourceNode("li", "source-event");
        var head = sourceNode("div", "source-event-head");
        head.appendChild(sourceNode("span", "source-event-time", utcClock(event.occurred_at_ms)));
        head.appendChild(
          sourceNode(
            "span",
            "source-event-kind",
            String(event.kind || "service").replace(/_/g, " ")
          )
        );
        head.appendChild(
          sourceNode(
            "span",
            "source-chip",
            String(event.disposition || "unknown").toUpperCase()
          )
        );
        item.appendChild(head);
        var details = [];
        if (event.attack_class) {
          details.push(rejectClassLabel(event.attack_class));
        }
        if (event.category) {
          details.push(event.category + (event.rule ? "/" + event.rule : ""));
        } else if (event.rule) {
          details.push(event.rule);
        }
        if (event.reason) {
          details.push(event.reason);
        }
        if (event.method || event.path) {
          details.push([event.method, event.path].filter(Boolean).join(" "));
        }
        if (event.site) {
          details.push(event.site);
        }
        if (event.status !== null && event.status !== undefined) {
          details.push("status " + event.status);
        }
        if (details.length) {
          item.appendChild(sourceNode("div", "source-event-detail", details.join(" · ")));
        }
        eventList.appendChild(item);
      });
      recent.appendChild(eventList);
      if (events.length > 8) {
        recent.appendChild(
          sourceNode(
            "p",
            "source-note",
            "Showing the 8 most recent of " + number(events.length) + " retained events."
          )
        );
      }
    }
    body.appendChild(recent);

    body.appendChild(
      sourceNode(
        "p",
        "source-drawer-footer",
        "Recorded events are selected samples from the live snapshot, not a complete request log. Counts describe retained records only."
      )
    );
  }

  function syncSourceLinks() {
    var detail = state.sourceDetail;
    var buttons = document.querySelectorAll(".source-link");
    for (var index = 0; index < buttons.length; index += 1) {
      var button = buttons[index];
      var expanded =
        detail.open &&
        button.getAttribute("data-source-ip") === detail.ip &&
        button.getAttribute("data-source-role") === detail.role;
      button.setAttribute("aria-expanded", expanded ? "true" : "false");
    }
  }

  function loadSourceInfo(ip, request) {
    fetch("/api/v1/ip-info?ip=" + encodeURIComponent(ip), {
      credentials: "same-origin",
    })
      .then(function (response) {
        if (response.status === 401) {
          throw new Error("unauthorized");
        }
        if (!response.ok) {
          throw new Error("HTTP " + response.status);
        }
        return response.json();
      })
      .then(function (data) {
        var detail = state.sourceDetail;
        if (!detail.open || request !== detail.request) {
          return;
        }
        detail.info = data;
        detail.loading = false;
        detail.error = null;
        renderSourceDetail();
      })
      .catch(function (error) {
        var detail = state.sourceDetail;
        if (!detail.open || request !== detail.request) {
          return;
        }
        if (error.message === "unauthorized") {
          window.location.replace("/login");
          return;
        }
        detail.loading = false;
        detail.error = error.message;
        renderSourceDetail();
      });
  }

  function loadSourceRdap(ip, request) {
    fetch("/api/v1/rdap?ip=" + encodeURIComponent(ip), {
      credentials: "same-origin",
    })
      .then(function (response) {
        if (response.status === 401) {
          throw new Error("unauthorized");
        }
        if (!response.ok) {
          throw new Error("HTTP " + response.status);
        }
        return response.json();
      })
      .then(function (data) {
        var detail = state.sourceDetail;
        if (!detail.open || request !== detail.request) {
          return;
        }
        detail.rdap = data;
        detail.rdapLoading = false;
        detail.rdapError = null;
        renderSourceDetail();
      })
      .catch(function (error) {
        var detail = state.sourceDetail;
        if (!detail.open || request !== detail.request) {
          return;
        }
        if (error.message === "unauthorized") {
          window.location.replace("/login");
          return;
        }
        detail.rdapLoading = false;
        detail.rdapError = error.message;
        renderSourceDetail();
      });
  }

  function openSourceDetail(role, ip, eventKey) {
    var detail = state.sourceDetail;
    detail.returnFocus = document.activeElement;
    var wasOpen = detail.open;
    detail.open = true;
    detail.ip = ip;
    detail.role = role;
    detail.eventKey = eventKey || null;
    var anchorEvent = eventKey ? state.events.get(eventKey) : null;
    detail.peer = anchorEvent && anchorEvent.peer ? String(anchorEvent.peer) : null;
    detail.openedAt = now();
    detail.events = sourceEvents(role, ip);
    detail.info = null;
    detail.error = null;
    detail.loading = true;
    detail.rdap = null;
    detail.rdapError = null;
    detail.rdapLoading = true;
    detail.request += 1;
    var request = detail.request;
    $("source-drawer").hidden = false;
    renderSourceDetail();
    syncSourceLinks();
    if (!wasOpen) {
      $("source-drawer-close").focus();
    }
    loadSourceInfo(ip, request);
    loadSourceRdap(ip, request);
  }

  function refreshSourceDetail() {
    var detail = state.sourceDetail;
    if (!detail.open || !detail.ip) {
      return;
    }
    detail.openedAt = now();
    detail.events = sourceEvents(detail.role, detail.ip);
    detail.info = null;
    detail.error = null;
    detail.loading = true;
    detail.rdap = null;
    detail.rdapError = null;
    detail.rdapLoading = true;
    detail.request += 1;
    var request = detail.request;
    renderSourceDetail();
    loadSourceInfo(detail.ip, request);
    loadSourceRdap(detail.ip, request);
  }

  function closeSourceDetail(suppressFocus) {
    var detail = state.sourceDetail;
    if (!detail.open) {
      return;
    }
    var returnFocus = detail.returnFocus;
    var previousIp = detail.ip;
    var previousRole = detail.role;
    detail.open = false;
    detail.request += 1;
    detail.ip = null;
    detail.role = "client";
    detail.eventKey = null;
    detail.peer = null;
    detail.openedAt = null;
    detail.events = [];
    detail.info = null;
    detail.loading = false;
    detail.error = null;
    detail.rdap = null;
    detail.rdapLoading = false;
    detail.rdapError = null;
    detail.returnFocus = null;
    $("source-drawer").hidden = true;
    syncSourceLinks();
    if (suppressFocus) {
      return;
    }
    if (returnFocus && returnFocus.isConnected) {
      returnFocus.focus();
      return;
    }
    var buttons = document.querySelectorAll(".source-link");
    for (var index = 0; index < buttons.length; index += 1) {
      var button = buttons[index];
      if (
        button.getAttribute("data-source-ip") === previousIp &&
        button.getAttribute("data-source-role") === previousRole
      ) {
        button.focus();
        return;
      }
    }
    var main = $("main");
    if (main) {
      main.focus({ preventScroll: true });
    }
  }

  function applyState(data) {
    var snapshot = data.snapshot;
    state.latest = data;
    if (snapshot && typeof snapshot.observed_at_ms === "number") {
      state.clockOffsetMs = snapshot.observed_at_ms - Date.now();
    }
    var fresh = [];
    if (snapshot && snapshot.source) {
      var generation = snapshot.source.generation;
      var generationChanged = state.generation !== generation;
      if (generationChanged) {
        state.generation = generation;
        state.events.clear();
        state.previous = null;
        resetTopology();
        closeSourceDetail();
      }
      var incoming = snapshot.events || [];
      var maximumSequence = topo.lastSequence || 0;
      incoming.forEach(function (event) {
        var key = generation + ":" + event.sequence;
        if (!state.events.has(key)) {
          state.events.set(key, event);
          if (
            !generationChanged &&
            topo.lastSequence !== null &&
            event.sequence > topo.lastSequence &&
            (typeof snapshot.observed_at_ms !== "number" ||
              snapshot.observed_at_ms - event.occurred_at_ms <= 15000)
          ) {
            fresh.push(event);
          }
        }
        if (event.sequence > maximumSequence) {
          maximumSequence = event.sequence;
        }
      });
      if (topo.lastSequence === null) {
        fresh = [];
      }
      topo.lastSequence = maximumSequence;
      while (state.events.size > 200) {
        var oldest = state.events.keys().next();
        state.events.delete(oldest.value);
      }
    }
    updateHeader();
    setConnection(state.connected);
    if (state.view === "live") {
      renderLive();
      if (fresh.length) {
        processFreshEvents(fresh);
      }
    }
  }

  function connectLive() {
    if (!window.EventSource) {
      banner("This browser does not support EventSource; reload the page for a new snapshot.", "warn");
      return;
    }
    var source = new EventSource("/api/v1/live");
    state.source = source;
    source.addEventListener("state", function (message) {
      try {
        applyState(JSON.parse(message.data));
      } catch (error) {
        banner("Received an unreadable live state.", "bad");
      }
    });
    source.addEventListener("pending", function (message) {
      try {
        var data = JSON.parse(message.data);
        state.latest = { snapshot: null, collection: data.collection, writer: data.writer };
        setConnection(true);
        renderLive();
      } catch (error) {
        banner("Received an unreadable collection state.", "bad");
      }
    });
    source.onopen = function () {
      state.connected = true;
      setConnection(true);
    };
    source.onerror = function () {
      state.connected = false;
      setConnection(false);
    };
  }

  function sumMetric(buckets, metric) {
    var total = 0;
    var known = false;
    var incomplete = false;
    buckets.forEach(function (bucket) {
      var stats = bucket.counters ? bucket.counters[metric] : null;
      if (!stats || !stats.known_minutes) {
        return;
      }
      total += stats.sum;
      known = true;
      if (bucket.coverage && bucket.coverage.incomplete) {
        incomplete = true;
      }
    });
    return { total: known ? total : null, incomplete: incomplete };
  }

  function renderMetrics() {
    var data = state.metrics;
    if (!data) {
      return;
    }
    var buckets = data.buckets || [];
    var displayWidth = displayGrainMs(data.range_ms || state.rangeMs, buckets);
    var requests = sumMetric(buckets, "requests");
    var rejected = sumMetric(buckets, "rejected_requests");
    var logged = sumMetric(buckets, "log_requests");
    var failures = sumMetric(buckets, "upstream_connection_failures");
    var timeouts = sumMetric(buckets, "upstream_timeouts");
    var decoy = sumMetric(buckets, "decoy_credential_use_requests");

    metricValue("metrics-requests", number(requests.total));
    metricValue("metrics-rejected", number(rejected.total));
    metricValue("metrics-logged", number(logged.total));
    metricValue("metrics-upstream", number(failures.total === null && timeouts.total === null ? null : (failures.total || 0) + (timeouts.total || 0)));
    metricValue("metrics-decoy", number(decoy.total));
    metricValue("metrics-rejection-rate", percent(rejected.total, requests.total));

    var partial = requests.incomplete || rejected.incomplete;
    text(
      $("metrics-requests-detail"),
      buckets.length
        ? plural(buckets.length, "stored interval", "stored intervals") + (partial ? "; partial coverage" : "; complete coverage")
        : "no retained intervals in this range"
    );
    text(
      $("metrics-rejected-detail"),
      rejected.total === null ? "no measured rejections" : "counted once per request"
    );

    var first = buckets.length ? buckets[0].start_ms : null;
    var last = buckets.length
      ? buckets[buckets.length - 1].start_ms + (GRAIN_MS[buckets[buckets.length - 1].grain] || 0)
      : null;
    var grains = [];
    buckets.forEach(function (bucket) {
      var label = grainLabel(bucket.grain);
      if (grains.indexOf(label) === -1) {
        grains.push(label);
      }
    });
    var meta = [];
    meta.push("chart: " + displayGrainLabel(displayWidth) + " buckets, per-minute rate");
    meta.push("storage grain: " + (grains.length ? grains.join(" → ") : "unavailable"));
    if (first !== null) {
      meta.push("available: " + utc(first) + " to " + utc(last));
    }
    if (data.pages > 1) {
      meta.push(plural(data.pages, "page", "pages") + " fetched");
    }
    if (data.truncated) {
      var cut = data.next_start_ms !== null && data.next_start_ms !== undefined ? " at " + utc(data.next_start_ms) : "";
      meta.push("history incomplete" + cut + "; narrow the range");
    }
    if (data.pending_minutes) {
      meta.push(plural(data.pending_minutes, "minute", "minutes") + " awaiting materialization");
    }
    if (data.oldest_available_ms !== null && data.oldest_available_ms !== undefined) {
      meta.push("oldest retained: " + utc(data.oldest_available_ms));
    }
    meta.push("expiry: " + utc(data.expiry_ms));
    text($("metrics-meta"), meta.join(" | "));

    var grouped = groupBuckets(buckets, displayWidth);
    renderChart(grouped, displayWidth, data.from_ms, data.until_ms);
    renderCountryChart(grouped, displayWidth, data.from_ms, data.until_ms);
    renderCountryMap(buckets);
    var classTotals = rejectionClassTotals(buckets);
    var reasonTotals = rejectionReasonTotals(buckets);
    var rejectedTotal = rejected.total || 0;
    renderReasonClasses(classTotals, rejectedTotal);
    renderRejectionClassShare(classTotals, rejectedTotal);
    renderReasons(reasonTotals, rejectedTotal);
    renderRejectionReasonShare(reasonTotals, rejectedTotal);
    renderCorrelations();
    var ranking = countryRanking(buckets);
    renderCountryRanking(ranking);
    renderCountryShare(ranking);
  }

  function renderChart(buckets, displayWidth, rangeStart, rangeEnd) {
    var host = $("chart");
    host.innerHTML = "";
    if (!buckets.length) {
      host.textContent = "No retained intervals in this range.";
      host.className = "chart muted";
      return;
    }
    host.className = "chart";
    var width = 960;
    var height = 244;
    var left = 48;
    var right = 12;
    var bottom = 46;
    var top = 12;
    var innerWidth = width - left - right;
    var innerHeight = height - top - bottom;
    var max = 0;
    var hasRate = false;
    var series = buckets.map(function (group) {
      var requests = counterRate(group, "requests");
      var rejected = counterRate(group, "rejected_requests");
      if (requests !== null || rejected !== null) {
        hasRate = true;
      }
      max = Math.max(max, requests || 0, rejected || 0);
      var grains = Object.keys(group.grains).sort(function (a, b) {
        return (GRAIN_MS[a] || 0) - (GRAIN_MS[b] || 0);
      });
      return {
        group: group,
        requests: requests,
        rejected: rejected,
        requestsTotal: counterTotal(group, "requests"),
        rejectedTotal: counterTotal(group, "rejected_requests"),
        logged: counterTotal(group, "log_requests"),
        failures: counterTotal(group, "upstream_connection_failures"),
        timeouts: counterTotal(group, "upstream_timeouts"),
        decoy: counterTotal(group, "decoy_credential_use_requests"),
        completeMinutes: group.counters.requests ? group.counters.requests.complete_minutes : 0,
        observedMinutes: group.observed_minutes,
        incomplete: group.incomplete,
        grains: grains.map(grainShortLabel),
      };
    });
    if (!hasRate) {
      host.textContent = "No complete-minute data in this range.";
      host.className = "chart muted";
      return;
    }
    max = Math.max(1, max);

    var spanStart = rangeStart;
    var spanEnd = rangeEnd;
    if (
      typeof spanStart !== "number" ||
      typeof spanEnd !== "number" ||
      !isFinite(spanStart) ||
      !isFinite(spanEnd) ||
      spanEnd <= spanStart
    ) {
      spanStart = series[0].group.start_ms;
      spanEnd = series[series.length - 1].group.end_ms;
    }
    var span = Math.max(1, spanEnd - spanStart);
    function x(ms) {
      return left + ((ms - spanStart) / span) * innerWidth;
    }

    var ns = "http://www.w3.org/2000/svg";
    var svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 " + width + " " + height);
    svg.setAttribute("role", "img");
    svg.setAttribute("tabindex", "0");
    svg.setAttribute("focusable", "true");
    svg.setAttribute(
      "aria-label",
      "Requests and rejections per minute by UTC interval across the selected range. Use the left and right arrow keys to inspect intervals."
    );

    function line(y, label) {
      var axis = document.createElementNS(ns, "line");
      axis.setAttribute("x1", left);
      axis.setAttribute("x2", width - right);
      axis.setAttribute("y1", y);
      axis.setAttribute("y2", y);
      axis.setAttribute("stroke", "#edf0f4");
      svg.appendChild(axis);
      var tick = document.createElementNS(ns, "text");
      tick.setAttribute("x", 4);
      tick.setAttribute("y", y + 4);
      tick.textContent = formatRate(label);
      svg.appendChild(tick);
    }

    line(top, max);
    line(top + innerHeight / 2, max / 2);
    line(top + innerHeight, 0);

    var hoverBand = document.createElementNS(ns, "rect");
    hoverBand.setAttribute("y", top);
    hoverBand.setAttribute("height", innerHeight);
    hoverBand.setAttribute("fill", "#f2f5f9");
    hoverBand.setAttribute("pointer-events", "none");
    hoverBand.setAttribute("visibility", "hidden");
    svg.appendChild(hoverBand);

    series.forEach(function (point) {
      var x0 = Math.max(left, x(point.group.start_ms));
      var x1 = Math.min(left + innerWidth, x(point.group.end_ms));
      if (x1 <= x0) {
        return;
      }
      var slotWidth = x1 - x0;
      var barWidth = Math.max(1, Math.min(slotWidth, MAX_BAR_WIDTH));
      var barX = x0 + (slotWidth - barWidth) / 2;
      var requestHeight = point.requests === null ? 0 : (point.requests / max) * innerHeight;
      var rejectHeight = point.rejected === null ? 0 : (point.rejected / max) * innerHeight;
      var requestsBar = document.createElementNS(ns, "rect");
      requestsBar.setAttribute("x", barX);
      requestsBar.setAttribute("y", top + innerHeight - requestHeight);
      requestsBar.setAttribute("width", barWidth);
      requestsBar.setAttribute("height", Math.max(0, requestHeight));
      requestsBar.setAttribute("fill", REQUESTS_BAR_COLOR);
      svg.appendChild(requestsBar);
      var rejectedBar = document.createElementNS(ns, "rect");
      rejectedBar.setAttribute("x", barX);
      rejectedBar.setAttribute("y", top + innerHeight - rejectHeight);
      rejectedBar.setAttribute("width", barWidth);
      rejectedBar.setAttribute("height", Math.max(0, rejectHeight));
      rejectedBar.setAttribute("fill", REJECTED_BAR_COLOR);
      svg.appendChild(rejectedBar);
    });

    var tooltip = document.createElement("div");
    tooltip.className = "chart-tooltip";
    tooltip.hidden = true;
    var tooltipIndex = -1;

    function addTooltipRow(list, label, value) {
      var term = document.createElement("dt");
      term.textContent = label;
      var detail = document.createElement("dd");
      detail.textContent = value;
      list.appendChild(term);
      list.appendChild(detail);
    }

    function showTooltip(index, event) {
      var point = series[index];
      var x0 = Math.max(left, x(point.group.start_ms));
      var x1 = Math.min(left + innerWidth, x(point.group.end_ms));
      hoverBand.setAttribute("x", x0);
      hoverBand.setAttribute("width", Math.max(1, x1 - x0));
      hoverBand.setAttribute("visibility", "visible");
      if (index !== tooltipIndex) {
        tooltipIndex = index;
        tooltip.textContent = "";
        var heading = document.createElement("p");
        heading.className = "chart-tooltip-time";
        heading.textContent = displayLabel(point.group);
        tooltip.appendChild(heading);
        var list = document.createElement("dl");
        list.className = "chart-tooltip-list";
        addTooltipRow(list, "Requests", number(point.requestsTotal));
        addTooltipRow(list, "Requests / min", formatRate(point.requests));
        addTooltipRow(list, "Rejected", number(point.rejectedTotal));
        addTooltipRow(list, "Rejection rate", percent(point.rejectedTotal, point.requestsTotal));
        addTooltipRow(list, "Rejected / min", formatRate(point.rejected));
        addTooltipRow(list, "LOG detections", number(point.logged));
        addTooltipRow(list, "Upstream failures", number(point.failures));
        addTooltipRow(list, "Upstream timeouts", number(point.timeouts));
        addTooltipRow(list, "Decoy use", number(point.decoy));
        if (point.observedMinutes) {
          addTooltipRow(list, "Complete minutes", number(point.completeMinutes) + " of " + number(point.observedMinutes));
        }
        if (point.grains.length) {
          addTooltipRow(list, "Storage grain", point.grains.join(", "));
        }
        tooltip.appendChild(list);
        var noteText = point.requests === null && point.rejected === null
          ? "No complete minutes in this interval."
          : point.incomplete
            ? "Partial interval coverage; rate uses complete minutes."
            : "";
        if (noteText) {
          var note = document.createElement("p");
          note.className = "chart-tooltip-note";
          note.textContent = noteText;
          tooltip.appendChild(note);
        }
      }
      tooltip.hidden = false;
      positionTooltip(index, event);
    }

    function positionTooltip(index, event) {
      var frame = host.getBoundingClientRect();
      var anchorX;
      var anchorY;
      if (event) {
        anchorX = event.clientX - frame.left;
        anchorY = event.clientY - frame.top;
      } else {
        var svgFrame = svg.getBoundingClientRect();
        var group = series[index].group;
        var center = (x(group.start_ms) + x(group.end_ms)) / 2;
        center = Math.max(left, Math.min(left + innerWidth, center));
        anchorX = svgFrame.left - frame.left + (center / width) * svgFrame.width;
        anchorY = svgFrame.top - frame.top + ((top + innerHeight / 2) / height) * svgFrame.height;
      }
      var tooltipX = anchorX + 14;
      var y = anchorY - tooltip.offsetHeight - 12;
      if (tooltipX + tooltip.offsetWidth > host.clientWidth - 8) {
        tooltipX = anchorX - tooltip.offsetWidth - 14;
      }
      if (tooltipX < 8) {
        tooltipX = 8;
      }
      if (y < 8) {
        y = anchorY + 18;
      }
      if (y + tooltip.offsetHeight > host.clientHeight - 8) {
        y = Math.max(8, host.clientHeight - tooltip.offsetHeight - 8);
      }
      tooltip.style.left = tooltipX + "px";
      tooltip.style.top = y + "px";
    }

    function hideTooltip() {
      tooltipIndex = -1;
      tooltip.hidden = true;
      hoverBand.setAttribute("visibility", "hidden");
    }

    function groupAt(ms) {
      var low = 0;
      var high = series.length - 1;
      while (low <= high) {
        var middle = Math.floor((low + high) / 2);
        var group = series[middle].group;
        if (ms < group.start_ms) {
          high = middle - 1;
        } else if (ms >= group.end_ms) {
          low = middle + 1;
        } else {
          return middle;
        }
      }
      return -1;
    }

    function inspectHover(event) {
      var frame = svg.getBoundingClientRect();
      if (!frame.width) {
        return;
      }
      var position = ((event.clientX - frame.left) / frame.width) * width;
      if (position < left || position > left + innerWidth) {
        hideTooltip();
        return;
      }
      var ms = spanStart + ((position - left) / innerWidth) * span;
      var index = groupAt(ms);
      if (index < 0) {
        hideTooltip();
        return;
      }
      keyboardIndex = index;
      showTooltip(index, event);
    }

    var keyboardIndex = series.length - 1;

    svg.addEventListener("pointermove", inspectHover);
    svg.addEventListener("pointerdown", inspectHover);
    svg.addEventListener("pointerleave", hideTooltip);
    svg.addEventListener("pointercancel", hideTooltip);
    svg.addEventListener("blur", hideTooltip);
    svg.addEventListener("keydown", function (event) {
      if (event.key === "Escape") {
        hideTooltip();
        return;
      }
      var next = keyboardIndex;
      if (event.key === "ArrowLeft") {
        next -= 1;
      } else if (event.key === "ArrowRight") {
        next += 1;
      } else if (event.key === "Home") {
        next = 0;
      } else if (event.key === "End") {
        next = series.length - 1;
      } else {
        return;
      }
      event.preventDefault();
      keyboardIndex = Math.max(0, Math.min(series.length - 1, next));
      showTooltip(keyboardIndex);
    });

    var labelGap = displayWidth >= DAY_MS ? 120 : 150;
    var labelCount = Math.max(2, Math.min(7, Math.floor(innerWidth / labelGap)));
    for (var slot = 0; slot < labelCount; slot += 1) {
      var fraction = slot / Math.max(1, labelCount - 1);
      var labelTime = spanStart + fraction * span;
      var labelX = x(labelTime);
      var anchor = "middle";
      if (slot === 0) {
        labelX = left;
        anchor = "start";
      } else if (slot === labelCount - 1) {
        labelX = left + innerWidth;
        anchor = "end";
        labelTime = spanEnd;
      } else {
        labelTime = Math.round(labelTime / displayWidth) * displayWidth;
        if (labelTime <= spanStart || labelTime >= spanEnd) {
          continue;
        }
        labelX = x(labelTime);
      }
      var tick = document.createElementNS(ns, "line");
      tick.setAttribute("x1", labelX);
      tick.setAttribute("x2", labelX);
      tick.setAttribute("y1", top + innerHeight);
      tick.setAttribute("y2", top + innerHeight + 5);
      tick.setAttribute("stroke", "#d9dfe7");
      svg.appendChild(tick);
      var label = document.createElementNS(ns, "text");
      label.setAttribute("x", labelX);
      label.setAttribute("y", top + innerHeight + 20);
      label.setAttribute("text-anchor", anchor);
      label.textContent = displayTimeLabel(labelTime, displayWidth);
      svg.appendChild(label);
    }
    var axisTitle = document.createElementNS(ns, "text");
    axisTitle.setAttribute("x", width - right);
    axisTitle.setAttribute("y", height - 6);
    axisTitle.setAttribute("text-anchor", "end");
    axisTitle.setAttribute("class", "chart-axis-title");
    axisTitle.textContent = "UTC";
    svg.appendChild(axisTitle);

    host.appendChild(svg);
    var legend = document.createElement("div");
    legend.className = "legend";
    legend.innerHTML = '<span class="legend-requests">requests / min</span><span class="legend-rejected">rejected / min</span>';
    host.appendChild(legend);
    host.appendChild(tooltip);
  }

  function countryTotalsFromGroups(groups) {
    var totals = {};
    groups.forEach(function (group) {
      var countries = group.countries || {};
      Object.keys(countries).forEach(function (code) {
        addCountryCount(totals, code, countries[code]);
      });
    });
    return totals;
  }

  function countryOrder(totals) {
    return Object.keys(totals).sort(function (a, b) {
      return (totals[b].requests - totals[a].requests) || a.localeCompare(b);
    });
  }

  function countryColor(index) {
    return COUNTRY_COLORS[index % COUNTRY_COLORS.length];
  }

  function countryTotalsFromBuckets(buckets) {
    var totals = {};
    var known = false;
    var incomplete = false;
    buckets.forEach(function (bucket) {
      var countries = bucket.additional && bucket.additional.countries;
      if (!countries) {
        if (bucket.counters && bucket.counters.requests && bucket.counters.requests.sum) {
          incomplete = true;
        }
        return;
      }
      Object.keys(countries).forEach(function (code) {
        addCountryCount(totals, code, countries[code]);
        known = true;
      });
      if ((bucket.additional.country_overflow || 0) > 0) {
        incomplete = true;
      }
    });
    return { totals: totals, known: known, incomplete: incomplete };
  }

  function renderCountryChart(groups, displayWidth, rangeStart, rangeEnd) {
    var host = $("country-chart");
    host.innerHTML = "";
    var totals = countryTotalsFromGroups(groups);
    var codes = countryOrder(totals);
    if (!groups.length) {
      host.textContent = "No retained intervals in this range.";
      host.className = "chart muted";
      return;
    }
    if (!codes.length) {
      host.textContent = "No country detail in these retained intervals.";
      host.className = "chart muted";
      return;
    }
    var topCodes = codes.slice(0, 8);
    var colorByCode = {};
    topCodes.forEach(function (code, index) {
      colorByCode[code] = countryColor(index);
    });

    var max = 0;
    var hasRate = false;
    var hasOther = false;
    var series = groups.map(function (group) {
      var stats = group.counters && group.counters.requests;
      var complete = stats ? stats.complete_minutes : 0;
      var countries = group.countries_complete || {};
      var requestSegments = [];
      var rejectedSegments = [];
      var requestTotal = 0;
      var rejectedTotal = 0;
      topCodes.forEach(function (code) {
        var counts = countries[code];
        if (!counts) {
          return;
        }
        if (counts.requests) {
          requestSegments.push({ code: code, value: counts.requests });
          requestTotal += counts.requests;
        }
        if (counts.rejected) {
          rejectedSegments.push({ code: code, value: counts.rejected });
          rejectedTotal += counts.rejected;
        }
      });
      var otherRequests = 0;
      var otherRejected = 0;
      Object.keys(countries).forEach(function (code) {
        if (topCodes.indexOf(code) !== -1 || !countries[code]) {
          return;
        }
        otherRequests += countries[code].requests;
        otherRejected += countries[code].rejected;
      });
      if (otherRequests) {
        requestSegments.push({ code: "OTHER", value: otherRequests });
        hasOther = true;
      }
      if (otherRejected) {
        rejectedSegments.push({ code: "OTHER", value: otherRejected });
        hasOther = true;
      }
      var requestRate = complete && requestTotal ? requestTotal / complete : null;
      var rejectedRate = complete && rejectedTotal ? rejectedTotal / complete : null;
      if (requestRate !== null || rejectedRate !== null) {
        hasRate = true;
      }
      max = Math.max(max, requestRate || 0, rejectedRate || 0);
      return {
        group: group,
        complete: complete,
        requestRate: requestRate,
        rejectedRate: rejectedRate,
        requestTotal: requestTotal,
        rejectedTotal: rejectedTotal,
        requestSegments: requestSegments,
        rejectedSegments: rejectedSegments,
        countryIncomplete: group.country_incomplete || !group.country_known,
      };
    });

    if (!hasRate) {
      host.textContent = "No complete-minute country detail in this range.";
      host.className = "chart muted";
      return;
    }
    host.className = "chart";
    max = Math.max(1, max);

    var width = 960;
    var height = 244;
    var left = 48;
    var right = 12;
    var bottom = 46;
    var top = 12;
    var innerWidth = width - left - right;
    var innerHeight = height - top - bottom;

    var spanStart = rangeStart;
    var spanEnd = rangeEnd;
    if (
      typeof spanStart !== "number" ||
      typeof spanEnd !== "number" ||
      !isFinite(spanStart) ||
      !isFinite(spanEnd) ||
      spanEnd <= spanStart
    ) {
      spanStart = series[0].group.start_ms;
      spanEnd = series[series.length - 1].group.end_ms;
    }
    var span = Math.max(1, spanEnd - spanStart);
    function x(ms) {
      return left + ((ms - spanStart) / span) * innerWidth;
    }

    var ns = "http://www.w3.org/2000/svg";
    var svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 " + width + " " + height);
    svg.setAttribute("role", "img");
    svg.setAttribute("tabindex", "0");
    svg.setAttribute("focusable", "true");
    svg.setAttribute(
      "aria-label",
      "Requests and rejections per minute split by country. Use the left and right arrow keys to inspect intervals."
    );

    function line(y, label) {
      var axis = document.createElementNS(ns, "line");
      axis.setAttribute("x1", left);
      axis.setAttribute("x2", width - right);
      axis.setAttribute("y1", y);
      axis.setAttribute("y2", y);
      axis.setAttribute("stroke", "#edf0f4");
      svg.appendChild(axis);
      var tick = document.createElementNS(ns, "text");
      tick.setAttribute("x", 4);
      tick.setAttribute("y", y + 4);
      tick.textContent = formatRate(label);
      svg.appendChild(tick);
    }

    line(top, max);
    line(top + innerHeight / 2, max / 2);
    line(top + innerHeight, 0);

    var hoverBand = document.createElementNS(ns, "rect");
    hoverBand.setAttribute("y", top);
    hoverBand.setAttribute("height", innerHeight);
    hoverBand.setAttribute("fill", "#f2f5f9");
    hoverBand.setAttribute("pointer-events", "none");
    hoverBand.setAttribute("visibility", "hidden");
    svg.appendChild(hoverBand);

    function segmentColor(code) {
      return code === "OTHER" ? COUNTRY_OTHER_COLOR : colorByCode[code] || COUNTRY_OTHER_COLOR;
    }

    function drawStack(centerX, barWidth, segments, complete, rejected) {
      if (!complete) {
        return;
      }
      var y = top + innerHeight;
      segments.forEach(function (segment) {
        var segmentHeight = ((segment.value / complete) / max) * innerHeight;
        if (segmentHeight <= 0) {
          return;
        }
        y -= segmentHeight;
        var rect = document.createElementNS(ns, "rect");
        rect.setAttribute("x", centerX - barWidth / 2);
        rect.setAttribute("y", y);
        rect.setAttribute("width", barWidth);
        rect.setAttribute("height", Math.max(0, segmentHeight));
        rect.setAttribute("fill", segmentColor(segment.code));
        if (rejected) {
          rect.setAttribute("opacity", "0.68");
        }
        svg.appendChild(rect);
      });
    }

    series.forEach(function (point) {
      var x0 = Math.max(left, x(point.group.start_ms));
      var x1 = Math.min(left + innerWidth, x(point.group.end_ms));
      if (x1 <= x0 || !point.complete) {
        return;
      }
      var slotWidth = x1 - x0;
      var barWidth = Math.max(1, Math.min(MAX_BAR_WIDTH, slotWidth * 0.26));
      drawStack(x0 + slotWidth * 0.30, barWidth, point.requestSegments, point.complete, false);
      drawStack(x0 + slotWidth * 0.70, barWidth, point.rejectedSegments, point.complete, true);
    });

    var tooltip = document.createElement("div");
    tooltip.className = "chart-tooltip";
    tooltip.hidden = true;
    var tooltipIndex = -1;

    function addTooltipRow(list, label, value) {
      var term = document.createElement("dt");
      term.textContent = label;
      var detail = document.createElement("dd");
      detail.textContent = value;
      list.appendChild(term);
      list.appendChild(detail);
    }

    function showTooltip(index, event) {
      var point = series[index];
      var x0 = Math.max(left, x(point.group.start_ms));
      var x1 = Math.min(left + innerWidth, x(point.group.end_ms));
      hoverBand.setAttribute("x", x0);
      hoverBand.setAttribute("width", Math.max(1, x1 - x0));
      hoverBand.setAttribute("visibility", "visible");
      if (index !== tooltipIndex) {
        tooltipIndex = index;
        tooltip.textContent = "";
        var heading = document.createElement("p");
        heading.className = "chart-tooltip-time";
        heading.textContent = displayLabel(point.group);
        tooltip.appendChild(heading);
        var list = document.createElement("dl");
        list.className = "chart-tooltip-list";
        addTooltipRow(list, "Requests", number(point.requestTotal));
        addTooltipRow(list, "Requests / min", formatRate(point.requestRate));
        addTooltipRow(list, "Rejected", number(point.rejectedTotal));
        addTooltipRow(list, "Rejection rate", percent(point.rejectedTotal, point.requestTotal));
        addTooltipRow(list, "Rejected / min", formatRate(point.rejectedRate));
        var byCode = {};
        point.requestSegments.forEach(function (segment) {
          byCode[segment.code] = byCode[segment.code] || { requests: 0, rejected: 0 };
          byCode[segment.code].requests += segment.value;
        });
        point.rejectedSegments.forEach(function (segment) {
          byCode[segment.code] = byCode[segment.code] || { requests: 0, rejected: 0 };
          byCode[segment.code].rejected += segment.value;
        });
        Object.keys(byCode).slice(0, 6).forEach(function (code) {
          addTooltipRow(
            list,
            code === "OTHER" ? "OTHER" : countryLabel(code),
            number(byCode[code].requests) + " req / " + number(byCode[code].rejected) + " rej"
          );
        });
        tooltip.appendChild(list);
        if (point.countryIncomplete) {
          var note = document.createElement("p");
          note.className = "chart-tooltip-note";
          note.textContent = "Country detail is incomplete for this interval.";
          tooltip.appendChild(note);
        }
      }
      tooltip.hidden = false;
      positionTooltip(index, event);
    }

    function positionTooltip(index, event) {
      var frame = host.getBoundingClientRect();
      var anchorX;
      var anchorY;
      if (event) {
        anchorX = event.clientX - frame.left;
        anchorY = event.clientY - frame.top;
      } else {
        var svgFrame = svg.getBoundingClientRect();
        var group = series[index].group;
        var center = (x(group.start_ms) + x(group.end_ms)) / 2;
        center = Math.max(left, Math.min(left + innerWidth, center));
        anchorX = svgFrame.left - frame.left + (center / width) * svgFrame.width;
        anchorY = svgFrame.top - frame.top + ((top + innerHeight / 2) / height) * svgFrame.height;
      }
      var tooltipX = anchorX + 14;
      var y = anchorY - tooltip.offsetHeight - 12;
      if (tooltipX + tooltip.offsetWidth > host.clientWidth - 8) {
        tooltipX = anchorX - tooltip.offsetWidth - 14;
      }
      if (tooltipX < 8) {
        tooltipX = 8;
      }
      if (y < 8) {
        y = anchorY + 18;
      }
      if (y + tooltip.offsetHeight > host.clientHeight - 8) {
        y = Math.max(8, host.clientHeight - tooltip.offsetHeight - 8);
      }
      tooltip.style.left = tooltipX + "px";
      tooltip.style.top = y + "px";
    }

    function hideTooltip() {
      tooltipIndex = -1;
      tooltip.hidden = true;
      hoverBand.setAttribute("visibility", "hidden");
    }

    function groupAt(ms) {
      var low = 0;
      var high = series.length - 1;
      while (low <= high) {
        var middle = Math.floor((low + high) / 2);
        var group = series[middle].group;
        if (ms < group.start_ms) {
          high = middle - 1;
        } else if (ms >= group.end_ms) {
          low = middle + 1;
        } else {
          return middle;
        }
      }
      return -1;
    }

    function inspectHover(event) {
      var frame = svg.getBoundingClientRect();
      if (!frame.width) {
        return;
      }
      var position = ((event.clientX - frame.left) / frame.width) * width;
      if (position < left || position > left + innerWidth) {
        hideTooltip();
        return;
      }
      var ms = spanStart + ((position - left) / innerWidth) * span;
      var index = groupAt(ms);
      if (index < 0) {
        hideTooltip();
        return;
      }
      keyboardIndex = index;
      showTooltip(index, event);
    }

    var keyboardIndex = series.length - 1;

    svg.addEventListener("pointermove", inspectHover);
    svg.addEventListener("pointerdown", inspectHover);
    svg.addEventListener("pointerleave", hideTooltip);
    svg.addEventListener("pointercancel", hideTooltip);
    svg.addEventListener("blur", hideTooltip);
    svg.addEventListener("keydown", function (event) {
      if (event.key === "Escape") {
        hideTooltip();
        return;
      }
      var next = keyboardIndex;
      if (event.key === "ArrowLeft") {
        next -= 1;
      } else if (event.key === "ArrowRight") {
        next += 1;
      } else if (event.key === "Home") {
        next = 0;
      } else if (event.key === "End") {
        next = series.length - 1;
      } else {
        return;
      }
      event.preventDefault();
      keyboardIndex = Math.max(0, Math.min(series.length - 1, next));
      showTooltip(keyboardIndex);
    });

    var labelGap = displayWidth >= DAY_MS ? 120 : 150;
    var labelCount = Math.max(2, Math.min(7, Math.floor(innerWidth / labelGap)));
    for (var slot = 0; slot < labelCount; slot += 1) {
      var fraction = slot / Math.max(1, labelCount - 1);
      var labelTime = spanStart + fraction * span;
      var labelX = x(labelTime);
      var anchor = "middle";
      if (slot === 0) {
        labelX = left;
        anchor = "start";
      } else if (slot === labelCount - 1) {
        labelX = left + innerWidth;
        anchor = "end";
        labelTime = spanEnd;
      } else {
        labelTime = Math.round(labelTime / displayWidth) * displayWidth;
        if (labelTime <= spanStart || labelTime >= spanEnd) {
          continue;
        }
        labelX = x(labelTime);
      }
      var tick = document.createElementNS(ns, "line");
      tick.setAttribute("x1", labelX);
      tick.setAttribute("x2", labelX);
      tick.setAttribute("y1", top + innerHeight);
      tick.setAttribute("y2", top + innerHeight + 5);
      tick.setAttribute("stroke", "#d9dfe7");
      svg.appendChild(tick);
      var label = document.createElementNS(ns, "text");
      label.setAttribute("x", labelX);
      label.setAttribute("y", top + innerHeight + 20);
      label.setAttribute("text-anchor", anchor);
      label.textContent = displayTimeLabel(labelTime, displayWidth);
      svg.appendChild(label);
    }
    var axisTitle = document.createElementNS(ns, "text");
    axisTitle.setAttribute("x", width - right);
    axisTitle.setAttribute("y", height - 6);
    axisTitle.setAttribute("text-anchor", "end");
    axisTitle.setAttribute("class", "chart-axis-title");
    axisTitle.textContent = "UTC";
    svg.appendChild(axisTitle);

    host.appendChild(svg);
    var legend = document.createElement("div");
    legend.className = "legend legend-countries";
    topCodes.forEach(function (code, index) {
      var entry = document.createElement("span");
      entry.className = "legend-country";
      entry.style.setProperty("--bar", colorByCode[code] || COUNTRY_OTHER_COLOR);
      entry.textContent = countryLabel(code) || code;
      legend.appendChild(entry);
    });
    if (hasOther) {
      var other = document.createElement("span");
      other.className = "legend-country";
      other.style.setProperty("--bar", COUNTRY_OTHER_COLOR);
      other.textContent = "OTHER";
      legend.appendChild(other);
    }
    var note = document.createElement("span");
    note.className = "legend-note";
    note.textContent = "left requests / right rejected";
    legend.appendChild(note);
    host.appendChild(legend);
    host.appendChild(tooltip);
  }

  function worldMapBounds(max) {
    var bounds = [];
    for (var index = 1; index < 6; index += 1) {
      var raw = Math.ceil(Math.expm1((index / 6) * Math.log1p(max)));
      var value = Math.min(max, Math.max(index, raw));
      if (bounds.length && value <= bounds[bounds.length - 1]) {
        value = Math.min(max, bounds[bounds.length - 1] + 1);
      }
      bounds.push(value);
    }
    return bounds;
  }

  function worldMapColor(info, max) {
    if (!info) {
      return WORLD_MAP_NO_DATA;
    }
    if (info.rejected <= 0) {
      return WORLD_MAP_ZERO;
    }
    if (max <= WORLD_MAP_COLORS.length) {
      return WORLD_MAP_COLORS[Math.min(WORLD_MAP_COLORS.length - 1, info.rejected - 1)];
    }
    var bounds = worldMapBounds(max);
    for (var index = 0; index < bounds.length; index += 1) {
      if (info.rejected <= bounds[index]) {
        return WORLD_MAP_COLORS[index];
      }
    }
    return WORLD_MAP_COLORS[WORLD_MAP_COLORS.length - 1];
  }

  function worldMapTitle(code, info) {
    var label = countryLabel(code) || code;
    if (!info) {
      return label + " - no country data";
    }
    return (
      label +
      " - " +
      number(info.rejected) +
      " blocked, " +
      number(info.requests) +
      " requests"
    );
  }

  function addWorldMapLegendItem(legend, colour, label) {
    var item = document.createElement("span");
    item.className = "country-map-legend-item";
    var swatch = document.createElement("span");
    swatch.className = "country-map-swatch";
    swatch.style.setProperty("--country-map-swatch", colour);
    item.appendChild(swatch);
    item.appendChild(document.createTextNode(label));
    legend.appendChild(item);
  }

  function renderCountryMap(buckets) {
    var host = $("country-map");
    host.innerHTML = "";
    var world = window.KUNATO_WORLD_MAP;
    if (!world || !world.countries || !world.width || !world.height) {
      host.textContent = "World map geometry is unavailable.";
      host.className = "country-map country-map-muted";
      return;
    }
    var data = countryTotalsFromBuckets(buckets);
    var totals = data.totals;
    var max = 0;
    Object.keys(totals).forEach(function (code) {
      if (code !== "ZZ") {
        max = Math.max(max, totals[code].rejected);
      }
    });
    var markerByCode = {};
    (world.markers || []).forEach(function (marker) {
      if (marker && marker.code) {
        markerByCode[marker.code] = marker;
      }
    });
    var unmapped = [];
    Object.keys(totals).forEach(function (code) {
      if (code !== "ZZ" && !world.countries[code] && !markerByCode[code]) {
        unmapped.push(code);
      }
    });

    var svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("viewBox", "0 0 " + world.width + " " + world.height);
    svg.setAttribute("width", String(world.width));
    svg.setAttribute("height", String(world.height));
    svg.setAttribute("role", "img");
    svg.setAttribute(
      "aria-label",
      "World map coloured by the number of WAF-blocked requests per country in the selected history range."
    );
    svg.setAttribute("class", "country-map-svg");

    Object.keys(world.countries)
      .sort()
      .forEach(function (code) {
        var info = totals[code];
        var path = document.createElementNS(SVG_NS, "path");
        path.setAttribute("d", world.countries[code]);
        path.setAttribute("fill", worldMapColor(info, max));
        path.setAttribute("class", "country-path");
        path.setAttribute("data-country", code);
        var title = document.createElementNS(SVG_NS, "title");
        title.textContent = worldMapTitle(code, info);
        path.appendChild(title);
        svg.appendChild(path);
      });

    Object.keys(markerByCode)
      .sort()
      .forEach(function (code) {
        if (!totals[code]) {
          return;
        }
        var marker = markerByCode[code];
        var circle = document.createElementNS(SVG_NS, "circle");
        circle.setAttribute("cx", String(marker.x));
        circle.setAttribute("cy", String(marker.y));
        circle.setAttribute("r", "3.3");
        circle.setAttribute("fill", worldMapColor(totals[code], max));
        circle.setAttribute("class", "country-marker");
        circle.setAttribute("data-country", code);
        var title = document.createElementNS(SVG_NS, "title");
        title.textContent = worldMapTitle(code, totals[code]);
        circle.appendChild(title);
        svg.appendChild(circle);
      });

    host.className = "country-map";
    host.appendChild(svg);

    var legend = document.createElement("div");
    legend.className = "country-map-legend";
    addWorldMapLegendItem(legend, WORLD_MAP_NO_DATA, "No country data");
    addWorldMapLegendItem(legend, WORLD_MAP_ZERO, "0 blocked");
    if (max > 0) {
      if (max <= WORLD_MAP_COLORS.length) {
        for (var count = 1; count <= max; count += 1) {
          addWorldMapLegendItem(
            legend,
            WORLD_MAP_COLORS[Math.min(WORLD_MAP_COLORS.length - 1, count - 1)],
            number(count)
          );
        }
      } else {
        var bounds = worldMapBounds(max);
        var lower = 1;
        bounds.forEach(function (upper, index) {
          if (upper < lower) {
            return;
          }
          addWorldMapLegendItem(
            legend,
            WORLD_MAP_COLORS[index],
            lower === upper ? number(lower) : number(lower) + "–" + number(upper)
          );
          lower = upper + 1;
        });
        if (lower <= max) {
          addWorldMapLegendItem(
            legend,
            WORLD_MAP_COLORS[WORLD_MAP_COLORS.length - 1],
            number(lower) + "–" + number(max)
          );
        }
      }
    }
    host.appendChild(legend);

    var notes = [];
    if (!data.known) {
      notes.push(
        "No country detail in these retained intervals; countries are shown without data."
      );
    }
    if (!buckets.length) {
      notes.push("No retained intervals in this range.");
    }
    if (totals.ZZ) {
      notes.push(
        "UNKNOWN (ZZ): " +
          number(totals.ZZ.rejected) +
          " blocked, " +
          number(totals.ZZ.requests) +
          " requests; not mapped."
      );
    }
    if (unmapped.length) {
      notes.push(
        plural(unmapped.length, "country", "countries") +
          " with data have no map geometry and remain in the top table."
      );
    }
    if (data.incomplete) {
      notes.push("Country detail is incomplete for some intervals in this range.");
    }
    if (data.known && max === 0) {
      notes.push("No blocked requests in this range.");
    }
    if (notes.length) {
      var note = document.createElement("p");
      note.className = "country-map-note";
      note.textContent = notes.join(" ");
      host.appendChild(note);
    }

    var tooltip = document.createElement("div");
    tooltip.className = "chart-tooltip country-map-tooltip";
    tooltip.hidden = true;
    host.appendChild(tooltip);

    function mapCode(target) {
      while (target && target !== svg) {
        if (target.getAttribute) {
          var code = target.getAttribute("data-country");
          if (code) {
            return code;
          }
        }
        target = target.parentNode;
      }
      return null;
    }

    function positionMapTooltip(event) {
      var frame = host.getBoundingClientRect();
      var x = event.clientX - frame.left + 14;
      var y = event.clientY - frame.top - tooltip.offsetHeight - 12;
      if (x + tooltip.offsetWidth > host.clientWidth - 8) {
        x = event.clientX - frame.left - tooltip.offsetWidth - 14;
      }
      if (x < 8) {
        x = 8;
      }
      if (y < 8) {
        y = event.clientY - frame.top + 18;
      }
      if (y + tooltip.offsetHeight > host.clientHeight - 8) {
        y = Math.max(8, host.clientHeight - tooltip.offsetHeight - 8);
      }
      tooltip.style.left = x + "px";
      tooltip.style.top = y + "px";
    }

    function showMapTooltip(code, event) {
      var info = totals[code];
      tooltip.textContent = "";
      var heading = document.createElement("p");
      heading.className = "chart-tooltip-time";
      heading.textContent = countryLabel(code) || code;
      tooltip.appendChild(heading);
      var list = document.createElement("dl");
      list.className = "chart-tooltip-list";
      function row(label, value) {
        var term = document.createElement("dt");
        term.textContent = label;
        var detail = document.createElement("dd");
        detail.textContent = value;
        list.appendChild(term);
        list.appendChild(detail);
      }
      if (info) {
        row("Blocked", number(info.rejected));
        row("Requests", number(info.requests));
        row("Block rate", percent(info.rejected, info.requests));
      } else {
        row("Country detail", "Unavailable");
      }
      tooltip.appendChild(list);
      tooltip.hidden = false;
      positionMapTooltip(event);
    }

    function hideMapTooltip() {
      tooltip.hidden = true;
    }

    svg.addEventListener("pointermove", function (event) {
      var code = mapCode(event.target);
      if (!code) {
        hideMapTooltip();
        return;
      }
      showMapTooltip(code, event);
    });
    svg.addEventListener("pointerleave", hideMapTooltip);
    svg.addEventListener("pointercancel", hideMapTooltip);
  }

  var REASONS = [
    "rule", "response_rule", "rate_limit", "ban", "overload", "client_identity",
    "host", "admin_access", "body", "decode", "form", "upload", "graphql", "saml",
    "php_request", "php_response", "hardening", "jwt", "decoy", "behavior",
    "protocol", "response_inspection", "country_policy",
  ];

  var REJECT_CLASS_LABELS = {
    "sql-injection": "SQL injection",
    "nosql-injection": "NoSQL injection",
    "ldap-injection": "LDAP injection",
    "xpath-injection": "XPath injection",
    "jdbc-injection": "JDBC injection",
    "xss": "XSS",
    "css-injection": "CSS injection",
    "ssti": "SSTI",
    "command-injection": "Command injection",
    "path-traversal": "Path traversal",
    "remote-file-inclusion": "Remote file inclusion",
    "ssrf": "SSRF",
    "xxe": "XXE",
    "deserialization": "Deserialization",
    "prototype-pollution": "Prototype pollution",
    "open-redirect": "Open redirect",
    "parameter-pollution": "Parameter pollution",
    "mass-assignment": "Mass assignment",
    "prompt-injection": "Prompt injection",
    "cache-deception": "Cache deception",
    "config-injection": "Config injection",
    "jwt": "JWT",
    "malicious-upload": "Malicious upload",
    "protocol": "Protocol anomaly",
    "scanner": "Scanner",
    "brute-force": "Brute force",
    "discovery": "Discovery",
    "exposure": "Exposure",
    "info-disclosure": "Info disclosure",
    "bypass": "Bypass",
    "exploit": "Known exploit",
    "cve": "CVE signature",
    "other": "Other rule",
    "rate-limit": "Rate limit",
    "ban": "Active ban",
    "overload": "Overload",
    "client-identity": "Client identity",
    "host": "Host policy",
    "admin-access": "Admin gate",
    "body-limit": "Body limit",
    "decode": "Decode failure",
    "form": "Form guard",
    "graphql": "GraphQL guard",
    "saml": "SAML guard",
    "php-request": "PHP request",
    "php-response": "PHP response",
    "hardening": "Hardening",
    "decoy": "Decoy",
    "behavior": "Behavior",
    "response-inspection": "Response inspection",
    "country-policy": "Country gate",
  };

  function rejectClassLabel(value) {
    var key = String(value === null || value === undefined ? "" : value);
    return REJECT_CLASS_LABELS[key] || humanToken(key.replace(/-/g, " "));
  }

  function rejectionClassTotals(buckets) {
    var totals = {};
    var known = false;
    buckets.forEach(function (bucket) {
      var classes = bucket.rejection_classes || {};
      Object.keys(classes).forEach(function (key) {
        var stats = classes[key];
        if (!stats || !stats.known_minutes) {
          return;
        }
        totals[key] = (totals[key] || 0) + stats.sum;
        known = true;
      });
    });
    var entries = Object.keys(totals).map(function (key) {
      return { key: key, label: rejectClassLabel(key), value: totals[key] };
    });
    entries.sort(function (a, b) {
      return b.value - a.value || a.key.localeCompare(b.key);
    });
    var measured = entries.reduce(function (sum, entry) {
      return sum + entry.value;
    }, 0);
    return { entries: entries, measured: measured, known: known };
  }

  function rejectionClassEntries(summary, rejected) {
    var entries = summary.entries.slice();
    if (rejected > summary.measured) {
      entries.push({
        key: "unrecorded",
        label: "Unrecorded cause",
        value: rejected - summary.measured,
        unrecorded: true,
      });
    }
    return entries;
  }

  function renderReasonClasses(summary, rejected) {
    var body = $("rejection-classes");
    if (!body) {
      return;
    }
    body.innerHTML = "";
    function message(value) {
      var row = document.createElement("tr");
      var cell = document.createElement("td");
      cell.colSpan = 3;
      cell.className = "muted";
      cell.textContent = value;
      row.appendChild(cell);
      body.appendChild(row);
    }
    if (!summary.known) {
      message(
        rejected
          ? "Attack-type detail is unavailable for these stored intervals."
          : "No measured rejections in this range."
      );
      return;
    }
    var entries = rejectionClassEntries(summary, rejected);
    if (!entries.length) {
      message("No measured rejections in this range.");
      return;
    }
    entries.forEach(function (entry) {
      var row = document.createElement("tr");
      var name = document.createElement("td");
      name.textContent = entry.label;
      var count = document.createElement("td");
      count.className = "num";
      count.textContent = number(entry.value);
      var share = document.createElement("td");
      share.className = "num";
      share.textContent = percent(entry.value, rejected);
      row.appendChild(name);
      row.appendChild(count);
      row.appendChild(share);
      body.appendChild(row);
    });
  }

  function renderRejectionClassShare(summary, rejected) {
    var host = $("rejection-class-share");
    if (!host) {
      return;
    }
    if (!summary.known) {
      renderSharePie(host, [], {
        empty: rejected
          ? "Attack-type detail is unavailable for these stored intervals."
          : "No measured rejections in this range.",
      });
      return;
    }
    renderSharePie(
      host,
      shareSlices(rejectionClassEntries(summary, rejected), {
        colors: REJECTION_SHARE_COLORS,
        limit: REJECTION_SHARE_LIMIT,
        otherLabel: "OTHER",
        otherColor: REJECTION_OTHER_COLOR,
        unrecordedColor: REJECTION_UNRECORDED_COLOR,
      }),
      {
        label: "Attack type and cause share of rejections",
        empty: "No measured rejections in this range.",
        unit: "rejections",
      }
    );
  }

  function rejectionReasonTotals(buckets) {
    var totals = {};
    REASONS.forEach(function (reason) {
      totals[reason] = 0;
    });
    buckets.forEach(function (bucket) {
      var reasons = bucket.reasons || {};
      REASONS.forEach(function (reason) {
        if (reasons[reason]) {
          totals[reason] += reasons[reason].sum;
        }
      });
    });
    return totals;
  }

  function rejectionReasonEntries(totals, rejected) {
    var entries = [];
    var measured = 0;
    REASONS.forEach(function (reason) {
      if (!totals[reason]) {
        return;
      }
      entries.push({ key: reason, label: reason.replace(/_/g, " "), value: totals[reason] });
      measured += totals[reason];
    });
    if (rejected > measured) {
      entries.push({
        key: "unrecorded",
        label: "Unrecorded mechanism",
        value: rejected - measured,
        unrecorded: true,
      });
    }
    return entries;
  }

  function renderReasons(totals, rejected) {
    var body = $("reasons");
    body.innerHTML = "";
    var any = false;
    REASONS.forEach(function (reason) {
      if (!totals[reason]) {
        return;
      }
      any = true;
      var row = document.createElement("tr");
      var name = document.createElement("td");
      name.textContent = reason.replace(/_/g, " ");
      var count = document.createElement("td");
      count.className = "num";
      count.textContent = number(totals[reason]);
      var share = document.createElement("td");
      share.className = "num";
      share.textContent = percent(totals[reason], rejected);
      row.appendChild(name);
      row.appendChild(count);
      row.appendChild(share);
      body.appendChild(row);
    });
    if (!any) {
      var row = document.createElement("tr");
      var cell = document.createElement("td");
      cell.colSpan = 3;
      cell.className = "muted";
      cell.textContent = "No measured rejections in this range.";
      row.appendChild(cell);
      body.appendChild(row);
    }
  }

  function renderRejectionReasonShare(totals, rejected) {
    var host = $("rejection-reason-share");
    if (!host) {
      return;
    }
    renderSharePie(
      host,
      shareSlices(rejectionReasonEntries(totals, rejected), {
        colors: REJECTION_SHARE_COLORS,
        limit: REJECTION_SHARE_LIMIT,
        otherLabel: "OTHER",
        otherColor: REJECTION_OTHER_COLOR,
        unrecordedColor: REJECTION_UNRECORDED_COLOR,
      }),
      {
        label: "Terminal mechanism share of rejections",
        empty: "No measured rejections in this range.",
        unit: "rejections",
      }
    );
  }

  function renderCorrelations() {
    var page = state.correlations;
    var body = $("correlations");
    body.innerHTML = "";
    var records = page ? page.records || [] : [];
    if (!records.length) {
      var row = document.createElement("tr");
      var cell = document.createElement("td");
      cell.colSpan = 6;
      cell.className = "muted";
      cell.textContent = page ? "No retained decoy evidence in this range." : "Correlation evidence unavailable.";
      row.appendChild(cell);
      body.appendChild(row);
      return;
    }
    records.forEach(function (record) {
      var row = document.createElement("tr");
      function add(value, className) {
        var cell = document.createElement("td");
        cell.textContent = value === null || value === undefined || value === "" ? "unrecorded" : String(value);
        if (className) {
          cell.className = className;
        }
        row.appendChild(cell);
      }
      add(record.credential_id);
      add(record.site);
      add(utc(record.first_seen_ms));
      add(utc(record.last_credential_ms));
      add(number(record.credential_evidence_count), "num");
      add(number(record.occurrence_evidence_count), "num");
      body.appendChild(row);
    });
  }

  function countryRanking(buckets) {
    var totals = {};
    var known = false;
    var incomplete = false;
    buckets.forEach(function (bucket) {
      var countries = bucket.additional && bucket.additional.countries;
      if (!countries) {
        if (bucket.counters && bucket.counters.requests && bucket.counters.requests.sum) {
          incomplete = true;
        }
        return;
      }
      Object.keys(countries).forEach(function (code) {
        addCountryCount(totals, code, countries[code]);
        known = true;
      });
      if ((bucket.additional.country_overflow || 0) > 0) {
        incomplete = true;
      }
    });
    return {
      entries: countryOrder(totals).map(function (code) {
        return { code: code, counts: totals[code] };
      }),
      known: known,
      incomplete: incomplete,
    };
  }

  function renderCountryRanking(ranking) {
    var body = $("country-ranking");
    body.innerHTML = "";
    function message(value) {
      var row = document.createElement("tr");
      var cell = document.createElement("td");
      cell.colSpan = 5;
      cell.className = "muted";
      cell.textContent = value;
      row.appendChild(cell);
      body.appendChild(row);
    }
    if (!ranking.known) {
      message("Country detail is unavailable for these stored intervals.");
      return;
    }
    if (!ranking.entries.length) {
      message("No country statistics in this range.");
      return;
    }
    ranking.entries.slice(0, COUNTRY_RANKING_LIMIT).forEach(function (entry, index) {
      var row = document.createElement("tr");
      var rank = document.createElement("td");
      rank.className = "country-rank";
      rank.textContent = String(index + 1);
      row.appendChild(rank);
      var country = document.createElement("td");
      var swatch = document.createElement("span");
      swatch.className = "country-swatch";
      swatch.style.setProperty("--country-swatch", countryColor(index));
      country.appendChild(swatch);
      country.appendChild(document.createTextNode(countryLabel(entry.code) || entry.code));
      row.appendChild(country);
      var requests = document.createElement("td");
      requests.className = "num";
      requests.textContent = number(entry.counts.requests);
      row.appendChild(requests);
      var rejected = document.createElement("td");
      rejected.className = "num";
      rejected.textContent = number(entry.counts.rejected);
      row.appendChild(rejected);
      var rate = document.createElement("td");
      rate.className = "num";
      rate.textContent = percent(entry.counts.rejected, entry.counts.requests);
      row.appendChild(rate);
      body.appendChild(row);
    });
    if (ranking.incomplete) {
      message("Country detail is incomplete for some intervals in this range.");
    }
  }

  function shareArc(startFraction, endFraction) {
    var radius = 98;
    var start = startFraction * Math.PI * 2 - Math.PI / 2;
    var end = endFraction * Math.PI * 2 - Math.PI / 2;
    var x1 = (100 + radius * Math.cos(start)).toFixed(2);
    var y1 = (100 + radius * Math.sin(start)).toFixed(2);
    var x2 = (100 + radius * Math.cos(end)).toFixed(2);
    var y2 = (100 + radius * Math.sin(end)).toFixed(2);
    var largeArc = endFraction - startFraction > 0.5 ? 1 : 0;
    return (
      "M 100 100 L " + x1 + " " + y1 +
      " A " + radius + " " + radius + " 0 " + largeArc + " 1 " + x2 + " " + y2 +
      " Z"
    );
  }

  function shareSlices(entries, options) {
    var regular = entries
      .filter(function (entry) {
        return entry.value > 0 && !entry.unrecorded;
      })
      .sort(function (a, b) {
        return b.value - a.value || a.label.localeCompare(b.label);
      });
    var pinned = entries.filter(function (entry) {
      return entry.value > 0 && entry.unrecorded;
    });
    var slices = regular.slice(0, options.limit).map(function (entry, index) {
      return {
        label: entry.label,
        value: entry.value,
        color: options.colors[index % options.colors.length],
      };
    });
    var other = regular.slice(options.limit).reduce(function (sum, entry) {
      return sum + entry.value;
    }, 0);
    if (other > 0) {
      slices.push({ label: options.otherLabel, value: other, color: options.otherColor });
    }
    pinned.forEach(function (entry) {
      slices.push({
        label: entry.label,
        value: entry.value,
        color: options.unrecordedColor,
      });
    });
    return slices;
  }

  function shareSliceTitle(slice, total, unit) {
    var title = document.createElementNS(SVG_NS, "title");
    title.textContent =
      slice.label + ": " + percent(slice.value, total) + " (" + number(slice.value) + " " + unit + ")";
    return title;
  }

  function shareTotal(slices) {
    return slices.reduce(function (sum, slice) {
      return sum + slice.value;
    }, 0);
  }

  function renderSharePie(host, slices, options) {
    host.innerHTML = "";
    host.className = "share-pie";
    var total = shareTotal(slices);
    if (!slices.length || !total) {
      host.className = "share-pie share-pie-muted";
      host.textContent = options.empty;
      return;
    }
    var svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("class", "share-pie-svg");
    svg.setAttribute("viewBox", "0 0 200 200");
    svg.setAttribute("role", "img");
    svg.setAttribute(
      "aria-label",
      options.label + ": " +
        slices
          .map(function (slice) {
            return slice.label + " " + percent(slice.value, total);
          })
          .join(", ")
    );
    var offset = 0;
    slices.forEach(function (slice, index) {
      var fraction = slice.value / total;
      var end = index === slices.length - 1 ? 1 : offset + fraction;
      var shape;
      if (slices.length === 1) {
        shape = document.createElementNS(SVG_NS, "circle");
        shape.setAttribute("cx", "100");
        shape.setAttribute("cy", "100");
        shape.setAttribute("r", "98");
      } else {
        shape = document.createElementNS(SVG_NS, "path");
        shape.setAttribute("d", shareArc(offset, end));
      }
      shape.setAttribute("fill", slice.color);
      shape.setAttribute("class", "share-pie-slice");
      shape.appendChild(shareSliceTitle(slice, total, options.unit));
      svg.appendChild(shape);
      offset = end;
    });
    host.appendChild(svg);
    var legend = document.createElement("div");
    legend.className = "share-pie-legend";
    slices.forEach(function (slice) {
      var entry = document.createElement("span");
      entry.className = "share-pie-entry";
      var swatch = document.createElement("span");
      swatch.className = "share-pie-swatch";
      swatch.style.setProperty("--share-swatch", slice.color);
      entry.appendChild(swatch);
      var label = document.createElement("span");
      label.className = "share-pie-label";
      label.textContent = slice.label;
      label.title = slice.label;
      entry.appendChild(label);
      var value = document.createElement("span");
      value.className = "share-pie-value";
      value.textContent = percent(slice.value, total);
      entry.appendChild(value);
      legend.appendChild(entry);
    });
    host.appendChild(legend);
    if (options.note) {
      var note = document.createElement("p");
      note.className = "share-pie-note";
      note.textContent = options.note;
      host.appendChild(note);
    }
  }

  function countryShareSlices(entries) {
    return shareSlices(
      entries.map(function (entry) {
        return {
          label: countryLabel(entry.code) || entry.code,
          value: entry.counts.requests,
        };
      }),
      {
        colors: COUNTRY_COLORS,
        limit: COUNTRY_RANKING_LIMIT,
        otherLabel: "OTHER",
        otherColor: COUNTRY_OTHER_COLOR,
      }
    );
  }

  function renderCountryShare(ranking) {
    var host = $("country-share");
    if (!ranking.known) {
      renderSharePie(host, [], {
        empty: "Country detail is unavailable for these stored intervals.",
      });
      return;
    }
    renderSharePie(host, countryShareSlices(ranking.entries), {
      label: "Request share by source country",
      empty: "No requests with country detail in this range.",
      unit: "requests",
      note: ranking.incomplete
        ? "Country detail is incomplete for some intervals in this range."
        : null,
    });
  }

  var MAX_HISTORY_PAGES = 64;
  var HISTORY_PAGE_LIMIT = 128;
  var metricsRequest = 0;

  async function fetchHistory(from, until, attempt) {
    attempt = attempt || 0;
    var buckets = [];
    var seen = {};
    var firstPage = null;
    var pageCount = 0;
    var pageFrom = from;
    var revision = null;
    var nextStart = null;
    var truncated = false;
    for (var page = 0; page < MAX_HISTORY_PAGES; page += 1) {
      var query = "?from_ms=" + pageFrom + "&until_ms=" + until + "&limit=" + HISTORY_PAGE_LIMIT;
      if (revision !== null) {
        query += "&revision=" + revision;
      }
      var response = await fetch("/api/v1/history" + query, { credentials: "same-origin" });
      if (response.status === 401) {
        window.location.replace("/login");
        throw new Error("unauthorized");
      }
      if (response.status === 409) {
        if (attempt >= 2) {
          throw new Error("history changed; retry");
        }
        return fetchHistory(from, until, attempt + 1);
      }
      if (response.status === 503) {
        if (attempt >= 2) {
          throw new Error("history is busy; retry");
        }
        await new Promise(function (resolve) {
          setTimeout(resolve, 1000);
        });
        return fetchHistory(from, until, attempt + 1);
      }
      if (!response.ok) {
        throw new Error("history request failed with " + response.status);
      }
      var data = await response.json();
      if (!firstPage) {
        firstPage = data;
        revision = data.revision;
      }
      pageCount += 1;
      var pageBuckets = data.buckets || [];
      pageBuckets.forEach(function (bucket) {
        if (seen[bucket.start_ms]) {
          return;
        }
        seen[bucket.start_ms] = true;
        buckets.push(bucket);
      });
      nextStart = data.next_start_ms;
      if (nextStart === null || nextStart === undefined || !pageBuckets.length) {
        nextStart = nextStart === undefined ? null : nextStart;
        break;
      }
      if (nextStart <= pageFrom || page === MAX_HISTORY_PAGES - 1) {
        truncated = true;
        break;
      }
      pageFrom = nextStart;
    }
    if (nextStart !== null && nextStart !== undefined) {
      truncated = true;
    }
    buckets.sort(function (a, b) {
      return a.start_ms - b.start_ms;
    });
    return {
      version: 1,
      instance: firstPage ? firstPage.instance : null,
      from_ms: from,
      until_ms: until,
      range_ms: until - from,
      expiry_ms: firstPage ? firstPage.expiry_ms : null,
      oldest_available_ms: firstPage ? firstPage.oldest_available_ms : null,
      pending_minutes: firstPage ? firstPage.pending_minutes : 0,
      revision: firstPage ? firstPage.revision : null,
      returned: buckets.length,
      pages: pageCount,
      truncated: truncated,
      next_start_ms: truncated ? nextStart : null,
      buckets: buckets,
    };
  }

  async function fetchCorrelations(from, until, request) {
    try {
      var query = "?from_ms=" + from + "&until_ms=" + until + "&limit=128";
      var response = await fetch("/api/v1/correlations" + query, { credentials: "same-origin" });
      if (!response.ok) {
        throw new Error("correlation request failed with " + response.status);
      }
      var page = await response.json();
      if (request === metricsRequest) {
        state.correlations = page;
        renderCorrelations();
      }
    } catch (error) {
      if (request === metricsRequest) {
        state.correlations = null;
        renderCorrelations();
      }
    }
  }

  function loadMetrics() {
    var request = ++metricsRequest;
    var until = Date.now();
    var from = until - state.rangeMs;
    fetchCorrelations(from, until, request);
    fetchHistory(from, until)
      .then(function (data) {
        if (request !== metricsRequest) {
          return;
        }
        state.metrics = data;
        renderMetrics();
      })
      .catch(function (error) {
        if (request !== metricsRequest) {
          return;
        }
        if (error.message !== "unauthorized") {
          text($("metrics-meta"), "History unavailable: " + error.message);
        }
      });
  }

  function loadEdr() {
    var request = ++state.edrRequest;
    fetch("/api/v1/edr", { credentials: "same-origin" })
      .then(function (response) {
        if (response.status === 401) {
          throw new Error("unauthorized");
        }
        if (!response.ok) {
          throw new Error("HTTP " + response.status);
        }
        return response.json();
      })
      .then(function (data) {
        if (request !== state.edrRequest) {
          return;
        }
        state.edr = data;
        renderEdr();
      })
      .catch(function (error) {
        if (request !== state.edrRequest) {
          return;
        }
        if (error.message === "unauthorized") {
          window.location.replace("/login");
          return;
        }
        renderEdrError(error.message);
      });
  }

  function renderEdr() {
    var data = state.edr;
    if (!data) {
      return;
    }
    if (!data.enabled) {
      renderEdrDisabled(data);
      return;
    }
    if (!data.view) {
      renderEdrStarting(data);
      return;
    }
    var view = data.view;
    var stale = edrIsStale(data);
    renderEdrStatus(view, stale);
    renderEdrLamps(view, stale);
    renderEdrFindings(view);
    renderEdrTelemetry(view);
    var detected = (view.detectors || []).filter(function (detector) {
      return detector.state === "detected";
    }).length;
    var unknown = (view.detectors || []).filter(function (detector) {
      return detector.state === "unknown";
    }).length;
    if (stale || view.state === "stopped" || view.state === "failed") {
      detected = 0;
      unknown = (view.detectors || []).length;
    }
    text(
      $("edr-live-summary"),
      detected +
        " detector" +
        (detected === 1 ? "" : "s") +
        " with findings; " +
        unknown +
        " could not be evaluated."
    );
  }

  function edrIsStale(data) {
    return data.stale === true;
  }

  function edrTaskLabel(value) {
    if (value === "running") {
      return "EDR running";
    }
    if (value === "starting") {
      return "EDR starting";
    }
    if (value === "failed") {
      return "EDR failed";
    }
    if (value === "stopped") {
      return "EDR stopped";
    }
    return "EDR state unknown";
  }

  function renderEdrStatus(view, stale) {
    text($("edr-task-chip"), edrTaskLabel(view.state));
    var schedule = view.schedule || {};
    var last = schedule.last_evaluated_at_ms;
    if (last) {
      var evaluated = "Evaluated " + utcMinute(last) + " UTC";
      if (schedule.last_window) {
        evaluated +=
          " · window " +
          utcMinute(schedule.last_window.from_ms) +
          "–" +
          utcMinute(schedule.last_window.until_ms) +
          " UTC";
      }
      text($("edr-last-evaluated"), evaluated);
    } else {
      text($("edr-last-evaluated"), "No evaluation yet");
    }
    text(
      $("edr-next-evaluation"),
      schedule.next_evaluation_at_ms
        ? "Next " + utcMinute(schedule.next_evaluation_at_ms) + " UTC"
        : "Next evaluation unavailable"
    );
    text(
      $("edr-schedule"),
      "Window " +
        formatDurationMs(schedule.window_ms) +
        " · baseline " +
        formatDurationMs(schedule.baseline_ms)
    );
    var note;
    if (view.error) {
      note = "EDR task error: " + view.error;
    } else if (stale) {
      note =
        "The last evaluation is older than the expected hourly window, or the next evaluation is overdue. The lamps show the last completed report; check the console EDR task and the WAF snapshot source.";
    } else if (view.state === "starting") {
      note = "Waiting for the first hourly evaluation. The analysis covers the last complete UTC hour.";
    } else if (!last) {
      note = "No hourly evaluation has completed yet.";
    } else {
      note =
        "The lamps describe the last completed hourly window. A red lamp is a finding in that window, not a live alarm.";
    }
    text($("edr-status-note"), note);
  }

  function renderEdrLamps(view, stale) {
    var grid = $("edr-lamp-grid");
    emptyNode(grid);
    var detectors = view.detectors || [];
    if (!detectors.length) {
      renderEdrUnavailableLamps("No detector state is available.");
      return;
    }
    detectors.forEach(function (detector) {
      var state = detector.state;
      var reason = detector.reason;
      if (stale) {
        state = "unknown";
        reason = "The next evaluation is overdue.";
      } else if (view.state === "stopped") {
        state = "unknown";
        reason = "The EDR task is stopped.";
      } else if (view.state === "failed") {
        state = "unknown";
        reason = "The EDR task failed.";
      }
      grid.appendChild(edrLampCard(detector, state, reason));
    });
  }

  function renderEdrUnavailableLamps(reason) {
    var grid = $("edr-lamp-grid");
    emptyNode(grid);
    EDR_DETECTOR_KINDS.forEach(function (kind) {
      grid.appendChild(
        edrLampCard(
          {
            kind: kind,
            count: 0,
            severity: null,
            last_detected_at_ms: null,
          },
          "unknown",
          reason
        )
      );
    });
  }

  function edrLampCard(detector, state, reason) {
    var meta = EDR_DETECTOR_LABELS[detector.kind] || {
      title: String(detector.kind || "unknown").replace(/_/g, " "),
      detail: "",
    };
    var card = document.createElement("article");
    card.className = "edr-lamp is-" + state;
    var dot = document.createElement("span");
    dot.className = "edr-lamp-dot";
    dot.setAttribute("aria-hidden", "true");
    var body = document.createElement("div");
    body.className = "edr-lamp-body";
    var stateLine = document.createElement("p");
    stateLine.className = "edr-lamp-state";
    stateLine.textContent =
      state === "detected" ? "DETECTED" : state === "quiet" ? "QUIET" : "UNKNOWN";
    var title = document.createElement("p");
    title.className = "edr-lamp-title";
    title.textContent = meta.title;
    var metaLine = document.createElement("p");
    metaLine.className = "edr-lamp-meta";
    if (state === "detected") {
      var parts = [plural(detector.count || 0, "finding", "findings")];
      if (detector.severity) {
        parts.push(String(detector.severity).toUpperCase());
      }
      if (detector.last_detected_at_ms) {
        parts.push("last " + utcMinute(detector.last_detected_at_ms) + " UTC");
      }
      metaLine.textContent = parts.join(" · ");
    } else if (state === "quiet") {
      metaLine.textContent = "No finding in the last evaluated window.";
    } else {
      metaLine.textContent = "Not evaluated.";
    }
    var detail = document.createElement("p");
    detail.className = "edr-lamp-detail";
    detail.textContent = meta.detail;
    body.appendChild(stateLine);
    body.appendChild(title);
    body.appendChild(metaLine);
    body.appendChild(detail);
    if (state === "unknown" && reason) {
      var why = document.createElement("p");
      why.className = "edr-lamp-reason";
      why.textContent = reason;
      body.appendChild(why);
    }
    card.appendChild(dot);
    card.appendChild(body);
    return card;
  }

  function renderEdrFindings(view) {
    var list = $("edr-findings-list");
    var note = $("edr-findings-note");
    emptyNode(list);
    var findings = view.findings || [];
    var total = (view.detectors || []).reduce(function (sum, detector) {
      return sum + (detector.count || 0);
    }, 0);
    if (!findings.length) {
      var unknown = (view.detectors || []).some(function (detector) {
        return detector.state === "unknown";
      });
      list.appendChild(
        edrEmpty(
          unknown
            ? "No finding in the last evaluated window, but at least one detector could not be evaluated. Treat the amber lamps as unknown, not clear."
            : "No finding in the last evaluated window."
        )
      );
      text(
        note,
        "The latest hourly window only; the finding ring keeps age and recurrence across console restarts."
      );
      return;
    }
    if (total > findings.length) {
      text(
        note,
        "Showing " +
          findings.length +
          " of " +
          number(total) +
          " findings; the detector counts are exact."
      );
    } else {
      text(
        note,
        "The latest hourly window only; the finding ring keeps age and recurrence across console restarts."
      );
    }
    findings.forEach(function (finding) {
      list.appendChild(edrFindingCard(finding));
    });
  }

  function edrFindingCard(finding) {
    var card = document.createElement("article");
    card.className = "edr-finding severity-" + finding.severity;
    var head = document.createElement("div");
    head.className = "edr-finding-head";
    var severity = document.createElement("span");
    severity.className = "chip";
    severity.textContent = String(finding.severity || "unknown").toUpperCase();
    var kind = document.createElement("span");
    kind.className = "edr-finding-kind";
    kind.textContent =
      (EDR_DETECTOR_LABELS[finding.kind] || {}).title ||
      String(finding.kind || "").replace(/_/g, " ");
    head.appendChild(severity);
    head.appendChild(kind);
    var source = edrFindingSource(finding);
    if (source) {
      var sourceNode = document.createElement("span");
      sourceNode.className = "edr-finding-source";
      sourceNode.textContent = source;
      head.appendChild(sourceNode);
    }
    card.appendChild(head);
    var history = document.createElement("p");
    history.className = "edr-finding-history";
    var parts = [];
    if (finding.first_seen_ms) {
      parts.push("first detected " + utcMinute(finding.first_seen_ms) + " UTC");
    }
    if (finding.episode_started_ms && finding.episode_started_ms !== finding.first_seen_ms) {
      parts.push("episode started " + utcMinute(finding.episode_started_ms) + " UTC");
    }
    if (finding.last_seen_ms) {
      parts.push("last seen " + utcMinute(finding.last_seen_ms) + " UTC");
    }
    parts.push("seen in " + plural(finding.observed_windows || 0, "evaluation", "evaluations"));
    if ((finding.episodes || 0) > 1) {
      parts.push(plural(finding.episodes, "episode", "episodes"));
    }
    history.textContent = parts.join(" · ");
    card.appendChild(history);
    var evidence = document.createElement("ul");
    evidence.className = "edr-finding-evidence";
    edrEvidenceLines(finding).forEach(function (line) {
      var item = document.createElement("li");
      item.textContent = line;
      evidence.appendChild(item);
    });
    card.appendChild(evidence);
    var recommendation = document.createElement("p");
    recommendation.className = "edr-finding-rec";
    recommendation.textContent = finding.recommendation || "";
    card.appendChild(recommendation);
    return card;
  }

  function edrFindingSource(finding) {
    if (finding.source) {
      var country = countryName(finding.country);
      return finding.source + (country ? " · " + country : "");
    }
    if (finding.success_source) {
      var successCountry = countryName(finding.success_country);
      return "success source " + finding.success_source + (successCountry ? " · " + successCountry : "");
    }
    return "distributed sources";
  }

  function edrEvidenceLines(finding) {
    var evidence = finding.evidence || {};
    var lines = [];
    if (finding.kind === "slow_authentication") {
      lines.push(
        "Failures: " +
          number(evidence.failures) +
          " over " +
          plural(evidence.active_buckets || 0, "active minute", "active minutes") +
          "; span " +
          number(evidence.span_minutes) +
          " minutes."
      );
      if (evidence.first_failure_ms) {
        lines.push(
          "Failure range: " +
            utcMinute(evidence.first_failure_ms) +
            "–" +
            (evidence.last_failure_ms ? utcMinute(evidence.last_failure_ms) : "unknown") +
            " UTC."
        );
      }
      lines.push(
        "Maximum " +
          number(evidence.max_failures_per_minute) +
          " failure(s) per minute; baseline " +
          formatDecimal(evidence.baseline_failures_per_hour, 1) +
          " failures/hour (z " +
          formatDecimal(evidence.baseline_z, 1) +
          ")."
      );
    } else if (finding.kind === "reverse_brute_force") {
      lines.push(
        "Failures: " +
          number(evidence.failures) +
          " from an estimated " +
          number(Math.round(evidence.distinct_sources || 0)) +
          " distinct sources; mean " +
          formatDecimal(evidence.mean_failures_per_source, 2) +
          " per source."
      );
      if (evidence.first_failure_ms) {
        lines.push(
          "Failure range: " +
            utcMinute(evidence.first_failure_ms) +
            "–" +
            (evidence.last_failure_ms ? utcMinute(evidence.last_failure_ms) : "unknown") +
            " UTC."
        );
      }
      if (evidence.top_path) {
        lines.push(
          "Top failure path: " +
            evidence.top_path +
            " (" +
            formatDecimal((Number(evidence.top_path_share) || 0) * 100, 1) +
            "% of failures)."
        );
      }
      lines.push(
        "Baseline " +
          formatDecimal(evidence.baseline_failures_per_hour, 1) +
          " failures/hour (z " +
          formatDecimal(evidence.baseline_z, 1) +
          ")."
      );
    } else if (finding.kind === "auth_success_after_failures") {
      lines.push(
        "Failures before the success: " +
          number(evidence.failures) +
          " over " +
          plural(evidence.active_buckets || 0, "active minute", "active minutes") +
          "; success at " +
          (evidence.success_ms ? utcMinute(evidence.success_ms) + " UTC" : "unknown") +
          "."
      );
      if (evidence.first_failure_ms) {
        lines.push(
          "Failure range: " +
            utcMinute(evidence.first_failure_ms) +
            "–" +
            (evidence.last_failure_ms ? utcMinute(evidence.last_failure_ms) : "unknown") +
            " UTC."
        );
      }
      lines.push(
        "Successful responses in the window: " +
          number(evidence.successes) +
          "; total source failures: " +
          number(evidence.total_failures) +
          "."
      );
    } else if (finding.kind === "campaign_success") {
      lines.push(
        "Failures: " +
          number(evidence.failures) +
          " from an estimated " +
          number(Math.round(evidence.distinct_sources || 0)) +
          " distinct sources; mean " +
          formatDecimal(evidence.mean_failures_per_source, 2) +
          " per source."
      );
      if (evidence.first_failure_ms) {
        lines.push(
          "Failure range: " +
            utcMinute(evidence.first_failure_ms) +
            "–" +
            (evidence.last_failure_ms ? utcMinute(evidence.last_failure_ms) : "unknown") +
            " UTC."
        );
      }
      if (evidence.success_source) {
        lines.push(
          "Success source: " +
            evidence.success_source +
            " at " +
            (evidence.success_ms ? utcMinute(evidence.success_ms) + " UTC" : "unknown") +
            "; its last failure " +
            (evidence.source_last_failure_ms
              ? utcMinute(evidence.source_last_failure_ms) + " UTC"
              : "unknown") +
            "."
        );
      }
    }
    if (!lines.length) {
      lines.push("No structured evidence is available for this finding.");
    }
    return lines;
  }

  function edrEmpty(message) {
    var node = document.createElement("p");
    node.className = "edr-empty";
    node.textContent = message;
    return node;
  }

  function renderEdrTelemetry(view) {
    var telemetry = view.telemetry || {};
    setEdrTelemetry("edr-failure-telemetry", telemetry.failure, false);
    setEdrTelemetry("edr-success-telemetry", telemetry.success, true);
    var summary = telemetry.summary;
    if (!summary) {
      text($("edr-summary"), "Unavailable");
    } else {
      var parts = [
        "Requests " + number(summary.requests),
        "auth failures " + number(summary.auth_failures),
        "auth successes " + number(summary.auth_successes),
        "distinct failing sources " +
          (summary.distinct_auth_sources === null || summary.distinct_auth_sources === undefined
            ? "unknown"
            : number(summary.distinct_auth_sources)),
        "baseline " + number(summary.baseline_hours) + " hours",
      ];
      if (summary.auth_paths && summary.auth_paths.length) {
        parts.push(
          "top failure paths " +
            summary.auth_paths
              .map(function (value) {
                return value.path + " (" + number(value.count) + ")";
              })
              .join(", ")
        );
      }
      text($("edr-summary"), parts.join(" · "));
    }
    var task = view.task || {};
    var taskParts = [
      "Snapshots " + number(task.snapshots),
      "retained " + number(task.retained_minutes) + " minutes / " + number(task.retained_hours) + " hours",
    ];
    if (task.baseline_warming_up) {
      taskParts.push("baseline warming up");
    }
    text($("edr-task-detail"), taskParts.join(" · "));
    var notes = $("edr-notes");
    emptyNode(notes);
    var values = (view.notes || []).slice();
    if (view.error) {
      values.unshift("EDR task error: " + view.error);
    }
    if (!values.length) {
      var item = document.createElement("li");
      item.textContent = "No notes for the last evaluation.";
      notes.appendChild(item);
    } else {
      values.forEach(function (value) {
        var entry = document.createElement("li");
        entry.textContent = value;
        notes.appendChild(entry);
      });
    }
  }

  function setEdrTelemetry(id, value, success) {
    var node = $(id);
    var label;
    if (value === "present") {
      label = "Present";
    } else if (value === "partial") {
      label = "Incomplete (lower bound)";
    } else {
      label = success ? "Missing or not configured" : "Missing";
    }
    text(node, label);
    node.classList.toggle("is-unavailable", value !== "present");
  }

  function renderEdrDisabled(data) {
    var config = data.config || {};
    text($("edr-task-chip"), "EDR disabled");
    text($("edr-last-evaluated"), "No evaluation");
    text($("edr-next-evaluation"), "Next evaluation unavailable");
    text(
      $("edr-schedule"),
      "Window " + formatDurationMs(config.window_ms) + " · baseline " + formatDurationMs(config.baseline_ms)
    );
    text(
      $("edr-status-note"),
      "EDR is disabled. Enable console.edr in the Kunato configuration and restart the console service. No lamp can be evaluated."
    );
    text($("edr-live-summary"), "EDR is disabled; no detector was evaluated.");
    renderEdrUnavailableLamps("EDR is disabled by console.edr.enabled: false.");
    var list = $("edr-findings-list");
    emptyNode(list);
    list.appendChild(edrEmpty("EDR is disabled; no findings are evaluated."));
    text($("edr-findings-note"), "Enable console.edr to run the hourly analysis.");
    text($("edr-failure-telemetry"), "Not collected");
    text($("edr-success-telemetry"), "Not collected");
    $("edr-failure-telemetry").classList.add("is-unavailable");
    $("edr-success-telemetry").classList.add("is-unavailable");
    text($("edr-summary"), "Unavailable");
    text($("edr-task-detail"), "EDR task is not running.");
    var notes = $("edr-notes");
    emptyNode(notes);
    var item = document.createElement("li");
    item.textContent = "Set console.edr.enabled: true to evaluate the four detectors.";
    notes.appendChild(item);
  }

  function renderEdrStarting(data) {
    var config = data.config || {};
    text($("edr-task-chip"), "EDR starting");
    text($("edr-last-evaluated"), "No evaluation yet");
    text($("edr-next-evaluation"), "Next evaluation unavailable");
    text(
      $("edr-schedule"),
      "Window " + formatDurationMs(config.window_ms) + " · baseline " + formatDurationMs(config.baseline_ms)
    );
    text($("edr-status-note"), "Waiting for the EDR task to publish its first state.");
    text($("edr-live-summary"), "Waiting for the EDR task to publish its first state.");
    renderEdrUnavailableLamps("No EDR state has been published yet.");
    var list = $("edr-findings-list");
    emptyNode(list);
    list.appendChild(edrEmpty("Waiting for the first hourly evaluation."));
    text($("edr-findings-note"), "The latest hourly window only.");
    text($("edr-failure-telemetry"), "Unavailable");
    text($("edr-success-telemetry"), "Unavailable");
    text($("edr-summary"), "Unavailable");
    text($("edr-task-detail"), "EDR task is starting.");
    var notes = $("edr-notes");
    emptyNode(notes);
    var item = document.createElement("li");
    item.textContent = "Waiting for the console EDR task.";
    notes.appendChild(item);
  }

  function renderEdrError(message) {
    if (state.edr && state.edr.view) {
      text(
        $("edr-status-note"),
        "The console could not refresh the EDR state: " +
          message +
          ". Showing the last received state."
      );
      return;
    }
    text($("edr-task-chip"), "EDR unavailable");
    text($("edr-status-note"), "The console could not read the EDR state: " + message);
    text($("edr-live-summary"), "The EDR state is unavailable.");
    renderEdrUnavailableLamps("The EDR state is unavailable.");
    var list = $("edr-findings-list");
    emptyNode(list);
    list.appendChild(edrEmpty("The EDR state is unavailable."));
    var notes = $("edr-notes");
    emptyNode(notes);
    var item = document.createElement("li");
    item.textContent = message;
    notes.appendChild(item);
  }

  function showView(name) {
    if (name !== "live" && state.sourceDetail.open) {
      closeSourceDetail(true);
    }
    state.view = name;
    Object.keys(view).forEach(function (key) {
      view[key].hidden = key !== name;
    });
    document.querySelectorAll(".nav-item").forEach(function (item) {
      item.classList.toggle("is-active", item.dataset.view === name);
    });
    var titles = {
      live: "Real-time monitor",
      metrics: "Metrics",
      edr: "EDR",
    };
    var subtitles = {
      live: "Latest state from the WAF; UTC timestamps. Read-only.",
      metrics:
        "Retained UTC history; chart display grain, storage grain, and coverage are shown with the data.",
      edr: "Hourly authentication-abuse analysis over the latest evaluated window. Read-only.",
    };
    text($("page-title"), titles[name] || "EDR");
    text($("page-subtitle"), subtitles[name] || "");
    if (name === "metrics") {
      loadMetrics();
    } else if (name === "edr") {
      loadEdr();
    } else {
      updateEventAges();
      updateTopology();
      updateTopologyScrollHint();
    }
  }

  document.querySelectorAll(".nav-item").forEach(function (item) {
    item.addEventListener("click", function () {
      showView(item.dataset.view);
    });
  });

  document.querySelectorAll("[data-period-ms]").forEach(function (button) {
    button.addEventListener("click", function () {
      var rangeMs = Number(button.dataset.periodMs);
      if (!rangeMs || state.rangeMs === rangeMs) {
        return;
      }
      state.rangeMs = rangeMs;
      syncPeriodButtons();
      loadMetrics();
    });
  });

  $("refresh").addEventListener("click", loadMetrics);

  $("sign-out").addEventListener("click", function () {
    fetch("/api/v1/session", { method: "DELETE", credentials: "same-origin" }).finally(function () {
      window.location.replace("/login");
    });
  });

  document.querySelectorAll("[data-topo-mode]").forEach(function (button) {
    button.addEventListener("click", function () {
      setTopologyMode(button.getAttribute("data-topo-mode"));
    });
  });

  $("topo-return").addEventListener("click", function () {
    setTopologyMode("realtime");
  });

  $("topo-new").addEventListener("click", function () {
    setTopologyMode("realtime");
  });

  $("source-drawer-close").addEventListener("click", function () {
    closeSourceDetail();
  });
  $("source-drawer-refresh").addEventListener("click", refreshSourceDetail);
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape" && state.sourceDetail.open) {
      event.preventDefault();
      closeSourceDetail();
    }
  });

  syncPeriodButtons();

  buildTopology();
  updateTopologyScrollHint();
  window.requestAnimationFrame(updateTopologyScrollHint);

  var topoResizeTimer = null;
  window.addEventListener("resize", function () {
    clearTimeout(topoResizeTimer);
    topoResizeTimer = setTimeout(updateTopologyScrollHint, 120);
  });

  setInterval(updateEventAges, 10000);
  setInterval(function () {
    if (state.view === "edr" && !document.hidden) {
      loadEdr();
    }
  }, 60000);
  document.addEventListener("visibilitychange", function () {
    if (!document.hidden) {
      updateEventAges();
      if (state.view === "edr") {
        loadEdr();
      }
    }
  });

  fetch("/api/v1/session", { credentials: "same-origin" })
    .then(function (response) {
      return response.json();
    })
    .then(function (session) {
      state.session = session;
      if (session.enabled && !session.authenticated) {
        window.location.replace("/login");
        return;
      }
      updateHeader();
      connectLive();
    })
    .catch(function () {
      banner("The console service is not reachable.", "bad");
    });
})();
