"use strict";

(function () {
  var state = {
    view: "live",
    session: { enabled: false, authenticated: true },
    latest: null,
    previous: null,
    events: new Map(),
    generation: null,
    rangeMs: 86400000,
    metrics: null,
    correlations: null,
    connected: false,
    source: null,
  };

  var view = {
    live: document.getElementById("live-view"),
    metrics: document.getElementById("metrics-view"),
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

  function setConnection(connected) {
    state.connected = connected;
    var dot = $("collection-dot");
    var label = $("collection-text");
    var snapshot = state.latest;
    var collection = snapshot ? snapshot.collection : null;
    if (!connected) {
      dot.className = "dot dot-bad";
      label.textContent = "Live stream disconnected";
      return;
    }
    if (!collection) {
      dot.className = "dot dot-unknown";
      label.textContent = "Waiting for collection";
      return;
    }
    if (!collection.connected) {
      dot.className = "dot dot-bad";
      label.textContent = "WAF snapshot source unavailable";
      return;
    }
    if (collection.storage_error) {
      dot.className = "dot dot-warn";
      label.textContent = "Collecting; storage error";
      return;
    }
    dot.className = "dot dot-ok";
    label.textContent = "Collecting";
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
      text($("live-requests"), number(requests));
      text($("live-rejected"), number(rejected));
      text($("live-logged"), number(logged));
      text($("live-connections"), number(snapshot.active_connections));
      text($("live-upstream"), number(failures === null && timeouts === null ? null : (failures || 0) + (timeouts || 0)));
      text($("live-decoy"), number(decoy));
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

    var collection = latest ? latest.collection : null;
    var writer = latest ? latest.writer : null;
    var health = $("live-health");
    health.innerHTML = "";
    function row(name, value, level) {
      var dt = document.createElement("dt");
      dt.textContent = name;
      var dd = document.createElement("dd");
      dd.textContent = value;
      if (level) {
        dd.className = level;
      }
      health.appendChild(dt);
      health.appendChild(dd);
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
      cell.colSpan = 8;
      cell.className = "muted";
      cell.textContent = "No events received yet.";
      empty.appendChild(cell);
      body.appendChild(empty);
      return;
    }
    events.slice(0, 200).forEach(function (event) {
      var row = document.createElement("tr");
      function add(value, className) {
        var cell = document.createElement("td");
        cell.textContent = value === null || value === undefined || value === "" ? "unrecorded" : String(value);
        if (className) {
          cell.className = className;
        }
        row.appendChild(cell);
      }
      add(utc(event.occurred_at_ms));
      add(String(event.kind).replace(/_/g, " "));
      add(String(event.disposition).toUpperCase());
      add(event.reason || (event.category ? event.category + (event.rule ? "/" + event.rule : "") : null));
      add(event.method);
      add(event.path);
      add(event.site);
      add(event.client || event.peer);
      body.appendChild(row);
    });
  }

  function applyState(data) {
    var snapshot = data.snapshot;
    state.latest = data;
    if (snapshot && snapshot.source) {
      if (state.generation !== snapshot.source.generation) {
        state.generation = snapshot.source.generation;
        state.events.clear();
        state.previous = null;
      }
      (snapshot.events || []).forEach(function (event) {
        state.events.set(snapshot.source.generation + ":" + event.sequence, event);
      });
      while (state.events.size > 200) {
        var oldest = state.events.keys().next();
        state.events.delete(oldest.value);
      }
    }
    updateHeader();
    setConnection(state.connected);
    if (state.view === "live") {
      renderLive();
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
    var requests = sumMetric(buckets, "requests");
    var rejected = sumMetric(buckets, "rejected_requests");
    var logged = sumMetric(buckets, "log_requests");
    var failures = sumMetric(buckets, "upstream_connection_failures");
    var timeouts = sumMetric(buckets, "upstream_timeouts");
    var decoy = sumMetric(buckets, "decoy_credential_use_requests");

    text($("metrics-requests"), number(requests.total));
    text($("metrics-rejected"), number(rejected.total));
    text($("metrics-logged"), number(logged.total));
    text($("metrics-upstream"), number(failures.total === null && timeouts.total === null ? null : (failures.total || 0) + (timeouts.total || 0)));
    text($("metrics-decoy"), number(decoy.total));
    text($("metrics-rejection-rate"), percent(rejected.total, requests.total));

    var partial = requests.incomplete || rejected.incomplete;
    text(
      $("metrics-requests-detail"),
      buckets.length
        ? buckets.length + " intervals; " + (partial ? "partial coverage" : "complete intervals only for rates")
        : "no retained intervals in this range"
    );
    text(
      $("metrics-rejected-detail"),
      rejected.total === null ? "no measured rejections" : "counted once per request"
    );

    var first = buckets.length ? buckets[0].start_ms : null;
    var grainMs = {
      minute: 60000,
      five_minutes: 300000,
      ten_minutes: 600000,
      twenty_minutes: 1200000,
      hour: 3600000,
    };
    var last = buckets.length
      ? buckets[buckets.length - 1].start_ms + (grainMs[buckets[buckets.length - 1].grain] || 0)
      : null;
    var grain = buckets.length ? String(buckets[0].grain).replace(/_/g, " ") : "unavailable";
    var meta = [];
    meta.push("grain: " + grain);
    if (first !== null) {
      meta.push("available: " + utc(first) + " to " + utc(last));
    }
    if (data.truncated) {
      meta.push("response truncated at " + number(data.returned) + " intervals; narrow the range");
    }
    if (data.pending_minutes) {
      meta.push(number(data.pending_minutes) + " minutes awaiting materialization");
    }
    if (data.oldest_available_ms !== null && data.oldest_available_ms !== undefined) {
      meta.push("oldest retained: " + utc(data.oldest_available_ms));
    }
    meta.push("expiry: " + utc(data.expiry_ms));
    text($("metrics-meta"), meta.join(" | "));

    renderChart(buckets);
    renderReasons(buckets);
    renderCorrelations();
  }

  function renderChart(buckets) {
    var host = $("chart");
    host.innerHTML = "";
    if (!buckets.length) {
      host.textContent = "No retained intervals in this range.";
      host.className = "chart muted";
      return;
    }
    host.className = "chart";
    var width = 960;
    var height = 220;
    var left = 48;
    var bottom = 24;
    var top = 12;
    var innerWidth = width - left - 12;
    var innerHeight = height - top - bottom;
    var max = 1;
    var series = buckets.map(function (bucket) {
      var requests = bucket.counters && bucket.counters.requests ? bucket.counters.requests.sum : 0;
      var rejected = bucket.counters && bucket.counters.rejected_requests ? bucket.counters.rejected_requests.sum : 0;
      max = Math.max(max, requests, rejected);
      return { requests: requests, rejected: rejected, start: bucket.start_ms };
    });
    var step = innerWidth / series.length;
    var bar = Math.max(1, step * 0.7);

    var ns = "http://www.w3.org/2000/svg";
    var svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 " + width + " " + height);
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", "Requests and rejections per interval");

    function line(y, label) {
      var axis = document.createElementNS(ns, "line");
      axis.setAttribute("x1", left);
      axis.setAttribute("x2", width - 12);
      axis.setAttribute("y1", y);
      axis.setAttribute("y2", y);
      axis.setAttribute("stroke", "#2a323d");
      svg.appendChild(axis);
      var tick = document.createElementNS(ns, "text");
      tick.setAttribute("x", 4);
      tick.setAttribute("y", y + 4);
      tick.textContent = new Intl.NumberFormat().format(label);
      svg.appendChild(tick);
    }

    line(top, max);
    line(top + innerHeight / 2, Math.round(max / 2));
    line(top + innerHeight, 0);

    series.forEach(function (point, index) {
      var x = left + index * step + (step - bar) / 2;
      var requestHeight = (point.requests / max) * innerHeight;
      var rejectHeight = (point.rejected / max) * innerHeight;
      var requestsBar = document.createElementNS(ns, "rect");
      requestsBar.setAttribute("x", x);
      requestsBar.setAttribute("y", top + innerHeight - requestHeight);
      requestsBar.setAttribute("width", bar);
      requestsBar.setAttribute("height", Math.max(0, requestHeight));
      requestsBar.setAttribute("fill", "#6ea8fe");
      var title = document.createElementNS(ns, "title");
      title.textContent =
        utc(point.start) +
        ": " +
        number(point.requests) +
        " requests, " +
        number(point.rejected) +
        " rejected";
      requestsBar.appendChild(title);
      svg.appendChild(requestsBar);
      var rejectedBar = document.createElementNS(ns, "rect");
      rejectedBar.setAttribute("x", x);
      rejectedBar.setAttribute("y", top + innerHeight - rejectHeight);
      rejectedBar.setAttribute("width", bar);
      rejectedBar.setAttribute("height", Math.max(0, rejectHeight));
      rejectedBar.setAttribute("fill", "rgba(255,107,107,0.85)");
      svg.appendChild(rejectedBar);
    });

    host.appendChild(svg);
    var legend = document.createElement("div");
    legend.className = "legend";
    legend.innerHTML = '<span class="legend-requests">requests</span><span class="legend-rejected">rejected</span>';
    host.appendChild(legend);
  }

  var REASONS = [
    "rule", "response_rule", "rate_limit", "ban", "overload", "client_identity",
    "host", "admin_access", "body", "decode", "form", "upload", "graphql", "saml",
    "php_request", "php_response", "hardening", "jwt", "decoy", "behavior",
    "protocol", "response_inspection",
  ];

  function renderReasons(buckets) {
    var body = $("reasons");
    body.innerHTML = "";
    var totals = {};
    var rejected = 0;
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
      if (bucket.counters && bucket.counters.rejected_requests) {
        rejected += bucket.counters.rejected_requests.sum;
      }
    });
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
      share.textContent = rejected ? ((100 * totals[reason]) / rejected).toFixed(1) + "%" : "Unavailable";
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

  function loadMetrics() {
    var until = Date.now();
    var from = until - state.rangeMs;
    text($("metrics-meta"), "Loading history...");
    var query = "?from_ms=" + from + "&until_ms=" + until + "&limit=128";
    fetch("/api/v1/history" + query, { credentials: "same-origin" })
      .then(function (response) {
        if (response.status === 401) {
          window.location.replace("/login");
          throw new Error("unauthorized");
        }
        if (!response.ok) {
          throw new Error("history request failed with " + response.status);
        }
        return response.json();
      })
      .then(function (page) {
        state.metrics = page;
        renderMetrics();
      })
      .catch(function (error) {
        if (error.message !== "unauthorized") {
          text($("metrics-meta"), "History unavailable: " + error.message);
        }
      });

    fetch("/api/v1/correlations" + query, { credentials: "same-origin" })
      .then(function (response) {
        if (!response.ok) {
          throw new Error("correlation request failed with " + response.status);
        }
        return response.json();
      })
      .then(function (page) {
        state.correlations = page;
        renderCorrelations();
      })
      .catch(function () {
        state.correlations = null;
        renderCorrelations();
      });
  }

  function showView(name) {
    state.view = name;
    Object.keys(view).forEach(function (key) {
      view[key].hidden = key !== name;
    });
    document.querySelectorAll(".nav-item").forEach(function (item) {
      item.classList.toggle("is-active", item.dataset.view === name);
    });
    text($("page-title"), name === "live" ? "Real-time monitor" : "Metrics");
    text(
      $("page-subtitle"),
      name === "live"
        ? "Latest state from the WAF; UTC timestamps. Read-only."
        : "Retained UTC history; grain and coverage are shown with the data."
    );
    if (name === "metrics") {
      loadMetrics();
    }
  }

  document.querySelectorAll(".nav-item").forEach(function (item) {
    item.addEventListener("click", function () {
      showView(item.dataset.view);
    });
  });

  $("range").addEventListener("change", function (event) {
    state.rangeMs = Number(event.target.value);
    loadMetrics();
  });
  $("refresh").addEventListener("click", loadMetrics);

  $("sign-out").addEventListener("click", function () {
    fetch("/api/v1/session", { method: "DELETE", credentials: "same-origin" }).finally(function () {
      window.location.replace("/login");
    });
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
