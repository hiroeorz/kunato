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
    clockOffsetMs: 0,
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

  function intervalLabel(bucket) {
    var start = utcMinute(bucket.start_ms);
    var duration = GRAIN_MS[bucket.grain] || 0;
    if (!duration) {
      return start + " UTC";
    }
    var end = utcMinute(bucket.start_ms + duration);
    if (start.slice(0, 10) === end.slice(0, 10)) {
      return start + "–" + end.slice(11) + " UTC";
    }
    return start + " – " + end + " UTC";
  }

  function bucketCounter(bucket, name) {
    var stats = bucket.counters ? bucket.counters[name] : null;
    return stats && stats.known_minutes ? stats.sum : null;
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
      row.className = ageClass(event.occurred_at_ms);
      row.setAttribute("data-occurred-at", String(event.occurred_at_ms));
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
    if (snapshot && typeof snapshot.observed_at_ms === "number") {
      state.clockOffsetMs = snapshot.observed_at_ms - Date.now();
    }
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
        ? plural(buckets.length, "interval", "intervals") + "; " + (partial ? "partial coverage" : "complete intervals only for rates")
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
      var label = String(bucket.grain).replace(/_/g, " ");
      if (grains.indexOf(label) === -1) {
        grains.push(label);
      }
    });
    var meta = [];
    meta.push("grain: " + (grains.length ? grains.join(" → ") : "unavailable"));
    if (first !== null) {
      meta.push("available: " + utc(first) + " to " + utc(last));
    }
    if (data.truncated) {
      meta.push("response truncated at " + plural(data.returned, "interval", "intervals") + "; narrow the range");
    }
    if (data.pending_minutes) {
      meta.push(plural(data.pending_minutes, "minute", "minutes") + " awaiting materialization");
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
    var height = 244;
    var left = 48;
    var right = 12;
    var bottom = 46;
    var top = 12;
    var innerWidth = width - left - right;
    var innerHeight = height - top - bottom;
    var max = 1;
    var series = buckets.map(function (bucket) {
      var requests = bucketCounter(bucket, "requests");
      var rejected = bucketCounter(bucket, "rejected_requests");
      max = Math.max(max, requests || 0, rejected || 0);
      return {
        bucket: bucket,
        requests: requests,
        rejected: rejected,
        logged: bucketCounter(bucket, "log_requests"),
        failures: bucketCounter(bucket, "upstream_connection_failures"),
        timeouts: bucketCounter(bucket, "upstream_timeouts"),
        decoy: bucketCounter(bucket, "decoy_credential_use_requests"),
        incomplete: Boolean(bucket.coverage && bucket.coverage.incomplete),
      };
    });
    var step = innerWidth / series.length;
    var bar = Math.max(1, Math.min(step * 0.7, 48));

    var ns = "http://www.w3.org/2000/svg";
    var svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 " + width + " " + height);
    svg.setAttribute("role", "img");
    svg.setAttribute("tabindex", "0");
    svg.setAttribute("focusable", "true");
    svg.setAttribute(
      "aria-label",
      "Requests and rejections per UTC interval. Use the left and right arrow keys to inspect intervals."
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
      tick.textContent = new Intl.NumberFormat().format(label);
      svg.appendChild(tick);
    }

    line(top, max);
    line(top + innerHeight / 2, Math.round(max / 2));
    line(top + innerHeight, 0);

    var hoverBand = document.createElementNS(ns, "rect");
    hoverBand.setAttribute("y", top);
    hoverBand.setAttribute("height", innerHeight);
    hoverBand.setAttribute("fill", "#f2f5f9");
    hoverBand.setAttribute("pointer-events", "none");
    hoverBand.setAttribute("visibility", "hidden");
    svg.appendChild(hoverBand);

    series.forEach(function (point, index) {
      var x = left + index * step + (step - bar) / 2;
      var requests = point.requests || 0;
      var rejected = point.rejected || 0;
      var requestHeight = (requests / max) * innerHeight;
      var rejectHeight = (rejected / max) * innerHeight;
      var requestsBar = document.createElementNS(ns, "rect");
      requestsBar.setAttribute("x", x);
      requestsBar.setAttribute("y", top + innerHeight - requestHeight);
      requestsBar.setAttribute("width", bar);
      requestsBar.setAttribute("height", Math.max(0, requestHeight));
      requestsBar.setAttribute("fill", "#829ab3");
      svg.appendChild(requestsBar);
      var rejectedBar = document.createElementNS(ns, "rect");
      rejectedBar.setAttribute("x", x);
      rejectedBar.setAttribute("y", top + innerHeight - rejectHeight);
      rejectedBar.setAttribute("width", bar);
      rejectedBar.setAttribute("height", Math.max(0, rejectHeight));
      rejectedBar.setAttribute("fill", "#dc9b6c");
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
      hoverBand.setAttribute("x", left + index * step);
      hoverBand.setAttribute("width", Math.max(1, step));
      hoverBand.setAttribute("visibility", "visible");
      if (index !== tooltipIndex) {
        tooltipIndex = index;
        tooltip.textContent = "";
        var heading = document.createElement("p");
        heading.className = "chart-tooltip-time";
        heading.textContent = intervalLabel(point.bucket);
        tooltip.appendChild(heading);
        var list = document.createElement("dl");
        list.className = "chart-tooltip-list";
        addTooltipRow(list, "Requests", number(point.requests));
        addTooltipRow(list, "Rejected", number(point.rejected));
        addTooltipRow(list, "Rejection rate", percent(point.rejected, point.requests));
        addTooltipRow(list, "LOG detections", number(point.logged));
        addTooltipRow(list, "Upstream failures", number(point.failures));
        addTooltipRow(list, "Upstream timeouts", number(point.timeouts));
        addTooltipRow(list, "Decoy use", number(point.decoy));
        tooltip.appendChild(list);
        if (point.incomplete) {
          var note = document.createElement("p");
          note.className = "chart-tooltip-note";
          note.textContent = "Partial interval coverage";
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
        anchorX = svgFrame.left - frame.left + ((left + (index + 0.5) * step) / width) * svgFrame.width;
        anchorY = svgFrame.top - frame.top + ((top + innerHeight / 2) / height) * svgFrame.height;
      }
      var x = anchorX + 14;
      var y = anchorY - tooltip.offsetHeight - 12;
      if (x + tooltip.offsetWidth > host.clientWidth - 8) {
        x = anchorX - tooltip.offsetWidth - 14;
      }
      if (x < 8) {
        x = 8;
      }
      if (y < 8) {
        y = anchorY + 18;
      }
      if (y + tooltip.offsetHeight > host.clientHeight - 8) {
        y = Math.max(8, host.clientHeight - tooltip.offsetHeight - 8);
      }
      tooltip.style.left = x + "px";
      tooltip.style.top = y + "px";
    }

    function hideTooltip() {
      tooltipIndex = -1;
      tooltip.hidden = true;
      hoverBand.setAttribute("visibility", "hidden");
    }

    function inspectHover(event) {
      var frame = svg.getBoundingClientRect();
      if (!frame.width) {
        return;
      }
      var x = ((event.clientX - frame.left) / frame.width) * width;
      if (x < left || x > left + innerWidth) {
        hideTooltip();
        return;
      }
      var index = Math.floor((x - left) / step);
      index = Math.max(0, Math.min(series.length - 1, index));
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

    var labelCount = Math.max(2, Math.min(7, Math.floor(innerWidth / 120)));
    labelCount = Math.min(labelCount, series.length);
    var used = {};
    for (var slot = 0; slot < labelCount; slot += 1) {
      var labelIndex = Math.round((slot * (series.length - 1)) / Math.max(1, labelCount - 1));
      if (used[labelIndex]) {
        continue;
      }
      used[labelIndex] = true;
      var point = series[labelIndex];
      var x = left + (labelIndex + 0.5) * step;
      var anchor = "middle";
      if (labelIndex === 0) {
        x = left;
        anchor = "start";
      } else if (labelIndex === series.length - 1) {
        x = left + innerWidth;
        anchor = "end";
      }
      var tick = document.createElementNS(ns, "line");
      tick.setAttribute("x1", x);
      tick.setAttribute("x2", x);
      tick.setAttribute("y1", top + innerHeight);
      tick.setAttribute("y2", top + innerHeight + 5);
      tick.setAttribute("stroke", "#d9dfe7");
      svg.appendChild(tick);
      var label = document.createElementNS(ns, "text");
      label.setAttribute("x", x);
      label.setAttribute("y", top + innerHeight + 20);
      label.setAttribute("text-anchor", anchor);
      label.textContent = utcMinute(point.bucket.start_ms);
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
    legend.innerHTML = '<span class="legend-requests">requests</span><span class="legend-rejected">rejected</span>';
    host.appendChild(legend);
    host.appendChild(tooltip);
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
    } else {
      updateEventAges();
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

  setInterval(updateEventAges, 10000);
  document.addEventListener("visibilitychange", function () {
    if (!document.hidden) {
      updateEventAges();
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
