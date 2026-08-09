(() => {
  "use strict";

  const root = document.documentElement;
  const themeButton = document.getElementById("theme-toggle");
  const flowsBody = document.getElementById("flows");
  const tableWrap = flowsBody.closest(".table-wrap");
  const flowsFoot = document.getElementById("flows-foot");
  const loadOlderButton = document.getElementById("load-older");
  const paginationStatus = document.getElementById("pagination-status");
  const detailTemplate = document.getElementById("detail-template");
  const empty = document.getElementById("empty");
  const connection = document.getElementById("connection");
  const filterForm = document.getElementById("flow-filters");
  const rows = new Map();
  const flowItems = new Map();
  const collapsedSessions = new Set();
  const knownHosts = new Set();
  const hostList = document.getElementById("host-list");
  const PAGE_SIZE = 100;
  const MAX_ROWS = 2000;
  // Distance from the top of the list still treated as "following the feed".
  const FEED_TOP_TOLERANCE = 40;
  let events;
  let selectedID = null;
  let detailRow = null;
  let nextBeforeID = 0;
  let hasMore = true;
  let loading = false;
  let rebuildScheduled = false;
  // Set by a live arrival, consumed by the next rebuild: only prepends may snap
  // the list to the top, never a row toggle, drawer, or older-history page.
  let prependedSinceRebuild = false;
  let observer = null;

  const toggleFeedButton = document.getElementById("toggle-feed");
  let isPaused = false;
  // Only a pause the drawer itself introduced may be undone when it closes; an
  // explicit operator pause must survive inspecting a flow.
  let pausedByDetail = false;

  const savedTheme = localStorage.getItem("veilgate-theme");
  if (savedTheme === "light" || savedTheme === "dark") root.dataset.theme = savedTheme;
  updateThemeLabel();
  loadFilters(new URLSearchParams(location.search));

  themeButton.addEventListener("click", () => {
    root.dataset.theme = root.dataset.theme === "dark" ? "light" : "dark";
    localStorage.setItem("veilgate-theme", root.dataset.theme);
    updateThemeLabel();
  });
  loadOlderButton.addEventListener("click", () => loadPage(false));
  filterForm.addEventListener("submit", event => {
    event.preventDefault();
    applyFilters();
  });
  document.getElementById("reset-filters").addEventListener("click", () => {
    filterForm.reset();
    applyFilters();
  });
  if (toggleFeedButton) {
    toggleFeedButton.addEventListener("click", toggleFeed);
  }

  function updateThemeLabel() {
    themeButton.textContent = root.dataset.theme === "dark" ? "Use light theme" : "Use dark theme";
  }

  function loadFilters(params) {
    for (const name of ["client", "host", "decision", "mode"]) {
      const control = filterForm.elements.namedItem(name);
      control.value = params.get(name) || "";
    }
  }

  function filterParams() {
    const params = new URLSearchParams();
    for (const name of ["client", "host", "decision", "mode"]) {
      const value = filterForm.elements.namedItem(name).value.trim();
      if (value) params.set(name, value);
    }
    return params;
  }

  function applyFilters() {
    const params = filterParams();
    history.replaceState(null, "", params.size ? `?${params}` : location.pathname);
    closeDetail();
    flowsBody.replaceChildren();
    rows.clear();
    flowItems.clear();
    collapsedSessions.clear();
    nextBeforeID = 0;
    hasMore = true;
    empty.hidden = false;
    empty.querySelector("h3").textContent = "No matching traffic";
    empty.querySelector("p").textContent = "Adjust the filters or wait for a matching authenticated request.";
    if (events) events.close();
    // Applying or resetting filters is an explicit intent to see fresh traffic.
    if (isPaused) { resumeFeed(); return; }
    loadPage(true);
    connectEvents(params);
  }

  function duration(ns) {
    const ms = ns / 1e6;
    if (ms < 1000) return `${Math.round(ms)} ms`;
    return `${(ms / 1000).toFixed(2)} s`;
  }

  function bytes(value) {
    if (value < 1024) return `${value} B`;
    if (value < 1048576) return `${(value / 1024).toFixed(1)} KiB`;
    return `${(value / 1048576).toFixed(1)} MiB`;
  }

  function cell(row, label, text, className) {
    const td = document.createElement("td");
    td.dataset.label = label;
    if (className) td.className = className;
    td.textContent = text;
    row.appendChild(td);
    return td;
  }

  function trackHost(host) {
    if (!host || knownHosts.has(host)) return;
    knownHosts.add(host);
    updateHostDatalist();
  }

  function updateHostDatalist() {
    if (!hostList) return;
    const sorted = [...knownHosts].sort();
    hostList.replaceChildren(...sorted.map(h => {
      const option = document.createElement("option");
      option.value = h;
      return option;
    }));
  }

  function renderFlow(item, prepend) {
    if (item.host) trackHost(item.host);
    if (rows.has(item.id)) return;
    const row = document.createElement("tr");
    row.tabIndex = 0;
    row.setAttribute("aria-selected", "false");
    row.setAttribute("aria-expanded", "false");
    row.setAttribute("aria-label", `Inspect flow ${item.id}`);
    const timestamp = new Date(item.started_at);
    cell(row, "Time", timestamp.toLocaleTimeString(), "nowrap");
    cell(row, "Decision", item.decision, `decision ${item.decision}`);
    cell(row, "Client", item.client || "Unknown", "mono");
    const requestCell = cell(row, "Request", item.method, "mono");
    if (item.session_id && item.method === "CONNECT") {
      const toggle = document.createElement("button");
      toggle.type = "button";
      toggle.className = "session-toggle";
      toggle.setAttribute("aria-expanded", String(!collapsedSessions.has(item.session_id)));
      toggle.setAttribute("aria-label", "Collapse CONNECT session");
      toggle.textContent = "▾";
      toggle.addEventListener("click", event => {
        event.stopPropagation();
        const collapsed = collapsedSessions.has(item.session_id);
        if (collapsed) collapsedSessions.delete(item.session_id);
        else collapsedSessions.add(item.session_id);
        toggle.setAttribute("aria-expanded", String(collapsed));
        toggle.setAttribute("aria-label", collapsed ? "Collapse CONNECT session" : "Expand CONNECT session");
        toggle.textContent = collapsed ? "▾" : "▸";
        rebuildFlowOrder();
      });
      requestCell.prepend(toggle);
      row.classList.add("session-parent");
    } else if (item.session_id) {
      row.classList.add("session-child");
    }
    cell(row, "Target", `${item.host}:${item.port}${item.path || ""}`, "mono target");
    cell(row, "Mode", item.mode || "Unknown", "mode");
    cell(row, "Status", item.status || "—", "mono");
    cell(row, "Received", bytes(item.bytes_received), "nowrap");
    cell(row, "Duration", duration(item.duration_ns), "nowrap");
    row.addEventListener("click", () => selectFlow(item, row));
    row.addEventListener("keydown", event => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        selectFlow(item, row);
      }
    });
    row.dataset.id = item.id;
    row.dataset.sessionId = item.session_id || "";
    rows.set(item.id, row);
    flowItems.set(item.id, item);
    if (prepend) {
      row.classList.add("new");
      prependedSinceRebuild = true;
    }
    empty.hidden = true;
  }

  function evictOverflow() {
    if (flowItems.size <= MAX_ROWS) return;
    let removable = flowItems.size - MAX_ROWS;
    for (const id of [...flowItems.keys()].sort((a, b) => a - b)) {
      if (removable <= 0) break;
      if (id === selectedID) continue;
      flowItems.delete(id);
      rows.delete(id);
      removable--;
    }
  }

  function scheduleRebuild() {
    if (rebuildScheduled) return;
    rebuildScheduled = true;
    requestAnimationFrame(() => { rebuildScheduled = false; rebuildFlowOrder(); });
  }

  function rebuildFlowOrder() {
    const groups = new Map();
    for (const item of flowItems.values()) {
      const key = item.session_id || `flow-${item.id}`;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(item);
    }
    const orderedGroups = [...groups.entries()].sort(([, left], [, right]) => {
      const leftMax = Math.max(...left.map(item => new Date(item.started_at).getTime()));
      const rightMax = Math.max(...right.map(item => new Date(item.started_at).getTime()));
      return rightMax - leftMax;
    });
    const orderedRows = [];
    for (const [key, group] of orderedGroups) {
      const parent = group.find(item => item.method === "CONNECT");
      const children = group.filter(item => item !== parent).sort((a, b) => new Date(b.started_at) - new Date(a.started_at));
      if (parent) orderedRows.push(rows.get(parent.id));
      const collapsed = parent && collapsedSessions.has(key);
      for (const child of children) {
        const row = rows.get(child.id);
        row.hidden = Boolean(collapsed);
        orderedRows.push(row);
      }
    }
    const visibleRows = orderedRows.filter(Boolean);
    // Anchor the inline detail drawer directly beneath its selected row, and
    // close it if that row disappeared or was collapsed out of view.
    if (selectedID !== null && detailRow) {
      const selectedRow = rows.get(selectedID);
      const index = selectedRow ? visibleRows.indexOf(selectedRow) : -1;
      if (index === -1 || selectedRow.hidden) {
        closeDetail();
      } else {
        visibleRows.splice(index + 1, 0, detailRow);
      }
    }
    // Reordering detaches every row and live arrivals prepend above the
    // operator's position, so a raw scrollTop no longer points at the same
    // content. Anchor on a stable row and dropping focus is restored too.
    const focused = document.activeElement;
    const anchor = anchorRow(visibleRows);
    const anchorTop = anchor ? anchor.getBoundingClientRect().top : 0;
    const wrapLeft = tableWrap ? tableWrap.scrollLeft : 0;
    flowsBody.replaceChildren(...visibleRows);
    if (tableWrap) tableWrap.scrollLeft = wrapLeft;
    const prepended = prependedSinceRebuild;
    prependedSinceRebuild = false;
    if (anchor && anchor.isConnected) restoreAnchor(anchor, anchorTop);
    else if (prepended && atFeedTop()) snapToFeedTop();
    if (focused instanceof HTMLElement && focused.isConnected && document.activeElement !== focused) {
      focused.focus({preventScroll: true});
    }
    updatePaginationFoot();
  }

  // Prefer the row the operator is inspecting; otherwise the topmost row still
  // in view, so prepended live arrivals cannot push it out from under them.
  // Resting at the top is follow mode instead: no anchor, so arrivals land in
  // view and snapToFeedTop clears the sticky header. The tolerance keeps a
  // slightly nudged scroll position following.
  function anchorRow(visibleRows) {
    const selected = selectedID !== null ? rows.get(selectedID) : null;
    if (selected && selected.isConnected && !selected.hidden) return selected;
    if (atFeedTop()) return null;
    const top = tableWrap ? tableWrap.getBoundingClientRect().top : 0;
    for (const row of visibleRows) {
      if (row.hidden || !row.isConnected) continue;
      if (row.getBoundingClientRect().bottom > top) return row;
    }
    return null;
  }

  function atFeedTop() {
    const wrapAtTop = !tableWrap || tableWrap.scrollHeight <= tableWrap.clientHeight || tableWrap.scrollTop <= FEED_TOP_TOLERANCE;
    return wrapAtTop && window.scrollY <= FEED_TOP_TOLERANCE;
  }

  // Within the tolerance the sticky column header would cover the arrival, so
  // return to the exact top. Instant, matching restoreAnchor and reduced motion.
  function snapToFeedTop() {
    if (tableWrap && tableWrap.scrollHeight > tableWrap.clientHeight) tableWrap.scrollTop = 0;
    if (window.scrollY > 0) window.scrollTo({top: 0, behavior: "instant"});
  }

  function restoreAnchor(anchor, anchorTop) {
    let delta = anchor.getBoundingClientRect().top - anchorTop;
    if (tableWrap && tableWrap.scrollHeight > tableWrap.clientHeight) {
      tableWrap.scrollTop += delta;
      delta = anchor.getBoundingClientRect().top - anchorTop;
    }
    if (Math.abs(delta) >= 1) window.scrollTo({top: window.scrollY + delta, behavior: "instant"});
  }

  function updatePaginationFoot() {
    flowsFoot.hidden = flowItems.size === 0;
    loadOlderButton.disabled = loading || !hasMore;
    loadOlderButton.hidden = !hasMore && !loading;
    if (loading) paginationStatus.textContent = "Loading older flows\u2026";
    else if (!hasMore) paginationStatus.textContent = "End of retained history.";
    else paginationStatus.textContent = "";
  }

  // Explicit operator dismissal: closing the drawer lifts the pause it caused.
  function dismissDetail() {
    closeDetail();
    if (isPaused && pausedByDetail) resumeFeed();
  }

  function closeDetail() {
    selectedID = null;
    if (detailRow) { detailRow.remove(); detailRow = null; }
    for (const other of rows.values()) {
      other.setAttribute("aria-selected", "false");
      other.setAttribute("aria-expanded", "false");
    }
  }

  async function selectFlow(item, row) {
    if (selectedID === item.id) { dismissDetail(); return; }
    closeDetail();
    selectedID = item.id;
    if (!isPaused) {
      pauseFeed();
      pausedByDetail = true;
    }
    row.setAttribute("aria-selected", "true");
    row.setAttribute("aria-expanded", "true");
    detailRow = document.createElement("tr");
    detailRow.className = "detail-row";
    const holder = document.createElement("td");
    holder.colSpan = 9;
    const drawer = detailTemplate.content.firstElementChild.cloneNode(true);
    holder.appendChild(drawer);
    detailRow.appendChild(holder);
    wireDetail(drawer);
    populateDetail(drawer, item);
    rebuildFlowOrder();
    if (matchMedia("(max-width: 640px)").matches) {
      detailRow.scrollIntoView({block: "nearest", behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth"});
    }
    try {
      const response = await fetch(`/api/v1/flows/${item.id}`, {headers: {Accept: "application/json"}});
      if (response.ok && selectedID === item.id && detailRow) populateDetail(drawer, await response.json());
    } catch {
      // Preserve summary metadata when detailed capture is temporarily unavailable.
    }
  }

  function wireDetail(drawer) {
    drawer.querySelector(".close-detail").addEventListener("click", dismissDetail);
    // Top-level Overview/Request/Response/WebSocket tabs.
    setupTablist(drawer.querySelector(".tabs"), drawer, "data-tab", "data-panel");
    // Second-level Headers/Body sub-tabs, scoped to their own panel.
    for (const list of drawer.querySelectorAll(".subtabs")) {
      setupTablist(list, list.closest(".tab-panel"), "data-subtab", "data-subpanel");
    }
  }

  function setupTablist(list, panelScope, tabAttr, panelAttr) {
    const tabs = [...list.querySelectorAll('[role="tab"]')];
    const panels = new Map([...panelScope.querySelectorAll(`[${panelAttr}]`)].map(panel => [panel.getAttribute(panelAttr), panel]));
    const activate = tab => {
      for (const candidate of tabs) {
        const on = candidate === tab;
        candidate.setAttribute("aria-selected", String(on));
        candidate.tabIndex = on ? 0 : -1;
        const panel = panels.get(candidate.getAttribute(tabAttr));
        if (panel) panel.hidden = !on;
      }
    };
    tabs.forEach((tab, index) => {
      tab.addEventListener("click", () => { activate(tab); tab.focus(); });
      tab.addEventListener("keydown", event => {
        let next = null;
        if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
        else if (event.key === "ArrowLeft") next = (index - 1 + tabs.length) % tabs.length;
        else if (event.key === "Home") next = 0;
        else if (event.key === "End") next = tabs.length - 1;
        if (next === null) return;
        event.preventDefault();
        activate(tabs[next]);
        tabs[next].focus();
      });
    });
  }

  function populateDetail(drawer, item) {
    const detailFields = drawer.querySelector("#detail-fields");
    const policyTrace = drawer.querySelector("#policy-trace");
    detailFields.replaceChildren();
    const fields = [
      ["Flow ID", item.id], ["Session ID", item.session_id || "Standalone"], ["Started", new Date(item.started_at).toISOString()],
      ["Client", item.client || "Unknown"], ["Decision", item.decision],
      ["Mediation", item.mode || "Unknown"],
      ["Downstream protocol", item.downstream_protocol || "Unknown"],
      ["Upstream protocol", item.upstream_protocol || "Not negotiated"],
      ["Request", `${item.method} ${item.scheme}://${item.host}:${item.port}${item.path || ""}`],
      ["Destination IP", item.destination_ip || "Not connected"],
      ["HTTP status", item.status || "Not available"], ["Reason", item.reason || "Completed"],
      ["Secrets substituted", (item.secret_names || []).join(", ") || "None"],
      ["Secrets scrubbed", (item.response_secret_names || []).join(", ") || "None"],
      ["Sent", bytes(item.bytes_sent)], ["Received", bytes(item.bytes_received)],
      ["Duration", duration(item.duration_ns)]
    ];
    for (const [name, value] of fields) {
      const group = document.createElement("div");
      const dt = document.createElement("dt");
      const dd = document.createElement("dd");
      dt.textContent = name;
      dd.textContent = value;
      group.append(dt, dd);
      detailFields.appendChild(group);
    }
    policyTrace.replaceChildren();
    const trace = item.policy_trace || [];
    if (!trace.length) {
      const li = document.createElement("li");
      li.textContent = "No policy trace retained for this flow.";
      policyTrace.appendChild(li);
    }
    for (const step of trace) {
      const li = document.createElement("li");
      const label = document.createElement("strong");
      const explanation = document.createElement("span");
      label.textContent = `${step.check}: ${step.outcome}`;
      explanation.textContent = step.detail ? `— ${step.detail}` : "";
      li.append(label, explanation);
      policyTrace.appendChild(li);
    }
    renderCapture(drawer, item.capture || {});
  }

  function renderCapture(drawer, capture) {
    const requestHeaders = drawer.querySelector(".capture-request-headers");
    const requestBody = drawer.querySelector(".capture-request-body");
    const responseHeaders = drawer.querySelector(".capture-response-headers");
    const responseBody = drawer.querySelector(".capture-response-body");
    const websocket = drawer.querySelector(".capture-websocket");
    for (const container of [requestHeaders, requestBody, responseHeaders, responseBody, websocket]) container.replaceChildren();
    let reqHeadCount = 0, reqBodyCount = 0, respHeadCount = 0, respBodyCount = 0, websocketCount = 0;
    if ((capture.request_headers || []).length) {
      appendHeaderSection(requestHeaders, "Request headers", capture.request_headers);
      reqHeadCount++;
    }
    if (capture.query) {
      appendCaptureSection(requestHeaders, "Request query", "application/x-www-form-urlencoded", capture.query, false);
      reqHeadCount++;
    }
    if (capture.request_body) {
      appendCaptureSection(requestBody, "Request body", capture.request_body.content_type, capture.request_body.text, capture.request_body.omitted);
      reqBodyCount++;
    }
    if ((capture.response_headers || []).length) {
      appendHeaderSection(responseHeaders, "Response headers", capture.response_headers);
      respHeadCount++;
    }
    if (capture.response_body) {
      appendCaptureSection(responseBody, "Response body", capture.response_body.content_type, capture.response_body.text, capture.response_body.omitted);
      respBodyCount++;
    }
    for (const [index, message] of (capture.websocket_messages || []).entries()) {
      const direction = message.direction === "client-to-upstream" ? "Client → upstream" : "Upstream → client";
      if (message.kind === "binary") {
        appendCaptureSection(websocket, `WebSocket message ${index + 1} · ${direction}`, "binary metadata", `Size: ${bytes(message.size || 0)}\nSHA-256: ${message.sha256 || "Unavailable"}`, false);
      } else {
        appendCaptureSection(websocket, `WebSocket message ${index + 1} · ${direction}`, "text frame", message.text, false);
      }
      websocketCount++;
    }
    if (capture.truncated) {
      appendCaptureSection(requestBody, "Capture limit reached", "", "Additional headers, body content, or WebSocket messages were not retained.", false);
      reqBodyCount++;
    }
    setPanelEmpty(requestHeaders, reqHeadCount);
    setPanelEmpty(requestBody, reqBodyCount);
    setPanelEmpty(responseHeaders, respHeadCount);
    setPanelEmpty(responseBody, respBodyCount);
    setPanelEmpty(websocket, websocketCount);
  }

  function setPanelEmpty(container, count) {
    const note = container.parentElement.querySelector(".capture-empty");
    if (note) note.hidden = count > 0;
  }

  function appendHeaderSection(container, title, headers) {
    const section = document.createElement("section");
    const heading = document.createElement("h4");
    const list = document.createElement("dl");
    heading.textContent = title;
    list.className = "header-list";
    for (const header of headers) {
      for (const value of header.values || []) {
        const row = document.createElement("div");
        const name = document.createElement("dt");
        const content = document.createElement("dd");
        name.textContent = header.name;
        content.textContent = value;
        row.append(name, content);
        list.appendChild(row);
      }
    }
    section.append(heading, list);
    container.appendChild(section);
  }

  function appendCaptureSection(container, title, contentType, text, omitted) {
    const section = document.createElement("section");
    const headingRow = document.createElement("div");
    const heading = document.createElement("h4");
    const meta = document.createElement("p");
    const pre = document.createElement("pre");
    headingRow.className = "capture-heading";
    heading.textContent = title;
    meta.textContent = contentType || "Content type unavailable";
    headingRow.appendChild(heading);
    const raw = text || "";
    const formatted = omitted ? null : window.VeilgateCaptureFormatters.format(contentType, raw);
    if (formatted) {
      const toggle = document.createElement("button");
      toggle.type = "button";
      toggle.className = "secondary capture-toggle";
      toggle.textContent = "Show raw";
      toggle.setAttribute("aria-pressed", "true");
      toggle.addEventListener("click", () => {
        const showFormatted = toggle.getAttribute("aria-pressed") !== "true";
        toggle.setAttribute("aria-pressed", String(showFormatted));
        toggle.textContent = showFormatted ? "Show raw" : "Prettify";
        meta.textContent = `${contentType || "Content type unavailable"} · ${showFormatted ? formatted.label : "Raw"}`;
        renderCaptureText(pre, showFormatted ? formatted.text : (raw || "Empty payload"), showFormatted ? formatted.language : "");
      });
      headingRow.appendChild(toggle);
      meta.textContent = `${contentType || "Content type unavailable"} · ${formatted.label}`;
    }
    const displayed = omitted ? "Content omitted because its media type is unsupported or binary." : (formatted?.text || raw || "Empty payload");
    renderCaptureText(pre, displayed, omitted ? "" : (formatted?.language || ""));
    section.append(headingRow, meta, pre);
    container.appendChild(section);
  }

  function renderCaptureText(pre, text, language) {
    pre.replaceChildren();
    for (const token of window.VeilgateCaptureFormatters.highlight(text, language)) {
      if (!token.type) {
        pre.appendChild(document.createTextNode(token.text));
        continue;
      }
      const span = document.createElement("span");
      span.className = `syntax-${token.type}`;
      span.textContent = token.text;
      pre.appendChild(span);
    }
  }

  async function loadPage(reset) {
    if (loading) return;
    if (!reset && !hasMore) return;
    loading = true;
    updatePaginationFoot();
    const params = filterParams();
    params.set("limit", String(PAGE_SIZE));
    if (!reset && nextBeforeID) params.set("before_id", String(nextBeforeID));
    try {
      const response = await fetch(`/api/v1/flows?${params}`, {headers: {Accept: "application/json"}});
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const page = await response.json();
      for (const parent of page.session_parents || []) renderFlow(parent, false);
      for (const item of page.flows || []) renderFlow(item, false);
      if (page.next_before_id) nextBeforeID = page.next_before_id;
      hasMore = Boolean(page.has_more);
      evictOverflow();
      rebuildFlowOrder();
      empty.hidden = flowItems.size > 0;
    } catch {
      setConnection("disconnected", "History unavailable");
    } finally {
      loading = false;
      updatePaginationFoot();
    }
  }

  function setupObserver() {
    if (observer) observer.disconnect();
    observer = new IntersectionObserver(entries => {
      for (const entry of entries) {
        if (entry.isIntersecting && hasMore && !loading) loadPage(false);
      }
    }, {rootMargin: "200px"});
    observer.observe(document.getElementById("flows-sentinel"));
  }

  function connectEvents(params) {
    if (isPaused) return;
    setConnection("stale", "Connecting");
    events = new EventSource(`/api/v1/events${params.size ? `?${params}` : ""}`);
    events.onopen = () => setConnection("connected", "Live");
    events.addEventListener("flow", event => {
      const item = JSON.parse(event.data);
      if (item.host) trackHost(item.host);
      renderFlow(item, true);
      evictOverflow();
      scheduleRebuild();
    });
    events.onerror = () => {
      if (!isPaused) setConnection("stale", "Reconnecting");
    };
  }

  function setConnection(state, label) {
    if (isPaused) {
      connection.className = "connection paused";
      connection.lastChild.textContent = "Paused";
      return;
    }
    connection.className = `connection ${state}`;
    connection.lastChild.textContent = label;
  }

  function pauseFeed() {
    if (isPaused) return;
    isPaused = true;
    if (events) events.close();
    setConnection("paused", "Paused");
    if (toggleFeedButton) {
      toggleFeedButton.textContent = "Resume feed";
      toggleFeedButton.setAttribute("aria-label", "Resume live feed");
      toggleFeedButton.setAttribute("aria-pressed", "true");
    }
  }

  async function resumeFeed() {
    isPaused = false;
    pausedByDetail = false;
    if (toggleFeedButton) {
      toggleFeedButton.textContent = "Pause feed";
      toggleFeedButton.setAttribute("aria-label", "Pause live feed");
      toggleFeedButton.setAttribute("aria-pressed", "false");
    }
    setConnection("stale", "Connecting");
    await loadPage(true);
    connectEvents(filterParams());
  }

  function toggleFeed() {
    if (isPaused) {
      resumeFeed();
    } else {
      pauseFeed();
      pausedByDetail = false;
    }
  }

  setupObserver();
  loadPage(true);
  connectEvents(filterParams());
})();
