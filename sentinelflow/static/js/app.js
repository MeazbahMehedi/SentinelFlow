/*
 * SentinelFlow dashboard client.
 * Captured strings are always inserted with textContent, never as HTML.
 */
'use strict';

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

const POLL_INTERVAL = 1500;
const PROTOCOL_COLORS = {
  dark: { TCP: '#62e9bb', UDP: '#9995e9', ICMP: '#f4ac68', OTHER: '#87b7cf' },
  light: { TCP: '#118c63', UDP: '#8b75cc', ICMP: '#d49d43', OTHER: '#6c98af' },
};
const RISK_COLORS = { low: '#5d7a6c', medium: '#f4ac68', high: '#ff9f68', critical: '#ff7989' };

const state = { snapshot: null, revision: null, alerts: null, pollTimer: null };

/* ---------- Formatting helpers ---------- */

const formatBytes = (value) => {
  let n = Number(value) || 0;
  for (const unit of ['B', 'KB', 'MB', 'GB']) {
    if (n < 1024 || unit === 'GB') {
      return n.toLocaleString(undefined, { maximumFractionDigits: unit === 'B' ? 0 : 1 }) + ' ' + unit;
    }
    n /= 1024;
  }
  return n + ' GB';
};

const formatUtc = (seconds) =>
  new Date(seconds * 1000).toLocaleString('en-GB', { timeZone: 'UTC', hour12: false });

const themeColor = (name, fallback) =>
  getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;

const isLight = () => document.documentElement.dataset.theme === 'light';

const protocolColor = (name) => {
  const palette = PROTOCOL_COLORS[isLight() ? 'light' : 'dark'];
  return palette[name] || palette.OTHER;
};

const riskLevel = (score) => (score >= 60 ? 'critical' : score >= 30 ? 'high' : score > 0 ? 'medium' : 'low');

const sessionQuery = () => {
  const scope = document.body.dataset.session;
  return scope ? 'session=' + encodeURIComponent(scope) : '';
};

let toastTimer;
function toast(message) {
  const element = $('#toast');
  if (!element) return;
  element.textContent = message;
  element.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => element.classList.remove('show'), 4500);
}

function canvasContext(canvas) {
  const rect = canvas.getBoundingClientRect();
  const ratio = window.devicePixelRatio || 1;
  canvas.width = rect.width * ratio;
  canvas.height = rect.height * ratio;
  const ctx = canvas.getContext('2d');
  ctx.scale(ratio, ratio);
  return { ctx, w: rect.width, h: rect.height };
}

/* ---------- Traffic timeline ---------- */

const chartState = { points: [], series: [] };

function lineChart(series) {
  const canvas = $('#traffic-chart');
  if (!canvas) return;
  const { ctx, w, h } = canvasContext(canvas);
  const pad = { l: 40, r: 12, t: 20, b: 20 };
  const pw = w - pad.l - pad.r;
  const ph = h - pad.t - pad.b;
  const max = Math.max(4, ...series.map((x) => x.packets));
  ctx.clearRect(0, 0, w, h);
  ctx.font = '9px Consolas, monospace';
  for (let i = 0; i <= 4; i++) {
    const y = pad.t + (ph / 4) * i;
    ctx.strokeStyle = themeColor('--chart-grid', '#26352f');
    ctx.lineWidth = 0.7;
    ctx.beginPath();
    ctx.moveTo(pad.l, y);
    ctx.lineTo(w - pad.r, y);
    ctx.stroke();
    ctx.fillStyle = themeColor('--chart-text', '#5d7a6c');
    ctx.textAlign = 'right';
    ctx.fillText(Math.round(max * (1 - i / 4)), pad.l - 10, y + 3);
  }
  const empty = $('#chart-empty');
  if (empty) empty.hidden = Boolean(series.length);
  chartState.series = series;
  chartState.points = [];
  if (!series.length) return;

  const points = series.map((p, i) => [
    pad.l + (i / Math.max(1, series.length - 1)) * pw,
    pad.t + ph - (p.packets / max) * ph,
  ]);
  if (points.length === 1) points.push([pad.l + pw, points[0][1]]);
  chartState.points = points;

  ctx.beginPath();
  ctx.moveTo(points[0][0], pad.t + ph);
  for (const p of points) ctx.lineTo(...p);
  ctx.lineTo(points.at(-1)[0], pad.t + ph);
  ctx.closePath();
  const gradient = ctx.createLinearGradient(0, pad.t, 0, h);
  gradient.addColorStop(0, themeColor('--chart-fill', '#62e9bb2c'));
  gradient.addColorStop(1, '#62e9bb00');
  ctx.fillStyle = gradient;
  ctx.fill();

  ctx.beginPath();
  points.forEach((p, i) => (i ? ctx.lineTo(...p) : ctx.moveTo(...p)));
  ctx.strokeStyle = themeColor('--chart-line', '#62e9bb');
  ctx.lineWidth = 1.8;
  ctx.lineJoin = 'round';
  ctx.stroke();

  const last = points.at(-1);
  ctx.beginPath();
  ctx.arc(last[0], last[1], 3, 0, Math.PI * 2);
  ctx.fillStyle = themeColor('--chart-line', '#b4ffe0');
  ctx.fill();
}

function bindChartTooltip() {
  const canvas = $('#traffic-chart');
  const tooltip = $('#chart-tooltip');
  if (!canvas || !tooltip) return;
  canvas.addEventListener('mousemove', (event) => {
    if (!chartState.points.length) return;
    const rect = canvas.getBoundingClientRect();
    const x = event.clientX - rect.left;
    let index = 0;
    chartState.points.forEach((p, i) => {
      if (Math.abs(p[0] - x) < Math.abs(chartState.points[index][0] - x)) index = i;
    });
    const bucket = chartState.series[Math.min(index, chartState.series.length - 1)];
    const [px, py] = chartState.points[index];
    tooltip.replaceChildren();
    const time = document.createElement('span');
    time.textContent = formatUtc(bucket.ts) + ' UTC';
    const value = document.createElement('strong');
    value.textContent = bucket.packets.toLocaleString() + ' packets · ' + formatBytes(bucket.bytes);
    tooltip.append(time, value);
    tooltip.hidden = false;
    tooltip.style.left = Math.min(rect.width - 190, Math.max(0, px - 90)) + 'px';
    tooltip.style.top = Math.max(0, py - 58) + 'px';
  });
  canvas.addEventListener('mouseleave', () => (tooltip.hidden = true));
}

/* ---------- Protocol donut ---------- */

function donut(protocols) {
  const canvas = $('#protocol-chart');
  if (!canvas) return;
  const { ctx, w, h } = canvasContext(canvas);
  ctx.clearRect(0, 0, w, h);
  const total = protocols.reduce((n, p) => n + p.value, 0);
  const r = w / 2 - 20;
  ctx.lineWidth = 18;
  ctx.strokeStyle = themeColor('--chart-empty', '#22372c');
  ctx.beginPath();
  ctx.arc(w / 2, h / 2, r, 0, Math.PI * 2);
  ctx.stroke();
  let start = -Math.PI / 2;
  for (const p of protocols) {
    const end = start + (p.value / Math.max(1, total)) * Math.PI * 2;
    ctx.beginPath();
    ctx.strokeStyle = protocolColor(p.label);
    ctx.arc(w / 2, h / 2, r, start + 0.025, end - 0.025 > start + 0.025 ? end - 0.025 : end);
    ctx.stroke();
    start = end;
  }
  const legend = $('#protocol-legend');
  if (!legend) return;
  legend.replaceChildren();
  for (const p of protocols) {
    const span = document.createElement('span');
    const swatch = document.createElement('i');
    swatch.className = 'swatch ' + p.label;
    span.append(swatch, document.createTextNode(p.label + ' ' + Math.round((p.value / Math.max(1, total)) * 100) + '%'));
    legend.append(span);
  }
  if (!protocols.length) {
    const span = document.createElement('span');
    span.textContent = 'No packets analyzed';
    legend.append(span);
  }
}

/* ---------- Live snapshot ---------- */

function applySnapshot(snapshot) {
  state.snapshot = snapshot;
  for (const [key, value] of Object.entries(snapshot.totals)) {
    $$('[data-live="' + key + '"]').forEach((el) => {
      el.textContent = key === 'bytes' ? formatBytes(value) : Number(value || 0).toLocaleString();
    });
  }
  for (const level of ['critical', 'high', 'medium', 'low']) {
    $$('[data-severity="' + level + '"]').forEach((el) => (el.textContent = snapshot.severity_totals[level] || 0));
  }
  lineChart(snapshot.series);
  donut(snapshot.protocols);

  const active = snapshot.sessions.find((s) => ['running', 'paused'].includes(s.status));
  const label = $('#active-label');
  if (label) label.textContent = active ? (active.source === 'live' ? 'LIVE CAPTURE' : 'REPLAY ' + active.status.toUpperCase()) : 'LOCAL SENSOR';

  for (const s of snapshot.sessions) {
    const card = $('[data-session-card="' + s.id + '"]');
    if (!card) continue;
    card.querySelector('[data-processed]').textContent = s.processed.toLocaleString();
    card.querySelector('[data-dropped]').textContent = s.dropped + ' dropped or unprocessed at stop';
    const fill = card.querySelector('[data-progress]');
    fill.style.width = (s.total ? Math.min(100, (s.processed / s.total) * 100) : 0) + '%';
    const status = card.querySelector('[data-status] .badge');
    if (status && status.textContent !== s.status) {
      status.textContent = s.status;
      status.className = 'badge ' + s.status;
      // Controls depend on status; reload once so the right buttons render.
      if (document.body.dataset.page === 'replay') setTimeout(() => location.reload(), 650);
    }
  }

  if (state.alerts !== null && snapshot.totals.alerts > state.alerts) {
    const fresh = snapshot.totals.alerts - state.alerts;
    toast(fresh + ' new detection(s). Open Threat alerts to investigate.');
    const banner = $('#new-alerts-banner');
    if (banner) {
      banner.hidden = false;
      $('[data-new-alerts]', banner).textContent = fresh + ' new detection(s) arrived since this page loaded.';
    }
  }
  state.alerts = snapshot.totals.alerts;
}

function setConnection(online) {
  const label = $('#stream-label');
  const dot = $('#stream-dot');
  if (!label) return;
  label.textContent = online ? 'Workspace connected' : 'Reconnecting to workspace';
  dot.classList.toggle('offline', !online);
}

async function poll() {
  clearTimeout(state.pollTimer);
  if (document.hidden) return;
  try {
    const params = [sessionQuery(), state.revision !== null ? 'rev=' + state.revision : ''].filter(Boolean).join('&');
    const response = await fetch('/api/snapshot' + (params ? '?' + params : ''), { cache: 'no-store' });
    if (response.status === 401) return location.reload();
    if (response.ok && response.status !== 204) {
      const snapshot = await response.json();
      const changed = state.revision !== null;
      state.revision = snapshot.revision;
      applySnapshot(snapshot);
      if (changed) refreshTrafficTable();
    }
    setConnection(response.ok);
  } catch (_) {
    setConnection(false);
  }
  state.pollTimer = setTimeout(poll, POLL_INTERVAL);
}

async function refreshTrafficTable() {
  const body = $('#traffic-body');
  if (!body) return;
  try {
    const query = sessionQuery();
    const response = await fetch('/api/packets' + (query ? '?' + query : ''));
    if (!response.ok) return;
    const rows = await response.json();
    if (!rows.length) return;
    body.replaceChildren();
    for (const r of rows) {
      const tr = document.createElement('tr');
      for (const key of ['ts', 'src', 'dst', 'proto', 'length', 'dns']) {
        const td = document.createElement('td');
        if (key === 'src' || key === 'dst') {
          const link = document.createElement('a');
          link.className = 'mono';
          link.href = '/hosts/' + encodeURIComponent(r[key]);
          link.textContent = r[key];
          const port = document.createElement('small');
          port.textContent = ':' + (key === 'src' ? r.sport : r.dport);
          td.append(link, port);
        } else if (key === 'proto') {
          const span = document.createElement('span');
          span.className = 'proto ' + r.proto;
          span.textContent = r.proto;
          td.append(span);
        } else {
          td.className = key === 'dns' ? 'muted small wrap' : 'muted mono small';
          td.textContent = key === 'ts' ? formatUtc(r.ts) : key === 'length' ? formatBytes(r.length) : r.dns || r.flags || '—';
        }
        tr.append(td);
      }
      body.append(tr);
    }
  } catch (_) {
    /* Connection state is reported by the poller. */
  }
}

/* ---------- Host conversation graph ---------- */

const graph = { nodes: [], edges: [], drag: null, width: 0, height: 0 };
const GRAPH_PADDING = 36;
const GRAPH_ITERATIONS = 400;

async function loadGraph() {
  const canvas = $('#host-graph');
  if (!canvas) return;
  const query = sessionQuery();
  const response = await fetch('/api/graph' + (query ? '?' + query : ''));
  if (!response.ok) return;
  const data = await response.json();
  $('#graph-empty').hidden = data.nodes.length > 0;
  const maxBytes = Math.max(1, ...data.edges.map((e) => e.bytes));
  graph.nodes = data.nodes.map((n) => ({ ...n }));
  const index = Object.fromEntries(graph.nodes.map((n) => [n.id, n]));
  graph.edges = data.edges.map((e) => ({ ...e, a: index[e.source], b: index[e.target], weight: e.bytes / maxBytes }));
  for (const node of graph.nodes) node.degree = graph.edges.filter((e) => e.a === node || e.b === node).length;
  layoutGraph();
  drawGraph();
}

/* Fruchterman-Reingold layout with linear cooling, computed once. */
function layoutGraph() {
  const rect = $('#host-graph').getBoundingClientRect();
  const w = (graph.width = rect.width);
  const h = (graph.height = rect.height);
  const nodes = graph.nodes;
  if (!nodes.length) return;
  const k = Math.sqrt(((w - GRAPH_PADDING * 2) * (h - GRAPH_PADDING * 2)) / nodes.length) * 0.9;
  nodes.forEach((n, i) => {
    const angle = (i / nodes.length) * Math.PI * 2;
    n.x = w / 2 + Math.cos(angle) * w * 0.3;
    n.y = h / 2 + Math.sin(angle) * h * 0.3;
  });
  for (let step = 0; step < GRAPH_ITERATIONS; step++) {
    const temperature = (w / 8) * (1 - step / GRAPH_ITERATIONS) + 0.5;
    for (const n of nodes) n.dx = n.dy = 0;
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i];
        const b = nodes[j];
        const dx = a.x - b.x || 0.01;
        const dy = a.y - b.y || 0.01;
        const dist = Math.hypot(dx, dy);
        const force = (k * k) / dist;
        a.dx += (dx / dist) * force;
        a.dy += (dy / dist) * force;
        b.dx -= (dx / dist) * force;
        b.dy -= (dy / dist) * force;
      }
    }
    for (const e of graph.edges) {
      const dx = e.a.x - e.b.x;
      const dy = e.a.y - e.b.y;
      const dist = Math.max(0.01, Math.hypot(dx, dy));
      const force = (dist * dist) / k;
      e.a.dx -= (dx / dist) * force;
      e.a.dy -= (dy / dist) * force;
      e.b.dx += (dx / dist) * force;
      e.b.dy += (dy / dist) * force;
    }
    for (const n of nodes) {
      n.dx += (w / 2 - n.x) * 0.02 * k;
      n.dy += (h / 2 - n.y) * 0.02 * k;
      const length = Math.max(0.01, Math.hypot(n.dx, n.dy));
      n.x += (n.dx / length) * Math.min(length, temperature);
      n.y += (n.dy / length) * Math.min(length, temperature);
      n.x = Math.min(w - GRAPH_PADDING, Math.max(GRAPH_PADDING, n.x));
      n.y = Math.min(h - GRAPH_PADDING, Math.max(GRAPH_PADDING, n.y));
    }
  }
}

function drawGraph() {
  const canvas = $('#host-graph');
  if (!canvas || !graph.nodes.length) return;
  const { ctx, w, h } = canvasContext(canvas);
  if (Math.abs(w - graph.width) > 1 || Math.abs(h - graph.height) > 1) {
    const sx = w / graph.width;
    const sy = h / graph.height;
    graph.nodes.forEach((n) => ((n.x *= sx), (n.y *= sy)));
    graph.width = w;
    graph.height = h;
  }
  ctx.clearRect(0, 0, w, h);
  for (const e of graph.edges) {
    ctx.strokeStyle = isLight() ? 'rgba(17,140,99,' + (0.18 + e.weight * 0.6) + ')' : 'rgba(98,233,187,' + (0.14 + e.weight * 0.55) + ')';
    ctx.lineWidth = 0.8 + e.weight * 4;
    ctx.beginPath();
    ctx.moveTo(e.a.x, e.a.y);
    ctx.lineTo(e.b.x, e.b.y);
    ctx.stroke();
  }
  ctx.font = '10px Consolas, monospace';
  ctx.textAlign = 'center';
  for (const n of graph.nodes) {
    n.radius = 5 + Math.min(9, n.degree * 1.2);
    ctx.beginPath();
    ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
    ctx.fillStyle = RISK_COLORS[riskLevel(n.risk)];
    ctx.fill();
    ctx.lineWidth = 2;
    ctx.strokeStyle = themeColor('--panel', '#11191f');
    ctx.stroke();
    if (n.degree > 1 || n.risk > 0 || graph.nodes.length <= 24) {
      ctx.fillStyle = themeColor('--muted', '#8d9ea8');
      ctx.fillText(n.id, n.x, n.y + n.radius + 12);
    }
  }
}

function graphNodeAt(event) {
  const rect = $('#host-graph').getBoundingClientRect();
  const x = event.clientX - rect.left;
  const y = event.clientY - rect.top;
  return graph.nodes.find((n) => Math.hypot(n.x - x, n.y - y) <= (n.radius || 8) + 4);
}

function bindGraph() {
  const canvas = $('#host-graph');
  if (!canvas) return;
  const tooltip = $('#graph-tooltip');
  let moved = false;
  canvas.addEventListener('pointerdown', (event) => {
    graph.drag = graphNodeAt(event) || null;
    moved = false;
    if (graph.drag) canvas.setPointerCapture(event.pointerId);
  });
  canvas.addEventListener('pointermove', (event) => {
    const rect = canvas.getBoundingClientRect();
    if (graph.drag) {
      moved = true;
      graph.drag.x = event.clientX - rect.left;
      graph.drag.y = event.clientY - rect.top;
      drawGraph();
      return;
    }
    const node = graphNodeAt(event);
    canvas.style.cursor = node ? 'pointer' : 'default';
    if (!node) return (tooltip.hidden = true);
    tooltip.replaceChildren();
    const name = document.createElement('strong');
    name.textContent = node.id;
    const detail = document.createElement('span');
    detail.textContent = node.degree + ' conversation(s) · risk ' + node.risk;
    tooltip.append(name, detail);
    tooltip.hidden = false;
    tooltip.style.left = Math.min(rect.width - 190, node.x + 12) + 'px';
    tooltip.style.top = Math.max(0, node.y - 50) + 'px';
  });
  canvas.addEventListener('pointerup', (event) => {
    const node = graph.drag;
    graph.drag = null;
    if (node && !moved) {
      const query = sessionQuery();
      location.href = '/hosts/' + encodeURIComponent(node.id) + (query ? '?' + query : '');
    }
  });
  canvas.addEventListener('mouseleave', () => (tooltip.hidden = true));
}

/* ---------- Bulk alert triage ---------- */

function bindBulkSelection() {
  const form = $('#bulk-form');
  if (!form) return;
  const boxes = () => $$('input[name="ids"][form="bulk-form"]');
  const update = () => {
    const count = boxes().filter((b) => b.checked).length;
    form.hidden = count === 0;
    $('[data-selected-count]', form).textContent = count + ' selected';
  };
  $('[data-select-all]')?.addEventListener('change', (event) => {
    boxes().forEach((b) => (b.checked = event.target.checked));
    update();
  });
  boxes().forEach((b) => b.addEventListener('change', update));
  $('[data-clear-selection]', form).addEventListener('click', () => {
    boxes().forEach((b) => (b.checked = false));
    const all = $('[data-select-all]');
    if (all) all.checked = false;
    update();
  });
}

/* ---------- Command palette ---------- */

const PAGES = [
  ['Overview', '/', 'Dashboard and latest detections'],
  ['Live traffic', '/traffic', 'Packet explorer'],
  ['Threat alerts', '/alerts', 'Detection inbox and triage'],
  ['PCAP replay', '/replay', 'Import, replay and live capture'],
  ['Host explorer', '/hosts', 'Conversation map and host risk'],
  ['Analytics', '/analytics', 'Breakdowns, tactics and services'],
  ['Detection rules', '/rules', 'Thresholds and windows'],
  ['The developers', '/team', 'Project team'],
  ['GitHub projects', '/repositories', 'Public repositories'],
  ['Settings', '/settings', 'Indicators, accounts and retention'],
];

const looksLikeIp = (text) => /^[0-9a-f:.]+$/i.test(text) && (text.includes('.') || text.includes(':'));

function paletteItems(query) {
  const text = query.trim();
  const items = [];
  const alertMatch = text.match(/^#?(\d+)$/);
  if (alertMatch) items.push(['Open alert #' + alertMatch[1], '/alerts/' + alertMatch[1], 'Alert investigation']);
  if (looksLikeIp(text)) {
    items.push(['Investigate host ' + text, '/hosts/' + encodeURIComponent(text), 'Host profile']);
    items.push(['Search traffic for ' + text, '/traffic?q=' + encodeURIComponent(text), 'Packet explorer']);
  } else if (text) {
    items.push(['Search alerts for “' + text + '”', '/alerts?q=' + encodeURIComponent(text), 'Detection inbox']);
    items.push(['Search traffic for “' + text + '”', '/traffic?q=' + encodeURIComponent(text), 'Packet explorer']);
  }
  const lower = text.toLowerCase();
  for (const page of PAGES) {
    if (!lower || page[0].toLowerCase().includes(lower) || page[2].toLowerCase().includes(lower)) items.push(page);
  }
  return items.slice(0, 9);
}

function bindPalette() {
  const palette = $('#palette');
  if (!palette) return;
  const input = $('#palette-input');
  const list = $('#palette-results');
  let active = 0;
  let items = [];

  const render = () => {
    items = paletteItems(input.value);
    active = Math.min(active, Math.max(0, items.length - 1));
    list.replaceChildren();
    items.forEach(([label, href, hint], i) => {
      const li = document.createElement('li');
      li.setAttribute('role', 'option');
      li.className = i === active ? 'active' : '';
      const strong = document.createElement('strong');
      strong.textContent = label;
      const small = document.createElement('small');
      small.textContent = hint;
      li.append(strong, small);
      li.addEventListener('click', () => (location.href = href));
      list.append(li);
    });
  };
  const open = () => {
    palette.hidden = false;
    input.value = '';
    active = 0;
    render();
    input.focus();
  };
  const close = () => (palette.hidden = true);

  $$('[data-palette-open]').forEach((b) => b.addEventListener('click', open));
  palette.addEventListener('click', (event) => event.target === palette && close());
  input.addEventListener('input', () => {
    active = 0;
    render();
  });
  input.addEventListener('keydown', (event) => {
    if (event.key === 'ArrowDown') active = Math.min(items.length - 1, active + 1);
    else if (event.key === 'ArrowUp') active = Math.max(0, active - 1);
    else if (event.key === 'Enter' && items[active]) return (location.href = items[active][1]);
    else if (event.key === 'Escape') return close();
    else return;
    event.preventDefault();
    render();
  });
  document.addEventListener('keydown', (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
      event.preventDefault();
      palette.hidden ? open() : close();
    } else if (event.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName)) {
      event.preventDefault();
      open();
    }
  });
}

/* ---------- Page wiring ---------- */

function bindCaptureCheck() {
  const button = $('#capture-check');
  if (!button) return;
  button.addEventListener('click', async () => {
    button.disabled = true;
    try {
      const response = await fetch('/api/capture/status');
      if (!response.ok) throw new Error('Check failed');
      const status = await response.json();
      $('#capture-health-title').textContent = status.ready ? 'Backend available' : 'Capture setup needed';
      $('#capture-health-message').textContent = status.message;
      $('#capture-health').className = 'capture-health ' + (status.ready ? 'healthy' : 'needs-setup');
      const select = $('#capture-interface');
      const previous = select.value;
      select.replaceChildren(new Option('Choose an interface', ''));
      for (const iface of status.interfaces) {
        const address = iface.address && iface.address !== '0.0.0.0' ? ' · ' + iface.address : '';
        select.append(new Option(iface.label + address, iface.id));
      }
      if (status.interfaces.some((i) => i.id === previous)) select.value = previous;
      $('#start-live-button').disabled = !status.ready;
    } catch (_) {
      toast('Capture check could not complete. Refresh and try again.');
    } finally {
      button.disabled = false;
    }
  });
}

function startClock() {
  const clock = $('#clock');
  if (!clock) return;
  const tick = () => (clock.textContent = new Date().toLocaleTimeString('en-GB', { timeZone: 'UTC', hour12: false }) + ' UTC');
  tick();
  setInterval(tick, 1000);
}

function redrawCharts() {
  if (state.snapshot) {
    lineChart(state.snapshot.series);
    donut(state.snapshot.protocols);
  }
  drawGraph();
}

function init() {
  $$('.refresh').forEach((b) => b.addEventListener('click', () => location.reload()));
  $$('.dismiss').forEach((b) => b.addEventListener('click', () => b.closest('.notice').remove()));
  $$('form[data-confirm]').forEach((form) =>
    form.addEventListener('submit', (event) => {
      if (form.dataset.confirm && !confirm(form.dataset.confirm)) event.preventDefault();
    }),
  );
  $$('[data-progress]').forEach((el) => (el.style.width = Math.min(100, Number(el.dataset.progress)) + '%'));
  $$('[data-width]').forEach((el) => (el.style.width = Math.min(100, Number(el.dataset.width)) + '%'));
  $$('[data-left]').forEach((el) => (el.style.left = Math.min(100, Number(el.dataset.left)) + '%'));
  $$('.panel, .metric-card, .hero, .rule-card, .developer-card, .team-intro').forEach((el) => el.classList.add('reveal'));

  $('#menu-toggle')?.addEventListener('click', () => $('#sidebar').classList.toggle('open'));
  document.addEventListener('click', (event) => {
    if (innerWidth <= 950 && !event.target.closest('#sidebar') && !event.target.closest('#menu-toggle')) {
      $('#sidebar')?.classList.remove('open');
    }
  });

  let resizeTimer;
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(redrawCharts, 150);
  });
  window.addEventListener('themechange', redrawCharts);
  document.addEventListener('visibilitychange', () => !document.hidden && poll());

  startClock();
  bindChartTooltip();
  bindBulkSelection();
  bindPalette();
  bindCaptureCheck();
  bindGraph();
  loadGraph();
  if ($('#stream-label')) {
    poll();
    refreshTrafficTable();
  }
}

init();
