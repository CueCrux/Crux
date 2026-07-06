// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.
//
// Unified Shell Console v2 — DSL renderer (ExecPlan unified-shell-console-2026-07-03, M1).
// One clean renderer for the ported page registry (pages.js). Renders sections →
// cards using the v2 token system, and implements every control type the 26 CX
// pages use: search · input · textarea · select · toggle · btn · info · exp ·
// rpcout · bar · theme. UMD: window.CruxRender in the browser; module.exports
// under node so the smoke can read CONTROL_TYPES + grep the posture-gate logic.
// It touches the DOM/network only inside functions, never at module load.
//
// Posture (customer-safe, forward-facing UI): a control tagged `mut:true` is a
// WRITE. It is rendered only for operators (data-requires="operator", hidden for
// customers) and, even for operators, disabled with title "wired in M3+" — no
// dead mutations ship in M1. Read-only loads (GET-on-open) are posture-free.
;(function (root, factory) {
  var api = factory();
  if (typeof module === 'object' && module.exports) { module.exports = api; }
  else { root.CruxRender = api; }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // The control types this renderer knows how to draw. The smoke asserts every
  // control type used anywhere in pages.js has a branch here.
  var CONTROL_TYPES = ['search', 'input', 'textarea', 'select', 'toggle', 'btn', 'info', 'exp', 'rpcout', 'bar', 'theme', 'chart', 'disclose', 'repogrid', 'wbread'];
  var GATE_TITLE = 'wired in M3+';

  // ---- Environment shims (only used when rendering in a browser) ---------
  function doc() { return (typeof document !== 'undefined') ? document : null; }
  function posture() { return (typeof window !== 'undefined' && window.CRUX_POSTURE) || 'customer'; }
  function isOperator() { return posture() === 'operator'; }

  // ---- Posture derivation (pure; the smoke unit-tests this) --------------
  // operator ⟺ the daemon reports auth_mode 'off' (an unauthenticated local
  // instance — every caller already has full power server-side, so operator
  // controls match server reality) OR
  // the admin-scoped capability probe (GET /v1/admin/version) returned 200.
  // Anything else — including a failed or blocked probe — is a customer view.
  // `probe` is injected ({ authMode, adminProbeStatus }) so this stays a pure,
  // side-effect-free function that can be asserted statically. Posture is a
  // server property: the caller derives it fresh each boot, never persists it.
  function derivePosture(probe) {
    var p = probe || {};
    if (p.authMode === 'off') { return 'operator'; }
    if (p.adminProbeStatus === 200) { return 'operator'; }
    return 'customer';
  }

  // ---- Gated mutations — the SINGLE choke point --------------------------
  // The one and only place the gated write client (window global set by api.js)
  // is invoked. Nothing runs unless operator posture holds, so a customer view
  // can never mutate even if a code path reaches here. The smoke asserts the
  // gated client is referenced nowhere else in pages / render / shell.
  function operatorGatedCall(invoke) {
    if (!isOperator()) {
      return Promise.reject(new Error('operator posture required for gated mutation'));
    }
    var gated = (typeof window !== 'undefined') ? window.CruxApiGated : null;
    if (!gated || typeof invoke !== 'function') {
      return Promise.reject(new Error('gated mutation client unavailable'));
    }
    return invoke(gated);
  }

  // The approving/authoring passport, mirroring the legacy console: a client
  // identity selection in localStorage — never a fabricated value. Approvals
  // are passport-attributed (Art. 14); empty ⇒ the caller must bind first.
  function boundPassport() {
    try { return (localStorage.getItem('crux-console-bound-passport') || '').trim(); }
    catch (e) { return ''; }
  }

  // Public gated helpers. Each resolves to the raw fetch Response so callers
  // can read the REAL backend body (no fabricated fields).
  function approveGate(actionId, approverPassport) {
    return operatorGatedCall(function (g) { return g.gateApprove(actionId, { approver_passport: approverPassport }); });
  }
  function rejectGate(actionId, approverPassport) {
    return operatorGatedCall(function (g) { return g.gateReject(actionId, { approver_passport: approverPassport }); });
  }
  function commentWork(workId, authorPassport, body) {
    return operatorGatedCall(function (g) { return g.workComment(workId, { author_passport: authorPassport, body: body }); });
  }
  function enrichAction(input) {
    return operatorGatedCall(function (g) { return g.actionsEnrich(input); });
  }

  // Parse a fetch Response without ever throwing — the read counterpart of the
  // gated helpers above.
  function readJson(response) {
    return response.json().then(
      function (data) { return { ok: response.ok, status: response.status, data: data }; },
      function () { return { ok: response.ok, status: response.status, data: null }; }
    );
  }

  // Safe nested property access (used by the Pro dashboard strip). Pure.
  function get(obj, path) {
    var cur = obj;
    for (var i = 0; i < path.length; i++) { if (cur == null) { return undefined; } cur = cur[path[i]]; }
    return cur;
  }

  function el(tag, attrs, children) {
    var node = doc().createElement(tag);
    if (attrs) {
      for (var k in attrs) {
        if (attrs[k] == null) { continue; }
        if (k === 'text') { node.textContent = attrs[k]; }
        else if (k === 'html') { node.innerHTML = attrs[k]; }
        else { node.setAttribute(k, attrs[k]); }
      }
    }
    if (children) {
      for (var i = 0; i < children.length; i++) {
        var c = children[i];
        if (c == null) { continue; }
        node.appendChild(typeof c === 'string' ? doc().createTextNode(c) : c);
      }
    }
    return node;
  }

  // ---- Network: never throws, never spams the console. Every read goes
  // through the generated allowlist client (window.CruxApi from
  // /console-v2/api.js) — the v2 console performs no raw fetches (M2 gate).
  function fetchJSON(url) {
    var api = (typeof window !== 'undefined') ? window.CruxApi : null;
    if (!api || typeof api.get !== 'function') { return Promise.resolve({ ok: false, status: 0, data: null }); }
    return api.get(url)
      .then(function (r) {
        return r.json().then(
          function (data) { return { ok: r.ok, status: r.status, data: data }; },
          function () { return { ok: r.ok, status: r.status, data: null }; }
        );
      })
      .catch(function () { return { ok: false, status: 0, data: null }; });
  }

  // Repos for one project: GET /v1/projects/{id}/repos via the generated
  // named CruxApi method (a parameterised route — reachable only through the
  // method, never CruxApi.get's literal allowlist). render.js keeps zero raw
  // network calls of its own: the network layer lives inside api.js's method.
  function fetchRepos(projectId) {
    var api = (typeof window !== 'undefined') ? window.CruxApi : null;
    if (!api || typeof api.projectsByIdRepos !== 'function') { return Promise.resolve({ ok: false, status: 0, data: null }); }
    return api.projectsByIdRepos(projectId)
      .then(function (r) {
        return r.json().then(
          function (data) { return { ok: r.ok, status: r.status, data: data }; },
          function () { return { ok: r.ok, status: r.status, data: null }; }
        );
      })
      .catch(function () { return { ok: false, status: 0, data: null }; });
  }

  // =======================================================================
  //  Demo mode (labelled, gated). window.CRUX_DEMO is set by the shell (from
  //  ?demo / localStorage). demoData() is the SINGLE choke point that reads the
  //  CruxDemo fixture module — every fixture-fed panel goes through it, so the
  //  smoke can prove fixtures are reachable ONLY behind the demo flag. Real data
  //  always wins: callers reach demoData() only when a panel is empty/degraded.
  // =======================================================================
  function demoOn() { return typeof window !== 'undefined' && !!window.CRUX_DEMO; }
  // ---- Presentation mode (Standard | Professional) ----------------------
  // Mode is PRESENTATION only — it never gates writes or reads. The security
  // boundary is posture (operator/customer), which is derived server-side and is
  // wholly independent of mode. proMode() drives density, Pro-only sections/
  // pages, the full pill row, and the Overwatch dashboard strip — nothing more.
  function proMode() { return typeof window !== 'undefined' && window.CRUX_MODE === 'professional'; }
  function demoData(key) {
    if (!demoOn()) { return null; }
    var d = (typeof window !== 'undefined') ? window.CruxDemo : null;
    return (d && key && d[key] != null) ? d[key] : null;
  }
  function demoChip(inline) { return el('span', { 'class': 'demo-chip' + (inline ? ' inline' : ''), text: 'demo' }); }

  // ---- Project repo card grid (item 2b) ---------------------------------
  // One card per linked repo — real GET /v1/projects/{id}/repos rows win; a demo
  // fixture (demoData('projectRepos'), demoOn()-guarded) fills the grid ONLY when
  // the real list is empty. Fields are surfaced real (slug · role · plane) —
  // never fabricated.
  function repoCard(link) {
    var slug = (link.owner != null && link.repo != null) ? (link.owner + '/' + link.repo) : String(link.slug || link.repo || 'repo');
    var meta = [link.role, link.plane_id].filter(Boolean).join(' · ');
    var card = el('div', { 'class': 'repo-card' }, [el('div', { 'class': 'repo-card-name', text: slug })]);
    if (meta) { card.appendChild(el('div', { 'class': 'repo-card-meta', text: meta })); }
    return card;
  }
  function loadRepoGrid(host, projectId) {
    return fetchRepos(projectId).then(function (res) {
      host.textContent = '';
      var links = (res.ok && res.data && res.data.links) ? res.data.links : [];
      if (!links.length) {
        var demo = demoData('projectRepos');   // demoOn()-guarded fixture — only when the real list is empty
        if (demo && demo.length) {
          var dg = el('div', { 'class': 'repo-grid' });
          demo.forEach(function (l) { dg.appendChild(repoCard(l)); });
          host.appendChild(dg);
          host.appendChild(demoChip(true));
          return;
        }
        host.appendChild(el('p', { 'class': 'ctl-desc', text: res.ok ? 'No repos linked yet.' : ('Repos unavailable — ' + (res.status === 0 ? 'unreachable' : 'HTTP ' + res.status) + '.') }));
        return;
      }
      var grid = el('div', { 'class': 'repo-grid' });
      links.forEach(function (l) { grid.appendChild(repoCard(l)); });
      host.appendChild(grid);
    });
  }

  // ---- Workbench live READ tool (M13a) ----------------------------------
  // A wbread control self-loads one /v1/workbench/* GET through the named api.js
  // client method (window.CruxApi.<method>) and paints a compact summary. This
  // is a READ: it is GET-only, never the operator-gated write client, never a POST — the M13a
  // workbench port wires only non-mutating reads live (writes stay gated for
  // M13b). render.js keeps zero raw network calls of its own; the fetch lives
  // inside the api.js generated method.
  function fetchWorkbench(apiMethod, query) {
    var api = (typeof window !== 'undefined') ? window.CruxApi : null;
    if (!api || typeof api[apiMethod] !== 'function') { return Promise.resolve({ ok: false, status: 0, data: null }); }
    return api[apiMethod](query)
      .then(function (r) {
        return r.json().then(
          function (data) { return { ok: r.ok, status: r.status, data: data }; },
          function () { return { ok: r.ok, status: r.status, data: null }; }
        );
      })
      .catch(function () { return { ok: false, status: 0, data: null }; });
  }
  function loadWorkbenchRead(host, control) {
    return fetchWorkbench(control.api, control.query).then(function (res) {
      host.textContent = '';
      host.appendChild(el('div', { 'class': 'ctl-info' }, [
        el('span', { 'class': 'ctl-info-k', text: control.label || 'read tool' }),
        el('span', { 'class': 'ctl-info-v', text: control.hint || '' })
      ]));
      if (res.ok && res.data) {
        var schema = res.data.schema || '';
        var count = (res.data.count != null) ? res.data.count
          : (Array.isArray(res.data.queues) ? res.data.queues.length
            : (Array.isArray(res.data.events) ? res.data.events.length
              : (Array.isArray(res.data.entries) ? res.data.entries.length : null)));
        host.appendChild(el('p', { 'class': 'ctl-desc', text: (schema ? String(schema) : 'ok · HTTP ' + res.status) + (count != null ? ' · ' + count + ' item(s)' : '') }));
      } else if (res.status === 402) {
        host.appendChild(el('p', { 'class': 'ctl-desc', text: 'Pro capability required — enable this workbench surface to read it.' }));
      } else {
        host.appendChild(el('p', { 'class': 'ctl-desc', text: res.status === 0 ? 'unreachable' : ('HTTP ' + res.status) }));
      }
    });
  }

  // =======================================================================
  //  Charts — a no-dependency, single-series inline-SVG area/line helper. One
  //  series only; the title names it, so there is NO legend. Stroke = var(--acc)
  //  2px (non-scaling); the area fills from a per-instance svg gradient
  //  (--acc low-opacity → transparent); gridlines are faint var(--edge); the
  //  final point carries an emphasised dot. Value labels are ink tokens with
  //  tabular-nums — never the series colour.
  // =======================================================================
  var __chartSeq = 0;
  function svgEl(name, attrs) {
    var node = doc().createElementNS('http://www.w3.org/2000/svg', name);
    if (attrs) { for (var k in attrs) { if (attrs[k] != null) { node.setAttribute(k, String(attrs[k])); } } }
    return node;
  }
  // Area+line chart over `values` (finite numbers). `opts`: { spark }. Returns an
  // <svg>, or null for a series too short to plot (caller shows an empty state).
  function areaChart(values, opts) {
    opts = opts || {};
    var vals = (values || []).map(Number).filter(function (n) { return isFinite(n); });
    if (vals.length < 2) { return null; }
    var spark = !!opts.spark;
    var W = spark ? 76 : 640, H = spark ? 24 : 180;
    var pad = spark ? 2 : 14, padB = spark ? pad : pad + 10;
    var min = Math.min.apply(null, vals), max = Math.max.apply(null, vals);
    var span = (max - min) || 1;
    var innerW = W - pad * 2, innerH = H - pad - padB;
    function x(i) { return pad + (innerW * i) / (vals.length - 1); }
    function y(v) { return pad + innerH * (1 - (v - min) / span); }
    var id = 'cxg' + (++__chartSeq);
    var svg = svgEl('svg', { 'class': spark ? 'chart-svg spark' : 'chart-svg', viewBox: '0 0 ' + W + ' ' + H, preserveAspectRatio: spark ? 'none' : 'xMidYMid meet', role: 'img', 'aria-hidden': 'true' });
    var defs = svgEl('defs');
    var grad = svgEl('linearGradient', { id: id, x1: '0', y1: '0', x2: '0', y2: '1' });
    grad.appendChild(svgEl('stop', { offset: '0%', 'stop-color': 'var(--acc)', 'stop-opacity': spark ? '0.3' : '0.34' }));
    grad.appendChild(svgEl('stop', { offset: '100%', 'stop-color': 'var(--acc)', 'stop-opacity': '0' }));
    defs.appendChild(grad); svg.appendChild(defs);
    if (!spark) {
      for (var g = 0; g <= 2; g++) {
        var gy = (pad + (innerH * g) / 2).toFixed(1);
        svg.appendChild(svgEl('line', { 'class': 'chart-grid', x1: pad, y1: gy, x2: W - pad, y2: gy, 'vector-effect': 'non-scaling-stroke' }));
      }
    }
    var line = '';
    for (var i = 0; i < vals.length; i++) { line += (i ? 'L' : 'M') + x(i).toFixed(1) + ' ' + y(vals[i]).toFixed(1) + ' '; }
    var base = (pad + innerH).toFixed(1);
    var area = line + 'L' + x(vals.length - 1).toFixed(1) + ' ' + base + ' L' + x(0).toFixed(1) + ' ' + base + ' Z';
    svg.appendChild(svgEl('path', { d: area, fill: 'url(#' + id + ')', stroke: 'none' }));
    svg.appendChild(svgEl('path', { 'class': 'chart-line', d: line.trim(), 'vector-effect': 'non-scaling-stroke' }));
    var ex = x(vals.length - 1).toFixed(1), ey = y(vals[vals.length - 1]).toFixed(1);
    if (!spark) { svg.appendChild(svgEl('circle', { 'class': 'chart-dot-ring', cx: ex, cy: ey, r: 4.5 })); }
    svg.appendChild(svgEl('circle', { 'class': 'chart-dot', cx: ex, cy: ey, r: spark ? 1.8 : 3 }));
    return svg;
  }
  function fmtChartVal(v, fmt) {
    if (typeof v !== 'number' || !isFinite(v)) { return '—'; }
    if (fmt === 'compact') {
      var abs = Math.abs(v);
      if (abs >= 1e6) { return (v / 1e6).toFixed(1) + 'M'; }
      if (abs >= 1e3) { return (v / 1e3).toFixed(1) + 'k'; }
    }
    try { return v.toLocaleString('en-US'); } catch (e) { return String(v); }
  }

  // The full chart CARD body: title + latest value, a Day / Week / Month range
  // switch (three .btn-quiet toggles, aria-pressed), and the area chart for the
  // active range. Series come from control.series (real) or — only when none is
  // provided and demo mode is on — from the CruxDemo fixture named by
  // control.demoKey. No series at all ⇒ an honest empty state (never a
  // fabricated single-scalar series).
  function renderChart(control) {
    var wrap = el('div', { 'class': 'chart-card' });
    var demoSeries = null;
    var series = control.series || null;
    if ((!series || !hasSeries(series)) && control.demoKey) { demoSeries = demoData(control.demoKey); series = demoSeries || series; }
    var head = el('div', { 'class': 'chart-head' }, [el('h3', { 'class': 'chart-title', text: control.title || 'Trend' })]);
    var latest = el('span', { 'class': 'chart-latest' });
    head.appendChild(latest);
    wrap.appendChild(head);
    if (control.sub) { wrap.appendChild(el('p', { 'class': 'chart-sub', text: control.sub })); }
    if (!series || !hasSeries(series)) {
      wrap.appendChild(el('p', { 'class': 'chart-empty', text: 'No time-series available yet' + (control.hint ? ' — ' + control.hint : '') + '.' }));
      return wrap;
    }
    if (demoSeries) { wrap.appendChild(demoChip(false)); }
    var figure = el('div', { 'class': 'chart-figure' });
    var rangeRow = el('div', { 'class': 'chart-range', role: 'group', 'aria-label': 'Chart range' });
    var order = [['day', 'Day'], ['week', 'Week'], ['month', 'Month']];
    function draw(rk) {
      var vals = series[rk] || [];
      figure.textContent = '';
      var chart = areaChart(vals, {});
      if (chart) { latest.textContent = fmtChartVal(vals[vals.length - 1], control.fmt); figure.appendChild(chart); }
      else { latest.textContent = ''; figure.appendChild(el('p', { 'class': 'chart-empty', text: 'Not enough points in this range.' })); }
      var btns = rangeRow.querySelectorAll('.btn-quiet');
      for (var i = 0; i < btns.length; i++) { btns[i].setAttribute('aria-pressed', btns[i].getAttribute('data-range') === rk ? 'true' : 'false'); }
    }
    order.forEach(function (r) {
      var b = el('button', { 'class': 'btn-quiet', type: 'button', 'data-range': r[0], 'aria-pressed': 'false' }, [r[1]]);
      if (!series[r[0]] || series[r[0]].length < 2) { b.disabled = true; }
      b.addEventListener('click', function () { draw(r[0]); });
      rangeRow.appendChild(b);
    });
    wrap.appendChild(rangeRow);
    wrap.appendChild(figure);
    var initial = (control.range && series[control.range] && series[control.range].length >= 2) ? control.range
      : (series.week && series.week.length >= 2 ? 'week' : (series.day && series.day.length >= 2 ? 'day' : 'month'));
    draw(initial);
    return wrap;
  }
  function hasSeries(s) {
    if (!s) { return false; }
    return ['day', 'week', 'month'].some(function (k) { return Array.isArray(s[k]) && s[k].length >= 2; });
  }

  // Bucket /v1/activity rows into a per-day count series (last `days` days) over
  // rows whose kind/tool matches `pred` — a REAL time-series (events/day), used
  // for the Facts + Sessions tile sparklines. Returns null when there's no signal.
  function bucketActivityByDay(rows, pred, days) {
    if (!Array.isArray(rows) || !rows.length) { return null; }
    var DAY = 86400000, now = Date.now();
    var buckets = new Array(days).fill(0), any = false;
    rows.forEach(function (r) {
      if (!pred(r)) { return; }
      var t = Number(r.ts_unix_ms || r.ts || r.at || r.time);
      if (!isFinite(t)) { return; }
      var idx = days - 1 - Math.floor((now - t) / DAY);
      if (idx >= 0 && idx < days) { buckets[idx]++; any = true; }
    });
    return any ? buckets : null;
  }

  // =======================================================================
  //  Control renderers — one branch per CONTROL_TYPES entry.
  // =======================================================================

  // The posture gate. Any mutating control is stamped operator-only and left
  // disabled until M3+. This is the single choke point the smoke audits.
  function applyMutationGate(node, control) {
    if (!control || !control.mut) { return node; }
    node.setAttribute('data-requires', 'operator');   // shell.applyPosture hides for customers
    node.hidden = !isOperator();                       // and belt-and-braces at render time
    var target = node.querySelector('input, select, textarea, button') || node;
    if (target && 'disabled' in target) { target.disabled = true; }
    node.classList.add('is-gated');
    node.setAttribute('title', GATE_TITLE);
    var tag = node.querySelector('.gate-tag');
    if (!tag) { node.appendChild(el('span', { 'class': 'gate-tag', text: GATE_TITLE })); }
    return node;
  }

  // ---- M13b live-write harness -------------------------------------------
  // A control whose label is a key in WIRED_WRITES is rendered ENABLED for
  // operators (never disabled, no "wired in M3+" tag) and fires a REAL, guarded
  // mutation. The guard harness on every wired write:
  //   1. operator posture — stampOperatorOnly hides it from customers AND
  //      operatorGatedCall refuses in customer posture (belt-and-braces);
  //   2. bound-passport Art.14 refusal — no passport ⇒ the write refuses;
  //   3. confirm dialog on the destructive subset (spec.confirm) BEFORE firing;
  //   4. the write runs ONLY through operatorGatedCall (the gated choke point, spec.run);
  //   5. the REAL backend response is rendered (receipt/id/state) — never faked.
  var ART14_MSG = 'Bind a passport first — Art.14 requires an attributed approver before any gated write.';

  // Operator-only stamp: hidden for customers (shell.applyPosture + belt-and-
  // braces here), but — unlike applyMutationGate — never disabled. Used for the
  // operator form fields and the live-wired write buttons.
  function stampOperatorOnly(node) {
    node.setAttribute('data-requires', 'operator');
    node.hidden = !isOperator();
    return node;
  }

  // Gather a { key: value } map from the enclosing form scope by data-k. Toggles
  // (data-toggle) yield booleans; everything else yields its string value.
  function collectForm(scope) {
    var out = {};
    if (!scope || !scope.querySelectorAll) { return out; }
    var nodes = scope.querySelectorAll('[data-k]');
    for (var i = 0; i < nodes.length; i++) {
      var n = nodes[i];
      var k = n.getAttribute('data-k');
      if (!k) { continue; }
      if (n.getAttribute('data-toggle') === '1') { out[k] = !!n.checked; }
      else { out[k] = (n.value != null ? n.value : ''); }
    }
    return out;
  }

  function splitIds(s) { return String(s == null ? '' : s).split(/[\s,]+/).map(function (x) { return x.trim(); }).filter(Boolean); }
  function num(s, dflt) { var v = parseFloat(s); return isFinite(v) ? v : dflt; }

  // Render the REAL response — a receipt id / created id / new state when the
  // backend returns one, an honest HTTP error otherwise. NEVER a fabricated hash.
  function formatReceipt(r) {
    if (!r) { return 'no response'; }
    var d = r.data || {};
    var rid = d.receipt_id || (d.receipt && (d.receipt.receipt_id || (typeof d.receipt === 'string' ? d.receipt : null)))
      || d.id || d.link_id || d.passport_id || d.scan_id || d.action_id;
    if (r.ok) {
      var bits = [];
      if (rid && typeof rid === 'string') { bits.push(rid); }
      if (d.status && typeof d.status === 'string') { bits.push(d.status); }
      if (d.state && typeof d.state === 'string') { bits.push(d.state); }
      if (d.connected != null) { bits.push(d.connected ? 'connected' : 'not connected'); }
      return 'OK · ' + (bits.length ? bits.join(' · ') : ('HTTP ' + r.status + ' · recorded'));
    }
    var detail = (d && (d.detail || d.error || d.message));
    return 'HTTP ' + r.status + (detail ? ' · ' + detail : '');
  }

  function showWiredResult(host, text, isErr) {
    host.textContent = '';
    host.appendChild(el('p', { 'class': 'wired-result' + (isErr ? ' is-err' : ' is-ok'), text: text }));
  }

  // Two-step in-DOM confirm for the destructive subset. Names the consequence +
  // scope; the write fires ONLY after the operator clicks Confirm.
  function showConfirm(host, message, onConfirm) {
    host.textContent = '';
    var panel = el('div', { 'class': 'wired-confirm', 'role': 'alertdialog', 'aria-label': 'Confirm destructive action' });
    panel.appendChild(el('p', { 'class': 'wired-confirm-msg', text: message }));
    var actions = el('div', { 'class': 'wired-confirm-actions' });
    var no = el('button', { 'class': 'btn-quiet wired-confirm-no', type: 'button' }, ['Cancel']);
    var yes = el('button', { 'class': 'btn-primary wired-confirm-go', type: 'button' }, ['Confirm']);
    no.addEventListener('click', function () { host.textContent = ''; });
    yes.addEventListener('click', function () { host.textContent = ''; onConfirm(); });
    actions.appendChild(no);
    actions.appendChild(yes);
    panel.appendChild(actions);
    host.appendChild(panel);
  }

  // The curated live-write registry. The key is the exact button label; each
  // `run(f, pp)` builds its body from the gathered form `f` + bound passport `pp`
  // and dispatches through operatorGatedCall (the sole gated-client choke point),
  // resolving to a normalised { ok, status, data }. `confirm` (string or fn(f))
  // marks the destructive/spend subset that requires a confirm dialog first.
  var WIRED_WRITES = {
    // ── additive creates (no confirm) ──────────────────────────────────────
    'Create project': { destructive: false, confirm: null,
      run: function (f) { return operatorGatedCall(function (g) { return g.createProject({ id: f.proj_id, name: f.proj_name }); }).then(readJson); } },
    'Create passport': { destructive: false, confirm: null,
      run: function (f) { return operatorGatedCall(function (g) { return g.createPassport({ id: f.pp_id, category: f.pp_category, name: f.pp_name, owner: f.pp_owner, position: f.pp_position, company: f.pp_company, notes: f.pp_notes }); }).then(readJson); } },
    'Add key': { destructive: false, confirm: null,
      run: function (f, pp) { return operatorGatedCall(function (g) { return g.extensionAddKey({ passport_fpr: f.key_fpr, public_key_hex: f.key_pub, trust_tier: f.key_tier, added_by: pp }); }).then(readJson); } },
    // ── outbound probes (SSRF-guarded / connect) — no confirm ───────────────
    'Probe endpoint': { destructive: false, confirm: null,
      run: function (f) { return operatorGatedCall(function (g) { return g.embeddingProbe({ url: f.embed_url }); }).then(readJson); } },
    'Verify connection': { destructive: false, confirm: null,
      run: function (f) { return operatorGatedCall(function (g) { return g.githubConnect({ pat: f.gh_pat, skip_verify: !!f.gh_skiptls }); }).then(readJson); } },
    'Scan path': { destructive: false, confirm: null,
      run: function () { return operatorGatedCall(function (g) { return g.workspaceScanRun({}); }).then(readJson); } },
    // ── workbench writes (receipted; additive) ──────────────────────────────
    'Build context pack': { destructive: false, confirm: null,
      run: function (f) { return operatorGatedCall(function (g) { return g.workbenchContextPack({ tenant_id: f.wb_ctx_tenant || f.wb_tenant || 'default', query: f.wb_ctx_query || '', token_budget: num(f.wb_ctx_budget, 2000) }); }).then(readJson); } },
    'Run impact preflight': { destructive: false, confirm: null,
      run: function (f) { return operatorGatedCall(function (g) { return g.workbenchImpactPreflight({ tenant_id: f.wb_pf_tenant || f.wb_tenant || 'default', changed_paths: splitIds(f.wb_target) }); }).then(readJson); } },
    'Simulate policy': { destructive: false, confirm: null,
      run: function (f) { return operatorGatedCall(function (g) { return g.workbenchPolicySimulation({ tool_name: 'policy.simulate', action_description: f.wb_sim_action || ('simulate ' + (f.wb_policy || 'policy')), tool_parameters: { policy_profile: f.wb_policy } }); }).then(readJson); } },
    'Probe route': { destructive: false, confirm: null,
      run: function (f) { return operatorGatedCall(function (g) { return g.workbenchRouteProbe({ route: f.wb_route || '', include_tests: false, include_storyline: false }); }).then(readJson); } },
    'Record capability audit': { destructive: false, confirm: null,
      run: function (f, pp) { return operatorGatedCall(function (g) { return g.featureCapabilityAudit(f.wb_cap_id || '', { status: f.wb_cap_status || 'pass', auditor: pp, notes: f.wb_cap_notes || '' }); }).then(readJson); } },
    // ── token-spend: outbound LLM call → confirm noting spend ────────────────
    'Test call': { destructive: false, confirm: 'This makes an OUTBOUND request to the connected LLM and MAY SPEND TOKENS on your account. Proceed?',
      run: function (f) { return operatorGatedCall(function (g) { return g.openaiChat({ model: (f.oa_model && f.oa_model !== 'none') ? f.oa_model : undefined, messages: [{ role: 'user', content: 'ping' }], max_tokens: 1 }); }).then(readJson); } },
    // ── destructive subset — each names its consequence + scope in confirm ──
    'Consolidate facts': { destructive: true,
      confirm: function (f) { return 'Writes a canonical fact for ' + (f.cr_entity || '?') + ' · ' + (f.cr_key || '?') + ' and SUPERSEDES the ' + splitIds(f.cr_targets).length + ' listed target fact(s) — they stop resolving. Fact-store mutation. Proceed?'; },
      run: function (f, pp) { return operatorGatedCall(function (g) { return g.reviewConsolidation({ consolidation_id: 'cons_' + Date.now().toString(36), entity: f.cr_entity, key: f.cr_key, canonical_value: f.cr_value, target_fact_ids: splitIds(f.cr_targets), protected_fact_ids: splitIds(f.cr_protected), confidence: num(f.cr_conf, 0.8), protected_confidence_floor: num(f.cr_floor, 0.99), actor: pp }); }).then(readJson); } },
    'Confirm candidate': { destructive: true,
      confirm: function (f) { return 'Creates the resolving identity link for candidate ' + (f.ic_candidate_id || '?') + ' (local ' + (f.ic_local_passport_id || '?') + ' ↔ remote ' + (f.ic_remote_fpr || '?') + ') — only if both signatures verify server-side. Irreversible resolution. Proceed?'; },
      run: function (f) { return operatorGatedCall(function (g) { return g.identityCandidateConfirm(f.ic_candidate_id || '', { local_passport_id: f.ic_local_passport_id, remote_fpr: f.ic_remote_fpr, remote_public_key_hex: f.ic_remote_public_key_hex, created_at: f.ic_created_at, sig_local: f.ic_sig_local, sig_remote: f.ic_sig_remote }); }).then(readJson); } },
    'Apply lane weights': { destructive: true,
      confirm: function (f) { return 'Writes FUSION_RRF_LANE_WEIGHTS to CoreCrux for ' + (f.tenant_id || f.tenant_pick || 'GLOBAL (all tenants)') + ' — changes retrieval ranking for that scope. Proceed?'; },
      run: function (f, pp) { var weights = {}; ['bm25', 'cosine', 'sparse', 'hyde', 'topology', 'vernacular', 'indexing', 'topology_trait_expansion', 'navtree', 'events'].forEach(function (lane) { var v = f['w_' + lane]; if (v != null && v !== '') { weights[lane] = num(v, 0); } }); return operatorGatedCall(function (g) { return g.laneWeightsApply({ tenant_id: f.tenant_id || f.tenant_pick || undefined, weights: weights, fusion_rrf_enabled: !!f.fusion_rrf, reason: f.reason || '', actor: pp }); }).then(readJson); } },
    'Reset lane weights': { destructive: true,
      confirm: 'Clears the lane-weight overlay (global scope) — retrieval reverts to CoreCrux defaults for every tenant that inherited it. Proceed?',
      run: function () { return operatorGatedCall(function (g) { return g.laneWeightsReset({}); }).then(readJson); } },
    'Restart daemon': { destructive: true,
      confirm: 'This RESTARTS THE DAEMON PROCESS — the daemon exits immediately (POST /v1/admin/restart) and relies on the service/container restart policy to come back. All in-flight requests drop and the console briefly disconnects. Proceed?',
      run: function () { return operatorGatedCall(function (g) { return g.adminRestart({}); }).then(readJson); } },
    'Re-run onboarding': { destructive: true,
      confirm: 'Resets onboarding — the first-run wizard shows again on next load and the recorded completion is cleared for this node. Proceed?',
      run: function () { return operatorGatedCall(function (g) { return g.onboardingRestart({}); }).then(readJson); } },
    // ── "Withhold all": no batch route — loops gateReject over every pending
    //    gate (read via fetchJSON, each reject through operatorGatedCall). ──────
    'Withhold all': { destructive: true,
      confirm: 'Rejects ALL currently-pending gated transitions (keeps every one from proceeding), each attributed to your passport. Bulk action across every pending gate. Proceed?',
      run: function (f, pp) {
        return fetchJSON('/v1/work/gate/pending').then(function (res) {
          var pend = (res && res.data && (res.data.pending || res.data.items)) || [];
          pend = pend.filter(function (p) { return (p.status || 'pending') === 'pending' && p.action_id; });
          if (!pend.length) { return { ok: true, status: 200, data: { status: '0 withheld — none pending' } }; }
          var okN = 0, errN = 0;
          return pend.reduce(function (chain, p) {
            return chain.then(function () {
              return operatorGatedCall(function (g) { return g.gateReject(p.action_id, { approver_passport: pp }); }).then(readJson).then(function (r) { if (r && r.ok) { okN++; } else { errN++; } });
            });
          }, Promise.resolve()).then(function () { return { ok: errN === 0, status: 200, data: { status: okN + ' withheld' + (errN ? ', ' + errN + ' failed' : '') } }; });
        });
      } }
  };

  // Wire a live-write button: the click handler runs the full guard harness.
  function attachWiredWrite(btn, node, control, spec) {
    var host = el('div', { 'class': 'wired-out', 'aria-live': 'polite' });
    node.appendChild(host);
    btn.addEventListener('click', function () {
      if (!isOperator()) { showWiredResult(host, 'Operator posture required — this control is unavailable in customer view.', true); return; }
      var pp = boundPassport();
      if (!pp) { showWiredResult(host, ART14_MSG, true); return; }
      var scope = btn.closest('.ctl-disclose-panel') || btn.closest('.exp-body') || btn.closest('.v2card') || node;
      var f = collectForm(scope);
      var fire = function () {
        host.textContent = '';
        btn.disabled = true;
        Promise.resolve().then(function () { return spec.run(f, pp); })
          .then(function (r) { showWiredResult(host, formatReceipt(r), !(r && r.ok)); })
          .catch(function (e) { showWiredResult(host, 'refused · ' + (e && e.message ? e.message : e), true); })
          .then(function () { btn.disabled = false; });
      };
      var msg = spec.confirm ? (typeof spec.confirm === 'function' ? spec.confirm(f) : spec.confirm) : null;
      if (msg) { showConfirm(host, msg, fire); } else { fire(); }
    });
  }

  function labelled(control, inner) {
    var row = el('div', { 'class': 'ctl-row' });
    if (control.label) { row.appendChild(el('label', { 'class': 'ctl-label', text: control.label })); }
    row.appendChild(inner);
    if (control.desc) { row.appendChild(el('p', { 'class': 'ctl-desc', text: control.desc })); }
    return row;
  }

  function renderControl(control, sectionCard) {
    var t = control.t;
    var node;
    switch (t) {
      case 'search': {
        var input = el('input', { 'class': 'ctl-input ctl-search', type: 'search', placeholder: control.ph || 'Filter…', 'aria-label': control.ph || 'Filter' });
        // Client-side filter over sibling rows in the same card (real M1 behaviour).
        input.addEventListener('input', function () {
          var q = input.value.trim().toLowerCase();
          var rows = sectionCard.querySelectorAll('.exp, .ctl-info');
          for (var i = 0; i < rows.length; i++) {
            var txt = (rows[i].textContent || '').toLowerCase();
            rows[i].style.display = (!q || txt.indexOf(q) >= 0) ? '' : 'none';
          }
        });
        node = el('div', { 'class': 'ctl-row' }, [input]);
        break;
      }
      case 'info': {
        node = el('div', { 'class': 'ctl-info' }, [
          el('span', { 'class': 'ctl-info-k', text: control.label != null ? String(control.label) : '' }),
          el('span', { 'class': 'ctl-info-v', text: control.v != null ? String(control.v) : '—' })
        ]);
        break;
      }
      case 'input': {
        var inp = el('input', { 'class': 'ctl-input' + (control.mono ? ' mono' : ''), type: control.secret ? 'password' : 'text', placeholder: control.ph || '', value: control.v != null ? control.v : '', 'data-k': control.k });
        // A mut input is operator-only (hidden for customers) but, unlike M1,
        // now ENABLED so the operator can fill a live-wired write's body.
        node = control.mut ? stampOperatorOnly(labelled(control, inp)) : labelled(control, inp);
        break;
      }
      case 'textarea': {
        var ta = el('textarea', { 'class': 'ctl-input ctl-textarea' + (control.mono ? ' mono' : ''), rows: control.rows || 3, placeholder: control.ph || '', text: control.v != null ? control.v : '', 'data-k': control.k });
        node = control.mut ? stampOperatorOnly(labelled(control, ta)) : labelled(control, ta);
        break;
      }
      case 'select': {
        var sel = el('select', { 'class': 'ctl-input ctl-select', 'data-k': control.k });
        var opts = control.options || [];
        for (var oi = 0; oi < opts.length; oi++) {
          var o = opts[oi];
          var val = (o && typeof o === 'object') ? (o.value != null ? o.value : o.v) : o;
          var lab = (o && typeof o === 'object') ? (o.label != null ? o.label : val) : o;
          var opt = el('option', { value: String(val), text: String(lab === '' ? '—' : lab) });
          if (String(val) === String(control.v)) { opt.setAttribute('selected', 'selected'); }
          sel.appendChild(opt);
        }
        node = control.mut ? stampOperatorOnly(labelled(control, sel)) : labelled(control, sel);
        break;
      }
      case 'toggle': {
        // LED toggle (legacy .active-toggle, index.html:388-392): a squarer
        // family chip with an 8px LED that glows (--ok) when on. The .on class
        // reflects control.v (the server value); the input carries the a11y
        // state; a mut toggle is operator-only but ENABLED (M13b) so its boolean
        // can feed a live-wired write (e.g. fusion_rrf → Apply lane weights).
        var box = el('label', { 'class': 'ctl-toggle' + (control.v ? ' on' : '') });
        var cb = el('input', { type: 'checkbox', 'data-k': control.k, 'data-toggle': control.k ? '1' : null });
        if (control.v) { cb.setAttribute('checked', 'checked'); }
        box.appendChild(cb);
        box.appendChild(el('span', { 'class': 'led', 'aria-hidden': 'true' }));
        box.appendChild(el('span', { 'class': 'ctl-toggle-label', text: control.label || '' }));
        var wrap = el('div', { 'class': 'ctl-row' }, [box]);
        if (control.desc) { wrap.appendChild(el('p', { 'class': 'ctl-desc', text: control.desc })); }
        node = control.mut ? stampOperatorOnly(wrap) : wrap;
        break;
      }
      case 'btn': {
        if (control.href) {
          // Deep-machinery fallback links (Pro console / 3D substrate) — quiet family.
          // A graphLaunch link (M9 "View graph") takes the small .cx-graphlink size.
          node = el('a', { 'class': 'btn-quiet' + (control.graphLaunch ? ' cx-graphlink' : ''), href: control.href, title: control.hint || '' }, [control.label || 'Open']);
          break;
        }
        // A mut button whose label is in WIRED_WRITES is LIVE (M13b): operator-
        // only + enabled, firing a real guarded mutation via attachWiredWrite.
        var wspec = control.mut ? WIRED_WRITES[control.label] : null;
        if (wspec) {
          var wbtn = el('button', { 'class': 'btn-quiet' + (control.danger ? ' danger' : ''), type: 'button', title: control.hint || control.label || 'Action' }, [control.label || 'Action']);
          node = el('div', { 'class': 'ctl-row wired-write' }, [wbtn]);
          stampOperatorOnly(node);
          attachWiredWrite(wbtn, node, control, wspec);
          break;
        }
        // Every other page-level button is the quiet family; `danger` is a colour
        // cue. A still-gated mut write stays disabled + "wired in M3+".
        var btn = el('button', { 'class': 'btn-quiet' + (control.danger ? ' danger' : ''), type: 'button', disabled: 'disabled', title: GATE_TITLE }, [control.label || 'Action']);
        node = el('div', { 'class': 'ctl-row' }, [btn]);
        if (control.mut) { node = applyMutationGate(node, control); }
        else { node.appendChild(el('span', { 'class': 'gate-tag', text: GATE_TITLE })); }
        break;
      }
      case 'chart': {
        node = renderChart(control);
        break;
      }
      case 'bar': {
        var pct = Math.max(0, Math.min(100, Number(control.pct) || 0));
        var track = el('div', { 'class': 'ctl-bar-track' }, [el('div', { 'class': 'ctl-bar-fill' + (control.tone ? ' ' + control.tone : '') })]);
        track.firstChild.style.width = pct + '%';
        node = el('div', { 'class': 'ctl-bar' }, [
          el('div', { 'class': 'ctl-bar-head' }, [el('span', { text: control.label || '' }), el('span', { 'class': 'ctl-bar-val', text: control.v != null ? String(control.v) : '' })]),
          track
        ]);
        break;
      }
      case 'rpcout': {
        node = el('pre', { 'class': 'ctl-rpcout', text: control.v != null ? String(control.v) : 'Response renders here.' });
        break;
      }
      case 'theme': {
        node = el('div', { 'class': 'ctl-row ctl-theme' }, [
          el('span', { 'class': 'ctl-info-k', text: 'theme' }),
          el('span', { 'class': 'ctl-info-v', text: 'switch in the sidebar (Glass · Dark · Light)' })
        ]);
        break;
      }
      case 'exp': {
        var det = el('details', { 'class': 'exp' });
        if (control.open) { det.setAttribute('open', 'open'); }
        if (control.hideIf && control.sys) { det.setAttribute('data-hideif', control.hideIf); }
        // Pro-board left colour strip, keyed by work/plan state (item 7). The
        // strip geometry (3px, radius-clipped) matches the Overwatch gate cards.
        if (control.strip) { det.classList.add('exp-strip'); det.setAttribute('data-strip', String(control.strip)); }
        var sum = el('summary', { 'class': 'exp-sum' }, [
          el('span', { 'class': 'exp-label', text: control.label || '' }),
          control.sub ? el('span', { 'class': 'exp-sub', text: control.sub }) : null,
          // Extra mono metadata (ids/timestamps) — always in the DOM but CSS-
          // hidden in Standard; Professional mode reveals it (legacy-list density).
          control.meta ? el('span', { 'class': 'exp-meta', text: String(control.meta) }) : null,
          control.badge ? el('span', { 'class': 'exp-badge', text: String(control.badge) }) : null
        ]);
        det.appendChild(sum);
        var body = el('div', { 'class': 'exp-body' });
        if (control.desc) { body.appendChild(el('p', { 'class': 'ctl-desc', text: control.desc })); }
        var kids = control.controls || [];
        for (var ki = 0; ki < kids.length; ki++) {
          var kc = renderControl(kids[ki], sectionCard);
          if (kc) { body.appendChild(kc); }
        }
        det.appendChild(body);
        node = det;
        break;
      }
      case 'disclose': {
        // Progressive disclosure (item 2c): a nav-family button that reveals its
        // form on click; a second click OR Escape collapses it. The whole control
        // carries data-requires="operator" (it leads to mutations — customers
        // never see it); the inner submit controls stay mut-gated (disabled,
        // "wired in M3+") exactly as elsewhere.
        var dwrap = el('div', { 'class': 'ctl-disclose' });
        var dbtn = el('button', { 'class': 'btn-quiet ctl-disclose-btn', type: 'button', 'aria-expanded': 'false' }, [control.label || 'Show']);
        var dpanel = el('div', { 'class': 'ctl-disclose-panel', hidden: 'hidden' });
        var dkids = control.controls || [];
        for (var dci = 0; dci < dkids.length; dci++) {
          var dcn = renderControl(dkids[dci], sectionCard);
          if (dcn) { dpanel.appendChild(dcn); }
        }
        var setOpen = function (open) {
          dbtn.setAttribute('aria-expanded', open ? 'true' : 'false');
          dpanel.hidden = !open;
        };
        dbtn.addEventListener('click', function () { setOpen(dbtn.getAttribute('aria-expanded') !== 'true'); });
        dpanel.addEventListener('keydown', function (ev) { if (ev.key === 'Escape') { setOpen(false); dbtn.focus(); } });
        dwrap.appendChild(dbtn);
        dwrap.appendChild(dpanel);
        if (control.requires === 'operator' || control.mut) {
          dwrap.setAttribute('data-requires', 'operator');   // shell.applyPosture hides for customers
          dwrap.hidden = !isOperator();
        }
        node = dwrap;
        break;
      }
      case 'repogrid': {
        // A project's linked repos as a card grid, fetched lazily (real rows win;
        // demo fixture fills only when empty — see loadRepoGrid).
        node = el('div', { 'class': 'repogrid-host' }, [el('p', { 'class': 'ctl-desc', text: 'Loading repos…' })]);
        loadRepoGrid(node, control.projectId);
        break;
      }
      case 'wbread': {
        // A live workbench READ tool (M13a): self-loads a /v1/workbench/* GET via
        // the api.js client (never a mutation, never the gated write client). Real payload
        // wins; an honest degraded / pro-gate note otherwise.
        node = el('div', { 'class': 'wbread-host' }, [el('div', { 'class': 'ctl-info' }, [
          el('span', { 'class': 'ctl-info-k', text: control.label || 'read tool' }),
          el('span', { 'class': 'ctl-info-v', text: 'loading…' })
        ])]);
        loadWorkbenchRead(node, control);
        break;
      }
      default: {
        // Unknown control type: render an inert note rather than crash.
        node = el('div', { 'class': 'ctl-info' }, [el('span', { 'class': 'ctl-info-k', text: String(t || '?') }), el('span', { 'class': 'ctl-info-v', text: '(unrenderable control)' })]);
      }
    }
    return node;
  }

  function renderSection(section) {
    var card = el('section', { 'class': 'v2card' + (section.wide ? ' wide' : '') });
    if (section.h) { card.appendChild(el('h3', { 'class': 'v2card-h', text: section.h })); }
    if (section.sub) { card.appendChild(el('p', { 'class': 'v2card-sub', text: section.sub })); }
    if (section.tiles) {
      var grid = el('div', { 'class': 'stats' });
      for (var ti = 0; ti < section.tiles.length; ti++) {
        var tile = section.tiles[ti];
        var v = el('div', { 'class': 'v', text: String(tile[1]) });
        if (tile[2]) { v.appendChild(doc().createTextNode(' ')); v.appendChild(el('small', { text: String(tile[2]) })); }
        grid.appendChild(el('div', { 'class': 'stat' }, [el('div', { 'class': 'k', text: String(tile[0]) }), v]));
      }
      card.appendChild(grid);
    }
    var controls = section.controls || [];
    var body = el('div', { 'class': 'v2card-body' });
    for (var i = 0; i < controls.length; i++) {
      var cn = renderControl(controls[i], card);
      if (cn) { body.appendChild(cn); }
    }
    card.appendChild(body);
    return card;
  }

  function renderSections(container, sections) {
    container.textContent = '';
    var grid = el('div', { 'class': 'v2grid' });
    var pro = proMode();
    for (var i = 0; i < sections.length; i++) {
      // A section tagged pro:true renders only in Professional mode (full page
      // surface). Standard curates it away. This is presentation, never posture.
      if (sections[i] && sections[i].pro && !pro) { continue; }
      grid.appendChild(renderSection(sections[i]));
    }
    container.appendChild(grid);
  }

  // =======================================================================
  //  Overwatch landing — Overwatch-concept look (post-M6). A full-width stat-
  //  tile row, then a 7fr/5fr split: NEEDS YOU gate cards on the left, FLEET +
  //  ACTIVITY ticker (+ the engine card when mediation answers) on the right.
  //  Bespoke DOM (not the page DSL) so the gate cards carry real, posture-gated
  //  approve/return handlers. Behaviour is unchanged from M3 — every panel still
  //  renders a real-fields-only degraded/empty state and never throws. Only the
  //  DOM/class shape changed to match the concept.
  // =======================================================================

  // A landing panel: a mono section header (concept .sechead) with a right-
  // aligned live count/link, over a body the async fills populate.
  function panel(title, ctText, first, linkText, linkHref) {
    var wrap = el('div', { 'class': 'ow-panel' });
    var head = el('div', { 'class': 'ow-sec' + (first ? ' first' : '') }, [el('h2', { text: title })]);
    var ct = el('span', { 'class': 'ow-ct', text: ctText || '' });
    head.appendChild(ct);
    if (linkText) { head.appendChild(el('a', { 'class': 'ow-link', href: linkHref || '#' }, [linkText])); }
    var body = el('div', { 'class': 'ow-body' });
    wrap.appendChild(head);
    wrap.appendChild(body);
    wrap.__ct = ct; wrap.__body = body;
    return wrap;
  }
  function setCt(wrap, text) { if (wrap && wrap.__ct) { wrap.__ct.textContent = String(text); } }

  // Minimal inline SVGs (this module has no icon set) — a check + a return
  // arrow, used on the approve button, the done-line, and the all-clear state.
  function svgIcon(paths, w) {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="' + (w || 2) +
      '" stroke-linecap="round" stroke-linejoin="round">' + paths + '</svg>';
  }
  var SVG_CHECK = svgIcon('<path d="M4.5 12.5l5 5L19.5 7"/>', 2.4);
  var SVG_RETURN = svgIcon('<path d="M9 14L4 9l5-5"/><path d="M4 9h11a5 5 0 0 1 0 10h-4"/>');
  function iconBtn(cls, iconHtml, label) {
    var b = el('button', { 'class': cls, type: 'button' });
    if (iconHtml) { b.innerHTML = iconHtml; }
    b.appendChild(doc().createTextNode(label));
    return b;
  }
  // Two-letter initials for the mini gradient avatar (derived from the real
  // passport id — never a fabricated display name).
  function initials(pid) {
    var s = String(pid || '').replace(/^p_/, '').replace(/[^A-Za-z0-9]/g, '');
    return (s.slice(0, 2) || '··').toUpperCase();
  }
  function noteChip(text) { return el('span', { 'class': 'ow-chip', text: String(text) }); }
  function kv(k, v) {
    return el('div', { 'class': 'ctl-info' }, [
      el('span', { 'class': 'ctl-info-k', text: String(k) }),
      el('span', { 'class': 'ctl-info-v', text: (v == null || v === '') ? '—' : String(v) })
    ]);
  }
  function tsLabel(ms) {
    if (ms == null) { return '—'; }
    var d = new Date(Number(ms));
    return isNaN(d.getTime()) ? String(ms) : d.toISOString().slice(0, 16).replace('T', ' ');
  }

  // Mark a landing panel as demo-fed (an inline chip in its section header).
  function markPanelDemo(wrap) {
    var head = wrap && wrap.querySelector ? wrap.querySelector('.ow-sec') : null;
    if (head && !head.querySelector('.demo-chip')) { head.appendChild(demoChip(true)); }
  }

  // Shared fleet-row builder (real join rows AND demo fixtures use it, so the two
  // render byte-identically). `row`: { sessionHex, passport, execplan, milestone,
  // intent, leases[], overlaps[], orchestrators[], snapshot, live }.
  function fleetRow(row) {
    var live = !!(row.sessionHex || row.intent || row.milestone || row.live);
    var frow = el('div', { 'class': 'ow-fleet-row' });
    frow.appendChild(el('span', { 'class': 'ow-dot' + (live ? ' pulse' : ' idle'), 'aria-hidden': 'true' }));
    var meta = el('div', { 'class': 'ow-fleet-meta' }, [
      el('b', { text: (row.sessionHex ? row.sessionHex + ' · ' : '') + (row.passport || '—') })
    ]);
    var focusText = [row.execplan && (row.execplan + (row.milestone ? ' @ ' + row.milestone : '')), row.intent].filter(Boolean).join(' · ') || 'idle';
    meta.appendChild(el('div', { 'class': 'ow-focus', text: focusText, title: focusText }));
    var leases = row.leases || [], overlaps = row.overlaps || [];
    if (leases.length || overlaps.length) {
      var lz = el('div', { 'class': 'ow-leases' });
      leases.forEach(function (l) { lz.appendChild(el('span', { 'class': 'ow-lease', text: l })); });
      if (overlaps.length) { lz.appendChild(el('span', { 'class': 'ow-lease ov', text: '⚠ ' + overlaps.length + ' overlap' + (overlaps.length === 1 ? '' : 's') })); }
      meta.appendChild(lz);
    }
    // Cross-feature launch point (M9): open this session's neighbourhood in the
    // Canvas relation graph. Read-only link — visible in both postures.
    meta.appendChild(el('a', { 'class': 'btn-quiet cx-graphlink', href: '#/canvas/graph?focus=session:' + (row.sessionHex || row.passport || ''), title: 'Open in the Canvas relation graph' }, ['View graph']));
    frow.appendChild(meta);
    var side = el('div', { 'class': 'ow-fleet-side' });
    if ((row.orchestrators || []).length) { side.appendChild(el('div', { text: row.orchestrators.join(', ') })); }
    if (row.snapshot) { side.appendChild(el('div', { text: 'snap ' + row.snapshot })); }
    if (side.childNodes.length) { frow.appendChild(side); }
    return frow;
  }

  // Shared activity ticker builder (real rows AND demo fixtures).
  function activityTicker(rows) {
    var ticker = el('div', { 'class': 'ow-ticker' });
    (rows || []).slice(0, 12).forEach(function (r0) {
      var tick = el('div', { 'class': 'ow-tick' });
      var rid = (r0.receipt_ids || [])[0] || r0.receipt_id;
      if (rid) { tick.appendChild(el('span', { 'class': 'ow-hash', text: rid })); }
      var label = (r0.kind || 'event') + (r0.tool ? ' · ' + r0.tool : '');
      tick.appendChild(el('span', { 'class': 'ow-tick-label', text: label, title: r0.preview || label }));
      if (r0.ts) { tick.appendChild(el('span', { 'class': 'ow-tick-ts', text: String(r0.ts) })); }
      ticker.appendChild(tick);
    });
    return ticker;
  }

  // ---- Demo panel fills — each returns true when it painted from fixtures ---
  // These run ONLY when a real panel came back empty/degraded (real data wins).
  // A read-only demo gate card (no live approve/return in demo mode).
  function demoGateCard(p) {
    var wrap = el('div', { 'class': 'ow-gate' });
    var top = el('div', { 'class': 'ow-gate-top' }, [el('span', { 'class': 'ow-badge', text: 'ART.14 HUMAN GATE' })]);
    if (p.risk_class) { top.appendChild(el('span', { 'class': 'ow-badge risk', text: 'RISK · ' + String(p.risk_class).toUpperCase() })); }
    top.appendChild(el('span', { 'class': 'ow-slug', text: p.action_id || '' }));
    wrap.appendChild(top);
    wrap.appendChild(el('h3', { text: p.work_id || p.action_id || 'gated transition' }));
    wrap.appendChild(el('p', { 'class': 'ow-gate-action', text: (p.requested_action || 'update_state') + (p.target_state ? ' → ' + p.target_state : '') }));
    wrap.appendChild(el('div', { 'class': 'ow-attr' }, [
      el('span', { 'class': 'ow-avatar', text: initials(p.requested_by_passport) }),
      el('span', { text: 'requested by ' + (p.requested_by_passport || '?') + ' · ' + tsLabel(p.requested_at_unix_ms) })
    ]));
    if (p.consequences && p.consequences.length) {
      var c = el('div', { 'class': 'ow-conseq' });
      if (p.narrative) { c.appendChild(el('p', { 'class': 'ow-narrative', text: p.narrative })); }
      p.consequences.slice(0, 5).forEach(function (row) {
        c.appendChild(el('div', { 'class': 'ow-conseq-row' }, [
          el('span', {}, [el('b', { text: row.consequence_type || 'consequence' }), doc().createTextNode(' — ' + (row.detail || '') + (row.target ? ' · ' + row.target : ''))])
        ]));
      });
      wrap.appendChild(c);
    }
    wrap.appendChild(el('p', { 'class': 'ow-await', text: 'Demo fixture — approve / return is disabled in demo mode.' }));
    return wrap;
  }
  function demoNeedsYou(wrap) {
    var list = demoData('needsYou');
    if (!list || !list.length) { return false; }
    var body = wrap.__body;
    body.textContent = '';
    setCt(wrap, list.length + ' pending · demo fixtures');
    markPanelDemo(wrap);
    list.forEach(function (p) { body.appendChild(demoGateCard(p)); });
    return true;
  }
  function demoFleet(wrap) {
    var list = demoData('fleet');
    if (!list || !list.length) { return false; }
    var body = wrap.__body;
    body.textContent = '';
    setCt(wrap, list.length + ' session' + (list.length === 1 ? '' : 's') + ' · demo fixtures');
    markPanelDemo(wrap);
    list.forEach(function (row) { body.appendChild(fleetRow(row)); });
    return true;
  }
  function demoActivity(wrap) {
    var rows = demoData('activity');
    if (!rows || !rows.length) { return false; }
    var body = wrap.__body;
    body.textContent = '';
    setCt(wrap, rows.length + ' recent · demo fixtures');
    markPanelDemo(wrap);
    body.appendChild(activityTicker(rows));
    return true;
  }

  // Stat tiles: reuse cx-overview's exact tile set (pages.js buildOverview via
  // its load.build) so the landing readout never drifts from the page.
  function fillTiles(card, ctx) {
    var ready = ctx.summary
      ? Promise.resolve({ ok: true, status: 200, data: ctx.summary })
      : fetchJSON('/v1/console/summary');
    return ready.then(function (res) {
      card.textContent = '';
      var CP = (typeof window !== 'undefined') ? window.CruxPages : null;
      var page = CP && CP.PAGES && CP.PAGES['cx-overview'];
      if (page && page.load && typeof page.load.build === 'function') {
        var sections;
        try { sections = page.load.build(res); } catch (e) { sections = []; }
        (sections || []).forEach(function (sec) { card.appendChild(renderSection(sec)); });
      } else {
        card.appendChild(kv('summary', res.ok ? 'loaded' : 'unavailable'));
        return;
      }
      // Expand + chart the Daemon-at-a-glance tiles (ExecPlans + Token usage +
      // the moved Engine tile, legacy-size identity numbers, honest charts).
      return decorateTiles(card, ctx, res);
    });
  }
  var __glanceRows = null;               // cached /v1/activity rows for range re-bucketing
  var __glanceDays = 7;                   // active window: Day=7 · Week=30 · Month=90
  function addTileSparklines(card) {
    return fetchJSON('/v1/activity?tenant_id=default&token_budget=1500').then(function (res) {
      __glanceRows = (res.ok && res.data && res.data.rows) ? res.data.rows : [];
      paintGlanceSparks(card, __glanceDays);
    });
  }
  // Re-bucket the two REAL time-series tiles (Facts · Sessions) over the active
  // window and repaint their sparklines. The scalar/meter tiles are point-in-time
  // counters with no ranged series, so the range toggle honestly leaves them be.
  function paintGlanceSparks(card, days) {
    __glanceDays = days;
    attachSpark(card, 'Facts', seriesFor(__glanceRows || [], /fact/i, 'factsSpark', days));
    attachSpark(card, 'Sessions', seriesFor(__glanceRows || [], /session/i, 'sessionsSpark', days));
  }
  function seriesFor(rows, re, demoKey, days) {
    var real = bucketActivityByDay(rows, function (r) { return re.test((r.kind || '') + ' ' + (r.tool || '')); }, days || 7);
    if (real) { return { vals: real, demo: false }; }
    var d = demoData(demoKey);
    return d ? { vals: d, demo: true } : null;
  }
  // Replace (not stack) the tile's spark + demo chip so range switches repaint cleanly.
  function attachSpark(card, label, s) {
    var stats = card.querySelectorAll('.stat');
    for (var i = 0; i < stats.length; i++) {
      var k = stats[i].querySelector('.k');
      if (k && k.textContent.trim().toLowerCase() === label.toLowerCase()) {
        var tile = stats[i];
        var old = tile.querySelector('.chart-svg'); if (old && old.parentNode) { old.parentNode.removeChild(old); }
        var oldChip = tile.querySelector('.demo-chip'); if (oldChip && oldChip.parentNode) { oldChip.parentNode.removeChild(oldChip); }
        if (!s || !s.vals) { return; }
        var sp = areaChart(s.vals, { spark: true });
        if (sp) { tile.appendChild(sp); if (s.demo) { tile.appendChild(demoChip(true)); } }
        return;
      }
    }
  }
  // Day / Week / Month range toggle, injected top-right of the glance header
  // (reuses the .modeseg presentation-control look). Only the two real-series
  // tiles respond; the honest choke point is paintGlanceSparks.
  function buildGlanceRange(card) {
    var heads = card.querySelectorAll('.v2card-h'), h = null;
    for (var i = 0; i < heads.length; i++) {
      if (heads[i].textContent.trim().toLowerCase() === 'daemon at a glance') { h = heads[i]; break; }
    }
    if (!h || !h.parentNode || h.parentNode.querySelector('.glance-range')) { return; }
    var seg = el('div', { 'class': 'modeseg glance-range', role: 'group', 'aria-label': 'Activity range' });
    [['Day', 7], ['Week', 30], ['Month', 90]].forEach(function (r) {
      var b = el('button', { 'class': 'modeseg-btn', type: 'button', text: r[0] });
      b.setAttribute('aria-pressed', r[1] === __glanceDays ? 'true' : 'false');
      b.addEventListener('click', function () {
        var btns = seg.querySelectorAll('.modeseg-btn');
        for (var j = 0; j < btns.length; j++) { btns[j].setAttribute('aria-pressed', 'false'); }
        b.setAttribute('aria-pressed', 'true');
        paintGlanceSparks(card, r[1]);
      });
      seg.appendChild(b);
    });
    var row = el('div', { 'class': 'v2card-head-row' });
    h.parentNode.insertBefore(row, h);
    row.appendChild(h);
    row.appendChild(seg);
  }

  // ---- Daemon-at-a-glance expansion (landing-only) -----------------------
  // buildOverview (pages.js) emits the six base tiles; the landing owns the
  // expansion so the standalone cx-overview page stays lean. HONESTY per tile:
  //  · Facts / Sessions — legacy-size number + REAL /v1/activity events/day
  //    sparkline (bucketActivityByDay; demo only when the feed is empty + demo on).
  //  · ExecPlans — legacy-size number, REAL count from /v1/work?source=all.
  //  · Token usage — REAL headline scalar from /v1/cost/report; the trend chart is
  //    demoOn()-guarded because the cost lens has NO real bucketed series yet (see
  //    pages.js usageTrend hint), so a fabricated line never renders as real.
  //  · Storage free — an honest METER from the REAL free_ratio (no series at all).
  //  · MCP agents / Integrations — pure scalars with no real series: the chart is
  //    demoOn()-guarded demo only (demo-chipped), never a fabricated real line.
  //  · Engine — a REAL rolling latency micro-series measured client-side (probes
  //    /v1/console/engine/summary); demo/scalar fallback when mediation is off.
  function statByLabel(card, label) {
    var stats = card.querySelectorAll('.stat');
    for (var i = 0; i < stats.length; i++) {
      var k = stats[i].querySelector('.k');
      if (k && k.textContent.trim().toLowerCase() === String(label).toLowerCase()) { return stats[i]; }
    }
    return null;
  }
  function markStatLarge(card, label) { var s = statByLabel(card, label); if (s) { s.classList.add('stat-lg'); } }
  function markStatDemo(stat) { if (stat && !stat.querySelector('.demo-chip')) { stat.appendChild(demoChip(true)); } }
  // Build a .stat node with the SAME structure renderSection emits.
  function makeStat(label, value, sub) {
    var v = el('div', { 'class': 'v', text: String(value) });
    if (sub) { v.appendChild(doc().createTextNode(' ')); v.appendChild(el('small', { text: String(sub) })); }
    return el('div', { 'class': 'stat' }, [el('div', { 'class': 'k', text: String(label) }), v]);
  }
  // Insert a new tile before/after an anchor tile (by label), or at the grid end.
  function injectStat(card, anchorLabel, pos, label, value) {
    var grid = card.querySelector('.stats');
    if (!grid) { return null; }
    var stat = makeStat(label, value, null);
    var anchor = anchorLabel ? statByLabel(card, anchorLabel) : null;
    if (pos === 'end' || !anchor) { grid.appendChild(stat); return stat; }
    if (pos === 'before') { grid.insertBefore(stat, anchor); }
    else { grid.insertBefore(stat, anchor.nextSibling); }
    return stat;
  }
  function setStatValue(stat, value, sub) {
    if (!stat) { return; }
    var v = stat.querySelector('.v');
    if (!v) { return; }
    v.textContent = String(value);
    if (sub) { v.appendChild(doc().createTextNode(' ')); v.appendChild(el('small', { text: String(sub) })); }
  }
  // demoOn()-guarded demo spark for a pure-scalar tile (no real series exists);
  // demoData() returns null when demo is off, so nothing shows unless demo mode.
  function attachDemoSpark(card, label, demoKey) {
    var stat = statByLabel(card, label);
    if (!stat) { return; }
    var d = demoData(demoKey);                       // demoOn()-guarded choke point
    if (!d) { return; }
    var vals = Array.isArray(d) ? d : (d.week || d.day || d.month);
    var sp = areaChart(vals, { spark: true });
    if (sp) { stat.appendChild(sp); markStatDemo(stat); }
  }
  // Honest gauge/meter for a REAL ratio (0..1) — no fabricated series.
  function attachMeter(stat, ratio) {
    if (!stat) { return; }
    var r = Number(ratio);
    if (!isFinite(r)) { return; }
    var pct = Math.max(0, Math.min(100, r * 100));
    var track = el('div', { 'class': 'tile-meter', role: 'img', 'aria-label': pct.toFixed(0) + '% free' },
      [el('div', { 'class': 'tile-meter-fill' })]);
    track.firstChild.style.width = pct.toFixed(1) + '%';
    stat.appendChild(track);
  }
  // Rolling REAL latency buffer — accumulates measured engine round-trips across
  // landing renders. A single view bursts a few probes so the spark is real data.
  var __engineLatencyBuf = [];
  function fillEngineTile(stat) {
    if (!stat) { return; }
    var MAX = 30, BURST = 4;
    function paint() {
      var old = stat.querySelector('.chart-svg'); if (old && old.parentNode) { old.parentNode.removeChild(old); }
      if (__engineLatencyBuf.length) {
        setStatValue(stat, __engineLatencyBuf[__engineLatencyBuf.length - 1], 'ms');
        if (__engineLatencyBuf.length >= 2) {
          var sp = areaChart(__engineLatencyBuf, { spark: true });
          if (sp) { stat.appendChild(sp); }
        }
        return;
      }
      // No real sample — a demoOn()-guarded demo series (demo-chipped) or an
      // honest "off" scalar. Never a fabricated real latency line.
      var d = demoData('engineLatencySeries');
      if (d && d.length) { setStatValue(stat, d[d.length - 1], 'ms'); var s2 = areaChart(d, { spark: true }); if (s2) { stat.appendChild(s2); } markStatDemo(stat); }
      else { setStatValue(stat, 'off', null); }
    }
    function probe(n) {
      if (n <= 0) { paint(); return; }
      fetchJSON('/v1/console/engine/summary').then(function (r) {
        if (r.ok && r.data && r.data.engine_reachable && r.data.engine_latency_ms != null) {
          __engineLatencyBuf.push(Number(r.data.engine_latency_ms));
          if (__engineLatencyBuf.length > MAX) { __engineLatencyBuf.shift(); }
          probe(n - 1);   // keep probing to fill the rolling buffer with REAL samples
        } else { paint(); }   // unreachable / off — stop early, fall back honestly
      }).catch(function () { paint(); });
    }
    probe(BURST);
  }
  function decorateTiles(card, ctx, res) {
    var summary = (res && res.data) || (ctx && ctx.summary) || {};
    // Legacy-size numbers on the identity tiles (index.html renderDash .dash-num).
    markStatLarge(card, 'Facts');
    markStatLarge(card, 'Sessions');
    // Inject the two new tiles in place + the moved Engine tile at the end.
    var execStat = injectStat(card, 'Sessions', 'after', 'ExecPlans', 'loading…');
    if (execStat) { execStat.classList.add('stat-lg'); }
    injectStat(card, 'Storage free', 'before', 'Token usage', 'loading…');
    var engineStat = injectStat(card, null, 'end', 'Engine', '—');
    // Facts + Sessions REAL activity sparklines + the Day/Week/Month range toggle.
    buildGlanceRange(card);
    var work = addTileSparklines(card);
    // ExecPlans — REAL count from /v1/work (demo fixture only when the feed is empty).
    fetchJSON('/v1/work?source=all').then(function (r) {
      var items = (r.ok && r.data) ? (r.data.work || r.data.items || []) : [];
      if (!items || !items.length) { var dw = demoData('work'); if (dw) { items = dw; markStatDemo(execStat); } }
      setStatValue(execStat, (items ? items.length : 0), 'plans');
    });
    // Token usage — REAL headline scalar; the trend spark is demoOn()-guarded.
    fetchJSON('/v1/cost/report?tenant_id=default&token_budget=1500').then(function (r) {
      var d = (r.ok && r.data) ? r.data : null;
      var head = d && d.report && d.report.report && d.report.report.headline;
      var us = statByLabel(card, 'Token usage');
      if (head && head.context_tokens_per_turn != null) { setStatValue(us, fmtChartVal(head.context_tokens_per_turn, 'compact'), '/ turn'); }
      else { setStatValue(us, '—', 'no report'); }
      attachDemoSpark(card, 'Token usage', 'usageSeries');
    });
    // Storage free — an honest meter from the REAL free_ratio.
    attachMeter(statByLabel(card, 'Storage free'), get(summary, ['capacity', 'free_ratio']));
    // MCP agents + Integrations — demoOn()-guarded demo sparks only (no real series).
    attachDemoSpark(card, 'MCP agents', 'mcpSeries');
    attachDemoSpark(card, 'Integrations', 'integrationsSeries');
    // Engine — REAL client-side latency micro-series (moved off the right column).
    fillEngineTile(engineStat);
    return work;
  }

  // Needs-you: pending gates from GET /v1/work/gate/pending. Operator posture
  // gets approve / return-with-note (+ foresight); customer gets a read-only
  // queue.
  function fillNeedsYou(wrap) {
    var body = wrap.__body;
    return fetchJSON('/v1/work/gate/pending').then(function (res) {
      body.textContent = '';
      if (!res.ok || !res.data) {
        if (demoNeedsYou(wrap)) { return; }   // demo fills only a degraded panel
        setCt(wrap, 'gate queue unavailable');
        body.appendChild(kv(res.status === 0 ? 'unreachable' : ('HTTP ' + res.status), 'GET /v1/work/gate/pending'));
        return;
      }
      var pending = (res.data.pending || []).filter(function (p) { return (p.status || 'pending') === 'pending'; });
      if (!pending.length && demoNeedsYou(wrap)) { return; }   // demo fills only an empty panel
      setCt(wrap, pending.length + ' pending · /v1/work/gate/pending' + (isOperator() ? '' : ' · awaiting operator'));
      if (!pending.length) {
        var ok = el('div', { 'class': 'ow-allclear' });
        ok.innerHTML = SVG_CHECK;
        ok.appendChild(el('div', {}, [
          el('b', { text: 'All clear — agents unblocked' }),
          el('span', { text: 'no gated transitions are waiting' })
        ]));
        body.appendChild(ok);
        return;
      }
      pending.forEach(function (p) { body.appendChild(gateCard(p)); });
    });
  }

  function gateCard(p) {
    var wrap = el('div', { 'class': 'ow-gate', 'data-action-id': p.action_id });
    var who = p.requested_by_passport || '?';
    // Top row: the Art.14 badge (these pending items ARE human gates), a real
    // risk badge only if the API carries one, and the action-id slug chip.
    var top = el('div', { 'class': 'ow-gate-top' }, [el('span', { 'class': 'ow-badge', text: 'ART.14 HUMAN GATE' })]);
    if (p.risk_class) { top.appendChild(el('span', { 'class': 'ow-badge risk', text: 'RISK · ' + String(p.risk_class).toUpperCase() })); }
    top.appendChild(el('span', { 'class': 'ow-slug', text: p.action_id || '' }));
    wrap.appendChild(top);
    // Title = the work being gated; the requested transition sits under it.
    wrap.appendChild(el('h3', { text: p.work_id || p.action_id || 'gated transition' }));
    wrap.appendChild(el('p', { 'class': 'ow-gate-action', text: (p.requested_action || 'update_state') + (p.target_state ? ' → ' + p.target_state : '') }));
    // Attribution — mono line with a mini gradient avatar from the passport id.
    wrap.appendChild(el('div', { 'class': 'ow-attr' }, [
      el('span', { 'class': 'ow-avatar', text: initials(who) }),
      el('span', { text: 'requested by ' + who + ' · ' + tsLabel(p.requested_at_unix_ms) })
    ]));
    if (!isOperator()) {
      wrap.appendChild(el('p', { 'class': 'ow-await', text: 'Read-only in customer view — awaiting operator approval.' }));
      return wrap;
    }
    // Operator: foresight consequences + approve / return-with-note. All the
    // interactive machinery lives in .ow-gate-op so markResolved can swap it for
    // the done-line without touching the header above.
    var op = el('div', { 'class': 'ow-gate-op' });
    wrap.appendChild(op);
    var conseq = el('div', { 'class': 'ow-conseq' }, [el('p', { 'class': 'ow-narrative', text: 'Loading consequences…' })]);
    op.appendChild(conseq);
    loadConsequences(p, conseq);
    op.appendChild(el('div', { 'class': 'ow-attr' }, [el('span', { text: 'approving as ' + (boundPassport() || 'bind a passport (Art. 14)') })]));
    var note = el('input', { 'class': 'ow-note', type: 'text', placeholder: 'optional note — returned to the requester as a work comment', 'aria-label': 'Return note' });
    var status = el('p', { 'class': 'ow-status' });
    var approveBtn = iconBtn('btn-primary', SVG_CHECK, 'Approve');
    var returnBtn = iconBtn('btn-quiet', SVG_RETURN, 'Return with note');
    op.appendChild(el('div', { 'class': 'ow-actions' }, [approveBtn, returnBtn]));
    op.appendChild(note);
    op.appendChild(status);
    function unlock() { approveBtn.disabled = false; returnBtn.disabled = false; }
    function lock(msg) { approveBtn.disabled = true; returnBtn.disabled = true; status.textContent = msg || ''; }
    approveBtn.addEventListener('click', function () {
      var who = boundPassport();
      if (!who) { status.textContent = 'Bind a passport to approve — approvals must be attributed (Art. 14).'; return; }
      lock('Approving…');
      approveGate(p.action_id, who).then(readJson).then(function (r) {
        if (r.ok) { markResolved(wrap, 'approved', r.data, who); }
        else { status.textContent = 'Approve failed · HTTP ' + r.status + (r.data && r.data.detail ? ' · ' + r.data.detail : ''); unlock(); }
      }).catch(function (e) { status.textContent = 'Approve failed · ' + (e && e.message || e); unlock(); });
    });
    returnBtn.addEventListener('click', function () {
      var who = boundPassport();
      if (!who) { status.textContent = 'Bind a passport to return — decisions must be attributed (Art. 14).'; return; }
      lock('Returning…');
      var noteText = (note.value || '').trim();
      var pre = noteText ? commentWork(p.work_id, who, noteText).then(readJson) : Promise.resolve({ ok: true });
      pre.then(function () { return rejectGate(p.action_id, who).then(readJson); }).then(function (r) {
        if (r.ok) { markResolved(wrap, 'returned', r.data, who); }
        else { status.textContent = 'Return failed · HTTP ' + r.status; unlock(); }
      }).catch(function (e) { status.textContent = 'Return failed · ' + (e && e.message || e); unlock(); });
    });
    return wrap;
  }

  // Optimistic resolve. The backend returns the updated WorkItem (not a
  // receipt), so surface only REAL fields; a receipt id renders here only if
  // the response carries one, else "recorded" — never a fabricated hash.
  function markResolved(wrap, kind, data, who) {
    wrap.classList.add('is-resolved');   // stripe flips --warn → --ok
    var op = wrap.querySelector('.ow-gate-op');
    if (op) { op.textContent = ''; } else { op = el('div', { 'class': 'ow-gate-op' }); wrap.appendChild(op); }
    var receipt = data && (data.receipt_id || (data.receipt && data.receipt.receipt_id) || data.receipt);
    var line = el('div', { 'class': 'ow-done' + (kind === 'returned' ? ' returned' : '') });
    line.innerHTML = (kind === 'returned' ? SVG_RETURN : SVG_CHECK);
    line.appendChild(el('span', { text: (kind === 'approved' ? 'Approved' : 'Returned') + ' by ' + who + (data && data.state ? ' · ' + data.state : '') }));
    // A receipt id only if the backend returned one; otherwise "recorded" — never a fabricated hash.
    line.appendChild(el('span', { 'class': 'ow-hash', text: (receipt && typeof receipt === 'string') ? receipt : 'recorded' }));
    op.appendChild(line);
  }

  // Foresight (Art. 15) via POST /v1/actions/enrich. Degrades silently on any
  // non-ok / error path so a card with no available foresight just drops the
  // block rather than showing an error.
  function loadConsequences(p, mount) {
    var input = {
      tool_name: p.requested_action || 'update_state',
      action_description: 'Approve gated transition for ' + (p.work_id || p.action_id) + (p.target_state ? ' → ' + p.target_state : ''),
      tool_parameters: { work_id: p.work_id, target_state: p.target_state, action_id: p.action_id }
    };
    enrichAction(input).then(readJson).then(function (r) {
      mount.textContent = '';
      // Consequences block renders ONLY when enrich returns a proposal; on any
      // non-ok / empty path the block is removed rather than left as an empty box.
      if (!r.ok || !r.data || !r.data.proposal) { if (mount.parentNode) { mount.parentNode.removeChild(mount); } return; }
      var prop = r.data.proposal, meta = prop.consequence_metadata || {};
      if (prop.narrative) { mount.appendChild(el('p', { 'class': 'ow-narrative', text: prop.narrative })); }
      var bits = [meta.materiality && ('materiality ' + meta.materiality), meta.reversibility, meta.blast_radius && ('blast ' + meta.blast_radius)].filter(Boolean);
      if (bits.length) { mount.appendChild(el('div', { 'class': 'ow-meta' }, bits.map(noteChip))); }
      (prop.consequences || []).slice(0, 5).forEach(function (c) {
        mount.appendChild(el('div', { 'class': 'ow-conseq-row' }, [
          el('span', {}, [
            el('b', { text: c.consequence_type || 'consequence' }),
            doc().createTextNode(' — ' + (c.detail || '') + (c.target ? ' · ' + c.target : ''))
          ])
        ]));
      });
      if (!mount.childNodes.length && mount.parentNode) { mount.parentNode.removeChild(mount); }
    }).catch(function () { if (mount.parentNode) { mount.parentNode.removeChild(mount); } });
  }

  // Fleet: one client-side join of coord_active ⋈ punchcards ⋈ sessions ⋈
  // orchestrators, keyed by passport. A 404/400 source is skipped with a quiet
  // chip; the panel still renders from whatever is available.
  function fillFleet(wrap) {
    var body = wrap.__body;
    var chips = el('div', { 'class': 'ow-srcchips' });
    wrap.insertBefore(chips, body);
    return Promise.all([
      fetchJSON('/v1/coord/active'),
      fetchJSON('/v1/punchcards'),
      fetchJSON('/v1/console/sessions'),
      fetchJSON('/v1/orchestrators')
    ]).then(function (r) {
      var coord = r[0], punch = r[1], sess = r[2], orcs = r[3];
      body.textContent = '';
      chips.textContent = '';
      [['coord', coord], ['punchcards', punch], ['sessions', sess], ['orchestrators', orcs]].forEach(function (pair) {
        var ok = pair[1].ok && pair[1].data;
        var off = pair[1].status === 404 || pair[1].status === 400;
        chips.appendChild(noteChip(pair[0] + ' · ' + (ok ? 'on' : (off ? 'off' : 'n/a'))));
      });
      var rows = {};
      function slot(pid) { pid = pid || '—'; return rows[pid] || (rows[pid] = { passport: pid, intent: null, milestone: null, execplan: null, leases: [], orchestrators: [], snapshot: null, sessionHex: null, overlaps: [] }); }
      if (coord.ok && coord.data) {
        (coord.data.active_sessions || []).forEach(function (s) {
          var row = slot(s.passport_id); var i = s.intent || {};
          row.execplan = i.execplan_slug || row.execplan;
          row.milestone = i.milestone || row.milestone;
          row.intent = i.note || row.intent;
          row.sessionHex = (s.session_id_hex || '').slice(0, 8) || row.sessionHex;
          (s.leases || []).forEach(function (l) { if (l.resource) { row.leases.push(l.resource); } });
          (s.overlaps || []).forEach(function (o) { row.overlaps.push(o); });   // real coord overlap rows only
        });
      }
      if (punch.ok && punch.data) {
        (punch.data.punchcards || (Array.isArray(punch.data) ? punch.data : [])).forEach(function (c) {
          var row = slot(c.holder_passport || c.holder);
          if (c.resource) { row.leases.push(c.resource + (c.mode ? ' (' + c.mode + ')' : '')); }
        });
      }
      if (sess.ok && sess.data) {
        var list = sess.data.sessions || sess.data.items || (Array.isArray(sess.data) ? sess.data : []);
        list.forEach(function (s) { if (s.archived) { return; } var row = slot(s.passport_id); row.execplan = row.execplan || s.execplan_slug; row.snapshot = s.session_id || s.id; });
      }
      if (orcs.ok && orcs.data) {
        (orcs.data.orchestrators || (Array.isArray(orcs.data) ? orcs.data : [])).forEach(function (o) {
          (o.members || []).forEach(function (m) {
            var pid = m && (m.passport_id || m.passport || (typeof m === 'string' ? m : null));
            if (pid) { slot(String(pid)).orchestrators.push(o.name || o.id); }
          });
          if (o.created_by_passport) { slot(o.created_by_passport).orchestrators.push(o.name || o.id); }
        });
      }
      var keys = Object.keys(rows);
      if (!keys.length && demoFleet(wrap)) { return; }   // demo fills only an empty fleet
      setCt(wrap, keys.length + ' session' + (keys.length === 1 ? '' : 's') + ' · coord ⋈ punchcards ⋈ sessions ⋈ orchestrators');
      if (!keys.length) { body.appendChild(kv('quiet', 'no live sessions right now')); return; }
      keys.forEach(function (k) { body.appendChild(fleetRow(rows[k])); });
    });
  }

  // Activity strip: latest N from /v1/activity. When the feature flag is off it
  // 404s → M1-style link card to the dedicated /console/activity surface.
  function fillActivity(wrap) {
    var body = wrap.__body;
    return fetchJSON('/v1/activity?tenant_id=default&token_budget=1500').then(function (res) {
      body.textContent = '';
      if (res.status === 404) {
        if (demoActivity(wrap)) { return; }   // demo fills only when the surface is off
        setCt(wrap, 'dedicated surface');
        body.appendChild(kv('stream', 'GET /v1/events/stream?types=activity.appended'));
        body.appendChild(el('a', { 'class': 'ow-link', href: '/console/activity' }, ['Open the activity log →']));
        return;
      }
      if (!res.ok || !res.data) {
        if (demoActivity(wrap)) { return; }
        setCt(wrap, 'activity unavailable');
        body.appendChild(kv(res.status === 0 ? 'unreachable' : ('HTTP ' + res.status), 'GET /v1/activity'));
        return;
      }
      var rows = (res.data.rows || []).slice(0, 12);
      if (!rows.length && demoActivity(wrap)) { return; }
      setCt(wrap, (res.data.returned != null ? res.data.returned : rows.length) + ' recent · /v1/activity');
      if (!rows.length) { body.appendChild(kv('quiet', 'no activity captured yet')); return; }
      // Ticker: one card of border-separated rows. Receipt ids ride as trust
      // hash-chips; the preview folds into the row's hover title to stay one-line.
      body.appendChild(activityTicker(rows));
    });
  }

  // Engine (mediated) card — reuses the existing daemon-proxied read
  // (GET /v1/console/engine/summary). It renders ONLY when the mediation
  // endpoint answers with data; a 404 / off / unreachable removes the panel
  // entirely (no fabricated engine card when mediation is off).
  function fillEngine(wrap) {
    var body = wrap.__body;
    return fetchJSON('/v1/console/engine/summary').then(function (res) {
      if (res.status === 404 || res.status === 0 || !res.ok || !res.data) {
        var dd = demoData('engine');
        if (dd) {
          setCt(wrap, 'demo fixtures');
          markPanelDemo(wrap);
          body.textContent = '';
          body.appendChild(el('div', { 'class': 'ow-engine' }, [
            kv('mediated', dd.mediated === true ? 'yes · daemon-proxied' : '—'),
            kv('engine', dd.engine_reachable ? ('reachable · ' + (dd.engine_latency_ms != null ? dd.engine_latency_ms + ' ms' : '—')) : 'unreachable'),
            kv('fetched', dd.fetched_at_unix_ms != null ? tsLabel(dd.fetched_at_unix_ms) : '—')
          ]));
          return;
        }
        if (wrap.parentNode) { wrap.parentNode.removeChild(wrap); }
        return;
      }
      var d = res.data;
      setCt(wrap, 'via daemon origin');
      body.textContent = '';
      body.appendChild(el('div', { 'class': 'ow-engine' }, [
        kv('mediated', d.mediated === true ? 'yes · daemon-proxied' : '—'),
        kv('engine', d.engine_reachable ? ('reachable · ' + (d.engine_latency_ms != null ? d.engine_latency_ms + ' ms' : '—')) : 'unreachable'),
        kv('fetched', d.fetched_at_unix_ms != null ? tsLabel(d.fetched_at_unix_ms) : '—')
      ]));
    });
  }

  // =======================================================================
  //  Pro-mode dashboard strip (M8) — the home for the legacy CX-landing top
  //  cards (renderDash, index.html:2119): daemon · execplans · token usage ·
  //  MCP gateway. Renders ONLY in Professional mode, between the stat tiles and
  //  the needs-you/fleet columns. Every card reads REAL data; a demo fixture
  //  fills a card only when its real feed is flag-off (demoOn()-guarded). The
  //  MCP-gateway card is the one legacy card that had no v2 home before M8.
  // =======================================================================
  function numstr(n) { return (typeof n === 'number' && isFinite(n)) ? n.toLocaleString('en-US') : '—'; }
  function workStageLite(w) {
    var s = String(w.state || w.status || 'planned').toLowerCase();
    return ({ complete: 'done', deployed: 'done', run: 'in_progress', ok: 'done', err: 'blocked', idle: 'planned' })[s] || s;
  }
  function dashCard(kind, label, value, chips) {
    var card = el('div', { 'class': 'ow-dashcard', 'data-card': kind });
    card.appendChild(el('div', { 'class': 'ow-dashcard-k', text: label }));
    card.appendChild(el('div', { 'class': 'ow-dashcard-v', text: value == null ? '—' : String(value) }));
    var row = el('div', { 'class': 'ow-dashcard-chips' });
    (chips || []).filter(Boolean).forEach(function (c) { row.appendChild(noteChip(String(c))); });
    card.appendChild(row);
    return card;
  }
  function swapVal(card, v) { var e = card.querySelector('.ow-dashcard-v'); if (e) { e.textContent = String(v); } }
  function swapChips(card, chips) {
    var old = card.querySelector('.ow-dashcard-chips');
    var row = el('div', { 'class': 'ow-dashcard-chips' });
    (chips || []).filter(Boolean).forEach(function (c) { row.appendChild(noteChip(String(c))); });
    if (old && old.parentNode) { old.parentNode.replaceChild(row, old); } else { card.appendChild(row); }
  }
  function markCardDemo(card) { if (card && !card.querySelector('.demo-chip')) { card.appendChild(demoChip(true)); } }
  function renderDashStrip(host, ctx) {
    host.textContent = '';
    var summary = ctx && ctx.summary;
    var facts = get(summary, ['stores', 'facts']);
    var sessions = get(summary, ['stores', 'sessions']);
    var authMode = get(summary, ['daemon', 'auth_mode']);
    // 1 · Daemon — facts / sessions / auth, straight from the boot summary.
    host.appendChild(dashCard('daemon', 'DAEMON', numstr(facts) + ' facts',
      [sessions != null ? (sessions + ' sessions') : null, authMode ? ('auth ' + authMode) : null]));
    // 2 · ExecPlans — kanban stage counts from /v1/work.
    var execCard = dashCard('execplans', 'EXECPLANS', 'loading…', null);
    host.appendChild(execCard);
    // 3 · Token usage — measured headline from the cost lens.
    var usageCard = dashCard('usage', 'TOKEN USAGE', 'loading…', null);
    host.appendChild(usageCard);
    // 4 · MCP gateway — the legacy card that had no v2 home before M8.
    var mcpAgents = get(summary, ['daemon', 'mcp_agent_count']);
    var mcpCard = dashCard('mcp', 'MCP GATEWAY', get(summary, ['daemon', 'mcp_enabled']) ? 'listening' : 'off',
      ['/mcp · :14801', mcpAgents != null ? (mcpAgents + ' agents') : null]);
    host.appendChild(mcpCard);
    // Async fills (real data first; demo fixtures fill only a flag-off feed).
    fetchJSON('/v1/work?source=all').then(function (r) {
      var items = (r.ok && r.data) ? (r.data.work || r.data.items || []) : [];
      if ((!items || !items.length)) { var dw = demoData('work'); if (dw) { items = dw; markCardDemo(execCard); } }
      var counts = { planned: 0, in_progress: 0, blocked: 0, done: 0 };
      (items || []).forEach(function (w) { var st = workStageLite(w); if (counts[st] != null) { counts[st]++; } });
      swapVal(execCard, (items ? items.length : 0) + ' plans');
      swapChips(execCard, [counts.in_progress + ' in progress', counts.blocked + ' blocked', counts.done + ' done']);
    });
    fetchJSON('/v1/cost/report?tenant_id=default&token_budget=1500').then(function (r) {
      var d = (r.ok && r.data) ? r.data : null;
      var head = d && d.report && d.report.report && d.report.report.headline;
      if (head && head.context_tokens_per_turn != null) {
        swapVal(usageCard, fmtChartVal(head.context_tokens_per_turn, 'compact') + ' / turn');
        swapChips(usageCard, [Math.round(head.cache_read_to_output_ratio || 0) + '× cache replay', (head.assistant_turns || 0) + ' turns']);
      } else {
        var ds = demoData('usageSeries');
        if (ds && ds.week && ds.week.length) { swapVal(usageCard, fmtChartVal(ds.week[ds.week.length - 1], 'compact') + ' / wk'); markCardDemo(usageCard); }
        else { swapVal(usageCard, 'no report'); swapChips(usageCard, ['corecruxctl session cost --post']); }
      }
    });
    fetchJSON('/v1/mcp/tools').then(function (r) {
      var tools = (r.ok && r.data) ? (r.data.tools || r.data.items || r.data) : null;
      if (Array.isArray(tools)) {
        swapChips(mcpCard, ['/mcp · :14801', tools.length + ' tools', mcpAgents != null ? (mcpAgents + ' agents') : null]);
      }
    });
  }

  // Right-column page navigation for the Overwatch destination — the nav-family
  // section that REPLACES the suppressed top sub-nav pill row (the shell
  // suppresses the pill row for the overwatch destination only; every other
  // destination keeps its pills). The page list is reused from pages.js
  // (window.CruxPages.PAGES filtered to dest==='overwatch') — never hardcoded —
  // so it stays in sync: Overview · Activity · Live board · Orchestrators ·
  // Punchcards · Agent. Pro-only pages (Agent) show only in Professional mode,
  // mirroring the pill row's gating so a Standard click never dead-redirects.
  function owPageNav() {
    var wrap = panel('Pages', 'this destination', true);
    var nav = el('nav', { 'class': 'ow-pagenav', 'aria-label': 'Overwatch pages' });
    var CP = (typeof window !== 'undefined') ? window.CruxPages : null;
    var PAGES = CP && CP.PAGES;
    var activeId = null;
    if (typeof location !== 'undefined' && location.hash) {
      var parts = String(location.hash).replace(/^#\/?/, '').split('/');
      if (parts[0] === 'overwatch' && parts[1]) { activeId = parts[1]; }
    }
    if (PAGES) {
      Object.keys(PAGES).forEach(function (id) {
        var p = PAGES[id];
        if (!p || p.dest !== 'overwatch') { return; }
        if (p.pro === true && !proMode()) { return; }   // Pro pages only in Pro mode (mirror the pill row)
        var a = el('a', { 'class': 'pill', href: '#/overwatch/' + id, 'aria-current': id === activeId ? 'page' : 'false' }, [p.title]);
        if (p.operatorOnly) { a.setAttribute('data-requires', 'operator'); }   // hidden for customers
        nav.appendChild(a);
      });
    }
    if (!nav.childNodes.length) { nav.appendChild(el('span', { 'class': 'ow-ct', text: 'no pages' })); }
    wrap.__body.appendChild(nav);
    return wrap;
  }

  // The Overwatch landing entry point (shell.html calls this for the overwatch
  // destination, above the — now suppressed — page-pill row). Nodes are appended
  // in order first, then filled async, so ordering is stable regardless of fetch
  // timing. Layout: tagline → Daemon-at-a-glance tiles → two columns (LEFT:
  // Needs-you then Fleet; RIGHT: the destination page nav). The dashboard strip
  // + activity ticker are gone (duplicated the strip cards / Activity page); the
  // Engine card folded into the tiles.
  function renderOverwatchLanding(region, ctx) {
    ctx = ctx || {};
    region.textContent = '';
    var root = el('div', { 'class': 'ow-landing' });
    region.appendChild(root);
    // Tagline introducing the Overwatch view (concept apphead sub).
    root.appendChild(el('p', { 'class': 'ow-tagline', text: 'You steer. Agents work. Everything receipts.' }));
    // Daemon-at-a-glance — full-width stat tiles, reused from the cx-overview
    // build and expanded in decorateTiles (ExecPlans + Token usage + Engine).
    var tileCard = el('div', { 'class': 'ow-tiles' }, [el('p', { 'class': 'v2card-sub', text: 'Loading…' })]);
    root.appendChild(tileCard);
    // Two columns — LEFT: Needs-you then Fleet (fleet moved under needs-you);
    // RIGHT: the destination page nav (replaces the suppressed pill row).
    var cols = el('div', { 'class': 'ow-cols' });
    var left = el('div', { 'class': 'ow-col' });
    var right = el('div', { 'class': 'ow-col' });
    cols.appendChild(left); cols.appendChild(right);
    root.appendChild(cols);
    var needs = panel('Needs you', 'loading gate queue…', true);
    var fleet = panel('Fleet', 'loading live sessions…', false);
    left.appendChild(needs);
    left.appendChild(fleet);          // Fleet directly under Needs-you
    right.appendChild(owPageNav());   // page nav replaces the top pill row
    return Promise.all([
      fillTiles(tileCard, ctx),
      fillNeedsYou(needs),
      fillFleet(fleet)
    ]);
  }

  // =======================================================================
  //  Page entry point. Renders a page's static sections immediately, then —
  //  if the page declares a GET-on-open loader — fetches and re-renders with
  //  live data. Failures degrade gracefully (build() owns the empty state).
  // =======================================================================

  function renderPage(page, container) {
    if (!page) {
      renderSections(container, [{ h: 'Not found', wide: true, controls: [{ t: 'info', label: '—', v: 'no such page' }] }]);
      return Promise.resolve();
    }
    if (page.operatorOnly && !isOperator()) {
      renderSections(container, [{ h: page.title, wide: true, controls: [
        { t: 'info', label: 'operator only', v: 'This surface is only available in operator posture.' },
        { t: 'info', label: 'why', v: 'Forward-facing consoles hide operator deep-machinery until an operator scope is granted.' }
      ] }]);
      return Promise.resolve();
    }
    // Immediate paint from static sections (skeleton / fallback).
    renderSections(container, page.sections && page.sections.length ? page.sections : [{ h: page.title, wide: true, controls: [{ t: 'info', label: 'status', v: 'loading…' }] }]);
    if (!page.load || typeof page.load.build !== 'function') {
      return Promise.resolve();
    }
    var token = container.__renderToken = (container.__renderToken || 0) + 1;
    return fetchJSON(page.load.endpoint).then(function (res) {
      if (container.__renderToken !== token) { return; }   // superseded by a newer navigation
      var sections;
      try { sections = page.load.build(res); }
      catch (e) { sections = [{ h: page.title, wide: true, controls: [{ t: 'info', label: 'render error', v: String(e && e.message || e) }] }]; }
      renderSections(container, sections);
    });
  }

  // =======================================================================
  //  Canvas (M9) — a size-adaptive dashboard Board + a real-edge relation
  //  Graph. Both reuse the EXISTING builders/panels as self-contained cells so
  //  the readout never drifts. Every fetch stays inside a function (never at
  //  module load), so this module still `require()`s cleanly under node.
  // =======================================================================

  // ---- canvasTier — PURE viewport→tier mapping (smoke check 25) ----------
  // xs (<720w: single column, 4 widgets) · s (<1600w: ~6) · m (<2560w: ~10) ·
  // l (<3840w: ~14) · xl (≥3840w — the 4K+ tier: the full board, 16+ widgets).
  // Width-driven so the truth table is stable; a very short height steps DOWN
  // one tier (only when a finite height is supplied — the smoke calls it width-
  // only, so the canonical 500/1200/2000/3000/4000 → xs/s/m/l/xl table holds).
  var CANVAS_TIER_ORDER = ['xs', 's', 'm', 'l', 'xl'];
  function canvasTier(width, height) {
    var w = Number(width) || 0;
    var tier;
    if (w < 720) { tier = 'xs'; }
    else if (w < 1600) { tier = 's'; }
    else if (w < 2560) { tier = 'm'; }
    else if (w < 3840) { tier = 'l'; }
    else { tier = 'xl'; }
    var h = Number(height);
    if (isFinite(h) && h > 0 && h < 560) {
      var idx = CANVAS_TIER_ORDER.indexOf(tier);
      if (idx > 0) { tier = CANVAS_TIER_ORDER[idx - 1]; }
    }
    return tier;
  }

  // ---- parseFocus — PURE deep-link focus parser (smoke check 26) ---------
  // "<type>:<id>" → { type, id }; splits on the FIRST colon so composite ids
  // (e.g. work:execplan:unified-shell-console) survive. Malformed → null.
  function parseFocus(str) {
    if (typeof str !== 'string') { return null; }
    var s = str.trim();
    var i = s.indexOf(':');
    if (i <= 0 || i >= s.length - 1) { return null; }
    var type = s.slice(0, i), id = s.slice(i + 1);
    if (!type || !id) { return null; }
    return { type: type, id: id };
  }

  // ---- Board cell builders (reuse existing surfaces) ---------------------
  function canvasCellHead(cell, title) { cell.appendChild(el('h3', { 'class': 'v2card-h', text: title })); }

  // Reuse a whole ported page's real build() as a cell — real data wins,
  // demo fixtures fill only flag-off feeds (via the page builder's own logic).
  // Wrapped so one failed feed degrades ONE cell, never the board.
  function canvasPageCell(cell, pageId) {
    var CP = (typeof window !== 'undefined') ? window.CruxPages : null;
    var page = CP && CP.PAGES && CP.PAGES[pageId];
    var body = el('div', { 'class': 'canvas-cell-body' });
    cell.appendChild(body);
    function paint(sections) { body.textContent = ''; (sections || []).forEach(function (s) { try { body.appendChild(renderSection(s)); } catch (e) { /* skip one bad section */ } }); }
    if (!page) { canvasCellHead(cell, pageId); body.appendChild(el('p', { 'class': 'ctl-desc', text: 'page unavailable' })); return Promise.resolve(); }
    if (page.sections && page.sections.length) { paint(page.sections); }
    if (!page.load || typeof page.load.build !== 'function') { return Promise.resolve(); }
    return fetchJSON(page.load.endpoint).then(function (res) {
      var sections;
      try { sections = page.load.build(res); }
      catch (e) { sections = [{ h: page.title, controls: [{ t: 'info', label: 'render error', v: String(e && e.message || e) }] }]; }
      paint(sections);
    }).catch(function () { /* degraded state already painted */ });
  }

  // Reuse an Overwatch landing panel (needs-you / fleet / activity / engine).
  function canvasPanelCell(cell, title, filler, ct) {
    var wrap = panel(title, ct || 'loading…', true);
    cell.appendChild(wrap);
    try { filler(wrap); } catch (e) { /* one failed feed degrades one cell */ }
  }

  // A D/W/M chart cell (real series where one exists, else demo/empty — same
  // posture as the cost/usage trend cards).
  function canvasChartCell(cell, title, demoKey) {
    cell.appendChild(renderChart({ t: 'chart', title: title, demoKey: demoKey, fmt: 'compact', range: 'week', sub: 'measured over time' }));
  }

  // The Pro dashboard strip as a cell (daemon · execplans · usage · MCP gateway).
  function canvasDashCell(cell, ctx) {
    canvasCellHead(cell, 'Fleet dashboard');
    var strip = el('div', { 'class': 'ow-dashstrip' });
    cell.appendChild(strip);
    try { renderDashStrip(strip, ctx || {}); } catch (e) { /* degrade one cell */ }
  }

  // ---- Widget registry (smoke check 25) ----------------------------------
  // { id, span, minTier, build }. minTier gates a widget IN at that tier and up.
  // Cumulative counts: xs 4 · s 6 · m 10 · l 14 · xl 18 (the 4K+ board).
  var CANVAS_WIDGETS = [
    { id: 'stat-tiles', span: 2, minTier: 'xs', title: 'Daemon at a glance', build: function (cell) { return canvasPageCell(cell, 'cx-overview'); } },
    { id: 'needs-you', span: 2, minTier: 'xs', title: 'Needs you', build: function (cell) { return canvasPanelCell(cell, 'Needs you', fillNeedsYou, 'loading gate queue…'); } },
    { id: 'fleet', span: 1, minTier: 'xs', title: 'Fleet', build: function (cell) { return canvasPanelCell(cell, 'Fleet', fillFleet, 'loading fleet…'); } },
    { id: 'activity', span: 1, minTier: 'xs', title: 'Activity', build: function (cell) { return canvasPanelCell(cell, 'Activity', fillActivity, 'loading…'); } },
    { id: 'cost-chart', span: 2, minTier: 's', title: 'Token burn', build: function (cell) { return canvasChartCell(cell, 'Token burn', 'costSeries'); } },
    { id: 'work', span: 2, minTier: 's', title: 'ExecPlans', build: function (cell) { return canvasPageCell(cell, 'cx-work'); } },
    { id: 'usage-chart', span: 2, minTier: 'm', title: 'Token usage', build: function (cell) { return canvasChartCell(cell, 'Token usage', 'usageSeries'); } },
    { id: 'facts', span: 2, minTier: 'm', title: 'Facts', build: function (cell) { return canvasPageCell(cell, 'cx-facts'); } },
    { id: 'engine', span: 1, minTier: 'm', title: 'Engine', build: function (cell) { return canvasPanelCell(cell, 'Engine', fillEngine, 'checking mediation…'); } },
    { id: 'dashboard-strip', span: 4, minTier: 'm', title: 'Fleet dashboard', build: function (cell, ctx) { return canvasDashCell(cell, ctx); } },
    { id: 'projects', span: 2, minTier: 'l', title: 'Projects', build: function (cell) { return canvasPageCell(cell, 'cx-projects'); } },
    { id: 'sessions', span: 2, minTier: 'l', title: 'Sessions', build: function (cell) { return canvasPageCell(cell, 'cx-sessions'); } },
    { id: 'tenants', span: 2, minTier: 'l', title: 'Tenants', build: function (cell) { return canvasPageCell(cell, 'cx-tenants'); } },
    { id: 'live-board', span: 2, minTier: 'l', title: 'Live board', build: function (cell) { return canvasPageCell(cell, 'cx-coord'); } },
    { id: 'passports', span: 1, minTier: 'xl', title: 'Passports', build: function (cell) { return canvasPageCell(cell, 'cx-passport'); } },
    { id: 'gates', span: 2, minTier: 'xl', title: 'Gates', build: function (cell) { return canvasPageCell(cell, 'cx-gates'); } },
    { id: 'orchestrators', span: 1, minTier: 'xl', title: 'Orchestrators', build: function (cell) { return canvasPageCell(cell, 'cx-orchestrators'); } },
    { id: 'integrations', span: 1, minTier: 'xl', title: 'Integrations', build: function (cell) { return canvasPageCell(cell, 'cx-integrations'); } }
  ];

  // ---- Board renderer — recompose on (debounced) resize, tier-driven -----
  var __canvasResizeHandler = null;
  function renderCanvasBoard(host, ctx) {
    ctx = ctx || {};
    var lastTier = null;
    function viewport() {
      var W = (typeof window !== 'undefined' && window.innerWidth) || 1280;
      var H = (typeof window !== 'undefined' && window.innerHeight) || 800;
      return { W: W, H: H };
    }
    function paint() {
      // Stop + detach once the board leaves the DOM (route change).
      if (host.ownerDocument && host.isConnected === false && __canvasResizeHandler) {
        if (typeof window !== 'undefined') { window.removeEventListener('resize', __canvasResizeHandler); }
        __canvasResizeHandler = null;
        return;
      }
      var vp = viewport();
      var tier = canvasTier(vp.W, vp.H);
      if (tier === lastTier) { return; }   // only recompose on a real tier change (no churn)
      lastTier = tier;
      host.textContent = '';
      host.setAttribute('data-tier', tier);
      var maxIdx = CANVAS_TIER_ORDER.indexOf(tier);
      var board = el('div', { 'class': 'canvas-board' });
      host.appendChild(board);
      var shown = 0;
      CANVAS_WIDGETS.forEach(function (w) {
        if (CANVAS_TIER_ORDER.indexOf(w.minTier) > maxIdx) { return; }
        shown++;
        var cell = el('div', { 'class': 'canvas-cell', 'data-span': String(w.span), 'data-widget': w.id });
        board.appendChild(cell);
        try { w.build(cell, ctx); }
        catch (e) { cell.textContent = ''; canvasCellHead(cell, w.title || w.id); cell.appendChild(el('p', { 'class': 'ctl-desc', text: 'widget unavailable' })); }
      });
      var meta = el('p', { 'class': 'ctl-desc', text: tier + ' tier · ' + shown + ' widget' + (shown === 1 ? '' : 's') + ' · resize to recompose' });
      host.appendChild(meta);
    }
    paint();
    // Debounced resize recompose (no animated reflow — reduced-motion-safe by
    // construction: the grid re-lays out instantly, nothing is transitioned).
    if (__canvasResizeHandler && typeof window !== 'undefined') { window.removeEventListener('resize', __canvasResizeHandler); }
    var t = null;
    __canvasResizeHandler = function () { if (t) { clearTimeout(t); } t = setTimeout(paint, 200); };
    if (typeof window !== 'undefined') { window.addEventListener('resize', __canvasResizeHandler); }
  }

  // ---- Graph model — nodes/edges STRICTLY from real endpoint fields ------
  // Grounded (api.js allowlist + the page builders):
  //   projects (GET /v1/projects → .projects[]: id,name,is_default,planning_target)
  //   work     (GET /v1/work     → .work|.items[]: id,title,state,project_id,
  //             created_by_passport,assignee_passport)
  //   gates    (GET /v1/work/gate/pending → .pending[]: action_id,work_id,
  //             target_state,requested_by_passport,risk_class)
  //   passports(GET /v1/passports → .passports[]: id,name,category,reputation_tier)
  //   sessions (GET /v1/coord/active → .active_sessions[]: session_id_hex,
  //             passport_id, intent.execplan_slug, intent.milestone) — 404-tolerant
  //   repos    (GET /v1/projects/{id}/repos → .links[]: owner,repo,role,plane_id)
  // Real edges only: an edge is kept ONLY when BOTH endpoints resolved to a node.
  function graphRelTime(ms) {
    var n = Number(ms); if (!isFinite(n) || n <= 0) { return null; }
    var diff = Date.now() - n; if (diff < 0) { diff = 0; }
    var s = Math.floor(diff / 1000), m = Math.floor(s / 60), h = Math.floor(m / 60), d = Math.floor(h / 24);
    if (d >= 1) { return d + 'd ago'; } if (h >= 1) { return h + 'h ago'; } if (m >= 1) { return m + 'm ago'; } return 'just now';
  }
  function sessionKind(id) {
    id = String(id);
    if (id.indexOf('handoff:') === 0) { return 'handoff'; }
    if (id.indexOf('execplan:') === 0) { return 'execplan'; }
    if (id.indexOf('hook:session:') === 0) { return 'hook'; }
    if (id.indexOf('orchestrate') === 0) { return 'orchestrator'; }
    return 'session';
  }
  function buildGraphModel(data) {
    data = data || {};
    var nodes = [], edges = [], index = {};
    function add(type, rawId, label, extra, opts) {
      if (rawId == null || rawId === '') { return null; }
      var key = type + ':' + rawId;
      if (index[key]) { return index[key]; }
      opts = opts || {};
      var n = { key: key, type: type, id: rawId, label: label || String(rawId), extra: extra || {},
        sub: opts.sub || null, raw: opts.raw || null, strip: opts.strip || null };
      index[key] = n; nodes.push(n); return n;
    }
    function edge(from, to, kind) { if (from && to) { edges.push({ from: from, to: to, kind: kind }); } }

    // Saved sessions — the real /v1/console/sessions list (id strings). The card
    // shows the id + derived kind; deeper per-session fields land when the daemon
    // exposes them (coord/active is empty at rest locally).
    var savedList = (data.sessionsSaved && (data.sessionsSaved.sessions || data.sessionsSaved.items)) || [];
    (Array.isArray(savedList) ? savedList : []).slice(0, 18).forEach(function (item) {
      var sid = (typeof item === 'string') ? item : (item && (item.session_id || item.id));
      if (!sid) { return; }
      var kind = sessionKind(sid);
      add('session', sid, sid, { session_id: sid, kind: kind, state: 'idle' },
        { sub: kind + ' · saved', strip: 'idle',
          raw: { session_id: sid, kind: kind, state: 'idle', archived: false, source: '/v1/console/sessions' } });
    });

    var projects = (data.projects && data.projects.projects) || [];
    projects.forEach(function (p) {
      add('project', p.id, p.name || p.id, { name: p.name, 'default': p.is_default ? 'yes' : null, planning: p.planning_target });
    });

    (data.repos || []).forEach(function (r) {
      (r.links || []).forEach(function (lk) {
        var rid = (lk.owner != null && lk.repo != null) ? (lk.owner + '/' + lk.repo) : (lk.repo || lk.slug);
        if (add('repo', rid, rid, { role: lk.role, plane: lk.plane_id })) { edge('repo:' + rid, 'project:' + r.projectId, 'repo-of'); }
      });
    });

    var work = (data.work && (data.work.work || data.work.items)) || [];
    work.forEach(function (w) {
      var when = graphRelTime(w.updated_at_unix_ms || w.created_at_unix_ms);
      add('work', w.id, w.title || w.id, { state: w.state, project: w.project_id, created_by: w.created_by_passport, milestone: w.current_milestone },
        { strip: workStageLite(w), raw: w,
          sub: (w.state || 'work') + (w.created_by_passport ? (' · ' + w.created_by_passport) : '') + (when ? (' · ' + when) : '') });
      if (w.project_id) { edge('work:' + w.id, 'project:' + w.project_id, 'in-project'); }
      if (w.created_by_passport) { edge('work:' + w.id, 'passport:' + w.created_by_passport, 'created-by'); }
      if (w.assignee_passport) { edge('work:' + w.id, 'passport:' + w.assignee_passport, 'assigned-to'); }
    });

    var gates = (data.gates && data.gates.pending) || [];
    gates.forEach(function (p) {
      add('gate', p.action_id, p.work_id || p.action_id, { work: p.work_id, target: p.target_state, risk: p.risk_class, requested_by: p.requested_by_passport });
      if (p.work_id) { edge('gate:' + p.action_id, 'work:' + p.work_id, 'gates'); }
      if (p.requested_by_passport) { edge('gate:' + p.action_id, 'passport:' + p.requested_by_passport, 'requested-by'); }
    });

    var passports = (data.passports && data.passports.passports) || [];
    passports.forEach(function (p) {
      add('passport', p.id, p.name || p.id, { category: p.category, tier: p.reputation_tier });
    });

    var sessions = (data.sessions && data.sessions.active_sessions) || [];
    sessions.forEach(function (s) {
      var sid = s.session_id_hex || s.passport_id;
      var i = s.intent || {};
      add('session', sid, (s.session_id_hex ? s.session_id_hex.slice(0, 8) : (s.passport_id || 'session')), { execplan: i.execplan_slug, milestone: i.milestone, passport: s.passport_id });
      if (s.passport_id) { edge('session:' + sid, 'passport:' + s.passport_id, 'runs-as'); }
      var slug = i.execplan_slug;
      if (slug) {
        var wk = index['work:' + slug] ? ('work:' + slug) : (index['work:execplan:' + slug] ? ('work:execplan:' + slug) : null);
        if (wk) { edge('session:' + sid, wk, 'working-on'); }
      }
    });

    // Real edges only — drop any edge whose endpoints did not both resolve.
    edges = edges.filter(function (e) { return index[e.from] && index[e.to]; });
    return { nodes: nodes, edges: edges };
  }

  // Deterministic layered layout — columns by node type. No random seed: node
  // positions are a pure function of type + insertion order (replayable).
  // Card layout — columns by type (sessions lead, matching the concept). Each
  // node carries its top-left x/y + card w/h; edges connect card centres.
  function layoutGraph(nodes) {
    var COLS = ['session', 'work', 'gate', 'project', 'passport', 'repo'];
    var CARD_W = 300, CARD_H = 106;
    var byType = {};
    nodes.forEach(function (n) { (byType[n.type] || (byType[n.type] = [])).push(n); });
    var used = COLS.filter(function (t) { return (byType[t] || []).length; });
    Object.keys(byType).forEach(function (t) { if (used.indexOf(t) < 0) { used.push(t); } });
    var colGap = CARD_W + 96, rowGap = CARD_H + 22, marginX = 26, marginY = 26, maxRows = 0;
    used.forEach(function (t) { maxRows = Math.max(maxRows, (byType[t] || []).length); });
    used.forEach(function (t, ci) {
      (byType[t] || []).forEach(function (n, ri) { n.x = marginX + ci * colGap; n.y = marginY + ri * rowGap; n.w = CARD_W; n.h = CARD_H; });
    });
    return { width: marginX * 2 + Math.max(1, used.length) * colGap, height: marginY * 2 + Math.max(1, maxRows) * rowGap };
  }
  function graphNodeRadius(type) { return type === 'project' ? 9 : (type === 'work' ? 8 : 6); }
  function graphNeighbourhood(edges, key) {
    var out = {};
    edges.forEach(function (e) { if (e.from === key) { out[e.to] = true; } if (e.to === key) { out[e.from] = true; } });
    return out;
  }
  // Lenient focus→node match (handles composite / prefixed ids).
  function graphMatchNode(nodes, focus) {
    var exactKey = focus.type + ':' + focus.id;
    for (var i = 0; i < nodes.length; i++) { if (nodes[i].key === exactKey) { return nodes[i]; } }
    for (var j = 0; j < nodes.length; j++) {
      var n = nodes[j];
      if (n.type === focus.type && (String(n.id).indexOf(focus.id) >= 0 || String(focus.id).indexOf(String(n.id)) >= 0)) { return n; }
    }
    return null;
  }
  function graphInspector(inspector, n, model) {
    inspector.textContent = '';
    inspector.appendChild(el('div', { 'class': 'canvas-insp-type', text: 'Node inspector' }));
    var badges = el('div', { 'class': 'cv-insp-badges' }, [el('span', { 'class': 'cv-badge cv-badge-type', text: n.type })]);
    var state = (n.extra && n.extra.state) || n.strip;
    if (state) { badges.appendChild(el('span', { 'class': 'cv-badge cv-badge-state', text: String(state) })); }
    inspector.appendChild(badges);
    inspector.appendChild(el('h3', { 'class': 'cv-insp-title', text: n.label }));
    if (n.sub) { inspector.appendChild(el('p', { 'class': 'cv-insp-sub', text: n.sub })); }
    var fields = el('div', { 'class': 'cv-insp-fields' });
    var rows = [['id', n.id]];
    Object.keys(n.extra || {}).forEach(function (k) { rows.push([k, n.extra[k]]); });
    rows.forEach(function (kvp) {
      if (kvp[1] == null || kvp[1] === '') { return; }
      fields.appendChild(el('div', { 'class': 'cv-field' }, [el('span', { 'class': 'cv-field-k', text: kvp[0] }), el('span', { 'class': 'cv-field-v', text: String(kvp[1]) })]));
    });
    inspector.appendChild(fields);
    if (n.raw) { inspector.appendChild(el('pre', { 'class': 'cv-insp-json', text: JSON.stringify(n.raw, null, 2) })); }
    if (model) {
      var idx = {}; model.nodes.forEach(function (x) { idx[x.key] = x; });
      var seen = {}, links = [];
      model.edges.forEach(function (e) {
        var other = e.from === n.key ? e.to : (e.to === n.key ? e.from : null);
        if (other && idx[other] && !seen[other]) { seen[other] = true; links.push(idx[other]); }
      });
      if (links.length) {
        inspector.appendChild(el('div', { 'class': 'cv-insp-linked-h', text: 'Linked' }));
        links.forEach(function (ln) {
          var item = el('div', { 'class': 'cv-linked-item', role: 'button', tabindex: '0' }, [
            el('span', { 'class': 'cv-linked-dot' }),
            el('span', { 'class': 'cv-linked-label', text: ln.label }),
            el('span', { 'class': 'cv-linked-sub', text: ln.type })
          ]);
          item.addEventListener('click', function () { graphInspector(inspector, ln, model); });
          inspector.appendChild(item);
        });
      }
    }
  }

  var __canvasGraphCleanup = null;
  function drawGraph(stage, inspector, model, focus) {
    stage.textContent = '';
    if (!model.nodes.length) { stage.appendChild(el('p', { 'class': 'ctl-desc', text: 'No graph yet — no sessions / work / passports available.' })); return; }
    var dims = layoutGraph(model.nodes);
    var index = {}; model.nodes.forEach(function (n) { index[n.key] = n; });
    // One transformed layer holds the SVG edge canvas + the HTML node cards, so
    // pan/zoom moves cards and edges together.
    var layer = el('div', { 'class': 'cv-graph-layer' });
    layer.style.width = dims.width + 'px'; layer.style.height = dims.height + 'px';
    var svg = svgEl('svg', { 'class': 'cv-graph-edges', width: dims.width, height: dims.height, 'aria-hidden': 'true' });
    layer.appendChild(svg);
    function cx(n) { return n.x + (n.w || 300) / 2; }
    function cy(n) { return n.y + (n.h || 106) / 2; }
    var edgeEls = [];
    model.edges.forEach(function (e) {
      var a = index[e.from], b = index[e.to]; if (!a || !b) { return; }
      var ln = svgEl('path', { 'class': 'cv-gedge', d: 'M' + cx(a) + ' ' + cy(a) + ' L' + cx(b) + ' ' + cy(b) });
      ln.__from = e.from; ln.__to = e.to; svg.appendChild(ln); edgeEls.push(ln);
    });
    var cardEls = {};
    model.nodes.forEach(function (n) {
      var card = el('div', { 'class': 'cv-card', 'data-type': n.type, role: 'button', tabindex: '0' });
      if (n.strip) { card.setAttribute('data-strip', n.strip); }
      card.style.left = n.x + 'px'; card.style.top = n.y + 'px';
      var head = el('div', { 'class': 'cv-card-head' }, [el('span', { 'class': 'cv-card-kind', text: (n.extra && n.extra.kind) || n.type })]);
      var badge = (n.extra && n.extra.state) || n.strip;
      if (badge) { head.appendChild(el('span', { 'class': 'cv-card-badge', text: String(badge) })); }
      card.appendChild(head);
      card.appendChild(el('div', { 'class': 'cv-card-title', text: n.label }));
      if (n.sub) { card.appendChild(el('div', { 'class': 'cv-card-sub', text: n.sub })); }
      var idline = (n.extra && n.extra.session_id) || (n.type === 'work' ? n.id : null);
      if (idline) { card.appendChild(el('div', { 'class': 'cv-card-id', text: idline })); }
      function open() { select(n.key); graphInspector(inspector, n, model); }
      card.addEventListener('click', function (ev) { ev.stopPropagation(); open(); });
      card.addEventListener('keydown', function (ev) { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); open(); } });
      layer.appendChild(card); cardEls[n.key] = card;
    });
    stage.appendChild(layer);

    var view = { tx: 16, ty: 16, scale: 1 };
    function apply() { layer.style.transform = 'translate(' + view.tx + 'px,' + view.ty + 'px) scale(' + view.scale + ')'; }
    apply();
    function select(key) {
      var nbr = graphNeighbourhood(model.edges, key); nbr[key] = true;
      var hasLinks = Object.keys(nbr).length > 1;   // don't grey the world for an isolated node
      Object.keys(cardEls).forEach(function (k) {
        cardEls[k].classList.toggle('is-sel', k === key);
        cardEls[k].classList.toggle('is-dim', hasLinks && !nbr[k]);
      });
      edgeEls.forEach(function (ln) { ln.classList.toggle('is-dim', hasLinks && !(nbr[ln.__from] && nbr[ln.__to])); });
    }

    // Pan (drag on empty stage) + wheel zoom.
    var drag = null;
    stage.addEventListener('mousedown', function (ev) { if (ev.target.closest && ev.target.closest('.cv-card')) { return; } drag = { x: ev.clientX, y: ev.clientY, tx: view.tx, ty: view.ty }; });
    function onMove(ev) { if (!drag) { return; } view.tx = drag.tx + (ev.clientX - drag.x); view.ty = drag.ty + (ev.clientY - drag.y); apply(); }
    function onUp() { drag = null; }
    stage.addEventListener('wheel', function (ev) { ev.preventDefault(); var f = ev.deltaY < 0 ? 1.1 : 0.9; view.scale = Math.max(0.4, Math.min(2.2, view.scale * f)); apply(); });
    if (typeof window !== 'undefined') { window.addEventListener('mousemove', onMove); window.addEventListener('mouseup', onUp); }
    __canvasGraphCleanup = function () { if (typeof window !== 'undefined') { window.removeEventListener('mousemove', onMove); window.removeEventListener('mouseup', onUp); } };

    // Focus deep-link: select + highlight the node's neighbourhood.
    if (focus && focus.type && focus.id != null) {
      var fn = index[focus.type + ':' + focus.id] || graphMatchNode(model.nodes, focus);
      if (fn) { select(fn.key); graphInspector(inspector, fn, model); }
    }
  }

  function renderCanvasGraph(host, ctx, focus) {
    host.textContent = '';
    if (__canvasGraphCleanup) { __canvasGraphCleanup(); __canvasGraphCleanup = null; }
    var wrap = el('div', { 'class': 'canvas-graph' });
    var stage = el('div', { 'class': 'canvas-graph-stage' }, [el('p', { 'class': 'ctl-desc', text: 'Building graph…' })]);
    var inspector = el('div', { 'class': 'canvas-graph-inspector' }, [
      el('div', { 'class': 'canvas-insp-type', text: 'inspector' }),
      el('p', { 'class': 'ctl-desc', text: 'Click a node to inspect its real fields. Drag to pan · wheel to zoom.' })
    ]);
    wrap.appendChild(stage); wrap.appendChild(inspector);
    host.appendChild(wrap);
    return fetchJSON('/v1/projects').then(function (projRes) {
      var projList = (projRes.ok && projRes.data && projRes.data.projects) || [];
      var repoReqs = projList.slice(0, 12).map(function (p) {
        return fetchRepos(p.id).then(function (r) { return { projectId: p.id, links: (r.ok && r.data && r.data.links) || [] }; });
      });
      return Promise.all([
        Promise.resolve(projRes),
        fetchJSON('/v1/work?source=all'),
        fetchJSON('/v1/work/gate/pending'),
        fetchJSON('/v1/passports'),
        fetchJSON('/v1/coord/active'),
        Promise.all(repoReqs),
        fetchJSON('/v1/console/sessions')
      ]);
    }).then(function (r) {
      var data = {
        projects: (r[0].ok && r[0].data) || null,
        work: (r[1].ok && r[1].data) || null,
        gates: (r[2].ok && r[2].data) || null,
        passports: (r[3].ok && r[3].data) || null,
        sessions: (r[4].ok && r[4].data) || null,   // /v1/coord/active 404 → null (tolerated)
        repos: r[5] || [],
        sessionsSaved: (r[6] && r[6].ok && r[6].data) || null   // /v1/console/sessions — saved session ids
      };
      var model = buildGraphModel(data);
      if (!model.nodes.length && demoOn()) {
        var demoModel = buildGraphModel({ work: { work: demoData('work') || [] }, gates: { pending: demoData('needsYou') || [] } });
        if (demoModel.nodes.length) {
          model = demoModel;
          var head = wrap.querySelector('.canvas-graph-inspector .canvas-insp-type');
          if (head) { head.textContent = 'inspector · demo'; }
        }
      }
      drawGraph(stage, inspector, model, focus);
    }).catch(function () { stage.textContent = ''; stage.appendChild(el('p', { 'class': 'ctl-desc', text: 'Graph unavailable.' })); });
  }

  // ---- Canvas entry point (shell routes the canvas destination here) -----
  // No sub-pills: Canvas IS the page, with a nav-family Board | Graph switch.
  function renderCanvas(host, ctx) {
    ctx = ctx || {};
    var view = ctx.view === 'graph' ? 'graph' : 'board';
    host.textContent = '';
    var region = el('div', { 'class': 'canvas-region' });
    var seg = el('div', { 'class': 'modeseg canvas-seg', role: 'group', 'aria-label': 'Canvas view' });
    [['board', 'Board'], ['graph', 'Graph']].forEach(function (v) {
      var b = el('button', { 'class': 'modeseg-btn', type: 'button', 'data-view': v[0], 'aria-pressed': v[0] === view ? 'true' : 'false' }, [v[1]]);
      (function (vid) { b.addEventListener('click', function () { location.hash = '#/canvas/' + vid; }); })(v[0]);
      seg.appendChild(b);
    });
    region.appendChild(el('div', { 'class': 'canvas-head' }, [seg]));
    var body = el('div', { 'class': 'canvas-body' });
    region.appendChild(body);
    host.appendChild(region);
    if (view === 'graph') { return renderCanvasGraph(body, ctx, ctx.focus); }
    renderCanvasBoard(body, ctx);
    return Promise.resolve();
  }

  // =======================================================================
  //  Documents mode (M10) — the console-as-reader.
  //
  //  Ported COMPOSITION + MATERIAL from the WebCrux Proof reader
  //  (PlanCrux/docs/roadmaps/webcrux/UIWebSurfaces/webcrux-surfaces-demo-v3.jsx):
  //  the Section/Card reading composition, the EvidenceCard side surface, Receipt
  //  chips, and coverage/progress affordances — rebuilt in v2 tokens (no React,
  //  no JSX colour values). Its three-rail Proof layout (LEFT context rail ·
  //  CENTRE ~72ch reading column · RIGHT coverage/evidence rail) becomes the
  //  documents-mode 3-zone: the slimmed rail is the document tree, the main column
  //  is the reading surface, and the right panel is the evidence material.
  //
  //  Mode is PRESENTATION: renderDocuments NEVER touches posture (the security
  //  boundary). Real sources ground the reader — bundled daemon reference docs
  //  (genuinely shipped with this build; the same content the Pro dx-docs page
  //  lists) + per-tenant document corpora (GET /v1/console/tenants, chunks via the
  //  named CruxApi.consoleTenantsByTenantIdChunks method). Evidence is grounded in
  //  real facts (/v1/console/facts) + receipt refs (/v1/activity). The JSX's rich
  //  Proof narrative is a demoOn()-gated fixture (demoData('docsReader')) so the
  //  reader shows its full composition in demo mode — clearly demo-chipped.
  // =======================================================================

  // Bundled daemon reference docs — real, offline, no endpoint (the same static
  // reference content the Pro dx-docs page carries, composed here as a reader).
  var DOC_REFERENCE = [
    { slug: 'readme-corecruxd', title: 'README · corecruxd', subtitle: '17 crates · axum HTTP :14800 · Ed25519 CROWN receipts',
      sections: [
        { h: 'Build', body: ['cargo build --release builds the CPU-only daemon.', 'cargo test --workspace runs the suite; cargo clippy --workspace -- -D warnings gates the lint.'] },
        { h: 'Architecture', body: ['An axum HTTP surface on :14800 alongside a tonic gRPC plane.', 'An append-only shard store with sealed segments; Ed25519 CROWN receipts sign every mutation.'] },
        { h: 'Key rules', body: ['No GPU/CUDA in this repo — the daemon is CPU-only.', 'Port 14800 is fixed. Source-available under the CueCrux Community Licence.'] }
      ] },
    { slug: 'plans-md', title: 'PLANS.md', subtitle: 'the ExecPlan format',
      sections: [
        { h: 'Required sections', body: ['Every ExecPlan carries Purpose, Non-goals, Context, Constraints, Proposed design, Milestones, Test plan, Rollout/rollback, Risks, Progress, and a Decision log.', 'Plans are living documents: the Progress checklist and Decision log stay current milestone-by-milestone.'] }
      ] },
    { slug: 'mcp-system-prompt', title: 'mcp-system-prompt.md', subtitle: 'the MCP tool surface + capability ladder',
      sections: [
        { h: 'Tool surface', body: ['Retrieval: query, query_scan, query_expand.', 'Memory: store_fact, query_facts, delete_fact.', 'Coordination + observability: create_handoff, accept_handoff, sync_status, get_bootstrap.'] },
        { h: 'Two non-negotiables', body: ['token_budget is mandatory on every retrieval call.', 'Chat is for state transitions; durable content goes to store_fact or files.'] }
      ] }
  ];

  // Per-tenant document chunks via the named method (a parameterised route —
  // reachable only through the method, never CruxApi.get's literal allowlist).
  // Keeps renderDocuments at zero raw fetches (the network layer lives in api.js).
  function fetchTenantChunks(tenantId) {
    var api = (typeof window !== 'undefined') ? window.CruxApi : null;
    if (!api || typeof api.consoleTenantsByTenantIdChunks !== 'function') { return Promise.resolve({ ok: false, status: 0, data: null }); }
    return api.consoleTenantsByTenantIdChunks(tenantId)
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, status: r.status, data: d }; }, function () { return { ok: r.ok, status: r.status, data: null }; }); })
      .catch(function () { return { ok: false, status: 0, data: null }; });
  }

  // Small module cache so selecting a doc doesn't re-fetch the tenant list.
  var __docCache = { tenants: null };

  // ---- Reader material — ported micro-surfaces (v2 tokens) ---------------
  function docStr(v) { return (v == null || v === '') ? '—' : String(v); }
  var DOC_COV_TONE = { high: 'ok', medium: 'warn', low: 'crit' };
  function docCovTone(label) { return DOC_COV_TONE[String(label || '').toLowerCase()] || 'ink3'; }
  function docCovBadge(label, score) {
    var tone = docCovTone(label);
    var txt = String(label || '—') + (score != null ? ' · ' + Math.round(score * 100) + '%' : '');
    return el('span', { 'class': 'doc-cov doc-cov-' + tone, text: txt });
  }
  // Section micro-label (ported Section): mono · uppercase · wide tracking.
  function docSection(text) { return el('div', { 'class': 'doc-sec', text: String(text) }); }
  // A coverage component bar (ported CovBar) — reuses the .ctl-bar track/fill.
  function docCovBar(label, value) {
    var pct = Math.max(0, Math.min(100, Math.round((Number(value) || 0) * 100)));
    var tone = pct > 66 ? 'ok' : (pct > 33 ? '' : 'err');
    var track = el('div', { 'class': 'ctl-bar-track' }, [el('div', { 'class': 'ctl-bar-fill' + (tone ? ' ' + tone : '') })]);
    track.firstChild.style.width = pct + '%';
    return el('div', { 'class': 'ctl-bar' }, [
      el('div', { 'class': 'ctl-bar-head' }, [el('span', { text: String(label) }), el('span', { 'class': 'ctl-bar-val', text: pct + '%' })]),
      track
    ]);
  }
  // Receipt chip (ported Receipt): a mono ⛓ hash chip.
  function docReceipt(id, label, tsText) {
    var row = el('div', { 'class': 'doc-receipt' }, [
      el('span', { 'class': 'doc-receipt-id', text: '⛓ ' + String(id) })
    ]);
    if (label) { row.appendChild(el('span', { 'class': 'doc-receipt-label', text: String(label) })); }
    if (tsText) { row.appendChild(el('span', { 'class': 'doc-receipt-ts', text: String(tsText) })); }
    return row;
  }
  // EvidenceCard (ported) — a card with a role-keyed left strip: support→ok,
  // context→trust, challenge→warn. Surfaces real fields only.
  var DOC_ROLE_TONE = { support: 'ok', context: 'trust', challenge: 'warn' };
  function docEvidenceCard(e) {
    var tone = DOC_ROLE_TONE[e.role] || 'ink3';
    var card = el('div', { 'class': 'doc-evcard doc-ev-' + tone });
    var top = el('div', { 'class': 'doc-evcard-top' }, [el('span', { 'class': 'doc-evcard-domain', text: docStr(e.domain || e.source || 'source') })]);
    if (e.score != null) { top.appendChild(el('span', { 'class': 'doc-cov doc-cov-' + (e.score > 0.7 ? 'ok' : 'warn'), text: Math.round(e.score * 100) + '%' })); }
    card.appendChild(top);
    if (e.quote) { card.appendChild(el('div', { 'class': 'doc-evcard-quote', text: '“' + e.quote + '”' })); }
    if (e.summary) { card.appendChild(el('div', { 'class': 'doc-evcard-summary', text: e.summary })); }
    if (e.type) { card.appendChild(el('span', { 'class': 'doc-cov doc-cov-' + (e.type === 'contradiction' ? 'crit' : 'warn'), text: e.type })); }
    var foot = el('div', { 'class': 'doc-evcard-foot' }, [el('span', { text: docStr(e.source || e.domain) })]);
    if (e.observedAt) { foot.appendChild(el('span', { 'class': 'doc-evcard-ts', text: String(e.observedAt) })); }
    card.appendChild(foot);
    return card;
  }

  // =======================================================================
  //  JSX SURFACE PORT (M12) — the 11 WebCrux Proof surfaces
  //  (webcrux-surfaces-demo-v3.jsx) become the Documents-mode surface list.
  //  The rail's document tree is prefixed with the JSX's own 11-surface NAV
  //  (its `NAV` const, line 3028); each surface is a route #/documents/<id>.
  //  Proof (id 'proof') reuses the M11-fixed 3-zone reader below. The other ten
  //  are ported here as `renderDocSurface_<id>` composition functions (React →
  //  plain DOM). Every JSX colour token (T.accent/T.cyan/T.purple/…) maps to a
  //  v2 theme token via the ported micro-kit (docBadge/docDot/docStatusChip/
  //  docModeTag/docTiles + the existing docSection/docCard/docCovBar/docReceipt/
  //  docEvidenceCard) — so nothing carries a literal colour.
  //
  //  Honesty (the M12 gate): a surface with a real daemon endpoint reads it via
  //  the api.js client (fetchJSON → window.CruxApi.get) and shows real fields;
  //  a surface with NO clean endpoint renders the JSX's own data ONLY behind the
  //  demoOn()-guarded demoData('surfaces') choke point, clearly demo-chipped, and
  //  otherwise shows an honest "sample surface — enable demo data" empty state.
  //  NOTHING is fabricated as if real. Presentation only — no posture side effects.
  // =======================================================================
  var DOC_SURFACES = [
    { id: 'proof', label: 'Proof', icon: '◈' },
    { id: 'watch', label: 'Watch', icon: '◎' },
    { id: 'ask', label: 'Ask', icon: '◇' },
    { id: 'living', label: 'Living Objects', icon: '⬡' },
    { id: 'deps', label: 'Dependencies', icon: '⬙' },
    { id: 'signals', label: 'Signals', icon: '⚡' },
    { id: 'diff', label: 'Receipt Diff', icon: '⟷' },
    { id: 'sourcing', label: 'Sourcing', icon: '🔍' },
    { id: 'lanes', label: 'Lanes', icon: '⧈' },
    { id: 'domains', label: 'Domains', icon: '🏛' },
    { id: 'reverse', label: 'Reverse', icon: '⊘' }
  ];
  var DOC_SURFACE_IDS = DOC_SURFACES.map(function (s) { return s.id; });
  function isDocSurface(id) { return DOC_SURFACE_IDS.indexOf(id) >= 0; }
  // Reader docs ('ref:'/'tenant:'/'demo:proof'/null) belong to the Proof surface.
  function surfaceIdOf(docId) { return (docId && isDocSurface(docId)) ? docId : 'proof'; }

  // ---- Ported micro-kit (JSX tokens → v2 tokens) -------------------------
  // Generic pill (ported Badge). tone ∈ {ok,warn,crit,trust,''} → the doc-cov
  // family (already theme-tokenised); '' is the neutral surface pill.
  function docBadge(text, tone) { return el('span', { 'class': 'doc-cov' + (tone ? ' doc-cov-' + tone : ''), text: String(text) }); }
  // Coloured dot (ported Dot).
  function docDot(tone) { return el('span', { 'class': 'doc-dot' + (tone ? ' doc-dot-' + tone : ''), 'aria-hidden': 'true' }); }
  // Confidence band (ported CovBadge) — High→ok · Medium→warn · Low→crit.
  var DOC_BAND_TONE = { high: 'ok', medium: 'warn', low: 'crit' };
  function docBandTone(label) { return DOC_BAND_TONE[String(label || '').toLowerCase()] || ''; }
  var DOC_BAND_SCORE = { high: 0.82, medium: 0.55, low: 0.22 };
  function docBandBadge(label, score) {
    var s = (score != null) ? score : DOC_BAND_SCORE[String(label || '').toLowerCase()];
    return el('span', { 'class': 'doc-cov doc-cov-' + (docBandTone(label) || 'trust'), text: String(label || '—') + (s != null ? ' · ' + Math.round(s * 100) + '%' : '') });
  }
  // Status chip (ported StatusChip) — Stable→ok · Updated→warn · Attention→crit.
  var DOC_STATUS = { stable: ['ok', '●'], updated: ['warn', '◐'], attention: ['crit', '◉'], fresh: ['ok', '●'], stale: ['warn', '◐'], contested: ['crit', '◉'], superseded: ['', '○'], healthy: ['ok', '●'], error: ['crit', '◉'] };
  function docStatusChip(status) { var c = DOC_STATUS[String(status || '').toLowerCase()] || ['', '○']; return el('span', { 'class': 'doc-cov' + (c[0] ? ' doc-cov-' + c[0] : ''), text: c[1] + ' ' + status }); }
  // Mode tag (ported ModeTag) — verified→trust · audit→warn · light→neutral.
  var DOC_MODE_TONE = { verified: 'trust', audit: 'warn', light: '' };
  function docModeTag(mode) { return el('span', { 'class': 'doc-cov' + (DOC_MODE_TONE[String(mode || '').toLowerCase()] ? ' doc-cov-' + DOC_MODE_TONE[String(mode).toLowerCase()] : ''), text: String(mode) }); }
  // A quiet, inert surface button (ported Btn) — demo surfaces carry no live
  // behaviour, so these are nav-family .btn-quiet with no handler.
  function docBtn(label) { return el('button', { 'class': 'btn-quiet', type: 'button', text: String(label) }); }
  // Stat-tile row (ported the repeated {value / label} triples).
  function docTiles(pairs) {
    var row = el('div', { 'class': 'doc-tiles' });
    (pairs || []).forEach(function (p) {
      row.appendChild(el('div', { 'class': 'doc-tile' }, [
        el('div', { 'class': 'doc-tile-v', text: String(p[0]) }),
        el('div', { 'class': 'doc-tile-k', text: String(p[1]) })
      ]));
    });
    return row;
  }
  function docSurfaceHead(main, icon, title, sub, note) {
    var head = el('div', { 'class': 'doc-read-head' });
    head.appendChild(el('h1', { 'class': 'doc-read-title', text: icon + ' ' + title }));
    if (sub) { head.appendChild(el('p', { 'class': 'doc-read-sub', text: sub })); }
    if (note) { head.appendChild(el('p', { 'class': 'doc-surface-note', text: note })); }
    main.appendChild(head);
  }
  // A clickable/expandable list card (ported the repeated <Card> row). `opts`:
  // { chips:[node], title, text, side:[str], strip:tone, detail:fn(body) }.
  function docListCard(opts) {
    var card = el('details', { 'class': 'doc-card doc-list-card' + (opts.strip ? ' doc-strip doc-strip-' + opts.strip : '') });
    var sum = el('summary', { 'class': 'doc-list-sum' });
    var mainCol = el('div', { 'class': 'doc-surface-row-main' });
    if (opts.chips && opts.chips.length) { var cw = el('div', { 'class': 'doc-chips' }); opts.chips.forEach(function (c) { if (c) { cw.appendChild(c); } }); mainCol.appendChild(cw); }
    if (opts.title) { mainCol.appendChild(el('div', { 'class': 'doc-row-title', text: opts.title })); }
    if (opts.text) { mainCol.appendChild(el('div', { 'class': 'doc-row-text', text: opts.text })); }
    var row = el('div', { 'class': 'doc-surface-row' }, [mainCol]);
    if (opts.side && opts.side.length) {
      var sideCol = el('div', { 'class': 'doc-surface-row-side' });
      opts.side.forEach(function (s) { if (s != null) { sideCol.appendChild(el('div', { text: String(s) })); } });
      row.appendChild(sideCol);
    }
    sum.appendChild(row);
    card.appendChild(sum);
    if (typeof opts.detail === 'function') {
      var body = el('div', { 'class': 'doc-list-body' });
      opts.detail(body);
      card.appendChild(body);
    }
    return card;
  }
  function docArrow() { return el('span', { 'class': 'doc-arrow', 'aria-hidden': 'true', text: '→' }); }
  // Honest empty state for a demo surface with demo mode off.
  function docSurfaceEmpty(host, msg) {
    host.appendChild(el('div', { 'class': 'doc-surface-empty' }, [
      el('p', { 'class': 'ctl-desc', text: msg || 'Sample surface — enable demo data (?demo=1) to preview.' })
    ]));
  }
  // The demo-fixture choke point for surfaces: reads CruxDemo.surfaces[id] ONLY
  // through demoData() (demoOn()-guarded), so a surface can never render its
  // fixture un-flagged. Returns null when demo is off / the fixture is absent.
  function surfaceDemo(id) { var s = demoData('surfaces'); return (s && s[id]) ? s[id] : null; }

  // ---- 2 · Watch (real /v1/activity change feed + demo watched items) -----
  function renderDocSurface_watch(main, ctx) {
    docSurfaceHead(main, '◎', 'Watch', "We'll tell you when something you rely on changes.");
    var host = el('div', { 'class': 'doc-ev-host' }, [el('p', { 'class': 'ctl-desc', text: 'Loading change feed…' })]);
    main.appendChild(host);
    fetchJSON('/v1/activity?tenant_id=default&token_budget=1500').then(function (res) {
      host.textContent = '';
      var rows = (res.ok && res.data && res.data.rows) ? res.data.rows : [];
      if (rows.length) {
        host.appendChild(docSection('Change feed · /v1/activity'));
        rows.slice(0, 20).forEach(function (r) {
          var rid = (r.receipt_ids || [])[0] || r.receipt_id;
          host.appendChild(docListCard({ chips: [docBadge(r.kind || 'event', 'trust'), r.tool ? docBadge(r.tool, '') : null], title: r.preview || (r.kind || 'event'), side: [r.ts || null, rid || null] }));
        });
        return;
      }
      var w = surfaceDemo('watch');
      if (w && w.length) {
        var counts = { updated: w.filter(function (x) { return x.status !== 'Stable'; }).length, attn: w.filter(function (x) { return x.status === 'Attention'; }).length };
        host.appendChild(docTiles([[String(w.length), 'watched'], [String(counts.updated), 'updated (7d)'], [String(counts.attn), 'attention']]));
        host.appendChild(demoChip(true));
        host.appendChild(docSection('Watched items · demo'));
        w.forEach(function (x) {
          host.appendChild(docListCard({
            chips: [docBadge(x.type, ''), docStatusChip(x.status), x.dependents ? docBadge(x.dependents + ' deps', '') : null],
            title: x.name, side: [x.lastChecked ? String(x.lastChecked).slice(0, 10) : null], strip: docBandTone(x.band),
            detail: (x.history && x.history.length) ? function (body) {
              body.appendChild(docSection('Change log (' + x.history.length + ')'));
              x.history.forEach(function (h) {
                var c = el('div', { 'class': 'doc-card' }, [el('div', { 'class': 'doc-row-title', text: h.what })]);
                if (h.why) { c.appendChild(el('div', { 'class': 'doc-row-text', text: h.why })); }
                var chips = el('div', { 'class': 'doc-chips' }, [docBandBadge(h.cBefore), docArrow(), docBandBadge(h.cAfter)]);
                (h.codes || []).forEach(function (code) { chips.appendChild(docBadge(code, 'trust')); });
                c.appendChild(chips);
                body.appendChild(c);
              });
            } : null
          }));
        });
        return;
      }
      docSurfaceEmpty(host, 'Nothing you rely on has changed — silence is success. Enable demo data (?demo=1) to preview watched items.');
    });
  }

  // ---- 3 · Ask (demo surface — no live answer endpoint on this daemon) -----
  function renderDocSurface_ask(main, ctx) {
    docSurfaceHead(main, '◇', 'Ask', 'A verified answer canvas — claims linked to evidence, every iteration receipted.');
    var d = surfaceDemo('ask');
    if (!d) { docSurfaceEmpty(main, 'Ask has no live answer endpoint on this daemon build. Enable demo data (?demo=1) to preview the answer canvas.'); return; }
    main.appendChild(el('div', { 'class': 'doc-chips' }, [docModeTag(d.mode || 'verified'), docBandBadge(d.cov && d.cov.label, d.cov && d.cov.score), demoChip(true)]));
    main.appendChild(el('div', { 'class': 'doc-card' }, [el('div', { 'class': 'doc-row-text', text: d.query })]));
    if (d.thread && d.thread.length) {
      main.appendChild(docSection('Thread · ' + d.thread.length + ' iterations'));
      var strip = el('div', { 'class': 'doc-chips' });
      d.thread.forEach(function (t) { strip.appendChild(docBadge(t.label, t.type === 'ask' ? 'trust' : (t.type === 'alter_query' ? '' : 'warn'))); });
      main.appendChild(strip);
    }
    main.appendChild(docSection('Answer'));
    var ans = el('div', { 'class': 'doc-card' });
    (d.paragraphs || []).forEach(function (p) { ans.appendChild(el('p', { 'class': 'doc-chunk-text', text: p })); });
    main.appendChild(ans);
    main.appendChild(docSection('Claims (' + (d.claims || []).length + ')'));
    (d.claims || []).forEach(function (cl) {
      main.appendChild(el('div', { 'class': 'doc-claim-row' }, [docDot(cl.status === 'contested' ? 'warn' : 'ok'), el('span', { 'class': 'doc-row-text', text: cl.text }), el('span', { 'class': 'doc-chunk-claims', text: cl.id })]));
    });
    main.appendChild(docSection('Evidence (' + (d.evidence || []).length + ')'));
    (d.evidence || []).forEach(function (e) { main.appendChild(docEvidenceCard({ role: e.role === 'primary' ? 'support' : (e.role === 'context' ? 'context' : 'support'), domain: e.domain, summary: e.title, source: e.role, score: e.score })); });
    main.appendChild(docSection('Coverage'));
    var cov = el('div', { 'class': 'doc-card' }, [docBandBadge(d.cov && d.cov.label, d.cov && d.cov.score)]);
    var comp = (d.cov && d.cov.comp) || {};
    ['retrieval', 'domains', 'temporal', 'clusters'].forEach(function (k) { if (comp[k] != null) { cov.appendChild(docCovBar(k, comp[k])); } });
    main.appendChild(cov);
    main.appendChild(demoChip(true));
  }

  // ---- 4 · Living Objects (demo surface) ---------------------------------
  function renderDocSurface_living(main, ctx) {
    docSurfaceHead(main, '⬡', 'Living Objects', 'Artefacts with state, subscriptions, pressure, and auto-maintenance.');
    var list = surfaceDemo('living');
    if (!list || !list.length) { docSurfaceEmpty(main, 'No living-object endpoint on this daemon build. Enable demo data (?demo=1) to preview artefact state + pressure.'); return; }
    main.appendChild(demoChip(true));
    list.forEach(function (a) {
      main.appendChild(docListCard({
        chips: [docStatusChip(a.state), docBandBadge(a.confidence), docBadge('T' + a.trunkTier, ''), docBadge(a.lane, ''), a.pressureLevel > 0 ? docBadge('⚡ P' + a.pressureLevel, a.pressureLevel >= 3 ? 'crit' : (a.pressureLevel >= 2 ? 'warn' : '')) : null],
        title: a.title, text: a.domain, strip: DOC_STATUS[a.state] ? DOC_STATUS[a.state][0] : '',
        side: [(a.dependents.answers) + 'a · ' + a.dependents.mises + 'm', a.relations.length + ' rels'],
        detail: function (body) {
          body.appendChild(docTiles([[String(a.dependents.answers), 'answers'], [String(a.dependents.mises), 'mises'], [String(a.dependents.collections), 'collections']]));
          if (a.pressure && a.pressure.length) {
            body.appendChild(docSection('Active pressure'));
            a.pressure.forEach(function (p) {
              var tone = p.severity >= 3 ? 'crit' : (p.severity >= 2 ? 'warn' : '');
              var c = el('div', { 'class': 'doc-card doc-strip doc-strip-' + tone }, [el('div', { 'class': 'doc-chips' }, [docBadge(p.code, tone), docBadge('severity ' + p.severity, tone)])]);
              c.appendChild(el('div', { 'class': 'doc-row-text', text: p.summary }));
              c.appendChild(el('div', { 'class': 'doc-cov doc-cov-warn', text: '→ ' + p.action }));
              body.appendChild(c);
            });
          }
          body.appendChild(docSection('Relations (' + a.relations.length + ')'));
          a.relations.forEach(function (r) {
            body.appendChild(el('div', { 'class': 'doc-card' }, [el('div', { 'class': 'doc-chips' }, [docBadge(r.type.replace(/_/g, ' '), r.type.indexOf('contradict') >= 0 ? 'crit' : (r.type === 'supports' || r.type === 'supersedes' ? 'ok' : '')), docBadge(r.method, '')]), el('div', { 'class': 'doc-row-title', text: r.target }), el('div', { 'class': 'doc-row-text', text: 'confidence ' + Math.round(r.confidence * 100) + '%' })]));
          });
          body.appendChild(docSection('Version chain'));
          a.versions.forEach(function (v, i) { body.appendChild(el('div', { 'class': 'doc-receipt' }, [docDot(i === 0 ? 'ok' : ''), el('span', { 'class': 'doc-receipt-label', text: v.v }), el('span', { 'class': 'doc-receipt-ts', text: v.date + ' · ' + v.hash })])); });
        }
      }));
    });
  }

  // ---- 5 · Dependencies (demo surface — assumption-loaded dependency tree) -
  function renderDocSurface_deps(main, ctx) {
    docSurfaceHead(main, '⬙', 'Dependencies', 'What the answer rests on — confidence beams and assumption loading, node by node.');
    var d = surfaceDemo('deps');
    if (!d || !d.root) { docSurfaceEmpty(main, 'No dependency-graph endpoint on this daemon build. Enable demo data (?demo=1) to preview the assumption-loaded tree.'); return; }
    main.appendChild(el('div', { 'class': 'doc-chips' }, [docBandBadge(null, d.root.confidence), docBadge('fragility ' + Math.round(d.root.fragility * 100) + '%', d.root.fragility > 0.5 ? 'crit' : 'warn'), demoChip(true)]));
    main.appendChild(el('div', { 'class': 'doc-card' }, [el('div', { 'class': 'doc-row-text', text: d.query })]));
    main.appendChild(docSection('Dependency tree'));
    function assumTone(load) { return load <= 0.25 ? 'ok' : (load <= 0.5 ? 'warn' : 'crit'); }
    function walkNode(node, depth) {
      var row = el('div', { 'class': 'doc-dep-node', style: 'margin-left:' + (depth * 16) + 'px' });
      row.appendChild(el('div', { 'class': 'doc-chips' }, [
        docDot(assumTone(node.assumptionLoad)),
        el('span', { 'class': 'doc-row-title', text: node.label }),
        node.trunkTier ? docBadge('T' + node.trunkTier, '') : null,
        docBadge(node.type, node.type === 'assumption' ? 'warn' : '')
      ].filter(Boolean)));
      if (node.sublabel) { row.appendChild(el('div', { 'class': 'doc-row-text', text: node.sublabel })); }
      row.appendChild(docCovBar('confidence', node.confidence));
      row.appendChild(el('div', { 'class': 'doc-chunk-claims', text: 'assumption load ' + Math.round(node.assumptionLoad * 100) + '% · coverage ' + Math.round((node.coverageContribution || 0) * 100) + '%' }));
      main.appendChild(row);
      (node.children || []).forEach(function (c) { walkNode(c, depth + 1); });
    }
    walkNode(d.root, 0);
    main.appendChild(el('p', { 'class': 'ctl-desc', text: 'Assumption load: green ≤25% grounded · amber ≤50% · red assumption-heavy. Beam = confidence.' }));
    main.appendChild(demoChip(true));
  }

  // ---- 6 · Signals (demo surface — epistemic status-change feed) ----------
  function renderDocSurface_signals(main, ctx) {
    docSurfaceHead(main, '⚡', 'Signals', 'No breaking news. Only broken assumptions.', 'Epistemic status changes backed by receipts and diffs.');
    var list = surfaceDemo('signals');
    if (!list || !list.length) { docSurfaceEmpty(main, 'No signal feed on this daemon build. Enable demo data (?demo=1) to preview epistemic status changes.'); return; }
    main.appendChild(demoChip(true));
    var sevTone = { high: 'crit', medium: 'warn', low: 'ok' };
    list.forEach(function (s) {
      var tone = sevTone[s.severity] || '';
      main.appendChild(docListCard({
        chips: [docBadge(s.severity, tone), docBadge(s.type.replace(/_/g, ' '), ''), docBadge(s.target.type, '')],
        title: s.title, text: s.what, strip: tone,
        side: [s.publishedAt ? String(s.publishedAt).slice(0, 10) : null, s.depImpact.answers + 'a · ' + s.depImpact.artefacts + 'art'],
        detail: function (body) {
          body.appendChild(docSection('Why it changed'));
          body.appendChild(el('div', { 'class': 'doc-card' }, [el('div', { 'class': 'doc-row-text', text: s.why })]));
          var chips = el('div', { 'class': 'doc-chips' });
          (s.codes || []).forEach(function (c) { chips.appendChild(docBadge(c, 'trust')); });
          body.appendChild(chips);
          body.appendChild(el('div', { 'class': 'doc-chips' }, [docBandBadge(s.cBefore), docArrow(), docBandBadge(s.cAfter)]));
          if (s.rBefore || s.rAfter) {
            body.appendChild(docSection('Receipts'));
            if (s.rBefore) { body.appendChild(docReceipt(s.rBefore, 'before', null)); }
            if (s.rAfter) { body.appendChild(docReceipt(s.rAfter, 'after', null)); }
          }
        }
      }));
    });
  }

  // ---- 7 · Receipt Diff (real receipt timeline + demo before/after diff) ---
  function renderDocSurface_diff(main, ctx) {
    docSurfaceHead(main, '⟷', 'Receipt Diff', 'Side-by-side CROWN snapshot comparison — what changed and why.');
    var d = surfaceDemo('diff');
    if (d && d.before && d.after) {
      var b = d.before, a = d.after;
      var grid = el('div', { 'class': 'doc-diff-grid' });
      grid.appendChild(el('div', { 'class': 'doc-card doc-strip doc-strip-trust' }, [el('div', { 'class': 'doc-chips' }, [docBadge('BEFORE', 'trust'), docModeTag(b.mode)]), docReceipt(b.id, null, b.ts)]));
      grid.appendChild(el('div', { 'class': 'doc-card doc-strip doc-strip-warn' }, [el('div', { 'class': 'doc-chips' }, [docBadge('AFTER', 'warn'), docModeTag(a.mode)]), docReceipt(a.id, null, a.ts)]));
      main.appendChild(grid);
      main.appendChild(demoChip(true));
      main.appendChild(docSection('Confidence band'));
      var cd = a.confidence.score - b.confidence.score;
      main.appendChild(el('div', { 'class': 'doc-card' }, [el('div', { 'class': 'doc-chips' }, [docBandBadge(b.confidence.band, b.confidence.score), docArrow(), docBandBadge(a.confidence.band, a.confidence.score), docBadge((cd >= 0 ? '+' : '') + Math.round(cd * 100) + '%', cd >= 0 ? 'ok' : 'crit')])]));
      main.appendChild(docSection('Coverage components'));
      var covCard = el('div', { 'class': 'doc-card' });
      ['retrieval', 'domains', 'temporal', 'clusters'].forEach(function (k) {
        var delta = (a.coverage[k] || 0) - (b.coverage[k] || 0);
        var r = el('div', { 'class': 'doc-diff-row' }, [el('span', { 'class': 'doc-chunk-claims', text: k })]);
        r.appendChild(docCovBar('before', b.coverage[k]));
        r.appendChild(docCovBar('after', a.coverage[k]));
        r.appendChild(el('span', { 'class': 'doc-cov doc-cov-' + (delta >= 0 ? 'ok' : 'crit'), text: (delta >= 0 ? '+' : '') + Math.round(delta * 100) + '%' }));
        covCard.appendChild(r);
      });
      main.appendChild(covCard);
      if (a.dropped && a.dropped.length) {
        main.appendChild(docSection('Dropped evidence'));
        a.dropped.forEach(function (e) { main.appendChild(docEvidenceCard({ role: 'challenge', domain: e.domain, summary: e.title, source: e.reason, type: 'contradiction' })); });
      }
      return;
    }
    // Real receipt timeline (grounds the surface even without the demo diff).
    var host = el('div', { 'class': 'doc-ev-host' }, [el('p', { 'class': 'ctl-desc', text: 'Loading receipts…' })]);
    main.appendChild(host);
    fetchJSON('/v1/activity?tenant_id=default&token_budget=1500').then(function (res) {
      host.textContent = '';
      var rows = (res.ok && res.data && res.data.rows) ? res.data.rows : [];
      var seen = {}, n = 0;
      host.appendChild(docSection('Receipt timeline · /v1/activity'));
      rows.forEach(function (r) { var rid = (r.receipt_ids || [])[0] || r.receipt_id; if (!rid || seen[rid] || n >= 12) { return; } seen[rid] = true; n++; host.appendChild(docReceipt(rid, (r.kind || 'event') + (r.tool ? ' · ' + r.tool : ''), r.ts ? String(r.ts) : null)); });
      if (!n) { docSurfaceEmpty(host, 'No receipts to compare yet. Enable demo data (?demo=1) to preview a before/after CROWN diff.'); }
    });
  }

  // ---- 8 · Sourcing (demo surface — coverage-gap → sourcing lifecycle) -----
  function renderDocSurface_sourcing(main, ctx) {
    docSurfaceHead(main, '🔍', 'Sourcing', "When answers are thin, here's the path to fix them.", 'Policy-gated, costed, budgeted. Structured sourcing, not scraping.');
    var list = surfaceDemo('sourcing');
    if (!list || !list.length) { docSurfaceEmpty(main, 'No sourcing-request endpoint on this daemon build. Enable demo data (?demo=1) to preview the coverage-gap → sourcing lifecycle.'); return; }
    main.appendChild(demoChip(true));
    var stTone = { discovering: 'trust', quoted: '', awaiting_user_choice: 'warn', completed: 'ok', failed: 'crit' };
    list.forEach(function (s) {
      main.appendChild(docListCard({
        chips: [docBadge(String(s.status).replace(/_/g, ' '), stTone[s.status] || ''), docBandBadge(s.covLabel, s.covScore), s.fragility > 0.6 ? docBadge('fragility ' + Math.round(s.fragility * 100) + '%', 'crit') : null],
        title: s.query, side: [s.quoteEstimate ? s.quoteEstimate.crux + ' Crux' : null, s.suggestions.length + ' suggestion' + (s.suggestions.length === 1 ? '' : 's')],
        detail: function (body) {
          body.appendChild(docSection('Source suggestions (' + s.suggestions.length + ')'));
          s.suggestions.forEach(function (sg) {
            var sgTone = { accepted: 'ok', rejected: 'crit', ingested: 'trust' }[sg.status] || '';
            var c = el('div', { 'class': 'doc-card doc-strip doc-strip-' + sgTone }, [el('div', { 'class': 'doc-evcard-domain', text: sg.url })]);
            c.appendChild(el('div', { 'class': 'doc-row-text', text: sg.rationale }));
            c.appendChild(el('div', { 'class': 'doc-chips' }, [docBadge(sg.status, sgTone), docBadge(sg.lane + ' lane', '')]));
            body.appendChild(c);
          });
          if (s.quoteEstimate) {
            body.appendChild(docSection('Cost estimate'));
            body.appendChild(docTiles([[String(s.quoteEstimate.crux), 'Crux'], ['£' + s.quoteEstimate.gbp.toFixed(2), 'GBP'], ['~' + s.quoteEstimate.chunks, 'chunks est.']]));
            body.appendChild(el('p', { 'class': 'ctl-desc', text: 'No token pricing. No surprise bills.' }));
          }
          if (s.status === 'awaiting_user_choice') { body.appendChild(el('div', { 'class': 'doc-btn-row' }, [docBtn('✓ Upgrade (fund ingestion)'), docBtn('⏳ Backlog'), docBtn('⊘ Cancel')])); }
          body.appendChild(docSection('Discovered domains'));
          var dz = el('div', { 'class': 'doc-chips' });
          (s.discoveredDomains || []).forEach(function (dm) { dz.appendChild(docBadge(dm, 'trust')); });
          body.appendChild(dz);
        }
      }));
    });
  }

  // ---- 9 · Lanes (real RRF lane weights + demo embedding lane stack) -------
  function renderDocSurface_lanes(main, ctx) {
    docSurfaceHead(main, '⧈', 'Lanes', 'Fast baseline for everything. Selective upgrades for what matters.', 'Late-fusion retrieval · no cross-dimension maths.');
    var host = el('div', { 'class': 'doc-ev-host' }, [el('p', { 'class': 'ctl-desc', text: 'Loading lane weights…' })]);
    main.appendChild(host);
    fetchJSON('/v1/console/corecrux/lane-weights').then(function (res) {
      host.textContent = '';
      var d = (res.ok && res.data) ? res.data : null;
      if (d && d.weights) {
        host.appendChild(docSection('RRF fusion weights · ' + (d.scope || 'global') + (d.fusion_rrf_enabled ? ' · RRF on' : ' · RRF off')));
        var card = el('div', { 'class': 'doc-card' });
        var mx = 1; Object.keys(d.weights).forEach(function (k) { mx = Math.max(mx, Number(d.weights[k]) || 0); });
        Object.keys(d.weights).forEach(function (k) { card.appendChild(docCovBar(k, (Number(d.weights[k]) || 0) / mx)); });
        host.appendChild(card);
      } else {
        host.appendChild(el('p', { 'class': 'ctl-desc', text: res.status === 0 ? 'Lane weights unreachable.' : 'CoreCrux lane-weight overlay unavailable (subscription lanes off).' }));
      }
      // Embedding lane stack — the JSX material (no live per-lane throughput
      // endpoint on this daemon), demo-chipped.
      var stack = surfaceDemo('lanes');
      if (stack && stack.lanes && stack.lanes.length) {
        host.appendChild(docSection('Embedding lane stack · demo'));
        host.appendChild(demoChip(true));
        var maxArt = Math.max.apply(null, stack.lanes.map(function (l) { return l.stats.artefacts; }).concat([1]));
        stack.lanes.forEach(function (l) {
          host.appendChild(docListCard({
            chips: [docBadge(l.tier, 'trust'), docBadge(l.dim + ' dim', ''), docBadge(l.provider, '')],
            title: l.model, text: l.desc,
            side: [l.stats.artefacts.toLocaleString() + ' artefacts', l.stats.cost + ' · p95 ' + l.stats.p95],
            detail: function (body) {
              body.appendChild(docCovBar('share of stack', l.stats.artefacts / maxArt));
              body.appendChild(docTiles([[String(l.stats.backlog), 'backlog'], [l.stats.throughput, 'throughput'], [l.modes.join(' · '), 'modes']]));
            }
          }));
        });
        if (stack.promotions && stack.promotions.length) {
          host.appendChild(docSection('Recent promotions · demo'));
          stack.promotions.forEach(function (p) {
            host.appendChild(docListCard({ chips: [docBadge(p.from + ' → ' + p.to, ''), docBadge(p.reason, 'trust'), docBadge(p.status, p.status === 'done' ? 'ok' : (p.status === 'running' ? 'warn' : ''))], title: p.artefact, side: [p.score != null ? 'score ' + p.score : (p.budget || null)] }));
          });
        }
      }
    });
  }

  // ---- 10 · Domains (real feature coverage + demo domain health) ----------
  function renderDocSurface_domains(main, ctx) {
    docSurfaceHead(main, '🏛', 'Domains', 'Corpus health per source — coverage, freshness, trust, contradiction.');
    var host = el('div', { 'class': 'doc-ev-host' }, [el('p', { 'class': 'ctl-desc', text: 'Loading coverage…' })]);
    main.appendChild(host);
    fetchJSON('/v1/features/capabilities/analysis/coverage').then(function (res) {
      host.textContent = '';
      var systems = (res.ok && res.data && (res.data.systems || res.data.coverage || res.data.rows)) || [];
      if (Array.isArray(systems) && systems.length) {
        host.appendChild(docSection('Feature coverage by system · /v1/features/…/coverage'));
        systems.slice(0, 20).forEach(function (s) {
          var total = s.total || s.count || 0, tested = s.tested || 0;
          var ratio = total ? tested / total : 0;
          host.appendChild(docListCard({ chips: [docBandBadge(ratio > 0.66 ? 'High' : (ratio > 0.33 ? 'Medium' : 'Low'), ratio)], title: s.system || s.name || s.id || 'system', side: [tested + '/' + total + ' tested'], detail: function (body) { body.appendChild(docCovBar('tested', ratio)); } }));
        });
      } else {
        host.appendChild(el('p', { 'class': 'ctl-desc', text: res.status === 0 ? 'Coverage unreachable.' : 'Feature coverage unavailable on this daemon (needs the features lens).' }));
      }
      var doms = surfaceDemo('domains');
      if (doms && doms.length) {
        host.appendChild(docSection('Source domain health · demo'));
        host.appendChild(demoChip(true));
        doms.forEach(function (dm) {
          host.appendChild(docListCard({
            chips: [docStatusChip(dm.ingestionStatus), docBadge(dm.type, ''), dm.flags && dm.flags.length ? docBadge('⚠ ' + dm.flags.length, 'warn') : null],
            title: dm.name + ' · ' + dm.slug, side: [dm.artefacts + ' artefacts', dm.dependents.answers + 'a · ' + dm.dependents.mises + 'm'],
            detail: function (body) {
              body.appendChild(docCovBar('coverage', dm.coverage));
              body.appendChild(docCovBar('freshness', dm.freshness));
              body.appendChild(docCovBar('trust', dm.trust));
              body.appendChild(docCovBar('contradiction', dm.contradiction));
              (dm.flags || []).forEach(function (f) { body.appendChild(el('div', { 'class': 'doc-cov doc-cov-warn', text: f.msg })); });
            }
          }));
        });
      }
    });
  }

  // ---- 11 · Reverse (demo surface — assertion verification + counterfactuals)
  function renderDocSurface_reverse(main, ctx) {
    docSurfaceHead(main, '⊘', 'Reverse', 'Paste an assertion — the engine finds what supports or contests it, then shows what breaks if you remove a source.');
    var d = surfaceDemo('reverse');
    if (!d) { docSurfaceEmpty(main, 'No reverse-verification endpoint on this daemon build. Enable demo data (?demo=1) to preview assertion verification.'); return; }
    main.appendChild(el('div', { 'class': 'doc-card' }, [el('div', { 'class': 'doc-row-text', text: d.assertion })]));
    main.appendChild(demoChip(true));
    var an = d.analysis || {};
    var vTone = an.verdictColor === 'red' ? 'crit' : (an.verdictColor === 'amber' ? 'warn' : 'ok');
    main.appendChild(docSection('Verdict'));
    main.appendChild(el('div', { 'class': 'doc-card doc-strip doc-strip-' + vTone }, [
      el('div', { 'class': 'doc-chips' }, [docBadge(an.verdict, vTone), docBandBadge(an.covLabel, an.covScore), docBadge('confidence ' + Math.round((an.confidence || 0) * 100) + '%', vTone), docBadge('fragility ' + Math.round((an.fragility || 0) * 100) + '%', an.fragility > 0.5 ? 'crit' : 'warn')]),
      el('div', { 'class': 'doc-issues' })
    ]));
    (an.issues || []).forEach(function (iss) { main.appendChild(el('div', { 'class': 'doc-card doc-strip doc-strip-' + (iss.severity === 'medium' ? 'warn' : ''), }, [el('div', { 'class': 'doc-chips' }, [docBadge(iss.severity, iss.severity === 'medium' ? 'warn' : '')]), el('div', { 'class': 'doc-row-text', text: iss.text })])); });
    main.appendChild(docSection('Evidence (' + (d.evidence || []).length + ') — remove a source to see what breaks'));
    (d.evidence || []).forEach(function (e) {
      var cf = (d.counterfactuals || {})[e.id];
      main.appendChild(docListCard({
        chips: [docBadge(e.role, e.role === 'primary' ? 'trust' : ''), docBadge(Math.round(e.score * 100) + '%', e.score > 0.7 ? 'ok' : 'warn')],
        title: e.title, text: e.domain,
        detail: function (body) {
          (e.supports || []).forEach(function (sp) { body.appendChild(el('div', { 'class': 'doc-claim-row' }, [docDot('ok'), el('span', { 'class': 'doc-row-text', text: sp })])); });
          if (e.note) { body.appendChild(el('p', { 'class': 'ctl-desc', text: e.note })); }
          if (cf) {
            var t = cf.verdictColor === 'red' ? 'crit' : (cf.verdictColor === 'amber' ? 'warn' : 'ok');
            body.appendChild(docSection('If removed →'));
            body.appendChild(el('div', { 'class': 'doc-card doc-strip doc-strip-' + t }, [el('div', { 'class': 'doc-chips' }, [docBadge(cf.verdict, t), docBadge('confidence ' + Math.round(cf.confidence * 100) + '%', t)]), el('div', { 'class': 'doc-row-text', text: cf.answer })]));
            if (cf.warning) { body.appendChild(el('div', { 'class': 'doc-cov doc-cov-crit', text: '⚠ ' + cf.warning })); }
          }
        }
      }));
    });
  }

  // Surface dispatch — Proof is the reader (handled in renderDocuments); the
  // other ten are the ported composition functions above.
  var DOC_SURFACE_RENDER = {
    watch: renderDocSurface_watch, ask: renderDocSurface_ask, living: renderDocSurface_living,
    deps: renderDocSurface_deps, signals: renderDocSurface_signals, diff: renderDocSurface_diff,
    sourcing: renderDocSurface_sourcing, lanes: renderDocSurface_lanes, domains: renderDocSurface_domains,
    reverse: renderDocSurface_reverse
  };
  function renderDocSurface(main, id, ctx) {
    var fn = DOC_SURFACE_RENDER[id];
    if (fn) { fn(main, ctx || {}); }
    else { main.appendChild(el('p', { 'class': 'ctl-desc', text: 'Unknown surface.' })); }
  }

  // ---- Document source model (real + demo) -------------------------------
  // Resolve a docId ("ref:<slug>" · "tenant:<id>" · "demo:proof") + the source
  // list. Real tenants win; the demo Proof doc appears only when demoOn().
  function docDefaultId(tenants) {
    if (demoOn()) { return 'demo:proof'; }
    if (DOC_REFERENCE.length) { return 'ref:' + DOC_REFERENCE[0].slug; }
    if (tenants && tenants.length) { return 'tenant:' + (tenants[0].tenant_id || tenants[0].id); }
    return null;
  }

  // Build the rail document tree (left zone) + the phone sources sheet share it.
  // The tree now LEADS with the JSX's own 11-surface NAV (Proof · Watch · Ask ·
  // Living Objects · Dependencies · Signals · Receipt Diff · Sourcing · Lanes ·
  // Domains · Reverse) as the primary Documents-mode navigation; the bundled
  // reference docs + tenant corpora follow as a "Docs" group (Proof-reader docs).
  // The Explore rail — styled exactly like the Command rail (.nav-item). Explorer
  // is pinned at the top and stays inside the Explore surface; the surfaces are
  // the Explore "Pages". Reader docs + tenant corpora are NOT listed here — they
  // are reached from Explorer search results (which open in the Ask/reader surface).
  function buildDocTree(host, tenants, activeId) {
    host.textContent = '';
    var isExplorer = (activeId === 'explorer');
    var activeSurface = surfaceIdOf(activeId);
    function navItem(label, glyph, current, target) {
      var b = el('button', { 'class': 'nav-item', type: 'button', 'aria-current': current ? 'page' : 'false' }, [
        el('span', { 'class': 'nav-glyph', 'aria-hidden': 'true', text: glyph || '' }),
        el('span', { 'class': 'label', text: label })
      ]);
      b.addEventListener('click', function () { location.hash = target; });
      host.appendChild(b);
    }
    // Explorer + the surfaces all live in one flat list (no group label).
    navItem('Explorer', '⌕', isExplorer, '#/documents/explorer');
    DOC_SURFACES.forEach(function (s) {
      navItem(s.label, s.icon, !isExplorer && s.id === activeSurface, '#/documents/' + s.id);
    });
  }

  // ---- Reading surface (centre) ------------------------------------------
  function docReadHeader(main, title, subtitle, mode, cov) {
    var head = el('div', { 'class': 'doc-read-head' });
    head.appendChild(el('h1', { 'class': 'doc-read-title', text: title }));
    if (subtitle) { head.appendChild(el('p', { 'class': 'doc-read-sub', text: subtitle })); }
    var chips = el('div', { 'class': 'doc-read-chips' });
    if (mode) { chips.appendChild(el('span', { 'class': 'doc-cov doc-cov-trust', text: mode })); }
    if (cov) { chips.appendChild(docCovBadge(cov.label, cov.score)); }
    if (chips.childNodes.length) { head.appendChild(chips); }
    main.appendChild(head);
  }
  function docReadChunk(container, ch) {
    var tone = docCovTone(ch.cov && ch.cov.label);
    var block = el('div', { 'class': 'doc-chunk doc-chunk-' + tone });
    block.appendChild(el('p', { 'class': 'doc-chunk-text', text: ch.text }));
    var meta = el('div', { 'class': 'doc-chunk-meta' });
    if (ch.label) { meta.appendChild(el('span', { 'class': 'doc-cov doc-cov-' + tone, text: String(ch.label).replace(/_/g, ' ') })); }
    if (ch.cov && ch.cov.score > 0) { meta.appendChild(docCovBadge(ch.cov.label, ch.cov.score)); }
    if (ch.claims && ch.claims.length) { meta.appendChild(el('span', { 'class': 'doc-chunk-claims', text: ch.claims.length + ' claim' + (ch.claims.length === 1 ? '' : 's') })); }
    if (ch.fragile) { meta.appendChild(el('span', { 'class': 'doc-cov doc-cov-crit', text: '⚠ fragile' })); }
    if (meta.childNodes.length) { block.appendChild(meta); }
    container.appendChild(block);
  }
  function renderDocReference(main, doc) {
    docReadHeader(main, doc.title, doc.subtitle, 'reference', null);
    (doc.sections || []).forEach(function (sec) {
      main.appendChild(docSection(sec.h));
      var card = el('div', { 'class': 'doc-card' });
      (sec.body || []).forEach(function (p) { card.appendChild(el('p', { 'class': 'doc-chunk-text', text: p })); });
      main.appendChild(card);
    });
  }
  function renderDocDemo(main, doc) {
    docReadHeader(main, doc.title, doc.subtitle, doc.mode, doc.coverage);
    main.appendChild(demoChip(true));
    (doc.sections || []).forEach(function (sec) {
      main.appendChild(docSection(sec.title));
      (sec.chunks || []).forEach(function (ch) { docReadChunk(main, ch); });
    });
  }
  function renderDocTenant(main, tenantId) {
    docReadHeader(main, tenantId, 'tenant corpus · what the daemon has read', 'corpus', null);
    var host = el('div', { 'class': 'doc-tenant-body' }, [el('p', { 'class': 'ctl-desc', text: 'Loading documents…' })]);
    main.appendChild(host);
    fetchTenantChunks(tenantId).then(function (res) {
      host.textContent = '';
      if (!res.ok || !res.data) {
        host.appendChild(el('p', { 'class': 'ctl-desc', text: res.status === 404 ? 'No per-tenant chunk endpoint on this build.' : ('Documents unavailable — ' + (res.status === 0 ? 'unreachable' : 'HTTP ' + res.status) + '.') }));
        return;
      }
      var chunks = res.data.chunks || res.data.items || (Array.isArray(res.data) ? res.data : []);
      if (!chunks.length) { host.appendChild(el('p', { 'class': 'ctl-desc', text: 'No documents read into this tenant yet.' })); return; }
      // Group by document/source when the chunk carries one; else a flat read.
      var groups = {};
      chunks.slice(0, 60).forEach(function (c) {
        var g = c.doc_id || c.document || c.source || c.section || 'document';
        (groups[g] = groups[g] || []).push(c);
      });
      Object.keys(groups).forEach(function (g) {
        main.appendChild(docSection(g));
        var card = el('div', { 'class': 'doc-card' });
        groups[g].slice(0, 20).forEach(function (c) {
          var text = c.text || c.preview || c.content || c.body || (c.digest ? ('chunk ' + c.digest) : JSON.stringify(c).slice(0, 200));
          card.appendChild(el('p', { 'class': 'doc-chunk-text', text: String(text) }));
        });
        main.appendChild(card);
      });
    });
  }

  // ---- Evidence panel (right zone) ---------------------------------------
  // Real facts as EvidenceCards + receipt refs from activity + coverage/progress
  // where real numbers exist; the demo doc fills all three from its fixture.
  function renderDocEvidence(panel, ctx, docId) {
    panel.textContent = '';
    var isDemoDoc = docId === 'demo:proof';
    var dr = isDemoDoc ? demoData('docsReader') : null;

    // 1 · Coverage / progress — only where real numbers exist.
    if (dr && dr.coverage) {
      panel.appendChild(docSection('Coverage'));
      var covCard = el('div', { 'class': 'doc-card' }, [docCovBadge(dr.coverage.label, dr.coverage.score)]);
      (dr.coverage.components || []).forEach(function (c) { covCard.appendChild(docCovBar(c[0], c[1])); });
      if (dr.coverage.fragility != null) { covCard.appendChild(el('p', { 'class': 'ctl-desc', text: 'Fragility ' + Math.round(dr.coverage.fragility * 100) + '% — evidence base concentration.' })); }
      covCard.appendChild(demoChip(true));
      panel.appendChild(covCard);
    } else {
      var s = ctx && ctx.summary;
      var free = get(s, ['capacity', 'free_ratio']);
      var facts = get(s, ['stores', 'facts']);
      if (free != null || facts != null) {
        panel.appendChild(docSection('Corpus'));
        var card = el('div', { 'class': 'doc-card' });
        if (facts != null) { card.appendChild(kv('facts', fmtChartVal(facts, 'compact'))); }
        if (free != null) { card.appendChild(docCovBar('storage free', free)); }
        panel.appendChild(card);
      }
    }

    // 2 · Related facts as EvidenceCards.
    panel.appendChild(docSection('Related facts'));
    if (dr) {
      (dr.evidence || []).forEach(function (e) { panel.appendChild(docEvidenceCard(e)); });
      panel.appendChild(demoChip(true));
    } else {
      var factsHost = el('div', { 'class': 'doc-ev-host' }, [el('p', { 'class': 'ctl-desc', text: 'Loading facts…' })]);
      panel.appendChild(factsHost);
      fetchJSON('/v1/console/facts?top_k=8').then(function (res) {
        factsHost.textContent = '';
        var fs = (res.ok && res.data && res.data.facts) ? res.data.facts : [];
        if (!fs.length) { factsHost.appendChild(el('p', { 'class': 'ctl-desc', text: res.ok ? 'No related facts.' : 'Facts unavailable.' })); return; }
        fs.slice(0, 8).forEach(function (f) {
          factsHost.appendChild(docEvidenceCard({ role: 'support', domain: f.entity, summary: String(f.value != null ? f.value : f.key).slice(0, 160), source: f.key || f.entity, observedAt: f.stored_at ? String(f.stored_at).slice(0, 10) : null }));
        });
      });
    }

    // 3 · Receipts.
    panel.appendChild(docSection('Receipts'));
    if (dr) {
      (dr.receipts || []).forEach(function (r) { panel.appendChild(docReceipt(r.id, r.label, r.ts)); });
      panel.appendChild(demoChip(true));
    } else {
      var rcptHost = el('div', { 'class': 'doc-ev-host' }, [el('p', { 'class': 'ctl-desc', text: 'Loading receipts…' })]);
      panel.appendChild(rcptHost);
      fetchJSON('/v1/activity?tenant_id=default&token_budget=1500').then(function (res) {
        rcptHost.textContent = '';
        var rows = (res.ok && res.data && res.data.rows) ? res.data.rows : [];
        var seen = {}, n = 0;
        rows.forEach(function (r0) {
          var rid = (r0.receipt_ids || [])[0] || r0.receipt_id;
          if (!rid || seen[rid] || n >= 8) { return; }
          seen[rid] = true; n++;
          rcptHost.appendChild(docReceipt(rid, (r0.kind || 'event') + (r0.tool ? ' · ' + r0.tool : ''), r0.ts ? String(r0.ts) : null));
        });
        if (!n) { rcptHost.appendChild(el('p', { 'class': 'ctl-desc', text: res.status === 404 ? 'Activity surface off — no receipt refs.' : 'No receipts captured yet.' })); }
      });
    }
  }

  // ---- Documents entry point (the shell routes documents mode here) ------
  // ctx: { summary, docId, railHost }. Builds the rail document tree (left zone),
  // the ~72ch reading surface (centre), and the evidence panel (right zone /
  // stacked on phone). Presentation only — no posture side effects.
  function renderDocuments(host, ctx) {
    ctx = ctx || {};
    host.textContent = '';
    // Tree hosts (rail + phone sheet) to re-decorate once the live corpora land.
    var treeHosts = [];
    var activeDocId = null;
    function paint(tenants) {
      // The docId (route #/documents/<id>) is EITHER one of the 10 non-Proof
      // surfaces (a full-width composition) OR a reader doc ('ref:'/'tenant:'/
      // 'demo:proof') / 'proof' / null (the 3-zone Proof reader — the M11 default).
      var raw = ctx.docId;
      // Explorer — the corpus search, rendered INSIDE the Explore shell so the
      // Explore rail (Explorer + Pages) stays put. Reader docs are reached from
      // the search results, not a menu.
      if (raw === 'explorer') {
        if (ctx.railHost) { buildDocTree(ctx.railHost, tenants, 'explorer'); }
        var exWrap = el('div', { 'class': 'doc-reader doc-surface-wrap' });
        var exMain = el('main', { 'class': 'doc-surface-main explorer-surface' });
        exWrap.appendChild(exMain);
        host.appendChild(exWrap);
        renderExplorer(exMain, ctx);
        return;
      }
      var surfaceId = (raw && isDocSurface(raw) && raw !== 'proof') ? raw : null;
      var readerDocId = (raw && !isDocSurface(raw)) ? raw : docDefaultId(tenants);
      var railActive = surfaceId || readerDocId || 'proof';
      activeDocId = railActive;
      treeHosts = [];
      // Rail tree (desktop) — the shell hands us the rail host. Leads with the
      // 11-surface nav; the active surface (or the Proof reader) is aria-current.
      if (ctx.railHost) { buildDocTree(ctx.railHost, tenants, railActive); treeHosts.push(ctx.railHost); }
      var reader = el('div', { 'class': 'doc-reader' + (surfaceId ? ' doc-surface-wrap' : '') });
      // Phone sources sheet (CSS hides it on the desktop tier, where the rail
      // tree is shown instead) — carries the same 11-surface nav + docs tree.
      var sheet = el('details', { 'class': 'doc-sources-sheet' });
      sheet.appendChild(el('summary', { 'class': 'doc-sources-summary', text: 'Surfaces & sources' }));
      var sheetTree = el('div', { 'class': 'doc-tree' });
      buildDocTree(sheetTree, tenants, railActive); treeHosts.push(sheetTree);
      sheet.appendChild(sheetTree);
      reader.appendChild(sheet);
      if (surfaceId) {
        // A ported JSX surface — full-width single column, no evidence rail.
        var smain = el('main', { 'class': 'doc-surface-main' });
        reader.appendChild(smain);
        host.appendChild(reader);
        renderDocSurface(smain, surfaceId, ctx);
        return;
      }
      // Proof reader — the M11 3-zone layout (reading surface + evidence panel).
      var main = el('main', { 'class': 'doc-main' });
      var evidence = el('aside', { 'class': 'doc-evidence' });
      reader.appendChild(main);
      reader.appendChild(evidence);
      host.appendChild(reader);
      var docId = readerDocId;
      if (!docId) { main.appendChild(el('p', { 'class': 'ctl-desc', text: 'No documents to read yet. Ingest a corpus, or enable demo mode (?demo=1) to preview the reader.' })); }
      else if (docId === 'demo:proof' && demoData('docsReader')) { renderDocDemo(main, demoData('docsReader')); }
      else if (docId.indexOf('ref:') === 0) {
        var ref = DOC_REFERENCE.filter(function (d) { return 'ref:' + d.slug === docId; })[0];
        if (ref) { renderDocReference(main, ref); } else { main.appendChild(el('p', { 'class': 'ctl-desc', text: 'Unknown reference doc.' })); }
      } else if (docId.indexOf('tenant:') === 0) { renderDocTenant(main, docId.slice('tenant:'.length)); }
      else { main.appendChild(el('p', { 'class': 'ctl-desc', text: 'Unknown document.' })); }
      // Evidence panel (real facts + receipts + coverage where real).
      renderDocEvidence(evidence, ctx, docId);
    }
    // SYNCHRONOUS first paint. The reader (the tree + the bundled reference docs +
    // the demo Proof doc) needs ZERO network, so it must never sit behind the
    // /v1/console/tenants fetch. Previously EVERY paint was deferred until that
    // fetch resolved — on a slow, hung, or unreachable daemon the reader stayed
    // blank forever (no .doc-main, an empty tree). Paint now runs up front against
    // the tenant cache (or []); the live corpora list only re-decorates the tree's
    // "Corpora · tenants" branch when it lands.
    paint(__docCache.tenants || []);
    if (__docCache.tenants) { return Promise.resolve(); }
    return fetchJSON('/v1/console/tenants').then(function (res) {
      var tenants = (res.ok && res.data && (res.data.tenants || res.data.items)) || [];
      __docCache.tenants = tenants;
      // Re-decorate the tree host(s) with the live corpora. The main reading pane
      // is already painted; with DOC_REFERENCE non-empty the default doc is stable
      // across the tenant list (docDefaultId only falls through to a tenant when
      // there are no reference docs), so refreshing the tree alone avoids a
      // reading-surface flash. A tenant doc's own chunks lazy-fetch on selection.
      if (tenants.length) { treeHosts.forEach(function (t) { buildDocTree(t, tenants, activeDocId); }); }
    }).catch(function () {});
  }

  // =======================================================================
  //  Explorer (M11) — corpus search. READS ONLY, so it is customer-safe and
  //  visible in every posture. Two backends:
  //    * Local    → CruxApiRead.queryTextSearch (daemon BM25 over the local
  //                 tenant index; response = {results:[{result_id,score,
  //                 source_label,rank,…}]}, grounded in query.rs
  //                 post_query_text_search — hits carry an id + score, no text).
  //    * WikiCrux → CruxApiRead.engineSearch (the daemon-mediated /v1/retrieve
  //                 proxy; response = {data:{results:[{title,content,score,
  //                 source,tenantId,…}]}} — RetrievalResult, grounded in the
  //                 Engine openapi.json). Carries snippet + title + tenant.
  //  Every network call goes through window.CruxApiRead (the curated read-POST
  //  client in api.js); render.js performs no raw fetch. Debounced; no throws on
  //  any failure. demoOn() fills sample cards (chipped) when a backend is
  //  unreachable/off — real results always win.
  // =======================================================================
  var EXPLORER_BACKENDS = [{ id: 'local', label: 'Local' }, { id: 'wikicrux', label: 'WikiCrux' }];

  // Call the curated read-POST client; resolve to {ok,status,data} — never throw.
  function readPost(method, body) {
    var api = (typeof window !== 'undefined') ? window.CruxApiRead : null;
    if (!api || typeof api[method] !== 'function') { return Promise.resolve({ ok: false, status: 0, data: null }); }
    return api[method](body)
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, status: r.status, data: d }; }, function () { return { ok: r.ok, status: r.status, data: null }; }); })
      .catch(function () { return { ok: false, status: 0, data: null }; });
  }
  // Local text-search hit → card model (real fields only; local BM25 hits have
  // no stored text, so snippet is null — id + score + source only).
  function explorerLocalCards(data) {
    var results = (data && data.results) || [];
    return results.map(function (h) {
      var id = h.result_id || ((h.segment_index != null && h.doc_id != null) ? (h.segment_index + ':' + h.doc_id) : 'result');
      return { title: id, snippet: null, source: h.source_label || 'local_tenant_index', score: h.score, tenant: null, rank: h.rank };
    });
  }
  // WikiCrux /v1/retrieve result (under the mediated envelope's data.results) →
  // card model. title/content/score/source/tenantId are the real RetrievalResult
  // fields.
  function explorerEngineCards(data) {
    var results = get(data, ['data', 'results']) || (data && data.results) || [];
    return results.map(function (r) {
      return { title: r.title || r.docId || r.chunkId || 'result', snippet: r.content || null, source: r.source || null, score: r.score, tenant: r.tenantId || null };
    });
  }
  function explorerScoreTone(score) { return score > 0.66 ? 'ok' : (score > 0.33 ? 'warn' : 'ink3'); }
  function explorerCard(c, demo, onOpen) {
    var card = el('div', { 'class': 'explorer-card', role: 'button', tabindex: '0' });
    if (onOpen) {
      card.addEventListener('click', function () { onOpen(c); });
      card.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onOpen(c); } });
    }
    var top = el('div', { 'class': 'explorer-card-top' }, [el('span', { 'class': 'explorer-card-title', text: String(c.title) })]);
    if (typeof c.score === 'number' && isFinite(c.score)) {
      top.appendChild(el('span', { 'class': 'doc-cov doc-cov-' + explorerScoreTone(c.score), text: c.score.toFixed(2) }));
    }
    card.appendChild(top);
    if (c.snippet) { card.appendChild(el('div', { 'class': 'explorer-card-snippet', text: String(c.snippet) })); }
    var meta = el('div', { 'class': 'explorer-card-meta' });
    if (c.source) { meta.appendChild(el('span', { 'class': 'doc-cov doc-cov-trust', text: String(c.source) })); }
    if (c.tenant) { meta.appendChild(el('span', { 'class': 'ctl-desc', text: 'tenant · ' + c.tenant })); }
    if (c.rank != null) { meta.appendChild(el('span', { 'class': 'ctl-desc', text: '#' + c.rank })); }
    if (meta.childNodes.length) { card.appendChild(meta); }
    if (demo) { card.appendChild(demoChip(true)); }
    return card;
  }

  // =======================================================================
  //  Site map — a static reference destination: the console's flat rail
  //  rearranged into 5 destinations + System. Bespoke card grid (no sections
  //  model). Reads nothing; renders in every posture. Ported from the unified-
  //  shell concept (rev 1 · 2026-07-03).
  // =======================================================================
  var SITEMAP_ICONS = {
    radar: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 12l6-6"/></svg>',
    board: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="5" height="16" rx="1"/><rect x="10" y="4" width="5" height="10" rx="1"/><rect x="17" y="4" width="4" height="13" rx="1"/></svg>',
    brain: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="5" width="16" height="4.5" rx="2"/><rect x="4" y="12" width="16" height="4.5" rx="2"/><path d="M11 19.5h6"/></svg>',
    shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/><path d="M9 12l2 2 4-4"/></svg>',
    gauge: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 14a8 8 0 1 1 16 0"/><path d="M12 14l3.5-3.5"/><path d="M4 19h16"/></svg>',
    server: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3.5" y="4" width="17" height="6.5" rx="1.8"/><rect x="3.5" y="13.5" width="17" height="6.5" rx="1.8"/><path d="M7 7.2h.01M7 16.7h.01"/></svg>'
  };
  var SITEMAP = [
    { icon: 'radar', color: 'var(--acc)', title: 'Overwatch', tag: "the arm's-length home — glance, decide, get out", items: [
      { name: 'Home · Needs you', anno: { t: 'PROMOTED', cls: 'promote' }, why: 'Gates rise from rail item #8 to the first thing you see. Review counts and blocked-plan questions surface here too.', provs: [{ t: 'cx-overview' }, { t: 'cx-gates (actionable)' }, { t: 'cx-review (count)' }] },
      { name: 'Fleet', anno: { t: '4 → 1', cls: 'merge' }, why: "Live board, sessions, orchestrators and punchcards are four rail items describing one question — \"who is working and on what?\" Leases and intents become facets of a session row.", provs: [{ t: 'cx-coord' }, { t: 'cx-sessions (live)' }, { t: 'cx-orchestrators' }, { t: 'cx-punchcards' }] },
      { name: 'Activity', why: 'The rolling all-sessions log, unchanged — plus the human-lane page folds in as a filter, not a separate URL.', provs: [{ t: 'cx-activity' }, { t: '/console/activity' }] }
    ] },
    { icon: 'board', color: '#5EC2E7', title: 'Work', tag: "plans are true north — resume, don't respawn", items: [
      { name: 'Board', anno: { t: 'VIEW SWITCH', cls: 'vsw' }, why: 'Kanban graduates from a rail pull-out to the primary view; list and graph become a segmented switch on the page — the DUAL_VIEW pattern, made explicit.', provs: [{ t: 'cx-work' }, { t: 'kanban pull-out' }, { t: 'console-3d (work graph)' }] },
      { name: 'Projects', why: 'Repo pairing, planning repo, working tenants — unchanged, but now feeds Board filters instead of standing alone.', provs: [{ t: 'cx-projects' }] },
      { name: 'Runs', why: 'Session history splits from the live fleet: archived sessions with their per-run token usage attached, searchable by plan.', provs: [{ t: 'cx-sessions (archive)' }, { t: 'cx-usage (per-run)' }] }
    ] },
    { icon: 'brain', color: 'var(--trust)', title: 'Memory', tag: 'the substrate — what the node knows and how fresh it is', items: [
      { name: 'Facts', anno: { t: '2 → 1', cls: 'merge' }, why: 'cx-facts (by entity prefix) and cx-memory (recent per tenant) are the same data with different lenses — one page, three lenses: by entity · recent · by tenant.', provs: [{ t: 'cx-facts' }, { t: 'cx-memory' }] },
      { name: 'Tenants & lanes', why: 'Store list with AMR lane policy per tenant; system tenants stay hidden by default.', provs: [{ t: 'cx-tenants' }] },
      { name: 'Documents · ingest', why: 'What the daemon has read, per tenant — and how to feed it more. Unchanged.', provs: [{ t: 'cx-documents' }] },
      { name: 'Review', anno: { t: 'COUNT → HOME', cls: 'promote' }, why: 'Contradictions + guarded consolidation live here; the pending count is an Overwatch card because it needs human judgment.', provs: [{ t: 'cx-review' }] },
      { name: 'Tuning', anno: { t: 'ADVANCED', cls: 'adv' }, why: 'RRF lane weights are expert controls — kept, but behind a disclosure so they stop competing with daily pages.', provs: [{ t: 'cx-lane-weights' }] }
    ] },
    { icon: 'shield', color: 'var(--ok)', title: 'Trust', tag: 'regulation is a destination, not a settings page', items: [
      { name: 'Receipts', anno: { t: 'VIEW SWITCH', cls: 'vsw' }, why: 'CROWN receipt list with the graph pull-out as a view switch; the receipts-vs-console demo becomes the "why receipts" explainer here.', provs: [{ t: 'cx-receipts' }, { t: '/console/receipts-vs-console' }] },
      { name: 'Gates', why: 'The full Art.14 queue + history + timeout policy. Overwatch shows the actionable slice; this is the canonical record.', provs: [{ t: 'cx-gates' }] },
      { name: 'Identity', anno: { t: '2 → 1', cls: 'merge' }, why: 'Passports and identity-link ceremonies are one story: who exists, who signs, what links. Device grants (/activate) approve from here too.', provs: [{ t: 'cx-passport' }, { t: 'cx-identity' }, { t: '/activate' }] },
      { name: 'Policy & posture', anno: { t: 'NEW', cls: 'new' }, why: 'Mediation (capability ladder, foresight) joins a compliance posture panel — the Art.10–15 cards from this concept. Today that story is implicit; regulated buyers need it on one page.', provs: [{ t: 'cx-mediation' }, { t: 'posture panel (new)', 'new': true }] }
    ] },
    { icon: 'gauge', color: 'var(--warn)', title: 'Meters', tag: 'cost, capacity, evidence — replaces "Benchmarks" as the 5th section', items: [
      { name: 'Token burn', why: 'The ground-truth cost lens, unchanged — headline number surfaces as an Overwatch tile.', provs: [{ t: 'cx-cost' }] },
      { name: 'Usage', why: 'Observation-derived usage aggregates; per-run slices move to Work → Runs.', provs: [{ t: 'cx-usage' }] },
      { name: 'Storage & node', anno: { t: 'UNBURIED', cls: 'promote' }, why: "Storage breakdown, infra summary, ops health and update/bootstrap status escape the Settings page — they're monitoring, not configuration.", provs: [{ t: 'storage-breakdown' }, { t: 'infra/summary' }, { t: 'ops health' }] },
      { name: 'Benchmarks', anno: { t: 'NEW', cls: 'new' }, why: 'bench:* facts get a real page — corpus identity, commit, lane flags — with deep links to scorecrux.com for published suites.', provs: [{ t: 'bench:* facts' }, { t: 'ScoreCrux links', 'new': true }] }
    ] },
    { icon: 'server', color: 'var(--ink3)', title: 'System', note: 'bottom of rail', tag: 'configure rarely, then leave', items: [
      { name: 'Settings', why: 'Access posture, embedding endpoint, sync, freshness horizons, retention, appearance, coordination toggles — minus the monitoring sections that moved to Meters.', provs: [{ t: 'cx-settings' }] },
      { name: 'Integrations', anno: { t: '2 → 1', cls: 'merge' }, why: 'Packs and signed extensions are one catalog with two provenance badges; install stays inert until a passport grant exists.', provs: [{ t: 'cx-integrations' }, { t: 'cx-extensions' }] },
      { name: 'Developer', why: 'Raw JSON-RPC console and the DX docs scope live under Developer; the GX global-search scope becomes ⌘K everywhere.', provs: [{ t: 'cx-raw' }, { t: 'DX scope' }, { t: 'GX scope → ⌘K' }] }
    ] }
  ];
  function renderSiteMap(host) {
    host.textContent = '';
    var grid = el('div', { 'class': 'map-grid' });
    SITEMAP.forEach(function (s) {
      var sec = el('div', { 'class': 'map-sec' });
      sec.style.setProperty('--sec-c', s.color);
      var ico = el('span', { 'class': 'map-ico' }); ico.innerHTML = SITEMAP_ICONS[s.icon] || '';
      var icoSvg = ico.querySelector('svg'); if (icoSvg) { icoSvg.setAttribute('width', '16'); icoSvg.setAttribute('height', '16'); }
      var h = el('h3', null, [ico, doc().createTextNode(s.title)]);
      if (s.note) { h.appendChild(el('span', { 'class': 'map-h-note', text: ' · ' + s.note })); }
      sec.appendChild(h);
      sec.appendChild(el('div', { 'class': 'tag', text: s.tag }));
      s.items.forEach(function (it) {
        var b = el('b', null, [doc().createTextNode(it.name)]);
        if (it.anno) { b.appendChild(el('span', { 'class': 'anno ' + it.anno.cls, text: it.anno.t })); }
        var pg = el('div', { 'class': 'map-page' }, [b, el('div', { 'class': 'why', text: it.why })]);
        if (it.provs && it.provs.length) {
          var provs = el('div', { 'class': 'provs' });
          it.provs.forEach(function (pv) { provs.appendChild(el('span', { 'class': 'prov' + (pv['new'] ? ' new' : ''), text: pv.t })); });
          pg.appendChild(provs);
        }
        sec.appendChild(pg);
      });
      grid.appendChild(sec);
    });
    host.appendChild(grid);
    var note = el('div', { 'class': 'map-note' });
    note.innerHTML =
      '<b>The count:</b> today\'s console is 26 flat rail items in the CX scope plus 4 sibling scopes (DX · GX · AX · IX). This arrangement lands the same surface in <b>5 destinations + System</b> — 9 pages merge into 4, three buried things get promoted (gates, review, node health), two get built new (posture, benchmarks), and nothing is dropped. The 2D|3D substrate switch and the kanban/graph pull-outs survive as per-page view switches. Phone gets Overwatch · Work · Trust + More; Memory, Meters and System sit behind More because approving a gate at a bus stop is real and re-tuning lane weights is not.'
      + '<br><br><b>The function census behind this map:</b> Crux Daemon exposes 118 HTTP routes (~40 groups), 114 registered MCP tools (14 live at free tier — the console renders from the capability plan, not the registry), 98 corecruxctl subcommands; CruxEngine adds 295 paths on port 14343 + 164 on 14344. ≈789 functions total, each assigned a destination in <span class="mono">PlanCrux/docs/architecture/function-map-daemon-engine-2026-07-03.md</span>. Engine functions reach this UI only through daemon-mediated proxy routes (the lane-weights / gpu1 precedent) — one origin, one passport, receipts on every cross-system mutation.';
    host.appendChild(note);
  }

  function renderExplorer(host, ctx) {
    ctx = ctx || {};
    host.textContent = '';
    // Starts vertically centred (empty state); un-centres once results render.
    var region = el('div', { 'class': 'explorer-region explorer-empty' });
    host.appendChild(region);
    // Local carries a token_budget; WikiCrux carries a top_k (Engine limit ≤50).
    var state = { backend: 'local', query: '', budget: 1500, topk: 8 };

    var controls = el('div', { 'class': 'explorer-controls' });
    var searchRow = el('div', { 'class': 'explorer-search' });
    var input = el('input', { 'class': 'explorer-input', type: 'search', placeholder: 'Search the corpus…', 'aria-label': 'Search query' });
    searchRow.appendChild(input);
    var toggle = el('div', { 'class': 'explorer-toggle', role: 'group', 'aria-label': 'Search backend' });
    var toggleBtns = {};
    EXPLORER_BACKENDS.forEach(function (b) {
      var btn = el('button', { 'class': 'btn-quiet', type: 'button', 'data-backend': b.id, 'aria-pressed': b.id === state.backend ? 'true' : 'false', text: b.label });
      btn.addEventListener('click', function () {
        if (state.backend === b.id) { return; }
        state.backend = b.id; syncToggle(); relabelBudget();
        if (state.query.trim()) { doSearch(); }
      });
      toggle.appendChild(btn); toggleBtns[b.id] = btn;
    });
    searchRow.appendChild(toggle);
    controls.appendChild(searchRow);

    var budgetRow = el('label', { 'class': 'explorer-budget' });
    var budgetLabel = el('span', { text: 'token budget' });
    var budgetInput = el('input', { type: 'number', min: '1', value: String(state.budget), 'aria-label': 'result budget' });
    budgetRow.appendChild(budgetLabel); budgetRow.appendChild(budgetInput);
    controls.appendChild(budgetRow);
    region.appendChild(controls);

    var results = el('div', { 'class': 'explorer-results' });
    region.appendChild(results);
    results.appendChild(el('p', { 'class': 'ctl-desc', text: 'Type a query to search the corpus.' }));

    function syncToggle() { EXPLORER_BACKENDS.forEach(function (b) { toggleBtns[b.id].setAttribute('aria-pressed', b.id === state.backend ? 'true' : 'false'); }); }
    function relabelBudget() {
      if (state.backend === 'local') { budgetLabel.textContent = 'token budget'; budgetInput.value = String(state.budget); }
      else { budgetLabel.textContent = 'top_k'; budgetInput.value = String(state.topk); }
    }
    input.addEventListener('input', function () { state.query = input.value; scheduleSearch(); });
    budgetInput.addEventListener('input', function () {
      var n = parseInt(budgetInput.value, 10);
      if (!isFinite(n) || n < 1) { return; }
      if (state.backend === 'local') { state.budget = n; } else { state.topk = Math.min(50, n); }
      if (state.query.trim()) { scheduleSearch(); }
    });

    var debTimer = null;
    function scheduleSearch() { if (debTimer) { clearTimeout(debTimer); } debTimer = setTimeout(doSearch, 250); }

    function maybeDemo() {
      if (!demoOn()) { return; }
      var sample = demoData('explorer');
      if (!sample || !sample.length) { return; }
      results.appendChild(docSection('Sample results'));
      sample.forEach(function (c) { results.appendChild(explorerCard(c, true, showDetail)); });
    }
    // Result detail — clicking a result opens it on its own "page". Facts /
    // execplans / sessions come from the daemon (Command side); articles / living
    // objects / Proof are Crux Engine (Engine side) — that richer sourcing lands
    // with the Ask surface wiring.
    function resetEmpty() {
      results.textContent = '';
      results.appendChild(el('p', { 'class': 'ctl-desc', text: 'Type a query to search the corpus.' }));
      region.classList.add('explorer-empty');
    }
    function showDetail(c) {
      region.classList.remove('explorer-empty');
      results.textContent = '';
      var back = el('button', { 'class': 'btn-quiet explorer-back', type: 'button' }, ['← Back to results']);
      back.addEventListener('click', function () { if (state.query.trim()) { doSearch(); } else { resetEmpty(); } });
      var head = el('div', { 'class': 'explorer-detail-head' }, [el('h2', { text: String(c.title) })]);
      if (typeof c.score === 'number' && isFinite(c.score)) { head.appendChild(el('span', { 'class': 'doc-cov doc-cov-' + explorerScoreTone(c.score), text: c.score.toFixed(2) })); }
      var detail = el('article', { 'class': 'explorer-detail' }, [back, head]);
      var meta = el('div', { 'class': 'explorer-card-meta' });
      if (c.source) { meta.appendChild(el('span', { 'class': 'doc-cov doc-cov-trust', text: String(c.source) })); }
      if (c.tenant) { meta.appendChild(el('span', { 'class': 'ctl-desc', text: 'tenant · ' + c.tenant })); }
      if (c.rank != null) { meta.appendChild(el('span', { 'class': 'ctl-desc', text: '#' + c.rank })); }
      if (meta.childNodes.length) { detail.appendChild(meta); }
      detail.appendChild(el('p', { 'class': 'explorer-detail-body', text: String(c.snippet || c.text || 'No further detail on this result yet.') }));
      detail.appendChild(el('p', { 'class': 'ctl-desc', text: 'Full detail is sourced from the Crux Engine (Ask surface) — wiring in progress.' }));
      results.appendChild(detail);
    }
    function paintResults(res, mapper) {
      region.classList.remove('explorer-empty');   // a search ran — dock to the top
      results.textContent = '';
      if (res.status === 404) {
        results.appendChild(el('p', { 'class': 'ctl-desc', text: state.backend === 'wikicrux' ? 'WikiCrux search unavailable — engine mediation off.' : 'Search unavailable — feature off.' }));
        maybeDemo(); return;
      }
      if (!res.ok || !res.data) {
        results.appendChild(el('p', { 'class': 'ctl-desc', text: 'Search unavailable — ' + (res.status === 0 ? 'backend unreachable' : 'HTTP ' + res.status) + '.' }));
        maybeDemo(); return;
      }
      var cards = mapper(res.data);
      if (!cards.length) { results.appendChild(el('p', { 'class': 'ctl-desc', text: 'No results for “' + state.query.trim() + '”.' })); return; }
      cards.forEach(function (c) { results.appendChild(explorerCard(c, false, showDetail)); });
    }
    function doSearch() {
      var q = state.query.trim();
      if (!q) { results.textContent = ''; results.appendChild(el('p', { 'class': 'ctl-desc', text: 'Type a query to search the corpus.' })); return; }
      results.textContent = '';
      results.appendChild(el('p', { 'class': 'ctl-desc', text: 'Searching…' }));
      if (state.backend === 'local') {
        readPost('queryTextSearch', { query: q, token_budget: state.budget, tenant_id: 'default' }).then(function (res) { paintResults(res, explorerLocalCards); });
      } else {
        readPost('engineSearch', { query: q, top_k: state.topk }).then(function (res) { paintResults(res, explorerEngineCards); });
      }
    }
    // Carry a query typed into the top-right search field straight into a search.
    var pending = (typeof window !== 'undefined' && window.CRUX_PENDING_QUERY) || '';
    if (pending) {
      if (typeof window !== 'undefined') { window.CRUX_PENDING_QUERY = ''; }
      input.value = pending; state.query = pending;
      region.classList.remove('explorer-empty');
      doSearch();
    }
    // Expose the imperative handle for tests / deep integration (no auto-search).
    return { search: doSearch, state: state };
  }

  return {
    CONTROL_TYPES: CONTROL_TYPES,
    GATE_TITLE: GATE_TITLE,
    // M11 — Explorer (corpus search; reads only, posture-independent).
    renderExplorer: renderExplorer,
    // Site map — static reference destination (rail → destinations map).
    renderSiteMap: renderSiteMap,
    // M10 — Documents mode (the console-as-reader).
    renderDocuments: renderDocuments,
    DOC_REFERENCE: DOC_REFERENCE,
    // M12 — the 11 ported JSX surfaces (Documents-mode surface list).
    DOC_SURFACES: DOC_SURFACES,
    renderDocSurface: renderDocSurface,
    // M9 — Canvas: size-adaptive board + real-edge relation graph.
    canvasTier: canvasTier,
    parseFocus: parseFocus,
    CANVAS_WIDGETS: CANVAS_WIDGETS,
    buildGraphModel: buildGraphModel,
    renderCanvas: renderCanvas,
    renderPage: renderPage,
    renderSections: renderSections,
    fetchJSON: fetchJSON,
    // M8 — presentation mode helper (never gates posture; see proMode()).
    proMode: proMode,
    // exposed so the shell can re-run the gate after a posture change
    isOperator: isOperator,
    // M3 — posture derivation (pure; unit-tested by the smoke) + the Overwatch
    // landing entry point + the gated-mutation helpers (all funnel through the
    // single operatorGatedCall choke point).
    derivePosture: derivePosture,
    renderOverwatchLanding: renderOverwatchLanding,
    boundPassport: boundPassport,
    approveGate: approveGate,
    rejectGate: rejectGate,
    commentWork: commentWork,
    enrichAction: enrichAction,
    // M13b — the live-write registry (exposed so the smoke can audit the harness:
    // every entry fires through operatorGatedCall; the destructive subset carries
    // a confirm). The runtime never reaches the gated write client except via these + the
    // operator helpers above, all funnelling through operatorGatedCall.
    WIRED_WRITES: WIRED_WRITES
  };
});
