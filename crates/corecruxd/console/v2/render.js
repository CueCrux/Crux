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
  var CONTROL_TYPES = ['search', 'input', 'textarea', 'select', 'toggle', 'btn', 'info', 'exp', 'approver', 'mintcard', 'rpcout', 'bar', 'theme', 'chart', 'disclose', 'repogrid', 'wbread'];
  var GATE_TITLE = 'wired in M3+';
  var RUNTIME_CAPABILITY_PRESENTATION = Object.freeze([
    Object.freeze(['append', 'Dataplane append']),
    Object.freeze(['local_embedders', 'Local embedders']),
    Object.freeze(['embedding_delegation', 'Embedding delegation']),
    Object.freeze(['rerank_gpu', 'GPU rerank']),
    Object.freeze(['hosted_sync', 'Hosted sync']),
    Object.freeze(['projection_queries', 'Projection queries']),
    Object.freeze(['graph_expand', 'Graph expansion']),
    Object.freeze(['console_link_graph', 'Link graph (CoreCrux proxy)'])
  ]);

  // ---- Environment shims (only used when rendering in a browser) ---------
  function doc() { return (typeof document !== 'undefined') ? document : null; }
  function posture() { return (typeof window !== 'undefined' && window.CRUX_POSTURE) || 'customer'; }
  function isOperator() { return posture() === 'operator'; }

  function runtimeCapabilityDescriptor() {
    return (typeof window !== 'undefined' && window.CRUX_RUNTIME_CAPABILITIES) || null;
  }

  function controlCapabilityMap() {
    var pages = (typeof window !== 'undefined') ? window.CruxPages : null;
    return (pages && pages.CONTROL_CAPABILITY_MAP) || {};
  }

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

  function storeBoundPassport(passportId) {
    var id = String(passportId || '').trim();
    if (!id) { return false; }
    try { localStorage.setItem('crux-console-bound-passport', id); return true; }
    catch (e) { return false; }
  }

  function removeBoundPassport() {
    try { localStorage.removeItem('crux-console-bound-passport'); return true; }
    catch (e) { return false; }
  }

  // Public gated helpers. Each resolves to the raw fetch Response so callers
  // can read the REAL backend body (no fabricated fields).
  function approveGate(actionId, approverPassport) {
    return operatorGatedCall(function (g) { return g.gateApprove(actionId, { approver_passport: approverPassport }); });
  }
  function rejectGate(actionId, approverPassport) {
    return operatorGatedCall(function (g) { return g.gateReject(actionId, { approver_passport: approverPassport }); });
  }
  function approveMintRequest(requestId, approverPassport, category, name) {
    return operatorGatedCall(function (g) {
      return g.passportMintRequestApprove(requestId, {
        approver_passport: approverPassport,
        category: category,
        name: name
      });
    });
  }
  function rejectMintRequest(requestId, approverPassport) {
    return operatorGatedCall(function (g) {
      return g.passportMintRequestReject(requestId, { approver_passport: approverPassport });
    });
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
    // Split a query-bearing path into (base, query): CruxApi.get allowlists the
    // BASE path and re-applies the query via withQuery. Passing the whole
    // "path?query" string would miss the allowlist → reject → false-empty (the
    // /v1/work?source=all + cx-facts/cost/review/memory bug). Base paths are all
    // in the manifest allowlist, so this heals every query-bearing read at once.
    var qi = url.indexOf('?'), base = url, query = null;
    if (qi >= 0) {
      base = url.slice(0, qi); query = {};
      new URLSearchParams(url.slice(qi + 1)).forEach(function (v, k) { query[k] = v; });
    }
    return api.get(base, query)
      .then(function (r) {
        return r.json().then(
          function (data) { return { ok: r.ok, status: r.status, data: data }; },
          function () { return { ok: r.ok, status: r.status, data: null }; }
        );
      })
      .catch(function () { return { ok: false, status: 0, data: null }; });
  }

  // Wrap any CruxApi NAMED-method call (parameterised reads — e.g. activity(query),
  // the projection artifact endpoints) into the same {ok,status,data} envelope as
  // fetchJSON. Named methods are how the console reaches routes that carry a query
  // (CruxApi.get only accepts literal, query-less allowlist paths). render.js keeps
  // zero raw fetches of its own — the network layer lives in api.js.
  function fetchVia(invoke) {
    if (typeof invoke !== 'function') { return Promise.resolve({ ok: false, status: 0, data: null }); }
    var p;
    try { p = invoke(); } catch (e) { return Promise.resolve({ ok: false, status: 0, data: null }); }
    if (!p || typeof p.then !== 'function') { return Promise.resolve({ ok: false, status: 0, data: null }); }
    return p.then(function (r) {
      return r.json().then(
        function (data) { return { ok: r.ok, status: r.status, data: data }; },
        function () { return { ok: r.ok, status: r.status, data: null }; }
      );
    }).catch(function () { return { ok: false, status: 0, data: null }; });
  }

  // /v1/activity is a parameterised read — reach it via CruxApi.activity(query),
  // never fetchJSON (a query string is not a literal allowlist path, so get()
  // rejects it). Used by the Watch + Receipt-Diff change feeds.
  function activityRows(query) {
    var api = (typeof window !== 'undefined') ? window.CruxApi : null;
    return fetchVia(api && typeof api.activity === 'function' ? function () { return api.activity(query); } : null);
  }

  // Call a parameterised {id}-path CruxApi method (e.g. the living-object
  // projection reads adminProjectionsArtifactsByArtifactId{State,Dependents,
  // Relations,PressureEvents}) → {ok,status,data}. Dataplane-gated on the daemon,
  // so callers must handle a 501 "dataplane disabled" by degrading honestly.
  function projCall(method, id, query) {
    var api = (typeof window !== 'undefined') ? window.CruxApi : null;
    return fetchVia(api && typeof api[method] === 'function' ? function () { return api[method](id, query); } : null);
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

  // A mapped control is usable only when /v1/version explicitly declares its
  // capability available. Missing, newer, or incomplete descriptors fail
  // closed. This layer only disables; posture and the gated mutation client
  // remain the authority for whether an enabled write may run.
  function runtimeCapabilityState(capabilityName, descriptor) {
    var state = {
      capability: capabilityName, availability: 'unknown', disabled: true,
      reasonCode: '', reason: ''
    };
    if (!descriptor || descriptor.schema_version !== 1 || !descriptor.capabilities) {
      state.reasonCode = 'descriptor_unavailable';
      state.reason = 'Capability status is unavailable for this daemon.';
      return state;
    }
    var capability = descriptor.capabilities[capabilityName];
    if (!capability) {
      state.reasonCode = 'capability_undeclared';
      state.reason = 'This daemon did not declare the required capability.';
      return state;
    }
    var availabilityValid = capability.availability === 'available' || capability.availability === 'unavailable' || capability.availability === 'degraded';
    var reasonsValid = typeof capability.reason_code === 'string' && capability.reason_code.length > 0
      && typeof capability.reason === 'string' && capability.reason.length > 0;
    var stagesValid = ['compiled', 'configured', 'initialized', 'entitled', 'degraded'].every(function (stage) {
      return typeof capability[stage] === 'boolean';
    });
    var availableStateValid = capability.availability !== 'available' || !capability.degraded;
    var degradedStateValid = capability.availability !== 'degraded' || capability.degraded;
    if (!availabilityValid || !reasonsValid || !stagesValid || !availableStateValid || !degradedStateValid) {
      state.reasonCode = 'capability_descriptor_invalid';
      state.reason = 'This daemon returned an incomplete capability status.';
      return state;
    }
    state.availability = capability.availability;
    state.reasonCode = capability.reason_code;
    state.reason = capability.reason;
    if (capability.availability === 'available') {
      state.disabled = false;
      return state;
    }
    return state;
  }

  function capabilityStateForControl(controlId, descriptor, map) {
    var spec = (map || {})[controlId];
    return spec ? runtimeCapabilityState(spec.capability, descriptor) : null;
  }

  // Does the daemon's runtime capability PLAN grant a capability by name? The
  // unified shell gates capability-scoped DESTINATIONS on this (render from the
  // plan, never the route registry) — e.g. the Link graph pane only appears when
  // the daemon reports console_link_graph 'available' (its mediation proxy is
  // configured). Fails closed: an absent/invalid descriptor ⇒ not available.
  function capabilityAvailable(name) {
    return runtimeCapabilityState(name, runtimeCapabilityDescriptor()).availability === 'available';
  }

  function runtimeCapabilitySection(descriptor) {
    return {
      h: 'Runtime capabilities', wide: true,
      controls: RUNTIME_CAPABILITY_PRESENTATION.map(function (entry) {
        var state = runtimeCapabilityState(entry[0], descriptor);
        return {
          t: 'info', label: entry[1], capability: state.capability,
          availability: state.availability, reasonCode: state.reasonCode,
          reason: state.reason,
          v: state.availability + ' — ' + state.reason
        };
      })
    };
  }

  function withRuntimeCapabilitySection(page, sections) {
    if (!page || page.id !== 'cx-settings') { return sections; }
    return [runtimeCapabilitySection(runtimeCapabilityDescriptor())].concat(sections || []);
  }

  function applyCapabilityGate(node, controlId, descriptor, map) {
    if (!node || !controlId) { return node; }
    if (arguments.length < 3) { descriptor = runtimeCapabilityDescriptor(); }
    if (arguments.length < 4) { map = controlCapabilityMap(); }
    var state = capabilityStateForControl(controlId, descriptor, map);
    if (!state) { return node; }
    node.setAttribute('data-capability', state.capability);
    node.setAttribute('data-capability-availability', state.availability);
    if (!state.disabled) { return node; }

    node.setAttribute('data-capability-reason', state.reasonCode);
    node.setAttribute('aria-disabled', 'true');
    node.setAttribute('title', state.reason);
    node.classList.add('is-capability-disabled');
    var reasonId = 'capability-reason-' + String(controlId).replace(/[^a-z0-9_-]+/gi, '-');
    var targets = node.querySelectorAll('input, select, textarea, button');
    for (var i = 0; i < targets.length; i++) {
      targets[i].disabled = true;
      targets[i].setAttribute('aria-disabled', 'true');
      targets[i].setAttribute('title', state.reason);
      var describedBy = targets[i].getAttribute('aria-describedby') || '';
      if ((' ' + describedBy + ' ').indexOf(' ' + reasonId + ' ') < 0) {
        targets[i].setAttribute('aria-describedby', (describedBy ? describedBy + ' ' : '') + reasonId);
      }
    }
    var reason = node.querySelector('.capability-reason');
    if (!reason) {
      reason = el('p', { id: reasonId, 'class': 'ctl-desc capability-reason' });
      node.appendChild(reason);
    }
    reason.textContent = (state.availability === 'degraded' ? 'Degraded' : 'Unavailable') + ' — ' + state.reason;
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

  function mintProblem(action, r) {
    var data = (r && r.data) || {};
    var detail = data.detail || data.error || data.message;
    return action + ' failed · HTTP ' + (r ? r.status : 0) + (detail ? ' · ' + detail : '');
  }

  function refreshMintPanel(sectionCard, flash) {
    return fetchJSON('/v1/passport/mint-requests/pending').then(function (res) {
      var pages = (typeof window !== 'undefined') ? window.CruxPages : null;
      var page = pages && pages.PAGES && pages.PAGES['cx-mints'];
      var sections = page && page.load && typeof page.load.build === 'function' ? page.load.build(res) : [];
      if (flash && sections[0]) {
        var controls = sections[0].controls || [];
        var insertAt = controls[0] && controls[0].t === 'approver' ? 1 : 0;
        controls.splice(insertAt, 0, { t: 'info', label: 'last decision', v: flash });
        sections[0].controls = controls;
      }
      var grid = sectionCard && sectionCard.parentNode;
      var container = grid && grid.parentNode;
      if (container && sections.length) { renderSections(container, withRuntimeCapabilitySection(page, sections)); }
      return res;
    });
  }

  function passportPickerLabel(passport) {
    var bits = [String(passport.id)];
    if (passport.category) { bits.push(String(passport.category)); }
    if (passport.reputation_tier) { bits.push(String(passport.reputation_tier)); }
    return bits.join(' · ');
  }

  function renderBoundApproverControl(sectionCard) {
    var current = boundPassport();
    var details = el('details', { 'class': 'exp', open: 'open', 'data-bound-approver-control': 'true' });
    details.appendChild(el('summary', { 'class': 'exp-sum' }, [
      el('span', { 'class': 'exp-label', text: 'Bound approver' }),
      el('span', { 'class': 'exp-sub', text: 'Shared attribution identity for operator approvals' }),
      el('span', { 'class': 'exp-badge', text: current ? 'bound' : 'unbound' })
    ]));

    var body = el('div', { 'class': 'exp-body' });
    body.appendChild(el('div', { 'class': 'ctl-info' }, [
      el('span', { 'class': 'ctl-info-k', text: 'current approver' }),
      el('span', {
        'class': 'ctl-info-v',
        'data-bound-approver-current': 'true',
        text: current || 'No approver bound — bind one to accept/reject (Art.14)'
      })
    ]));

    var pickerId = 'bound-approver-passport';
    var pickerRow = el('div', { 'class': 'ctl-row' });
    pickerRow.appendChild(el('label', { 'class': 'ctl-label', 'for': pickerId, text: 'Approver passport' }));
    var pickerHost = el('div', { 'data-bound-approver-picker-host': 'true' }, [
      el('p', { 'class': 'ctl-desc', text: 'Loading passports…' })
    ]);
    pickerRow.appendChild(pickerHost);
    pickerRow.appendChild(el('p', {
      'class': 'ctl-desc',
      text: 'This shared binding is used by mint and work-gate approve/reject actions.'
    }));
    body.appendChild(pickerRow);

    var bind = el('button', { 'class': 'btn-primary', type: 'button', disabled: 'disabled', 'data-bound-approver-action': 'bind' }, ['Bind']);
    var clear = el('button', { 'class': 'btn-quiet danger', type: 'button', 'data-bound-approver-action': 'clear' }, ['Clear']);
    clear.disabled = !current;
    var status = el('p', { 'class': 'ow-status', role: 'status', 'aria-live': 'polite', 'data-bound-approver-status': 'true' });
    body.appendChild(el('div', { 'class': 'ow-actions' }, [bind, clear]));
    body.appendChild(status);
    details.appendChild(body);
    stampOperatorOnly(details);

    var picker = null;
    function installPicker(res) {
      var passports = res && res.ok && res.data && Array.isArray(res.data.passports)
        ? res.data.passports.filter(function (p) { return p && String(p.id || '').trim(); })
        : [];
      pickerHost.textContent = '';
      if (passports.length) {
        picker = el('select', {
          'class': 'ctl-input ctl-select', id: pickerId, 'data-bound-approver-picker': 'select',
          'aria-label': 'Approver passport'
        });
        var choose = el('option', { value: '', text: 'Choose approver passport…' });
        if (!passports.some(function (p) { return String(p.id).trim() === current; })) {
          choose.setAttribute('selected', 'selected');
        }
        picker.appendChild(choose);
        passports.forEach(function (passport) {
          var id = String(passport.id).trim();
          var option = el('option', { value: id, text: passportPickerLabel(passport) });
          if (id === current) { option.setAttribute('selected', 'selected'); }
          picker.appendChild(option);
        });
        picker.value = passports.some(function (p) { return String(p.id).trim() === current; }) ? current : '';
      } else {
        picker = el('input', {
          'class': 'ctl-input mono', id: pickerId, type: 'text', value: current,
          placeholder: 'Enter passport id', autocomplete: 'off',
          'data-bound-approver-picker': 'text', 'aria-label': 'Approver passport id'
        });
        picker.value = current;
        status.textContent = res && res.ok
          ? 'No passports returned — enter an approver passport id manually.'
          : 'Passport list unavailable — enter an approver passport id manually.';
      }
      pickerHost.appendChild(picker);
      bind.disabled = false;
      return picker;
    }

    details.cruxReady = fetchJSON('/v1/passports').then(installPicker);

    bind.addEventListener('click', function () {
      var chosen = picker && String(picker.value || '').trim();
      if (!chosen) { status.textContent = 'Choose or enter an approver passport id before binding.'; if (picker) { picker.focus(); } return Promise.resolve(); }
      if (!storeBoundPassport(chosen)) { status.textContent = 'Could not save the approver binding in local storage.'; return Promise.resolve(); }
      bind.disabled = true; clear.disabled = true;
      status.textContent = 'Bound ' + chosen + ' · refreshing…';
      return refreshMintPanel(sectionCard).then(function (res) {
        if (!res.ok) { status.textContent = 'Bound ' + chosen + ' · panel refresh unavailable (HTTP ' + res.status + ').'; bind.disabled = false; clear.disabled = false; }
        return res;
      });
    });

    clear.addEventListener('click', function () {
      if (!removeBoundPassport()) { status.textContent = 'Could not clear the approver binding from local storage.'; return Promise.resolve(); }
      bind.disabled = true; clear.disabled = true;
      status.textContent = 'Approver cleared · refreshing…';
      return refreshMintPanel(sectionCard).then(function (res) {
        if (!res.ok) { status.textContent = 'Approver cleared · panel refresh unavailable (HTTP ' + res.status + ').'; bind.disabled = false; }
        return res;
      });
    });
    return details;
  }

  function renderMintRequestCard(control, sectionCard) {
    var request = control.request || {};
    var requestId = String(request.request_id || '');
    var domId = requestId.replace(/[^a-zA-Z0-9_-]/g, '-') || 'unknown';
    var requestedCategory = control.category || '';
    var details = el('details', { 'class': 'exp', open: 'open', 'data-mint-request-id': requestId });
    details.appendChild(el('summary', { 'class': 'exp-sum' }, [
      el('span', { 'class': 'exp-label', text: request.requester_id || 'unknown requester' }),
      el('span', { 'class': 'exp-sub', text: (control.age || 'age unknown') + ' · requested by ' + (request.requested_by_passport || '?') }),
      el('span', { 'class': 'exp-badge', text: requestedCategory || 'category required' })
    ]));
    var body = el('div', { 'class': 'exp-body' });
    body.appendChild(el('div', { 'class': 'ctl-info' }, [
      el('span', { 'class': 'ctl-info-k', text: 'reason' }),
      el('span', { 'class': 'ctl-info-v', text: request.reason || '—' })
    ]));
    body.appendChild(el('div', { 'class': 'ctl-info' }, [
      el('span', { 'class': 'ctl-info-k', text: 'requested category' }),
      el('span', { 'class': 'ctl-info-v', text: request.requested_category || 'not supplied' })
    ]));

    var categoryId = 'mint-category-' + domId;
    var category = el('select', { 'class': 'ctl-input ctl-select', id: categoryId, 'data-mint-field': 'category' });
    [
      { value: '', label: 'Choose category…' },
      { value: 'personal', label: 'personal' },
      { value: 'work', label: 'work' },
      { value: 'public', label: 'public' }
    ].forEach(function (entry) {
      var option = el('option', { value: entry.value, text: entry.label });
      if (entry.value === requestedCategory) { option.setAttribute('selected', 'selected'); }
      category.appendChild(option);
    });
    category.value = requestedCategory;
    body.appendChild(el('div', { 'class': 'ctl-row' }, [
      el('label', { 'class': 'ctl-label', 'for': categoryId, text: 'Category' }), category,
      el('p', { 'class': 'ctl-desc', text: requestedCategory ? 'Pre-filled from the agent request; change it before accepting if needed.' : 'Required — choose the passport category before accepting.' })
    ]));

    var nameId = 'mint-name-' + domId;
    var name = el('input', { 'class': 'ctl-input', id: nameId, type: 'text', value: '', placeholder: 'Optional display name', autocomplete: 'off', 'data-mint-field': 'name' });
    name.value = '';
    body.appendChild(el('div', { 'class': 'ctl-row' }, [
      el('label', { 'class': 'ctl-label', 'for': nameId, text: 'Name (optional)' }), name
    ]));

    var accept = el('button', { 'class': 'btn-primary', type: 'button', 'data-mint-action': 'accept' }, ['Accept']);
    var reject = el('button', { 'class': 'btn-quiet danger', type: 'button', 'data-mint-action': 'reject' }, ['Reject']);
    var status = el('p', { 'class': 'ow-status', role: 'status', 'aria-live': 'polite', 'data-mint-status': requestId });
    body.appendChild(el('div', { 'class': 'ow-actions' }, [accept, reject]));
    body.appendChild(status);
    details.appendChild(body);
    stampOperatorOnly(details);

    function lock(message) { accept.disabled = true; reject.disabled = true; status.textContent = message; }
    function unlock() { accept.disabled = false; reject.disabled = false; }
    accept.addEventListener('click', function () {
      var approver = boundPassport();
      var selected = (category.value || '').trim();
      if (!approver) { status.textContent = 'Bind a passport to accept — mint decisions must be attributed (Art. 14).'; return Promise.resolve(); }
      if (!selected) { status.textContent = 'Choose a category before accepting.'; category.focus(); return Promise.resolve(); }
      lock('Accepting…');
      return approveMintRequest(requestId, approver, selected, (name.value || '').trim()).then(readJson).then(function (r) {
        if (!r.ok) { status.textContent = mintProblem('Accept', r); unlock(); return r; }
        var mintedCategory = (r.data && r.data.category) || selected;
        status.textContent = 'Accepted · minted as ' + mintedCategory + ' · refreshing…';
        return refreshMintPanel(sectionCard, 'Accepted ' + request.requester_id + ' · minted as ' + mintedCategory);
      }).catch(function (e) { status.textContent = 'Accept failed · ' + (e && e.message || e); unlock(); });
    });
    reject.addEventListener('click', function () {
      var approver = boundPassport();
      if (!approver) { status.textContent = 'Bind a passport to reject — mint decisions must be attributed (Art. 14).'; return Promise.resolve(); }
      lock('Rejecting…');
      return rejectMintRequest(requestId, approver).then(readJson).then(function (r) {
        if (!r.ok) { status.textContent = mintProblem('Reject', r); unlock(); return r; }
        status.textContent = 'Rejected · refreshing…';
        return refreshMintPanel(sectionCard, 'Rejected ' + request.requester_id);
      }).catch(function (e) { status.textContent = 'Reject failed · ' + (e && e.message || e); unlock(); });
    });
    return details;
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
          var rows = sectionCard.querySelectorAll('.exp, .ctl-info, .cvx-kcard, .sess-card');
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
        if (control.capability) {
          node.classList.add('runtime-capability-status');
          node.setAttribute('data-capability', control.capability);
          node.setAttribute('data-capability-availability', control.availability || 'unknown');
          node.setAttribute('data-capability-reason', control.reasonCode || 'availability_unknown');
          node.setAttribute('title', control.reason || 'Capability status is unavailable.');
        }
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
      case 'kanban': {
        // ExecPlans as a clean board: columns keyed by work state; each card
        // carries a risk badge, execplan slug, bold title, a gradient progress
        // bar with its milestone count, the owner passport + a graph link.
        var board = el('div', { 'class': 'cvx-kanban' });
        (control.columns || []).forEach(function (col) {
          var cards = col.cards || [];
          var colEl = el('div', { 'class': 'cvx-kcol' });
          colEl.appendChild(el('div', { 'class': 'cvx-kcol-head' }, [
            el('span', { 'class': 'cvx-kcol-title', text: col.title }),
            el('span', { 'class': 'cvx-kcol-count', text: String(cards.length) })
          ]));
          var colBody = el('div', { 'class': 'cvx-kcol-body' });
          if (!cards.length) { colBody.appendChild(el('p', { 'class': 'cvx-kempty', text: 'none' })); }
          cards.forEach(function (c) {
            var kc = el('div', { 'class': 'cvx-kcard', 'data-strip': c.strip });
            var top = el('div', { 'class': 'cvx-kcard-top' });
            if (c.risk) { top.appendChild(el('span', { 'class': 'cvx-krisk risk-' + c.risk, text: c.risk })); }
            if (c.milestone) { top.appendChild(el('span', { 'class': 'cvx-kms', text: c.milestone })); }
            kc.appendChild(top);
            if (c.slug) { kc.appendChild(el('div', { 'class': 'cvx-kslug', text: c.slug })); }
            kc.appendChild(el('div', { 'class': 'cvx-ktitle', text: c.title }));
            if (c.prog != null) {
              var ktrack = el('div', { 'class': 'cvx-ktrack' }, [el('div', { 'class': 'cvx-kfill' })]);
              ktrack.firstChild.style.width = Math.max(0, Math.min(100, Number(c.pct) || 0)) + '%';
              kc.appendChild(el('div', { 'class': 'cvx-kprog' }, [ktrack, el('span', { 'class': 'cvx-kprogv', text: String(c.prog) })]));
            }
            var foot = el('div', { 'class': 'cvx-kcard-foot' });
            if (c.passport) { foot.appendChild(el('span', { 'class': 'cvx-kpass', text: c.passport })); }
            if (c.note) { foot.appendChild(el('span', { 'class': 'cvx-knote', text: c.note })); }
            if (c.graph && c.graph.href) { foot.appendChild(el('a', { 'class': 'btn-quiet cx-graphlink cvx-kgraph', href: c.graph.href, title: 'View in relation graph' }, ['graph'])); }
            if (foot.childNodes.length) { kc.appendChild(foot); }
            colBody.appendChild(kc);
          });
          colEl.appendChild(colBody);
          board.appendChild(colEl);
        });
        node = board;
        break;
      }
      case 'sesscard': {
        // A session as a rich, always-visible card: id + status, the execplan +
        // passport it carries, and two horizontal gradient bars (tokens · progress).
        var sc = el('div', { 'class': 'sess-card', 'data-strip': control.status === 'active' ? 'in_progress' : (control.status === 'archived' ? 'done' : 'planned') });
        sc.appendChild(el('div', { 'class': 'sess-card-head' }, [
          el('span', { 'class': 'sess-id', text: String(control.id) }),
          el('span', { 'class': 'exp-badge', text: String(control.status || 'session') })
        ]));
        var smeta = el('div', { 'class': 'sess-card-meta' });
        if (control.execplan) { smeta.appendChild(el('span', { 'class': 'sess-chip sess-chip-plan', text: control.execplan })); }
        if (control.passport) { smeta.appendChild(el('span', { 'class': 'sess-chip sess-chip-pass', text: control.passport })); }
        if (control.tenant) { smeta.appendChild(el('span', { 'class': 'sess-chip', text: control.tenant })); }
        if (smeta.childNodes.length) { sc.appendChild(smeta); }
        var sessBar = function (label, val, pct, cls) {
          var track = el('div', { 'class': 'ctl-bar-track' }, [el('div', { 'class': 'ctl-bar-fill ' + cls })]);
          track.firstChild.style.width = Math.max(0, Math.min(100, Number(pct) || 0)) + '%';
          return el('div', { 'class': 'ctl-bar sess-bar' }, [
            el('div', { 'class': 'ctl-bar-head' }, [el('span', { text: label }), el('span', { 'class': 'ctl-bar-val', text: String(val) })]),
            track
          ]);
        };
        if (control.tokLabel != null) { sc.appendChild(sessBar('token usage', control.tokLabel, control.tokPct, 'grad-tok')); }
        if (control.progLabel != null) { sc.appendChild(sessBar('progress', control.progLabel, control.progPct, 'grad-prog')); }
        var sfoot = el('div', { 'class': 'sess-card-foot' });
        if (control.turns != null) { sfoot.appendChild(el('span', { 'class': 'sess-foot-k', text: control.turns + ' turns' })); }
        if (control.updated) { sfoot.appendChild(el('span', { 'class': 'sess-foot-k', text: String(control.updated) })); }
        if (control.focusId) { sfoot.appendChild(el('a', { 'class': 'btn-quiet cx-graphlink', href: '#/canvas/graph?focus=session:' + control.focusId, title: 'View this session in the relation graph' }, ['graph'])); }
        if (sfoot.childNodes.length) { sc.appendChild(sfoot); }
        node = sc;
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
      case 'mintcard': {
        node = renderMintRequestCard(control, sectionCard);
        break;
      }
      case 'approver': {
        node = renderBoundApproverControl(sectionCard);
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
    return applyCapabilityGate(node, control && control.k);
  }

  function renderSection(section) {
    var card = el('section', { 'class': 'v2card' + (section.wide ? ' wide' : '') + (section.hidden ? ' is-collapsed' : '') });
    if (section.id) { card.id = section.id; }
    var hideToggles = [];   // header view-filter toggles, wired once the body exists
    var headCtls = section.headControls || [];
    if (section.h && (section.headAction || headCtls.length)) {
      // Card header row: title left; view-filter toggles + a "+"/cog action right.
      var hrow = el('div', { 'class': 'v2card-head-row' });
      hrow.appendChild(el('h3', { 'class': 'v2card-h', text: section.h }));
      var actions = el('div', { 'class': 'v2card-head-actions' });
      headCtls.forEach(function (hc) {
        var cn = renderControl(hc, card);
        if (!cn) { return; }
        cn.classList.add('in-head');
        actions.appendChild(cn);
        if (hc.hideKey) { hideToggles.push({ node: cn, hideKey: hc.hideKey }); }
      });
      if (section.headAction) {
        var act = section.headAction;
        var addBtn = el('button', { 'class': 'v2card-addbtn' + (act.variant ? ' ' + act.variant : ''), type: 'button', text: act.label || '+',
          title: act.title || 'Add', 'aria-expanded': 'false', 'aria-label': act.title || 'Add' });
        addBtn.addEventListener('click', function () {
          var tgt = act.target ? doc().getElementById(act.target) : null;
          if (!tgt) { return; }
          var opening = tgt.classList.contains('is-collapsed');
          if (opening) { tgt.classList.remove('is-collapsed'); if (tgt.scrollIntoView) { tgt.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); } }
          else { tgt.classList.add('is-collapsed'); }
          addBtn.setAttribute('aria-expanded', opening ? 'true' : 'false');
          addBtn.classList.toggle('is-on', opening);
        });
        actions.appendChild(addBtn);
      }
      hrow.appendChild(actions);
      card.appendChild(hrow);
    } else if (section.h) {
      card.appendChild(el('h3', { 'class': 'v2card-h', text: section.h }));
    }
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
    // Wire header view-filter toggles now that the [data-hideif] rows exist.
    // A checked toggle hides matching rows and lights its LED (the toggle has no
    // server value to persist — it is a pure view filter).
    hideToggles.forEach(function (ht) {
      var cb = ht.node.querySelector ? ht.node.querySelector('input[type="checkbox"]') : null;
      if (!cb) { return; }
      var chip = ht.node.querySelector('.ctl-toggle');
      var apply = function () {
        if (chip && chip.classList) { chip.classList.toggle('on', cb.checked); }
        var rows = card.querySelectorAll('[data-hideif="' + ht.hideKey + '"]');
        for (var r = 0; r < rows.length; r++) { rows[r].classList.toggle('is-hidden', cb.checked); }
      };
      apply();
      cb.addEventListener('change', apply);
    });
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

  // ---- Attention-zone classifier (M3b) — PURE (smoke truth-table) ---------
  // Sort ONE normalised work/session item into exactly one attention zone, with
  // an explicit precedence and an explicit staleness rule. No DOM, no fetch — the
  // wiring below normalises the live feeds into items and calls this per item.
  //
  // Item signals (all optional; absent ⇒ that signal is not present):
  //   gatePending      a gated transition referencing this item awaits approval
  //                    (the wiring JOINS the gate feed to work items by work_id,
  //                    so each item is classified exactly once — no double-count)
  //   state            work state — the real WorkItem enum: 'planned' |
  //                    'in_progress' | 'blocked' | 'complete' | 'deployed' |
  //                    'archive' | 'pending_approval' | 'drafting'
  //                    (crates/corecruxd/src/work.rs WORK_STATES)
  //   blockerReason    stated reason a plan is blocked (context only)
  //   waitingForInput  a session is waiting for operator input. NOTE: coord has
  //                    no structured field for this today, so the wiring passes
  //                    an INFERRED value (see sessionWaitingForInput); this signal
  //                    is exact only when a real structured field feeds it.
  //   liveSession      this item is a live coord session (carries a heartbeat)
  //   lastSeenUnixMs   coord liveness heartbeat. It is PASSPORT-level, not
  //                    session-level (coord.rs:292) — sibling sessions of one
  //                    passport share it — so "fresh" means "this identity is
  //                    around", not per-session activity. We don't claim more.
  //   reviewPending    finished, awaiting review
  //
  // Precedence (high → low): needs_you > running > done_review. Anything in none
  // of the three (a planned/idle plan, a stale-heartbeat session) returns null.
  // Staleness rule: a live session is "running" only while its heartbeat age is
  // in [0, ATTENTION_LIVENESS_STALE_MS] — a non-finite or FUTURE timestamp (clock
  // skew → negative age) is NOT running, and an older heartbeat is idle (so a
  // walked-away session never masquerades as active work). Kept well under the
  // coord presence TTL (900s) so the inbox reflects live work, not mere presence.
  var ATTENTION_LIVENESS_STALE_MS = 5 * 60 * 1000;   // 5 minutes
  function deriveAttentionZone(item, now) {
    if (!item || typeof item !== 'object') { return null; }
    // needs_you — a human must act: an approval is pending, a plan is blocked,
    // or a session is waiting for input.
    if (item.gatePending) { return 'needs_you'; }
    if (item.state === 'blocked') { return 'needs_you'; }
    if (item.waitingForInput) { return 'needs_you'; }
    // running — work actively in flight: an in_progress plan, or a live session
    // whose heartbeat is fresh (the staleness rule: finite + non-negative age).
    var nowMs = Number(now);
    var last = Number(item.lastSeenUnixMs);
    var age = nowMs - last;
    var fresh = item.lastSeenUnixMs != null && isFinite(nowMs) && isFinite(last) &&
      age >= 0 && age <= ATTENTION_LIVENESS_STALE_MS;
    if (item.state === 'in_progress') { return 'running'; }
    if (item.liveSession && fresh) { return 'running'; }
    // done_review — finished, awaiting review. No 'reviewed' flag exists on a
    // WorkItem, so a 'complete' plan is, by default, awaiting review.
    if (item.reviewPending || item.state === 'complete') { return 'done_review'; }
    return null;
  }

  // ponytail: heuristic — coord carries no structured waiting-for-input field, so
  // the only signal is the session's OWN announced intent note, and NL intent is
  // unreliable ("awaiting CI; no input needed" can match). So this stays a soft
  // INFERRED signal (the card labels it "may need input · inferred"), never a
  // definite claim. Upgrade path: a coord `waiting_for_input` intent flag → exact.
  // Requires BOTH a waiting verb and a person/decision object to cut the loudest
  // false positives, but the honesty lever is the card label, not the regex.
  var WAIT_VERB_RE = /\b(await\w*|waiting|needs?|need)\b/i;
  var WAIT_OBJECT_RE = /\b(input|operator|human|reviewer?|approval|sign-?off|decision|go-?ahead|your\s+\w+|you)\b/i;
  function sessionWaitingForInput(note) {
    return typeof note === 'string' && WAIT_VERB_RE.test(note) && WAIT_OBJECT_RE.test(note);
  }

  // Read-only needs_you cards for the two non-gate signals (blocked plan / waiting
  // session). They carry NO mutation — a blocked plan is unblocked by editing the
  // plan or resolving its gate, not from the inbox — so they never touch the gated
  // choke point. data-zone lets the smoke assert grouping.
  function blockedPlanCard(w) {
    var card = el('div', { 'class': 'ow-gate ow-attn-blocked', 'data-zone': 'needs_you', 'data-attn-kind': 'blocked', 'data-work-id': w.id || '' });
    card.appendChild(el('div', { 'class': 'ow-gate-top' }, [
      el('span', { 'class': 'ow-badge risk', text: 'BLOCKED' }),
      el('span', { 'class': 'ow-slug', text: w.id || '' })
    ]));
    card.appendChild(el('h3', { text: w.title || w.id || 'blocked plan' }));
    if (w.blocker_reason) { card.appendChild(el('p', { 'class': 'ow-await', text: w.blocker_reason })); }
    card.appendChild(el('a', { 'class': 'btn-quiet', href: '#/canvas/tree?focus=work:' + (w.id || ''), title: 'Open in the plan tree' }, ['View plan']));
    return card;
  }
  // The waiting signal is INFERRED from the intent note (coord has no structured
  // field), so the card says "may need input" + an "inferred from intent" chip —
  // never a definite "waiting for input" claim the daemon cannot back.
  function waitingSessionCard(s) {
    var i = s.intent || {};
    var pid = s.passport_id || '?';
    var card = el('div', { 'class': 'ow-gate ow-attn-waiting', 'data-zone': 'needs_you', 'data-attn-kind': 'session', 'data-inferred': 'intent-note' });
    card.appendChild(el('div', { 'class': 'ow-gate-top' }, [
      el('span', { 'class': 'ow-badge', text: 'MAY NEED INPUT' }),
      el('span', { 'class': 'ow-slug', text: (s.session_id_hex ? String(s.session_id_hex).slice(0, 8) : pid) })
    ]));
    card.appendChild(el('div', { 'class': 'ow-attr' }, [
      el('span', { 'class': 'ow-avatar', text: initials(pid) }),
      el('span', { text: pid + (i.execplan_slug ? ' · ' + i.execplan_slug + (i.milestone ? ' @ ' + i.milestone : '') : '') })
    ]));
    if (i.note) { card.appendChild(el('p', { 'class': 'ow-await', text: i.note })); }
    card.appendChild(el('span', { 'class': 'ow-chip ow-inferred', title: 'inferred from the session’s announced intent note — coord has no structured waiting-for-input signal', text: 'inferred from intent' }));
    card.appendChild(el('a', { 'class': 'btn-quiet cx-graphlink', href: '#/canvas/graph?focus=session:' + (s.session_id_hex || pid), title: 'Open in the Canvas relation graph' }, ['View graph']));
    return card;
  }

  // Needs-you: the attention INBOX (M3b) — the needs_you zone from
  // deriveAttentionZone over three live feeds, each read THROUGH the generated
  // client (M4a pattern):
  //   · pending gates   ← /v1/work/gate/pending  (literal → fetchJSON)
  //   · blocked plans   ← /v1/work?source=all    (parameterised → CruxApi.work)
  //   · waiting/live sessions ← /v1/coord/active (literal → fetchJSON)
  // Fail-honest PER FEED (M4a appendFeedNotices): a failed feed shows a degraded
  // notice and never silently empties the zone, and "All clear" renders only when
  // EVERY feed is healthy. Operators get approve / return on gate cards (through
  // the gated choke point); the other cards are read-only. Demo fills ONLY a
  // genuinely-empty healthy panel (every feed ok but nothing pending) — never a
  // failure, so it can never erase the per-feed degraded notices.
  function fillNeedsYou(wrap) {
    var body = wrap.__body;
    var api = (typeof window !== 'undefined') ? window.CruxApi : null;
    return Promise.all([
      fetchJSON('/v1/work/gate/pending'),
      fetchVia(api && typeof api.work === 'function' ? function () { return api.work({ source: 'all' }); } : null),
      fetchJSON('/v1/coord/active')
    ]).then(function (r) {
      var gateRes = r[0], workRes = r[1], coordRes = r[2];
      body.textContent = '';
      // Fail honest per feed (coord 404 = "off, not error"; the coord clock also
      // anchors session-liveness so a wall-clock skew never mislabels freshness).
      appendFeedNotices(body, [
        ['gates', gateRes, 'pending gated transitions'],
        ['work', workRes, 'blocked plans'],
        ['coord', coordRes, 'waiting / live sessions']
      ]);
      // Session liveness is PASSPORT-level (coord.rs:292): sibling sessions of one
      // passport share a heartbeat, so "fresh" reads as "identity is around".
      var now = (coordRes.ok && coordRes.data && coordRes.data.now_unix_ms) || Date.now();
      var pending = ((gateRes.ok && gateRes.data && gateRes.data.pending) || []).filter(function (p) { return (p.status || 'pending') === 'pending'; });
      var workItems = (workRes.ok && workRes.data && (workRes.data.work || workRes.data.items)) || [];
      var sessions = (coordRes.ok && coordRes.data && coordRes.data.active_sessions) || [];
      // JOIN the gate feed to work items by work_id so a gated in_progress/blocked
      // item is classified EXACTLY ONCE (gatePending → needs_you, never also
      // running/done_review). Without the join the item double-counts.
      var gateByWork = Object.create(null);
      pending.forEach(function (p) { if (p && p.work_id != null) { gateByWork[p.work_id] = p; } });
      var needs = [], running = 0, review = 0;
      var usedGate = Object.create(null);   // action_ids consumed by a joined work item
      workItems.forEach(function (w) {
        if (!w || w.id == null || w.superseded_by) { return; }   // a superseded plan is not live attention
        var gate = gateByWork[w.id] || null;
        var z = deriveAttentionZone({ gatePending: !!gate, state: w.state, blockerReason: w.blocker_reason }, now);
        if (z === 'needs_you') {
          // Gate wins the render (it is the actionable card); else it is blocked.
          if (gate) { needs.push({ kind: 'gate', v: gate }); if (gate.action_id) { usedGate[gate.action_id] = 1; } }
          else { needs.push({ kind: 'blocked', v: w }); }
        } else if (z === 'running') { running++; }
        else if (z === 'done_review') { review++; }
      });
      // Pending gates whose work_id is not in the work feed still need showing —
      // render each once (skip the ones already joined above; no drop, no dupe).
      pending.forEach(function (p) {
        if (p && p.action_id && usedGate[p.action_id]) { return; }
        needs.push({ kind: 'gate', v: p });
      });
      // Sessions are a separate axis from work items, so no double-count risk.
      sessions.forEach(function (s) {
        var z = deriveAttentionZone({ liveSession: true, lastSeenUnixMs: s.last_seen_at_unix_ms, waitingForInput: sessionWaitingForInput((s.intent || {}).note) }, now);
        if (z === 'needs_you') { needs.push({ kind: 'session', v: s }); }
        else if (z === 'running') { running++; }
      });
      var anyFail = !gateRes.ok || !workRes.ok || !coordRes.ok;
      var nothing = !needs.length && !running && !review;
      // Demo fills ONLY a genuinely-empty HEALTHY panel — never when a feed
      // failed (that must keep its per-feed degraded notice; demoNeedsYou clears
      // the body, so gating it on !anyFail preserves the notices).
      if (nothing && !anyFail && demoNeedsYou(wrap)) { return; }
      setCt(wrap, needs.length + ' need you · ' + running + ' running · ' + review + ' awaiting review' + (isOperator() ? '' : ' · awaiting operator'));
      // Grouping readout (the running / done_review zones are counts; the
      // needs_you zone is rendered as actionable cards below).
      body.appendChild(el('div', {
        'class': 'ow-zone-summary', role: 'status',
        'data-needs-you': String(needs.length), 'data-running': String(running), 'data-done-review': String(review),
        text: needs.length + ' need you · ' + running + ' running · ' + review + ' awaiting review'
      }));
      if (!needs.length) {
        // Never "All clear" when a feed failed — the per-feed notices above say
        // what is degraded, and the inbox may be incomplete (fail honest).
        if (anyFail) {
          body.appendChild(el('p', { 'class': 'ow-await', text: 'Some feeds are degraded (see above) — the attention inbox may be incomplete.' }));
          return;
        }
        var ok = el('div', { 'class': 'ow-allclear' });
        ok.innerHTML = SVG_CHECK;
        ok.appendChild(el('div', {}, [
          el('b', { text: 'All clear — nothing needs you' }),
          el('span', { text: running + ' running · ' + review + ' awaiting review' })
        ]));
        body.appendChild(ok);
        return;
      }
      needs.forEach(function (n) {
        if (n.kind === 'gate') { body.appendChild(gateCard(n.v)); }
        else if (n.kind === 'blocked') { body.appendChild(blockedPlanCard(n.v)); }
        else { body.appendChild(waitingSessionCard(n.v)); }
      });
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

  // Optimistic resolve. The M3a-hardened approve/reject returns the updated
  // WorkItem flattened WITH a resolvable `receipt_id` (the bound-actor CROWN
  // receipt) — surface that reference. Only a real value renders; a response
  // lacking one shows "recorded", never a fabricated hash.
  function markResolved(wrap, kind, data, who) {
    wrap.classList.add('is-resolved');   // stripe flips --warn → --ok
    var op = wrap.querySelector('.ow-gate-op');
    if (op) { op.textContent = ''; } else { op = el('div', { 'class': 'ow-gate-op' }); wrap.appendChild(op); }
    var receipt = data && (data.receipt_id || (data.receipt && data.receipt.receipt_id) || data.receipt);
    var haveReceipt = receipt && typeof receipt === 'string';
    var line = el('div', { 'class': 'ow-done' + (kind === 'returned' ? ' returned' : '') });
    line.innerHTML = (kind === 'returned' ? SVG_RETURN : SVG_CHECK);
    line.appendChild(el('span', { text: (kind === 'approved' ? 'Approved' : 'Returned') + ' by ' + who + (data && data.state ? ' · ' + data.state : '') }));
    // The resolvable receipt reference (M3a) — resolvable via /v1/receipts/{id}.
    line.appendChild(el('span', { 'class': 'ow-hash', title: haveReceipt ? 'CROWN receipt · resolvable at /v1/receipts/' + receipt : 'receipt not returned', text: haveReceipt ? 'receipt ' + receipt : 'recorded' }));
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
  // 404s → static hint pointing at the Work › Activity surface folded into this
  // console (the standalone /console/activity page has been removed).
  function fillActivity(wrap) {
    var body = wrap.__body;
    return fetchJSON('/v1/activity?tenant_id=default&token_budget=1500').then(function (res) {
      body.textContent = '';
      if (res.status === 404) {
        if (demoActivity(wrap)) { return; }   // demo fills only when the surface is off
        setCt(wrap, 'Work › Activity');
        body.appendChild(kv('stream', 'GET /v1/events/stream?types=activity.appended'));
        body.appendChild(kv('activity log', 'folded into Work › Activity in this console'));
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
    // Tab row (the Overwatch pages minus Overview) + a content area that swaps
    // below the tiles. Default = Activity: Needs-you + Fleet (50%) | Activity (50%).
    var CP = (typeof window !== 'undefined') ? window.CruxPages : null;
    var PAGES = (CP && CP.PAGES) || {};
    var order = ['cx-activity', 'cx-coord', 'cx-orchestrators', 'cx-punchcards', 'ax-agent'];
    var tabs = [];
    order.forEach(function (id) { var p = PAGES[id]; if (p && p.dest === 'overwatch') { tabs.push({ id: id, title: p.title }); } });
    Object.keys(PAGES).forEach(function (id) {
      var p = PAGES[id];
      if (p && p.dest === 'overwatch' && id !== 'cx-overview' && order.indexOf(id) < 0) { tabs.push({ id: id, title: p.title }); }
    });
    var tabBar = el('div', { 'class': 'ow-tabs', role: 'tablist', 'aria-label': 'Overwatch views' });
    var content = el('div', { 'class': 'ow-tabcontent' });
    root.appendChild(tabBar); root.appendChild(content);
    var tabBtns = {}, active = tabs.length ? tabs[0].id : null;
    // Honour a deep link (#/overwatch/<id>) by opening that tab.
    if (typeof location !== 'undefined' && location.hash) {
      var hp = String(location.hash).replace(/^#\/?/, '').split('/');
      if (hp[0] === 'overwatch' && hp[1] && tabs.some(function (t) { return t.id === hp[1]; })) { active = hp[1]; }
    }
    tabs.forEach(function (t) {
      var b = el('button', { 'class': 'ow-tab', type: 'button', role: 'tab', 'data-tab': t.id, 'aria-selected': t.id === active ? 'true' : 'false' }, [t.title]);
      b.addEventListener('click', function () {
        active = t.id;
        Object.keys(tabBtns).forEach(function (k) { tabBtns[k].setAttribute('aria-selected', k === t.id ? 'true' : 'false'); });
        renderTab(t.id);
      });
      tabBar.appendChild(b); tabBtns[t.id] = b;
    });
    function renderTab(id) {
      content.textContent = '';
      var page = PAGES[id];
      if (id === 'cx-activity') {
        var cols = el('div', { 'class': 'ow-cols' });
        var left = el('div', { 'class': 'ow-col' });
        var right = el('div', { 'class': 'ow-col' });
        cols.appendChild(left); cols.appendChild(right);
        content.appendChild(cols);
        var needs = panel('Needs you', 'loading gate queue…', true);
        var fleet = panel('Fleet', 'loading live sessions…', false);
        left.appendChild(needs); left.appendChild(fleet);   // Needs-you then Fleet (left 50%)
        var actHost = el('div', { 'class': 'page-host' });
        right.appendChild(actHost);
        if (page) { renderPage(page, actHost); }             // Activity (cx-activity) on the right 50%
        fillNeedsYou(needs); fillFleet(fleet);
        return;
      }
      var host = el('div', { 'class': 'page-host' });
      content.appendChild(host);
      if (page) { renderPage(page, host); }
    }
    if (active) { renderTab(active); }
    return fillTiles(tileCard, ctx);
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
    // Custom-rendered pages (no section model).
    if (page.id === 'cx-activity-log') { container.textContent = ''; renderActivityLog(container); return Promise.resolve(); }
    if (page.id === 'cx-facts') { container.textContent = ''; renderFactsBrowser(container); return Promise.resolve(); }
    if (page.id === 'cx-sessions') { container.textContent = ''; renderSessionsBrowser(container); return Promise.resolve(); }
    if (page.operatorOnly && !isOperator()) {
      renderSections(container, [{ h: page.title, wide: true, controls: [
        { t: 'info', label: 'operator only', v: 'This surface is only available in operator posture.' },
        { t: 'info', label: 'why', v: 'Forward-facing consoles hide operator deep-machinery until an operator scope is granted.' }
      ] }]);
      return Promise.resolve();
    }
    // Immediate paint from static sections (skeleton / fallback).
    var initialSections = page.sections && page.sections.length ? page.sections : [{ h: page.title, wide: true, controls: [{ t: 'info', label: 'status', v: 'loading…' }] }];
    renderSections(container, withRuntimeCapabilitySection(page, initialSections));
    if (!page.load || typeof page.load.build !== 'function') {
      return Promise.resolve();
    }
    var token = container.__renderToken = (container.__renderToken || 0) + 1;
    return fetchJSON(page.load.endpoint).then(function (res) {
      if (container.__renderToken !== token) { return; }   // superseded by a newer navigation
      var sections;
      try { sections = page.load.build(res); }
      catch (e) { sections = [{ h: page.title, wide: true, controls: [{ t: 'info', label: 'render error', v: String(e && e.message || e) }] }]; }
      renderSections(container, withRuntimeCapabilitySection(page, sections));
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

  // =======================================================================
  //  WebCrux tile canvas (M14) — the canvas tile pattern ported from
  //  WebCrux-aurora (useCanvasState.ts · CanvasView.vue · CanvasNode.vue), the
  //  interaction grammar per Unified-Web-Direction §07 / Aurora-Spec-2026-07-07.
  //  The measured values ARE the spec:
  //    · SIZE_MAP tiles (square/wide/tall/hero × sm/md/lg/xl) on a 20px snap grid
  //    · onion-layer auto-layout — Chebyshev rings out from the anchor hero
  //    · drag-to-pan with a 4px deadzone (translate clamped ≤ 0, right/down only)
  //    · click-to-expand in place: siblings dim (blur 18px · saturate .2 ·
  //      opacity .15) and the layer auto-pans so the card lands at {20,20}
  //    · entry scale(.92)+8px rise .4s (70ms stagger) · exit .25s · easing
  //      cubic-bezier(.16,1,.3,1) everywhere · hover lift −3px
  //    · form/stack view under 640px (12-col spans — the PageView.vue port)
  //  Vanilla port: no framework, no randomness (layout is a pure function of
  //  card order + saved positions, so smoke-26 determinism holds console-wide),
  //  reduced-motion-safe (the global reduce rule kills animation/transition; a
  //  dedicated fallback drops the dim blur so context stays readable). The
  //  synchronous first paint runs under the smoke's minimal DOM: no classList,
  //  no querySelector, no localStorage, no document-level listeners until the
  //  environment actually provides them.
  // =======================================================================

  var TILE_GRID = 20;
  function tileSnap(v) { return Math.round((Number(v) || 0) / TILE_GRID) * TILE_GRID; }

  // Base px dimensions per shape+size combo (SIZE_MAP, ported verbatim).
  var TILE_SIZE_MAP = {
    square: { sm: { w: 180, h: 180 }, md: { w: 240, h: 240 }, lg: { w: 320, h: 320 }, xl: { w: 400, h: 400 } },
    wide:   { sm: { w: 260, h: 140 }, md: { w: 360, h: 180 }, lg: { w: 480, h: 220 }, xl: { w: 600, h: 260 } },
    tall:   { sm: { w: 180, h: 260 }, md: { w: 220, h: 360 }, lg: { w: 280, h: 440 }, xl: { w: 320, h: 520 } },
    hero:   { sm: { w: 360, h: 200 }, md: { w: 480, h: 260 }, lg: { w: 600, h: 320 }, xl: { w: 720, h: 380 } }
  };
  var TILE_PAN_TARGET = { x: 20, y: 20 };   // auto-pan target on expand
  var TILE_PAN_DEAD_ZONE = 4;               // px — shared pan/drag deadzone
  var TILE_LAYOUT_PAD = 35, TILE_LAYOUT_GAP = 24, TILE_MAX_GRID_ROWS = 60;
  var TILE_FORM_BREAK = 640;                // below this width: the form stack

  function tileDims(shape, size) {
    var byShape = TILE_SIZE_MAP[shape] || TILE_SIZE_MAP.square;
    return byShape[size] || byShape.md;
  }
  // Rendered dims — grid-derived overrideW/H win over the SIZE_MAP base.
  function tileRenderedDims(card) {
    var base = tileDims(card.shape, card.size);
    return {
      w: card.overrideW != null ? card.overrideW : base.w,
      h: card.overrideH != null ? card.overrideH : base.h
    };
  }

  // Shape → grid span at quarter-anchor resolution (getGridSpan, ported; the
  // 16:9-image row expansion is dropped — console tiles carry no images).
  function tileGridSpan(card) {
    switch (card.shape) {
      case 'hero': return [4, 4];
      case 'wide': return [4, 2];
      case 'tall': return [2, 4];
      default: return [2, 2];
    }
  }
  function tileSpanToPixel(cols, rows, cellW, cellH, gap) {
    return { w: cols * cellW + (cols - 1) * gap, h: rows * cellH + (rows - 1) * gap };
  }

  // Onion-layer auto-layout (autoLayoutCards, ported). Manual + pinned cards
  // keep their positions; the rest sort chromeless → hero → original order and
  // the first becomes the ANCHOR defining a quarter-anchor cell grid
  // (cell = (anchor − 3·gap) / 4). Free cells are scanned in Chebyshev-distance
  // rings from the origin — first fit wins, radiating a tight onion pattern out
  // from the hero. Pure and deterministic: no randomness, no DOM.
  function tileAutoLayout(cards, saved) {
    var pad = TILE_LAYOUT_PAD, gap = TILE_LAYOUT_GAP;
    var result = {}, locked = {};
    (cards || []).forEach(function (card) {
      var pos = saved && saved[card.id];
      if (pos && pos.manual) {
        locked[card.id] = true;
        result[card.id] = { x: pos.x, y: pos.y, manual: true, w: pos.w, h: pos.h };
      } else if (card.pinned) {
        locked[card.id] = true;
        result[card.id] = { x: card.x || 0, y: card.y || 0 };
      }
    });
    var autoCards = (cards || []).filter(function (c) { return !locked[c.id]; });
    if (!autoCards.length) { return result; }
    autoCards = autoCards.slice().sort(function (a, b) {
      var ap = a.chromeless ? 0 : (a.shape === 'hero' ? 1 : 2);
      var bp = b.chromeless ? 0 : (b.shape === 'hero' ? 1 : 2);
      return ap - bp;
    });
    var anchorDim = tileRenderedDims(autoCards[0]);
    var cellW = Math.floor((anchorDim.w - 3 * gap) / 4);
    var cellH = Math.floor((anchorDim.h - 3 * gap) / 4);
    var spans = {}, totalCells = 0;
    autoCards.forEach(function (card) {
      var span = tileGridSpan(card);
      spans[card.id] = span;
      totalCells += span[0] * span[1];
    });
    // Dynamic maxCols: enough Chebyshev layers that (d+1)² covers every cell.
    var maxCols = Math.min(Math.max(Math.ceil(Math.sqrt(totalCells)) + 2, 3), TILE_MAX_GRID_ROWS);
    var occupied = {};
    function cellKey(c, r) { return c + ',' + r; }
    (cards || []).forEach(function (card) {
      if (!locked[card.id]) { return; }
      var pos = result[card.id];
      if (!pos) { return; }
      var dim = tileRenderedDims(card);
      var c0 = Math.max(0, Math.floor((pos.x - pad) / (cellW + gap)));
      var r0 = Math.max(0, Math.floor((pos.y - pad) / (cellH + gap)));
      var c1 = Math.ceil((pos.x - pad + dim.w) / (cellW + gap));
      var r1 = Math.ceil((pos.y - pad + dim.h) / (cellH + gap));
      for (var c = c0; c < Math.min(c1, maxCols); c++) {
        for (var r = r0; r < Math.min(r1, TILE_MAX_GRID_ROWS); r++) { occupied[cellKey(c, r)] = true; }
      }
    });
    function canPlace(col, row, cols, rows) {
      if (col + cols > maxCols || row + rows > TILE_MAX_GRID_ROWS) { return false; }
      for (var c = col; c < col + cols; c++) {
        for (var r = row; r < row + rows; r++) { if (occupied[cellKey(c, r)]) { return false; } }
      }
      return true;
    }
    function markOccupied(col, row, cols, rows) {
      for (var c = col; c < col + cols; c++) {
        for (var r = row; r < row + rows; r++) { occupied[cellKey(c, r)] = true; }
      }
    }
    // Grid math produces exact, consistent gaps — no snap needed here.
    function gridToPixel(col, row) { return { x: pad + col * (cellW + gap), y: pad + row * (cellH + gap) }; }
    var scanOrder = [];
    for (var sr = 0; sr < TILE_MAX_GRID_ROWS; sr++) {
      for (var sc = 0; sc < maxCols; sc++) { scanOrder.push([sc, sr]); }
    }
    scanOrder.sort(function (a, b) {
      var da = Math.max(a[0], a[1]), db = Math.max(b[0], b[1]);
      if (da !== db) { return da - db; }
      if (a[1] !== b[1]) { return a[1] - b[1]; }
      return a[0] - b[0];
    });
    autoCards.forEach(function (card) {
      var span = spans[card.id];
      var dim = tileSpanToPixel(span[0], span[1], cellW, cellH, gap);
      var placed = false;
      for (var i = 0; i < scanOrder.length; i++) {
        var col = scanOrder[i][0], row = scanOrder[i][1];
        if (canPlace(col, row, span[0], span[1])) {
          markOccupied(col, row, span[0], span[1]);
          var pos = gridToPixel(col, row);
          result[card.id] = { x: pos.x, y: pos.y, w: dim.w, h: dim.h };
          placed = true;
          break;
        }
      }
      if (!placed) {   // grid full — stack below every occupied cell
        var maxR = 0;
        Object.keys(occupied).forEach(function (k) {
          var rr = parseInt(k.split(',')[1], 10);
          if (isFinite(rr) && rr > maxR) { maxR = rr; }
        });
        markOccupied(0, maxR + 1, span[0], span[1]);
        var p2 = gridToPixel(0, maxR + 1);
        result[card.id] = { x: p2.x, y: p2.y, w: dim.w, h: dim.h };
      }
    });
    return result;
  }

  // Expanded dimensions (getExpandedDimensions, ported): content-estimated from
  // the card's own text (~7.5px/char, 18px lines, clamped 300px…90% viewport),
  // or a padded viewport fill for card.fill (the board's widget dashboards).
  function tileExpandedDims(vpW, vpH, card) {
    if (card.fill) {
      var fpad = 40;
      return { w: Math.max(320, vpW - fpad * 2), h: Math.max(300, vpH - fpad) };
    }
    var w = Math.max(Math.floor(vpW * 0.45), 440);
    if (w > vpW - 40) { w = Math.max(280, vpW - 40); }
    var charsPerLine = Math.max(Math.floor(w / 7.5), 40);
    var h = 48 + 28;
    if (card.subtitle) { h += 20; }
    if (card.body) { h += Math.ceil(String(card.body).length / charsPerLine) * 18 + 8; }
    (card.expandedParas || []).forEach(function (p) {
      h += Math.ceil(String(p).length / charsPerLine) * 18 + 16;
    });
    h = Math.max(h, 300);
    h = Math.min(h, Math.floor(vpH * 0.9));
    return { w: w, h: h };
  }

  // Manual tile positions persist per surface (drag-end snaps to the 20px grid
  // and marks manual; auto tiles re-flow around them on the next layout).
  function tileLoadPositions(storeKey) {
    try {
      var raw = localStorage.getItem('crux.console.tiles.' + storeKey);
      return raw ? JSON.parse(raw) : {};
    } catch (e) { return {}; }
  }
  function tileSavePositions(storeKey, positions) {
    try { localStorage.setItem('crux.console.tiles.' + storeKey, JSON.stringify(positions)); }
    catch (e) { /* quota / private mode — positions just don't persist */ }
  }

  // Build one tile node. The class string is assembled up front — no classList
  // on the first paint (the smoke's minimal DOM exercises the synchronous path).
  // Card shape: { id, eyebrow, title, subtitle, body, expandedParas, build(host),
  // shape, size, accent (theme-token key), chip {id,sig}, routeLink, chromeless,
  // pinned, fill }.
  function tileNode(card, idx, extraClass) {
    var cls = 'cvx-node';
    if (card.chromeless) { cls += ' cvx-chromeless'; }
    if (card.shape === 'hero') { cls += ' cvx-hero'; }
    if (extraClass) { cls += ' ' + extraClass; }
    var node = el('article', {
      'class': cls, 'data-id': card.id, 'data-accent': card.accent || 'neutral',
      tabindex: card.chromeless ? null : '0', role: card.chromeless ? null : 'button'
    });
    node.style.animationDelay = (Math.min(idx || 0, 12) * 70) + 'ms';   // entry stagger
    if (!card.chromeless) { node.appendChild(el('span', { 'class': 'cvx-accent', 'aria-hidden': 'true' })); }
    var content = el('div', { 'class': 'cvx-content' });
    if (card.eyebrow) { content.appendChild(el('div', { 'class': 'cvx-eyebrow', text: card.eyebrow })); }
    content.appendChild(el('h3', { 'class': 'cvx-title', text: card.title || card.id }));
    if (card.subtitle) { content.appendChild(el('p', { 'class': 'cvx-sub', text: card.subtitle })); }
    if (card.body) { content.appendChild(el('p', { 'class': 'cvx-body', text: card.body })); }
    if (typeof card.build === 'function') {
      // Live tile body — a reused console surface paints here (one failed feed
      // degrades one tile, never the canvas).
      var live = el('div', { 'class': 'cvx-live' });
      content.appendChild(live);
      try { card.build(live); }
      catch (e) { live.appendChild(el('p', { 'class': 'ctl-desc', text: 'tile unavailable' })); }
    }
    var paras = card.expandedParas || [];
    if (paras.length) {
      // Richer drill-in content — CSS-hidden at base level, shown on expand.
      var exp = el('div', { 'class': 'cvx-expbody' });
      paras.forEach(function (p) { exp.appendChild(el('p', { text: String(p) })); });
      content.appendChild(exp);
    }
    if (card.chip && card.chip.id) {
      // Receipt chip (Aurora signature): ✓ in --ok, id, scheme in --trust —
      // rendered ONLY for a real receipt id, never fabricated.
      var chip = el('span', { 'class': 'cvx-chip' }, [
        el('span', { 'class': 'cvx-chip-ok', text: '✓' }),
        el('span', { text: String(card.chip.id) })
      ]);
      if (card.chip.sig) { chip.appendChild(el('span', { 'class': 'cvx-chip-sig', text: String(card.chip.sig) })); }
      content.appendChild(chip);
    }
    node.appendChild(content);
    return node;
  }

  // ---- The canvas view (CanvasView.vue, ported) ---------------------------
  // One live instance at a time (route-driven, like the graph): the next call
  // releases the previous instance's document-level listeners.
  var __tileCleanup = null;
  function renderTileCanvas(host, cards, opts) {
    opts = opts || {};
    if (__tileCleanup) { __tileCleanup(); __tileCleanup = null; }
    host.textContent = '';
    var hostW = host.clientWidth || (typeof window !== 'undefined' && window.innerWidth) || 1280;
    if (hostW < TILE_FORM_BREAK) { return renderTileStack(host, cards, opts); }

    var surface = el('div', { 'class': 'cvx-surface' });
    surface.appendChild(el('div', { 'class': 'cvx-grid', 'aria-hidden': 'true' }));
    var layer = el('div', { 'class': 'cvx-layer' });
    surface.appendChild(layer);
    host.appendChild(surface);
    function vp() {
      return {
        w: surface.clientWidth || hostW,
        h: surface.clientHeight || 640
      };
    }

    var nodes = {};
    var expandedId = null;
    var manualPan = { x: 0, y: 0 };
    var squelchClick = false;

    function setClass(n, cls, on) { if (n && n.classList) { n.classList.toggle(cls, !!on); } }
    function findCard(id) {
      for (var i = 0; i < cards.length; i++) { if (cards[i].id === id) { return cards[i]; } }
      return null;
    }
    function applyLayerPan(x, y) {
      // Whole pixels only — sub-pixel translate blurs composited text.
      layer.style.transform = (x === 0 && y === 0) ? '' : 'translate(' + Math.round(x) + 'px, ' + Math.round(y) + 'px)';
    }

    function placeNode(card, node) {
      var dim = tileRenderedDims(card);
      node.style.left = card.x + 'px';
      node.style.top = card.y + 'px';
      node.style.width = dim.w + 'px';
      node.style.height = dim.h + 'px';
    }

    function collapse() {
      if (!expandedId) { return; }
      var card = findCard(expandedId), node = nodes[expandedId];
      expandedId = null;
      setClass(surface, 'cvx-has-exp', false);
      if (node && card) { setClass(node, 'cvx-exp', false); placeNode(card, node); }
      Object.keys(nodes).forEach(function (k) { setClass(nodes[k], 'cvx-dim', false); });
      manualPan = { x: 0, y: 0 };   // returning to base resets the pan to origin
      applyLayerPan(0, 0);
    }

    function expand(card) {
      if (card.routeLink) { if (typeof location !== 'undefined') { location.hash = card.routeLink; } return; }
      if (card.chromeless) { return; }
      if (expandedId === card.id) { collapse(); return; }
      if (expandedId) {
        // Direct hand-off between tiles: swap without the full collapse reset.
        var prev = findCard(expandedId), prevNode = nodes[expandedId];
        if (prevNode && prev) { setClass(prevNode, 'cvx-exp', false); placeNode(prev, prevNode); }
      }
      expandedId = card.id;
      var node = nodes[card.id];
      var v = vp();
      var exp = tileExpandedDims(v.w, v.h, card);
      setClass(surface, 'cvx-has-exp', true);
      setClass(node, 'cvx-exp', true);
      node.style.width = exp.w + 'px';
      node.style.height = exp.h + 'px';
      Object.keys(nodes).forEach(function (k) { setClass(nodes[k], 'cvx-dim', k !== card.id); });
      // Auto-pan the layer so the expanded card lands at {20,20}.
      applyLayerPan(TILE_PAN_TARGET.x - card.x, TILE_PAN_TARGET.y - card.y);
    }

    function mountCard(card, idx) {
      var node = tileNode(card, idx);
      placeNode(card, node);
      nodes[card.id] = node;
      layer.appendChild(node);
      node.addEventListener('pointerdown', function (ev) {
        if (expandedId || card.chromeless || card.pinned) { return; }
        if (ev.target && ev.target.closest && ev.target.closest('button, a, input, select, textarea, details')) { return; }
        drag = { x: ev.clientX, y: ev.clientY, cx: card.x, cy: card.y, card: card, node: node, moved: false };
        setClass(node, 'cvx-dragging', true);
      });
      node.addEventListener('click', function (ev) {
        if (ev.stopPropagation) { ev.stopPropagation(); }
        if (squelchClick) { squelchClick = false; return; }
        if (ev.target && ev.target.closest && ev.target.closest('button, a, input, select, textarea, details')) { return; }
        expand(card);
      });
      node.addEventListener('keydown', function (ev) {
        if (ev.key === 'Enter' || ev.key === ' ') { if (ev.preventDefault) { ev.preventDefault(); } expand(card); }
      });
    }

    function layoutAndMount() {
      var saved = opts.storeKey ? tileLoadPositions(opts.storeKey) : {};
      var positions = tileAutoLayout(cards, saved);
      cards.forEach(function (card, i) {
        var pos = positions[card.id] || { x: TILE_LAYOUT_PAD, y: TILE_LAYOUT_PAD };
        card.x = pos.x; card.y = pos.y;
        if (pos.w != null) { card.overrideW = pos.w; }
        if (pos.h != null) { card.overrideH = pos.h; }
        if (nodes[card.id]) { placeNode(card, nodes[card.id]); }
        else { mountCard(card, i); }
      });
    }
    layoutAndMount();

    // Manual pan — pointer-drag on empty surface, 4px deadzone, translate
    // clamped ≤ 0 (pan right/down only); the layer transition is CSS-disabled
    // while .cvx-panning so the drag tracks 1:1.
    var pan = null, drag = null;
    surface.addEventListener('pointerdown', function (ev) {
      if (ev.target && ev.target.closest && ev.target.closest('.cvx-node')) { return; }
      if (expandedId) { return; }   // manual pan is a base-level gesture
      pan = { x: ev.clientX, y: ev.clientY, px: manualPan.x, py: manualPan.y, moved: false };
      setClass(surface, 'cvx-panning', true);
    });
    surface.addEventListener('click', function (ev) {
      if (ev.target && ev.target.closest && ev.target.closest('.cvx-node')) { return; }
      if (squelchClick) { squelchClick = false; return; }
      if (expandedId) { collapse(); }   // click on empty canvas releases
    });
    function onPointerMove(ev) {
      if (pan) {
        var dx = ev.clientX - pan.x, dy = ev.clientY - pan.y;
        if (!pan.moved && Math.abs(dx) < TILE_PAN_DEAD_ZONE && Math.abs(dy) < TILE_PAN_DEAD_ZONE) { return; }
        pan.moved = true;
        manualPan = { x: Math.min(0, pan.px + dx), y: Math.min(0, pan.py + dy) };
        applyLayerPan(manualPan.x, manualPan.y);
        return;
      }
      if (drag) {
        var ddx = ev.clientX - drag.x, ddy = ev.clientY - drag.y;
        if (!drag.moved && Math.abs(ddx) < TILE_PAN_DEAD_ZONE && Math.abs(ddy) < TILE_PAN_DEAD_ZONE) { return; }
        drag.moved = true;
        drag.card.x = tileSnap(drag.cx + ddx);   // live snap to the 20px grid
        drag.card.y = tileSnap(drag.cy + ddy);
        drag.node.style.left = drag.card.x + 'px';
        drag.node.style.top = drag.card.y + 'px';
      }
    }
    function onPointerUp() {
      if (pan) {
        squelchClick = pan.moved;
        pan = null;
        setClass(surface, 'cvx-panning', false);
      }
      if (drag) {
        var d = drag;
        drag = null;
        setClass(d.node, 'cvx-dragging', false);
        squelchClick = squelchClick || d.moved;
        if (d.moved && opts.storeKey) {
          var saved = tileLoadPositions(opts.storeKey);
          var prev = saved[d.card.id] || {};
          saved[d.card.id] = {
            x: d.card.x, y: d.card.y, manual: true,
            // Preserve grid-derived dims so the tile doesn't snap back to SIZE_MAP size.
            w: prev.w != null ? prev.w : d.card.overrideW,
            h: prev.h != null ? prev.h : d.card.overrideH
          };
          tileSavePositions(opts.storeKey, saved);
        }
      }
    }
    function onKeyDown(ev) { if (ev.key === 'Escape' && expandedId) { collapse(); } }
    var d0 = doc();
    if (d0 && typeof d0.addEventListener === 'function') {
      d0.addEventListener('pointermove', onPointerMove);
      d0.addEventListener('pointerup', onPointerUp);
      d0.addEventListener('keydown', onKeyDown);
      __tileCleanup = function () {
        d0.removeEventListener('pointermove', onPointerMove);
        d0.removeEventListener('pointerup', onPointerUp);
        d0.removeEventListener('keydown', onKeyDown);
      };
    }

    return {
      // Re-flow with an updated card list (live tiles landing after their real
      // reads). Removed tiles leave over .25s (.cvx-leave); manual positions are
      // preserved; new tiles mount with the entry animation.
      relayout: function (nextCards) {
        var nextIds = {};
        nextCards.forEach(function (c) { nextIds[c.id] = true; });
        var leaving = [];
        Object.keys(nodes).forEach(function (id) {
          if (!nextIds[id]) { leaving.push(id); }
        });
        function finish() {
          leaving.forEach(function (id) {
            var n = nodes[id];
            if (n && n.parentNode && n.parentNode.removeChild) { n.parentNode.removeChild(n); }
            delete nodes[id];
          });
          cards = nextCards;
          layoutAndMount();
        }
        if (leaving.length && typeof setTimeout === 'function') {
          leaving.forEach(function (id) { setClass(nodes[id], 'cvx-leave', true); });
          setTimeout(finish, 250);   // the measured exit: .25s out
        } else { finish(); }
      },
      collapse: collapse
    };
  }

  // ---- The form / stack view (<640px — PageView.vue, ported) --------------
  // 12-col grid: hero 12 · wide 8 · square 6 · tall 4 (CSS collapses spans at
  // the 768/640 breakpoints). Click drills into a focused span-12 card with a
  // Back control; chromeless cards render as intro headers.
  function renderTileStack(host, cards, opts) {
    host.textContent = '';
    var wrap = el('div', { 'class': 'cvx-pv' });
    host.appendChild(wrap);
    function spanFor(card) {
      switch (card.shape) {
        case 'hero': return 12;
        case 'wide': return 8;
        case 'tall': return 4;
        default: return 6;
      }
    }
    var current = cards;
    function paintBase() {
      wrap.textContent = '';
      current.forEach(function (card) {
        if (!card.chromeless) { return; }
        var intro = el('div', { 'class': 'cvx-pv-intro' });
        intro.appendChild(el('h1', { 'class': 'cvx-pv-title', text: card.title || '' }));
        if (card.subtitle) { intro.appendChild(el('p', { 'class': 'cvx-pv-sub', text: card.subtitle })); }
        if (card.body) { intro.appendChild(el('p', { 'class': 'cvx-pv-body', text: card.body })); }
        wrap.appendChild(intro);
      });
      var grid = el('div', { 'class': 'cvx-pv-grid' });
      wrap.appendChild(grid);
      current.forEach(function (card, i) {
        if (card.chromeless) { return; }
        var node = tileNode(card, i);
        node.setAttribute('data-span', String(spanFor(card)));
        node.addEventListener('click', function (ev) {
          if (ev.stopPropagation) { ev.stopPropagation(); }
          if (ev.target && ev.target.closest && ev.target.closest('button, a, input, select, textarea, details')) { return; }
          if (card.routeLink) { if (typeof location !== 'undefined') { location.hash = card.routeLink; } return; }
          paintFocused(card);
        });
        node.addEventListener('keydown', function (ev) {
          if (ev.key === 'Enter' || ev.key === ' ') {
            if (ev.preventDefault) { ev.preventDefault(); }
            if (card.routeLink) { if (typeof location !== 'undefined') { location.hash = card.routeLink; } return; }
            paintFocused(card);
          }
        });
        grid.appendChild(node);
      });
    }
    function paintFocused(card) {
      wrap.textContent = '';
      var nav = el('div', { 'class': 'cvx-pv-nav' });
      var back = el('button', { 'class': 'btn-quiet', type: 'button' }, ['← Back']);
      back.addEventListener('click', function () { paintBase(); });
      nav.appendChild(back);
      wrap.appendChild(nav);
      var node = tileNode(card, 0, 'cvx-exp cvx-pv-focus');
      node.setAttribute('data-span', '12');
      wrap.appendChild(node);
    }
    paintBase();
    return {
      relayout: function (nextCards) { current = nextCards; paintBase(); },
      collapse: paintBase
    };
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
  // { id, span, minTier, build } — the audited contract; minTier gates a widget
  // IN at that tier and up. Cumulative counts: xs 4 · s 6 · m 10 · l 14 · xl 18
  // (the 4K+ board). M14 adds presentation-only tile metadata: { eyebrow, tile:
  // {shape,size}, accent } feed the WebCrux tile canvas (span stays the ported
  // grid weight and the smoke's integrity key — untouched).
  var CANVAS_WIDGETS = [
    { id: 'stat-tiles', span: 2, minTier: 'xs', title: 'Daemon at a glance', eyebrow: 'OVERWATCH · GLANCE', tile: { shape: 'hero', size: 'lg' }, accent: 'acc', build: function (cell) { return canvasPageCell(cell, 'cx-overview'); } },
    { id: 'needs-you', span: 2, minTier: 'xs', title: 'Needs you', eyebrow: 'OVERWATCH · ART.14', tile: { shape: 'wide', size: 'lg' }, accent: 'warn', build: function (cell) { return canvasPanelCell(cell, 'Needs you', fillNeedsYou, 'loading gate queue…'); } },
    { id: 'fleet', span: 1, minTier: 'xs', title: 'Fleet', eyebrow: 'OVERWATCH · FLEET', tile: { shape: 'tall', size: 'md' }, accent: 'ok', build: function (cell) { return canvasPanelCell(cell, 'Fleet', fillFleet, 'loading fleet…'); } },
    { id: 'activity', span: 1, minTier: 'xs', title: 'Activity', eyebrow: 'OVERWATCH · LIVE', tile: { shape: 'tall', size: 'md' }, accent: 'trust', build: function (cell) { return canvasPanelCell(cell, 'Activity', fillActivity, 'loading…'); } },
    { id: 'cost-chart', span: 2, minTier: 's', title: 'Token burn', eyebrow: 'METERS · COST', tile: { shape: 'wide', size: 'lg' }, accent: 'acc', build: function (cell) { return canvasChartCell(cell, 'Token burn', 'costSeries'); } },
    { id: 'work', span: 2, minTier: 's', title: 'ExecPlans', eyebrow: 'WORK · PLANS', tile: { shape: 'wide', size: 'lg' }, accent: 'acc', build: function (cell) { return canvasPageCell(cell, 'cx-work'); } },
    { id: 'usage-chart', span: 2, minTier: 'm', title: 'Token usage', eyebrow: 'METERS · USAGE', tile: { shape: 'wide', size: 'md' }, accent: 'acc', build: function (cell) { return canvasChartCell(cell, 'Token usage', 'usageSeries'); } },
    { id: 'facts', span: 2, minTier: 'm', title: 'Facts', eyebrow: 'MEMORY · FACTS', tile: { shape: 'wide', size: 'md' }, accent: 'acc', build: function (cell) { return canvasPageCell(cell, 'cx-facts'); } },
    { id: 'engine', span: 1, minTier: 'm', title: 'Engine', eyebrow: 'SYSTEM · MEDIATED', tile: { shape: 'square', size: 'md' }, accent: 'trust', build: function (cell) { return canvasPanelCell(cell, 'Engine', fillEngine, 'checking mediation…'); } },
    { id: 'dashboard-strip', span: 4, minTier: 'm', title: 'Fleet dashboard', eyebrow: 'OVERWATCH · DASH', tile: { shape: 'hero', size: 'md' }, accent: 'ok', build: function (cell, ctx) { return canvasDashCell(cell, ctx); } },
    { id: 'projects', span: 2, minTier: 'l', title: 'Projects', eyebrow: 'WORK · PROJECTS', tile: { shape: 'wide', size: 'md' }, accent: 'acc', build: function (cell) { return canvasPageCell(cell, 'cx-projects'); } },
    { id: 'sessions', span: 2, minTier: 'l', title: 'Sessions', eyebrow: 'WORK · SESSIONS', tile: { shape: 'wide', size: 'md' }, accent: 'ok', build: function (cell) { return canvasPageCell(cell, 'cx-sessions'); } },
    { id: 'tenants', span: 2, minTier: 'l', title: 'Tenants', eyebrow: 'MEMORY · CORPORA', tile: { shape: 'wide', size: 'md' }, accent: 'trust', build: function (cell) { return canvasPageCell(cell, 'cx-tenants'); } },
    { id: 'live-board', span: 2, minTier: 'l', title: 'Live board', eyebrow: 'WORK · COORD', tile: { shape: 'wide', size: 'md' }, accent: 'ok', build: function (cell) { return canvasPageCell(cell, 'cx-coord'); } },
    { id: 'passports', span: 1, minTier: 'xl', title: 'Passports', eyebrow: 'TRUST · IDENTITY', tile: { shape: 'square', size: 'md' }, accent: 'trust', build: function (cell) { return canvasPageCell(cell, 'cx-passport'); } },
    { id: 'gates', span: 2, minTier: 'xl', title: 'Gates', eyebrow: 'TRUST · ART.14', tile: { shape: 'wide', size: 'md' }, accent: 'warn', build: function (cell) { return canvasPageCell(cell, 'cx-gates'); } },
    { id: 'orchestrators', span: 1, minTier: 'xl', title: 'Orchestrators', eyebrow: 'WORK · ORCS', tile: { shape: 'square', size: 'md' }, accent: 'ok', build: function (cell) { return canvasPageCell(cell, 'cx-orchestrators'); } },
    { id: 'integrations', span: 1, minTier: 'xl', title: 'Integrations', eyebrow: 'SYSTEM · LINKS', tile: { shape: 'square', size: 'md' }, accent: 'neutral', build: function (cell) { return canvasPageCell(cell, 'cx-integrations'); } }
  ];

  // ---- Board renderer (M14) — the widget registry on the tile canvas -----
  // The pure canvasTier still decides WHICH widgets compose in (the size-
  // adaptive contract, smoke 25); the WebCrux tile canvas decides HOW they lay
  // out (onion-layer rings from the hero anchor, drag/pan/expand grammar).
  // Recompose on a debounced resize; under 640px renderTileCanvas falls through
  // to the form stack by itself.
  var __canvasResizeHandler = null;
  function renderCanvasBoard(host, ctx) {
    ctx = ctx || {};
    var lastKey = null;
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
      var mode = vp.W < TILE_FORM_BREAK ? 'stack' : 'canvas';
      var key = tier + ':' + mode;
      if (key === lastKey) { return; }   // only recompose on a real tier/mode change (no churn)
      lastKey = key;
      host.textContent = '';
      host.setAttribute('data-tier', tier);
      var maxIdx = CANVAS_TIER_ORDER.indexOf(tier);
      var tiles = [];
      CANVAS_WIDGETS.forEach(function (w) {
        if (CANVAS_TIER_ORDER.indexOf(w.minTier) > maxIdx) { return; }
        tiles.push({
          id: w.id,
          eyebrow: w.eyebrow || 'console',
          title: w.title || w.id,
          shape: (w.tile && w.tile.shape) || (w.span >= 4 ? 'hero' : (w.span === 2 ? 'wide' : 'square')),
          size: (w.tile && w.tile.size) || (w.span === 2 ? 'lg' : 'md'),
          accent: w.accent || 'neutral',
          fill: true,   // widgets expand to a padded viewport fill (dashboards need room)
          build: function (cell) {
            try { return w.build(cell, ctx); }
            catch (e) { cell.appendChild(el('p', { 'class': 'ctl-desc', text: 'widget unavailable' })); }
          }
        });
      });
      var boardHost = el('div', { 'class': 'cvx-board' });
      host.appendChild(boardHost);
      renderTileCanvas(boardHost, tiles, { storeKey: 'board-' + tier });
      host.appendChild(el('p', { 'class': 'ctl-desc cvx-board-meta', text: tier + ' tier · ' + tiles.length + ' widget' + (tiles.length === 1 ? '' : 's') + ' · drag a tile to place it · drag the canvas to pan · click to expand in place' }));
    }
    paint();
    // Debounced resize recompose. Tier/mode changes repaint instantly (no
    // animated reflow); within a tier the tile transitions carry the motion —
    // and the global prefers-reduced-motion rule switches those off wholesale.
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
        sub: opts.sub || null, raw: opts.raw || null, strip: opts.strip || null, progress: opts.progress || null };
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
          sub: (w.state || 'work') + (w.created_by_passport ? (' · ' + w.created_by_passport) : '') + (when ? (' · ' + when) : ''),
          progress: (w.milestones_total ? { done: w.milestones_done || 0, total: w.milestones_total, label: w.current_milestone } : null) });
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
      add('session', sid, (s.session_id_hex ? s.session_id_hex.slice(0, 8) : (s.passport_id || 'session')), { execplan: i.execplan_slug, milestone: i.milestone, passport: s.passport_id },
        { progress: (i.milestones_total ? { done: i.milestones_done || 0, total: i.milestones_total, label: i.milestone } : null) });
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

  // ---- Plan tree (M4a) — Project → ExecPlan → Milestone → live session -----
  // Pure join over the SAME real endpoint fields buildGraphModel consumes:
  //   projects (GET /v1/projects → .projects[]: id,name)
  //   work     (GET /v1/work?source=all → .work|.items[]: ExecPlan + kanban items;
  //             ExecPlan items carry project_id="execplans", id "execplan:<slug>",
  //             current_milestone, next_ready_milestone, milestones_done/total)
  //   sessions (GET /v1/coord/active → .active_sessions[]: session_id_hex,
  //             passport_id, intent{execplan_slug,milestone,paths,deploy_target},
  //             leases[]) — 404/disabled tolerated (data.sessions == null)
  // No fabricated edges: a session hangs off an ExecPlan ONLY when its announced
  // execplan_slug resolves to a real work item, and off a milestone ONLY when that
  // milestone id is one the data actually names. A session whose slug resolves to
  // nothing (or that announced none) lands under an explicit "unattached" root —
  // never guessed onto a plan. Milestone nodes are built solely from ids the data
  // names (current_milestone, next_ready_milestone, announced session milestones)
  // — never synthesised from milestones_total (ids are non-contiguous: M0, M3a,
  // M4b …, so a 1..total range would invent milestones that do not exist).
  // /v1/work?source=all merges TWO item kinds: aggregator-derived ExecPlans and
  // plain kanban work. Only ExecPlan items own a milestone layer + session
  // attachment; a kanban item rendered as an ExecPlan would fabricate a
  // session→milestone→ExecPlan shape. The load-bearing discriminator is
  // `plan_path` (set only by work_execplans::list_execplans; kanban items carry
  // None) — corroborated by the "execplan:" id prefix + the virtual "execplans"
  // project. See crates/corecruxd/src/work_execplans.rs:972.
  function isExecPlanItem(w) {
    return !!(w && (w.plan_path || String(w.id).indexOf('execplan:') === 0 || w.project_id === 'execplans'));
  }

  // ---- Stale-plan mismatch badge (M4c, console half) — pure -----------------
  // PR #457 adds `plan_content_hash` (lowercase BLAKE3 hex of the plan file's raw
  // bytes) to ExecPlan-projected /v1/work items. This derives the badge from the
  // HASH, not two machines' paths/clocks. Be honest about what the BROWSER can
  // know: it cannot read local files, so it never computes a local hash itself —
  // the real comparison consumer is the desktop shell (M5a), which passes the
  // local hash in. Driven purely by (daemon_hash, local_hash|null):
  //   · daemon_hash falsy     → no badge (nothing projected to attest)
  //   · local_hash null       → provenance chip only (daemon hash short-form)
  //   · both present, equal    → in-sync chip
  //   · both present, differ   → mismatch badge (T.2 guard)
  // Case-insensitive compare: both sides are lowercase hex, but normalise anyway
  // so a caller passing an upper-case digest never yields a false mismatch.
  function planHashBadge(daemon_hash, local_hash) {
    if (!daemon_hash) { return null; }
    var dShort = String(daemon_hash).slice(0, 12);
    if (local_hash == null) {
      return { kind: 'provenance', code: 'daemon_only', short: dShort, label: 'plan ' + dShort,
        title: 'daemon plan_content_hash (BLAKE3) — no local copy to compare; the browser cannot read local files, the desktop shell (M5a) supplies the local hash' };
    }
    if (String(daemon_hash).toLowerCase() === String(local_hash).toLowerCase()) {
      return { kind: 'insync', code: 'in_sync', short: dShort, label: 'plan in sync',
        title: 'local plan file matches the daemon-projected plan_content_hash (' + dShort + ')' };
    }
    return { kind: 'mismatch', code: 'stale_plan', short: dShort, localShort: String(local_hash).slice(0, 12),
      label: 'plan drift', title: 'local plan file (' + String(local_hash).slice(0, 12) + ') differs from the daemon plan_content_hash (' + dShort + ') — the projected plan may be stale' };
  }

  function buildPlanTree(data) {
    data = data || {};
    // null-proto lookup tables: ids like "__proto__"/"constructor" are data, not
    // prototype keys, so a plain {} would resolve wrongly or throw.
    var projectsMeta = Object.create(null);
    ((data.projects && data.projects.projects) || []).forEach(function (p) {
      if (p && p.id != null) { projectsMeta[p.id] = p.name || p.id; }
    });
    var work = (data.work && (data.work.work || data.work.items)) || [];
    var sessions = (data.sessions && data.sessions.active_sessions) || [];
    // M4c: optional client-side hash source keyed by work id AND bare slug. Empty
    // in-browser today (no source yet → provenance chips); the desktop shell (M5a)
    // fills it. null-proto so a slug like "__proto__" is data, not a chain key.
    var localHashes = Object.create(null);
    var haveLocalHashes = !!(data.localPlanHashes);
    if (haveLocalHashes) {
      Object.keys(data.localPlanHashes).forEach(function (k) { localHashes[k] = data.localPlanHashes[k]; });
    }

    // Resolve a session's bare intent.execplan_slug to a work item. The ExecPlan
    // work id is "execplan:<slug>"; kanban ids are opaque. Match exact id or the
    // "execplan:"-prefixed form — nothing fuzzier (fuzzy match = a fabricated edge).
    var itemById = Object.create(null);
    work.forEach(function (w) {
      if (!w || w.id == null) { return; }
      itemById[w.id] = w;
      if (String(w.id).indexOf('execplan:') === 0) { itemById[String(w.id).slice(9)] = w; }
    });
    function resolveItem(slug) {
      if (!slug) { return null; }
      return itemById[slug] || itemById['execplan:' + slug] || null;
    }
    function sessionNode(s, unresolvedSlug) {
      var i = s.intent || {};
      var sid = s.session_id_hex || s.passport_id || 'session';
      return {
        key: 'session:' + sid, type: 'session', id: sid,
        label: (s.session_id_hex ? String(s.session_id_hex).slice(0, 8) : (s.passport_id || 'session')),
        sub: s.passport_id || null, state: null, progress: null,
        // Announced focus + held leases travel WITH the node (M4a gate).
        focus: {
          execplan_slug: i.execplan_slug || null, milestone: i.milestone || null,
          paths: Array.isArray(i.paths) ? i.paths : [], deploy_target: i.deploy_target || null
        },
        leases: Array.isArray(s.leases) ? s.leases : [],
        // Non-null only for unattached sessions — the slug that resolved to no
        // work item, painted so the row says which plan failed to resolve.
        unresolvedSlug: unresolvedSlug || null,
        children: []
      };
    }

    // Bucket announced sessions by the item they resolve to (+ milestone). A
    // session that resolves to an ExecPlan is attached by milestone; one that
    // resolves to a kanban item attaches directly to it (no milestone level);
    // an unresolved session goes to the unattached list — never a fabricated plan.
    var byItemMilestone = Object.create(null);   // work.id -> { milestoneId|'' : [sessionNode] }
    var unattached = [];
    sessions.forEach(function (s) {
      if (!s) { return; }
      var i = s.intent || {};
      var item = resolveItem(i.execplan_slug);
      if (!item) { unattached.push(sessionNode(s, i.execplan_slug || null)); return; }
      // Milestone only matters for ExecPlan items; kanban sessions collapse to ''.
      var m = (isExecPlanItem(item) && i.milestone != null && i.milestone !== '') ? String(i.milestone) : '';
      var bucket = byItemMilestone[item.id] || (byItemMilestone[item.id] = Object.create(null));
      (bucket[m] || (bucket[m] = [])).push(sessionNode(s, null));
    });

    var projectNodes = Object.create(null), roots = [];
    function projectNode(pid) {
      if (projectNodes[pid]) { return projectNodes[pid]; }
      var label = projectsMeta[pid] || (pid === 'execplans' ? 'ExecPlans' : pid);
      var n = { key: 'project:' + pid, type: 'project', id: pid, label: label, sub: null,
        state: null, progress: null, focus: null, leases: [], children: [] };
      projectNodes[pid] = n; roots.push(n); return n;
    }
    function attachBucketFlat(target, bucket) {
      Object.keys(bucket).forEach(function (m) { bucket[m].forEach(function (sn) { target.children.push(sn); }); });
    }

    work.forEach(function (w) {
      if (!w || w.id == null) { return; }
      var proj = projectNode(w.project_id || 'unknown');
      var bucket = byItemMilestone[w.id] || Object.create(null);

      if (!isExecPlanItem(w)) {
        // Kanban item: a plain work node, NO milestone synthesis. Sessions that
        // announced this id hang directly off it (never a fabricated ExecPlan).
        var workNode = {
          key: 'work:' + w.id, type: 'work', id: w.id, label: w.title || w.id,
          sub: (w.state || 'work') + (w.blocker_reason ? (' · blocked: ' + w.blocker_reason) : ''),
          state: w.state || null, progress: null, focus: null, leases: [], children: []
        };
        proj.children.push(workNode);
        attachBucketFlat(workNode, bucket);
        return;
      }

      var slug = String(w.id).indexOf('execplan:') === 0 ? String(w.id).slice(9) : w.id;
      // M4c: daemon hash read defensively — `plan_content_hash` is additive
      // (PR #457), so this is undefined/absent until the daemon ships it, and the
      // node simply carries no badge. Local hash resolves by id then bare slug.
      var localHash = null;
      if (haveLocalHashes) { localHash = localHashes[w.id]; if (localHash == null) { localHash = localHashes[slug]; } }
      var planNode = {
        key: 'work:' + w.id, type: 'execplan', id: w.id, label: w.title || slug,
        sub: (w.state || 'work') + (w.blocker_reason ? (' · blocked: ' + w.blocker_reason) : ''),
        state: w.state || null,
        progress: (w.milestones_total ? { done: w.milestones_done || 0, total: w.milestones_total, label: w.current_milestone || null } : null),
        planBadge: planHashBadge(w.plan_content_hash || null, (localHash == null ? null : localHash)),
        focus: null, leases: [], children: []
      };
      proj.children.push(planNode);

      // Milestone ids the data names for THIS plan: current + next-ready + any a
      // live session announced. De-duped; empty ('' = no milestone) excluded.
      var mids = [], milestoneNodes = Object.create(null);
      function pushMid(m) { if (m != null && m !== '' && mids.indexOf(String(m)) < 0) { mids.push(String(m)); } }
      pushMid(w.current_milestone);
      pushMid(w.next_ready_milestone);
      Object.keys(bucket).forEach(function (m) { pushMid(m); });
      mids.forEach(function (mid) {
        var mn = { key: 'work:' + w.id + '#' + mid, type: 'milestone', id: mid, label: mid,
          sub: (mid === w.current_milestone ? 'current' : (mid === w.next_ready_milestone ? 'next ready' : null)),
          state: null, progress: null, focus: null, leases: [], children: [] };
        milestoneNodes[mid] = mn; planNode.children.push(mn);
      });
      // Attach sessions to their milestone node; a session that announced this
      // plan but no milestone (bucket key '') hangs directly off the plan.
      // M4b: stamp the RESOLVED ExecPlan entity so the session-detail view fetches
      // fact provenance only for sessions that actually resolved to an ExecPlan
      // (kanban/unattached carry no execplanEntity → explicit no-plan absent state).
      Object.keys(bucket).forEach(function (m) {
        var target = (m !== '' && milestoneNodes[m]) ? milestoneNodes[m] : planNode;
        bucket[m].forEach(function (sn) { sn.execplanEntity = 'execplan:' + slug; target.children.push(sn); });
      });
    });

    if (unattached.length) {
      roots.push({ key: 'unattached', type: 'unattached', id: 'unattached',
        label: 'Unattached sessions', sub: 'live sessions with no matching ExecPlan',
        state: null, progress: null, focus: null, leases: [], children: unattached });
    }
    return { roots: roots };
  }

  // Deterministic layered layout — columns by node type. No random seed: node
  // positions are a pure function of type + insertion order (replayable).
  // Card layout — columns by type (sessions lead, matching the concept). Each
  // node carries its top-left x/y + card w/h; edges connect card centres.
  function layoutGraph(nodes) {
    var COLS = ['session', 'work', 'gate', 'project', 'passport', 'repo'];
    var CARD_W = 300, CARD_H = 128;   // uniform node height (CSS .cv-card matches) so port anchors line up
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
  // Fills the inspector BODY (the topbar with the pin/close lives in the panel shell).
  function graphInspector(inspector, n, model) {
    inspector.textContent = '';
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
  function drawGraph(stage, onSelect, model, focus) {
    stage.textContent = '';
    if (!model.nodes.length) { stage.appendChild(el('p', { 'class': 'ctl-desc', text: 'No graph yet — no sessions / work / passports available.' })); return; }
    // Focus deep-link: when the board is opened on a specific node (e.g. a session
    // from the Sessions page), show ONLY that node + its direct connections — the
    // rest of the graph is withheld, not merely dimmed. Falls back to the full
    // model if the focus doesn't resolve.
    if (focus && focus.type && focus.id != null) {
      var fidx = {}; model.nodes.forEach(function (n) { fidx[n.key] = n; });
      var fnode = fidx[focus.type + ':' + focus.id] || graphMatchNode(model.nodes, focus);
      if (fnode) {
        var keep = graphNeighbourhood(model.edges, fnode.key); keep[fnode.key] = true;
        model = {
          nodes: model.nodes.filter(function (n) { return keep[n.key]; }),
          edges: model.edges.filter(function (e) { return keep[e.from] && keep[e.to]; })
        };
        focus = { type: fnode.type, id: fnode.id };   // normalise for the select() below
      }
    }
    var dims = layoutGraph(model.nodes);
    var index = {}; model.nodes.forEach(function (n) { index[n.key] = n; });
    // One transformed layer holds the SVG edge canvas + the HTML node cards, so
    // pan/zoom moves cards and edges together.
    var layer = el('div', { 'class': 'cv-graph-layer' });
    layer.style.width = dims.width + 'px'; layer.style.height = dims.height + 'px';
    var svg = svgEl('svg', { 'class': 'cv-graph-edges', width: dims.width, height: dims.height, 'aria-hidden': 'true' });
    // Two solid arrowhead markers (idle + hot) — userSpaceOnUse keeps them a
    // constant size regardless of stroke width; fill is set per class in CSS.
    var defs = svgEl('defs');
    [['cvArrow', 'cv-arrowhead'], ['cvArrowHot', 'cv-arrowhead cv-arrowhead-hot']].forEach(function (m) {
      var mk = svgEl('marker', { id: m[0], viewBox: '0 0 10 10', refX: '8', refY: '5', markerWidth: '9', markerHeight: '9', orient: 'auto-start-reverse', markerUnits: 'userSpaceOnUse' });
      mk.appendChild(svgEl('path', { 'class': m[1], d: 'M0.5 0.5 L9.5 5 L0.5 9.5 z' }));
      defs.appendChild(mk);
    });
    svg.appendChild(defs);
    layer.appendChild(svg);
    var reduceMotion = (typeof window !== 'undefined' && window.matchMedia) ? window.matchMedia('(prefers-reduced-motion: reduce)').matches : false;
    // --- Edge routing with attachment "ports" -----------------------------
    // Each edge attaches to the SIDE of a node that faces the other node, at a
    // point distributed along that side — so multiple wires sharing one side fan
    // out evenly instead of piling onto a single spot. Recomputed on every drag.
    function nodeBox(n) { var w = n.w || 300, h = n.h || 106; return { x: n.x, y: n.y, w: w, h: h, cx: n.x + w / 2, cy: n.y + h / 2 }; }
    function facingSide(a, b) { var dx = b.cx - a.cx, dy = b.cy - a.cy; return (Math.abs(dx) >= Math.abs(dy)) ? (dx >= 0 ? 'right' : 'left') : (dy >= 0 ? 'bottom' : 'top'); }
    function anchor(box, side, slot, count) {
      var OUT = 6, PAD = 0.16;                        // OUT: sit just off the border · PAD: keep ports off the corners
      var t = count <= 1 ? 0.5 : PAD + (slot / (count - 1)) * (1 - 2 * PAD);
      if (side === 'left') { return { x: box.x - OUT, y: box.y + box.h * t }; }
      if (side === 'right') { return { x: box.x + box.w + OUT, y: box.y + box.h * t }; }
      if (side === 'top') { return { x: box.x + box.w * t, y: box.y - OUT }; }
      return { x: box.x + box.w * t, y: box.y + box.h + OUT };   // bottom
    }
    function layoutEdges() {
      var boxes = {}; model.nodes.forEach(function (n) { boxes[n.key] = nodeBox(n); });
      var ports = {};                                 // "nodeKey|side" -> [{ eo, end, otherCx, otherCy }]
      edgeObjs.forEach(function (eo) {
        var a = boxes[eo.from], b = boxes[eo.to]; if (!a || !b) { return; }
        var sa = facingSide(a, b), sb = facingSide(b, a);
        (ports[eo.from + '|' + sa] = ports[eo.from + '|' + sa] || []).push({ eo: eo, end: 'a', otherCx: b.cx, otherCy: b.cy });
        (ports[eo.to + '|' + sb] = ports[eo.to + '|' + sb] || []).push({ eo: eo, end: 'b', otherCx: a.cx, otherCy: a.cy });
      });
      Object.keys(ports).forEach(function (pk) {
        var list = ports[pk], sep = pk.lastIndexOf('|'), nodeKey = pk.slice(0, sep), side = pk.slice(sep + 1), box = boxes[nodeKey];
        var horiz = (side === 'left' || side === 'right');
        // Order ports by the OTHER endpoint's cross-axis position so wires meeting
        // one side don't cross each other at the attachment.
        list.sort(function (p, q) { return horiz ? (p.otherCy - q.otherCy) : (p.otherCx - q.otherCx); });
        list.forEach(function (item, i) {
          var pt = anchor(box, side, i, list.length);
          if (item.end === 'a') { item.eo.p1 = pt; } else { item.eo.p2 = pt; }
        });
      });
      edgeObjs.forEach(function (eo) {
        if (!eo.p1 || !eo.p2) { return; }
        eo.wire.setAttribute('d', 'M' + eo.p1.x.toFixed(1) + ' ' + eo.p1.y.toFixed(1) + ' L' + eo.p2.x.toFixed(1) + ' ' + eo.p2.y.toFixed(1));
        if (eo.pulse) { eo.pulse.setAttribute('cx', eo.p1.x.toFixed(1)); eo.pulse.setAttribute('cy', eo.p1.y.toFixed(1)); }
      });
    }
    var edgeObjs = [], edgeEls = [];
    model.edges.forEach(function (e, i) {
      var a = index[e.from], b = index[e.to]; if (!a || !b) { return; }
      var wire = svgEl('path', { 'class': 'cv-gedge', 'marker-end': 'url(#cvArrow)' });
      if (e.kind) { wire.setAttribute('data-kind', e.kind); }
      wire.__from = e.from; wire.__to = e.to;
      svg.appendChild(wire);
      var eo = { from: e.from, to: e.to, wire: wire, pulse: null, phase: (i % 10) / 10, p1: null, p2: null };
      if (!reduceMotion) { var pulse = svgEl('circle', { 'class': 'cv-pulse', r: '3.2' }); svg.appendChild(pulse); eo.pulse = pulse; }
      wire.__eo = eo; edgeObjs.push(eo); edgeEls.push(wire);
    });
    layoutEdges();
    // Flow pulses travel source → target along each wire, fading in/out at the ends.
    var rafId = null;
    if (!reduceMotion && edgeObjs.length && typeof window !== 'undefined' && window.requestAnimationFrame) {
      var tick = function (ts) {
        var t = (ts || 0) / 2200;
        edgeObjs.forEach(function (eo) {
          if (!eo.pulse || !eo.p1) { return; }
          var u = (t + eo.phase) % 1;
          eo.pulse.setAttribute('cx', (eo.p1.x + (eo.p2.x - eo.p1.x) * u).toFixed(1));
          eo.pulse.setAttribute('cy', (eo.p1.y + (eo.p2.y - eo.p1.y) * u).toFixed(1));
          eo.pulse.setAttribute('opacity', u < 0.12 ? (u / 0.12).toFixed(2) : (u > 0.88 ? ((1 - u) / 0.12).toFixed(2) : '1'));
        });
        rafId = window.requestAnimationFrame(tick);
      };
      rafId = window.requestAnimationFrame(tick);
    }
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
      // Milestone progress bar on work / session nodes — the fill tracks the
      // node's accent colour (--cv-c), so the bar reads as "this node's progress".
      if (n.progress && n.progress.total) {
        var pv = Math.max(0, Math.min(100, Math.round((n.progress.done / n.progress.total) * 100)));
        var ptrack = el('div', { 'class': 'cv-card-prog' }, [el('div', { 'class': 'cv-card-prog-fill' })]);
        ptrack.firstChild.style.width = pv + '%';
        var plabel = (n.progress.label ? (n.progress.label + ' · ') : '') + n.progress.done + '/' + n.progress.total;
        card.appendChild(el('div', { 'class': 'cv-card-progrow' }, [ptrack, el('span', { 'class': 'cv-card-progv', text: plabel })]));
      }
      var idline = (n.extra && n.extra.session_id) || (n.type === 'work' ? n.id : null);
      if (idline) { card.appendChild(el('div', { 'class': 'cv-card-id', text: idline })); }
      function open() { select(n.key); onSelect(n); }
      // Drag to move: delta ÷ view.scale → layer space; wires reflow every frame.
      // A ≤3px press is a click (select + inspect); a real drag just repositions.
      card.addEventListener('mousedown', function (ev) {
        if (ev.button !== 0) { return; }
        ev.stopPropagation();
        var sx = ev.clientX, sy = ev.clientY, ox = n.x, oy = n.y, moved = false;
        card.classList.add('is-dragging');
        function mv(e) {
          if (Math.abs(e.clientX - sx) + Math.abs(e.clientY - sy) > 3) { moved = true; }
          n.x = Math.max(0, ox + (e.clientX - sx) / view.scale);
          n.y = Math.max(0, oy + (e.clientY - sy) / view.scale);
          card.style.left = n.x + 'px'; card.style.top = n.y + 'px';
          layoutEdges();
        }
        function up() {
          window.removeEventListener('mousemove', mv); window.removeEventListener('mouseup', up);
          card.classList.remove('is-dragging');
          if (!moved) { open(); }
        }
        window.addEventListener('mousemove', mv); window.addEventListener('mouseup', up);
      });
      card.addEventListener('keydown', function (ev) { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); open(); } });
      layer.appendChild(card); cardEls[n.key] = card;
    });
    stage.appendChild(layer);

    var view = { tx: 16, ty: 16, scale: 1 };
    function apply() { layer.style.transform = 'translate(' + view.tx + 'px,' + view.ty + 'px) scale(' + view.scale + ')'; }
    // Fit-to-viewport: scale + centre the whole graph into the stage so it lands
    // on-screen without panning. When a node is focused the inspector slides in
    // over the right edge, so reserve that width and centre in the space left.
    function fitView() {
      var sw = stage.clientWidth || 960, sh = stage.clientHeight || 640, pad = 30;
      var reserveR = (focus && focus.type && focus.id != null) ? 380 : 0;
      var availW = Math.max(260, sw - reserveR - pad * 2), availH = Math.max(200, sh - pad * 2);
      var s = Math.max(0.42, Math.min(availW / dims.width, availH / dims.height, 1.15));
      view.scale = s;
      view.tx = pad + Math.max(0, (availW - dims.width * s) / 2);
      view.ty = pad + Math.max(0, (availH - dims.height * s) / 2);
      apply();
    }
    fitView();
    function select(key) {
      if (key == null) {
        Object.keys(cardEls).forEach(function (k) { cardEls[k].classList.remove('is-sel'); cardEls[k].classList.remove('is-dim'); });
        edgeEls.forEach(function (ln) {
          ln.classList.remove('is-dim'); ln.classList.remove('is-hot'); ln.setAttribute('marker-end', 'url(#cvArrow)');
          if (ln.__eo && ln.__eo.pulse) { ln.__eo.pulse.classList.remove('is-dim'); ln.__eo.pulse.classList.remove('is-hot'); }
        });
        return;
      }
      var nbr = graphNeighbourhood(model.edges, key); nbr[key] = true;
      var hasLinks = Object.keys(nbr).length > 1;   // don't grey the world for an isolated node
      Object.keys(cardEls).forEach(function (k) {
        cardEls[k].classList.toggle('is-sel', k === key);
        cardEls[k].classList.toggle('is-dim', hasLinks && !nbr[k]);
      });
      edgeEls.forEach(function (ln) {
        var touches = ln.__from === key || ln.__to === key;
        var dim = hasLinks && !(nbr[ln.__from] && nbr[ln.__to]);
        ln.classList.toggle('is-hot', touches);   // the selected node's own edges light up + flow faster
        ln.classList.toggle('is-dim', dim);
        ln.setAttribute('marker-end', touches ? 'url(#cvArrowHot)' : 'url(#cvArrow)');
        if (ln.__eo && ln.__eo.pulse) { ln.__eo.pulse.classList.toggle('is-hot', touches); ln.__eo.pulse.classList.toggle('is-dim', dim); }
      });
    }

    // Pan (drag on empty stage) + wheel zoom. A click on empty space (no drag)
    // deselects — the inspector then slides away unless it's pinned.
    var drag = null, moved = false;
    stage.addEventListener('mousedown', function (ev) { if (ev.target.closest && ev.target.closest('.cv-card')) { return; } drag = { x: ev.clientX, y: ev.clientY, tx: view.tx, ty: view.ty }; moved = false; });
    stage.addEventListener('click', function (ev) { if (ev.target.closest && ev.target.closest('.cv-card')) { return; } if (!moved) { select(null); onSelect(null); } });
    function onMove(ev) { if (!drag) { return; } moved = true; view.tx = drag.tx + (ev.clientX - drag.x); view.ty = drag.ty + (ev.clientY - drag.y); apply(); }
    function onUp() { drag = null; }
    stage.addEventListener('wheel', function (ev) { ev.preventDefault(); var f = ev.deltaY < 0 ? 1.1 : 0.9; view.scale = Math.max(0.4, Math.min(2.2, view.scale * f)); apply(); });
    if (typeof window !== 'undefined') { window.addEventListener('mousemove', onMove); window.addEventListener('mouseup', onUp); }
    __canvasGraphCleanup = function () {
      if (rafId != null && typeof window !== 'undefined' && window.cancelAnimationFrame) { window.cancelAnimationFrame(rafId); rafId = null; }
      if (typeof window !== 'undefined') { window.removeEventListener('mousemove', onMove); window.removeEventListener('mouseup', onUp); }
    };

    // Focus deep-link: select + highlight the node's neighbourhood + open panel.
    if (focus && focus.type && focus.id != null) {
      var fn = index[focus.type + ':' + focus.id] || graphMatchNode(model.nodes, focus);
      if (fn) { select(fn.key); onSelect(fn); }
    }
  }

  function renderCanvasGraph(host, ctx, focus) {
    host.textContent = '';
    if (__canvasGraphCleanup) { __canvasGraphCleanup(); __canvasGraphCleanup = null; }
    var model = null;
    var wrap = el('div', { 'class': 'canvas-graph' });
    var stage = el('div', { 'class': 'canvas-graph-stage' }, [el('p', { 'class': 'ctl-desc', text: 'Building graph…' })]);
    // Inspector panel — hidden off the right edge; slides in on node click. A pin
    // keeps it loaded when you click empty space or another surface.
    var inspector = el('div', { 'class': 'canvas-graph-inspector' });
    var pinBtn = el('button', { 'class': 'cv-insp-btn cv-insp-pin', type: 'button', title: 'Pin inspector', 'aria-pressed': 'false' });
    pinBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 4h6l-1 6 3 3v2H7v-2l3-3z"/><path d="M12 15v5"/></svg>';
    var closeBtn = el('button', { 'class': 'cv-insp-btn cv-insp-close', type: 'button', title: 'Close', 'aria-label': 'Close inspector' });
    closeBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>';
    var inspBody = el('div', { 'class': 'cv-insp-body' });
    inspector.appendChild(el('div', { 'class': 'cv-insp-topbar' }, [el('span', { 'class': 'canvas-insp-type', text: 'Node inspector' }), pinBtn, closeBtn]));
    inspector.appendChild(inspBody);
    var pinned = false;
    function setPinned(v) { pinned = v; pinBtn.setAttribute('aria-pressed', v ? 'true' : 'false'); inspector.classList.toggle('is-pinned', v); }
    function onSelect(n) { if (n) { graphInspector(inspBody, n, model); inspector.classList.add('is-open'); } else if (!pinned) { inspector.classList.remove('is-open'); } }
    pinBtn.addEventListener('click', function (e) { e.stopPropagation(); setPinned(!pinned); });
    closeBtn.addEventListener('click', function (e) { e.stopPropagation(); setPinned(false); inspector.classList.remove('is-open'); });
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
      model = buildGraphModel(data);
      // Demo mode: build the graph purely from the labelled fixtures (work +
      // sessions + their passports + projects + gates) so it is clean and
      // predictable — and so a demo session/work focus (e.g. the "graph" link on
      // a Sessions card) resolves to a real node with neighbours to show.
      if (demoOn()) {
        var dWork = demoData('work') || [], dSess = demoData('sessions') || [], dProj = demoData('projects') || [];
        var passIds = {};
        dWork.forEach(function (w) { if (w.assignee_passport) { passIds[w.assignee_passport] = 1; } });
        dSess.forEach(function (s) { if (s.passport_id) { passIds[s.passport_id] = 1; } });
        var demoModel = buildGraphModel({
          projects: { projects: dProj },
          work: { work: dWork },
          gates: { pending: demoData('needsYou') || [] },
          passports: { passports: Object.keys(passIds).map(function (id) { return { id: id, name: id }; }) },
          sessions: { active_sessions: dSess.map(function (s) { return { session_id_hex: s.session_id, passport_id: s.passport_id, intent: { execplan_slug: s.execplan_slug, milestone: (s.milestones_total ? ('M' + (s.milestones_done || 0) + '/' + s.milestones_total) : null), milestones_done: s.milestones_done, milestones_total: s.milestones_total } }; }) }
        });
        if (demoModel.nodes.length) {
          model = demoModel;
          var head = wrap.querySelector('.canvas-graph-inspector .canvas-insp-type');
          if (head) { head.textContent = 'inspector · demo'; }
        }
      }
      drawGraph(stage, onSelect, model, focus);
    }).catch(function () { stage.textContent = ''; stage.appendChild(el('p', { 'class': 'ctl-desc', text: 'Graph unavailable.' })); });
  }

  // ---- Canvas entry point (shell routes the canvas destination here) -----
  // No sub-pills: Canvas IS the page, with a nav-family Board | Graph switch.
  // ---- Plan-tree view (M4a) — render buildPlanTree() live ----------------
  // A session row carries its announced focus (@milestone, deploy target, up to
  // 4 declared paths) + held leases inline — the M4a "nodes carry announced
  // focus + leases" gate. Nodes with children use a native <details> for free
  // expand/collapse (no JS). Fails honest: unreachable/501/empty each render a
  // stated reason, never a blank pane.
  // Per-feed degraded notice (M4a fail-honest, reusing the M2 disabled-with-
  // reason idiom: an accessible node carrying a machine-readable reason). coord
  // 404/disabled is "off, not error"; a non-zero status is an HTTP failure; 0 is
  // unreachable. Only failed feeds emit a row.
  function appendFeedNotices(wrap, feeds) {
    feeds.forEach(function (f) {
      var name = f[0], res = f[1], what = f[2];
      if (res.ok) { return; }
      var code, msg;
      if (name === 'coord' && res.status === 404) {
        code = 'coord_disabled';
        msg = 'Coordination plane off (set CORECRUXD_COORD=1) — ' + what + ' not shown.';
      } else if (res.status === 0) {
        code = 'unreachable';
        msg = 'The ' + name + ' feed is unreachable — ' + what + ' may be stale or missing.';
      } else {
        code = 'http_' + res.status;
        msg = 'The ' + name + ' feed failed (HTTP ' + res.status + ') — ' + what + ' may be stale or missing.';
      }
      wrap.appendChild(el('p', {
        'class': 'plan-tree-degraded', role: 'status',
        'data-feed': name, 'data-feed-reason': code, text: msg
      }));
    });
  }
  function planTreeRowInner(node) {
    var frag = [el('span', { 'class': 'plan-tree-type plan-tree-type-' + node.type, text: node.type })];
    frag.push(el('span', { 'class': 'plan-tree-label', text: node.label }));
    if (node.state) { frag.push(el('span', { 'class': 'plan-tree-state', text: node.state })); }
    if (node.progress) {
      frag.push(el('span', { 'class': 'plan-tree-prog', text: node.progress.done + '/' + node.progress.total + (node.progress.label ? (' · ' + node.progress.label) : '') }));
    }
    // M4c: stale-plan hash chip. provenance = daemon hash short-form (no local
    // copy to compare); mismatch = a visible drift badge (T.2 guard).
    if (node.planBadge) {
      var pb = node.planBadge;
      var hashCls = pb.kind === 'mismatch' ? 'plan-tree-hash plan-tree-hash-mismatch'
        : (pb.kind === 'insync' ? 'plan-tree-hash plan-tree-hash-insync' : 'plan-tree-hash plan-tree-hash-prov');
      frag.push(el('span', { 'class': hashCls, 'data-hash-state': pb.code, title: pb.title, text: pb.label }));
    }
    if (node.sub) { frag.push(el('span', { 'class': 'plan-tree-sub', text: node.sub })); }
    if (node.type === 'session' && node.focus) {
      // Unattached: show the slug that resolved to no plan (which plan failed).
      if (node.unresolvedSlug) { frag.push(el('span', { 'class': 'plan-tree-focus plan-tree-unresolved', title: 'announced execplan_slug resolved to no work item', text: 'unresolved: ' + node.unresolvedSlug })); }
      if (node.focus.milestone) { frag.push(el('span', { 'class': 'plan-tree-focus', text: '@' + node.focus.milestone })); }
      if (node.focus.deploy_target) { frag.push(el('span', { 'class': 'plan-tree-focus', text: node.focus.deploy_target })); }
      (node.focus.paths || []).slice(0, 4).forEach(function (p) { frag.push(el('span', { 'class': 'plan-tree-path', text: p })); });
    }
    (node.leases || []).slice(0, 4).forEach(function (l) {
      frag.push(el('span', {
        'class': 'plan-tree-lease',
        title: 'lease · ' + (l.mode || 'modify') + (l.reason ? (' · ' + l.reason) : ''),
        text: 'lease: ' + (l.resource || l.punchcard_id || 'held')
      }));
    });
    return frag;
  }
  function planTreeNode(node, depth, onSelect) {
    var pad = (depth * 14 + 8) + 'px';
    var rowCls = 'plan-tree-row plan-tree-' + node.type;
    if (node.children && node.children.length) {
      var det = el('details', { 'class': 'plan-tree-node', open: 'open' });
      det.appendChild(el('summary', { 'class': rowCls, style: 'padding-left:' + pad }, planTreeRowInner(node)));
      node.children.forEach(function (c) { det.appendChild(planTreeNode(c, depth + 1, onSelect)); });
      return det;
    }
    // M4b: a session leaf opens its evidence detail on click/Enter/Space. Kept
    // behind the optional onSelect so the smoke can still paint a node with no
    // handler (and non-session leaves stay inert).
    if (node.type === 'session' && typeof onSelect === 'function') {
      var srow = el('div', { 'class': rowCls + ' plan-tree-session-open', style: 'padding-left:' + pad,
        role: 'button', tabindex: '0', 'aria-label': 'View session evidence: ' + (node.label || node.id || 'session') }, planTreeRowInner(node));
      srow.addEventListener('click', function () { onSelect(node); });
      srow.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(node); } });
      return srow;
    }
    return el('div', { 'class': rowCls, style: 'padding-left:' + pad }, planTreeRowInner(node));
  }
  function renderPlanTree(host, ctx) {
    host.textContent = '';
    var wrap = el('div', { 'class': 'plan-tree' }, [el('p', { 'class': 'ctl-desc', text: 'Building plan tree…' })]);
    host.appendChild(wrap);
    var api = (typeof window !== 'undefined') ? window.CruxApi : null;
    // /v1/work?source=all is a PARAMETERISED read → the named CruxApi.work({source})
    // method (CruxApi.get's literal allowlist rejects a query string). /v1/coord/
    // active is a literal read → fetchJSON. Both go through the generated client.
    return Promise.all([
      fetchJSON('/v1/projects'),
      fetchVia(api && typeof api.work === 'function' ? function () { return api.work({ source: 'all' }); } : null),
      fetchJSON('/v1/coord/active')
    ]).then(function (r) {
      var projRes = r[0], workRes = r[1], coordRes = r[2];
      var tree = buildPlanTree({
        projects: (projRes.ok && projRes.data) || null,
        work: (workRes.ok && workRes.data) || null,
        sessions: (coordRes.ok && coordRes.data) || null,
        // M5a: the desktop shell computes local BLAKE3 plan hashes and injects
        // them as a read-only global before page load (not IPC). Browser-only
        // users have it undefined → the badge stays provenance-only (M4c).
        localPlanHashes: (typeof window !== 'undefined' && window.CRUX_LOCAL_PLAN_HASHES) || null
      });
      wrap.textContent = '';
      // Fail honest PER FEED — a degraded notice renders whenever a feed failed,
      // even alongside a healthy tree. Without it, coord-off looks like "no
      // sessions" and a work 500 falsely marks every session unattached.
      appendFeedNotices(wrap, [
        ['work', workRes, 'ExecPlan + work items'],
        ['projects', projRes, 'project grouping'],
        ['coord', coordRes, 'live sessions, announced focus + leases']
      ]);
      if (!tree.roots.length) {
        var why = !workRes.ok
          ? (workRes.status === 0 ? 'work feed unreachable' : ('work feed unavailable — HTTP ' + workRes.status))
          : 'no plans or live sessions';
        wrap.appendChild(el('p', { 'class': 'ctl-desc', text: 'Plan tree empty — ' + why + '.' }));
        return;
      }
      // M4b: split into the tree column + a session-detail column. Clicking a
      // session paints its evidence (receipts, fact provenance, announced focus)
      // through the generated client. Notices stay above the split (fail-honest).
      var layout = el('div', { 'class': 'plan-tree-layout' });
      var treeCol = el('div', { 'class': 'plan-tree-col' });
      var detailCol = el('div', { 'class': 'session-detail-col' },
        [el('p', { 'class': 'ctl-desc', text: 'Select a session to view its evidence — receipts, fact provenance, announced focus.' })]);
      function onSelect(node) { renderSessionDetail(detailCol, node, api); }
      tree.roots.forEach(function (root) { treeCol.appendChild(planTreeNode(root, 0, onSelect)); });
      layout.appendChild(treeCol);
      layout.appendChild(detailCol);
      wrap.appendChild(layout);
    }).catch(function () {
      wrap.textContent = '';
      wrap.appendChild(el('p', { 'class': 'ctl-desc', text: 'Plan tree unavailable.' }));
    });
  }

  // ---- Session-detail / evidence contract (M4b) ---------------------------
  // Clicking a session opens an authorized/redacted evidence view over EXISTING
  // daemon GET routes only — NO new routes, NO hand-rolled fetches, and reads that
  // could carry content are NOT issued at all:
  //   · announced focus ← coord/active (travels WITH the sessionNode from M4a; no re-fetch)
  //   · receipts        ← GET /v1/sessions/{id}/observations (each record carries a
  //                       CROWN receipt ENVELOPE + the daemon-reported chain status)
  //   · fact provenance ← GET /v1/facts/entity/<resolved-execplan-entity> — ONLY when
  //                       the session resolved to an ExecPlan item (M4a resolution; a
  //                       kanban/unattached session carries no entity → no-plan absent)
  //   · transcript      ← REFERENCE-ONLY: rendered ONLY from an id/path ALREADY loaded
  //                       on the sessionNode (coord announcement field). We do NOT fetch
  //                       session state — that blob could embed transcript CONTENT, and
  //                       fetching-then-filtering still transits content to page JS. No
  //                       transcript-content route/method exists and none is added. Any
  //                       API-supplied path renders as inert text, never a link.
  // Honesty rules: any non-ok feed → degraded notice (M4a idiom); reachable-but-empty
  // (200 + empty) → absent-state (M2 disabled-with-reason idiom). No silent empties.
  // Badges never claim a cryptographic property the client did not verify.
  function shortHash(h) { return String(h || '').replace(/^blake3:/, '').slice(0, 12); }

  // A non-ok read (unreachable / HTTP error) → degraded. Reachable-but-empty is
  // NOT this — the caller renders that as an absent-state after confirming status.ok.
  function evidenceDegraded(status, what) {
    var s = status && status.status;
    if (s === 0 || s == null) { return { code: 'unreachable', degraded: true, reason: what + ' — feed unreachable.' }; }
    return { code: 'http_' + s, degraded: true, reason: what + ' — feed failed (HTTP ' + s + ').' };
  }

  function evidenceReceipts(observations, status) {
    var chain = (observations && observations.chain) || null;
    if (!status || !status.ok) {
      return { present: false, items: [], chain: chain, absent: evidenceDegraded(status, 'Receipts') };
    }
    var list = (observations && observations.observations) || [];
    if (!list.length) {
      return { present: false, items: [], chain: chain,
        absent: { code: 'empty', degraded: false, reason: 'No receipts recorded for this session.' } };
    }
    var items = list.slice(0, 50).map(function (o) {
      var r = o.receipt || {};
      // Structural fields ONLY — a receipt envelope is PRESENT. We do not verify the
      // Ed25519 signature in the browser, so nothing here asserts "signed"/"valid".
      return { observation_id: o.observation_id || null, provider: o.provider || null, kind: o.kind || null,
        ts: o.ts || null, seq: (o.seq == null ? null : o.seq),
        alg: r.alg || null, body_hash: r.body_hash || null };
    });
    return { present: true, items: items, chain: chain, absent: null };
  }

  // entity = the RESOLVED ExecPlan entity stamped by buildPlanTree (null for a
  // kanban/unattached session — never guessed from the announced slug, which could
  // point at a kanban item and fetch unrelated facts).
  function evidenceProvenance(facts, status, entity) {
    if (!entity) {
      return { present: false, entity: null, items: [],
        absent: { code: 'no_plan', degraded: false, reason: 'This session did not resolve to an ExecPlan — fact provenance is keyed by plan entity, so none can be resolved.' } };
    }
    if (!status || !status.ok) {
      return { present: false, entity: entity, items: [], absent: evidenceDegraded(status, 'Fact provenance for ' + entity) };
    }
    var list = (facts && facts.facts) || [];
    if (!list.length) {
      return { present: false, entity: entity, items: [],
        absent: { code: 'empty', degraded: false, reason: 'No facts recorded under ' + entity + '.' } };
    }
    var items = list.slice(0, 50).map(function (f) {
      // ONLY a canonical [REDACTED:…] marker is a redaction (redact_writer.rs). A
      // genuinely empty value is honest-empty — not a redaction claim.
      var redacted = (typeof f.value === 'string' && f.value.indexOf('[REDACTED:') === 0);
      return { key: f.key || null, stored_at: f.stored_at || null, actor: f.actor || null,
        source_receipt: f.source_receipt || null, version: (f.version == null ? null : f.version),
        superseded: !!f.superseded_by, private: !!f.private, redacted: redacted };
    });
    return { present: true, entity: entity, items: items, absent: null };
  }

  // Pure model builder — DOM-free so the smoke can assert the contract directly.
  function buildSessionDetail(input) {
    input = input || {};
    var session = input.session || {};
    var focus = session.focus || {};
    var focusModel = {
      execplan_slug: focus.execplan_slug || null, milestone: focus.milestone || null,
      deploy_target: focus.deploy_target || null,
      paths: Array.isArray(focus.paths) ? focus.paths : [],
      leases: Array.isArray(session.leases) ? session.leases : [],
      unresolvedSlug: session.unresolvedSlug || null
    };
    // Transcript reference — ONLY from data ALREADY loaded on the node (a coord
    // announcement field). No session-state fetch: that blob can embed content, and
    // content must never transit to page JS even to be filtered out.
    var tref = (focus.transcript_ref || session.transcriptRef || null);
    var transcript = tref ? { present: true, ref: String(tref) } : { present: false };

    return {
      sessionId: session.id || null, label: session.label || session.id || 'session',
      focus: focusModel, transcript: transcript,
      receipts: evidenceReceipts(input.observations, input.obsStatus),
      provenance: evidenceProvenance(input.facts, input.factsStatus, input.entity || null)
    };
  }

  function paintEvidenceSection(title, sec, itemFn, headBadge) {
    var s = el('div', { 'class': 'session-detail-sec' });
    var h = el('div', { 'class': 'session-detail-sec-h', text: title });
    s.appendChild(h);
    if (sec && sec.present) {
      if (headBadge) { var b = headBadge(sec); if (b) { h.appendChild(b); } }
      (sec.items || []).forEach(function (it) { s.appendChild(itemFn(it)); });
    } else {
      var a = (sec && sec.absent) || { code: 'unknown', degraded: false, reason: 'No data.' };
      s.appendChild(el('p', {
        'class': a.degraded ? 'session-detail-degraded' : 'session-detail-absent', role: 'status',
        'data-feed-reason': a.code, 'data-capability-reason': a.code, text: a.reason
      }));
    }
    return s;
  }

  function paintSessionDetail(model) {
    var root = el('div', { 'class': 'session-detail' });
    var head = el('div', { 'class': 'session-detail-head' });
    head.appendChild(el('div', { 'class': 'session-detail-title', text: 'Session ' + (model.label || model.sessionId || '—') }));
    var chips = el('div', { 'class': 'session-detail-chips' });
    var f = model.focus || {};
    if (f.execplan_slug) { chips.appendChild(el('span', { 'class': 'plan-tree-focus', text: f.execplan_slug })); }
    if (f.milestone) { chips.appendChild(el('span', { 'class': 'plan-tree-focus', text: '@' + f.milestone })); }
    if (f.deploy_target) { chips.appendChild(el('span', { 'class': 'plan-tree-focus', text: f.deploy_target })); }
    if (f.unresolvedSlug) { chips.appendChild(el('span', { 'class': 'plan-tree-focus plan-tree-unresolved', text: 'unresolved: ' + f.unresolvedSlug })); }
    // Declared paths + leases are API-supplied strings → TEXT only, never links.
    (f.paths || []).slice(0, 8).forEach(function (p) { chips.appendChild(el('span', { 'class': 'plan-tree-path', text: p })); });
    (f.leases || []).slice(0, 8).forEach(function (l) { chips.appendChild(el('span', { 'class': 'plan-tree-lease', title: 'lease · ' + (l.mode || 'modify'), text: 'lease: ' + (l.resource || l.punchcard_id || 'held') })); });
    head.appendChild(chips);
    root.appendChild(head);

    // Transcript — reference-only inert chip (or an explicit absent-state).
    var tsec = el('div', { 'class': 'session-detail-sec' });
    tsec.appendChild(el('div', { 'class': 'session-detail-sec-h', text: 'Transcript' }));
    if (model.transcript && model.transcript.present) {
      tsec.appendChild(el('span', { 'class': 'session-detail-transcript-ref', 'data-inert': 'reference-only',
        title: 'reference only — transcript content is never fetched or rendered', text: model.transcript.ref }));
    } else {
      tsec.appendChild(el('p', { 'class': 'session-detail-absent', 'data-capability-reason': 'no_transcript_ref',
        role: 'status', text: 'No transcript reference on this session.' }));
    }
    root.appendChild(tsec);

    root.appendChild(paintEvidenceSection('Receipts', model.receipts, function (r) {
      // data-receipt-body-hash is a plain hook for the M9 registry verification
      // link-out — NOT a client-side attestation. No "signed"/"valid" claim: the
      // browser did not verify the Ed25519 signature.
      var item = el('div', { 'class': 'session-detail-item', 'data-receipt-body-hash': (r.body_hash || null) });
      item.appendChild(el('span', { 'class': 'session-detail-k', text: (r.provider || 'obs') + (r.kind ? (' · ' + r.kind) : '') }));
      if (r.body_hash) { item.appendChild(el('span', { 'class': 'session-detail-hash', text: shortHash(r.body_hash) })); }
      item.appendChild(el('span', { 'class': 'session-detail-badge', title: 'a signed receipt envelope is attached (signature not verified in the browser)', text: 'receipt envelope' }));
      if (r.ts) { item.appendChild(el('span', { 'class': 'session-detail-k', text: r.ts })); }
      return item;
    }, function (sec) {
      // The daemon-REPORTED chain status, VERBATIM. Neutral chip — this is data the
      // daemon returned, not a verdict the client computed.
      if (!sec.chain || !sec.chain.status) { return null; }
      return el('span', { 'class': 'session-detail-badge', 'data-chain-status': sec.chain.status,
        title: (sec.chain.reason ? (sec.chain.reason + ' — ') : '') + 'chain status as reported by the daemon (not verified in the browser)',
        text: 'chain: ' + sec.chain.status });
    }));

    root.appendChild(paintEvidenceSection('Fact provenance' + (model.provenance.entity ? (' · ' + model.provenance.entity) : ''),
      model.provenance, function (fct) {
        var item = el('div', { 'class': 'session-detail-item' });
        item.appendChild(el('span', { 'class': 'session-detail-k', text: fct.key || '(key)' }));
        if (fct.version != null) { item.appendChild(el('span', { 'class': 'session-detail-badge', text: 'v' + fct.version })); }
        if (fct.actor) { item.appendChild(el('span', { 'class': 'session-detail-k', text: 'by ' + fct.actor })); }
        if (fct.source_receipt) { item.appendChild(el('span', { 'class': 'session-detail-hash', text: 'receipt ' + shortHash(fct.source_receipt) })); }
        if (fct.stored_at) { item.appendChild(el('span', { 'class': 'session-detail-k', text: fct.stored_at })); }
        if (fct.redacted) { item.appendChild(el('span', { 'class': 'session-detail-redacted', 'data-capability-reason': 'redacted', text: '[redacted]' })); }
        if (fct.superseded) { item.appendChild(el('span', { 'class': 'session-detail-badge warn', text: 'superseded' })); }
        return item;
      }, null));

    return root;
  }

  // Fetch the evidence through the generated client and paint it. Reads ONLY two
  // content-free feeds: observations (receipt envelopes) and — only for an ExecPlan-
  // resolved session — facts/entity (provenance). The transcript reference comes from
  // data already on the node; the session-state blob is never read (it can embed content).
  // A per-host selection token drops a stale paint when a newer session is clicked
  // mid-flight (slow A must not overwrite the freshly-selected B).
  function renderSessionDetail(host, sessionNode, api) {
    var seq = (host._detailSeq = (host._detailSeq || 0) + 1);
    host.textContent = '';
    api = api || ((typeof window !== 'undefined') ? window.CruxApi : null);
    sessionNode = sessionNode || {};
    var sid = sessionNode.id;
    var entity = sessionNode.execplanEntity || null;   // set by buildPlanTree only for ExecPlan-resolved sessions
    host.appendChild(el('p', { 'class': 'ctl-desc', text: 'Loading session evidence…' }));
    return Promise.all([
      fetchVia(sid && api && typeof api.sessionsBySessionIdObservations === 'function' ? function () { return api.sessionsBySessionIdObservations(sid); } : null),
      fetchVia(entity && api && typeof api.factsEntityByEntity === 'function' ? function () { return api.factsEntityByEntity(entity); } : null)
    ]).then(function (r) {
      if (host._detailSeq !== seq) { return; }   // superseded by a newer selection — drop this paint
      var model = buildSessionDetail({
        session: sessionNode, entity: entity,
        observations: r[0].data, obsStatus: r[0],
        facts: r[1].data, factsStatus: r[1]
      });
      host.textContent = '';
      host.appendChild(paintSessionDetail(model));
    }).catch(function () {
      if (host._detailSeq !== seq) { return; }
      host.textContent = '';
      host.appendChild(el('p', { 'class': 'ctl-desc', text: 'Session evidence unavailable.' }));
    });
  }

  function renderCanvas(host, ctx) {
    ctx = ctx || {};
    var view = ctx.view === 'graph' ? 'graph' : (ctx.view === 'tree' ? 'tree' : 'board');
    host.textContent = '';
    var region = el('div', { 'class': 'canvas-region' });
    var seg = el('div', { 'class': 'modeseg canvas-seg', role: 'group', 'aria-label': 'Canvas view' });
    [['board', 'Board'], ['graph', 'Graph'], ['tree', 'Tree']].forEach(function (v) {
      var b = el('button', { 'class': 'modeseg-btn', type: 'button', 'data-view': v[0], 'aria-pressed': v[0] === view ? 'true' : 'false' }, [v[1]]);
      (function (vid) { b.addEventListener('click', function () { location.hash = '#/canvas/' + vid; }); })(v[0]);
      seg.appendChild(b);
    });
    region.appendChild(el('div', { 'class': 'canvas-head' }, [seg]));
    var body = el('div', { 'class': 'canvas-body' });
    region.appendChild(body);
    host.appendChild(region);
    if (view === 'graph') { return renderCanvasGraph(body, ctx, ctx.focus); }
    if (view === 'tree') { return renderPlanTree(body, ctx); }
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
  // Explore-rail glyphs, drawn in the SAME line-icon style as the Command rail
  // (viewBox 0 0 24 24, stroke currentColor, stroke-width 1.8, round caps) so the
  // two menus read as one family. Keyed by surface id (+ 'explorer' for the pin).
  var SURFACE_ICONS = {
    canvas: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="8" height="8" rx="1.5"/><rect x="15" y="3" width="6" height="11" rx="1.5"/><rect x="3" y="15" width="11" height="6" rx="1.5"/><rect x="18" y="18" width="3" height="3" rx="1"/></svg>',
    explorer: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>',
    proof: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M6 3h8l4 4v13a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z"/><path d="M14 3v4h4"/><path d="M8.5 13.6l2.2 2.2 4-4.3"/></svg>',
    watch: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>',
    ask: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 4H4a1 1 0 0 0-1 1v11a1 1 0 0 0 1 1h3v4l5-4h8a1 1 0 0 0 1-1V5a1 1 0 0 0-1-1z"/><path d="M9.6 9.2a2.4 2.4 0 0 1 4.7.7c0 1.6-2.3 1.9-2.3 3.1"/><circle cx="12" cy="15.4" r=".6" fill="currentColor" stroke="none"/></svg>',
    living: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2.6l8 4.4v9.9l-8 4.5-8-4.5V7z"/><path d="M12 12.1l8-4.5M12 12.1v9.8M12 12.1L4 7.6"/></svg>',
    deps: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="6.5" r="2.4"/><circle cx="18" cy="7.5" r="2.4"/><circle cx="12" cy="18" r="2.4"/><path d="M8.1 7.6l2.6 8M15.8 9.3l-2.5 6.9"/></svg>',
    signals: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2.5L4.5 13.5H11l-1 8 8.5-11.5H12z"/></svg>',
    diff: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M8 5L3.5 9.5 8 14"/><path d="M3.5 9.5H15"/><path d="M16 10l4.5 4.5L16 19"/><path d="M20.5 14.5H9"/></svg>',
    sourcing: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M14.8 9.2l-2 5.6-5.6 2 2-5.6z"/></svg>',
    lanes: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M4 12h16M4 17h16"/><circle cx="8" cy="7" r="1.35" fill="currentColor" stroke="none"/><circle cx="15" cy="12" r="1.35" fill="currentColor" stroke="none"/><circle cx="10" cy="17" r="1.35" fill="currentColor" stroke="none"/></svg>',
    domains: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9.5l9-5.5 9 5.5"/><path d="M5 9.5V18M9.5 9.5V18M14.5 9.5V18M19 9.5V18"/><path d="M3.5 18h17"/></svg>',
    reverse: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 12a8 8 0 1 0 2.3-5.6"/><path d="M4 4.5V9h4.5"/></svg>'
  };
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
    activityRows({ tenant_id: 'default', token_budget: 1500 }).then(function (res) {
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

  // Coverage band label from a 0..1 score (retrieval coverage → High/Medium/Low).
  function covBandLabel(score) { var s = Number(score) || 0; return s > 0.66 ? 'High' : (s > 0.33 ? 'Medium' : 'Low'); }

  // ---- 3 · Ask (real: /v1/query/text-search — retrieval + coverage) --------
  // Ask runs a live BM25 retrieval over the local corpus (the same read-POST the
  // Explorer uses) and shows REAL coverage + evidence hits. Answer COMPOSITION
  // (claims · verdict · narrative) needs the reasoning engine, which the community
  // daemon doesn't ship — that canvas stays an honest demoOn() preview.
  function renderDocSurface_ask(main, ctx) {
    docSurfaceHead(main, '◇', 'Ask', 'Query the corpus — real BM25 retrieval + coverage; every hit receipt-addressable.');
    var bar = el('div', { 'class': 'doc-card', style: 'display:flex;gap:10px;align-items:center;' });
    var input = el('input', { 'class': 'ctl-input', type: 'text', placeholder: 'Ask the corpus…', style: 'flex:1;min-width:0;' });
    var runBtn = el('button', { 'class': 'btn-quiet', type: 'button' }, ['Ask']);
    bar.appendChild(input); bar.appendChild(runBtn);
    main.appendChild(bar);
    var out = el('div', { 'class': 'doc-ev-host' });
    main.appendChild(out);

    function askDemoCanvas(host, note) {
      var d = surfaceDemo('ask');
      if (!d) { docSurfaceEmpty(host, note || 'Type a question to run a live retrieval. Enable demo data (?demo=1) to preview the verified-answer canvas.'); return; }
      host.appendChild(docSection('Verified-answer canvas · preview'));
      host.appendChild(el('div', { 'class': 'doc-chips' }, [docModeTag(d.mode || 'verified'), docBandBadge(d.cov && d.cov.label, d.cov && d.cov.score), demoChip(true)]));
      host.appendChild(el('div', { 'class': 'doc-card' }, [el('div', { 'class': 'doc-row-text', text: d.query })]));
      var ans = el('div', { 'class': 'doc-card' });
      (d.paragraphs || []).forEach(function (p) { ans.appendChild(el('p', { 'class': 'doc-chunk-text', text: p })); });
      host.appendChild(ans);
      host.appendChild(docSection('Claims (' + (d.claims || []).length + ')'));
      (d.claims || []).forEach(function (cl) {
        host.appendChild(el('div', { 'class': 'doc-claim-row' }, [docDot(cl.status === 'contested' ? 'warn' : 'ok'), el('span', { 'class': 'doc-row-text', text: cl.text }), el('span', { 'class': 'doc-chunk-claims', text: cl.id })]));
      });
      host.appendChild(el('p', { 'class': 'ctl-desc', text: 'Claim ↔ evidence composition needs the reasoning engine (not in the community daemon).' }));
    }

    function run() {
      var q = String(input.value || '').trim();
      if (!q) { return; }
      out.textContent = '';
      out.appendChild(el('p', { 'class': 'ctl-desc', text: 'Retrieving…' }));
      readPost('queryTextSearch', { query: q, tenant_id: 'default', token_budget: 1500 }).then(function (res) {
        out.textContent = '';
        var d = (res.ok && res.data) ? res.data : null;
        var hits = (d && (d.results || d.hits)) || [];
        if (!d || !hits.length) {
          var why;
          if (res.status === 0) { why = 'Retrieval unreachable.'; }
          else if (!res.ok) { why = 'Retrieval lane unavailable' + (res.data && res.data.detail ? ' — ' + res.data.detail : ' (CORECRUXD_QUERY_TEXT_SEARCH)') + '.'; }
          else { why = 'No hits for "' + q + '".'; }
          out.appendChild(el('p', { 'class': 'ctl-desc', text: why }));
          askDemoCanvas(out, 'No live results. Enable demo data (?demo=1) to preview the verified-answer canvas.');
          return;
        }
        var cov = d.coverage || {};
        out.appendChild(docSection('Coverage · /v1/query/text-search'));
        var covCard = el('div', { 'class': 'doc-card' }, [docBandBadge(covBandLabel(cov.score), cov.score)]);
        if (cov.score != null) { covCard.appendChild(docCovBar('retrieval', cov.score)); }
        if (cov.below_floor) { covCard.appendChild(el('div', { 'class': 'doc-cov doc-cov-warn', text: cov.below_floor + ' hit(s) below the score floor' })); }
        out.appendChild(covCard);
        out.appendChild(docSection('Evidence (' + hits.length + ')'));
        hits.slice(0, 20).forEach(function (h) {
          out.appendChild(docEvidenceCard({
            role: 'support',
            domain: h.source_label || 'local_tenant_index',
            summary: h.result_id || ((h.segment_index != null ? h.segment_index : '?') + ':' + (h.doc_id != null ? h.doc_id : '?')),
            source: h.score_space || 'bm25-lexical',
            score: h.score
          }));
        });
        out.appendChild(el('p', { 'class': 'ctl-desc', text: 'Local BM25 hits carry an id + score, not stored text. Answer composition (claims · verdict) needs the reasoning engine.' }));
      });
    }
    runBtn.addEventListener('click', run);
    input.addEventListener('keydown', function (e) { if (e.key === 'Enter') { run(); } });
    // Before the first query, show the honest demo canvas (or an empty prompt).
    askDemoCanvas(out, null);
  }

  // ---- 4 · Living Objects (real: /v1/admin/projections/artifacts/{id}/*) ---
  // A living object IS an artefact's epistemic projection: living_status,
  // confidence, pressure, trunk tier, relations, and dependents — where a
  // dependent typed "mises" is a Minimal Sufficient Evidence Set that cited this
  // artefact. There is no artefact-LIST route (enumeration is per-id, as in
  // WebCrux), so the surface hydrates one artefact id at a time from the four
  // projection reads. Those reads are dataplane-gated (501 "dataplane disabled"
  // on the CPU-only community daemon) → the surface degrades honestly and shows
  // the demoOn()-chipped sample so the shape is still legible.
  function livingRelTone(t) { t = String(t || ''); return t.indexOf('contradict') >= 0 ? 'crit' : (t === 'supports' || t === 'supersedes' ? 'ok' : ''); }
  function renderDocSurface_living(main, ctx) {
    docSurfaceHead(main, '⬡', 'Living Objects', 'Artefacts with epistemic state, pressure, relations, and dependents (incl. MiSES — evidence sets that cite them).');
    var bar = el('div', { 'class': 'doc-card', style: 'display:flex;gap:10px;align-items:center;' });
    var input = el('input', { 'class': 'ctl-input', type: 'text', placeholder: 'Artefact id (e.g. 42)…', style: 'flex:1;min-width:0;' });
    var loadBtn = el('button', { 'class': 'btn-quiet', type: 'button' }, ['Load']);
    bar.appendChild(input); bar.appendChild(loadBtn);
    applyCapabilityGate(bar, 'documents.living.load');
    main.appendChild(bar);
    main.appendChild(el('p', { 'class': 'ctl-desc', text: 'Hydrates state · relations · dependents · pressure from /v1/admin/projections/artifacts/{id}/* (a projections/dataplane capability).' }));
    var out = el('div', { 'class': 'doc-ev-host' });
    main.appendChild(out);

    // The demoOn() sample list — legible shape when there is no live projection.
    function livingDemo(host, note) {
      var list = surfaceDemo('living');
      if (!list || !list.length) { docSurfaceEmpty(host, note || 'Enter an artefact id to hydrate a living object, or enable demo data (?demo=1) to preview artefact state + pressure.'); return; }
      host.appendChild(docSection('Sample artefacts · demo'));
      host.appendChild(demoChip(true));
      list.forEach(function (a) {
        host.appendChild(docListCard({
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
              body.appendChild(el('div', { 'class': 'doc-card' }, [el('div', { 'class': 'doc-chips' }, [docBadge(r.type.replace(/_/g, ' '), livingRelTone(r.type)), docBadge(r.method, '')]), el('div', { 'class': 'doc-row-title', text: r.target }), el('div', { 'class': 'doc-row-text', text: 'confidence ' + Math.round(r.confidence * 100) + '%' })]));
            });
            body.appendChild(docSection('Version chain'));
            a.versions.forEach(function (v, i) { body.appendChild(el('div', { 'class': 'doc-receipt' }, [docDot(i === 0 ? 'ok' : ''), el('span', { 'class': 'doc-receipt-label', text: v.v }), el('span', { 'class': 'doc-receipt-ts', text: v.date + ' · ' + v.hash })])); });
          }
        }));
      });
    }

    function load() {
      var id = String(input.value || '').trim();
      if (!id) { return; }
      out.textContent = '';
      out.appendChild(el('p', { 'class': 'ctl-desc', text: 'Loading artefact ' + id + '…' }));
      var q = { tenant_id: 'default' };
      Promise.all([
        projCall('adminProjectionsArtifactsByArtifactIdState', id, q),
        projCall('adminProjectionsArtifactsByArtifactIdDependents', id, { tenant_id: 'default', limit: 200 }),
        projCall('adminProjectionsArtifactsByArtifactIdRelations', id, { tenant_id: 'default', direction: 'out', limit: 200 }),
        projCall('adminProjectionsArtifactsByArtifactIdPressureEvents', id, { tenant_id: 'default', limit: 200 })
      ]).then(function (rs) {
        out.textContent = '';
        var st = rs[0];
        if (!st.ok) {
          var why = st.status === 0 ? 'Projections unreachable.'
            : ('Living-object projections unavailable' + (st.data && st.data.detail ? ' — ' + st.data.detail : '') + '.');
          out.appendChild(el('div', { 'class': 'doc-cov doc-cov-warn', text: why }));
          livingDemo(out, 'Living-object projections need a dataplane build. Enable demo data (?demo=1) to preview artefact state + pressure.');
          return;
        }
        var s = st.data || {};
        if (!s.present) { out.appendChild(el('p', { 'class': 'ctl-desc', text: 'No living object recorded for artefact ' + id + '.' })); livingDemo(out); return; }
        var deps = (rs[1].data && rs[1].data.dependents) || [];
        var evs = (rs[3].data && rs[3].data.events) || [];
        var rels = (rs[2].data && rs[2].data.relations) || [];
        var byType = { answer: 0, mises: 0, collection: 0, artifact: 0 };
        deps.forEach(function (d) { if (byType[d.dependent_type] == null) { byType[d.dependent_type] = 0; } byType[d.dependent_type]++; });
        var c = s.counts || {};
        out.appendChild(docSection('Living state · artefact ' + id + ' · /v1/admin/projections/artifacts/' + id));
        out.appendChild(el('div', { 'class': 'doc-chips' }, [
          docStatusChip(s.living_status || 'dormant'),
          docBandBadge(covBandLabel(s.confidence), s.confidence),
          s.trunk_tier != null ? docBadge('T' + s.trunk_tier, '') : null,
          s.pressure_level > 0 ? docBadge('⚡ P' + s.pressure_level, s.pressure_level >= 3 ? 'crit' : (s.pressure_level >= 2 ? 'warn' : '')) : null
        ].filter(Boolean)));
        out.appendChild(docTiles([
          [String(byType.answer), 'answers'], [String(byType.mises), 'mises'],
          [String(byType.collection), 'collections'], [String(c.relations_out || 0) + '/' + String(c.relations_in || 0), 'rel out/in']
        ]));
        if (evs.length) {
          out.appendChild(docSection('Pressure events (' + evs.length + ')'));
          evs.forEach(function (e) {
            var tone = e.severity >= 4 ? 'crit' : (e.severity >= 2 ? 'warn' : '');
            var card = el('div', { 'class': 'doc-card doc-strip doc-strip-' + tone }, [el('div', { 'class': 'doc-chips' }, [docBadge('code ' + e.pressure_code_id, tone), docBadge('severity ' + e.severity, tone), e.receipt_id ? docBadge('receipt', 'trust') : null].filter(Boolean))]);
            card.appendChild(el('div', { 'class': 'doc-cov doc-cov-' + (e.resolved_at_micros ? 'ok' : 'warn'), text: e.resolved_at_micros ? 'resolved' : 'open' }));
            out.appendChild(card);
          });
        }
        if (rels.length) {
          out.appendChild(docSection('Relations (' + rels.length + ')'));
          rels.forEach(function (r) {
            out.appendChild(el('div', { 'class': 'doc-card' }, [el('div', { 'class': 'doc-chips' }, [docBadge(String(r.relation_type).replace(/_/g, ' '), livingRelTone(r.relation_type)), docBadge('→ ' + r.dst_artifact_id, '')]), docCovBar('confidence', r.confidence)]));
          });
        }
        if (deps.length) {
          out.appendChild(docSection('Dependents (' + deps.length + ')'));
          deps.slice(0, 40).forEach(function (d) {
            out.appendChild(el('div', { 'class': 'doc-claim-row' }, [docDot(d.dependent_type === 'mises' ? 'ok' : ''), el('span', { 'class': 'doc-row-text', text: d.dependent_id }), el('span', { 'class': 'doc-chunk-claims', text: d.dependent_type })]));
          });
        }
      });
    }
    loadBtn.addEventListener('click', load);
    input.addEventListener('keydown', function (e) { if (e.key === 'Enter') { load(); } });
    livingDemo(out, null);
  }

  // ---- 5 · Dependencies (real: /v1/query/graph-expand) --------------------
  // Walk the relation graph from a seed artefact id: each node carries its hop
  // distance from the seed, the edge types traversed to reach it, and (when
  // include_state) its real living state + confidence. graph-expand is a
  // feature-flagged read-POST (CORECRUXD_QUERY_GRAPH_EXPAND); off/empty on the
  // community daemon → honest fallback to the assumption-loaded demo tree.
  function renderDocSurface_deps(main, ctx) {
    docSurfaceHead(main, '⬙', 'Dependencies', 'What an artefact rests on — real graph traversal: edge types, hop distance, and living state per node.');
    var bar = el('div', { 'class': 'doc-card', style: 'display:flex;gap:10px;align-items:center;' });
    var input = el('input', { 'class': 'ctl-input', type: 'text', placeholder: 'Seed artefact id(s), e.g. 42, 108…', style: 'flex:1;min-width:0;' });
    var runBtn = el('button', { 'class': 'btn-quiet', type: 'button' }, ['Expand']);
    bar.appendChild(input); bar.appendChild(runBtn);
    applyCapabilityGate(bar, 'documents.dependencies.expand');
    main.appendChild(bar);
    main.appendChild(el('p', { 'class': 'ctl-desc', text: 'Traverses the relation graph from your seed(s) via /v1/query/graph-expand (edge types · hops · living state).' }));
    var out = el('div', { 'class': 'doc-ev-host' });
    main.appendChild(out);

    function depsDemo(host, note) {
      var d = surfaceDemo('deps');
      if (!d || !d.root) { docSurfaceEmpty(host, note || 'Enter a seed artefact id to expand its dependency graph, or enable demo data (?demo=1) to preview the assumption-loaded tree.'); return; }
      host.appendChild(docSection('Assumption-loaded tree · demo'));
      host.appendChild(el('div', { 'class': 'doc-chips' }, [docBandBadge(null, d.root.confidence), docBadge('fragility ' + Math.round(d.root.fragility * 100) + '%', d.root.fragility > 0.5 ? 'crit' : 'warn'), demoChip(true)]));
      host.appendChild(el('div', { 'class': 'doc-card' }, [el('div', { 'class': 'doc-row-text', text: d.query })]));
      var assumptionTone = function (load) { return load <= 0.25 ? 'ok' : (load <= 0.5 ? 'warn' : 'crit'); };
      (function walkNode(node, depth) {
        var row = el('div', { 'class': 'doc-dep-node', style: 'margin-left:' + (depth * 16) + 'px' });
        row.appendChild(el('div', { 'class': 'doc-chips' }, [docDot(assumptionTone(node.assumptionLoad)), el('span', { 'class': 'doc-row-title', text: node.label }), node.trunkTier ? docBadge('T' + node.trunkTier, '') : null, docBadge(node.type, node.type === 'assumption' ? 'warn' : '')].filter(Boolean)));
        if (node.sublabel) { row.appendChild(el('div', { 'class': 'doc-row-text', text: node.sublabel })); }
        row.appendChild(docCovBar('confidence', node.confidence));
        host.appendChild(row);
        (node.children || []).forEach(function (c) { walkNode(c, depth + 1); });
      })(d.root, 0);
    }

    function run() {
      var raw = String(input.value || '').trim();
      if (!raw) { return; }
      var seeds = raw.split(/[,\s]+/).map(function (x) { return parseInt(x, 10); }).filter(function (n) { return !isNaN(n); });
      if (!seeds.length) { return; }
      out.textContent = '';
      out.appendChild(el('p', { 'class': 'ctl-desc', text: 'Expanding…' }));
      readPost('queryGraphExpand', { tenant_id: 'default', seed_artifact_ids: seeds, max_hops: 2, budget: 50, include_state: true }).then(function (res) {
        out.textContent = '';
        var d = (res.ok && res.data) ? res.data : null;
        var arts = (d && d.artifacts) || [];
        if (!d || !arts.length) {
          var why;
          if (res.status === 0) { why = 'Graph unreachable.'; }
          else if (!res.ok) { why = 'Graph-expand unavailable' + (res.data && res.data.detail ? ' — ' + res.data.detail : ' (CORECRUXD_QUERY_GRAPH_EXPAND)') + '.'; }
          else { why = 'No dependencies from seed(s) ' + seeds.join(', ') + '.'; }
          out.appendChild(el('div', { 'class': 'doc-cov doc-cov-warn', text: why }));
          depsDemo(out, 'No live graph. Enable demo data (?demo=1) to preview the assumption-loaded tree.');
          return;
        }
        var stats = d.traversal_stats || {};
        out.appendChild(docSection('Dependency graph · ' + arts.length + ' node(s) · /v1/query/graph-expand'));
        out.appendChild(el('div', { 'class': 'doc-chips' }, [docBadge('seeds ' + seeds.join(', '), 'trust'), docBadge((stats.hops_used != null ? stats.hops_used : '?') + ' hops', ''), docBadge((stats.edges_traversed != null ? stats.edges_traversed : '?') + ' edges', '')]));
        arts.slice().sort(function (a, b) { return (a.hop_distance || 0) - (b.hop_distance || 0); }).forEach(function (a) {
          var row = el('div', { 'class': 'doc-dep-node', style: 'margin-left:' + ((a.hop_distance || 0) * 16) + 'px' });
          var chips = [docDot(''), el('span', { 'class': 'doc-row-title', text: 'artefact ' + a.artifact_id }), docBadge('hop ' + (a.hop_distance != null ? a.hop_distance : '?'), '')];
          if (a.state && a.state.living_status) { chips.push(docStatusChip(a.state.living_status)); }
          if (a.state && a.state.trunk_tier != null) { chips.push(docBadge('T' + a.state.trunk_tier, '')); }
          (a.edge_types_used || []).forEach(function (et) { chips.push(docBadge(String(et).replace(/_/g, ' '), '')); });
          row.appendChild(el('div', { 'class': 'doc-chips' }, chips));
          if (a.state && a.state.confidence != null) { row.appendChild(docCovBar('confidence', a.state.confidence)); }
          else if (a.score != null) { row.appendChild(docCovBar('score', a.score)); }
          out.appendChild(row);
        });
      });
    }
    runBtn.addEventListener('click', run);
    input.addEventListener('keydown', function (e) { if (e.key === 'Enter') { run(); } });
    depsDemo(out, null);
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
    activityRows({ tenant_id: 'default', token_budget: 1500 }).then(function (res) {
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
    function navItem(label, iconKey, current, target) {
      var glyph = el('span', { 'class': 'nav-glyph', 'aria-hidden': 'true' });
      glyph.innerHTML = SURFACE_ICONS[iconKey] || '';   // inline SVG, Command-rail style
      var svg = glyph.querySelector && glyph.querySelector('svg');
      if (svg) { svg.setAttribute('width', '18'); svg.setAttribute('height', '18'); }
      var b = el('button', { 'class': 'nav-item', type: 'button', 'aria-current': current ? 'page' : 'false' }, [
        glyph, el('span', { 'class': 'label', text: label })
      ]);
      b.addEventListener('click', function () { location.hash = target; });
      host.appendChild(b);
    }
    // Canvas (M14 — the corpus tile landing) + Explorer + the surfaces all live
    // in one flat list (no group label). Icons are keyed by surface id
    // (Explorer uses the magnifier, matching Command).
    var isCanvas = (activeId === 'canvas');
    navItem('Canvas', 'canvas', isCanvas, '#/documents');
    navItem('Explorer', 'explorer', isExplorer, '#/documents/explorer');
    DOC_SURFACES.forEach(function (s) {
      navItem(s.label, s.id, !isExplorer && !isCanvas && s.id === activeSurface, '#/documents/' + s.id);
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

  // ---- Documents corpus canvas (M14) — the #/documents landing -----------
  // The corpus browsed as WebCrux tiles. The zero-network base set (bundled
  // reference docs + Explorer + the demo Proof doc when demo is on) paints
  // SYNCHRONOUSLY; live corpora / facts / receipts tiles land as their real
  // reads resolve and re-flow around any manually-placed tiles. Document tiles
  // navigate into the 3-zone reader (#/documents/<docId>); fact and receipt
  // tiles expand in place, surfacing REAL fields only (a receipt chip renders
  // only for a real receipt id). Presentation only — no posture side effects.
  function docCanvasBaseCards() {
    var cards = [
      { id: 'doc-intro', chromeless: true, shape: 'hero', size: 'md', accent: 'neutral',
        title: 'Documents',
        subtitle: 'the corpus as a canvas',
        body: 'Click a tile to read · drag a tile to place it · drag the canvas to pan.' },
      { id: 'doc-explorer', eyebrow: 'SEARCH · CORPUS', title: 'Explorer',
        subtitle: 'Local BM25 · WikiCrux mediated',
        body: 'Search the corpus — results open in the reader.',
        shape: 'square', size: 'md', accent: 'acc', routeLink: '#/documents/explorer' }
    ];
    DOC_REFERENCE.forEach(function (d, i) {
      cards.push({
        id: 'doc-ref-' + d.slug, eyebrow: 'DOCS · REFERENCE',
        title: d.title, subtitle: d.subtitle,
        body: (d.sections && d.sections[0] && d.sections[0].body && d.sections[0].body[0]) || null,
        shape: i === 0 ? 'hero' : 'wide', size: 'md', accent: 'trust',
        routeLink: '#/documents/ref:' + d.slug
      });
    });
    if (demoOn() && demoData('docsReader')) {
      cards.push({
        id: 'doc-demo-proof', eyebrow: 'PROOF · DEMO',
        title: 'Proof reader (demo)', subtitle: 'the full Proof composition — demo fixture',
        shape: 'wide', size: 'md', accent: 'warn', routeLink: '#/documents/demo:proof'
      });
    }
    return cards;
  }
  function renderDocCanvas(mount, ctx) {
    var cards = docCanvasBaseCards();
    var canvas = renderTileCanvas(mount, cards, { storeKey: 'documents' });
    var api = (typeof window !== 'undefined') ? window.CruxApi : null;
    // Live corpora — one tile per tenant (real list only; empty adds nothing).
    fetchVia(api && typeof api.consoleTenants === 'function' ? function () { return api.consoleTenants(); } : null)
      .then(function (res) {
        var tenants = (res.ok && res.data && (res.data.tenants || res.data.items)) || [];
        if (!tenants.length) { return; }
        __docCache.tenants = tenants;
        tenants.slice(0, 8).forEach(function (t) {
          var tid = t.tenant_id || t.id;
          if (tid == null || tid === '') { return; }
          cards.push({
            id: 'doc-tenant-' + tid, eyebrow: 'CORPUS · TENANT',
            title: String(tid),
            subtitle: t.chunk_count != null ? (t.chunk_count + ' chunks') : (t.category || null),
            body: 'What the daemon has read into this tenant.',
            shape: 'square', size: 'md', accent: 'ok',
            routeLink: '#/documents/tenant:' + tid
          });
        });
        canvas.relayout(cards);
      });
    // Related facts — expand in place to the full real value.
    fetchVia(api && typeof api.consoleFacts === 'function' ? function () { return api.consoleFacts({ top_k: 6 }); } : null)
      .then(function (res) {
        var facts = (res.ok && res.data && res.data.facts) || [];
        if (!facts.length) { return; }
        facts.slice(0, 6).forEach(function (f, i) {
          var paras = [];
          if (f.value != null) { paras.push(String(f.value)); }
          if (f.stored_at) { paras.push('stored ' + String(f.stored_at)); }
          cards.push({
            id: 'doc-fact-' + String(f.fact_id || f.id || i), eyebrow: 'MEMORY · FACT',
            title: String(f.entity || 'fact') + (f.key ? ' · ' + String(f.key) : ''),
            body: f.value != null ? String(f.value).slice(0, 140) : null,
            expandedParas: paras,
            shape: 'square', size: 'sm', accent: 'acc'
          });
        });
        canvas.relayout(cards);
      });
    // Receipt-backed activity — the chip carries the REAL receipt id.
    activityRows({ tenant_id: 'default', token_budget: 1500 }).then(function (res) {
      var rows = (res.ok && res.data && res.data.rows) || [];
      var seen = {}, added = 0;
      rows.forEach(function (r0) {
        var rid = (r0.receipt_ids || [])[0] || r0.receipt_id;
        if (!rid || seen[rid] || added >= 4) { return; }
        seen[rid] = true; added++;
        cards.push({
          id: 'doc-receipt-' + rid, eyebrow: 'TRUST · RECEIPT',
          title: (r0.kind || 'event') + (r0.tool ? ' · ' + r0.tool : ''),
          subtitle: r0.ts ? String(r0.ts) : null,
          body: r0.preview ? String(r0.preview).slice(0, 120) : null,
          expandedParas: [r0.preview ? String(r0.preview) : 'Receipt-backed activity event.'],
          chip: { id: rid, sig: 'ed25519' },
          shape: 'wide', size: 'sm', accent: 'ok'
        });
      });
      if (added) { canvas.relayout(cards); }
    });
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
      // M14 — the corpus tile canvas IS the #/documents landing (no docId, or
      // the explicit #/documents/canvas route). Reader docs stay at
      // #/documents/<docId>; the canvas paints its zero-network base set
      // synchronously, so the daemon-hang guarantee below still holds.
      if (raw == null || raw === '' || raw === 'canvas') {
        activeDocId = 'canvas';
        treeHosts = [];
        if (ctx.railHost) { buildDocTree(ctx.railHost, tenants, 'canvas'); treeHosts.push(ctx.railHost); }
        // doc-surface-wrap collapses the reader grid to one full-width column
        // (the canvas needs the whole measure; no evidence rail at base level).
        var cvReader = el('div', { 'class': 'doc-reader doc-surface-wrap doc-canvas-wrap' });
        var cvSheet = el('details', { 'class': 'doc-sources-sheet' });
        cvSheet.appendChild(el('summary', { 'class': 'doc-sources-summary', text: 'Surfaces & sources' }));
        var cvTree = el('div', { 'class': 'doc-tree' });
        buildDocTree(cvTree, tenants, 'canvas'); treeHosts.push(cvTree);
        cvSheet.appendChild(cvTree);
        cvReader.appendChild(cvSheet);
        var cvMain = el('main', { 'class': 'doc-canvas' });
        cvReader.appendChild(cvMain);
        host.appendChild(cvReader);
        renderDocCanvas(cvMain, ctx);
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

  // =======================================================================
  //  Activity log (Work › Activity) — the human-lane rolling activity log,
  //  ported from the standalone /console/activity into the v2 theme. Backfill
  //  via /v1/activity (through the client); row-expand derefs the turn's verbatim
  //  entries + Ed25519 receipt-verify badges via CruxApi.activityTurnByTurnId
  //  [/Verify]; live tail via EventSource on /v1/events/stream. Gated server-side
  //  by CORECRUXD_FEATURE_ACTIVITY_LOG (honest 404 copy when off).
  // =======================================================================
  var ACT_KINDS = ['question', 'answer', 'reasoning', 'command', 'fact', 'execplan', 'handoff', 'error'];
  var __actLogES = null;
  // /v1/activity is a parameterised read — use the named CruxApi.activity(query)
  // method (CruxApi.get only accepts literal, query-less allowlist paths).
  function activityBackfill(query) {
    var api = (typeof window !== 'undefined') ? window.CruxApi : null;
    if (!api || typeof api.activity !== 'function') { return Promise.resolve({ ok: false, status: 0, data: null }); }
    return api.activity(query).then(function (r) {
      return r.json().then(function (d) { return { ok: r.ok, status: r.status, data: d }; }, function () { return { ok: r.ok, status: r.status, data: null }; });
    }).catch(function () { return { ok: false, status: 0, data: null }; });
  }
  function activityTurnCall(method, turnId, query) {
    var api = (typeof window !== 'undefined') ? window.CruxApi : null;
    if (!api || typeof api[method] !== 'function') { return Promise.resolve({ ok: false, status: 0, data: null }); }
    return api[method](turnId, query).then(function (r) {
      return r.json().then(function (d) { return { ok: r.ok, status: r.status, data: d }; }, function () { return { ok: r.ok, status: r.status, data: null }; });
    }).catch(function () { return { ok: false, status: 0, data: null }; });
  }
  // =======================================================================
  //  Facts browser (console-surfaces-remediation M2) — the durable record,
  //  paged over GET /v1/facts/list. Custom-rendered (like the activity log)
  //  because the section model is a pure data→DOM transform: this surface needs
  //  server-side pagination + search (q=), an ingest-time as_of time-machine
  //  (as_of_unix_ms), and per-row detail that dereferences the FULL (untruncated)
  //  value by id. Every read routes through the generated client (fetchJSON +
  //  CruxApi.factsByFactId via fetchVia) — no raw network here. Degrades honestly
  //  on an older daemon (list route 404) to the recent-window console feed,
  //  banner-labelled.
  // =======================================================================
  var FACTS_PAGE_LIMIT = 100;      // rows per server page
  var FACTS_DOM_CAP = 2000;        // hard ceiling on rendered rows (never all-in)

  // Entity-prefix → the console's status/kind hue token (border-left tint).
  function factKindTone(prefix) {
    switch (prefix) {
      case 'execplan': return 'acc';
      case 'bench': return 'ok';
      case 'incident': return 'crit';
      case 'design': return 'trust';
      case 'session': return 'warn';
      default: return 'ink3';
    }
  }
  // Group key: the entity prefix up to the first ':' (execplan, bench, …);
  // reserved '__x::' entities group under their '__x::' stem; else 'other'.
  function factGroupKey(entity) {
    var e = String(entity || '');
    var m = e.match(/^([a-z0-9_]+):/i);
    if (m) { return m[1]; }
    var r = e.match(/^(__[a-z0-9_]+::)/i);
    if (r) { return r[1]; }
    return 'other';
  }
  function factGroupLabel(k) { return (/::$/.test(k)) ? k : (k === 'other' ? 'other' : k + ':*'); }

  function renderFactsBrowser(host) {
    host.textContent = '';
    function nfmt(n) {
      if (typeof n !== 'number' || !isFinite(n)) { return (n == null) ? '—' : String(n); }
      try { return n.toLocaleString('en-US'); } catch (e) { return String(n); }
    }
    function shortTime(iso) { var s = String(iso || ''); return s.length >= 16 ? s.slice(0, 16).replace('T', ' ') : (s || '—'); }
    function fmtConf(c) { return (typeof c === 'number' && isFinite(c)) ? c.toFixed(2) : '—'; }
    function prettyValue(v) {
      if (typeof v !== 'string') { try { return JSON.stringify(v, null, 2); } catch (e) { return String(v); } }
      var t = v.trim();
      if (t && (t.charAt(0) === '{' || t.charAt(0) === '[')) { try { return JSON.stringify(JSON.parse(v), null, 2); } catch (e) { return v; } }
      return v;
    }
    function qs(obj) {
      var parts = [];
      Object.keys(obj).forEach(function (k) { parts.push(encodeURIComponent(k) + '=' + encodeURIComponent(obj[k])); });
      return parts.join('&');
    }

    var state = {
      rows: [], seen: {}, groupBodies: {}, groupsExpanded: {},
      nextCursor: null, hasMore: false, totalVisible: null, totalNondeleted: null,
      census: null, q: '', entityPrefix: '',
      includeReserved: false, includeSuperseded: true, asOfMs: null,
      loading: false, fallback: false, deb: null, token: 0
    };

    // ---- toolbar ----
    var searchInput = el('input', { 'class': 'facts-input', type: 'search', placeholder: 'search entity / key / value…', 'aria-label': 'search facts' });
    var asOfInput = el('input', { 'class': 'facts-input facts-asof', type: 'datetime-local', 'aria-label': 'as of (ingest-time machine)' });
    var supToggle = el('button', { 'class': 'facts-toggle on', type: 'button', 'aria-pressed': 'true', title: 'include cross-entity-retired (superseded) facts' }, ['superseded']);
    var resToggle = el('button', { 'class': 'facts-toggle', type: 'button', 'aria-pressed': 'false', title: 'include daemon-reserved (__*) entities' }, ['reserved __*']);
    function field(label, node) { return el('label', { 'class': 'facts-field' }, [el('span', { text: label }), node]); }
    var toolbar = el('div', { 'class': 'facts-toolbar' }, [
      field('search', searchInput),
      field('as of', asOfInput),
      el('div', { 'class': 'facts-toggles' }, [supToggle, resToggle])
    ]);
    var countLine = el('p', { 'class': 'facts-count' });
    var chipsWrap = el('div', { 'class': 'facts-chips' });
    var banner = el('div', { 'class': 'facts-banner' }); banner.style.display = 'none';
    var groupsWrap = el('div', { 'class': 'facts-groups' });
    var moreWrap = el('div', { 'class': 'facts-more' });
    var sentinel = el('div', { 'class': 'facts-sentinel' });
    host.appendChild(el('div', { 'class': 'facts-browser' }, [toolbar, countLine, chipsWrap, banner, groupsWrap, moreWrap, sentinel]));

    function syncToggles() {
      supToggle.classList.toggle('on', state.includeSuperseded); supToggle.setAttribute('aria-pressed', state.includeSuperseded ? 'true' : 'false');
      resToggle.classList.toggle('on', state.includeReserved); resToggle.setAttribute('aria-pressed', state.includeReserved ? 'true' : 'false');
    }
    function baseQuery(extra) {
      var q = { limit: FACTS_PAGE_LIMIT };
      if (state.q) { q.q = state.q; }
      if (state.entityPrefix) { q.entity_prefix = state.entityPrefix; }
      if (state.includeReserved) { q.include_reserved = 1; }
      if (!state.includeSuperseded) { q.include_superseded = 0; }
      if (state.asOfMs != null) { q.as_of_unix_ms = state.asOfMs; }
      if (extra) { for (var k in extra) { q[k] = extra[k]; } }
      return q;
    }

    function paintCount() {
      var shown = state.rows.length, vis = state.totalVisible;
      var filtered = !!(state.q || state.entityPrefix);
      var label = filtered ? (vis === 1 ? 'match' : 'matches') : 'visible';
      var kids = [el('b', { text: nfmt(shown) }), ' shown of ', el('b', { text: (vis == null ? '—' : nfmt(vis)) }), ' ' + label];
      var c = state.census;
      if (c && c.stored != null) {
        kids.push(' · '); kids.push(el('b', { text: nfmt(c.stored) })); kids.push(' stored');
        if (c.priv != null && c.reserved != null) {
          kids.push(' (' + nfmt(c.priv) + ' private + ' + nfmt(c.reserved) + ' reserved ' + (state.includeReserved ? 'shown' : 'hidden') + ')');
        }
      } else if (state.totalNondeleted != null) {
        kids.push(' · '); kids.push(el('b', { text: nfmt(state.totalNondeleted) })); kids.push(' stored');
      }
      if (state.asOfMs != null) { kids.push(el('span', { 'class': 'facts-asof-tag', text: '⏱ as of ' + shortTime(new Date(state.asOfMs).toISOString()) })); }
      countLine.textContent = '';
      kids.forEach(function (k) { countLine.appendChild(typeof k === 'string' ? doc().createTextNode(k) : k); });
    }

    // Census: two limit=1 probes (reserved off / on, superseded included, current
    // as_of) yield the exact private + reserved split from the SAME response
    // fields — derived, never hardcoded.
    function loadCensus() {
      var probe = { limit: 1 };
      if (state.asOfMs != null) { probe.as_of_unix_ms = state.asOfMs; }
      var onQ = {}; for (var k in probe) { onQ[k] = probe[k]; } onQ.include_reserved = 1;
      var myToken = state.token;
      Promise.all([fetchJSON('/v1/facts/list?' + qs(probe)), fetchJSON('/v1/facts/list?' + qs(onQ))]).then(function (rr) {
        if (myToken !== state.token) { return; }
        var a = rr[0], b = rr[1];
        if (!a.ok || !a.data) { return; }
        var visible = a.data.total_visible, stored = a.data.total_nondeleted;
        var withReserved = (b.ok && b.data && b.data.total_visible != null) ? b.data.total_visible : visible;
        state.census = {
          stored: stored,
          reserved: (withReserved != null && visible != null) ? Math.max(0, withReserved - visible) : null,
          priv: (stored != null && withReserved != null) ? Math.max(0, stored - withReserved) : null
        };
        paintCount();
      });
    }

    function rowEl(f) {
      var badges = el('div', { 'class': 'facts-rbadges' });
      if (f.superseded_by) { badges.appendChild(el('span', { 'class': 'facts-badge sup', title: 'superseded by ' + f.superseded_by, text: 'superseded' })); }
      if (f.value_truncated) { badges.appendChild(el('span', { 'class': 'facts-badge', title: f.value_len + ' chars — open the row for the full value', text: nfmt(f.value_len) + ' ch' })); }
      var head = el('div', { 'class': 'facts-rhead' }, [
        el('span', { 'class': 'facts-key', text: f.key || '(no key)' }),
        el('span', { 'class': 'facts-entity', text: f.entity || '' }),
        badges,
        el('span', { 'class': 'facts-time', text: shortTime(f.stored_at) })
      ]);
      var val = el('div', { 'class': 'facts-val', text: (f.value || '') + (f.value_truncated ? ' …' : '') });
      var detail = el('div', { 'class': 'facts-detail' });
      var row = el('div', { 'class': 'facts-row tone-' + factKindTone(factGroupKey(f.entity)), role: 'button', tabindex: '0' }, [head, val, detail]);
      var opened = false;
      function toggle() { var o = row.classList.toggle('open'); if (o && !opened) { opened = true; expandRow(detail, f); } }
      row.addEventListener('click', toggle);
      row.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
      return row;
    }
    function expandRow(detail, f) {
      detail.textContent = '';
      detail.appendChild(el('div', { 'class': 'facts-loading', text: 'loading full fact…' }));
      fetchVia(function () { return window.CruxApi.factsByFactId(f.fact_id); }).then(function (res) {
        detail.textContent = '';
        var full = (res.ok && res.data) ? res.data : null;
        var value = full ? full.value : (f.value || '');
        var meta = el('div', { 'class': 'facts-kv' });
        function kv(k, v) { meta.appendChild(el('span', { 'class': 'facts-kv-k', text: k })); meta.appendChild(el('span', { 'class': 'facts-kv-v', text: (v == null || v === '') ? '—' : String(v) })); }
        kv('fact_id', f.fact_id);
        kv('entity', f.entity);
        kv('key', f.key);
        kv('actor', (full && full.actor != null) ? full.actor : f.actor);
        kv('confidence', fmtConf(full ? full.confidence : f.confidence));
        kv('horizon_class', (full && full.horizon_class) || f.horizon_class);
        kv('tokens', (full && full.tokens != null) ? full.tokens : f.tokens);
        kv('version', (full && full.version != null) ? full.version : f.version);
        kv('stored_at', (full && full.stored_at) || f.stored_at);
        if (f.superseded_by || (full && full.superseded_by)) { kv('superseded_by', f.superseded_by || (full && full.superseded_by)); }
        detail.appendChild(meta);
        if (!full) { detail.appendChild(el('p', { 'class': 'ctl-desc', text: 'Full value unavailable (HTTP ' + (res.status || '?') + ') — showing the row value.' })); }
        detail.appendChild(el('div', { 'class': 'facts-vlabel', text: (full && f.value_truncated) ? 'value (full)' : 'value' }));
        detail.appendChild(el('pre', { 'class': 'facts-vfull', text: prettyValue(value) }));
      });
    }

    function ensureGroup(k) {
      if (state.groupBodies[k]) { return state.groupBodies[k]; }
      if (!(k in state.groupsExpanded)) { state.groupsExpanded[k] = false; }
      var det = el('details', { 'class': 'facts-group tone-' + factKindTone(k) });
      if (state.groupsExpanded[k]) { det.setAttribute('open', 'open'); }
      var count = el('span', { 'class': 'facts-gcount' });
      var sum = el('summary', { 'class': 'facts-gsum' }, [el('span', { 'class': 'facts-gdot' }), el('span', { 'class': 'facts-gname', text: factGroupLabel(k) }), count]);
      det.appendChild(sum);
      det.addEventListener('toggle', function () { state.groupsExpanded[k] = det.open; });
      var body = el('div', { 'class': 'facts-glist' });
      det.appendChild(body);
      groupsWrap.appendChild(det);
      state.groupBodies[k] = { body: body, count: count, n: 0 };
      return state.groupBodies[k];
    }
    function appendRows(facts) {
      facts.forEach(function (f) { var g = ensureGroup(factGroupKey(f.entity)); g.body.appendChild(rowEl(f)); g.n++; g.count.textContent = g.n + ' loaded'; });
    }
    function firstPaint(facts) {
      groupsWrap.textContent = ''; state.groupBodies = {};
      if (!facts.length) { groupsWrap.appendChild(el('p', { 'class': 'facts-empty ctl-desc', text: 'No facts match.' })); return; }
      var counts = {};
      facts.forEach(function (f) { var k = factGroupKey(f.entity); counts[k] = (counts[k] || 0) + 1; });
      Object.keys(counts).sort(function (a, b) { return counts[b] - counts[a]; }).forEach(function (k, idx) { state.groupsExpanded[k] = idx < 4; });
      appendRows(facts);
    }

    function paintChips() {
      if (state.fallback) { chipsWrap.textContent = ''; return; }
      var counts = {};
      state.rows.forEach(function (f) { var k = factGroupKey(f.entity); counts[k] = (counts[k] || 0) + 1; });
      var keys = Object.keys(counts).filter(function (k) { return k !== 'other'; }).sort(function (a, b) { return counts[b] - counts[a]; }).slice(0, 12);
      chipsWrap.textContent = '';
      var allChip = el('button', { 'class': 'facts-chip' + (state.entityPrefix ? '' : ' on'), type: 'button', title: 'clear the entity-prefix filter' }, ['all']);
      allChip.addEventListener('click', function () { if (!state.entityPrefix) { return; } state.entityPrefix = ''; resetAndLoad(); });
      chipsWrap.appendChild(allChip);
      keys.forEach(function (k) {
        var pref = (/::$/.test(k)) ? k : k + ':';
        var active = state.entityPrefix === pref;
        var chip = el('button', { 'class': 'facts-chip' + (active ? ' on' : ''), type: 'button', title: 'filter to ' + pref + '* server-side' }, [el('span', { text: factGroupLabel(k) }), el('span', { 'class': 'c', text: String(counts[k]) })]);
        chip.addEventListener('click', function () {
          if (active) { state.entityPrefix = ''; }
          else { state.entityPrefix = pref; if (/^__/.test(pref) && !state.includeReserved) { state.includeReserved = true; syncToggles(); } }
          resetAndLoad();
        });
        chipsWrap.appendChild(chip);
      });
    }

    function paintMore() {
      moreWrap.textContent = '';
      if (state.fallback) { return; }
      if (state.rows.length >= FACTS_DOM_CAP) { moreWrap.appendChild(el('p', { 'class': 'facts-cap', text: 'Rendered ' + nfmt(FACTS_DOM_CAP) + '+ rows — narrow with search or a prefix chip to load the rest.' })); return; }
      if (state.hasMore) {
        var remaining = (state.totalVisible != null) ? Math.max(0, state.totalVisible - state.rows.length) : null;
        var btn = el('button', { 'class': 'btn-quiet', type: 'button' }, ['Load more' + (remaining != null ? ' (' + nfmt(remaining) + ' remaining)' : '')]);
        btn.addEventListener('click', loadNext);
        moreWrap.appendChild(btn);
      } else if (state.rows.length) {
        moreWrap.appendChild(el('p', { 'class': 'ctl-desc', text: 'End of ' + ((state.q || state.entityPrefix) ? 'matches' : 'the visible store') + '.' }));
      }
    }

    function loadPage(cursor, isFirst) {
      if (state.loading) { return; }
      state.loading = true;
      if (isFirst) { groupsWrap.textContent = ''; groupsWrap.appendChild(el('p', { 'class': 'facts-empty ctl-desc', text: 'loading…' })); }
      var myToken = state.token;
      fetchJSON('/v1/facts/list?' + qs(baseQuery(cursor ? { cursor: cursor } : null))).then(function (res) {
        if (myToken !== state.token) { return; }
        state.loading = false;
        if (isFirst && res.status === 404) { state.fallback = true; fallbackLoad(); return; }
        if (!res.ok || !res.data) {
          if (isFirst) { banner.style.display = ''; banner.className = 'facts-banner err'; banner.textContent = 'Facts listing unavailable — ' + (res.status === 0 ? 'daemon unreachable' : 'HTTP ' + res.status) + '.'; groupsWrap.textContent = ''; }
          return;
        }
        var d = res.data;
        state.totalVisible = d.total_visible; state.totalNondeleted = d.total_nondeleted;
        state.nextCursor = d.next_cursor || null; state.hasMore = !!d.has_more;
        var fresh = [];
        (d.facts || []).forEach(function (f) { if (f.fact_id && state.seen[f.fact_id]) { return; } if (f.fact_id) { state.seen[f.fact_id] = true; } state.rows.push(f); fresh.push(f); });
        if (isFirst) { firstPaint(state.rows); } else { appendRows(fresh); }
        paintCount(); paintChips(); paintMore();
      });
    }
    function loadNext() {
      if (state.fallback || state.loading || !state.hasMore) { return; }
      if (state.rows.length >= FACTS_DOM_CAP) { paintMore(); return; }
      loadPage(state.nextCursor, false);
    }
    function resetAndLoad() {
      state.token++;
      state.rows = []; state.seen = {}; state.groupBodies = {}; state.groupsExpanded = {};
      state.nextCursor = null; state.hasMore = false; state.loading = false; state.fallback = false;
      banner.style.display = 'none'; moreWrap.textContent = '';
      loadCensus();
      loadPage(null, true);
    }
    // Older daemon (no /v1/facts/list): fall back to the recent-window console
    // feed, honestly labelled — read-only, no server paging or search.
    function fallbackLoad() {
      banner.style.display = ''; banner.className = 'facts-banner warn';
      banner.textContent = 'Listing route unavailable on this daemon (needs the console-surfaces-remediation branch). Showing the recent window from /v1/console/facts only.';
      chipsWrap.textContent = ''; moreWrap.textContent = '';
      fetchJSON('/v1/console/facts?top_k=100').then(function (res) {
        groupsWrap.textContent = '';
        if (!res.ok || !res.data) { groupsWrap.appendChild(el('p', { 'class': 'facts-empty ctl-desc', text: 'Recent-window feed also unavailable (HTTP ' + (res.status || '?') + ').' })); return; }
        var facts = res.data.facts || [];
        state.rows = facts;
        state.totalVisible = (res.data.visible_count != null) ? res.data.visible_count : facts.length;
        state.totalNondeleted = (res.data.count != null) ? res.data.count : null;
        state.census = null;
        firstPaint(facts); paintCount();
        moreWrap.appendChild(el('p', { 'class': 'ctl-desc', text: 'Recent window: ' + nfmt(facts.length) + (state.totalNondeleted != null ? ' of ' + nfmt(state.totalNondeleted) + ' stored' : '') + ' (no server-side paging on this daemon).' }));
      });
    }

    // ---- wiring ----
    searchInput.addEventListener('input', function () { clearTimeout(state.deb); state.deb = setTimeout(function () { state.q = (searchInput.value || '').trim(); resetAndLoad(); }, 250); });
    asOfInput.addEventListener('change', function () { var v = asOfInput.value; if (!v) { state.asOfMs = null; } else { var t = new Date(v).getTime(); state.asOfMs = isFinite(t) ? t : null; } resetAndLoad(); });
    supToggle.addEventListener('click', function () { state.includeSuperseded = !state.includeSuperseded; syncToggles(); resetAndLoad(); });
    resToggle.addEventListener('click', function () { state.includeReserved = !state.includeReserved; syncToggles(); resetAndLoad(); });
    if (typeof IntersectionObserver !== 'undefined') {
      var io = new IntersectionObserver(function (entries) { if (entries[0] && entries[0].isIntersecting) { loadNext(); } }, { rootMargin: '500px' });
      io.observe(sentinel);
    }
    resetAndLoad();
  }

  // ─────────────────────────────────────────────────────────────────────────
  //  cx-sessions (console-surfaces-remediation M3): a searchable session list
  //  over /v1/console/sessions (session_rows — NOT the bare id strings the old
  //  builder read), with a row-click detail drawer over the new
  //  /v1/console/sessions/detail route. Custom-rendered like renderFactsBrowser;
  //  through-client only (fetchJSON → CruxApi.get), el()/textContent, no innerHTML.
  //  Deliberately SEPARATE from the canvas renderSessionDetail path (whose smoke
  //  gate forbids reading session state) — this drawer shows the full state blob
  //  the daemon exposes under admin-read.
  // ─────────────────────────────────────────────────────────────────────────
  function renderSessionsBrowser(host) {
    host.textContent = '';
    function nfmt(n) { if (typeof n !== 'number' || !isFinite(n)) { return (n == null) ? '—' : String(n); } try { return n.toLocaleString('en-US'); } catch (e) { return String(n); } }
    function compactTokens(n) {
      if (typeof n !== 'number' || !isFinite(n)) { return '—'; }
      if (n >= 1000) { var k = n / 1000; return (k >= 100 ? Math.round(k) : k.toFixed(1)) + 'k'; }
      return String(n);
    }
    function relTime(iso) {
      var t = Date.parse(iso || ''); if (!isFinite(t)) { return '—'; }
      var s = Math.max(0, Math.round((Date.now() - t) / 1000));
      if (s < 60) { return s + 's ago'; }
      var m = Math.round(s / 60); if (m < 60) { return m + 'm ago'; }
      var h = Math.round(m / 60); if (h < 48) { return h + 'h ago'; }
      return Math.round(h / 24) + 'd ago';
    }
    function prettyValue(v) {
      if (typeof v !== 'string') { try { return JSON.stringify(v, null, 2); } catch (e) { return String(v); } }
      var t = v.trim();
      if (t && (t.charAt(0) === '{' || t.charAt(0) === '[')) { try { return JSON.stringify(JSON.parse(v), null, 2); } catch (e) { return v; } }
      return v;
    }
    function shortId(id) { var s = String(id || ''); return s.length > 8 ? s.slice(0, 8) : s; }

    // Same-id ExecPlan lane (M3 follow-up): EXACT linkage — a session whose
    // logical id names an ExecPlan work-board item (`execplan:<slug>`, or a bare
    // `<slug>` that resolves to one). `state.plans` maps that id → the work item
    // {state, current_milestone, title}, fetched once alongside the session list.
    // Distinct from the coord live-announce lane (TTL) and the fact-authorship
    // heuristic lane — this is identity, not inference.
    var state = { all: [], q: '', includeArchived: false, totalCount: 0, archivedCount: 0, loading: false, token: 0, plans: {} };
    function planIdFor(s) {
      var lid = String((s && s.session_id) || '');
      if (!lid) { return null; }
      var id = lid.indexOf('execplan:') === 0 ? lid : 'execplan:' + lid;
      return state.plans[id] ? id : null;
    }

    var searchInput = el('input', { 'class': 'facts-input', type: 'search', placeholder: 'filter id / agent / passport / plan…', 'aria-label': 'filter sessions' });
    var archToggle = el('button', { 'class': 'facts-toggle', type: 'button', 'aria-pressed': 'false', title: 'include archived sessions' }, ['archived']);
    function field(label, node) { return el('label', { 'class': 'facts-field' }, [el('span', { text: label }), node]); }
    var toolbar = el('div', { 'class': 'facts-toolbar' }, [field('filter', searchInput), el('div', { 'class': 'facts-toggles' }, [archToggle])]);
    var countLine = el('p', { 'class': 'facts-count' });
    var banner = el('div', { 'class': 'facts-banner' }); banner.style.display = 'none';
    var listWrap = el('div', { 'class': 'facts-groups' });
    host.appendChild(el('div', { 'class': 'facts-browser' }, [toolbar, countLine, banner, listWrap]));

    function matches(s, q) {
      if (!q) { return true; }
      return ((s.session_id || '') + ' ' + (s.agent || '') + ' ' + (s.passport_id || '') + ' ' + (s.execplan_slug || '') + ' ' + (planIdFor(s) || '')).toLowerCase().indexOf(q) >= 0;
    }
    function paintCount(shown) {
      countLine.textContent = '';
      var loaded = state.all.length;
      // Rows the server would return for this view (archived are excluded unless
      // the toggle is on) — distinct from the 100-row cap below.
      var expected = state.includeArchived ? state.totalCount : Math.max(0, state.totalCount - state.archivedCount);
      var scope = state.includeArchived ? 'all' : 'active';
      var kids = [el('b', { text: nfmt(shown) }), ' shown'];
      if (state.q) { kids.push(' (filtered)'); }
      kids.push(' · '); kids.push(el('b', { text: nfmt(loaded) })); kids.push(' ' + scope + ' session' + (loaded === 1 ? '' : 's') + ' loaded');
      kids.push(' · '); kids.push(el('b', { text: nfmt(state.totalCount) })); kids.push(' total');
      if (state.archivedCount) { kids.push(' · ' + nfmt(state.archivedCount) + ' archived'); }
      // The server caps the row set at 100 — the ONLY real truncation signal
      // (archived exclusion is not truncation). Say so honestly when it bites.
      if (loaded >= 100 && expected > loaded) { kids.push(' · '); kids.push(el('span', { 'class': 'facts-asof-tag', text: 'showing first ' + nfmt(loaded) + ' of ' + nfmt(expected) })); }
      kids.forEach(function (k) { countLine.appendChild(typeof k === 'string' ? doc().createTextNode(k) : k); });
    }
    function chip(cls, text, title) { return el('span', { 'class': cls, title: title || '' }, [text]); }
    function rowEl(s) {
      var head = el('div', { 'class': 'facts-rhead' }, [
        el('span', { 'class': 'facts-key', text: s.session_id || '(no id)' }),
        el('span', { 'class': 'sess-sc ' + (s.state || 'idle'), text: s.state || 'idle' }),
        s.agent ? chip('sess-chip', s.agent, 'owning agent') : null,
        el('span', { 'class': 'facts-time', text: relTime(s.updated_at) })
      ]);
      var planId = planIdFor(s);
      var plan = planId ? state.plans[planId] : null;
      var planChipText = planId ? (planId.replace(/^execplan:/, '') + (plan && plan.state ? (' · ' + plan.state) : '')) : null;
      var metaChips = el('div', { 'class': 'sess-rmeta' }, [
        chip('sess-chip', compactTokens(s.total_tokens) + ' tok', 'total tokens (bytes/4 estimate)'),
        s.passport_id ? chip('sess-chip sess-chip-pass', s.passport_id, 'bound passport') : null,
        planId ? chip('sess-chip sess-chip-plan sess-chip-idmatch', planChipText, 'ExecPlan — matched by session id (exact)') : null,
        s.execplan_slug ? chip('sess-chip sess-chip-plan', s.execplan_slug + (s.milestone ? (' · ' + s.milestone) : ''), 'live coord announce') : null,
        s.archived ? chip('sess-chip', 'archived' + (s.archive_reason ? (': ' + s.archive_reason) : ''), 'archived session') : null
      ]);
      var sub = s.state_first_line ? el('div', { 'class': 'facts-val', text: s.state_first_line }) : el('div', { 'class': 'sess-note-empty', text: 'no state summary' });
      var detail = el('div', { 'class': 'facts-detail' });
      var row = el('div', { 'class': 'facts-row', role: 'button', tabindex: '0' }, [head, sub, metaChips, detail]);
      var opened = false;
      function toggle() { var o = row.classList.toggle('open'); if (o && !opened) { opened = true; expandDetail(detail, s); } }
      // A click inside the open drawer (the state-JSON <details> summary, text
      // selection) must NOT bubble up and collapse the row — only head/meta toggle.
      row.addEventListener('click', function (e) { if (e.target && e.target.closest && (e.target.closest('a') || e.target.closest('.facts-detail'))) { return; } toggle(); });
      row.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
      return row;
    }
    function kvGrid(pairs) {
      var meta = el('div', { 'class': 'facts-kv' });
      pairs.forEach(function (kv) {
        if (kv[1] == null || kv[1] === '') { return; }
        meta.appendChild(el('span', { 'class': 'facts-kv-k', text: kv[0] }));
        meta.appendChild(el('span', { 'class': 'facts-kv-v', text: String(kv[1]) }));
      });
      return meta;
    }
    function sectionLabel(t) { return el('div', { 'class': 'facts-vlabel', text: t }); }
    function emptyNote(t) { return el('p', { 'class': 'ctl-desc sess-empty', text: t }); }
    function expandDetail(detail, s) {
      detail.textContent = '';
      detail.appendChild(el('div', { 'class': 'facts-loading', text: 'loading session detail…' }));
      fetchJSON('/v1/console/sessions/detail?key=' + encodeURIComponent(s.raw_key || s.session_id || '')).then(function (res) {
        detail.textContent = '';
        if (!res.ok || !res.data) { detail.appendChild(emptyNote('Detail unavailable (HTTP ' + (res.status || '?') + ') — GET /v1/console/sessions/detail.')); return; }
        var d = res.data;
        var meta = d.session || {};
        // 1) session meta
        detail.appendChild(sectionLabel('session'));
        detail.appendChild(kvGrid([
          ['raw key', meta.raw_key], ['agent', meta.agent], ['state', meta.state],
          ['updated', meta.updated_at], ['expires', meta.expires_at],
          ['archived', meta.archived ? ('yes' + (meta.archive_reason ? (' · ' + meta.archive_reason) : '')) : 'no']
        ]));
        // 2) passport binding
        detail.appendChild(sectionLabel('passport'));
        if (d.binding) { detail.appendChild(kvGrid([['passport', d.binding.passport_id], ['category', d.binding.passport_category], ['project', d.binding.project_id]])); }
        else { detail.appendChild(emptyNote('No passport binding for this session. Bindings are minted on POST /session (sealed-plan sessions); agent save_session ids resolve to none.')); }
        // 3) linked ExecPlan — three lanes, most-authoritative first.
        detail.appendChild(sectionLabel('linked ExecPlan'));
        // 3a) same-id match (EXACT — the session id names a work-board ExecPlan).
        var planId = planIdFor(s);
        if (planId) {
          var plan = state.plans[planId] || {};
          detail.appendChild(kvGrid([
            ['same-id match', planId],
            ['title', plan.title],
            ['state', plan.state],
            ['current milestone', plan.current_milestone]
          ]));
          detail.appendChild(el('p', { 'class': 'ctl-desc', text: 'exact: this session’s id equals ExecPlan work item ' + planId + ' — identity, not inference.' }));
        } else {
          detail.appendChild(emptyNote('same-id match: none — this session’s id does not name an ExecPlan on the work board (/v1/work).'));
        }
        // 3b) live announce (coord intent, TTL-scoped).
        if (d.coord_intent) {
          detail.appendChild(kvGrid([
            ['live announce', (d.coord_intent.execplan_slug || '—') + (d.coord_intent.milestone ? (' · ' + d.coord_intent.milestone) : '')],
            ['paths', (d.coord_intent.paths || []).join(', ')], ['note', d.coord_intent.note]
          ]));
        } else { detail.appendChild(emptyNote('live announce: none — populated by coord_announce (TTL-scoped presence).')); }
        var plans = d.linked_plans_heuristic || [];
        if (plans.length) {
          var plist = el('div', { 'class': 'facts-kv' });
          plans.forEach(function (p) {
            plist.appendChild(el('span', { 'class': 'facts-kv-k', text: p.entity }));
            plist.appendChild(el('span', { 'class': 'facts-kv-v', text: p.matches + ' fact' + (p.matches === 1 ? '' : 's') }));
          });
          detail.appendChild(plist);
          detail.appendChild(el('p', { 'class': 'ctl-desc', text: 'derived from fact authorship — journaled session-plan linkage is a daemon follow-up.' }));
        } else { detail.appendChild(emptyNote('heuristic plan linkage: none — execplan:* facts authored by this session’s passport would appear here.')); }
        // 4) gates approved
        detail.appendChild(sectionLabel('gates decided'));
        var gates = d.gates || [];
        if (gates.length) {
          var glist = el('div', { 'class': 'facts-kv' });
          gates.forEach(function (g) {
            var left = g.gate_status + ' · ' + (g.work_title || g.work_id);
            var right = (g.receipt_id ? (shortId(g.receipt_id) + '…') : 'no receipt');
            glist.appendChild(el('span', { 'class': 'facts-kv-k', text: left }));
            glist.appendChild(el('span', { 'class': 'facts-kv-v', text: right }));
          });
          detail.appendChild(glist);
        } else { detail.appendChild(emptyNote('No gate decisions by this passport. Populated by gate approvals (WorkTransition receipts).')); }
        // 5) token usage
        detail.appendChild(sectionLabel('token usage'));
        detail.appendChild(kvGrid([['total tokens', nfmt(meta.total_tokens)], ['estimate', 'serialized-state bytes / 4']]));
        // 6) full state blob — collapsible, textContent only (admin-read decision).
        var pre = el('pre', { 'class': 'facts-vfull', text: prettyValue(d.state) });
        var det = el('details', { 'class': 'sess-state-details' }, [el('summary', {}, ['state JSON (full blob)']), pre]);
        detail.appendChild(det);
      });
    }
    function paint() {
      var q = (searchInput.value || '').trim().toLowerCase();
      state.q = q;
      var visible = state.all.filter(function (s) { return matches(s, q); });
      listWrap.textContent = '';
      if (!state.all.length) { listWrap.appendChild(el('p', { 'class': 'facts-empty ctl-desc', text: state.loading ? 'loading…' : 'No sessions. Sessions are written by save_session / cuecrux_session.' })); paintCount(0); return; }
      if (!visible.length) { listWrap.appendChild(el('p', { 'class': 'facts-empty ctl-desc', text: 'No sessions match the filter.' })); paintCount(0); return; }
      visible.forEach(function (s) { listWrap.appendChild(rowEl(s)); });
      paintCount(visible.length);
    }
    // Build the same-id ExecPlan map from the work board. Cheap, best-effort:
    // a failed/absent work feed just leaves state.plans empty (no plan chips /
    // "same-id: none" in the drawer) — honest degradation, never blocking.
    function loadPlans() {
      return fetchJSON('/v1/work?source=all').then(function (res) {
        var map = {};
        if (res.ok && res.data) {
          var items = res.data.work || res.data.items || res.data.work_items || [];
          items.forEach(function (w) {
            var id = w && w.id;
            if (typeof id === 'string' && id.indexOf('execplan:') === 0) {
              map[id] = { state: w.state || null, current_milestone: w.current_milestone || null, title: w.title || null };
            }
          });
        }
        state.plans = map;
      });
    }
    function load() {
      if (state.loading) { return; }
      state.loading = true; state.token++;
      var myToken = state.token;
      listWrap.textContent = ''; listWrap.appendChild(el('p', { 'class': 'facts-empty ctl-desc', text: 'loading…' }));
      Promise.all([
        fetchJSON('/v1/console/sessions?include_archived=' + (state.includeArchived ? 'true' : 'false')),
        loadPlans()
      ]).then(function (rr) {
        var res = rr[0];
        if (myToken !== state.token) { return; }
        state.loading = false;
        if (!res.ok || !res.data) { banner.style.display = ''; banner.className = 'facts-banner err'; banner.textContent = 'Sessions unavailable — ' + (res.status === 0 ? 'daemon unreachable' : 'HTTP ' + res.status) + '.'; listWrap.textContent = ''; return; }
        banner.style.display = 'none';
        state.all = res.data.session_rows || [];
        state.totalCount = (res.data.total_count != null) ? res.data.total_count : state.all.length;
        state.archivedCount = res.data.archived_count || 0;
        paint();
      });
    }

    searchInput.addEventListener('input', paint);
    archToggle.addEventListener('click', function () { state.includeArchived = !state.includeArchived; archToggle.classList.toggle('on', state.includeArchived); archToggle.setAttribute('aria-pressed', state.includeArchived ? 'true' : 'false'); load(); });
    load();
  }

  function renderActivityLog(host) {
    host.textContent = '';
    if (__actLogES) { try { __actLogES.close(); } catch (e) { /* noop */ } __actLogES = null; }
    var state = { tenant: 'default', session: '', budget: 2000, kinds: {}, rows: [], deb: null };
    ACT_KINDS.forEach(function (k) { state.kinds[k] = true; });
    var sessionInput = el('input', { 'class': 'act-input', type: 'text', placeholder: 'session id…', 'aria-label': 'session id' });
    var budgetInput = el('input', { 'class': 'act-input act-budget', type: 'number', min: '1', value: '2000', 'aria-label': 'token budget' });
    var searchInput = el('input', { 'class': 'act-input', type: 'search', placeholder: 'filter text…', 'aria-label': 'search' });
    function field(label, node) { return el('label', { 'class': 'act-field' }, [el('span', { text: label }), node]); }
    var kindsWrap = el('div', { 'class': 'act-kinds' });
    var loadBtn = el('button', { 'class': 'btn-primary', type: 'button' }, ['Load']);
    var liveBtn = el('button', { 'class': 'btn-quiet', type: 'button' }, ['Go live']);
    var controls = el('div', { 'class': 'act-controls' }, [field('session', sessionInput), field('token budget', budgetInput), field('search', searchInput), kindsWrap, loadBtn, liveBtn]);
    var liveDot = el('span', { 'class': 'act-livedot' });
    var statusText = el('span', { 'class': 'act-statustext', text: 'Enter a session id and Load. The activity log is gated by CORECRUXD_FEATURE_ACTIVITY_LOG.' });
    var list = el('div', { 'class': 'act-list' }, [el('p', { 'class': 'ctl-desc', text: 'No activity loaded yet.' })]);
    host.appendChild(el('div', { 'class': 'act-log' }, [controls, el('div', { 'class': 'act-status' }, [liveDot, statusText]), list]));

    function setStatus(t) { statusText.textContent = t; }
    function activeKinds() { return ACT_KINDS.filter(function (k) { return state.kinds[k]; }); }
    function renderKinds() {
      kindsWrap.textContent = '';
      ACT_KINDS.forEach(function (k) {
        var chip = el('button', { 'class': 'act-kchip k-' + k + (state.kinds[k] ? ' on' : ''), type: 'button', 'aria-pressed': state.kinds[k] ? 'true' : 'false', text: k });
        chip.addEventListener('click', function () { state.kinds[k] = !state.kinds[k]; renderKinds(); paint(); });
        kindsWrap.appendChild(chip);
      });
    }
    function load() {
      state.session = (sessionInput.value || '').trim();
      state.budget = parseInt(budgetInput.value, 10) || 2000;
      if (!state.session) { setStatus('Enter a session id first.'); return; }
      var ak = activeKinds();
      var query = { tenant_id: state.tenant, session: state.session, token_budget: state.budget };
      if (ak.length < ACT_KINDS.length) { query.kinds = ak.join(','); }
      activityBackfill(query).then(function (res) {
        if (res.status === 404) { state.rows = []; setStatus('Activity log disabled on this daemon (set CORECRUXD_FEATURE_ACTIVITY_LOG=1).'); paint(); return; }
        if (!res.ok || !res.data) { state.rows = []; setStatus('Load failed (HTTP ' + (res.status || '?') + ').'); paint(); return; }
        state.rows = res.data.rows || [];
        setStatus((res.data.returned != null ? res.data.returned : state.rows.length) + ' row(s)' + (res.data.truncated ? ' (budget-truncated — raise token_budget)' : '') + ' · session ' + state.session);
        paint();
      });
    }
    function matches(r, q) {
      if (!q) { return true; }
      return ((r.kind || '') + ' ' + (r.preview || '') + ' ' + (r.tool || '') + ' ' + (r.intent || '') + ' ' + (r.turn_id || '')).toLowerCase().indexOf(q) >= 0;
    }
    function paint() {
      var q = (searchInput.value || '').trim().toLowerCase();
      list.textContent = '';
      var visible = state.rows.filter(function (r) { return state.kinds[r.kind] && matches(r, q); });
      if (!visible.length) { list.appendChild(el('p', { 'class': 'ctl-desc', text: state.rows.length ? 'No matching activity.' : 'No activity loaded yet.' })); return; }
      visible.forEach(function (r) { list.appendChild(rowEl(r)); });
    }
    function rowEl(r) {
      var meta = el('div', { 'class': 'act-meta' }, [
        el('span', { 'class': 'act-kind', text: r.kind || '' }),
        el('span', { text: 'seq ' + r.seq }),
        el('span', { text: r.ts || '' }),
        el('span', { text: r.turn_id ? ('turn ' + r.turn_id) : '—' })
      ]);
      var extra = [r.tool, r.intent, (r.confidence != null ? ('conf ' + r.confidence) : null)].filter(Boolean).join(' · ');
      if (extra) { meta.appendChild(el('span', { text: extra })); }
      var expand = el('div', { 'class': 'act-expand' }, [el('div', { 'class': 'act-verbatim', text: 'loading verbatim…' }), el('div', { 'class': 'act-receipts' })]);
      var row = el('div', { 'class': 'act-row k-' + (r.kind || 'idle'), role: 'button', tabindex: '0' }, [meta, el('div', { 'class': 'act-preview', text: r.preview || '' }), expand]);
      var opened = false;
      function toggle() { var o = row.classList.toggle('open'); if (o && !opened) { opened = true; expandRow(row, r); } }
      row.addEventListener('click', toggle);
      row.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
      return row;
    }
    function expandRow(row, r) {
      var vb = row.querySelector('.act-verbatim'), rc = row.querySelector('.act-receipts');
      if (!r.turn_id) { vb.textContent = r.preview || '(no turn id — preview only)'; return; }
      var query = { tenant_id: state.tenant, session: state.session };
      activityTurnCall('activityTurnByTurnId', r.turn_id, query).then(function (res) {
        if (!res.ok || !res.data) { vb.textContent = 'deref failed (HTTP ' + (res.status || '?') + ')'; return; }
        var entries = res.data.entries || [];
        vb.textContent = entries.map(function (e) { return '[' + e.kind + '] ' + e.text; }).join('\n\n') || '(no entries)';
        rc.textContent = ''; rc.appendChild(el('span', { 'class': 'act-badge', text: '⏳ verifying…' }));
        activityTurnCall('activityTurnByTurnIdVerify', r.turn_id, query).then(function (vres) {
          rc.textContent = '';
          if (!vres.ok || !vres.data) { rc.appendChild(el('span', { 'class': 'act-badge warn', text: '• recorded (verify unavailable HTTP ' + (vres.status || '?') + ')' })); return; }
          var vrows = vres.data.entries || [], signer = vres.data.signer;
          if (!vrows.length) { rc.appendChild(el('span', { 'class': 'act-badge', text: 'no entries' })); return; }
          vrows.forEach(function (v) {
            var cls = 'act-badge', txt;
            if (!v.signed) { cls += ' warn'; txt = '• recorded ' + v.entry_id; }
            else if (v.verified) { cls += ' ok'; txt = '✓ verified ' + v.entry_id + (signer ? (' · ' + String(signer).slice(0, 12)) : ''); }
            else { cls += ' err'; txt = '✕ ' + ((v.errors && v.errors[0]) || 'unverifiable') + ' ' + v.entry_id; }
            rc.appendChild(el('span', { 'class': cls, text: txt }));
          });
        });
      });
    }
    function toggleLive() {
      if (__actLogES) { try { __actLogES.close(); } catch (e) { /* noop */ } __actLogES = null; liveDot.classList.remove('on'); liveBtn.textContent = 'Go live'; return; }
      if (typeof EventSource === 'undefined') { setStatus('Live streaming unsupported in this browser.'); return; }
      try { __actLogES = new EventSource('/v1/events/stream?types=activity.appended'); }
      catch (e) { setStatus('Live stream unavailable.'); return; }
      __actLogES.addEventListener('activity.appended', function () { clearTimeout(state.deb); state.deb = setTimeout(load, 400); });
      __actLogES.onerror = function () { liveBtn.textContent = 'Live (reconnecting)'; };
      liveDot.classList.add('on'); liveBtn.textContent = 'Stop live';
    }
    loadBtn.addEventListener('click', load);
    liveBtn.addEventListener('click', toggleLive);
    searchInput.addEventListener('input', paint);
    sessionInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') { load(); } });
    renderKinds();
    // Demo mode: a fresh daemon gates the activity log (CORECRUXD_FEATURE_ACTIVITY_LOG),
    // so the surface is blank until Loaded. Under ?demo=1 paint a labelled fixture
    // of a session's rolling turns (via the demoData() choke point) — a real
    // session id + Load still overrides it.
    var demoAct = demoData('activityLog');
    if (demoAct && demoAct.length) {
      state.session = 'sess_7f3a1c2b';
      sessionInput.value = state.session;
      state.rows = demoAct;
      setStatus(state.rows.length + ' row(s) · session ' + state.session + ' · demo');
      paint();
    }
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
      else { budgetLabel.textContent = 'Number of Results'; budgetInput.value = String(state.topk); }
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

  // ── Link graph pane (ExecPlan wikicrux-link-graph-explorer M4) ────────────
  // A special full-viewport destination: a WebGL six-degrees explorer over the
  // enwiki-prose link graph, served through the Crux daemon's read-only CoreCrux
  // mediation proxy (/v1/console/corecrux/graph/*). All reads go through the
  // generated CruxApi.get (fetchJSON) — no bearer in the browser (T.3). The
  // renderer is a client-only ESM module (custom three.js r165) dynamically
  // imported so the no-build shell never evaluates WebGL until this pane opens.
  function linkGraphTheme() {
    var t = (typeof document !== 'undefined') ? document.documentElement.getAttribute('data-theme') : null;
    return (t === 'dark' || t === 'glass') ? t : 'light';
  }
  function lgFmtNum(n) {
    if (typeof n !== 'number' || !isFinite(n)) { return String(n); }
    return n.toLocaleString ? n.toLocaleString() : String(n);
  }
  function lgError(res, what) {
    if (res.status === 503) { return 'Link graph unavailable — the CoreCrux graph is not built/enabled upstream.'; }
    if (res.status === 0) { return 'Graph backend unreachable.'; }
    var detail = res.data && res.data.detail;
    return 'Graph ' + what + ' failed (' + (res.status || '?') + ')' + (detail ? ': ' + detail : '') + '.';
  }

  function renderLinkGraph(host, ctx) {
    ctx = ctx || {};
    host.textContent = '';
    var region = el('div', { 'class': 'lg-region' });
    host.appendChild(region);

    // Safety net: the DEST is capability-gated, but a deep-link (#/linkgraph) can
    // still land here on a daemon without the proxy — fail to an honest empty state.
    if (!capabilityAvailable('console_link_graph')) {
      region.appendChild(el('div', { 'class': 'lg-empty' }, [
        el('h2', { text: 'Link graph is not configured' }),
        el('p', { 'class': 'ctl-desc', text: 'This daemon has no CoreCrux graph mediation proxy. Set CORECRUXD_CORECRUX_GRAPH_BASE_URL on the Crux daemon to enable the six-degrees explorer.' })
      ]));
      return;
    }

    var header = el('div', { 'class': 'lg-header' });
    var statLine = el('div', { 'class': 'lg-stats', role: 'status', 'aria-live': 'polite' }, [el('span', { 'class': 'ctl-desc', text: 'Loading graph stats…' })]);
    header.appendChild(statLine);
    region.appendChild(header);

    var controls = el('div', { 'class': 'lg-controls' });
    var fromIn = el('input', { 'class': 'lg-input', type: 'text', placeholder: 'From article… (e.g. Dog)', 'aria-label': 'Path start article' });
    var toIn = el('input', { 'class': 'lg-input', type: 'text', placeholder: 'To article… (e.g. Barack Obama)', 'aria-label': 'Path end article' });
    var findBtn = el('button', { 'class': 'btn-primary lg-btn', type: 'button' }, ['Find path']);
    controls.appendChild(fromIn); controls.appendChild(toIn); controls.appendChild(findBtn);
    region.appendChild(controls);

    var status = el('div', { 'class': 'lg-status ctl-desc', role: 'status', 'aria-live': 'polite', text: 'Enter two article titles to trace a shortest path, then click any node to expand its neighbourhood.' });
    region.appendChild(status);

    var stage = el('div', { 'class': 'lg-stage' });
    region.appendChild(stage);

    var rendererHandle = null;
    var rendererPromise = null;
    var themeObs = null;
    var reduced = (typeof window !== 'undefined' && window.matchMedia) ? window.matchMedia('(prefers-reduced-motion: reduce)').matches : false;

    function ensureRenderer() {
      if (rendererPromise) { return rendererPromise; }
      // Dynamic import so SSR/no-build never evaluates WebGL; `three` resolves via
      // the shell import map to the vendored r165 (zero new trust-kernel surface).
      rendererPromise = import('/console-v2/linkgraph-renderer.mjs').then(function (mod) {
        var make = mod.createLinkGraphRenderer || mod.default;
        rendererHandle = make();
        rendererHandle.mount(stage, { theme: linkGraphTheme(), reducedMotion: reduced, onNodeClick: onNodeClick });
        if (typeof MutationObserver !== 'undefined') {
          themeObs = new MutationObserver(function () { if (rendererHandle) { rendererHandle.setTheme(linkGraphTheme()); } });
          themeObs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
        }
        return rendererHandle;
      }).catch(function (err) {
        status.textContent = 'Renderer unavailable: ' + (err && err.message ? err.message : 'failed to load the graph module') + '.';
        return null;
      });
      return rendererPromise;
    }

    function loadStats() {
      fetchJSON('/v1/console/corecrux/graph/stats').then(function (res) {
        statLine.textContent = '';
        if (res.status === 503) { statLine.appendChild(el('span', { 'class': 'ctl-desc', text: 'Graph not built/enabled upstream — set CORECRUXD_LINK_GRAPH + build a .ccxg on the CoreCrux daemon.' })); return; }
        if (!res.ok || !res.data) { statLine.appendChild(el('span', { 'class': 'ctl-desc', text: lgError(res, 'stats') })); return; }
        var d = res.data;
        var snap = d.snapshot_id || (d.build && d.build.snapshot_id) || '—';
        var digest = (d.build && d.build.digest) ? String(d.build.digest).slice(0, 12) : '';
        statLine.appendChild(el('span', { 'class': 'lg-stat', text: 'snapshot ' + snap }));
        if (d.nodes && d.nodes.total != null) { statLine.appendChild(el('span', { 'class': 'lg-stat', text: lgFmtNum(d.nodes.total) + ' nodes' })); }
        if (d.edges && d.edges.total != null) { statLine.appendChild(el('span', { 'class': 'lg-stat', text: lgFmtNum(d.edges.total) + ' edges' })); }
        if (d.community_count != null) { statLine.appendChild(el('span', { 'class': 'lg-stat', text: lgFmtNum(d.community_count) + ' communities' })); }
        if (digest) { statLine.appendChild(el('span', { 'class': 'lg-stat lg-digest', title: 'CoreCrux .ccxg build digest (artifact provenance)', text: 'digest ' + digest + '…' })); }
      });
    }

    function doPath() {
      var a = fromIn.value.trim(), b = toIn.value.trim();
      if (!a || !b) { status.textContent = 'Enter two article titles.'; return; }
      status.textContent = 'Resolving titles…';
      fetchJSON('/v1/console/corecrux/graph/resolve?titles=' + encodeURIComponent(a + '|' + b)).then(function (res) {
        if (!res.ok || !res.data || !res.data.results) { status.textContent = lgError(res, 'resolve'); return; }
        var r = res.data.results;
        var src = r[0] && r[0].node_id, dst = r[1] && r[1].node_id;
        if (src === null || src === undefined) { status.textContent = 'Unresolved article: “' + a + '”.'; return; }
        if (dst === null || dst === undefined) { status.textContent = 'Unresolved article: “' + b + '”.'; return; }
        var srcT = (r[0] && r[0].canonical_title) || a, dstT = (r[1] && r[1].canonical_title) || b;
        status.textContent = 'Finding path ' + srcT + ' → ' + dstT + '…';
        fetchJSON('/v1/console/corecrux/graph/path?src=' + src + '&dst=' + dst + '&max_hops=6').then(function (pres) {
          if (!pres.ok || !pres.data) { status.textContent = lgError(pres, 'path'); return; }
          var d = pres.data;
          if (d.length === null || d.length === undefined) {
            status.textContent = 'No path within 6 hops between “' + srcT + '” and “' + dstT + '”.';
          } else {
            status.textContent = srcT + ' → ' + dstT + ': ' + d.length + ' hop' + (d.length === 1 ? '' : 's') + ' · ' + (d.paths ? d.paths.length : 0) + ' equal-length path(s)' + (d.truncated ? ' (truncated)' : '') + '.';
          }
          var cg = d.context || { nodes: [], edges: [], edge_kinds: [] };
          ensureRenderer().then(function (h) {
            if (!h) { return; }
            h.setData({ nodes: cg.nodes || [], edges: cg.edges || [], edgeKinds: cg.edge_kinds || [], paths: d.paths || [], seeds: [src, dst] });
          });
        });
      });
    }

    function onNodeClick(node) {
      if (!node) { return; }
      var label = node.title || String(node.id);
      status.textContent = 'Expanding “' + label + '”…';
      fetchJSON('/v1/console/corecrux/graph/ego?seeds=' + node.id + '&hops=1&budget_nodes=400&budget_edges=1500&degree_cap=40').then(function (res) {
        if (!res.ok || !res.data) { status.textContent = lgError(res, 'ego'); return; }
        var d = res.data;
        if (rendererHandle) { rendererHandle.expandData({ nodes: d.nodes || [], edges: d.edges || [], edgeKinds: d.edge_kinds || [] }); }
        var trunc = (d.truncated_nodes || d.truncated_edges || d.truncated_degree) ? ' (budget-truncated)' : '';
        status.textContent = 'Expanded “' + label + '” · +' + ((d.nodes || []).length) + ' node(s)' + trunc + '.';
      });
    }

    findBtn.addEventListener('click', doPath);
    [fromIn, toIn].forEach(function (inp) { inp.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') { doPath(); } }); });

    // Teardown on navigation away — dispose the WebGL context + observers so the
    // pane never leaks a live renderer or a perpetual observer (a11y/battery).
    var onHash = function () {
      if ((location.hash || '').indexOf('/linkgraph') < 0) {
        window.removeEventListener('hashchange', onHash);
        if (themeObs) { themeObs.disconnect(); themeObs = null; }
        if (rendererHandle) { rendererHandle.destroy(); rendererHandle = null; }
      }
    };
    if (typeof window !== 'undefined') { window.addEventListener('hashchange', onHash); }

    loadStats();
    return { search: doPath, expand: onNodeClick };
  }

  return {
    CONTROL_TYPES: CONTROL_TYPES,
    GATE_TITLE: GATE_TITLE,
    // M11 — Explorer (corpus search; reads only, posture-independent).
    renderExplorer: renderExplorer,
    // Link graph (ExecPlan wikicrux-link-graph-explorer M4) — WebGL six-degrees
    // explorer over the CoreCrux link graph via the read-only mediation proxy;
    // capabilityAvailable gates the DEST on the daemon's runtime capability plan.
    renderLinkGraph: renderLinkGraph,
    capabilityAvailable: capabilityAvailable,
    // Site map — static reference destination (rail → destinations map).
    renderSiteMap: renderSiteMap,
    // M2 (console-surfaces-remediation) — the paged, searchable facts browser.
    renderFactsBrowser: renderFactsBrowser,
    // M3 (console-surfaces-remediation) — sessions browser + detail drawer.
    renderSessionsBrowser: renderSessionsBrowser,
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
    // M14 — the WebCrux tile canvas engine (pure grid/state fns + the view;
    // the smoke unit-tests the pure subset and audits the grammar CSS).
    tileSnap: tileSnap,
    TILE_SIZE_MAP: TILE_SIZE_MAP,
    tileAutoLayout: tileAutoLayout,
    tileRenderedDims: tileRenderedDims,
    tileExpandedDims: tileExpandedDims,
    renderTileCanvas: renderTileCanvas,
    buildGraphModel: buildGraphModel,
    // M4a — plan-rooted tree join (pure; unit-tested by the smoke) + its view
    // (planTreeNode exposed so the smoke can paint the model into a mock DOM).
    buildPlanTree: buildPlanTree,
    planTreeNode: planTreeNode,
    renderPlanTree: renderPlanTree,
    // M4c (console half) — pure stale-plan mismatch badge (daemon_hash, local_hash|null).
    planHashBadge: planHashBadge,
    // M4b — session-detail / evidence contract (pure builder + its live renderer).
    buildSessionDetail: buildSessionDetail,
    paintSessionDetail: paintSessionDetail,
    renderSessionDetail: renderSessionDetail,
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
    runtimeCapabilitySection: runtimeCapabilitySection,
    capabilityStateForControl: capabilityStateForControl,
    applyCapabilityGate: applyCapabilityGate,
    renderOverwatchLanding: renderOverwatchLanding,
    // M3b — pure attention-zone classifier + its staleness threshold (smoke
    // truth-table); the needs_you zone is wired into the Overwatch inbox.
    deriveAttentionZone: deriveAttentionZone,
    ATTENTION_LIVENESS_STALE_MS: ATTENTION_LIVENESS_STALE_MS,
    fillNeedsYou: fillNeedsYou,
    boundPassport: boundPassport,
    approveGate: approveGate,
    rejectGate: rejectGate,
    approveMintRequest: approveMintRequest,
    rejectMintRequest: rejectMintRequest,
    renderBoundApproverControl: renderBoundApproverControl,
    renderMintRequestCard: renderMintRequestCard,
    commentWork: commentWork,
    enrichAction: enrichAction,
    // M13b — the live-write registry (exposed so the smoke can audit the harness:
    // every entry fires through operatorGatedCall; the destructive subset carries
    // a confirm). The runtime never reaches the gated write client except via these + the
    // operator helpers above, all funnelling through operatorGatedCall.
    WIRED_WRITES: WIRED_WRITES
  };
});
