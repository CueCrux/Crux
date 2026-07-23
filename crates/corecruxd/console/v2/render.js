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
  // M6 cx-identity: run the candidate proposers (the ONLY shipped producer of
  // /v1/identity/candidates). Operator-gated, server admin:write-gated.
  function seedIdentityCandidates() {
    return operatorGatedCall(function (g) { return g.identityCandidatePropose({}); });
  }
  // M6 cx-identity: confirm a candidate by supplying the cross-signature proof —
  // mints the resolving identity_link only after both signatures verify (daemon).
  function confirmIdentityCandidate(candidateId, proof) {
    return operatorGatedCall(function (g) { return g.identityCandidateConfirm(candidateId, proof); });
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
    if (page.id === 'cx-cost') { container.textContent = ''; renderCostBrowser(container); return Promise.resolve(); }
    // M6 trust cluster — custom-rendered (live listing / honest posture panels).
    if (page.id === 'cx-receipts') { container.textContent = ''; renderReceiptsBrowser(container); return Promise.resolve(); }
    if (page.id === 'cx-gates') { container.textContent = ''; renderGatesBoard(container); return Promise.resolve(); }
    if (page.id === 'cx-identity') { container.textContent = ''; renderIdentityBrowser(container); return Promise.resolve(); }
    if (page.id === 'cx-mediation') { container.textContent = ''; renderMediationPosture(container); return Promise.resolve(); }
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
  // Concentric type-shell (radial) layout — the zoomed-OUT overview. Nodes are
  // arranged on rings by node type: projects innermost (the anchors), work/gates
  // next, then sessions, then passports/repos outermost. Deterministic: nodes are
  // sorted by (type, id) and placed at evenly-spaced angles (no randomness —
  // stability across renders is the point). A shell that can't hold its band on
  // one ring wraps to further concentric sub-rings; ring radius always clears the
  // previous band by at least a card's span, so cards never stack/overlap. Sets
  // n.ringX / n.ringY (card top-left, layer coords) and returns the box dims.
  function layoutGraphRing(nodes) {
    var CARD_W = 300, CARD_H = 128, SEP = 340, RING_GAP = 210;
    var BANDS = [['project'], ['work', 'gate'], ['session'], ['passport', 'repo']];
    var bandOf = {}; BANDS.forEach(function (ts, i) { ts.forEach(function (t) { bandOf[t] = i; }); });
    var byBand = {};
    nodes.forEach(function (n) { var b = bandOf[n.type]; if (b == null) { b = BANDS.length; } (byBand[b] || (byBand[b] = [])).push(n); });
    var bandKeys = Object.keys(byBand).map(Number).sort(function (a, b) { return a - b; });
    var minR = 0, maxR = 0;
    bandKeys.forEach(function (bk) {
      var list = byBand[bk].slice().sort(function (a, b) {
        if (a.type !== b.type) { return a.type < b.type ? -1 : 1; }
        var ai = String(a.id), bi = String(b.id); return ai < bi ? -1 : (ai > bi ? 1 : 0);
      });
      var r = Math.max(minR + RING_GAP, SEP * 0.9), idx = 0, sub = 0;
      while (idx < list.length) {
        var cap = Math.max(1, Math.floor((2 * Math.PI * r) / SEP));
        var take = Math.min(cap, list.length - idx);
        var phase = bk * 0.7 + sub * 0.35;   // deterministic per-ring stagger
        for (var k = 0; k < take; k++) {
          var n = list[idx + k], a = phase + (k / take) * 2 * Math.PI;
          n.__rx = r * Math.cos(a); n.__ry = r * Math.sin(a);
        }
        idx += take; maxR = Math.max(maxR, r); r += RING_GAP; sub++;
      }
      minR = maxR;
    });
    var minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    nodes.forEach(function (n) {
      var x = (n.__rx || 0) - CARD_W / 2, y = (n.__ry || 0) - CARD_H / 2;
      if (x < minX) { minX = x; } if (y < minY) { minY = y; }
      if (x + CARD_W > maxX) { maxX = x + CARD_W; } if (y + CARD_H > maxY) { maxY = y + CARD_H; }
    });
    if (!isFinite(minX)) { minX = 0; minY = 0; maxX = CARD_W; maxY = CARD_H; }
    var pad = 80;
    nodes.forEach(function (n) {
      n.ringX = (n.__rx || 0) - CARD_W / 2 - minX + pad;
      n.ringY = (n.__ry || 0) - CARD_H / 2 - minY + pad;
      delete n.__rx; delete n.__ry;
    });
    return { width: (maxX - minX) + pad * 2, height: (maxY - minY) + pad * 2 };
  }
  // Graph legibility cap: /v1/work?source=all can carry >1,000 items (mostly
  // complete/archived) — a relation graph of the whole set is an unreadable
  // hairball. Keep an active-first, deterministic slice (in-progress/blocked/
  // review/drafting first, then deployed, planned, finally complete/archive;
  // ties broken by recency then id) and ALWAYS keep the focused node so a
  // ?focus=work:… deep-link still resolves. Honest: the caller shows "N of M".
  function graphWorkPriority(w) {
    var s = String((w && w.state) || '').toLowerCase();
    if (s === 'in_progress' || s === 'blocked' || s === 'review' || s === 'drafting') { return 0; }
    if (s === 'deployed') { return 1; }
    if (s === 'planned') { return 2; }
    return 3;   // complete / archive / done / unknown
  }
  function capGraphWork(list, focus, cap) {
    cap = cap || 80;
    if (!Array.isArray(list) || list.length <= cap) { return list; }
    var focusId = (focus && focus.type === 'work' && focus.id != null) ? String(focus.id) : null;
    var sorted = list.slice().sort(function (a, b) {
      var pa = graphWorkPriority(a), pb = graphWorkPriority(b);
      if (pa !== pb) { return pa - pb; }
      var ua = Number(a.updated_at_unix_ms || a.created_at_unix_ms || 0), ub = Number(b.updated_at_unix_ms || b.created_at_unix_ms || 0);
      if (ua !== ub) { return ub - ua; }
      var ai = String(a.id), bi = String(b.id); return ai < bi ? -1 : (ai > bi ? 1 : 0);
    });
    var kept = sorted.slice(0, cap);
    if (focusId) {
      var has = kept.some(function (w) { return String(w.id) === focusId || String(w.id) === 'execplan:' + focusId || 'execplan:' + String(w.id) === focusId; });
      if (!has) {
        var f = list.filter(function (w) { return String(w.id) === focusId || 'execplan:' + String(w.id) === focusId; })[0];
        if (f) { kept = kept.slice(0, cap - 1); kept.push(f); }
      }
    }
    return kept;
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
    var cardDims = layoutGraph(model.nodes);   // columns-by-type — the zoomed-IN detail arrangement
    model.nodes.forEach(function (n) { n.cardX = n.x; n.cardY = n.y; });
    var ringDims = layoutGraphRing(model.nodes);   // concentric type-shells — the zoomed-OUT overview
    var reduceMotion = (typeof window !== 'undefined' && window.matchMedia) ? window.matchMedia('(prefers-reduced-motion: reduce)').matches : false;
    // LOD threshold on the layer scale (view.scale): below it the nodes ride the
    // ring overview, above it the card view. Open in whichever the CARD layout's
    // natural fit lands in — a huge graph opens as the constellation, a small one
    // straight into cards.
    var LOD_THRESHOLD = 0.62;
    var focusReserve = (focus && focus.type && focus.id != null) ? 380 : 0;
    function fitScaleFor(d, reserveR) {
      var sw = stage.clientWidth || 960, sh = stage.clientHeight || 640, pad = 30;
      var availW = Math.max(260, sw - (reserveR || 0) - pad * 2), availH = Math.max(200, sh - pad * 2);
      return Math.min(availW / d.width, availH / d.height);
    }
    var mode = fitScaleFor(cardDims, focusReserve) < LOD_THRESHOLD ? 'ring' : 'card';
    model.nodes.forEach(function (n) { n.x = (mode === 'ring') ? n.ringX : n.cardX; n.y = (mode === 'ring') ? n.ringY : n.cardY; });
    var activeDims = (mode === 'ring') ? ringDims : cardDims;
    var index = {}; model.nodes.forEach(function (n) { index[n.key] = n; });
    // One transformed layer holds the SVG edge canvas + the HTML node cards, so
    // pan/zoom moves cards and edges together.
    var layer = el('div', { 'class': 'cv-graph-layer' });
    layer.setAttribute('data-lod', mode);
    layer.style.width = activeDims.width + 'px'; layer.style.height = activeDims.height + 'px';
    var svg = svgEl('svg', { 'class': 'cv-graph-edges', width: activeDims.width, height: activeDims.height, 'aria-hidden': 'true' });
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
    function placeCard(n) { var c = cardEls[n.key]; if (c) { c.style.left = n.x + 'px'; c.style.top = n.y + 'px'; } }
    // Frame a layout into the stage (centre + scale). Floor is mode-aware: the
    // ring overview may shrink far (the whole constellation on-screen), the card
    // view stays legible. Reserves the inspector width when a node is focused.
    function frame(d) {
      var sw = stage.clientWidth || 960, sh = stage.clientHeight || 640, pad = 30;
      var availW = Math.max(260, sw - focusReserve - pad * 2), availH = Math.max(200, sh - pad * 2);
      var floor = (mode === 'ring') ? 0.03 : 0.42, cap = (mode === 'ring') ? 1.0 : 1.15;
      var s = Math.max(floor, Math.min(availW / d.width, availH / d.height, cap));
      return { scale: s, tx: pad + Math.max(0, (availW - d.width * s) / 2), ty: pad + Math.max(0, (availH - d.height * s) / 2) };
    }
    function fitView() { var f = frame(activeDims); view.scale = f.scale; view.tx = f.tx; view.ty = f.ty; apply(); }
    fitView();
    // Zoom-aware LOD: crossing the threshold morphs the nodes between the ring
    // overview and the card detail arrangement over ~300ms (snap under reduced
    // motion or on very large graphs). Each node's tween START is its exact
    // current on-screen position re-expressed under the NEW framing, so nodes
    // never jump at the cut — they glide from where they were into the new layout.
    var lodRaf = null, TWEEN_MAX = 160;
    function screenCentre(n) { var w = n.w || 300, h = n.h || 128; return { x: view.tx + (n.x + w / 2) * view.scale, y: view.ty + (n.y + h / 2) * view.scale }; }
    function switchMode(next) {
      if (next === mode) { return; }
      var sc = {}; model.nodes.forEach(function (n) { sc[n.key] = screenCentre(n); });
      mode = next; activeDims = (mode === 'ring') ? ringDims : cardDims;
      layer.style.width = activeDims.width + 'px'; layer.style.height = activeDims.height + 'px';
      svg.setAttribute('width', activeDims.width); svg.setAttribute('height', activeDims.height);
      layer.setAttribute('data-lod', mode);
      if (modeLbl) { modeLbl.textContent = (mode === 'ring') ? 'overview' : 'detail'; }
      var f = frame(activeDims); view.scale = f.scale; view.tx = f.tx; view.ty = f.ty; apply();
      var from = {}, to = {};
      model.nodes.forEach(function (n) {
        var w = n.w || 300, h = n.h || 128;
        from[n.key] = { x: (sc[n.key].x - view.tx) / view.scale - w / 2, y: (sc[n.key].y - view.ty) / view.scale - h / 2 };
        to[n.key] = (mode === 'ring') ? { x: n.ringX, y: n.ringY } : { x: n.cardX, y: n.cardY };
      });
      if (lodRaf != null && typeof window !== 'undefined' && window.cancelAnimationFrame) { window.cancelAnimationFrame(lodRaf); lodRaf = null; }
      var canAnim = !reduceMotion && model.nodes.length <= TWEEN_MAX && typeof window !== 'undefined' && window.requestAnimationFrame;
      if (!canAnim) {
        model.nodes.forEach(function (n) { n.x = to[n.key].x; n.y = to[n.key].y; placeCard(n); });
        layoutEdges(); return;
      }
      var t0 = null, DUR = 300;
      model.nodes.forEach(function (n) { n.x = from[n.key].x; n.y = from[n.key].y; placeCard(n); });
      layoutEdges();
      function stepFn(ts) {
        if (t0 == null) { t0 = ts; }
        var p = Math.min(1, (ts - t0) / DUR);
        var e = p < 0.5 ? 2 * p * p : 1 - Math.pow(-2 * p + 2, 2) / 2;   // easeInOutQuad
        model.nodes.forEach(function (n) {
          n.x = from[n.key].x + (to[n.key].x - from[n.key].x) * e;
          n.y = from[n.key].y + (to[n.key].y - from[n.key].y) * e;
          placeCard(n);
        });
        layoutEdges();
        if (p < 1) { lodRaf = window.requestAnimationFrame(stepFn); } else { lodRaf = null; }
      }
      lodRaf = window.requestAnimationFrame(stepFn);
    }
    function zoomBy(factor) {
      var b = (mode === 'ring') ? { min: 0.03, max: 1.3 } : { min: 0.42, max: 2.4 };
      var ns = Math.max(b.min, Math.min(b.max, view.scale * factor));
      view.scale = ns; apply();
      if (mode === 'card' && factor < 1 && ns <= LOD_THRESHOLD) { switchMode('ring'); }
      else if (mode === 'ring' && factor > 1 && ns >= LOD_THRESHOLD) { switchMode('card'); }
    }
    // Unobtrusive +/- zoom cluster (wheel/pinch still work) carrying a live LOD label.
    var modeLbl = el('span', { 'class': 'cv-zoom-mode', text: (mode === 'ring') ? 'overview' : 'detail' });
    var zoomOut = el('button', { 'class': 'cv-zoom-btn', type: 'button', 'aria-label': 'Zoom out', title: 'Zoom out' }, ['−']);
    var zoomIn = el('button', { 'class': 'cv-zoom-btn', type: 'button', 'aria-label': 'Zoom in', title: 'Zoom in' }, ['+']);
    zoomOut.addEventListener('click', function (e) { e.stopPropagation(); zoomBy(0.8); });
    zoomIn.addEventListener('click', function (e) { e.stopPropagation(); zoomBy(1.25); });
    stage.appendChild(el('div', { 'class': 'cv-zoom' }, [zoomOut, modeLbl, zoomIn]));
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
    function onEmpty(ev) { return !(ev.target.closest && (ev.target.closest('.cv-card') || ev.target.closest('.cv-zoom'))); }
    stage.addEventListener('mousedown', function (ev) { if (!onEmpty(ev)) { return; } drag = { x: ev.clientX, y: ev.clientY, tx: view.tx, ty: view.ty }; moved = false; });
    stage.addEventListener('click', function (ev) { if (!onEmpty(ev)) { return; } if (!moved) { select(null); onSelect(null); } });
    function onMove(ev) { if (!drag) { return; } moved = true; view.tx = drag.tx + (ev.clientX - drag.x); view.ty = drag.ty + (ev.clientY - drag.y); apply(); }
    function onUp() { drag = null; }
    stage.addEventListener('wheel', function (ev) { ev.preventDefault(); zoomBy(ev.deltaY < 0 ? 1.1 : 0.9); });
    if (typeof window !== 'undefined') { window.addEventListener('mousemove', onMove); window.addEventListener('mouseup', onUp); }
    __canvasGraphCleanup = function () {
      if (rafId != null && typeof window !== 'undefined' && window.cancelAnimationFrame) { window.cancelAnimationFrame(rafId); rafId = null; }
      if (lodRaf != null && typeof window !== 'undefined' && window.cancelAnimationFrame) { window.cancelAnimationFrame(lodRaf); lodRaf = null; }
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
      // Cap the work feed to an active-first, deterministic slice so the relation
      // graph stays legible (the full source=all set can be >1,000 items). Keeps
      // the focused node so a ?focus=work:… deep-link still resolves; honest count
      // shown below. buildGraphModel + the card/focus paths are otherwise untouched.
      var workData = (r[1].ok && r[1].data) || null, totalWork = 0, shownWork = 0;
      if (workData) {
        var wlist = workData.work || workData.items || [];
        totalWork = wlist.length;
        var capped = capGraphWork(wlist, focus, 80);
        shownWork = capped.length;
        var wd = {}; for (var wk in workData) { wd[wk] = workData[wk]; }
        if (workData.work) { wd.work = capped; } else { wd.items = capped; }
        workData = wd;
      }
      var data = {
        projects: (r[0].ok && r[0].data) || null,
        work: workData,
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
      if (!demoOn() && totalWork > shownWork) {
        stage.appendChild(el('div', { 'class': 'cv-graph-note', text: 'showing ' + shownWork + ' of ' + totalWork + ' work items — active first (zoom in or open a node to explore)' }));
      }
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
    // M7: kind (data-kind) and state (data-state) travel on every row so the CSS
    // can colour by the console's existing status/kind hue vocabulary. Nulls are
    // dropped by el(), so stateless kinds (project/milestone/session) carry no
    // data-state. Additive — the existing classes + chips are untouched.
    var kindAttr = node.type, stateAttr = (node.state != null && node.state !== '') ? node.state : null;
    if (node.children && node.children.length) {
      var det = el('details', { 'class': 'plan-tree-node', open: 'open' });
      det.appendChild(el('summary', { 'class': rowCls, style: 'padding-left:' + pad, 'data-kind': kindAttr, 'data-state': stateAttr }, planTreeRowInner(node)));
      node.children.forEach(function (c) { det.appendChild(planTreeNode(c, depth + 1, onSelect)); });
      return det;
    }
    // M4b: a session leaf opens its evidence detail on click/Enter/Space. Kept
    // behind the optional onSelect so the smoke can still paint a node with no
    // handler (and non-session leaves stay inert).
    if (node.type === 'session' && typeof onSelect === 'function') {
      var srow = el('div', { 'class': rowCls + ' plan-tree-session-open', style: 'padding-left:' + pad,
        'data-kind': kindAttr, 'data-state': stateAttr,
        role: 'button', tabindex: '0', 'aria-label': 'View session evidence: ' + (node.label || node.id || 'session') }, planTreeRowInner(node));
      srow.addEventListener('click', function () { onSelect(node); });
      srow.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(node); } });
      return srow;
    }
    return el('div', { 'class': rowCls, style: 'padding-left:' + pad, 'data-kind': kindAttr, 'data-state': stateAttr }, planTreeRowInner(node));
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
      // ---- M7: colour legend + kind/state/text filters -------------------
      // Colour is added in CSS keyed on the row's data-kind / data-state (planTreeNode);
      // here we build the legend + the live filter controls. Filtering keeps
      // ancestors of matches visible (a node shows if it matches OR any descendant
      // does) so the tree stays navigable, and reports an honest "N of M" count.
      var KIND_LABELS = [['project', 'Project'], ['execplan', 'ExecPlan'], ['milestone', 'Milestone'], ['session', 'Session'], ['work', 'Kanban'], ['unattached', 'Unattached']];
      var STATE_ORDER = ['planned', 'in_progress', 'drafting', 'blocked', 'review', 'deployed', 'done', 'complete', 'archive'];
      var kindsPresent = {}, statesPresent = {}, totalNodes = 0;
      tree.roots.forEach(function (root) { (function w(n) { totalNodes++; kindsPresent[n.type] = true; if (n.state != null && n.state !== '') { statesPresent[n.state] = true; } (n.children || []).forEach(w); })(root); });
      var kindOn = {}, stateOn = {}, textq = '';
      Object.keys(kindsPresent).forEach(function (k) { kindOn[k] = true; });
      Object.keys(statesPresent).forEach(function (s) { stateOn[s] = true; });

      var controls = el('div', { 'class': 'plan-tree-controls' });
      var legend = el('div', { 'class': 'plan-tree-legend' });
      legend.appendChild(el('span', { 'class': 'plan-tree-legend-h', text: 'Kind' }));
      KIND_LABELS.forEach(function (kl) {
        if (!kindsPresent[kl[0]]) { return; }
        legend.appendChild(el('span', { 'class': 'plan-tree-legend-item' }, [
          el('span', { 'class': 'plan-tree-legend-swatch', 'data-kind': kl[0] }),
          el('span', { 'class': 'plan-tree-legend-lab', text: kl[1] })
        ]));
      });
      legend.appendChild(el('span', { 'class': 'plan-tree-legend-h', text: 'State' }));
      STATE_ORDER.forEach(function (s) {
        if (!statesPresent[s]) { return; }
        legend.appendChild(el('span', { 'class': 'plan-tree-legend-item' }, [
          el('span', { 'class': 'plan-tree-legend-swatch', 'data-state': s }),
          el('span', { 'class': 'plan-tree-legend-lab', text: s })
        ]));
      });

      var toolbar = el('div', { 'class': 'plan-tree-filters' });
      var kindRow = el('div', { 'class': 'plan-tree-filter-row' }, [el('span', { 'class': 'plan-tree-filter-lab', text: 'Kinds' })]);
      KIND_LABELS.forEach(function (kl) {
        if (!kindsPresent[kl[0]]) { return; }
        var chip = el('button', { 'class': 'plan-tree-toggle is-on', type: 'button', 'data-kind': kl[0], 'aria-pressed': 'true' }, [kl[1]]);
        chip.addEventListener('click', function () { kindOn[kl[0]] = !kindOn[kl[0]]; chip.classList.toggle('is-on', kindOn[kl[0]]); chip.setAttribute('aria-pressed', kindOn[kl[0]] ? 'true' : 'false'); repaint(); });
        kindRow.appendChild(chip);
      });
      var stateRow = el('div', { 'class': 'plan-tree-filter-row' }, [el('span', { 'class': 'plan-tree-filter-lab', text: 'States' })]);
      STATE_ORDER.forEach(function (s) {
        if (!statesPresent[s]) { return; }
        var chip = el('button', { 'class': 'plan-tree-toggle is-on', type: 'button', 'data-state': s, 'aria-pressed': 'true' }, [s]);
        chip.addEventListener('click', function () { stateOn[s] = !stateOn[s]; chip.classList.toggle('is-on', stateOn[s]); chip.setAttribute('aria-pressed', stateOn[s] ? 'true' : 'false'); repaint(); });
        stateRow.appendChild(chip);
      });
      var textInput = el('input', { 'class': 'plan-tree-search', type: 'search', placeholder: 'Filter by label, id or slug…', 'aria-label': 'Filter tree by text' });
      textInput.addEventListener('input', function () { textq = String(textInput.value || '').trim().toLowerCase(); repaint(); });
      var searchRow = el('div', { 'class': 'plan-tree-filter-row' }, [el('span', { 'class': 'plan-tree-filter-lab', text: 'Find' }), textInput]);
      toolbar.appendChild(kindRow); toolbar.appendChild(stateRow); toolbar.appendChild(searchRow);
      var countLine = el('p', { 'class': 'plan-tree-count', role: 'status' });
      controls.appendChild(legend); controls.appendChild(toolbar); controls.appendChild(countLine);
      wrap.appendChild(controls);

      // M4b: split into the tree column + a session-detail column. Clicking a
      // session paints its evidence (receipts, fact provenance, announced focus)
      // through the generated client. Notices + filters stay above the split.
      var layout = el('div', { 'class': 'plan-tree-layout' });
      var treeCol = el('div', { 'class': 'plan-tree-col' });
      var detailCol = el('div', { 'class': 'session-detail-col' },
        [el('p', { 'class': 'ctl-desc', text: 'Select a session to view its evidence — receipts, fact provenance, announced focus.' })]);
      function onSelect(node) { renderSessionDetail(detailCol, node, api); }
      layout.appendChild(treeCol);
      layout.appendChild(detailCol);
      wrap.appendChild(layout);

      function nodeMatches(n) {
        if (!kindOn[n.type]) { return false; }
        if (n.state != null && n.state !== '' && !stateOn[n.state]) { return false; }
        if (textq) {
          var hay = String(n.label || '') + ' ' + String(n.id || '');
          if (String(n.id || '').indexOf('execplan:') === 0) { hay += ' ' + String(n.id).slice(9); }
          if (n.unresolvedSlug) { hay += ' ' + n.unresolvedSlug; }
          if (hay.toLowerCase().indexOf(textq) < 0) { return false; }
        }
        return true;
      }
      // Keep ancestors of matches: a node survives if it matches OR any descendant
      // survives; its whole subtree is dropped only when nothing under it matches.
      function filterNode(n) {
        var kids = (n.children || []).map(filterNode).filter(Boolean);
        var self = nodeMatches(n);
        if (!self && kids.length === 0) { return null; }
        var copy = {}; for (var k in n) { copy[k] = n[k]; }
        copy.children = kids;
        return copy;
      }
      function repaint() {
        var froots = tree.roots.map(filterNode).filter(Boolean);
        treeCol.textContent = '';
        if (!froots.length) {
          treeCol.appendChild(el('p', { 'class': 'ctl-desc', text: 'No nodes match the current filters.' }));
        } else {
          froots.forEach(function (root) { treeCol.appendChild(planTreeNode(root, 0, onSelect)); });
        }
        var shown = 0;
        froots.forEach(function (root) { (function w(n) { shown++; (n.children || []).forEach(w); })(root); });
        countLine.textContent = 'showing ' + shown + ' of ' + totalNodes + ' nodes';
      }
      repaint();
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
  //  Site map (console-surfaces-remediation M8) — a real, click-through map of
  //  the console. Every node is an <a href="#/…"> to a REAL registered route,
  //  DERIVED at render time from the page registry (window.CruxPages.DESTS +
  //  PAGES) so it can never drift from the nav. The registry lacks two things a
  //  map needs — operator-voiced "what you'll find / when to use" copy, and the
  //  destination-IS-the-page routes (canvas views, explorer, sitemap, rings) —
  //  so those live in the small SITEMAP_META / synthetic-node maps below and are
  //  the ONLY hand-authored surface. Reads nothing; renders in every posture.
  //  Highlights where the operator just came from ("you are here", from
  //  window.CRUX_PREV_HASH) and numbers a recommended first-run path.
  // =======================================================================
  // Section glyphs, keyed by DEST *icon* id (copied from the shell's ICONS so the
  // map header art matches the Command rail 1:1).
  var SITEMAP_ICONS = {
    overwatch: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3"/></svg>',
    work: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="5" height="16" rx="1"/><rect x="10" y="4" width="5" height="10" rx="1"/><rect x="17" y="4" width="4" height="13" rx="1"/></svg>',
    memory: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v6c0 1.7 3.6 3 8 3s8-1.3 8-3V6"/><path d="M4 12v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"/></svg>',
    trust: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/><path d="M9 12l2 2 4-4"/></svg>',
    meters: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19a8 8 0 0 1 16 0"/><path d="M12 19l4-5"/><circle cx="12" cy="19" r="1.4"/></svg>',
    settings: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-1.8-.3 1.6 1.6 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.6 1.6 0 0 0-1-1.5 1.6 1.6 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.6 1.6 0 0 0 .3-1.8 1.6 1.6 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.6 1.6 0 0 0 1.5-1 1.6 1.6 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.6 1.6 0 0 0 1.8.3H9a1.6 1.6 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.6 1.6 0 0 0 1 1.5 1.6 1.6 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0-.3 1.8V9a1.6 1.6 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.6 1.6 0 0 0-1.5 1z"/></svg>',
    canvas: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>',
    search: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>',
    map: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="3" width="6" height="5" rx="1.4"/><rect x="3" y="16" width="6" height="5" rx="1.4"/><rect x="15" y="16" width="6" height="5" rx="1.4"/><path d="M12 8v4M6 16v-2.5h12V16"/></svg>',
    rings: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5.5"/><circle cx="12" cy="12" r="2"/><path d="M12 3v3"/></svg>'
  };
  // Section accent, keyed by DEST *id* (var(--) tokens only).
  var SITEMAP_ACCENT = {
    overwatch: 'var(--acc)', work: 'var(--acc)', memory: 'var(--trust)', trust: 'var(--ok)',
    meters: 'var(--warn)', system: 'var(--ink3)', canvas: 'var(--acc)', explorer: 'var(--trust)',
    sitemap: 'var(--acc)', rings: 'var(--trust)'
  };
  // One-line operator copy per node — "what you'll find / when to use", grounded
  // in what each page does TODAY (post M2–M7), honest where feature-gated. Keyed
  // by page id, plus synthetic keys for the destination-IS-the-page surfaces and
  // the Overwatch landing root (`#/overwatch`). Missing key → the registry `sub`
  // (endpoint noise stripped) is the honest fallback.
  var SITEMAP_META = {
    '#/overwatch':     'Start here — needs-you, fleet and live pulse at a glance',
    'cx-overview':     'Daemon posture, readiness and capacity, one screen',
    'cx-activity':     'Live session stream beside the needs-you and fleet panels',
    'cx-coord':        'Who is working right now — live sessions and leases',
    'cx-orchestrators':'Group plans running under one session',
    'cx-punchcards':   'Advisory path leases, grouped by session',
    'cx-work':         "ExecPlans as true north — resume, don't respawn",
    'cx-activity-log': 'The all-sessions live journal — searchable, streaming',
    'cx-projects':     'Repos, planning target, passports and working tenants',
    'cx-sessions':     'Who worked, on what plan, with what tokens',
    'cx-facts':        'Browse and search the whole visible fact store — time-machine included',
    'cx-memory':       'Recent facts per tenant — system tenants hidden by default',
    'cx-tenants':      'Memory stores and their AMR lane routing',
    'cx-documents':    'What the daemon has read — and how to feed it more',
    'cx-review':       'Contradictions and guarded consolidation, waiting for judgment',
    'cx-lane-weights': 'Expert RRF lane weights — operator controls',
    'cx-receipts':     'The signed evidence trail — verify Ed25519 proofs verbatim',
    'cx-gates':        'Approvals waiting on you — high-risk transitions pause here',
    'cx-mints':        'Agent-requested passports — review, then accept or reject',
    'cx-passport':     'Agent and people identities — create and view passports',
    'cx-identity':     'Cross-daemon identity links — inference proposes, consent disposes',
    'cx-mediation':    'Engine gateway posture — off on this CPU-only node',
    'cx-cost':         'Sessions × token burn, with plan attribution',
    'cx-usage':        'Aggregate call volume and average spend',
    'cx-settings':     'Access, sync, freshness, retention, appearance — configure rarely',
    'cx-integrations': 'Installed packs and their passport grants',
    'cx-extensions':   'Signed third-party manifests — per-passport grants',
    'cx-workbench':    'Operator tooling — read tools live, writes gated',
    'cx-raw':          'Raw JSON-RPC console — scopes attach automatically',
    'canvas:board':    'Size-adaptive tile dashboard — drag, pan, expand in place',
    'canvas:graph':    'Relation graph — real edges, ring layout when zoomed out',
    'canvas:tree':     'Plan tree — colour-coded by kind and state, filterable',
    'explorer':        'Search the corpus — local retrieval or mediated WikiCrux',
    'sitemap':         "You're here — the whole console, one guided map",
    'rings':           'The clock of work — the live work board, facts and glance as an animated ring'
  };
  // Honest per-node badges — access posture + feature-gating, stated on the card.
  var SITEMAP_BADGE = {
    'cx-lane-weights': { t: 'OPERATOR', cls: 'op' },
    'cx-mints':        { t: 'OPERATOR', cls: 'op' },
    'cx-raw':          { t: 'OPERATOR', cls: 'op' },
    'cx-identity':     { t: 'FEATURE-GATED', cls: 'gate' },
    'cx-mediation':    { t: 'ENGINE OFF', cls: 'gate' }
    // rings: no badge — it is now a native, live-wired page like every other
    // content surface (was PROTOTYPE while it shipped as an embedded iframe mock).
  };
  // Recommended first-run path (node keys, in order). Rendered as small numerals
  // on the matching cards + a legend; steps whose node is absent in this posture
  // are skipped so the numbering stays honest.
  var SITEMAP_START = ['#/overwatch', 'cx-sessions', 'cx-facts', 'cx-receipts'];
  var SITEMAP_START_LABEL = { '#/overwatch': 'Overwatch', 'cx-sessions': 'Sessions', 'cx-facts': 'Facts', 'cx-receipts': 'Receipts' };

  // Strip trailing "· /v1/…" endpoint noise from a registry sub for map display.
  function siteMapCleanSub(sub) {
    if (!sub) { return ''; }
    return String(sub).replace(/\s*·\s*\/v1\/\S*/g, '').trim();
  }

  // Build the map sections from the live registry. Returns [{ dest, nodes:[{ key,
  // name, href, sub }] }]. Pro-only pages are omitted (Pro mode owns them);
  // operator-only pages are omitted for a customer view so every rendered node
  // resolves to a live route in the current posture (no dead nodes).
  function siteMapSections(isOp) {
    var pages = (typeof window !== 'undefined') ? window.CruxPages : null;
    if (!pages || !pages.DESTS) { return []; }
    var byDest = {};
    Object.keys(pages.PAGES).forEach(function (id) {
      var p = pages.PAGES[id];
      (byDest[p.dest] = byDest[p.dest] || []).push(p);
    });
    return pages.DESTS.map(function (d) {
      var nodes = [];
      var list = byDest[d.id] || [];
      if (list.length) {
        if (d.id === 'overwatch') {
          nodes.push({ key: '#/overwatch', name: 'Home · at a glance', href: '#/overwatch' });
        }
        list.forEach(function (p) {
          if (p.pro === true) { return; }               // Pro-mode-only → not on this map
          if (p.operatorOnly && !isOp) { return; }      // customer can't reach it → skip
          nodes.push({ key: p.id, name: p.title, href: '#/' + d.id + '/' + p.id, sub: p.sub });
        });
      } else if (d.id === 'canvas') {
        nodes.push({ key: 'canvas:board', name: 'Board', href: '#/canvas/board' });
        nodes.push({ key: 'canvas:graph', name: 'Graph', href: '#/canvas/graph' });
        nodes.push({ key: 'canvas:tree', name: 'Tree', href: '#/canvas/tree' });
      } else {
        // explorer / sitemap / rings — the destination IS the page.
        nodes.push({ key: d.id, name: d.label, href: '#/' + d.id });
      }
      return { dest: d, nodes: nodes };
    }).filter(function (s) { return s.nodes.length; });
  }

  // Resolve which node the operator came FROM (window.CRUX_PREV_HASH) → node key,
  // for the "you are here" marker. Falls back to the Site map's own node when the
  // origin is unknown or was the map itself.
  function siteMapHereKey(prevHash, sections) {
    var h = String(prevHash || '').replace(/^#\/?/, '');
    var qi = h.indexOf('?'); if (qi >= 0) { h = h.slice(0, qi); }
    var parts = h.split('/').filter(Boolean);
    var dest = parts[0], leaf = parts[1];
    if (!dest || dest === 'sitemap') { return 'sitemap'; }
    if (dest === 'canvas') { return 'canvas:' + (leaf === 'graph' || leaf === 'tree' ? leaf : 'board'); }
    if (dest === 'explorer' || dest === 'rings') { return dest; }
    if (dest === 'overwatch' && !leaf) { return '#/overwatch'; }
    var present = {};
    sections.forEach(function (s) { s.nodes.forEach(function (n) { present[n.key] = s.dest.id; }); });
    if (leaf && present[leaf]) { return leaf; }         // explicit page node
    // Dest root with no explicit (or a hidden) page → that section's first node.
    var hit = null;
    sections.forEach(function (s) { if (!hit && s.dest.id === dest) { hit = s.nodes[0] && s.nodes[0].key; } });
    return hit || 'sitemap';
  }

  function renderSiteMap(host) {
    host.textContent = '';
    var isOp = (typeof window !== 'undefined' && window.CRUX_POSTURE === 'operator');
    var sections = siteMapSections(isOp);
    var prev = (typeof window !== 'undefined' && window.CRUX_PREV_HASH) || '';
    var hereKey = siteMapHereKey(prev, sections);

    // Start-here numerals — number only the steps whose node is present.
    var present = {};
    sections.forEach(function (s) { s.nodes.forEach(function (n) { present[n.key] = true; }); });
    var stepOf = {}; var step = 0;
    SITEMAP_START.forEach(function (k) { if (present[k]) { step++; stepOf[k] = step; } });

    var grid = el('div', { 'class': 'map-grid' });
    var nodeCount = 0;
    sections.forEach(function (s) {
      var d = s.dest;
      var sec = el('div', { 'class': 'map-sec' });
      if (sec.style && sec.style.setProperty) { sec.style.setProperty('--sec-c', SITEMAP_ACCENT[d.id] || 'var(--acc)'); }
      var ico = el('span', { 'class': 'map-ico' }); ico.innerHTML = SITEMAP_ICONS[d.icon] || '';
      if (ico.querySelector) { var icoSvg = ico.querySelector('svg'); if (icoSvg) { icoSvg.setAttribute('width', '16'); icoSvg.setAttribute('height', '16'); } }
      // Header links to the destination root.
      var head = el('a', { 'class': 'map-head', href: '#/' + d.id },
        [el('h3', null, [ico, doc().createTextNode(d.label)])]);
      sec.appendChild(head);
      sec.appendChild(el('div', { 'class': 'tag', text: d.sub || '' }));
      s.nodes.forEach(function (n) {
        nodeCount++;
        var isHere = (n.key === hereKey);
        var a = el('a', { 'class': 'map-page' + (isHere ? ' is-here' : ''), href: n.href });
        if (isHere) { a.setAttribute('aria-current', 'page'); }
        var b = el('b');
        if (stepOf[n.key]) { b.appendChild(el('span', { 'class': 'map-step', 'aria-hidden': 'true', text: String(stepOf[n.key]) })); }
        b.appendChild(doc().createTextNode(n.name));
        var badge = SITEMAP_BADGE[n.key];
        if (badge) { b.appendChild(el('span', { 'class': 'anno ' + badge.cls, text: badge.t })); }
        if (isHere) { b.appendChild(el('span', { 'class': 'map-here', text: 'YOU ARE HERE' })); }
        a.appendChild(b);
        a.appendChild(el('div', { 'class': 'why', text: SITEMAP_META[n.key] || siteMapCleanSub(n.sub) }));
        a.appendChild(el('div', { 'class': 'map-route', text: n.href }));
        sec.appendChild(a);
      });
      grid.appendChild(sec);
    });
    host.appendChild(grid);

    // Footer: recommended first-run path + honest counts.
    var note = el('div', { 'class': 'map-note' });
    var legend = el('div', { 'class': 'map-legend' });
    legend.appendChild(el('span', { 'class': 'map-legend-h', text: 'New here? Follow the path:' }));
    SITEMAP_START.forEach(function (k) {
      if (!stepOf[k]) { return; }
      legend.appendChild(el('span', { 'class': 'map-legend-step' },
        [el('span', { 'class': 'map-step', text: String(stepOf[k]) }), doc().createTextNode(' ' + (SITEMAP_START_LABEL[k] || k))]));
    });
    note.appendChild(legend);
    var count = el('p', { 'class': 'map-count' }, [
      el('b', { text: sections.length + ' destinations · ' + nodeCount + ' surfaces.' }),
      doc().createTextNode(' Every card is a live link to its route — derived from the page registry, so this map cannot drift from the nav. Operator-only and feature-gated surfaces are labelled; the highlighted card is where you came from.')
    ]);
    note.appendChild(count);
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

  // ─────────────────────────────────────────────────────────────────────────
  //  cx-cost — sessions × token burn (console-surfaces-remediation M5)
  //
  //  Custom-rendered like renderSessionsBrowser: a table of one row per posted
  //  session cost report, filters (passport / date range / plan / min-burn), a
  //  totals row, and a top-burn horizontal bar chart. Data comes from the
  //  in-memory cost store via GET /v1/cost/report (sessions[] carries the window,
  //  burn totals, poster passport, and producer-derived execplan_slugs — the
  //  additive M5 fields); the ExecPlan join is client-side over /v1/work.
  //
  //  Honesty: the store is POST-fed by `corecruxctl session cost --post` and gated
  //  by CORECRUXD_FEATURE_COST_LENS — the empty state names both. A session that
  //  carries execplan_slugs links PRECISELY to those plans (method "link"); one
  //  without falls back to window-overlap on the board (method "window-inferred"),
  //  labelled so it never reads as falsely precise.
  //  Through-client only (fetchJSON → CruxApi.get), el()/textContent, no innerHTML.
  // ─────────────────────────────────────────────────────────────────────────
  function renderCostBrowser(host) {
    host.textContent = '';
    function arr(v) { return Array.isArray(v) ? v : []; }
    function compactN(n) {
      if (typeof n !== 'number' || !isFinite(n)) { return '—'; }
      if (n >= 1e6) { return (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + 'M'; }
      if (n >= 1000) { var k = n / 1000; return (k >= 100 ? Math.round(k) : k.toFixed(1)) + 'k'; }
      return String(n);
    }
    function shortId(id) { var s = String(id || ''); return s.length > 10 ? s.slice(0, 8) + '…' : (s || '(no id)'); }
    function tsOf(s) { var t = Date.parse(s.started_at || s.received_at || s.generated_at || ''); return isFinite(t) ? t : null; }
    function fmtDay(iso) { var t = Date.parse(iso || ''); if (!isFinite(t)) { return '—'; } try { return new Date(t).toISOString().slice(0, 16).replace('T', ' '); } catch (e) { return '—'; } }
    function windowLabel(s) {
      if (s.started_at && s.ended_at) {
        var a = fmtDay(s.started_at), b = Date.parse(s.ended_at); var bt = isFinite(b) ? new Date(b).toISOString().slice(11, 16) : '';
        return a + (bt ? ('→' + bt) : '');
      }
      return 'rcvd ' + fmtDay(s.received_at);
    }
    function isLinked(s) { return arr(s.execplan_slugs).length > 0; }
    function planIdsFor(s) { return arr(s.execplan_slugs).map(function (sl) { return 'execplan:' + sl; }); }

    var state = { all: [], plans: {}, q: '', passport: '', plan: '', minBurn: 0, from: '', to: '', loading: false, token: 0 };

    // ---- toolbar (filters) ----
    var searchInput = el('input', { 'class': 'facts-input', type: 'search', placeholder: 'filter id / source / passport / plan…', 'aria-label': 'filter sessions' });
    var passportSel = el('select', { 'class': 'facts-input', 'aria-label': 'passport filter' });
    var planSel = el('select', { 'class': 'facts-input', 'aria-label': 'plan filter' });
    var minBurnInput = el('input', { 'class': 'facts-input facts-asof', type: 'number', min: '0', step: '1000', placeholder: 'min output tok', 'aria-label': 'minimum output-token burn' });
    var fromInput = el('input', { 'class': 'facts-input facts-asof', type: 'date', 'aria-label': 'from date' });
    var toInput = el('input', { 'class': 'facts-input facts-asof', type: 'date', 'aria-label': 'to date' });
    function field(label, node) { return el('label', { 'class': 'facts-field' }, [el('span', { text: label }), node]); }
    var toolbar = el('div', { 'class': 'facts-toolbar' }, [
      field('filter', searchInput), field('passport', passportSel), field('plan', planSel),
      field('min burn (out)', minBurnInput), field('from', fromInput), field('to', toInput)
    ]);
    var countLine = el('p', { 'class': 'facts-count' });
    var banner = el('div', { 'class': 'facts-banner' }); banner.style.display = 'none';
    var chartWrap = el('div', { 'class': 'cost-chart' });
    var totalsRow = el('div', { 'class': 'cost-totals' });
    var listWrap = el('div', { 'class': 'facts-groups' });
    host.appendChild(el('div', { 'class': 'facts-browser' }, [toolbar, countLine, banner, chartWrap, totalsRow, listWrap]));

    function opt(sel, value, label) { sel.appendChild(el('option', { value: value }, [label])); }
    function fillSelects() {
      passportSel.textContent = ''; planSel.textContent = '';
      opt(passportSel, '', 'all passports'); opt(planSel, '', 'all plans');
      var pps = {}, pls = {};
      state.all.forEach(function (s) {
        var pp = s.actor_passport || ''; if (pp && pp !== '__anon__') { pps[pp] = 1; }
        arr(s.execplan_slugs).forEach(function (sl) { pls[sl] = 1; });
      });
      Object.keys(pps).sort().forEach(function (p) { opt(passportSel, p, p); });
      Object.keys(pls).sort().forEach(function (p) { opt(planSel, p, p); });
      passportSel.value = state.passport; planSel.value = state.plan;
    }

    function matches(s) {
      if (state.q) {
        var hay = ((s.session_id || '') + ' ' + (s.source || '') + ' ' + (s.actor_passport || '') + ' ' + arr(s.execplan_slugs).join(' ')).toLowerCase();
        if (hay.indexOf(state.q) < 0) { return false; }
      }
      if (state.passport && s.actor_passport !== state.passport) { return false; }
      if (state.plan && arr(s.execplan_slugs).indexOf(state.plan) < 0) { return false; }
      if (state.minBurn > 0 && !((s.output_tokens || 0) >= state.minBurn)) { return false; }
      if (state.from || state.to) {
        var t = tsOf(s); if (t == null) { return false; }
        if (state.from) { var f = Date.parse(state.from + 'T00:00:00Z'); if (isFinite(f) && t < f) { return false; } }
        if (state.to) { var e = Date.parse(state.to + 'T23:59:59Z'); if (isFinite(e) && t > e) { return false; } }
      }
      return true;
    }

    function chip(cls, text, title) { return el('span', { 'class': cls, title: title || '' }, [text]); }
    function planChips(s) {
      if (!isLinked(s)) { return [chip('sess-chip', 'window-inferred', 'no producer link — burn attributes to plans by window-overlap on the board')]; }
      return planIdsFor(s).map(function (id) {
        var p = state.plans[id];
        var txt = id.replace(/^execplan:/, '') + (p && p.state ? (' · ' + p.state) : '');
        return chip('sess-chip sess-chip-plan', txt, p ? ('ExecPlan (producer link) — ' + (p.title || id)) : (id + ' — not yet on the work board'));
      });
    }
    function methodChip(s) {
      return isLinked(s)
        ? chip('sess-chip cost-method link', 'link', 'precise: this session named the plan(s) it worked')
        : chip('sess-chip cost-method window', 'window', 'coarse: attributed to overlapping plan windows');
    }

    function rowEl(s) {
      var head = el('div', { 'class': 'facts-rhead' }, [
        el('span', { 'class': 'facts-key', text: shortId(s.session_id) }),
        methodChip(s),
        el('span', { 'class': 'facts-time', text: windowLabel(s) })
      ]);
      var metaChips = el('div', { 'class': 'sess-rmeta' }, [
        chip('sess-chip', compactN(s.context_tokens || 0) + ' ctx', 'measured context tokens (Σ)'),
        chip('sess-chip cost-out', compactN(s.output_tokens || 0) + ' out', 'output tokens generated (Σ)'),
        (s.assistant_turns ? chip('sess-chip', s.assistant_turns + ' turns', 'assistant turns') : null),
        (s.actor_passport && s.actor_passport !== '__anon__') ? chip('sess-chip sess-chip-pass', s.actor_passport, 'poster passport') : null
      ].concat(planChips(s)));
      var sub = el('div', { 'class': 'facts-val', text: s.source || '(no source)' });
      var detail = el('div', { 'class': 'facts-detail' });
      var row = el('div', { 'class': 'facts-row', role: 'button', tabindex: '0' }, [head, sub, metaChips, detail]);
      var opened = false;
      function toggle() { var o = row.classList.toggle('open'); if (o && !opened) { opened = true; expandDetail(detail, s); } }
      row.addEventListener('click', function (e) { if (e.target && e.target.closest && (e.target.closest('a') || e.target.closest('.facts-detail'))) { return; } toggle(); });
      row.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
      return row;
    }
    function kvGrid(pairs) {
      var meta = el('div', { 'class': 'facts-kv' });
      pairs.forEach(function (kv) { if (kv[1] == null || kv[1] === '') { return; } meta.appendChild(el('span', { 'class': 'facts-kv-k', text: kv[0] })); meta.appendChild(el('span', { 'class': 'facts-kv-v', text: String(kv[1]) })); });
      return meta;
    }
    function sectionLabel(t) { return el('div', { 'class': 'facts-vlabel', text: t }); }
    function expandDetail(detail, s) {
      detail.textContent = '';
      detail.appendChild(sectionLabel('session'));
      detail.appendChild(kvGrid([
        ['session id', s.session_id], ['source', s.source],
        ['window', (s.started_at && s.ended_at) ? (s.started_at + '  →  ' + s.ended_at) : '(no transcript window — placed at ' + (s.received_at || '?') + ')'],
        ['received', s.received_at], ['generated', s.generated_at]
      ]));
      detail.appendChild(sectionLabel('burn'));
      detail.appendChild(kvGrid([
        ['context tokens (Σ)', compactN(s.context_tokens || 0) + '  (' + (s.context_tokens || 0) + ')'],
        ['output tokens (Σ)', compactN(s.output_tokens || 0) + '  (' + (s.output_tokens || 0) + ')'],
        ['context / turn', compactN(s.context_tokens_per_turn || 0)], ['assistant turns', s.assistant_turns]
      ]));
      detail.appendChild(sectionLabel('linked ExecPlan'));
      if (isLinked(s)) {
        var list = el('div', { 'class': 'facts-kv' });
        planIdsFor(s).forEach(function (id) {
          var p = state.plans[id];
          list.appendChild(el('span', { 'class': 'facts-kv-k', text: id }));
          list.appendChild(el('span', { 'class': 'facts-kv-v', text: p ? ((p.title || '—') + (p.state ? (' · ' + p.state) : '') + (p.current_milestone ? (' · ' + p.current_milestone) : '')) : 'not yet on the work board (rsync lag)' }));
        });
        detail.appendChild(list);
        detail.appendChild(el('p', { 'class': 'ctl-desc', text: 'producer link (method "link"): this session named these plans in its transcript — the burn credits them precisely (even-split across N).' }));
      } else {
        detail.appendChild(el('p', { 'class': 'ctl-desc sess-empty', text: 'no producer link — this session had no execplan_slugs. Its burn attributes to plans whose fact-window overlaps the session window (method "window", coarse). See the plan board /v1/work for the per-plan token_burn rollup.' }));
      }
      detail.appendChild(el('p', { 'class': 'ctl-desc', text: 'attribution recomputed read-time in cost_attribution.rs; passport = poster identity (' + (s.actor_passport || '__anon__') + ').' }));
    }

    function renderChart(visible) {
      chartWrap.textContent = '';
      var top = visible.slice().sort(function (a, b) { return (b.output_tokens || 0) - (a.output_tokens || 0); }).slice(0, 10);
      if (!top.length || (top[0].output_tokens || 0) <= 0) { return; }
      chartWrap.appendChild(el('div', { 'class': 'cost-chart-title', text: 'Top sessions by output tokens' }));
      var max = top[0].output_tokens || 1;
      top.forEach(function (s) {
        var pct = Math.max(2, Math.round(100 * (s.output_tokens || 0) / max));
        var fill = el('div', { 'class': 'cost-bar-fill' }); fill.style.width = pct + '%';
        chartWrap.appendChild(el('div', { 'class': 'cost-bar' }, [
          el('div', { 'class': 'cost-bar-label', title: s.session_id || '', text: shortId(s.session_id) }),
          el('div', { 'class': 'cost-bar-track' }, [fill]),
          el('div', { 'class': 'cost-bar-val', text: compactN(s.output_tokens || 0) })
        ]));
      });
    }
    function renderTotals(visible) {
      totalsRow.textContent = '';
      if (!visible.length) { return; }
      var ctx = 0, out = 0;
      visible.forEach(function (s) { ctx += (s.context_tokens || 0); out += (s.output_tokens || 0); });
      totalsRow.appendChild(el('span', { 'class': 'cost-totals-k', text: 'TOTALS' }));
      totalsRow.appendChild(el('span', { 'class': 'cost-totals-v' }, [el('b', { text: compactN(ctx) }), ' context']));
      totalsRow.appendChild(el('span', { 'class': 'cost-totals-v' }, [el('b', { text: compactN(out) }), ' output']));
      totalsRow.appendChild(el('span', { 'class': 'cost-totals-v' }, [el('b', { text: String(visible.length) }), ' session' + (visible.length === 1 ? '' : 's')]));
    }
    function paintCount(shown) {
      countLine.textContent = '';
      var kids = [el('b', { text: String(shown) }), ' shown'];
      if (state.q || state.passport || state.plan || state.minBurn || state.from || state.to) { kids.push(' (filtered)'); }
      kids.push(' · '); kids.push(el('b', { text: String(state.all.length) })); kids.push(' session report' + (state.all.length === 1 ? '' : 's') + ' posted');
      kids.forEach(function (k) { countLine.appendChild(typeof k === 'string' ? doc().createTextNode(k) : k); });
    }
    function emptyState() {
      listWrap.textContent = '';
      chartWrap.textContent = ''; totalsRow.textContent = '';
      var box = el('div', { 'class': 'facts-empty ctl-desc' }, [
        el('p', { text: 'No session cost reports posted for this tenant.' }),
        el('p', { text: 'The token-burn lens is POST-fed: it renders reports produced by  corecruxctl session cost --post  (which parses your local Claude Code transcript). Nothing is computed until a report is posted.' }),
        el('p', { text: 'Feature gate: CORECRUXD_FEATURE_COST_LENS must be enabled on the daemon.' })
      ]);
      listWrap.appendChild(box);
      paintCount(0);
    }
    function paint() {
      state.q = (searchInput.value || '').trim().toLowerCase();
      state.passport = passportSel.value || '';
      state.plan = planSel.value || '';
      state.minBurn = Math.max(0, parseInt(minBurnInput.value, 10) || 0);
      state.from = fromInput.value || ''; state.to = toInput.value || '';
      if (!state.all.length) { emptyState(); return; }
      var visible = state.all.filter(matches);
      renderChart(visible); renderTotals(visible);
      listWrap.textContent = '';
      if (!visible.length) { listWrap.appendChild(el('p', { 'class': 'facts-empty ctl-desc', text: 'No sessions match the filters.' })); paintCount(0); return; }
      visible.forEach(function (s) { listWrap.appendChild(rowEl(s)); });
      paintCount(visible.length);
    }
    function loadPlans() {
      return fetchJSON('/v1/work?source=all').then(function (res) {
        var map = {};
        if (res.ok && res.data) {
          var items = res.data.work || res.data.items || res.data.work_items || [];
          items.forEach(function (w) { if (w && typeof w.id === 'string' && w.id.indexOf('execplan:') === 0) { map[w.id] = { state: w.state || null, current_milestone: w.current_milestone || null, title: w.title || null }; } });
        }
        state.plans = map;
      });
    }
    function load() {
      if (state.loading) { return; }
      state.loading = true; state.token++; var myToken = state.token;
      listWrap.textContent = ''; listWrap.appendChild(el('p', { 'class': 'facts-empty ctl-desc', text: 'loading…' }));
      Promise.all([fetchJSON('/v1/cost/report?tenant_id=default&token_budget=4000'), loadPlans()]).then(function (rr) {
        var res = rr[0];
        if (myToken !== state.token) { return; }
        state.loading = false;
        if (!res.ok || !res.data) {
          banner.style.display = ''; banner.className = 'facts-banner err';
          banner.textContent = (res.status === 404)
            ? 'Cost lens off — set CORECRUXD_FEATURE_COST_LENS=1 on the daemon (GET /v1/cost/report → 404).'
            : 'Cost report unavailable — ' + (res.status === 0 ? 'daemon unreachable' : 'HTTP ' + res.status) + '.';
          listWrap.textContent = ''; chartWrap.textContent = ''; totalsRow.textContent = ''; return;
        }
        banner.style.display = 'none';
        state.all = arr(res.data.sessions);
        fillSelects();
        paint();
      });
    }
    [searchInput, minBurnInput].forEach(function (n) { n.addEventListener('input', paint); });
    [passportSel, planSel, fromInput, toInput].forEach(function (n) { n.addEventListener('change', paint); });
    load();
  }

  // console-surfaces-remediation M4: the activity log is DEFAULT-ON. On open it
  // pulls the all-sessions lane (GET /v1/activity with `session` OMITTED —
  // recent_all across every session for the tenant, cursor-paged by `before` =
  // last row's `cursor`) so the operator sees the live rolling record without
  // typing a session id. Entering a session id switches to that single session
  // (server `recent`, newest `limit`, no older paging); clearing it returns to
  // all-sessions. Search + kind chips are CLIENT-SIDE over the LOADED rows
  // (labelled so — the daemon has no activity full-text search). Live tail: the
  // `activity.appended` SSE carries ids-only, so the honest-cheap merge refetches
  // page 1 for the current mode and prepends genuinely-new rows. Through-client
  // only (activityBackfill → CruxApi.activity), el()/textContent, no innerHTML.
  var ACT_DOM_CAP = 1500;               // hard ceiling on rendered rows (never all-in)
  // Page-size budget for the default-on first pull: sized so the all-sessions
  // lane opens ALREADY populated (a rolling-log surface, not an empty prompt) —
  // ~80 rows on production-shaped data (200-char previews); `limit` caps at 100
  // and the budget binds first. Older pages reuse the same budget via `before`.
  var ACT_DEFAULT_BUDGET = 8000;
  var ACT_PAGE_LIMIT = 100;
  function renderActivityLog(host) {
    host.textContent = '';
    if (__actLogES) { try { __actLogES.close(); } catch (e) { /* noop */ } __actLogES = null; }

    function nfmt(n) { if (typeof n !== 'number' || !isFinite(n)) { return (n == null) ? '—' : String(n); } try { return n.toLocaleString('en-US'); } catch (e) { return String(n); } }
    function shortId(id) { var s = String(id || ''); return s.length > 8 ? s.slice(0, 8) : (s || '—'); }
    function relTime(iso) {
      var t = Date.parse(iso || ''); if (!isFinite(t)) { return String(iso || '—'); }
      var s = Math.max(0, Math.round((Date.now() - t) / 1000));
      if (s < 60) { return s + 's ago'; }
      var m = Math.round(s / 60); if (m < 60) { return m + 'm ago'; }
      var h = Math.round(m / 60); if (h < 48) { return h + 'h ago'; }
      return Math.round(h / 24) + 'd ago';
    }

    var state = {
      tenant: 'default', session: '', budget: ACT_DEFAULT_BUDGET, limit: ACT_PAGE_LIMIT,
      rows: [], seen: {}, kindsPresent: {}, kindsOff: {},
      nextCursor: null, hasMore: false, truncated: false,
      loading: false, token: 0, deb: null, liveDeb: null
    };
    function rowKey(r) { return (r.session_id || '') + ':' + r.seq; }
    // Newest-first invariant. Rows carry a monotonic per-row `cursor` (µs since
    // epoch) — the authoritative recency key; ts+seq is the honest fallback when
    // an older daemon omits it. state.rows is kept sorted DESC by this key after
    // every load/merge so the FIRST rendered row is ALWAYS the newest, regardless
    // of which path (initial page, Load-older append, or SSE merge) added it or
    // what order the server returned them in. (Previously order was implicit —
    // trusting the server's DESC feed + the correct insertion side — with no
    // enforced invariant, so any out-of-order page or merge inverted the DOM.)
    function actSortKey(r) {
      var c = Number(r && r.cursor);
      if (isFinite(c)) { return c; }
      var t = Date.parse((r && r.ts) || '');
      return (isFinite(t) ? t * 1000 : 0) + (parseInt(r && r.seq, 10) || 0);
    }
    function sortRowsNewestFirst() { state.rows.sort(function (a, b) { return actSortKey(b) - actSortKey(a); }); }
    function anyKindOff() { return Object.keys(state.kindsOff).some(function (k) { return state.kindsOff[k]; }); }
    function isFiltered() { return !!((searchInput.value || '').trim()) || anyKindOff(); }

    // ---- controls ----
    var sessionInput = el('input', { 'class': 'act-input', type: 'text', placeholder: 'session id — blank = all sessions', 'aria-label': 'session id filter' });
    var budgetInput = el('input', { 'class': 'act-input act-budget', type: 'number', min: '1', value: String(ACT_DEFAULT_BUDGET), 'aria-label': 'token budget per page' });
    var searchInput = el('input', { 'class': 'act-input', type: 'search', placeholder: 'filter loaded rows (client-side)…', 'aria-label': 'search loaded activity' });
    function field(label, node) { return el('label', { 'class': 'act-field' }, [el('span', { text: label }), node]); }
    var kindsWrap = el('div', { 'class': 'act-kinds' });
    var reloadBtn = el('button', { 'class': 'btn-quiet', type: 'button' }, ['Reload']);
    var liveBtn = el('button', { 'class': 'btn-quiet', type: 'button' }, ['Go live']);
    var controls = el('div', { 'class': 'act-controls' }, [field('session', sessionInput), field('token budget', budgetInput), field('search (client-side)', searchInput), kindsWrap, reloadBtn, liveBtn]);
    var liveDot = el('span', { 'class': 'act-livedot' });
    var statusText = el('span', { 'class': 'act-statustext', text: 'loading the all-sessions activity lane…' });
    var countLine = el('p', { 'class': 'facts-count' });
    var banner = el('div', { 'class': 'facts-banner' }); banner.style.display = 'none';
    var list = el('div', { 'class': 'act-list' }, [el('p', { 'class': 'ctl-desc', text: 'loading…' })]);
    var moreWrap = el('div', { 'class': 'facts-more' });
    var sentinel = el('div', { 'class': 'facts-sentinel' });
    host.appendChild(el('div', { 'class': 'act-log' }, [controls, el('div', { 'class': 'act-status' }, [liveDot, statusText]), countLine, banner, list, moreWrap, sentinel]));

    function setStatus(t) { statusText.textContent = t; }
    function modeLabel() { return state.session ? ('session ' + shortId(state.session)) : 'all sessions'; }

    // Kind chips are derived from the LOADED rows (kind → count) and filter
    // client-side (toggle off to hide). Stable ACT_KINDS order first, then any
    // unknown kinds. A chip carries its loaded count; toggling never re-queries.
    function updateKindsPresent() {
      var c = {};
      state.rows.forEach(function (r) { var k = r.kind || 'idle'; c[k] = (c[k] || 0) + 1; });
      state.kindsPresent = c;
    }
    function renderKinds() {
      kindsWrap.textContent = '';
      var order = ACT_KINDS.filter(function (k) { return state.kindsPresent[k]; });
      Object.keys(state.kindsPresent).forEach(function (k) { if (order.indexOf(k) < 0) { order.push(k); } });
      if (!order.length) { return; }
      order.forEach(function (k) {
        var on = !state.kindsOff[k];
        var chip = el('button', { 'class': 'act-kchip k-' + k + (on ? ' on' : ''), type: 'button', 'aria-pressed': on ? 'true' : 'false', title: 'client-side filter — toggle ' + k + ' rows' },
          [el('span', { text: k }), el('span', { 'class': 'act-kc', text: String(state.kindsPresent[k]) })]);
        chip.addEventListener('click', function () { state.kindsOff[k] = on; renderKinds(); paint(); });
        kindsWrap.appendChild(chip);
      });
    }

    function matches(r, q) {
      if (!q) { return true; }
      return ((r.session_id || '') + ' ' + (r.kind || '') + ' ' + (r.preview || '') + ' ' + (r.tool || '') + ' ' + (r.intent || '') + ' ' + (r.turn_id || '')).toLowerCase().indexOf(q) >= 0;
    }
    function visibleRows() {
      var q = (searchInput.value || '').trim().toLowerCase();
      return state.rows.filter(function (r) { return !state.kindsOff[r.kind || 'idle'] && matches(r, q); });
    }
    function emptyMsg() {
      return state.session
        ? ('No activity for session ' + shortId(state.session) + ' yet.')
        : 'The activity journal is empty. It fills as agents work — every question, answer, reasoning step, tool command, fact write, ExecPlan update, and handoff is appended to the activity journal (GET /v1/activity, gated by CORECRUXD_FEATURE_ACTIVITY_LOG).';
    }

    function paintCount(shown) {
      countLine.textContent = '';
      var loaded = state.rows.length;
      var kids = [el('b', { text: nfmt(shown) }), ' shown'];
      if (isFiltered()) { kids.push(' (filtered client-side)'); }
      kids.push(' of '); kids.push(el('b', { text: nfmt(loaded) })); kids.push(' loaded · ' + modeLabel());
      if (!state.session && state.hasMore) { kids.push(' · journal holds more — Load older'); }
      kids.forEach(function (k) { countLine.appendChild(typeof k === 'string' ? doc().createTextNode(k) : k); });
    }
    function paintMore() {
      moreWrap.textContent = '';
      if (state.session) {
        // Single-session view: the daemon's per-session read returns the newest
        // `limit` with no `before` older-paging. Say so honestly when it's full.
        if (state.hasMore && state.rows.length >= state.limit) {
          moreWrap.appendChild(el('p', { 'class': 'ctl-desc', text: 'Showing the most recent ' + nfmt(state.rows.length) + ' for this session — the single-session view is not paginated. Raise the token budget, or clear the session for the paged all-sessions timeline.' }));
        }
        return;
      }
      if (state.rows.length >= ACT_DOM_CAP) { moreWrap.appendChild(el('p', { 'class': 'facts-cap', text: 'Rendered ' + nfmt(ACT_DOM_CAP) + '+ rows — narrow with search or kind chips to keep paging.' })); return; }
      if (state.hasMore) {
        var btn = el('button', { 'class': 'btn-quiet', type: 'button' }, ['Load older']);
        btn.addEventListener('click', loadOlder);
        moreWrap.appendChild(btn);
      } else if (state.rows.length) {
        moreWrap.appendChild(el('p', { 'class': 'ctl-desc', text: 'End of the activity journal.' }));
      }
    }
    function paint() {
      var vis = visibleRows();
      list.textContent = '';
      if (!vis.length) {
        list.appendChild(el('p', { 'class': 'ctl-desc', text: state.rows.length ? 'No loaded rows match the current search / kind filter.' : emptyMsg() }));
      } else {
        vis.forEach(function (r) { list.appendChild(rowEl(r)); });
      }
      paintCount(vis.length);
      paintMore();
    }

    function refChip(cls, glyph, id, kind) {
      return el('span', { 'class': 'act-ref ' + cls, title: kind + ' ' + id, text: glyph + ' ' + String(id).slice(0, 14) });
    }
    function rowEl(r) {
      var meta = el('div', { 'class': 'act-meta' });
      meta.appendChild(el('span', { 'class': 'act-kind', text: r.kind || '' }));
      // Session short-id pill — click prefills the session filter (single-session).
      var sess = el('button', { 'class': 'act-sess', type: 'button', title: 'filter to session ' + (r.session_id || ''), text: shortId(r.session_id) });
      sess.addEventListener('click', function (e) { e.stopPropagation(); focusSession(r.session_id); });
      meta.appendChild(sess);
      // Relative time; absolute ISO on hover (title).
      meta.appendChild(el('span', { 'class': 'act-time', title: r.ts || '', text: relTime(r.ts) }));
      meta.appendChild(el('span', { text: 'seq ' + r.seq }));
      var extra = [r.tool, r.intent, (r.confidence != null ? ('conf ' + r.confidence) : null)].filter(Boolean).join(' · ');
      if (extra) { meta.appendChild(el('span', { text: extra })); }
      var kids = [meta, el('div', { 'class': 'act-preview', text: r.preview || '' })];
      // Receipt / fact-ref chips where present.
      var receipts = r.receipt_ids || [], facts = r.fact_refs || [];
      if (receipts.length || facts.length) {
        var refs = el('div', { 'class': 'act-refs' });
        receipts.slice(0, 3).forEach(function (rid) { refs.appendChild(refChip('rc', '✎', rid, 'receipt')); });
        if (receipts.length > 3) { refs.appendChild(el('span', { 'class': 'act-ref', text: '+' + (receipts.length - 3) + ' receipts' })); }
        facts.slice(0, 2).forEach(function (fid) { refs.appendChild(refChip('fr', '◆', fid, 'fact')); });
        if (facts.length > 2) { refs.appendChild(el('span', { 'class': 'act-ref', text: '+' + (facts.length - 2) + ' facts' })); }
        kids.push(refs);
      }
      var expand = el('div', { 'class': 'act-expand' }, [el('div', { 'class': 'act-verbatim', text: 'loading verbatim…' }), el('div', { 'class': 'act-receipts' })]);
      kids.push(expand);
      var row = el('div', { 'class': 'act-row k-' + (r.kind || 'idle'), role: 'button', tabindex: '0' }, kids);
      var opened = false;
      function toggle() { var o = row.classList.toggle('open'); if (o && !opened) { opened = true; expandRow(row, r); } }
      row.addEventListener('click', toggle);
      row.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
      return row;
    }
    function expandRow(row, r) {
      var vb = row.querySelector('.act-verbatim'), rc = row.querySelector('.act-receipts');
      // Deref uses the ROW's own session (all-sessions rows each carry one).
      var sess = r.session_id || state.session;
      if (!r.turn_id || !sess) { vb.textContent = r.preview || '(no turn id — preview only)'; return; }
      var query = { tenant_id: state.tenant, session: sess };
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

    // ---- loaders ----
    function buildQuery(before) {
      var q = { tenant_id: state.tenant, token_budget: state.budget, limit: state.limit };
      if (state.session) { q.session = state.session; }           // omit ⇒ all-sessions lane
      if (before != null) { q.before = before; }                  // older-page cursor (all-sessions only)
      return q;
    }
    function ingest(rows) {
      var fresh = [];
      (rows || []).forEach(function (r) { var k = rowKey(r); if (state.seen[k]) { return; } state.seen[k] = true; state.rows.push(r); fresh.push(r); });
      sortRowsNewestFirst();   // enforce newest-first regardless of page/server order
      return fresh;
    }
    function loadFresh() {
      state.session = (sessionInput.value || '').trim();
      state.budget = parseInt(budgetInput.value, 10) || ACT_DEFAULT_BUDGET;
      state.token++;
      state.rows = []; state.seen = {}; state.kindsPresent = {}; state.kindsOff = {};
      state.nextCursor = null; state.hasMore = false; state.truncated = false; state.loading = false;
      banner.style.display = 'none'; moreWrap.textContent = ''; kindsWrap.textContent = '';
      list.textContent = ''; list.appendChild(el('p', { 'class': 'ctl-desc', text: 'loading…' }));
      setStatus('loading the ' + modeLabel() + ' lane…');
      loadPage(null, true);
    }
    function loadPage(before, isFirst) {
      if (state.loading) { return; }
      state.loading = true;
      var myToken = state.token;
      activityBackfill(buildQuery(before)).then(function (res) {
        if (myToken !== state.token) { return; }
        state.loading = false;
        if (res.status === 404) { handle404(); return; }
        if (!res.ok || !res.data) {
          if (isFirst) { banner.style.display = ''; banner.className = 'facts-banner err'; banner.textContent = 'Activity load failed — ' + (res.status === 0 ? 'daemon unreachable' : 'HTTP ' + res.status) + '.'; list.textContent = ''; countLine.textContent = ''; }
          setStatus('load failed (HTTP ' + (res.status || '?') + ')');
          return;
        }
        var d = res.data;
        state.hasMore = !!d.has_more;
        state.nextCursor = (d.next_cursor != null) ? d.next_cursor : null;
        state.truncated = !!d.truncated;
        ingest(d.rows);
        updateKindsPresent(); renderKinds();
        setStatus(nfmt(state.rows.length) + ' row(s) loaded' + (state.truncated ? ' · page budget-truncated (raise token budget)' : '') + ' · ' + modeLabel());
        paint();
      });
    }
    function loadOlder() {
      if (state.loading || state.session || !state.hasMore) { return; }   // older-paging is all-sessions only
      if (state.rows.length >= ACT_DOM_CAP) { paintMore(); return; }
      if (state.nextCursor == null) { return; }
      loadPage(state.nextCursor, false);
    }

    // Honest flag-off state — keep the CORECRUXD_FEATURE_ACTIVITY_LOG copy. Under
    // ?demo=1 a labelled fixture stands in (a real, enabled daemon never 404s).
    function handle404() {
      var demoAct = demoOn() ? demoData('activityLog') : null;
      if (demoAct && demoAct.length) {
        state.rows = demoAct.map(function (r) { var c = {}; for (var k in r) { c[k] = r[k]; } if (!c.session_id) { c.session_id = 'sess_demo01'; } return c; });
        state.seen = {}; state.rows.forEach(function (r) { state.seen[rowKey(r)] = true; });
        sortRowsNewestFirst();
        state.hasMore = false; state.nextCursor = null;
        updateKindsPresent(); renderKinds();
        banner.style.display = ''; banner.className = 'facts-banner';
        banner.textContent = 'Activity log route is off (CORECRUXD_FEATURE_ACTIVITY_LOG) — showing a labelled demo fixture. Enable the flag for live data.';
        setStatus(nfmt(state.rows.length) + ' row(s) · demo');
        paint();
        return;
      }
      state.rows = []; state.hasMore = false; state.nextCursor = null;
      banner.style.display = ''; banner.className = 'facts-banner warn';
      banner.textContent = 'Activity log disabled on this daemon — set CORECRUXD_FEATURE_ACTIVITY_LOG=1 to enable GET /v1/activity and the live stream.';
      setStatus('route unavailable (404)');
      list.textContent = ''; list.appendChild(el('p', { 'class': 'ctl-desc', text: 'The activity journal route is off on this daemon.' }));
      countLine.textContent = ''; moreWrap.textContent = '';
    }

    // ---- live tail: the SSE event is ids-only, so refetch page 1 for the
    //      current mode (budgeted) and prepend genuinely-new rows (dedup on
    //      session:seq). Cheap + honest — no fabricated rows from the event. ----
    function focusSession(id) { sessionInput.value = id || ''; loadFresh(); }
    function scheduleLiveMerge() { clearTimeout(state.liveDeb); state.liveDeb = setTimeout(mergeNewest, 500); }
    function mergeNewest() {
      var myToken = state.token;
      activityBackfill(buildQuery(null)).then(function (res) {
        if (myToken !== state.token) { return; }
        if (!res.ok || !res.data) { return; }
        var incoming = res.data.rows || [], added = 0;
        for (var i = 0; i < incoming.length; i++) {                   // dedup-append; sort restores newest-first
          var r = incoming[i], k = rowKey(r);
          if (state.seen[k]) { continue; }
          state.seen[k] = true; state.rows.push(r); added++;
        }
        if (added) {
          sortRowsNewestFirst();                                      // genuinely-new rows float to the top by cursor
          updateKindsPresent(); renderKinds(); paint();
          setStatus('+' + added + ' new · ' + nfmt(state.rows.length) + ' loaded · live · ' + modeLabel());
        }
      });
    }
    function toggleLive() {
      if (__actLogES) { try { __actLogES.close(); } catch (e) { /* noop */ } __actLogES = null; liveDot.classList.remove('on'); liveBtn.textContent = 'Go live'; return; }
      if (typeof EventSource === 'undefined') { setStatus('Live streaming unsupported in this browser.'); return; }
      try { __actLogES = new EventSource('/v1/events/stream?types=activity.appended'); }
      catch (e) { setStatus('Live stream unavailable.'); return; }
      __actLogES.addEventListener('activity.appended', function () { scheduleLiveMerge(); });
      __actLogES.onerror = function () { liveBtn.textContent = 'Live (reconnecting)'; };
      liveDot.classList.add('on'); liveBtn.textContent = 'Stop live';
    }

    // ---- wiring ----
    reloadBtn.addEventListener('click', loadFresh);
    liveBtn.addEventListener('click', toggleLive);
    searchInput.addEventListener('input', function () { clearTimeout(state.deb); state.deb = setTimeout(paint, 200); });
    sessionInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') { loadFresh(); } });
    budgetInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') { loadFresh(); } });
    if (typeof IntersectionObserver !== 'undefined') {
      var io = new IntersectionObserver(function (entries) { if (entries[0] && entries[0].isIntersecting) { loadOlder(); } }, { rootMargin: '500px' });
      io.observe(sentinel);
    }
    // DEFAULT-ON: pull the all-sessions lane immediately (no session id required).
    loadFresh();
  }

  // ─────────────────────────────────────────────────────────────────────────
  //  M6 trust cluster — shared helpers for the four custom-rendered pages below.
  // ─────────────────────────────────────────────────────────────────────────
  function m6ShortTime(iso) { var s = String(iso || ''); return s.length >= 19 ? s.slice(0, 19).replace('T', ' ') : (s || '—'); }
  function m6Short(v, n) { var s = String(v == null ? '' : v); return s.length > n ? s.slice(0, n) + '…' : s; }
  function m6PrettyJson(v) { try { return JSON.stringify(v, null, 2); } catch (e) { return String(v); } }
  function m6Kv(pairs) {
    var meta = el('div', { 'class': 'facts-kv' });
    pairs.forEach(function (kv) {
      if (kv[1] == null || kv[1] === '') { return; }
      meta.appendChild(el('span', { 'class': 'facts-kv-k', text: kv[0] }));
      meta.appendChild(el('span', { 'class': 'facts-kv-v', text: String(kv[1]) }));
    });
    return meta;
  }
  function m6Label(t) { return el('div', { 'class': 'facts-vlabel', text: t }); }
  function m6Empty(t) { return el('p', { 'class': 'ctl-desc sess-empty', text: t }); }
  function m6Chip(cls, text, title) { return el('span', { 'class': cls, title: title || '' }, [String(text)]); }

  // ─────────────────────────────────────────────────────────────────────────
  //  cx-receipts (M6): live CROWN receipt listing over GET /v1/receipts/list
  //  (the new CE-local route). Newest-first rows (ts · kind chip · principal ·
  //  session pill · signer short + alg · body-hash short), Load-older cursor
  //  pagination, client-side search + kind chips. Row click → detail drawer:
  //  envelope fields, and for the fetchable ad_ga_* class the drawer pulls
  //  /v1/receipts/{id} + /signature + /verification THROUGH THE CLIENT and renders
  //  the daemon verification verdict VERBATIM (never a client-side "valid" claim).
  //  Envelope-only rows say why the body is unavailable on a CPU-only daemon.
  //  Through-client only (fetchJSON + CruxApi named methods), el()/textContent.
  // ─────────────────────────────────────────────────────────────────────────
  function renderReceiptsBrowser(host) {
    host.textContent = '';
    var TENANT = 'default';
    function kindTone(kind) {
      var k = String(kind || '');
      if (k.indexOf('approval') >= 0 || k.indexOf('gate') >= 0) { return 'trust'; }
      if (k.indexOf('mediation') >= 0 || k.indexOf('witness') >= 0) { return 'acc'; }
      if (k.indexOf('error') >= 0 || k.indexOf('deny') >= 0 || k.indexOf('reject') >= 0) { return 'crit'; }
      if (k.indexOf('model') >= 0 || k.indexOf('response') >= 0 || k.indexOf('stop') >= 0) { return 'ok'; }
      return 'ink3';
    }
    function qs(obj) { var p = []; Object.keys(obj).forEach(function (k) { if (obj[k] != null && obj[k] !== '') { p.push(encodeURIComponent(k) + '=' + encodeURIComponent(obj[k])); } }); return p.join('&'); }

    var state = { rows: [], seen: {}, q: '', kind: '', nextCursor: null, hasMore: false, matched: null, kindCounts: {}, loading: false, token: 0, deb: null };

    var searchInput = el('input', { 'class': 'facts-input', type: 'search', placeholder: 'search id / principal / kind / signer…', 'aria-label': 'search receipts' });
    function field(label, node) { return el('label', { 'class': 'facts-field' }, [el('span', { text: label }), node]); }
    var toolbar = el('div', { 'class': 'facts-toolbar' }, [field('search', searchInput)]);
    var countLine = el('p', { 'class': 'facts-count' });
    var chipsWrap = el('div', { 'class': 'facts-chips' });
    var banner = el('div', { 'class': 'facts-banner' }); banner.style.display = 'none';
    var listWrap = el('div', { 'class': 'facts-groups' });
    var moreWrap = el('div', { 'class': 'facts-more' });
    var help = el('div', { 'class': 'facts-banner m6-help' }, [
      el('div', { 'class': 'm6-help-h', text: 'Verify a receipt offline' }),
      el('p', { 'class': 'ctl-desc', text: 'The signed envelope (signer · alg · body hash · chain seq) is listed here for every observation. A CPU-only Crux daemon holds no dataplane, so the full CROWN body / signature / verification is dereferenceable only for the local ad_ga_* gate-approval receipts (open one to pull the daemon verdict verbatim). Dataplane receipts live in the hosted tier.' }),
      el('p', { 'class': 'ctl-desc', text: 'Offline: corecruxctl inspect-receipt <id> (or corecruxctl evidence <id> --keyring <path>) checks the Ed25519 signature without the daemon. Bundle export: GET /v1/replay/exports/receipts/{id}.' })
    ]);
    host.appendChild(el('div', { 'class': 'facts-browser' }, [toolbar, countLine, chipsWrap, banner, listWrap, moreWrap, help]));

    function matches(r, q) {
      if (!q) { return true; }
      var rc = r.receipt || {};
      return ((r.observation_id || '') + ' ' + (r.principal || '') + ' ' + (r.kind || '') + ' ' + (r.session_id || '') + ' ' + (rc.signed_by || '') + ' ' + (r.receipt_id || '')).toLowerCase().indexOf(q) >= 0;
    }
    function visibleRows() {
      var q = state.q;
      return state.rows.filter(function (r) { return (!state.kind || r.kind === state.kind) && matches(r, q); });
    }
    function paintCount() {
      countLine.textContent = '';
      var vis = visibleRows().length;
      var kids = [el('b', { text: String(vis) }), ' shown'];
      if (state.q || state.kind) { kids.push(' (filtered)'); }
      kids.push(' · '); kids.push(el('b', { text: String(state.rows.length) })); kids.push(' loaded');
      if (state.matched != null) { kids.push(' · '); kids.push(el('b', { text: String(state.matched) })); kids.push(' on this daemon'); }
      kids.forEach(function (k) { countLine.appendChild(typeof k === 'string' ? doc().createTextNode(k) : k); });
    }
    function paintChips() {
      chipsWrap.textContent = '';
      var counts = state.kindCounts || {};
      var keys = Object.keys(counts).sort(function (a, b) { return counts[b] - counts[a]; }).slice(0, 12);
      if (!keys.length) { return; }
      var allChip = el('button', { 'class': 'facts-chip' + (state.kind ? '' : ' on'), type: 'button', title: 'all kinds' }, ['all']);
      allChip.addEventListener('click', function () { state.kind = ''; paint(); });
      chipsWrap.appendChild(allChip);
      keys.forEach(function (k) {
        var active = state.kind === k;
        var chip = el('button', { 'class': 'facts-chip' + (active ? ' on' : ''), type: 'button', title: 'filter to kind ' + k }, [el('span', { text: k }), el('span', { 'class': 'c', text: String(counts[k]) })]);
        chip.addEventListener('click', function () { state.kind = active ? '' : k; paint(); });
        chipsWrap.appendChild(chip);
      });
    }
    function rowEl(r) {
      var rc = r.receipt || {};
      var head = el('div', { 'class': 'facts-rhead' }, [
        m6Chip('rcpt-kind tone-' + kindTone(r.kind), r.kind || 'observation', 'observation kind'),
        el('span', { 'class': 'facts-entity', text: r.principal || '(no principal)' }),
        r.session_short ? m6Chip('sess-chip', r.session_short, 'session ' + (r.session_id || '')) : null,
        el('span', { 'class': 'facts-time', text: m6ShortTime(r.ts) })
      ]);
      var metaChips = el('div', { 'class': 'sess-rmeta' }, [
        m6Chip('sess-chip', (rc.alg || '?') + ' · ' + (rc.signed_by_short || '—'), 'signer ' + (rc.signed_by || '')),
        m6Chip('sess-chip', 'hash ' + (rc.body_hash_short || '—'), rc.body_hash || ''),
        (r.seq != null) ? m6Chip('sess-chip', 'seq ' + r.seq, 'per-session chain sequence') : null,
        r.fetchable ? m6Chip('sess-chip rcpt-fetchable', 'CROWN body ✓', 'full body/signature/verification fetchable (ad_ga_*)') : m6Chip('sess-chip rcpt-envonly', 'envelope only', 'body lives in the hosted-tier dataplane')
      ]);
      var detail = el('div', { 'class': 'facts-detail' });
      var row = el('div', { 'class': 'facts-row tone-' + kindTone(r.kind), role: 'button', tabindex: '0' }, [head, metaChips, detail]);
      var opened = false;
      function toggle() { if (row.classList.contains('open')) { row.classList.remove('open'); return; } row.classList.add('open'); if (!opened) { opened = true; expandDetail(detail, r); } }
      row.addEventListener('click', function (e) { if (e.target && e.target.closest && e.target.closest('.facts-detail')) { return; } toggle(); });
      row.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
      return row;
    }
    function expandDetail(detail, r) {
      var rc = r.receipt || {};
      detail.textContent = '';
      detail.appendChild(m6Label('receipt envelope'));
      detail.appendChild(m6Kv([
        ['observation_id', r.observation_id], ['session_id', r.session_id], ['ts', r.ts],
        ['principal', r.principal], ['kind', r.kind], ['chain seq', r.seq],
        ['alg', rc.alg], ['signed_by', rc.signed_by], ['body_hash', rc.body_hash]
      ]));
      if (!r.fetchable) {
        detail.appendChild(m6Empty('Envelope only. This CPU-only daemon holds no dataplane pool, so the full CROWN body, signature, and verification are not dereferenceable here — dataplane receipts live in the hosted tier. The signed envelope above is the daemon record for this observation.'));
        return;
      }
      detail.appendChild(m6Label('CROWN body / signature / verification'));
      var slot = el('div', { 'class': 'facts-loading', text: 'fetching receipt ' + m6Short(r.receipt_id, 20) + '…' });
      detail.appendChild(slot);
      var id = r.receipt_id;
      Promise.all([
        fetchVia(function () { return window.CruxApi.receiptsByReceiptId(id, { tenant_id: TENANT }); }),
        fetchVia(function () { return window.CruxApi.receiptsByReceiptIdSignature(id, { tenant_id: TENANT }); }),
        fetchVia(function () { return window.CruxApi.receiptsByReceiptIdVerification(id, { tenant_id: TENANT }); })
      ]).then(function (rr) {
        var body = rr[0], sig = rr[1], ver = rr[2];
        slot.textContent = '';
        var wrap = el('div', {});
        wrap.appendChild(m6Kv([
          ['receipt_id', id],
          ['body', body.ok ? ('seq ' + (body.data && body.data.seq) + ' · ' + (body.data && body.data.contentType || 'body')) : ('unavailable (HTTP ' + (body.status || '?') + ')')],
          ['signature', sig.ok ? ('seq ' + (sig.data && sig.data.seq) + ' · ' + (sig.data && sig.data.contentType || 'sig')) : ('unavailable (HTTP ' + (sig.status || '?') + ')')]
        ]));
        // Verification verdict — rendered VERBATIM from the daemon report; the
        // console NEVER computes or claims "valid" itself.
        wrap.appendChild(m6Label('verification verdict (daemon, verbatim)'));
        if (!ver.ok || !ver.data) {
          wrap.appendChild(m6Empty('Verification unavailable (HTTP ' + (ver.status || '?') + ') — GET /v1/receipts/' + id + '/verification.'));
        } else {
          var v = ver.data;
          var verdictClass = (v.signature_valid === true && v.error_code === 'OK') ? 'rcpt-verdict ok' : 'rcpt-verdict bad';
          wrap.appendChild(el('div', { 'class': verdictClass }, [
            el('span', { 'class': 'rcpt-verdict-k', text: 'signature_valid' }), el('b', { text: String(v.signature_valid) }),
            el('span', { 'class': 'rcpt-verdict-k', text: 'error_code' }), el('b', { text: String(v.error_code) })
          ]));
          wrap.appendChild(el('pre', { 'class': 'facts-vfull', text: m6PrettyJson(v) }));
        }
        detail.appendChild(wrap);
      });
    }
    function paint() {
      var q = (searchInput.value || '').trim().toLowerCase();
      state.q = q;
      listWrap.textContent = '';
      var vis = visibleRows();
      if (!state.rows.length) { listWrap.appendChild(el('p', { 'class': 'facts-empty ctl-desc', text: state.loading ? 'loading receipts…' : 'No receipts. Receipts are minted on every signed observation (POST /v1/sessions/{id}/observations) and on gate approvals.' })); }
      else if (!vis.length) { listWrap.appendChild(el('p', { 'class': 'facts-empty ctl-desc', text: 'No receipts match the filter.' })); }
      else { vis.forEach(function (r) { listWrap.appendChild(rowEl(r)); }); }
      paintCount(); paintChips();
    }
    function paintMore() {
      moreWrap.textContent = '';
      if (state.hasMore) {
        var btn = el('button', { 'class': 'btn-quiet', type: 'button' }, ['Load older']);
        btn.addEventListener('click', loadNext);
        moreWrap.appendChild(btn);
      } else if (state.rows.length) {
        moreWrap.appendChild(el('p', { 'class': 'ctl-desc', text: 'End of the receipt journal.' }));
      }
    }
    function loadPage(cursor, isFirst) {
      if (state.loading) { return; }
      state.loading = true;
      if (isFirst) { paint(); }
      var myToken = state.token;
      var query = { limit: 50 };
      if (cursor) { query.before = cursor; }
      fetchJSON('/v1/receipts/list?' + qs(query)).then(function (res) {
        if (myToken !== state.token) { return; }
        state.loading = false;
        if (!res.ok || !res.data) {
          banner.style.display = ''; banner.className = 'facts-banner err';
          banner.textContent = 'Receipts listing unavailable — ' + (res.status === 0 ? 'daemon unreachable' : 'HTTP ' + res.status) + ' (needs the console-surfaces-remediation branch: GET /v1/receipts/list).';
          return;
        }
        banner.style.display = 'none';
        var d = res.data;
        state.matched = d.matched; state.nextCursor = d.next_cursor || null; state.hasMore = !!d.has_more;
        if (isFirst && d.kind_counts) { state.kindCounts = d.kind_counts; }
        (d.rows || []).forEach(function (r) { var k = r.observation_id; if (k && state.seen[k]) { return; } if (k) { state.seen[k] = true; } state.rows.push(r); });
        paint(); paintMore();
      });
    }
    function loadNext() { if (!state.loading && state.hasMore) { loadPage(state.nextCursor, false); } }
    searchInput.addEventListener('input', function () { clearTimeout(state.deb); state.deb = setTimeout(paint, 200); });
    loadPage(null, true);
  }

  // ─────────────────────────────────────────────────────────────────────────
  //  cx-gates (M6): the canonical Art.14 approval queue. Live pending list over
  //  GET /v1/work/gate/pending (unchanged endpoint); when empty, a RICH,
  //  code-grounded empty state — what a gate is (PendingGateAction), the
  //  BlockerKind taxonomy (needs_info | needs_approval), how one is created, and
  //  a client-side join over /v1/work linking blocked items owed an approval.
  //  Approvals stay operator-gated (approveGate/rejectGate → operatorGatedCall).
  // ─────────────────────────────────────────────────────────────────────────
  function renderGatesBoard(host) {
    host.textContent = '';
    function ageOf(unixMs) {
      var at = Number(unixMs); if (!isFinite(at) || at <= 0) { return 'age unknown'; }
      var m = Math.floor(Math.max(0, Date.now() - at) / 60000);
      if (m < 1) { return 'just now'; } if (m < 60) { return m + 'm ago'; }
      var h = Math.floor(m / 60); if (h < 24) { return h + 'h ago'; } return Math.floor(h / 24) + 'd ago';
    }
    var state = { pending: [], work: [], loading: false, token: 0 };
    var head = el('p', { 'class': 'facts-count' });
    var banner = el('div', { 'class': 'facts-banner' }); banner.style.display = 'none';
    var listWrap = el('div', { 'class': 'facts-groups' });
    host.appendChild(el('div', { 'class': 'facts-browser' }, [head, banner, listWrap]));

    function workLink(id) {
      return el('a', { 'class': 'btn-quiet cx-graphlink', href: '#/canvas/graph?focus=work:' + id, title: 'open ' + id + ' in the relation graph' }, ['View work item']);
    }
    function pendingRow(p) {
      var rows = m6Kv([
        ['action id', p.action_id], ['work id', p.work_id],
        ['requested', (p.requested_action || 'update_state') + (p.target_state ? ' → ' + p.target_state : '')],
        ['by passport', p.requested_by_passport], ['status', p.status || 'pending'], ['requested', ageOf(p.requested_at_unix_ms)]
      ]);
      var links = el('div', { 'class': 'sess-rmeta' }, [workLink(p.work_id)]);
      var actions = el('div', { 'class': 'gate-actions' });
      if (isOperator()) {
        var msg = el('span', { 'class': 'ctl-desc' });
        var approve = el('button', { 'class': 'btn-quiet', type: 'button' }, ['Approve']);
        var reject = el('button', { 'class': 'btn-quiet danger', type: 'button' }, ['Reject']);
        function run(fn, verb) {
          var pp = boundPassport();
          if (!pp) { msg.textContent = 'Bind a passport first (Art.14 — approvals are passport-attributed).'; return; }
          approve.disabled = reject.disabled = true; msg.textContent = verb + '…';
          fn(p.action_id, pp).then(readJson).then(function (r) {
            msg.textContent = (r && r.ok) ? (verb + ' recorded · receipt ' + m6Short((r.data && (r.data.receipt_id || (r.data.gate && r.data.gate.receipt_id))) || '—', 18)) : (verb + ' failed (HTTP ' + (r && r.status) + ')');
            load();
          }, function () { msg.textContent = verb + ' failed.'; approve.disabled = reject.disabled = false; });
        }
        approve.addEventListener('click', function () { run(approveGate, 'Approve'); });
        reject.addEventListener('click', function () { run(rejectGate, 'Reject'); });
        actions.appendChild(approve); actions.appendChild(reject); actions.appendChild(msg);
      } else {
        actions.appendChild(el('p', { 'class': 'ctl-desc', text: 'Approvals are operator-gated (Art.14) — grant an operator scope to approve or reject from the Overwatch “needs you” lane.' }));
      }
      var detail = el('div', { 'class': 'facts-detail' }, [rows, links, actions]);
      var badge = m6Chip('sess-chip sess-chip-plan', 'GATED', 'Art.14 human approval');
      var body = el('div', {}, [
        el('div', { 'class': 'facts-rhead' }, [el('span', { 'class': 'facts-key', text: p.work_id || '(work)' }), badge, el('span', { 'class': 'facts-time', text: ageOf(p.requested_at_unix_ms) })]),
        el('div', { 'class': 'facts-val', text: (p.requested_action || 'update_state') + (p.target_state ? ' → ' + p.target_state : '') + ' · by ' + (p.requested_by_passport || '?') }),
        detail
      ]);
      var row = el('div', { 'class': 'facts-row open tone-warn' }, [body]);
      return row;
    }
    function richEmpty() {
      var wrap = el('div', {});
      wrap.appendChild(el('div', { 'class': 'facts-banner ok-empty' }, [
        el('div', { 'class': 'm6-help-h', text: 'No gates pending — the queue is clear.' }),
        el('p', { 'class': 'ctl-desc', text: 'This is the canonical Art.14 approval queue. A gate is a PendingGateAction: it is created when an agent requests a work-item state transition that the work-gate policy holds for a human go/no-go (e.g. a destructive or high-risk update_state). It waits here with status “pending” until an operator approves or rejects — that decision mints a CROWN approval receipt (ad_ga_*), visible on the Receipts page.' })
      ]));
      wrap.appendChild(m6Label('how a gate is created'));
      wrap.appendChild(m6Kv([
        ['producer', 'work-gate policy on a state transition (WorkTransition → PendingGateAction)'],
        ['endpoint', 'GET /v1/work/gate/pending (this page) · POST /v1/work/gate/{actionId}/approve|reject'],
        ['requested_action', 'update_state (the only gated action today) + target_state'],
        ['resolution', 'approve/reject → CROWN ad_ga_* receipt, attributed to the approving passport']
      ]));
      wrap.appendChild(m6Label('blocker taxonomy (work.rs BlockerKind)'));
      wrap.appendChild(m6Kv([
        ['needs_info', 'blocked, waiting on an answer about the task'],
        ['needs_approval', 'blocked, waiting on an owner’s go/no-go — a HINT an approval is owed (not the gate itself; the gate stays keyed on passport/risk)']
      ]));
      // Client-side join: blocked work items owed an approval → the producers a
      // gate would come from. Cheap single read of /v1/work.
      var owed = state.work.filter(function (w) { return w && w.state === 'blocked' && (w.blocker_kind === 'needs_approval'); });
      wrap.appendChild(m6Label('work items owed an approval (blocked · needs_approval)'));
      if (!owed.length) {
        wrap.appendChild(m6Empty('None — no blocked work item currently carries blocker_kind = needs_approval on /v1/work.'));
      } else {
        owed.slice(0, 25).forEach(function (w) {
          var r = el('div', { 'class': 'facts-row tone-warn' }, [
            el('div', { 'class': 'facts-rhead' }, [el('span', { 'class': 'facts-key', text: w.id }), m6Chip('sess-chip', 'needs_approval', 'blocker kind'), el('span', { 'class': 'facts-time', text: w.state })]),
            w.title ? el('div', { 'class': 'facts-val', text: w.title }) : null,
            el('div', { 'class': 'sess-rmeta' }, [workLink(w.id)])
          ]);
          wrap.appendChild(r);
        });
      }
      return wrap;
    }
    function paint() {
      listWrap.textContent = '';
      var pend = (state.pending || []).filter(function (p) { return (p.status || 'pending') === 'pending'; });
      head.textContent = '';
      head.appendChild(el('b', { text: String(pend.length) }));
      head.appendChild(doc().createTextNode(' pending · /v1/work/gate/pending'));
      if (pend.length) { pend.forEach(function (p) { listWrap.appendChild(pendingRow(p)); }); }
      else { listWrap.appendChild(richEmpty()); }
    }
    function load() {
      if (state.loading) { return; } state.loading = true; state.token++;
      var myToken = state.token;
      Promise.all([fetchJSON('/v1/work/gate/pending'), fetchJSON('/v1/work?source=all')]).then(function (rr) {
        if (myToken !== state.token) { return; }
        state.loading = false;
        var g = rr[0], w = rr[1];
        if (!g.ok || !g.data) { banner.style.display = ''; banner.className = 'facts-banner err'; banner.textContent = 'Gates unavailable — ' + (g.status === 0 ? 'daemon unreachable' : 'HTTP ' + g.status) + '.'; listWrap.textContent = ''; return; }
        banner.style.display = 'none';
        state.pending = g.data.pending || [];
        state.work = (w.ok && w.data) ? (w.data.work || w.data.items || w.data.work_items || []) : [];
        paint();
      });
    }
    load();
  }

  // ─────────────────────────────────────────────────────────────────────────
  //  cx-identity (M6): the candidate-links surface. (a) an in-page help panel
  //  grounded in the code (what a candidate is, the NEW propose route + its two
  //  inputs, how consent disposes, the flag); (b) live candidates from
  //  /v1/identity/candidates (honest 404 naming the flag when off); (c) an
  //  operator-gated "Seed candidates" action wired to POST /v1/identity/candidates/
  //  propose through operatorGatedCall (disabled + reason in customer posture);
  //  confirm kept under the operator-gating idiom.
  // ─────────────────────────────────────────────────────────────────────────
  function renderIdentityBrowser(host) {
    host.textContent = '';
    var state = { candidates: [], status: 0, loading: false, token: 0 };

    var help = el('div', { 'class': 'facts-banner m6-help' }, [
      el('div', { 'class': 'm6-help-h', text: 'Candidate links — inference proposes, consent disposes' }),
      el('p', { 'class': 'ctl-desc', text: 'A candidate is a PROPOSAL that two identities (a local passport and an observed subject) may be the same principal. Candidates never resolve on their own — the principal resolver ignores them until an operator confirms.' })
    ]);
    var pipeline = el('div', {});
    pipeline.appendChild(m6Label('what writes candidates'));
    pipeline.appendChild(m6Kv([
      ['producer', 'POST /v1/identity/candidates/propose (the NEW M6 seed route — the only shipped producer)'],
      ['input · bindings', 'session→passport bindings: two distinct passports co-occurring in one tenant+project within the temporal window'],
      ['input · observations', 'observation-journal principals: distinct signing identities co-occurring in one session'],
      ['confirm', 'POST …/{id}/confirm with the cross-signature proof → mints a resolving, cross-signed identity_link'],
      ['reject', 'POST …/{id}/reject → keeps the audit trail, never resolves'],
      ['revoke', 'POST /v1/identity/links/{id}/revoke → retires a confirmed link'],
      ['flag', 'CORECRUXD_IDENTITY_LINKS=1 (all /v1/identity/* 404 when off)']
    ]));
    help.appendChild(pipeline);

    var seedWrap = el('div', { 'class': 'facts-toolbar', 'style': 'margin-top:10px' });
    var seedMsg = el('span', { 'class': 'ctl-desc' });
    var seedBtn = el('button', { 'class': 'btn-quiet', type: 'button' }, ['Seed candidates']);
    if (!isOperator()) {
      seedBtn.disabled = true;
      seedBtn.setAttribute('data-requires', 'operator');
      seedBtn.setAttribute('title', 'operator posture required — the seed route is admin:write');
      seedMsg.textContent = 'Operator posture required to run the proposers (admin:write).';
    } else {
      seedBtn.addEventListener('click', function () {
        seedBtn.disabled = true; seedMsg.textContent = 'running proposers…';
        seedIdentityCandidates().then(readJson).then(function (r) {
          seedBtn.disabled = false;
          if (r && r.ok && r.data) {
            var by = r.data.by_source || {};
            seedMsg.textContent = 'created ' + r.data.created + ' (examined ' + r.data.examined + ') · bindings ' + ((by.bindings && by.bindings.created) || 0) + '/' + ((by.bindings && by.bindings.examined) || 0) + ' · observations ' + ((by.observations && by.observations.created) || 0) + '/' + ((by.observations && by.observations.examined) || 0);
            load();
          } else { seedMsg.textContent = 'seed failed (HTTP ' + (r && r.status) + ')'; }
        }, function () { seedBtn.disabled = false; seedMsg.textContent = 'seed failed.'; });
      });
    }
    seedWrap.appendChild(seedBtn); seedWrap.appendChild(seedMsg);
    help.appendChild(seedWrap);

    var countLine = el('p', { 'class': 'facts-count' });
    var banner = el('div', { 'class': 'facts-banner' }); banner.style.display = 'none';
    var listWrap = el('div', { 'class': 'facts-groups' });
    host.appendChild(el('div', { 'class': 'facts-browser' }, [help, countLine, banner, listWrap]));

    function candidateRow(c) {
      var cand = c.candidate || c;
      var id = c.candidate_id || cand.candidate_id || c.id;
      var status = String(cand.status || 'proposed');
      var signals = (cand.signals || []).map(function (s) { return s.kind; }).join(' · ');
      var detail = el('div', { 'class': 'facts-detail' }, [
        m6Kv([
          ['candidate_id', id], ['status', status],
          ['local passport', cand.local_passport_fpr], ['observed subject', cand.observed_subject],
          ['confidence', cand.confidence], ['signals', signals || '—'],
          ['evidence', (cand.evidence_refs || []).join(', ')], ['proposed at', cand.proposed_at],
          ['resolved link', cand.resolved_link_id]
        ])
      ]);
      if (status === 'proposed' && isOperator()) {
        detail.appendChild(m6Label('confirm (operator — needs the cross-signature proof)'));
        var f = {};
        function inp(k, ph, v) { var i = el('input', { 'class': 'facts-input', type: 'text', placeholder: ph }); if (v) { i.value = v; } f[k] = i; return el('label', { 'class': 'facts-field' }, [el('span', { text: k }), i]); }
        var form = el('div', { 'class': 'facts-toolbar' }, [
          inp('local_passport_id', 'personal-default', 'personal-default'),
          inp('remote_fpr', 'p_… (= observed subject)', cand.observed_subject || ''),
          inp('remote_public_key_hex', '64 hex chars'),
          inp('created_at', '2026-06-15T00:00:00Z'),
          inp('sig_local', '128 hex chars'),
          inp('sig_remote', '128 hex chars')
        ]);
        var cmsg = el('span', { 'class': 'ctl-desc' });
        var confirmBtn = el('button', { 'class': 'btn-quiet', type: 'button' }, ['Confirm candidate']);
        confirmBtn.addEventListener('click', function () {
          confirmBtn.disabled = true; cmsg.textContent = 'verifying signatures…';
          confirmIdentityCandidate(id, {
            local_passport_id: f.local_passport_id.value, remote_fpr: f.remote_fpr.value,
            remote_public_key_hex: f.remote_public_key_hex.value, created_at: f.created_at.value,
            sig_local: f.sig_local.value, sig_remote: f.sig_remote.value
          }).then(readJson).then(function (r) {
            confirmBtn.disabled = false;
            cmsg.textContent = (r && r.ok) ? 'confirmed → identity_link minted' : 'rejected by daemon (HTTP ' + (r && r.status) + ') — ' + m6Short((r.data && (r.data.detail || r.data.title)) || 'signatures must verify', 80);
            if (r && r.ok) { load(); }
          }, function () { confirmBtn.disabled = false; cmsg.textContent = 'confirm failed.'; });
        });
        detail.appendChild(form); detail.appendChild(confirmBtn); detail.appendChild(cmsg);
        detail.appendChild(el('p', { 'class': 'ctl-desc', text: 'Reject is an API/CLI action: POST /v1/identity/candidates/' + id + '/reject (keeps the audit trail).' }));
      }
      var tone = status === 'confirmed' ? 'ok' : (status === 'rejected' ? 'crit' : 'trust');
      var row = el('div', { 'class': 'facts-row tone-' + tone, role: 'button', tabindex: '0' }, [
        el('div', { 'class': 'facts-rhead' }, [el('span', { 'class': 'facts-key', text: id }), m6Chip('sess-chip', status, 'candidate status'), el('span', { 'class': 'facts-time', text: (cand.confidence != null ? 'conf ' + cand.confidence : '') })]),
        el('div', { 'class': 'facts-val', text: (cand.observed_subject || '') + (signals ? ' · ' + signals : '') }),
        detail
      ]);
      var opened = false;
      function toggle() { var o = row.classList.toggle('open'); if (o && !opened) { opened = true; } }
      row.addEventListener('click', function (e) { if (e.target && e.target.closest && e.target.closest('.facts-detail')) { return; } toggle(); });
      row.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
      return row;
    }
    function paint() {
      listWrap.textContent = ''; countLine.textContent = '';
      if (state.status === 404) {
        banner.style.display = ''; banner.className = 'facts-banner warn';
        banner.textContent = 'Identity links are disabled on this daemon (all /v1/identity/* return 404). Set CORECRUXD_IDENTITY_LINKS=1 to enable candidates, the seed route, and confirmation.';
        return;
      }
      banner.style.display = 'none';
      countLine.appendChild(el('b', { text: String(state.candidates.length) }));
      countLine.appendChild(doc().createTextNode(' candidate' + (state.candidates.length === 1 ? '' : 's') + ' · /v1/identity/candidates'));
      if (!state.candidates.length) { listWrap.appendChild(el('p', { 'class': 'facts-empty ctl-desc', text: 'No candidates yet. Run “Seed candidates” above (operator) to propose from session bindings + observation principals — a fresh workspace has no other producer.' })); return; }
      state.candidates.forEach(function (c) { listWrap.appendChild(candidateRow(c)); });
    }
    function load() {
      if (state.loading) { return; } state.loading = true; state.token++;
      var myToken = state.token;
      fetchJSON('/v1/identity/candidates').then(function (res) {
        if (myToken !== state.token) { return; }
        state.loading = false; state.status = res.status;
        if (res.status === 404) { paint(); return; }
        if (!res.ok || !res.data) { banner.style.display = ''; banner.className = 'facts-banner err'; banner.textContent = 'Candidates unavailable — HTTP ' + res.status + '.'; return; }
        state.candidates = res.data.candidates || [];
        paint();
      });
    }
    load();
  }

  // ─────────────────────────────────────────────────────────────────────────
  //  cx-mediation (M6): honest CE posture over GET /v1/console/engine/summary,
  //  branching on the THREE real states — 404 "engine mediation not configured"
  //  → CE posture card; 502 "engine upstream unavailable" → configured-but-
  //  unreachable card; 200 → the proxied summary with its mediated/reachable/
  //  latency stamps. No dead controls are rendered (customer-safe by omission).
  // ─────────────────────────────────────────────────────────────────────────
  function renderMediationPosture(host) {
    host.textContent = '';
    var banner = el('div', { 'class': 'facts-banner' }); banner.style.display = 'none';
    var body = el('div', {});
    host.appendChild(el('div', { 'class': 'facts-browser' }, [banner, body]));

    function ceCard() {
      var wrap = el('div', {});
      wrap.appendChild(el('div', { 'class': 'facts-banner m6-help' }, [
        el('div', { 'class': 'm6-help-h', text: 'CE posture — engine mediation not configured' }),
        el('p', { 'class': 'ctl-desc', text: 'The gateway (mediation) plane is where a hosted CruxEngine mediates identity, the capability ladder, and Art.15 foresight on the browser’s behalf. This CPU-only Crux daemon holds NO engine state — it only proxies a small, curated set of read summaries when an engine base URL is configured. Right now none is, so the read side is honestly empty rather than a dead pane.' })
      ]));
      wrap.appendChild(m6Label('what exists on this daemon'));
      wrap.appendChild(m6Kv([
        ['engine state held here', 'none — the daemon proxies, it does not run the engine'],
        ['configured by', 'CORECRUXD_ENGINE_BASE_URL (+ optional CORECRUXD_ENGINE_API_KEY)'],
        ['read routes (when configured)', 'GET /v1/console/engine/summary · /bench · /spend (proxied, read-only)'],
        ['status now', '404 “engine mediation not configured” — base URL unset']
      ]));
      wrap.appendChild(m6Label('what a configured engine (M3+) unlocks'));
      wrap.appendChild(m6Kv([
        ['summary', 'engine liveness + reachability + latency stamps'],
        ['bench / spend', 'benchmark manifest + committed escrow spend, proxied'],
        ['search', 'mediated WikiCrux retrieval (POST /v1/console/engine/search)']
      ]));
      return wrap;
    }
    function unreachableCard() {
      var wrap = el('div', {});
      wrap.appendChild(el('div', { 'class': 'facts-banner warn' }, [
        el('div', { 'class': 'm6-help-h', text: 'Engine configured — upstream unavailable (502)' }),
        el('p', { 'class': 'ctl-desc', text: 'CORECRUXD_ENGINE_BASE_URL is set, but the daemon’s proxied read to the engine failed (transport error or non-2xx). The upstream body, headers, and API key are never forwarded — this is the terse 502 posture. Check the engine base URL, the API key, and engine health, then reload.' })
      ]));
      return wrap;
    }
    function summaryCard(d) {
      var wrap = el('div', {});
      wrap.appendChild(el('div', { 'class': 'facts-banner ok-empty' }, [
        el('div', { 'class': 'm6-help-h', text: 'Engine reachable — mediated summary' })
      ]));
      wrap.appendChild(m6Kv([
        ['mediated', d.mediated === true ? 'yes · daemon-proxied' : String(d.mediated)],
        ['engine_reachable', String(d.engine_reachable)],
        ['engine_latency_ms', d.engine_latency_ms],
        ['fetched_at_unix_ms', d.fetched_at_unix_ms]
      ]));
      wrap.appendChild(m6Label('proxied engine summary (verbatim)'));
      wrap.appendChild(el('pre', { 'class': 'facts-vfull', text: m6PrettyJson(d) }));
      return wrap;
    }
    function load() {
      body.textContent = ''; body.appendChild(el('p', { 'class': 'facts-loading', text: 'probing engine mediation…' }));
      fetchJSON('/v1/console/engine/summary').then(function (res) {
        body.textContent = '';
        if (res.status === 404) { body.appendChild(ceCard()); return; }
        if (res.status === 502) { body.appendChild(unreachableCard()); return; }
        if (res.ok && res.data) { body.appendChild(summaryCard(res.data)); return; }
        banner.style.display = ''; banner.className = 'facts-banner err';
        banner.textContent = 'Engine summary unavailable — ' + (res.status === 0 ? 'daemon unreachable' : 'HTTP ' + res.status) + '.';
      });
    }
    load();
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

  // =========================================================================
  //  Rings snapshot data — the honest degradation for the native Rings page
  //  (renderRings below). Ported verbatim from UI-prototype/rings-clock/
  //  console-mock.html; live feeds (/v1/work, /v1/console/summary,
  //  /v1/facts/list) supersede these at runtime when reachable.
  // =========================================================================
  var RINGS_PLANS_RAW = [{"s":"corecrux-object-storage-tier-2026-07-07","st":0,"d":6,"t":6,"b":61,"e":76,"o":59,"dep":["corecrux-memory-manager-2026-07-05"],"ext":[],"od":[]},{"s":"tier-packaging-p1-remediation-2026-07-13","st":1,"d":0,"t":1,"b":67,"e":76,"o":55,"dep":[],"ext":[],"od":[]},{"s":"crux-daemon-buyer-fit-buildout-2026-07-13","st":1,"d":1,"t":8,"b":67,"e":76,"o":64,"dep":[],"ext":[],"od":[]},{"s":"crux-audit-v2-closeout-2026-07-15","st":0,"d":7,"t":7,"b":69,"e":75,"o":56,"dep":["crux-audit-v2-remediation-2026-07-13"],"ext":[],"od":[]},{"s":"vault-consolidation-2026-04-07","st":1,"d":0,"t":8,"b":54,"e":75,"o":80,"dep":[],"ext":[],"od":[]},{"s":"cross-site-auth-sso-cuecrux-2026-07-13","st":1,"d":3,"t":6,"b":67,"e":75,"o":67,"dep":["paddle-billing-state-2026-07-13","unified-shell-console-2026-07-03"],"ext":["cuecrux-selfserve-launch-readiness-2026-07-16"],"od":[]},{"s":"wikicrux-agent-publish-plane-shared-tenant-2026-07-09","st":1,"d":1,"t":6,"b":73,"e":74,"o":5,"dep":["wikicrux-agent-adoption-sequence-2026-07-08","wikicrux-agent-first-wiki-service-2026-06-11"],"ext":["wikicrux-adoption-telemetry-and-corpus-flywheel-2026-07-09"],"od":[]},{"s":"portfolio-burn-down-orchestration-2026-07-10","st":2,"d":2,"t":8,"b":64,"e":74,"o":54,"dep":["commerce-paddle-billing-2026-06-11","crux-credit-burn-rail-2026-06-22","production-cutover-orchestration-2026-07-07"],"ext":[],"od":["OD-1"]},{"s":"commerce-paddle-billing-2026-06-11","st":1,"d":0,"t":8,"b":58,"e":72,"o":51,"dep":[],"ext":["portfolio-burn-down-orchestration-2026-07-10"],"od":[]},{"s":"daemon-distribution-packaging-2026-06-11","st":0,"d":7,"t":7,"b":36,"e":72,"o":137,"dep":[],"ext":[],"od":[]},{"s":"esi-v2-no-blindspot-live-write-2026-06-03","st":2,"d":3,"t":6,"b":27,"e":72,"o":137,"dep":[],"ext":[],"od":[]},{"s":"unified-shell-console-2026-07-03","st":1,"d":12,"t":13,"b":57,"e":58,"o":17,"dep":["open-engine-coordination-surfaces-2026-06-30"],"ext":["cross-site-auth-sso-cuecrux-2026-07-13"],"od":[]},{"s":"wikicrux-prose-dense-reembed-float16-pool-2026-06-27","st":0,"d":3,"t":5,"b":51,"e":51,"o":7,"dep":[],"ext":["wikicrux-retrieval-quality-hardening-2026-06-28"],"od":[]},{"s":"wikicrux-public-codemaps-2026-07-10","st":1,"d":4,"t":4,"b":64,"e":64,"o":0,"dep":[],"ext":["codemaps-cross-repo-graph-and-value-expansion-2026-07-10"],"od":[]},{"s":"wikicrux-retrieval-quality-hardening-2026-06-28","st":0,"d":6,"t":7,"b":52,"e":52,"o":11,"dep":["wikicrux-prose-dense-reembed-float16-pool-2026-06-27"],"ext":[],"od":[]},{"s":"wiki-prose-residual-extraction-2026-06-30","st":0,"d":3,"t":4,"b":54,"e":55,"o":15,"dep":[],"ext":["unified-retrieval-hardening-2026-07-02"],"od":[]},{"s":"vernacular-retrieval-lift-check-2026-05-21","st":0,"d":0,"t":7,"b":14,"e":14,"o":0,"dep":[],"ext":[],"od":[]},{"s":"wiki-cuecrux-com-prod-deploy-2026-07-08","st":0,"d":0,"t":5,"b":62,"e":62,"o":4,"dep":["wikicrux-agent-first-wiki-service-2026-06-11","wikicrux-grounding-poisoning-defense-2026-07-08"],"ext":["wikicrux-adoption-telemetry-and-corpus-flywheel-2026-07-09"],"od":[]},{"s":"wikicrux-agent-language-encode-2026-06-28","st":1,"d":5,"t":10,"b":52,"e":53,"o":30,"dep":["classical-ner-at-ingest-2026-05-05","wikicrux-agent-first-wiki-service-2026-06-11","wikicrux-full-enwiki-ingest-2026-06-28"],"ext":["unified-reasoner-encode-evidence-2026-06-29"],"od":[]},{"s":"wikicrux-grounding-poisoning-defense-2026-07-08","st":0,"d":5,"t":6,"b":62,"e":62,"o":4,"dep":["wikicrux-agent-first-wiki-service-2026-06-11"],"ext":["wiki-cuecrux-com-prod-deploy-2026-07-08","wikicrux-adoption-telemetry-and-corpus-flywheel-2026-07-09"],"od":[]},{"s":"vaultcrux-search-outcome-corpus-pollution-2026-05-31","st":0,"d":2,"t":3,"b":24,"e":24,"o":0,"dep":[],"ext":[],"od":[]},{"s":"wikicrux-idempotent-ingestion-2026-06-14","st":1,"d":4,"t":10,"b":38,"e":52,"o":48,"dep":[],"ext":["wikicrux-adoption-telemetry-and-corpus-flywheel-2026-07-09"],"od":[]},{"s":"wikicrux-agent-first-wiki-service-2026-06-11","st":1,"d":3,"t":8,"b":35,"e":37,"o":1,"dep":[],"ext":["wiki-cuecrux-com-prod-deploy-2026-07-08","wikicrux-adoption-telemetry-and-corpus-flywheel-2026-07-09","wikicrux-agent-adoption-sequence-2026-07-08","wikicrux-agent-language-encode-2026-06-28","wikicrux-agent-publish-plane-shared-tenant-2026-07-09","wikicrux-grounding-poisoning-defense-2026-07-08"],"od":[]},{"s":"wikicrux-full-enwiki-ingest-2026-06-28","st":1,"d":2,"t":9,"b":52,"e":54,"o":33,"dep":[],"ext":["enwiki-prose-dedicated-serving-data-1-2026-07-03","wikicrux-adoption-telemetry-and-corpus-flywheel-2026-07-09","wikicrux-agent-language-encode-2026-06-28"],"od":[]},{"s":"wikicrux-adoption-telemetry-and-corpus-flywheel-2026-07-09","st":1,"d":5,"t":10,"b":63,"e":67,"o":8,"dep":["enwiki-prose-dedicated-serving-data-1-2026-07-03","wiki-cuecrux-com-prod-deploy-2026-07-08","wikicrux-agent-adoption-sequence-2026-07-08","wikicrux-agent-first-wiki-service-2026-06-11","wikicrux-agent-publish-plane-shared-tenant-2026-07-09","wikicrux-full-enwiki-ingest-2026-06-28","wikicrux-grounding-poisoning-defense-2026-07-08","wikicrux-idempotent-ingestion-2026-06-14"],"ext":[],"od":[]},{"s":"vaultcrux-companion-lane-transforms-and-ccxev-2026-05-20","st":0,"d":0,"t":10,"b":15,"e":15,"o":0,"dep":[],"ext":[],"od":[]},{"s":"vaultcrux-multi-predicate-enumerate-2026-04-29","st":0,"d":0,"t":3,"b":20,"e":20,"o":0,"dep":[],"ext":[],"od":[]},{"s":"vaultcrux-multi-predicate-m3-verify-build-2026-06-09","st":0,"d":1,"t":5,"b":34,"e":34,"o":0,"dep":[],"ext":[],"od":[]},{"s":"tenant-isolation-policy-and-silo-2026-06-24","st":0,"d":7,"t":7,"b":48,"e":50,"o":25,"dep":[],"ext":[],"od":[]},{"s":"release-readiness-master-2026-06-11","st":1,"d":0,"t":6,"b":35,"e":49,"o":52,"dep":[],"ext":[],"od":[]},{"s":"tier0-deterministic-levers-2026-06-30","st":0,"d":5,"t":5,"b":54,"e":54,"o":6,"dep":[],"ext":[],"od":[]},{"s":"scorecrux-coding-intelligence-refresh-2026-06-25","st":1,"d":0,"t":5,"b":49,"e":50,"o":5,"dep":[],"ext":[],"od":[]},{"s":"tier-packaging-and-site-reframe-2026-07-13","st":1,"d":7,"t":8,"b":66,"e":67,"o":5,"dep":[],"ext":[],"od":[]},{"s":"unified-retrieval-hardening-2026-07-02","st":2,"d":7,"t":10,"b":55,"e":56,"o":1,"dep":["ccxi-query-shape-routing-2026-06-30","corecrux-offline-attach-candidate-selection-2026-07-01","embedder-pool-distribution-manager-2026-07-01","unified-production-claims-source-2026-06-30","unified-reasoner-encode-evidence-2026-06-29","wiki-prose-residual-extraction-2026-06-30"],"ext":[],"od":["OD-1","OD-2","OD-3"]},{"s":"proof-carrying-adaptive-packs-2026-07-13","st":1,"d":0,"t":7,"b":67,"e":67,"o":5,"dep":[],"ext":[],"od":[]},{"s":"security-critical-7-tenant-isolation-2026-06-11","st":0,"d":4,"t":7,"b":65,"e":65,"o":0,"dep":[],"ext":[],"od":[]},{"s":"topology-ccxn-entity-coverage-backfill-lme-s-2026-06-06","st":0,"d":3,"t":5,"b":31,"e":31,"o":0,"dep":[],"ext":[],"od":[]},{"s":"token-burn-precise-attribution-2026-06-26","st":0,"d":3,"t":3,"b":50,"e":50,"o":7,"dep":["execplan-token-burn-per-execplan-2026-06-26"],"ext":[],"od":["OD-28"]},{"s":"unified-reasoner-encode-evidence-2026-06-29","st":1,"d":0,"t":1,"b":53,"e":54,"o":25,"dep":["lme-s-aggregation-projection-lane-wikicrux-bridge-2026-06-28","wikicrux-agent-language-encode-2026-06-28"],"ext":["ccxi-query-shape-routing-2026-06-30","unified-retrieval-hardening-2026-07-02"],"od":[]},{"s":"unified-production-claims-source-2026-06-30","st":1,"d":3,"t":4,"b":54,"e":54,"o":6,"dep":[],"ext":["ccxi-query-shape-routing-2026-06-30","enwiki-prose-dedicated-serving-data-1-2026-07-03","unified-retrieval-hardening-2026-07-02"],"od":[]},{"s":"rcx-registry-deployment-readiness-2026-06-14","st":0,"d":5,"t":5,"b":38,"e":38,"o":0,"dep":[],"ext":[],"od":[]},{"s":"production-cutover-orchestration-2026-07-07","st":1,"d":39,"t":40,"b":61,"e":65,"o":2,"dep":[],"ext":["portfolio-burn-down-orchestration-2026-07-10"],"od":[]},{"s":"provider-integration-surfaces-2026-06-11","st":1,"d":5,"t":6,"b":36,"e":36,"o":1,"dep":[],"ext":[],"od":[]},{"s":"scratchpad-survival-wizard-standard-2026-06-30","st":1,"d":4,"t":4,"b":54,"e":55,"o":8,"dep":[],"ext":[],"od":[]},{"s":"topology-ccxn-weight-and-noise-tune-lme-s-2026-06-07","st":0,"d":4,"t":4,"b":31,"e":31,"o":0,"dep":[],"ext":[],"od":[]},{"s":"tokenburn-ab-harness-2026-06-10","st":0,"d":1,"t":7,"b":34,"e":34,"o":0,"dep":[],"ext":[],"od":[]},{"s":"prod-engine-reconcile-deploy-2026-06-26","st":0,"d":0,"t":1,"b":50,"e":50,"o":4,"dep":[],"ext":[],"od":[]},{"s":"phase-t-usage-receipts-2026-07-03","st":0,"d":3,"t":3,"b":64,"e":64,"o":3,"dep":[],"ext":[],"od":[]},{"s":"lme-s-gated-accuracy-push-2026-05-29","st":0,"d":0,"t":5,"b":22,"e":28,"o":0,"dep":[],"ext":[],"od":[]},{"s":"phase-t-cross-vendor-instrumentation-2026-07-03","st":1,"d":1,"t":3,"b":61,"e":64,"o":5,"dep":[],"ext":[],"od":[]},{"s":"passport-revocation-and-agent-card-discovery-2026-06-29","st":0,"d":7,"t":7,"b":53,"e":53,"o":26,"dep":[],"ext":[],"od":[]},{"s":"phase-0-hygiene-debt-2026-07-02","st":1,"d":3,"t":10,"b":56,"e":60,"o":27,"dep":["master-plan-refresh-and-docs-unification-2026-07-02"],"ext":[],"od":[]},{"s":"phase-t-usage-receipts-autoemit-version-notify-2026-07-03","st":0,"d":3,"t":3,"b":57,"e":57,"o":3,"dep":[],"ext":[],"od":[]},{"s":"master-plan-canonical-consolidation-2026-06-14","st":0,"d":4,"t":4,"b":38,"e":38,"o":0,"dep":[],"ext":[],"od":[]},{"s":"portfolio-status-decisions-registry-2026-06-11","st":0,"d":0,"t":4,"b":36,"e":36,"o":0,"dep":[],"ext":[],"od":[]},{"s":"open-engine-coordination-surfaces-2026-06-30","st":0,"d":0,"t":5,"b":54,"e":55,"o":9,"dep":[],"ext":["unified-shell-console-2026-07-03"],"od":[]},{"s":"plancrux-retirement-master-2026-05-19","st":1,"d":0,"t":9,"b":12,"e":34,"o":0,"dep":[],"ext":[],"od":[]},{"s":"mh-ab-v2-harness-build-2026-06-12","st":0,"d":1,"t":5,"b":36,"e":36,"o":0,"dep":[],"ext":["context-dependence-benchmark-scorecrux-2026-07-03"],"od":[]},{"s":"lme-s-multi-lane-retrieval-gemma-2026-05-23","st":0,"d":0,"t":7,"b":16,"e":16,"o":0,"dep":[],"ext":[],"od":[]},{"s":"lme-knowledge-reingest-and-legacy-segment-retire-2026-05-29","st":0,"d":0,"t":1,"b":22,"e":22,"o":0,"dep":[],"ext":[],"od":[]},{"s":"lane-coverage-backfill-2026-05-22","st":0,"d":2,"t":5,"b":15,"e":15,"o":0,"dep":[],"ext":[],"od":[]},{"s":"lme-ordering-day-precision-extraction-2026-06-12","st":1,"d":3,"t":6,"b":36,"e":37,"o":0,"dep":[],"ext":[],"od":[]},{"s":"lme-s-8-lever-deepdive-2026-06-04","st":0,"d":0,"t":1,"b":28,"e":29,"o":0,"dep":[],"ext":[],"od":[]},{"s":"lme-s-aggregation-projection-lane-wikicrux-bridge-2026-06-28","st":1,"d":0,"t":6,"b":52,"e":53,"o":26,"dep":["lme-s-aggregation-count-extraction-2026-06-18"],"ext":["unified-reasoner-encode-evidence-2026-06-29"],"od":[]},{"s":"lme-agent-native-retrieval-harness-2026-05-30","st":0,"d":2,"t":5,"b":23,"e":32,"o":0,"dep":[],"ext":[],"od":[]},{"s":"lme-s-aggregation-count-extraction-2026-06-18","st":0,"d":5,"t":5,"b":42,"e":47,"o":59,"dep":[],"ext":["lme-s-aggregation-projection-lane-wikicrux-bridge-2026-06-28"],"od":[]},{"s":"knowledge-state-production-hooks-2026-06-13","st":0,"d":6,"t":6,"b":37,"e":39,"o":9,"dep":[],"ext":[],"od":[]},{"s":"extraction-lane-observability-2026-05-21","st":0,"d":7,"t":7,"b":14,"e":35,"o":0,"dep":[],"ext":[],"od":[]},{"s":"execplan-lineage-provenance-open-questions-2026-06-25","st":0,"d":4,"t":5,"b":49,"e":49,"o":5,"dep":["coord-plane-p1-execplan-board-2026-06-23","crux-work-panel-execplans-as-truenorth-2026-05-26"],"ext":["execplan-board-fidelity-states-console-cost-2026-06-26"],"od":["OD-3","OD-24"]},{"s":"generative-execplans-and-deploy-coordination-2026-06-26","st":0,"d":0,"t":1,"b":50,"e":53,"o":27,"dep":["crux-work-panel-execplans-as-truenorth-2026-05-26","execplan-board-fidelity-states-console-cost-2026-06-26"],"ext":[],"od":[]},{"s":"identity-memory-portability-2026-06-11","st":0,"d":6,"t":6,"b":36,"e":36,"o":1,"dep":[],"ext":[],"od":[]},{"s":"fable5-d1-redteam-kill-risk-register-2026-07-02","st":0,"d":6,"t":6,"b":56,"e":56,"o":6,"dep":[],"ext":[],"od":[]},{"s":"gated-tiered-aggregation-prompt-fixes-2026-05-24","st":0,"d":0,"t":8,"b":17,"e":33,"o":0,"dep":[],"ext":[],"od":[]},{"s":"execplan-token-burn-per-execplan-2026-06-26","st":0,"d":2,"t":3,"b":50,"e":50,"o":12,"dep":["execplan-board-fidelity-states-console-cost-2026-06-26"],"ext":["token-burn-precise-attribution-2026-06-26"],"od":["OD-28"]},{"s":"event-lane-semantic-recall-2026-06-05","st":0,"d":6,"t":7,"b":29,"e":30,"o":0,"dep":[],"ext":[],"od":[]},{"s":"glassbox-eu-ai-act-soc2-compliance-bench-2026-06-26","st":0,"d":11,"t":11,"b":50,"e":51,"o":22,"dep":[],"ext":[],"od":[]},{"s":"event-counter-noise-reduction-2026-06-06","st":0,"d":6,"t":7,"b":30,"e":30,"o":0,"dep":[],"ext":[],"od":[]},{"s":"frontdoor-agent-ux-nuxt-feature-flag-wiring-2026-05-29","st":1,"d":0,"t":8,"b":21,"e":22,"o":0,"dep":[],"ext":[],"od":[]},{"s":"gold-free-extraction-automation-2026-05-31","st":1,"d":2,"t":11,"b":24,"e":28,"o":0,"dep":[],"ext":[],"od":[]},{"s":"execplan-board-fidelity-states-console-cost-2026-06-26","st":0,"d":3,"t":4,"b":50,"e":50,"o":5,"dep":["execplan-lineage-provenance-open-questions-2026-06-25"],"ext":["execplan-token-burn-per-execplan-2026-06-26","generative-execplans-and-deploy-coordination-2026-06-26"],"od":[]},{"s":"embedder-pool-distribution-manager-2026-07-01","st":1,"d":2,"t":6,"b":55,"e":55,"o":11,"dep":[],"ext":["unified-retrieval-hardening-2026-07-02"],"od":[]},{"s":"enwiki-prose-dedicated-serving-data-1-2026-07-03","st":0,"d":1,"t":6,"b":64,"e":64,"o":0,"dep":["claims-resident-bm25-and-next-steps-2026-06-30","unified-production-claims-source-2026-06-30","wikicrux-full-enwiki-ingest-2026-06-28"],"ext":["wikicrux-adoption-telemetry-and-corpus-flywheel-2026-07-09"],"od":[]},{"s":"embedder-pool-per-tenant-bundle-2026-06-16","st":0,"d":5,"t":5,"b":40,"e":40,"o":12,"dep":[],"ext":[],"od":[]},{"s":"enwiki-claims-coverage-expansion-2026-07-04","st":1,"d":2,"t":6,"b":64,"e":64,"o":0,"dep":[],"ext":[],"od":[]},{"s":"esi-v2-live-fact-write-path-2026-06-03","st":0,"d":0,"t":4,"b":27,"e":27,"o":0,"dep":[],"ext":[],"od":[]},{"s":"engine-ci-layer-7-remaining-highs-2026-05-21","st":0,"d":0,"t":4,"b":14,"e":14,"o":0,"dep":[],"ext":[],"od":[]},{"s":"enwiki-prose-ranking-quality-2026-07-03","st":0,"d":3,"t":5,"b":64,"e":64,"o":0,"dep":[],"ext":[],"od":["OD-1","OD-2"]},{"s":"cuecrux-feature-registry-and-router-2026-05-26","st":0,"d":0,"t":17,"b":19,"e":19,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-http-ingress-hardening-2026-06-11","st":1,"d":4,"t":5,"b":35,"e":36,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-self-hosting-hygiene-2026-06-05","st":0,"d":4,"t":5,"b":29,"e":29,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-prod-deploy-2026-06-05","st":0,"d":3,"t":4,"b":29,"e":29,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-gateway-production-2026-06-10","st":0,"d":0,"t":1,"b":34,"e":35,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-mcp-oauth-for-hosted-clients-2026-06-23","st":1,"d":5,"t":8,"b":47,"e":49,"o":44,"dep":[],"ext":[],"od":["OD-3","OD-24"]},{"s":"crux-session-capability-graph-completion-2026-06-08","st":1,"d":1,"t":5,"b":32,"e":32,"o":0,"dep":[],"ext":[],"od":[]},{"s":"cruxengine-companion-installer-deploy-hardening-2026-07-12","st":0,"d":4,"t":4,"b":66,"e":66,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-repo-audit-fixing-2026-06-15","st":0,"d":8,"t":8,"b":39,"e":39,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-moat-m4-memory-hook-m8-buyer-package-2026-06-11","st":0,"d":0,"t":2,"b":35,"e":35,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-repo-audit-hardening-followup-2026-06-15","st":0,"d":0,"t":1,"b":39,"e":39,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-signed-session-recorder-2026-06-21","st":0,"d":3,"t":3,"b":46,"e":46,"o":40,"dep":[],"ext":[],"od":[]},{"s":"crux-hook-client-wire-activity-2026-06-22","st":0,"d":5,"t":5,"b":46,"e":46,"o":38,"dep":[],"ext":[],"od":[]},{"s":"crux-headroom-token-efficiency-learnings-2026-06-24","st":0,"d":3,"t":6,"b":48,"e":49,"o":17,"dep":[],"ext":[],"od":[]},{"s":"crux-orchestrator-orcplan-2026-05-29","st":0,"d":0,"t":7,"b":22,"e":22,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-punchcard-resource-leases-2026-05-29","st":0,"d":0,"t":7,"b":22,"e":22,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-session-archive-and-friendly-titles-2026-06-13","st":0,"d":2,"t":7,"b":37,"e":37,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-growth-upsell-master-2026-06-11","st":1,"d":0,"t":4,"b":35,"e":36,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-mcp-notification-202-native-http-2026-07-06","st":0,"d":1,"t":3,"b":60,"e":61,"o":4,"dep":[],"ext":[],"od":[]},{"s":"crux-work-panel-execplans-as-truenorth-2026-05-26","st":0,"d":8,"t":8,"b":19,"e":20,"o":0,"dep":[],"ext":["execplan-lineage-provenance-open-questions-2026-06-25","generative-execplans-and-deploy-coordination-2026-06-26"],"od":[]},{"s":"crux-tenant-category-model-2026-05-22","st":0,"d":7,"t":7,"b":15,"e":15,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-new-tool-probe-fixes-2026-06-05","st":0,"d":3,"t":8,"b":29,"e":29,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-response-contract-v1-default-schema-2026-06-08","st":0,"d":6,"t":7,"b":32,"e":34,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-supply-chain-attestation-2026-06-11","st":0,"d":5,"t":5,"b":35,"e":48,"o":47,"dep":[],"ext":[],"od":[]},{"s":"cruxengine-companion-lane-port-2026-06-09","st":0,"d":7,"t":7,"b":33,"e":34,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-mcp-dynamic-tool-surface-2026-06-08","st":0,"d":1,"t":6,"b":32,"e":34,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-log-redaction-2026-06-11","st":1,"d":3,"t":5,"b":35,"e":36,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-integration-platform-surfaces","st":0,"d":0,"t":7,"b":31,"e":31,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-session-capability-catalog-refresh-2026-05-29","st":0,"d":0,"t":6,"b":21,"e":21,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-segment-integrity-audit-remediation-2026-06-13","st":0,"d":7,"t":7,"b":37,"e":37,"o":2,"dep":[],"ext":[],"od":[]},{"s":"crux-moat-track-master-2026-06-05","st":1,"d":0,"t":9,"b":35,"e":66,"o":90,"dep":[],"ext":[],"od":[]},{"s":"crux-agent-presence-coordination-2026-06-11","st":0,"d":0,"t":7,"b":35,"e":35,"o":1,"dep":[],"ext":[],"od":[]},{"s":"crux-config-wizard-dedup-lint-2026-06-23","st":0,"d":5,"t":5,"b":47,"e":47,"o":37,"dep":[],"ext":[],"od":["OD-18"]},{"s":"crux-audit-ii-gap-closure-codebase-audit-2026-06-13","st":0,"d":4,"t":4,"b":37,"e":37,"o":2,"dep":[],"ext":[],"od":[]},{"s":"crux-agent-passport-grouped-collaboration-2026-06-05","st":0,"d":5,"t":5,"b":29,"e":29,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-console-graph-cutover-2026-05-30","st":0,"d":0,"t":1,"b":23,"e":23,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-console-public-exposure-2026-05-17","st":1,"d":0,"t":6,"b":11,"e":11,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-daemon-full-audit-2026-06-05","st":0,"d":6,"t":6,"b":29,"e":29,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-dual-surface-activity-log-2026-06-18","st":0,"d":5,"t":5,"b":42,"e":46,"o":51,"dep":[],"ext":[],"od":[]},{"s":"cross-model-agreement-router-2026-06-04","st":0,"d":2,"t":3,"b":28,"e":28,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-audit-ii-gap-closure-implementation-2026-06-14","st":0,"d":14,"t":14,"b":38,"e":38,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-console-3d-substrate-concept-2026-06-11","st":0,"d":1,"t":4,"b":35,"e":35,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-daemon-security-gap-scan-2026-06-12","st":0,"d":3,"t":4,"b":36,"e":36,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crucible-gateway-supersede-clawd-2026-06-26","st":0,"d":0,"t":1,"b":50,"e":50,"o":5,"dep":[],"ext":[],"od":[]},{"s":"crux-freshness-dogfood-2026-06-04","st":0,"d":4,"t":8,"b":28,"e":29,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-daemon-console-lane-weights-2026-06-13","st":0,"d":7,"t":7,"b":37,"e":37,"o":2,"dep":[],"ext":[],"od":[]},{"s":"crux-credit-burn-rail-2026-06-22","st":1,"d":1,"t":7,"b":61,"e":62,"o":2,"dep":[],"ext":["portfolio-burn-down-orchestration-2026-07-10"],"od":[]},{"s":"crux-daemon-v8-coverage-scan-2026-06-13","st":0,"d":3,"t":3,"b":37,"e":37,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-domain-substrate-and-features-lens-2026-05-18","st":0,"d":6,"t":7,"b":11,"e":11,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crucible-control-plane-and-deep-retrieval-2026-06-18","st":1,"d":0,"t":1,"b":48,"e":50,"o":53,"dep":[],"ext":[],"od":[]},{"s":"crux-console-data-plane-wiring-2026-05-21","st":0,"d":3,"t":6,"b":14,"e":14,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-external-findings-remediation-2026-07-10","st":0,"d":7,"t":7,"b":64,"e":65,"o":3,"dep":[],"ext":[],"od":[]},{"s":"crux-daemon-hardening-audit-findings-2026-06-07","st":0,"d":6,"t":6,"b":31,"e":31,"o":0,"dep":[],"ext":[],"od":[]},{"s":"cross-session-identity-resolution-2026-06-15","st":0,"d":7,"t":7,"b":39,"e":39,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-console-lane-weight-polish-2026-06-14","st":0,"d":6,"t":6,"b":38,"e":38,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-ci-merge-queue-wiring-2026-06-26","st":0,"d":3,"t":4,"b":50,"e":53,"o":20,"dep":[],"ext":[],"od":[]},{"s":"crux-agent-action-ledger-token-accounting-2026-06-11","st":0,"d":6,"t":6,"b":35,"e":48,"o":47,"dep":[],"ext":[],"od":[]},{"s":"crux-activity-log-completion-2026-06-23","st":0,"d":4,"t":5,"b":47,"e":48,"o":38,"dep":[],"ext":[],"od":[]},{"s":"crux-codex-authentication-2026-06-12","st":0,"d":4,"t":4,"b":36,"e":57,"o":76,"dep":[],"ext":[],"od":[]},{"s":"crux-audit-chain-data-contract-2026-05-29","st":0,"d":1,"t":7,"b":22,"e":22,"o":0,"dep":[],"ext":[],"od":[]},{"s":"crux-agent-passport-mcp-binding-2026-06-10","st":0,"d":0,"t":1,"b":34,"e":34,"o":0,"dep":[],"ext":[],"od":[]},{"s":"corecrux-skip-companions-projection-control-2026-05-29","st":0,"d":0,"t":1,"b":21,"e":22,"o":0,"dep":[],"ext":[],"od":[]},{"s":"corecruxd-c2pa-vault-pki-runtime-enablement-2026-05-29","st":1,"d":0,"t":7,"b":21,"e":21,"o":0,"dep":[],"ext":[],"od":[]},{"s":"corecruxd-boost-overlay-persistence-2026-05-21","st":0,"d":1,"t":6,"b":14,"e":15,"o":0,"dep":[],"ext":[],"od":[]},{"s":"corecrux-turboquant-ccxe-quant-mode","st":1,"d":0,"t":6,"b":36,"e":36,"o":11,"dep":[],"ext":[],"od":[]},{"s":"corecrux-trait-expansion-lme-s-structural-losses-2026-05-21","st":0,"d":3,"t":6,"b":14,"e":15,"o":0,"dep":[],"ext":[],"od":[]},{"s":"corecrux-vernacular-v4-schema-and-prefilter-2026-05-20","st":0,"d":0,"t":8,"b":13,"e":13,"o":0,"dep":[],"ext":[],"od":[]},{"s":"corecrux-text-search-tenant-isolation-2026-06-30","st":0,"d":5,"t":6,"b":54,"e":54,"o":2,"dep":["corecrux-offline-serving-companions-2026-06-30"],"ext":["ccxi-query-shape-routing-2026-06-30"],"od":[]},{"s":"corpus-segregation-bulk-repartition-2026-06-26","st":0,"d":4,"t":6,"b":50,"e":52,"o":33,"dep":[],"ext":[],"od":[]},{"s":"corecrux-transition-doc-content-plane-contamination-2026-06-12","st":0,"d":2,"t":6,"b":36,"e":37,"o":0,"dep":[],"ext":[],"od":[]},{"s":"corecrux-topology-no-link-prune-2026-05-27","st":0,"d":3,"t":6,"b":20,"e":21,"o":0,"dep":[],"ext":[],"od":[]},{"s":"corecrux-trait-expansion-global-default-on-2026-05-21","st":1,"d":0,"t":6,"b":14,"e":33,"o":0,"dep":[],"ext":[],"od":[]},{"s":"corecrux-trait-expansion-substrate-density-auto-tune-2026-05-21","st":0,"d":4,"t":6,"b":14,"e":15,"o":0,"dep":[],"ext":[],"od":[]},{"s":"corecruxd-companion-hot-reload-2026-05-18","st":0,"d":0,"t":6,"b":11,"e":35,"o":0,"dep":[],"ext":[],"od":[]},{"s":"corecrux-offline-serving-companions-2026-06-30","st":0,"d":6,"t":6,"b":54,"e":54,"o":34,"dep":[],"ext":["ccxi-query-shape-routing-2026-06-30","corecrux-text-search-tenant-isolation-2026-06-30"],"od":[]},{"s":"corecrux-recstyle-keyword-extension-2026-05-21","st":0,"d":3,"t":5,"b":14,"e":14,"o":0,"dep":[],"ext":[],"od":[]},{"s":"corecrux-prometheus-indexmanager-double-count-2026-05-28","st":0,"d":0,"t":3,"b":21,"e":21,"o":0,"dep":[],"ext":[],"od":[]},{"s":"corecrux-seal-shard-vs-tick-shard-mismatch-2026-06-01","st":0,"d":0,"t":1,"b":25,"e":25,"o":0,"dep":[],"ext":[],"od":[]},{"s":"corecrux-query-expansion-via-trait-embeddings-2026-05-20","st":0,"d":4,"t":6,"b":14,"e":14,"o":0,"dep":[],"ext":[],"od":[]},{"s":"corecrux-ingest-extraction-followups-2026-06-11","st":1,"d":6,"t":9,"b":35,"e":36,"o":0,"dep":[],"ext":[],"od":[]},{"s":"corecrux-retrieve-agent-shaped-payload-2026-05-15","st":1,"d":2,"t":9,"b":23,"e":24,"o":0,"dep":[],"ext":[],"od":[]},{"s":"corecrux-loadedsegment-memstats-2026-05-23","st":0,"d":3,"t":6,"b":15,"e":15,"o":0,"dep":[],"ext":[],"od":[]},{"s":"corecrux-gpu1-memory-stabilization-2026-05-28","st":0,"d":2,"t":6,"b":21,"e":24,"o":0,"dep":[],"ext":[],"od":[]},{"s":"corecrux-ingest-extraction-top10-2026-06-11","st":0,"d":0,"t":1,"b":35,"e":35,"o":0,"dep":[],"ext":[],"od":[]},{"s":"corecrux-query-expansion-rollout-completion-2026-05-21","st":0,"d":3,"t":5,"b":14,"e":35,"o":0,"dep":[],"ext":[],"od":[]},{"s":"corecrux-no-link-prune-substrate-rebuild-2026-05-29","st":0,"d":0,"t":1,"b":21,"e":21,"o":0,"dep":[],"ext":[],"od":[]},{"s":"corecrux-daemon-fast-startup-2026-06-16","st":0,"d":4,"t":6,"b":40,"e":40,"o":17,"dep":[],"ext":[],"od":[]},{"s":"corecrux-evictor-convergence-2026-05-31","st":0,"d":3,"t":4,"b":24,"e":24,"o":0,"dep":[],"ext":[],"od":[]},{"s":"codex-crux-session-banner-2026-06-01","st":0,"d":8,"t":8,"b":25,"e":29,"o":0,"dep":[],"ext":[],"od":[]},{"s":"chaincrux-phase1-5-event-edges-and-temporal-filter-2026-05-22","st":0,"d":0,"t":8,"b":17,"e":17,"o":0,"dep":[],"ext":[],"od":[]},{"s":"context-mediation-injection-2026-06-11","st":1,"d":6,"t":7,"b":36,"e":36,"o":0,"dep":[],"ext":[],"od":[]},{"s":"corecrux-bm25-64bit-tenant-filter-2026-06-13","st":1,"d":0,"t":1,"b":37,"e":37,"o":0,"dep":[],"ext":[],"od":[]},{"s":"corecrux-cascade-engagement-lme-s-2026-05-22","st":0,"d":2,"t":6,"b":15,"e":15,"o":0,"dep":[],"ext":[],"od":[]},{"s":"claudeclaw-subscription-sonnet-backend-2026-06-03","st":0,"d":6,"t":6,"b":27,"e":28,"o":0,"dep":[],"ext":[],"od":[]},{"s":"context-bench-v2-100point-thirdparty-board-2026-07-03","st":1,"d":6,"t":7,"b":57,"e":65,"o":22,"dep":["context-dependence-benchmark-scorecrux-2026-07-03"],"ext":[],"od":[]},{"s":"corecrux-document-index-lane-2026-05-15","st":0,"d":0,"t":11,"b":11,"e":11,"o":0,"dep":[],"ext":[],"od":[]},{"s":"chaincrux-phase1-prove-earned-edge-2026-05-22","st":0,"d":0,"t":7,"b":15,"e":15,"o":0,"dep":[],"ext":[],"od":[]},{"s":"corecrux-bulk-ingest-at-scale-2026-06-14","st":0,"d":0,"t":1,"b":38,"e":48,"o":61,"dep":[],"ext":[],"od":[]},{"s":"corecrux-bulk-ingest-polish-2026-05-03","st":1,"d":0,"t":1,"b":64,"e":64,"o":0,"dep":[],"ext":[],"od":[]},{"s":"codemap-endpoint-and-agent-docs-hardening-2026-07-10","st":0,"d":4,"t":4,"b":63,"e":63,"o":0,"dep":[],"ext":["codemaps-cross-repo-graph-and-value-expansion-2026-07-10"],"od":[]},{"s":"clawd-unified-daemon-relocation-data1-2026-06-13","st":0,"d":7,"t":7,"b":36,"e":37,"o":0,"dep":[],"ext":[],"od":[]},{"s":"corecrux-evidence-hash-replay-dedup-2026-06-23","st":0,"d":5,"t":5,"b":47,"e":48,"o":44,"dep":[],"ext":[],"od":[]},{"s":"companion-build-429-hardening-2026-06-16","st":0,"d":6,"t":6,"b":40,"e":40,"o":7,"dep":[],"ext":[],"od":[]},{"s":"chaincrux-zero-events-substrate-investigation-2026-05-28","st":1,"d":0,"t":5,"b":21,"e":21,"o":0,"dep":[],"ext":[],"od":[]},{"s":"codemaps-facet-coverage-completion-2026-07-12","st":1,"d":0,"t":6,"b":66,"e":66,"o":0,"dep":["codemaps-cross-repo-graph-and-value-expansion-2026-07-10"],"ext":[],"od":[]},{"s":"corecrux-curator-clustering-spike-2026-07-07","st":0,"d":2,"t":3,"b":61,"e":61,"o":0,"dep":["corecrux-memory-manager-2026-07-05"],"ext":[],"od":[]},{"s":"corecrux-event-lane-rrf-wiring-2026-05-24","st":0,"d":0,"t":8,"b":17,"e":17,"o":0,"dep":[],"ext":[],"od":[]},{"s":"context-custody-surface-2026-06-30","st":0,"d":0,"t":1,"b":54,"e":54,"o":6,"dep":[],"ext":[],"od":[]},{"s":"context-dependence-benchmark-scorecrux-2026-07-03","st":0,"d":1,"t":7,"b":56,"e":57,"o":15,"dep":["mh-ab-v2-harness-build-2026-06-12"],"ext":["context-bench-v2-100point-thirdparty-board-2026-07-03"],"od":[]},{"s":"corecrux-fleet-control-plane-2026-07-03","st":1,"d":1,"t":7,"b":64,"e":64,"o":2,"dep":[],"ext":[],"od":[]},{"s":"codexclaw-deterministic-gate-orchestration-2026-05-26","st":0,"d":1,"t":8,"b":19,"e":35,"o":0,"dep":[],"ext":[],"od":[]},{"s":"chaincrux-cascade-route-integration-2026-05-25","st":0,"d":4,"t":8,"b":18,"e":21,"o":0,"dep":[],"ext":[],"od":[]},{"s":"ccxi-query-shape-routing-2026-06-30","st":1,"d":4,"t":6,"b":54,"e":54,"o":3,"dep":["corecrux-offline-serving-companions-2026-06-30","corecrux-text-search-tenant-isolation-2026-06-30","unified-production-claims-source-2026-06-30","unified-reasoner-encode-evidence-2026-06-29"],"ext":["unified-retrieval-hardening-2026-07-02"],"od":[]},{"s":"audit-ii-gap-closure-hardening-2026-06-14","st":0,"d":0,"t":10,"b":47,"e":47,"o":33,"dep":[],"ext":["domain-index-source-authority-signal-2026-07-08"],"od":[]},{"s":"ast-polyglot-code-graph-and-repo-watch-2026-07-08","st":0,"d":10,"t":10,"b":62,"e":63,"o":2,"dep":[],"ext":[],"od":[]},{"s":"audit-ii-operational-hardening-rollout-2026-06-14","st":0,"d":10,"t":10,"b":38,"e":38,"o":0,"dep":[],"ext":[],"od":[]},{"s":"atlas-manifest-routing-production-2026-06-05","st":0,"d":11,"t":11,"b":29,"e":64,"o":90,"dep":[],"ext":[],"od":["OD-10"]},{"s":"agent-ux-02-acknowledged-memory-use-2026-05-27","st":0,"d":4,"t":4,"b":20,"e":20,"o":0,"dep":[],"ext":[],"od":[]},{"s":"agent-native-noise-reduction-2026-06-08","st":1,"d":0,"t":8,"b":32,"e":65,"o":90,"dep":[],"ext":[],"od":[]},{"s":"agent-ux-03-freshness-decay-2026-05-27","st":0,"d":5,"t":6,"b":20,"e":20,"o":0,"dep":[],"ext":["dense-lane-and-extraction-upsell-2026-06-26"],"od":[]},{"s":"agent-query-eval-corpus-2026-06-07","st":0,"d":0,"t":6,"b":31,"e":31,"o":0,"dep":[],"ext":[],"od":[]},{"s":"agent-ux-best-in-class-master-2026-05-27","st":0,"d":1,"t":9,"b":20,"e":21,"o":0,"dep":[],"ext":[],"od":[]},{"s":"agent-ux-08-identity-continuity-2026-05-27","st":0,"d":3,"t":5,"b":21,"e":21,"o":0,"dep":[],"ext":[],"od":[]},{"s":"agent-ux-05-risk-tiered-hitl-2026-05-27","st":0,"d":3,"t":6,"b":21,"e":21,"o":0,"dep":[],"ext":[],"od":[]},{"s":"agent-ux-07-verifiable-output-receipts-2026-05-27","st":0,"d":5,"t":6,"b":21,"e":21,"o":0,"dep":[],"ext":[],"od":[]},{"s":"agent-ux-04-source-linked-traceability-2026-05-27","st":0,"d":3,"t":5,"b":20,"e":21,"o":0,"dep":[],"ext":["domain-index-source-authority-signal-2026-07-08"],"od":[]},{"s":"agent-ux-06-typed-action-traces-2026-05-27","st":0,"d":5,"t":8,"b":20,"e":20,"o":0,"dep":[],"ext":[],"od":[]},{"s":"agent-ux-11-byo-audit-trail-2026-05-27","st":1,"d":4,"t":6,"b":20,"e":20,"o":0,"dep":[],"ext":[],"od":[]},{"s":"agent-query-eval-lanes-on-retest-2026-06-08","st":0,"d":0,"t":5,"b":32,"e":33,"o":0,"dep":[],"ext":[],"od":[]},{"s":"agent-ux-10-visible-autonomy-contract-2026-05-27","st":0,"d":2,"t":6,"b":20,"e":20,"o":0,"dep":[],"ext":[],"od":[]},{"s":"amr-lane-authority-credit-gating-2026-06-07","st":1,"d":2,"t":7,"b":31,"e":32,"o":0,"dep":[],"ext":["domain-index-source-authority-signal-2026-07-08"],"od":[]},{"s":"agent-config-wizard-2026-05-19","st":0,"d":3,"t":8,"b":12,"e":12,"o":5,"dep":[],"ext":[],"od":[]},{"s":"agent-ux-01-readable-editable-memory-2026-05-27","st":0,"d":4,"t":4,"b":20,"e":20,"o":0,"dep":[],"ext":[],"od":[]},{"s":"agent-harness-testbench-messyworld-2026-06-18","st":1,"d":0,"t":7,"b":41,"e":65,"o":94,"dep":[],"ext":[],"od":[]},{"s":"agent-ux-12-calm-deferred-output-2026-05-27","st":0,"d":0,"t":6,"b":21,"e":21,"o":0,"dep":[],"ext":[],"od":[]},{"s":"agent-ux-09-scoped-forget-2026-05-27","st":0,"d":2,"t":5,"b":20,"e":20,"o":0,"dep":[],"ext":[],"od":[]}];

  var RINGS_RFACTS = [
  ['sso', 'brief', 'memory', 0.920, 'codex-work', 'medium', 205, 1],
  ['sso', 'gate:M0', 'gate', 0.936, 'codex-work', 'medium', 205, 1],
  ['sso', 'decision:topology-corrected-cruxengine', 'decision', 0.948, 'codex-work', 'medium', 207, 1],
  ['sso', 'milestone:M1-partial', 'memory', 0.990, 'codex-work', 'medium', 275, 1],
  ['bf', 'gate:M0', 'gate', 1.356, 'codex-work', 'stable', 412, 1],
  ['sso', 'gate:M1', 'gate', 1.381, 'codex-work', 'medium', 296, 1],
  ['sso', 'gate:M2', 'gate', 1.649, 'codex-work', 'medium', 236, 1],
  ['bf', 'gate:M1', 'gate', 1.669, 'codex-work', 'stable', 536, 1],
  ['sso', 'gate:M3-M4', 'gate', 1.829, 'codex-work', 'medium', 328, 1],
  ['bf', 'gate:M2', 'gate', 1.847, 'codex-work', 'stable', 463, 1],
  ['bf', 'gate:M4', 'gate', 1.858, 'codex-work', 'stable', 409, 1],
  ['bf', 'handoff:2026-07-14', 'handoff', 1.882, 'codex-work', 'stable', 409, 1],
  ['sso', 'console-v1-removed', 'memory', 1.892, 'codex-work', 'medium', 288, 1],
  ['bf', 'progress:M3', 'memory', 1.909, 'codex-work', 'volatile', 274, 1],
  ['bf', 'gate:M3', 'gate', 1.951, 'codex-work', 'stable', 316, 1],
  ['bf', 'gate:M3', 'gate', 2.032, 'codex-work', 'stable', 215, 2],
  ['sso', 'console-v1-removed-followup-done', 'memory', 2.891, 'codex-work', 'medium', 329, 1],
  ['sso', 'gate:M1-R-code', 'gate', 8.597, 'claude-work', 'medium', 127, 1],
  ['sso', 'decision:vault-target-regression-repair', 'decision', 8.597, 'claude-work', 'stable', 155, 1],
  ['bf', 'gate:M5b', 'gate', 9.367, 'claude-work', 'stable', 184, 1],
  ['bf', 'decision:m5b-installer-transaction', 'decision', 9.367, 'claude-work', 'stable', 232, 1],
];

  var RINGS_GRAPH_RAW = [{"e":"execplan:cross-site-auth-sso-cuecrux-2026-07-13","k":"gate:M1-R-code","d":75.59696759259168,"a":"claude-work","h":"medium","c":1.0,"t":127},{"e":"execplan:verifiable-record-products-2026-07-17","k":"gate:M3-core-pointer-producer-code-2026-07-22","d":76.75865740740846,"a":"claude-work","h":"stable","c":1.0,"t":158},{"e":"execplan:crux-daemon-buyer-fit-buildout-2026-07-13","k":"gate:M3","d":68.95072916666686,"a":"codex-work","h":"stable","c":1.0,"t":316},{"e":"incident:2026-07-22","k":"gpu1-cargo-deploy-help-side-effect","d":76.43028935185066,"a":"claude-work","h":"stable","c":1.0,"t":291},{"e":"execplan:cross-site-auth-sso-cuecrux-2026-07-13","k":"decision:vault-target-regression-repair","d":75.59696759259168,"a":"claude-work","h":"stable","c":1.0,"t":155},{"e":"execplan:crux-daemon-buyer-fit-buildout-2026-07-13","k":"progress:M3","d":68.90971064814948,"a":"codex-work","h":"volatile","c":1.0,"t":274},{"e":"execplan:production-ethos-audit-harness-2026-07-17","k":"gate:M5","d":74.60589120370423,"a":"codex-work","h":"volatile","c":1.0,"t":323},{"e":"execplan:cross-site-auth-sso-cuecrux-2026-07-13","k":"gate:M1","d":68.38157407407562,"a":"codex-work","h":"medium","c":1.0,"t":296},{"e":"execplan:wikicrux-public-readiness-hardening-2026-07-21","k":"gate:M3b-blocked","d":75.82773148148044,"a":"drivew-host","h":"stable","c":1.0,"t":221},{"e":"execplan:crux-daemon-buyer-fit-buildout-2026-07-13","k":"decision:m5b-installer-transaction","d":76.36789351851985,"a":"claude-work","h":"stable","c":1.0,"t":232},{"e":"incident:2026-07-22","k":"crc-v1-resident-ordinal-handle-alias","d":76.47960648148,"a":"claude-work","h":"stable","c":1.0,"t":185},{"e":"execplan:verifiable-record-products-2026-07-17","k":"gate:M9-evidence-publication","d":76.67115740740701,"a":"claude-work","h":"stable","c":1.0,"t":125},{"e":"execplan:cross-site-auth-sso-cuecrux-2026-07-13","k":"brief","d":67.92068287037182,"a":"codex-work","h":"medium","c":1.0,"t":205},{"e":"execplan:wikicrux-m5-pricing-enforcement-2026-07-17","k":"decision:m3b-refund-contract-parity","d":76.02534722222117,"a":"claude-work","h":"stable","c":1.0,"t":153},{"e":"execplan:verifiable-record-products-2026-07-17","k":"gate:M3-engine-consumer-deploy-2026-07-22","d":76.73957175925898,"a":"claude-work","h":"stable","c":1.0,"t":223},{"e":"execplan:cross-site-auth-sso-cuecrux-2026-07-13","k":"gate:M0","d":67.93586805555606,"a":"codex-work","h":"medium","c":1.0,"t":205},{"e":"execplan:crux-macaroon-token-attenuation-2026-07-16","k":"design:sync-delegation-convention","d":76.4979745370365,"a":"codex-work","h":"stable","c":1.0,"t":408},{"e":"execplan:crux-macaroon-token-attenuation-2026-07-16","k":"gate:M2prime-hotfix-reviewed-and-reconciliation-plan","d":76.41813657407329,"a":"codex-work","h":"stable","c":1.0,"t":743},{"e":"execplan:wikicrux-market-wedge-offers-2026-07-16","k":"decision:canonical-pricing","d":75.82225694444423,"a":"claude-work","h":"stable","c":1.0,"t":146},{"e":"execplan:wikicrux-m5-pricing-enforcement-2026-07-17","k":"gate:M3b","d":76.02534722222117,"a":"claude-work","h":"stable","c":1.0,"t":223},{"e":"execplan:verifiable-record-products-2026-07-17","k":"gate:M3","d":76.7468518518508,"a":"claude-work","h":"stable","c":1.0,"t":150},{"e":"execplan:cuecrux-selfserve-launch-readiness-2026-07-16","k":"gate:M8-edge-repair","d":76.54800925925883,"a":"claude-work","h":"none","c":1.0,"t":254},{"e":"bench:provenance-byok-local-20260721T174751Z-8e711150","k":"result","d":75.74369212962847,"a":"claude-work","h":"stable","c":1.0,"t":145},{"e":"execplan:cross-site-auth-sso-cuecrux-2026-07-13","k":"gate:M3-M4","d":68.8297453703708,"a":"codex-work","h":"medium","c":1.0,"t":328},{"e":"execplan:cross-site-auth-sso-cuecrux-2026-07-13","k":"console-v1-removed-followup-done","d":69.89159722222394,"a":"codex-work","h":"medium","c":1.0,"t":329},{"e":"execplan:cross-site-auth-sso-cuecrux-2026-07-13","k":"gate:M2","d":68.64881944444278,"a":"codex-work","h":"medium","c":1.0,"t":236},{"e":"execplan:crux-macaroon-token-attenuation-2026-07-16","k":"design:M3prime-sync-enforcement-on-v11","d":76.43527777777854,"a":"codex-work","h":"stable","c":1.0,"t":870},{"e":"incident:2026-07-22","k":"release-v0.5.48-macos-socket-fixture","d":76.56612268518438,"a":"claude-work","h":"stable","c":1.0,"t":147},{"e":"execplan:wikicrux-public-readiness-hardening-2026-07-21","k":"gate:M3b","d":75.84260416666802,"a":"drivew-host","h":"stable","c":1.0,"t":287},{"e":"execplan:wikicrux-market-wedge-offers-2026-07-16","k":"gate:M0","d":75.82225694444423,"a":"claude-work","h":"stable","c":1.0,"t":74},{"e":"execplan:corecrux-object-storage-tier-2026-07-07","k":"gate:G3-code-merge","d":76.63100694444438,"a":"claude-work","h":"stable","c":1.0,"t":125},{"e":"execplan:crux-daemon-buyer-fit-buildout-2026-07-13","k":"gate:M1","d":68.6698958333327,"a":"codex-work","h":"stable","c":1.0,"t":536},{"e":"execplan:wikicrux-m5-pricing-enforcement-2026-07-17","k":"gate:M5a","d":75.79510416666744,"a":"claude-work","h":"stable","c":1.0,"t":230},{"e":"execplan:cross-site-auth-sso-cuecrux-2026-07-13","k":"decision:topology-corrected-cruxengine-14343","d":67.94807870370278,"a":"codex-work","h":"medium","c":1.0,"t":207},{"e":"incident:2026-07-22","k":"passport-mint-pre-m2-approval-live","d":76.75064814814687,"a":"claude-work","h":"stable","c":1.0,"t":203},{"e":"incident:2026-07-22","k":"core-sidecar-snapshot-path","d":76.8100694444438,"a":"claude-work","h":"stable","c":1.0,"t":172},{"e":"execplan:crux-daemon-buyer-fit-buildout-2026-07-13","k":"gate:M5b","d":76.36789351851985,"a":"claude-work","h":"stable","c":1.0,"t":184},{"e":"execplan:crux-daemon-buyer-fit-buildout-2026-07-13","k":"handoff:2026-07-14","d":68.88217592592628,"a":"codex-work","h":"stable","c":1.0,"t":409},{"e":"execplan:cross-site-auth-sso-cuecrux-2026-07-13","k":"milestone:M1-partial","d":67.99072916666773,"a":"codex-work","h":"medium","c":1.0,"t":275},{"e":"execplan:crux-macaroon-token-attenuation-2026-07-16","k":"gate:M2-rustdoc-fix-and-M3-grounding","d":75.82988425925942,"a":"codex-work","h":"stable","c":1.0,"t":732},{"e":"execplan:sdkcrux-dependency-vuln-remediation-2026-07-20","k":"audit-snapshot","d":74.56193287036876,"a":"codex-work","h":"volatile","c":1.0,"t":415},{"e":"execplan:crux-daemon-buyer-fit-buildout-2026-07-13","k":"gate:M0","d":68.35657407407416,"a":"codex-work","h":"stable","c":1.0,"t":412},{"e":"execplan:crux-passport-mint-request-gate-2026-07-17","k":"gate:M2.1-integration","d":76.65032407407489,"a":"claude-work","h":"stable","c":1.0,"t":207},{"e":"execplan:cuecrux-selfserve-launch-readiness-2026-07-16","k":"decision:edge-cutover-gate","d":76.54349537036978,"a":"claude-work","h":"none","c":1.0,"t":167},{"e":"incident:2026-07-20","k":"sdkcrux-ci-runner-move-and-stacked-failures","d":74.54767361111226,"a":"codex-work","h":"volatile","c":1.0,"t":564},{"e":"execplan:production-ethos-audit-harness-2026-07-17","k":"gate:M7","d":75.6126157407416,"a":"claude-work","h":"stable","c":1.0,"t":116},{"e":"execplan:crux-daemon-buyer-fit-buildout-2026-07-13","k":"gate:M2","d":68.84675925926058,"a":"codex-work","h":"stable","c":1.0,"t":463},{"e":"execplan:crux-banner-redesign-2026-07-21","k":"gate:deploy-v0.5.47","d":76.39510416666599,"a":"codex-work","h":"volatile","c":1.0,"t":216},{"e":"execplan:wikicrux-market-wedge-offers-2026-07-16","k":"gate:M1","d":75.82225694444423,"a":"claude-work","h":"medium","c":1.0,"t":162},{"e":"execplan:verifiable-record-products-2026-07-17","k":"gate:M3-deploy-automation-2026-07-22","d":76.7569560185184,"a":"claude-work","h":"stable","c":1.0,"t":175},{"e":"execplan:crux-macaroon-token-attenuation-2026-07-16","k":"incident:M3-M4-collision-with-concurrent-security-hotfix","d":75.92763888889021,"a":"codex-work","h":"stable","c":1.0,"t":822},{"e":"execplan:crux-macaroon-token-attenuation-2026-07-16","k":"gate:M3prime-sync-delegation","d":76.61583333333328,"a":"codex-work","h":"stable","c":1.0,"t":638},{"e":"__work_comment__::w_51752647ca6e4bdbbe4c3b45d30241c9::c_9a7285cbf6604152be964e81d7de0367","k":"record","d":76.73920138888934,"a":null,"h":"none","c":1.0,"t":173},{"e":"execplan:crux-passport-mint-request-gate-2026-07-17","k":"gate:M2-live-containment-2026-07-22","d":76.75064814814687,"a":"claude-work","h":"stable","c":1.0,"t":159},{"e":"execplan:sdkcrux-dependency-vuln-remediation-2026-07-20","k":"gate:M4","d":74.58318287037036,"a":"codex-work","h":"volatile","c":1.0,"t":220},{"e":"execplan:corecrux-object-storage-tier-2026-07-07","k":"gate:G3-prod-safety-recheck","d":76.6583912037022,"a":"claude-work","h":"volatile","c":1.0,"t":131},{"e":"execplan:wikicrux-m5-pricing-enforcement-2026-07-17","k":"gate:M3a-harness","d":75.91656249999869,"a":"claude-work","h":"stable","c":1.0,"t":244},{"e":"execplan:production-ethos-audit-harness-2026-07-17","k":"gate:M4","d":74.578125,"a":"codex-work","h":"volatile","c":1.0,"t":344},{"e":"execplan:crux-daemon-buyer-fit-buildout-2026-07-13","k":"gate:M4","d":68.85881944444554,"a":"codex-work","h":"stable","c":1.0,"t":409},{"e":"execplan:crux-passport-mint-request-gate-2026-07-17","k":"gate:M2.1-integration","d":76.64783564814934,"a":"claude-work","h":"stable","c":1.0,"t":185},{"e":"execplan:wikicrux-public-readiness-hardening-2026-07-21","k":"gate:M3b","d":75.9136111111111,"a":"drivew-host","h":"stable","c":1.0,"t":293},{"e":"execplan:cross-site-auth-sso-cuecrux-2026-07-13","k":"console-v1-removed","d":68.89186342592438,"a":"codex-work","h":"medium","c":1.0,"t":288},{"e":"incident:2026-07-22","k":"vaultcrux-public-edge-loopback-regression","d":76.54800925925883,"a":"claude-work","h":"stable","c":1.0,"t":157},{"e":"incident:2026-07-22","k":"legal-hold-canary-mcp-auth-mismatch","d":76.43935185185182,"a":"codex-work","h":"stable","c":1.0,"t":214},{"e":"execplan:crux-daemon-buyer-fit-buildout-2026-07-13","k":"gate:M3","d":69.03211805555475,"a":"codex-work","h":"stable","c":1.0,"t":215},{"e":"incident:2026-07-22","k":"legal-hold-canary-mcp-auth-mismatch","d":76.43893518518598,"a":"codex-work","h":"stable","c":1.0,"t":214}];

  // =========================================================================
  //  Rings — the "clock of work" (console-surfaces-remediation M10). NATIVE
  //  port of UI-prototype/rings-clock/console-mock.html: a canvas 2D engine
  //  that replays the real ExecPlan portfolio as an animated ring, with lens
  //  tiles, a control bar, and a slide-out detail pane. Ported from the mock's
  //  string-built DOM to el()/svgEl() safe construction (no raw HTML strings);
  //  every raw network read rewired to the console's CruxApi client (fetchJSON); an
  //  explicit teardown cancels the RAF + observers + document/window listeners
  //  once the canvas leaves the DOM (route change clears #content). Snapshot
  //  data (RINGS_PLANS_RAW / RINGS_GRAPH_RAW / RINGS_RFACTS) is the honest
  //  degradation when a live feed is absent.
  // =========================================================================
  var __ringsCleanupFn = null;   // module-scope teardown handle (see renderRings)

  function renderRings(container, ctxIn) {
    ctxIn = ctxIn || {};
    // Tear down any previous instance (re-entry / rings→rings) before building.
    if (typeof __ringsCleanupFn === 'function') { try { __ringsCleanupFn(); } catch (e) { /* noop */ } __ringsCleanupFn = null; }
    container.textContent = '';

    var REDUCED = (typeof matchMedia === 'function') && matchMedia('(prefers-reduced-motion: reduce)').matches;
    var MONO = 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';
    var TAU = Math.PI * 2;
    var mix = function (a, b, k) { return a + (b - a) * k; };
    function mulberry32(a) {
      return function () {
        a |= 0; a = a + 0x6D2B79F5 | 0;
        var t = Math.imul(a ^ a >>> 15, 1 | a);
        t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
        return ((t ^ t >>> 14) >>> 0) / 4294967296;
      };
    }
    function hex2rgba(hex, a) {
      var n = parseInt(hex.slice(1), 16);
      return 'rgba(' + (n >> 16 & 255) + ',' + (n >> 8 & 255) + ',' + (n & 255) + ',' + Math.max(0, Math.min(1, a)) + ')';
    }

    // ---- DOM scaffold (replaces the mock's markup; refs kept, no getElementById) ----
    var root = el('div', { 'class': 'rings-root' });
    var stage = el('div', { 'class': 'rings-stage' });
    var cv = el('canvas', { 'class': 'rings-canvas', 'aria-label': 'Rings: the ExecPlan portfolio replayed as an animated clock; tiles switch the lens' });
    stage.appendChild(cv);

    function tileEl(lens, hue, label, n) {
      var nEl = el('span', { 'class': 'n', text: n });
      var b = el('button', { 'class': 'rings-tile', type: 'button', 'data-lens': lens, 'aria-pressed': lens === 'work' ? 'true' : 'false' },
        [el('span', { 'class': 't' }, [el('i', { style: 'background:' + hue }), label]), nEl]);
      return { b: b, n: nEl };
    }
    var tWork = tileEl('work', '#a78bfa', 'ExecPlans', '1,040');
    var tData = tileEl('data', '#8b96f2', 'Data graph', '66');
    var tMem = tileEl('memory', '#2dd4bf', 'Memory', '21');
    var tSess = tileEl('sessions', '#22d3ee', 'Sessions', '32');
    var tTok = tileEl('tokens', '#f5a623', 'Tokens', '—');
    var tiles = el('div', { 'class': 'rings-tiles', role: 'group', 'aria-label': 'Ring lenses' }, [tWork.b, tData.b, tMem.b, tSess.b, tTok.b]);
    var tileByLens = { work: tWork, data: tData, memory: tMem, sessions: tSess, tokens: tTok };
    stage.appendChild(tiles);

    function glEl(label, n) {
      var nEl = el('span', { 'class': 'n', text: n });
      return { el: el('button', { 'class': 'rings-gl', type: 'button' }, [el('span', { 'class': 't', text: label }), nEl]), n: nEl };
    }
    var glFacts = glEl('facts', '5,026'), glSessions = glEl('sessions', '76'), glExecplans = glEl('execplans', '1,081');
    var glMcp = glEl('mcp agents', '5'), glInt = glEl('integrations', '3'), glEngine = glEl('engine', 'off');
    var glSrc = el('span', { 'class': 'src', text: 'snapshot · 2026-07-22' });
    var glance = el('div', { 'class': 'rings-glance', role: 'group', 'aria-label': 'Daemon at a glance' },
      [glFacts.el, glSessions.el, glExecplans.el, glMcp.el, glInt.el, glEngine.el, glSrc]);
    stage.appendChild(glance);

    // ---- control bar ----
    function icBtn(txt, title, pressed) { return el('button', { 'class': 'ic', type: 'button', title: title, 'aria-pressed': pressed ? 'true' : 'false' }, [txt]); }
    var bSpin = icBtn('⟳', 'Ambient spin', !REDUCED);
    var bClock = icBtn('◷', 'Reset clock to 12 (also stops spin)', false); bClock.removeAttribute('aria-pressed');
    var bMode = icBtn('▥', 'Bars: spoke from centre to each node', true);
    var bDir = icBtn('⇅', 'Time edge: outward (rings grow) / inward (nodes sink from rim)', false);
    var bAll = icBtn('◌', 'Census: every plan stays on the clock; hover names sectors', false);
    var bDone = icBtn('✓', 'Show completed plans on the clock (auto-on during playback)', false);
    var bLedger = icBtn('≡', 'Completed-plans list (left). Auto-shows during playback; hides on lens swap.', false);
    var bState = icBtn('◑', 'State colours: complete green · in progress purple · blocked red', false);
    var bLin = icBtn('⌇', 'Lineage chords (depends_on)', false);
    var grpTools = el('span', { 'class': 'grp' }, [bSpin, bClock, bMode, bDir, bAll, bDone, bLedger, bState, bLin]);

    function opt(v, t) { return el('option', { value: v }, [t]); }
    var sKind = el('select', { 'aria-label': 'Filter by node kind' }, [opt('all', 'all kinds'), opt('gate', 'gates only'), opt('decision', 'decisions (OD) only'), opt('memory', 'memory only'), opt('handoff', 'handoffs only')]);
    var sAgent = el('select', { 'aria-label': 'Filter by agent passport' }, [opt('all', 'all agents'), opt('claude-work', 'claude-work'), opt('codex-work', 'codex-work')]);
    var grpFilters = el('span', { 'class': 'grp' }, [sKind, sAgent]);

    var bTokCum = el('button', { type: 'button', 'aria-pressed': 'true', title: 'Running total across the window' }, ['cumulative']);
    var bTokDay = el('button', { type: 'button', 'aria-pressed': 'false', title: 'Tokens per day' }, ['per day']);
    var grpTokViews = el('span', { 'class': 'grp' }, [bTokCum, bTokDay]); grpTokViews.style.display = 'none';

    var dStart = el('input', { type: 'date', min: '2026-05-18', max: '2026-07-22', value: '2026-05-18', 'aria-label': 'Window start date' });
    var rStart = el('input', { type: 'range', min: '0', max: '1000', value: '0', style: 'width:70px', 'aria-label': 'Window start' });
    var rEnd = el('input', { type: 'range', min: '0', max: '1000', value: '1000', style: 'width:70px', 'aria-label': 'Window end' });
    var dEnd = el('input', { type: 'date', min: '2026-05-18', max: '2026-07-22', value: '2026-07-22', 'aria-label': 'Window end date' });
    var grpWindow = el('span', { 'class': 'grp' }, [dStart, rStart, rEnd, dEnd]);

    var bPlay = icBtn('▶', 'Replay the window', false);
    var rTime = el('input', { type: 'range', min: '0', max: '1000', value: '1000', 'aria-label': 'Time' });
    var cDate = el('span', { 'class': 'chip', text: '2026-07-22' });
    var grpPlay = el('span', { 'class': 'grp' }, [bPlay, rTime, cDate]);

    var bZin = el('button', { type: 'button', 'aria-label': 'Zoom in' }, ['+']);
    var bZout = el('button', { type: 'button', 'aria-label': 'Zoom out' }, ['−']);
    var bZfit = el('button', { type: 'button' }, ['fit']);
    var grpZoom = el('span', { 'class': 'grp' }, [bZin, bZout, bZfit]);

    var hint = el('span', { 'class': 'hint', text: 'wheel = zoom · drag = pan · click node / sector / ledger · background clears' });
    var stagebar = el('div', { 'class': 'rings-stagebar' }, [grpTools, grpFilters, grpTokViews, grpWindow, grpPlay, grpZoom, hint]);
    stage.appendChild(stagebar);

    var pane = el('aside', { 'class': 'rings-pane', 'aria-label': 'Detail pane' });
    stage.appendChild(pane);
    root.appendChild(stage);

    var note = el('p', { 'class': 'rings-note', text: 'tiles switch the lens · ExecPlans lens keeps solo / ledger / lineage / filters · live: /v1/work · /v1/console/summary · /v1/facts/list — snapshot fallback when a feed is absent' });
    root.appendChild(note);

    var tip = el('div', { 'class': 'rings-tip', role: 'status' });
    root.appendChild(tip);
    container.appendChild(root);

    // ---- tooltip: DOM builder (safe DOM, no raw HTML) ----
    function tb(t) { return el('b', { text: t }); }
    function tk(t) { return el('span', { 'class': 'k', text: t }); }
    function br() { return el('br'); }
    function showTip(x, y, nodes) {
      tip.textContent = '';
      nodes.forEach(function (n2) { if (n2 == null) { return; } tip.appendChild(typeof n2 === 'string' ? doc().createTextNode(n2) : n2); });
      var pad = 14, w = tip.offsetWidth || 220;
      tip.style.left = Math.min(x + pad, (typeof innerWidth !== 'undefined' ? innerWidth : 1440) - w - 10) + 'px';
      tip.style.top = (y + pad + tip.offsetHeight > (typeof innerHeight !== 'undefined' ? innerHeight : 900) ? y - tip.offsetHeight - 8 : y + pad) + 'px';
      tip.style.opacity = 1;
    }
    function hideTip() { tip.style.opacity = 0; }

    // ---- time base: day 0 = 2026-05-07 ----
    var NOW = 76, dataSrc = 'snapshot';
    function dayDate(d) { return new Date(Date.UTC(2026, 4, 7) + d * 86400000).toISOString().slice(0, 10); }

    // ---- dataset ----
    var KIND_HUE = { gate: '#2dd4bf', decision: '#a78bfa', memory: '#8b96f2', handoff: '#f5a623', incident: '#ef4444' };
    var STATE = { 0: 'complete', 1: 'in_progress', 2: 'blocked' };
    var STATE_HUE = { 0: '#34d399', 1: '#a78bfa', 2: '#ef4444' };
    var stateHue = function (p) { return STATE_HUE[p.st]; };
    var PARK_DAYS = 18;

    var PLANS = [], DEP_EDGES = [], cells = [];
    function mapRaw(p, i) {
      var short = p.s.replace(/-2026-\d\d-\d\d$/, '').replace(/-2026$/, '');
      var exit = p.st === 0 ? p.e + 1.5 : (NOW - p.e > PARK_DAYS ? p.e + PARK_DAYS : Infinity);
      return { i: i, slug: p.s, short: short, st: p.st, done: p.d, total: p.t || 1, b: Math.max(0, p.b), e: p.e, o: p.o, exit: exit,
        dep: p.dep || [], ext: p.ext || [], od: p.od || [],
        traced: p.s.indexOf('crux-daemon-buyer-fit') === 0 || p.s.indexOf('cross-site-auth-sso') === 0 };
    }
    function loadPlans(raws) { PLANS.length = 0; raws.forEach(function (p, i) { PLANS.push(mapRaw(p, i)); }); }
    function rebuildLineage() {
      DEP_EDGES.length = 0;
      var bySlug = {}; PLANS.forEach(function (p) { bySlug[p.slug] = p; });
      PLANS.forEach(function (p) { p.dep.forEach(function (d) { var t2 = bySlug[d]; if (t2) { DEP_EDGES.push({ a: p, b: t2 }); } }); });
    }
    var J13 = 67;
    var RFACTS = RINGS_RFACTS;
    function buildCells() {
      cells.length = 0;
      var rr = mulberry32(0xC4C4);
      PLANS.forEach(function (p) {
        if (p.traced) {
          var tag = p.slug.indexOf('crux-daemon-buyer-fit') === 0 ? 'bf' : 'sso';
          RFACTS.forEach(function (r) {
            if (r[0] !== tag) { return; }
            cells.push({ p: p, key: r[1], kind: r[2], day: J13 + r[3], actor: r[4], horizon: r[5], tokens: r[6], version: r[7], real: true, ja: rr(), jr: rr() });
          });
          return;
        }
        var span = Math.max(0.5, p.e - p.b);
        var nGates = Math.min(p.done, 12);
        for (var m = 0; m < nGates; m++) {
          cells.push({ p: p, key: 'gate:M' + m, kind: 'gate', day: p.b + span * ((m + 1) / (nGates + 1)), real: false, ja: rr(), jr: rr() });
        }
        var nMem = Math.max(1, Math.min(6, Math.round(span / 6) + (p.o > 0 ? 2 : 0)));
        for (var mm = 0; mm < nMem; mm++) {
          var kinds = ['memory', 'memory', 'decision'];
          var kk = kinds[Math.floor(rr() * 3)];
          cells.push({ p: p, key: kk, kind: kk, day: p.b + span * rr(), real: false, ja: rr(), jr: rr() });
        }
      });
      PLANS.forEach(function (p) {
        p.cells = cells.filter(function (c) { return c.p === p; }).sort(function (a, b) { return b.day - a.day; });
        var asc = p.cells.slice().sort(function (a, b) { return a.day - b.day; });
        asc.forEach(function (c, k) { c.rank = k; c.n = asc.length; });
        asc.forEach(function (c) { c.tokW = (c.kind === 'gate' ? 3 : c.kind === 'decision' ? 2 : 1) + (c.tokens ? c.tokens / 250 : 0); });
        p.tokMax = Math.max.apply(null, [0.001].concat(asc.map(function (c) { return c.tokW; })));
        p.tokScale = 0.35 + 0.65 * Math.min(1, Math.log(1 + p.o) / Math.log(81));
      });
    }
    loadPlans(RINGS_PLANS_RAW); rebuildLineage(); buildCells();

    // ---- view state ----
    var rot = 0, spinning = !REDUCED, resetTween = false;
    var mode = 'bars', showCompleted = false, showLedger = false, dir = 'out', showAll = false;
    var hoverSec = null, colorByState = false, showLineage = false, lens = 'work', lensLabels = [];
    var fKind = 'all', fAgent = 'all';
    var passFilter = function (c) { return (fKind === 'all' || c.kind === fKind) && (fAgent === 'all' || c.actor === fAgent); };
    var S = 11, E = NOW, T = NOW, playing = false, Z = 1, panX = 0, panY = 0;
    var hover = null, pinned = null, sel = null, solo = null, ledgerRows = [];
    var mxAbs = 0, myAbs = 0, dragging = false, dragMoved = 0, lastPX = 0, lastPY = 0;
    var flashes = [];

    var SEAM = 0.10, BASE = -Math.PI / 2 + SEAM / 2, EPOCH_RINGS = 10;
    function activePlans(t) {
      if (solo) { return [solo]; }
      var out;
      if (showAll) { out = PLANS.filter(function (p) { return p.b <= t && p.e >= S - 0.001 && p.b <= E; }); }
      else { out = PLANS.filter(function (p) { return p.b <= t && t < p.exit && p.e >= S - 0.001 && p.b <= E; }); }
      if (!showCompleted) { out = out.filter(function (p) { return p.st !== 0; }); }
      return out;
    }
    function layoutTargets(t) {
      if (solo) { var o1 = new Map(); o1.set(solo.i, { a0: -Math.PI / 2 + 0.02, a1: Math.PI - 0.02 }); return o1; }
      var act = activePlans(t).sort(function (a, b) { return b.b - a.b || a.i - b.i; });
      var width = (TAU - SEAM) / Math.max(1, act.length);
      var out = new Map();
      act.forEach(function (p, k) { out.set(p.i, { a0: BASE + k * width, a1: BASE + (k + 1) * width }); });
      return out;
    }
    function stepLayout(dt) {
      var targets = layoutTargets(T);
      var k = REDUCED ? 1 : Math.min(1, dt * 7);
      PLANS.forEach(function (p) {
        var tg = targets.get(p.i);
        if (tg) {
          if (!p.lay) {
            var mid0 = (tg.a0 + tg.a1) / 2;
            p.lay = { a0: mid0, a1: mid0, alpha: 0 };
            if (flashes.length < 40) { flashes.push({ kind: 'enter', ang: mid0, t0: performance.now() / 1000, hue: '#8b96f2' }); }
          }
          p.lay.a0 = mix(p.lay.a0, tg.a0, k); p.lay.a1 = mix(p.lay.a1, tg.a1, k); p.lay.alpha = mix(p.lay.alpha, 1, k);
        } else if (p.lay) {
          if (!p.lay.exiting) {
            p.lay.exiting = true;
            var mid1 = (p.lay.a0 + p.lay.a1) / 2;
            var hue = p.st === 0 ? '#34d399' : p.st === 2 ? '#ef4444' : '#7e8595';
            flashes.push({ kind: 'exit', ang: mid1, t0: performance.now() / 1000, hue: hue });
          }
          var mid = (p.lay.a0 + p.lay.a1) / 2;
          p.lay.a0 = mix(p.lay.a0, mid, k); p.lay.a1 = mix(p.lay.a1, mid, k); p.lay.alpha = mix(p.lay.alpha, 0, k);
          if (p.lay.alpha < 0.02) { p.lay = null; }
        }
        if (p.lay && !targets.get(p.i)) { /* keep exiting */ } else if (p.lay) { p.lay.exiting = false; }
      });
    }

    // ---- stage geometry ----
    var ctx = cv.getContext('2d');
    var W = 0, H = 0, visible = true, rafId = null, lastT = performance.now();
    function resize() {
      var r = cv.getBoundingClientRect(), dpr = Math.min((typeof devicePixelRatio !== 'undefined' ? devicePixelRatio : 1) || 1, 2);
      W = r.width; H = r.height;
      cv.width = Math.round(W * dpr); cv.height = Math.round(H * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }
    var ro = (typeof ResizeObserver !== 'undefined') ? new ResizeObserver(resize) : null;
    if (ro) { ro.observe(cv); }
    var io = (typeof IntersectionObserver !== 'undefined') ? new IntersectionObserver(function (es) { visible = es[0].isIntersecting; }, { rootMargin: '60px' }) : null;
    if (io) { io.observe(cv); }

    function geom() {
      var cx = W / 2, cy = H / 2;
      var R = Math.min(W * 0.9, H * 0.78) * 0.44;
      var r0 = R * 0.13;
      return { cx: cx, cy: cy, R: R, r0: r0 };
    }
    var RAD_LO = 11;
    function dayR(g, day) {
      if (dir === 'in') { var age = Math.max(0, Math.min(1, (T - day) / Math.max(0.5, T - RAD_LO))); return g.r0 + (g.R - g.r0) * (0.96 - 0.88 * age); }
      var f = Math.max(0, Math.min(1, (day - RAD_LO) / Math.max(0.5, E - RAD_LO)));
      return g.r0 + (g.R - g.r0) * (0.08 + 0.88 * f);
    }
    function updateRadLo() {
      RAD_LO = S;
      if (lens !== 'work' || showAll || solo) { return; }
      var lo = Infinity;
      activePlans(T).forEach(function (p) { p.cells.forEach(function (c) { if (c.day <= T && c.day >= S && c.day <= E && c.day < lo) { lo = c.day; } }); });
      if (lo < Infinity) { RAD_LO = Math.max(S, Math.min(lo, E - 1)); }
    }
    function toScreen(g, x, y) { var c = Math.cos(rot), s = Math.sin(rot); return { x: g.cx + panX + (x * c - y * s) * Z, y: g.cy + panY + (x * s + y * c) * Z }; }
    function toDisc(g, sx, sy) { var ux = (sx - g.cx - panX) / Z, uy = (sy - g.cy - panY) / Z; var c = Math.cos(-rot), s = Math.sin(-rot); return { x: ux * c - uy * s, y: ux * s + uy * c }; }
    var soloRingR = function (g, c) { var unit = g.R - g.r0; var rMax = g.r0 + unit * 0.92, rMin = g.r0 + unit * 0.18; return c.n > 1 ? rMax - (rMax - rMin) * (c.rank / (c.n - 1)) : (rMax + rMin) / 2; };
    function cellPos(g, c) {
      if (!c.p.lay) { return null; }
      var frac = c.n > 1 ? (c.rank + 0.5) / c.n : 0.5;
      var a = c.p.lay.a0 + (c.p.lay.a1 - c.p.lay.a0) * (0.06 + 0.88 * frac);
      var r = solo === c.p ? soloRingR(g, c) : dayR(g, c.day) * (0.995 + c.jr * 0.01);
      return { a: a, r: r, x: Math.cos(a) * r, y: Math.sin(a) * r };
    }
    function dotR(c) { return (c.real ? 3.4 + (c.tokens || 200) / 260 : c.kind === 'gate' ? 3.2 : 2.6); }

    // ---- main draw loop ----
    function draw(now) {
      if (!cv.isConnected) { teardown(); return; }   // route change cleared #content
      var dt = Math.min(0.05, (now - lastT) / 1000); lastT = now;
      var time = now / 1000;
      if (spinning && !REDUCED && !resetTween) { rot += dt * 0.02; }
      if (resetTween) {
        var target = rot - (((rot % TAU) + TAU) % TAU);
        if (((rot % TAU) + TAU) % TAU > Math.PI) { target += TAU; }
        rot = mix(rot, target, REDUCED ? 1 : 0.12);
        if (Math.abs(rot - target) < 0.002) { rot = 0; resetTween = false; }
      }
      if (playing) {
        T += dt * (E - S) / 24;
        if (T >= E) { T = E; setPlaying(false); }
        rTime.value = Math.round((T - S) / Math.max(0.5, E - S) * 1000);
        cDate.textContent = dayDate(T);
      }
      if (lens === 'work') { stepLayout(dt); }
      updateRadLo();
      var g = geom();
      ctx.clearRect(0, 0, W, H);
      ctx.save();
      ctx.translate(g.cx + panX, g.cy + panY);
      ctx.scale(Z, Z);
      ctx.rotate(rot);
      if (!solo) {
        for (var i = 1; i <= EPOCH_RINGS; i++) {
          var rr0 = g.r0 + (g.R - g.r0) * (i / EPOCH_RINGS);
          ctx.strokeStyle = 'rgba(255,255,255,.09)'; ctx.lineWidth = 1 / Z;
          ctx.beginPath(); ctx.arc(0, 0, rr0, 0, 7); ctx.stroke();
        }
      }
      ctx.strokeStyle = 'rgba(139,150,242,.6)'; ctx.lineWidth = 1.5 / Z;
      ctx.beginPath();
      ctx.moveTo(Math.cos(-Math.PI / 2) * g.r0 * 0.9, Math.sin(-Math.PI / 2) * g.r0 * 0.9);
      ctx.lineTo(Math.cos(-Math.PI / 2) * (g.R + 10), Math.sin(-Math.PI / 2) * (g.R + 10));
      ctx.stroke();
      lensLabels = [];
      var soloLabels = null;
      if (lens !== 'work') {
        drawLensInFrame(ctx, g, time);
      } else {
        ctx.lineWidth = 1 / Z;
        PLANS.forEach(function (p) {
          if (!p.lay || p.lay.alpha < 0.02) { return; }
          var L = p.lay, al = L.alpha, wSec = L.a1 - L.a0;
          if (wSec * g.R * Z > 8) {
            ctx.strokeStyle = 'rgba(255,255,255,' + 0.06 * al + ')';
            ctx.beginPath(); ctx.moveTo(Math.cos(L.a0) * g.r0, Math.sin(L.a0) * g.r0); ctx.lineTo(Math.cos(L.a0) * g.R, Math.sin(L.a0) * g.R); ctx.stroke();
          }
          var hue = stateHue(p);
          if (p === hoverSec) {
            ctx.strokeStyle = hex2rgba(hue, 0.28 * al); ctx.lineWidth = 10 / Z;
            ctx.beginPath(); ctx.arc(0, 0, g.R - 5 / Z, L.a0, L.a1); ctx.stroke(); ctx.lineWidth = 1 / Z;
          }
          var aPad = Math.min(0.02, wSec * 0.10);
          ctx.strokeStyle = hex2rgba(hue, 0.28 * al); ctx.lineWidth = 1.6 / Z;
          ctx.beginPath(); ctx.arc(0, 0, g.R + 3, L.a0 + aPad, L.a1 - aPad); ctx.stroke();
          ctx.strokeStyle = hex2rgba(hue, 0.8 * al); ctx.lineWidth = 4.5 / Z;
          ctx.beginPath(); ctx.arc(0, 0, g.R + 3, L.a0 + aPad, L.a0 + aPad + Math.max(0.008, (wSec - 2 * aPad) * (p.done / p.total))); ctx.stroke();
          ctx.lineWidth = 1 / Z;
          if (p.od.length) {
            var nT = Math.min(p.od.length, Math.max(1, Math.floor((wSec - 2 * aPad) / 0.02)));
            ctx.strokeStyle = hex2rgba('#f5a623', 0.95 * al); ctx.lineWidth = 1.8 / Z;
            for (var oi = 0; oi < nT; oi++) {
              var oa = L.a0 + aPad + (oi + 0.5) * 0.019;
              ctx.beginPath(); ctx.moveTo(Math.cos(oa) * (g.R + 8), Math.sin(oa) * (g.R + 8)); ctx.lineTo(Math.cos(oa) * (g.R + 13), Math.sin(oa) * (g.R + 13)); ctx.stroke();
            }
            ctx.lineWidth = 1 / Z;
          }
          if (p.st === 2) {
            var pulse = REDUCED ? 0.5 : 0.35 + 0.3 * Math.sin(time * 4);
            ctx.strokeStyle = hex2rgba('#ef4444', pulse * al);
            ctx.beginPath(); ctx.arc(0, 0, g.R + 8, L.a0 + 0.01, L.a1 - 0.01); ctx.stroke();
          }
          var isHovSec = p === hoverSec;
          if ((wSec * g.R * Z > 46 || isHovSec) && solo !== p) {
            var midA = (L.a0 + L.a1) / 2, lr = g.R + 14;
            ctx.save();
            ctx.translate(Math.cos(midA) * lr, Math.sin(midA) * lr);
            ctx.rotate(midA + (Math.cos(midA + rot) < 0 ? Math.PI : 0));
            ctx.fillStyle = isHovSec ? 'rgba(238,240,246,1)' : 'rgba(200,206,219,' + 0.95 * al + ')';
            ctx.font = '700 ' + (12 / Z) + 'px ' + MONO;
            ctx.textAlign = Math.cos(midA + rot) < 0 ? 'right' : 'left'; ctx.textBaseline = 'middle';
            var lbl = isHovSec ? (p.short.length > 34 ? p.short.slice(0, 33) + '…' : p.short) : (p.short.length > 16 ? p.short.slice(0, 15) + '…' : p.short);
            ctx.fillText(lbl + ' ' + p.done + '/' + p.total, 0, 0);
            ctx.restore();
          }
          p.cells.forEach(function (c) {
            if (c.day > T || c.day < S || c.day > E) { return; }
            if (!passFilter(c)) { c._x = undefined; return; }
            var pos = cellPos(g, c);
            if (!pos) { return; }
            var chue = colorByState ? stateHue(c.p) : (KIND_HUE[c.kind] || '#8b96f2');
            var isSel = (hover === c || pinned === c);
            var age = T - c.day;
            var pop = REDUCED ? 1 : Math.min(1, age / 0.8);
            var rr = dotR(c) * (isSel ? 1.7 : 1) * (0.4 + 0.6 * pop);
            if (mode === 'bars') {
              ctx.strokeStyle = hex2rgba(chue, (0.34 + (c.real ? 0.3 : 0)) * al * pop);
              ctx.lineWidth = (isSel ? 3.6 : 2.6) / Math.sqrt(Z);
              ctx.beginPath(); ctx.moveTo(Math.cos(pos.a) * g.r0, Math.sin(pos.a) * g.r0); ctx.lineTo(pos.x, pos.y); ctx.stroke();
            }
            ctx.fillStyle = hex2rgba(chue, (c.real ? 0.92 : 0.55) * al * pop);
            if (c.kind === 'gate' && c.real) {
              ctx.beginPath();
              ctx.moveTo(pos.x, pos.y - rr - 1); ctx.lineTo(pos.x + rr, pos.y); ctx.lineTo(pos.x, pos.y + rr + 1); ctx.lineTo(pos.x - rr, pos.y);
              ctx.closePath(); ctx.fill();
            } else {
              ctx.beginPath(); ctx.arc(pos.x, pos.y, rr, 0, 7); ctx.fill();
            }
            if (c.version > 1) {
              ctx.strokeStyle = hex2rgba(chue, 0.8 * al); ctx.lineWidth = 1 / Z;
              ctx.beginPath(); ctx.arc(pos.x, pos.y, rr + 2.5 / Z, 0, 7); ctx.stroke();
            }
            if (!REDUCED && age < 0.8) {
              ctx.strokeStyle = hex2rgba(chue, (1 - age / 0.8) * 0.8); ctx.lineWidth = 1.5 / Z;
              ctx.beginPath(); ctx.arc(pos.x, pos.y, rr + (age / 0.8) * 14, 0, 7); ctx.stroke();
            }
            if (isSel) {
              ctx.strokeStyle = hex2rgba(chue, 0.95); ctx.lineWidth = 1.5 / Z;
              ctx.beginPath(); ctx.arc(pos.x, pos.y, rr + 4 / Z, 0, 7); ctx.stroke();
            }
            c._x = pos.x; c._y = pos.y; c._a = pos.a; c._r = pos.r; c._dr = rr;
          });
        });
      }
      if (!solo) {
        DEP_EDGES.forEach(function (ed) {
          var lit = hoverSec === ed.a || hoverSec === ed.b;
          if (!showLineage && !lit) { return; }
          if (!ed.a.lay || !ed.b.lay || ed.a.lay.alpha < 0.3 || ed.b.lay.alpha < 0.3) { return; }
          var am = (ed.a.lay.a0 + ed.a.lay.a1) / 2, bm = (ed.b.lay.a0 + ed.b.lay.a1) / 2;
          var r1 = g.R * 0.97;
          var ax = Math.cos(am) * r1, ay = Math.sin(am) * r1, bx = Math.cos(bm) * r1, by = Math.sin(bm) * r1;
          var alpha2 = lit ? 0.65 : 0.10;
          ctx.strokeStyle = hex2rgba('#8b96f2', alpha2); ctx.lineWidth = (lit ? 1.6 : 1.1) / Z;
          ctx.beginPath(); ctx.moveTo(ax, ay); ctx.quadraticCurveTo((ax + bx) / 2 * 0.2, (ay + by) / 2 * 0.2, bx, by); ctx.stroke();
          ctx.fillStyle = hex2rgba('#8b96f2', Math.min(1, alpha2 * 1.6));
          ctx.beginPath(); ctx.arc(bx, by, (lit ? 3 : 2.2) / Z, 0, 7); ctx.fill();
        });
        ctx.lineWidth = 1 / Z;
      }
      if (solo && solo.lay && solo.lay.alpha > 0.5) {
        soloLabels = [];
        var unit = g.R - g.r0, L2 = solo.lay;
        var evs = solo.cells.slice().sort(function (a, b) { return a.day - b.day; }).filter(function (c) { return c.day <= T && c.day >= S && c.day <= E && passFilter(c); });
        ctx.strokeStyle = 'rgba(255,255,255,.16)'; ctx.lineWidth = 1 / Z;
        ctx.beginPath(); ctx.moveTo(-(g.R + 10), 0); ctx.lineTo(-g.r0 * 0.72, 0); ctx.stroke();
        evs.forEach(function (c) {
          var r = soloRingR(g, c);
          var frac = c.n > 1 ? (c.rank + 0.5) / c.n : 0.5;
          var aNode = L2.a0 + (L2.a1 - L2.a0) * (0.06 + 0.88 * frac);
          var chue = KIND_HUE[c.kind] || '#8b96f2';
          var isSelBar = pinned === c;
          ctx.strokeStyle = hex2rgba(chue, 0.07); ctx.lineWidth = 1 / Z;
          ctx.beginPath(); ctx.arc(0, 0, r, L2.a0, aNode); ctx.stroke();
          ctx.strokeStyle = hex2rgba(chue, isSelBar ? 0.75 : 0.30); ctx.lineWidth = (isSelBar ? 2 : 1.3) / Z;
          ctx.beginPath(); ctx.arc(0, 0, r, aNode, Math.PI); ctx.stroke();
          var y1 = 0;
          var segs = [
            { h: unit * (0.06 + Math.min(0.30, ((c.tokens || 160) / 550) * 0.34)), col: hex2rgba('#8b96f2', 0.55) },
            { h: unit * 0.055, col: hex2rgba(chue, 0.95) }
          ];
          if (c.version > 1) { segs.push({ h: unit * 0.022, col: 'rgba(238,240,246,.85)' }); }
          segs.forEach(function (sg) {
            ctx.strokeStyle = sg.col; ctx.lineWidth = (5 / Z) * (isSelBar ? 1.5 : 1);
            ctx.beginPath(); ctx.moveTo(-r, -y1); y1 += sg.h; ctx.lineTo(-r, -y1); ctx.stroke();
          });
          c._bx = -r; c._bh = y1;
        });
        ctx.lineWidth = 1 / Z;
        var picks = evs.length ? [evs[0], evs[Math.floor((evs.length - 1) / 2)], evs[evs.length - 1]] : [];
        var seen = {};
        picks.forEach(function (c) { if (seen[c.rank]) { return; } seen[c.rank] = 1; soloLabels.push({ x: -soloRingR(g, c), y: 16, t: dayDate(c.day) }); });
        soloLabels.push({ x: -(g.r0 + unit * 0.55), y: -(unit * 0.62), t: 'event ledger · outer ring = first event', cap: true });
      }
      {
        var er = dir === 'in' ? g.r0 + (g.R - g.r0) * 0.96 : dayR(g, T);
        if (dir === 'in' || T < E - 0.01) {
          var grow = REDUCED ? 0.86 : (0.55 + 0.45 * ((time * 0.06) % 1));
          ctx.strokeStyle = 'rgba(139,150,242,.7)'; ctx.lineWidth = 1.6 / Z;
          ctx.setLineDash([5 / Z, 7 / Z]);
          ctx.beginPath(); ctx.arc(0, 0, er, -Math.PI / 2, -Math.PI / 2 + TAU * grow); ctx.stroke();
          ctx.setLineDash([]);
        }
      }
      for (var fi = flashes.length - 1; fi >= 0; fi--) {
        var f = flashes[fi];
        var kf = (time - f.t0) / 1.1;
        if (kf > 1) { flashes.splice(fi, 1); continue; }
        if (REDUCED) { continue; }
        var rrf = f.kind === 'exit' ? g.R * (1 + kf * 0.14) : g.R * (1.14 - kf * 0.14);
        ctx.strokeStyle = hex2rgba(f.hue, (1 - kf) * 0.9); ctx.lineWidth = (2.5 * (1 - kf) + 0.5) / Z;
        ctx.beginPath(); ctx.arc(0, 0, rrf, f.ang - 0.3 * (1 - kf * 0.5), f.ang + 0.3 * (1 - kf * 0.5)); ctx.stroke();
      }
      ctx.lineWidth = 1;
      var glow = ctx.createRadialGradient(0, 0, 0, 0, 0, g.r0 * 1.5);
      glow.addColorStop(0, 'rgba(139,150,242,.5)'); glow.addColorStop(1, 'transparent');
      ctx.fillStyle = glow; ctx.beginPath(); ctx.arc(0, 0, g.r0 * 1.5, 0, 7); ctx.fill();
      ctx.fillStyle = '#12151d'; ctx.beginPath(); ctx.arc(0, 0, g.r0 * 0.7, 0, 7); ctx.fill();
      ctx.strokeStyle = 'rgba(139,150,242,.85)'; ctx.lineWidth = 1 / Z;
      ctx.beginPath(); ctx.arc(0, 0, g.r0 * 0.7, 0, 7); ctx.stroke();
      ctx.restore();

      var nAct = activePlans(T).length;
      ctx.fillStyle = 'rgba(238,240,246,.95)'; ctx.font = '600 10.5px ' + MONO;
      ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      var core = toScreen(g, 0, 0);
      ctx.fillText('crux', core.x, core.y - 6);
      ctx.fillStyle = 'rgba(126,133,149,.9)'; ctx.font = '8.5px ' + MONO;
      ctx.fillText(lens === 'work' ? nAct + (showAll ? ' plans' : ' live') : lens, core.x, core.y + 7);
      ctx.textAlign = 'left'; ctx.textBaseline = 'alphabetic';
      ctx.fillStyle = 'rgba(126,133,149,.8)'; ctx.font = '9.5px ' + MONO;
      ctx.fillText(dayDate(S) + ' → ' + dayDate(E) + ' · T = ' + dayDate(T) + ' · ' + nAct + ' live · zoom ' + Z.toFixed(1) + '×'
        + (RAD_LO > S + 0.5 ? ' · rings from ' + dayDate(RAD_LO) : '') + ' · ' + dataSrc, 18, 24);
      if (soloLabels) {
        ctx.font = '9px ' + MONO; ctx.textAlign = 'center';
        soloLabels.forEach(function (L3) {
          var sp = toScreen(g, L3.x, L3.y);
          ctx.fillStyle = L3.cap ? 'rgba(182,188,201,.9)' : 'rgba(126,133,149,.85)';
          ctx.fillText(L3.t, sp.x, sp.y);
        });
        var tip2 = toScreen(g, 0, -(g.R + 24));
        ctx.fillStyle = 'rgba(238,240,246,.92)'; ctx.font = '700 10px ' + MONO;
        ctx.fillText(dayDate(solo.b) + ' → ' + dayDate(solo.e), tip2.x, tip2.y);
        ctx.textAlign = 'left';
      }
      if (lensLabels.length) {
        ctx.font = '9.5px ' + MONO; ctx.textAlign = 'center';
        lensLabels.forEach(function (L4) {
          var sp = toScreen(g, L4.x, L4.y);
          ctx.save();
          if (L4.rot !== undefined) { ctx.translate(sp.x, sp.y); ctx.rotate(L4.rot + rot); ctx.translate(-sp.x, -sp.y); }
          ctx.fillStyle = L4.cap ? 'rgba(182,188,201,.9)' : 'rgba(200,206,219,.95)';
          if (!L4.cap) { ctx.font = '700 11px ' + MONO; }
          ctx.fillText(L4.t, sp.x, sp.y);
          ctx.restore();
          ctx.font = '9.5px ' + MONO;
        });
        ctx.textAlign = 'left';
      }
      ledgerRows = [];
      if (lens === 'work' && showLedger) {
        var doneList = PLANS.filter(function (p) { return p.st === 0 && p.exit <= T && p.b <= E && p.e >= S - 0.001; }).sort(function (a, b) { return b.exit - a.exit; });
        ctx.font = '700 11px ' + MONO; ctx.fillStyle = 'rgba(45,212,191,.9)';
        ctx.fillText('completed · ' + doneList.length + (solo ? '  (filtering — click row again or background to clear)' : ''), 18, 52);
        ctx.font = '9.5px ' + MONO;
        var maxRows = Math.floor((H - 140) / 16);
        doneList.slice(0, maxRows).forEach(function (p, k) {
          var fresh = T - p.exit < 2.0, isSolo = solo === p, y = 70 + k * 16;
          if (isSolo) { ctx.fillStyle = 'rgba(139,150,242,.16)'; ctx.fillRect(12, y - 11, 218, 15); }
          ctx.fillStyle = fresh || isSolo ? 'rgba(45,212,191,.95)' : 'rgba(126,133,149,.75)';
          ctx.fillText('✓', 18, y);
          ctx.fillStyle = isSolo ? 'rgba(238,240,246,1)' : fresh ? 'rgba(238,240,246,.95)' : 'rgba(126,133,149,.8)';
          var lbl = p.short.length > 26 ? p.short.slice(0, 25) + '…' : p.short;
          ctx.fillText(lbl, 32, y);
          ctx.fillStyle = 'rgba(126,133,149,.55)';
          ctx.fillText(dayDate(p.exit).slice(5), 32 + 27 * 6.0, y);
          ledgerRows.push({ x: 12, y: y - 11, w: 218, h: 15, p: p });
        });
        if (doneList.length > maxRows) {
          ctx.fillStyle = 'rgba(126,133,149,.6)';
          ctx.fillText('… +' + (doneList.length - maxRows) + ' more', 18, 70 + maxRows * 16);
        }
      }
      rafId = null;
      if (visible && !doc().hidden && cv.isConnected) { rafId = requestAnimationFrame(draw); }
    }

    // ---- data graph lens ----
    var GNODES = [], GEDGES = [], GADJ = {}, gTotal = null, gCap = false;
    function loadGraph(raws) {
      GNODES.length = 0; GEDGES.length = 0;
      for (var k2 in GADJ) { delete GADJ[k2]; }
      raws.forEach(function (n, i) { var o = {}; for (var kk in n) { o[kk] = n[kk]; } o.i = i; GNODES.push(o); });
      var byE = {};
      GNODES.forEach(function (n) { (byE[n.e] = byE[n.e] || []).push(n); });
      for (var e in byE) {
        var arr = byE[e].sort(function (a, b) { return a.d - b.d; });
        for (var i = 1; i < arr.length; i++) { GEDGES.push({ a: arr[i - 1], b: arr[i] }); }
      }
      GEDGES.forEach(function (ed) { (GADJ[ed.a.i] = GADJ[ed.a.i] || []).push(ed.b.i); (GADJ[ed.b.i] = GADJ[ed.b.i] || []).push(ed.a.i); });
    }
    loadGraph(RINGS_GRAPH_RAW);
    var gSel = null;
    function gHops(i0) {
      var l1 = {}, l2 = {};
      (GADJ[i0] || []).forEach(function (j) { l1[j] = 1; });
      (GADJ[i0] || []).forEach(function (j) { (GADJ[j] || []).forEach(function (k2) { if (k2 !== i0 && !l1[k2]) { l2[k2] = 1; } }); });
      return { l1: l1, l2: l2 };
    }
    var G_FAM_HUE = function (e) {
      return e.indexOf('execplan:') === 0 ? '#a78bfa' : e.indexOf('bench:') === 0 ? '#f5a623' : e.indexOf('incident:') === 0 ? '#ef4444' : e.indexOf('design:') === 0 ? '#22d3ee' : e.indexOf('__work_comment__') === 0 ? '#34d399' : '#7e8595';
    };
    var G_THR = { volatile: 1, medium: 35, stable: 365, none: Infinity };
    function gEffConf(n) {
      var age = Math.max(0, T - n.d), thr = G_THR[n.h] || Infinity;
      if (thr === Infinity) { return n.c; }
      return age > thr ? n.c * 0.5 : n.c * (1 - 0.35 * (age / thr));
    }
    function drawDataLens(ctx2, g) {
      GNODES.forEach(function (n) { n._x = undefined; n._on = false; });
      var span = Math.max(0.5, E - S);
      var rIn = g.r0 * 1.25, rOut = g.R * 0.96;
      var vis = GNODES.filter(function (n) { return n.d <= T && n.d >= S && n.d <= E; });
      var cMin = 1, cMax = 0;
      vis.forEach(function (n) { var ec = gEffConf(n); if (ec < cMin) { cMin = ec; } if (ec > cMax) { cMax = ec; } });
      var cSpan = Math.max(0.02, cMax - cMin);
      var posOf = function (n) {
        var a = BASE + (TAU - SEAM) * Math.max(0, Math.min(1, (n.d - S) / span));
        var norm = (gEffConf(n) - cMin) / cSpan;
        var r = rIn + (rOut - rIn) * (1 - (0.08 + 0.84 * norm));
        return { a: a, x: Math.cos(a) * r, y: Math.sin(a) * r };
      };
      var hops = gSel !== null ? gHops(gSel) : null;
      var inFocus = function (i2) { return gSel === null ? null : (i2 === gSel ? 0 : hops.l1[i2] ? 1 : hops.l2[i2] ? 2 : -1); };
      [0.25, 0.5, 0.75].forEach(function (cf) { ctx2.strokeStyle = 'rgba(255,255,255,.04)'; ctx2.lineWidth = 1 / Z; ctx2.beginPath(); ctx2.arc(0, 0, rIn + (rOut - rIn) * cf, 0, 7); ctx2.stroke(); });
      GEDGES.forEach(function (ed) {
        if (ed.a.d > T || ed.b.d > T || ed.a.d < S || ed.b.d < S) { return; }
        var pa2 = posOf(ed.a), pb2 = posOf(ed.b);
        var alpha = 0.16;
        if (hops) { var fa = inFocus(ed.a.i), fb = inFocus(ed.b.i); alpha = (fa >= 0 && fb >= 0) ? 0.6 : 0.03; }
        ctx2.strokeStyle = hex2rgba(G_FAM_HUE(ed.a.e), alpha); ctx2.lineWidth = 1.1 / Z;
        ctx2.beginPath(); ctx2.moveTo(pa2.x, pa2.y); ctx2.quadraticCurveTo((pa2.x + pb2.x) / 2 * 0.55, (pa2.y + pb2.y) / 2 * 0.55, pb2.x, pb2.y); ctx2.stroke();
      });
      GNODES.forEach(function (n) {
        if (n.d > T || n.d < S || n.d > E) { return; }
        var p2 = posOf(n), hue2 = G_FAM_HUE(n.e), f2 = inFocus(n.i), isH = hover === n;
        var alpha = 0.85;
        if (f2 !== null) { alpha = f2 === -1 ? 0.10 : f2 === 0 ? 1 : f2 === 1 ? 0.95 : 0.6; }
        var rr = (2.2 + Math.min(3, (n.t || 150) / 180)) * (isH || f2 === 0 ? 1.7 : 1);
        ctx2.fillStyle = hex2rgba(hue2, alpha);
        ctx2.beginPath(); ctx2.arc(p2.x, p2.y, rr, 0, 7); ctx2.fill();
        if (f2 === 0) { ctx2.strokeStyle = hex2rgba(hue2, 0.95); ctx2.lineWidth = 1.5 / Z; ctx2.beginPath(); ctx2.arc(p2.x, p2.y, rr + 5 / Z, 0, 7); ctx2.stroke(); }
        if (isH) { ctx2.strokeStyle = hex2rgba(hue2, 0.9); ctx2.beginPath(); ctx2.arc(p2.x, p2.y, rr + 4 / Z, 0, 7); ctx2.stroke(); }
        n._x = p2.x; n._y = p2.y; n._dr = rr; n._on = true;
      });
      lensLabels.push({ x: 0, y: g.R + 42, cap: true,
        t: 'data graph · ' + GNODES.length + (gTotal ? ' of ' + gTotal.toLocaleString() + ' visible facts' + (gCap ? ' (node cap)' : '') : ' live facts') +
          ' · angle = source date · centre = higher confidence (rank-scaled ' + cMin.toFixed(2) + '–' + cMax.toFixed(2) + ') · edge = shared entity · click = 2-hop' });
    }

    // ---- tokens lens ----
    var TOK = null;
    function buildTok() {
      var spent = {}, saved = {};
      PLANS.forEach(function (p) {
        if (!p.cells.length || !p.o) { return; }
        var per = (p.o / 10) / p.cells.length;
        p.cells.forEach(function (c) { var d2 = Math.floor(c.day); spent[d2] = (spent[d2] || 0) + per; });
      });
      cells.forEach(function (c) { var d2 = Math.floor(c.day); saved[d2] = (saved[d2] || 0) + 0.003; });
      var totS = 0, totV = 0;
      for (var d2 in spent) { totS += spent[d2]; }
      for (var d3 in saved) { totV += saved[d3]; }
      return { spent: spent, saved: saved, totS: totS, totV: totV };
    }
    function refreshTok() { TOK = buildTok(); tTok.n.textContent = Math.round(TOK.totS) + 'M'; }
    refreshTok();
    var SNAP_TOK = TOK;
    var tokBins = [], tokView = 'cum', tokSel = null;
    function drawTokensLens(ctx2, g) {
      tokBins = [];
      var cum = tokView === 'cum';
      var rB = g.r0 * 1.7;
      var spanOut = g.R * 0.94 - rB, spanIn = rB - g.r0 * 0.8;
      var d0 = Math.ceil(S), d1 = Math.floor(Math.min(T, E));
      var cs = 0, cv2 = 0, maxS = 0.001, maxV = 0.001, rows = [];
      for (var d2 = d0; d2 <= d1; d2++) { var sp = TOK.spent[d2] || 0, sv = TOK.saved[d2] || 0; cs += sp; cv2 += sv; rows.push({ d: d2, sp: sp, sv: sv, cs: cs, cv: cv2 }); }
      rows.forEach(function (r2) { maxS = Math.max(maxS, cum ? r2.cs : r2.sp); maxV = Math.max(maxV, cum ? r2.cv : r2.sv); });
      ctx2.strokeStyle = 'rgba(255,255,255,.12)'; ctx2.lineWidth = 1 / Z;
      ctx2.beginPath(); ctx2.arc(0, 0, rB, BASE, BASE + TAU - SEAM); ctx2.stroke();
      var wA = (TAU - SEAM) / Math.max(1, (Math.floor(E) - Math.ceil(S) + 1));
      rows.forEach(function (r2) {
        var a = BASE + (TAU - SEAM) * ((r2.d + 0.5 - S) / Math.max(0.5, E - S));
        var hS = ((cum ? r2.cs : r2.sp) / maxS) * spanOut;
        var wBar = Math.max(1.5, wA * rB * 0.55) / Math.max(1, Math.sqrt(Z));
        var isSelDay = tokSel === r2.d;
        if (cum) {
          var hV = ((r2.cv) / maxV) * spanIn;
          ctx2.lineWidth = wBar;
          ctx2.strokeStyle = hex2rgba('#a78bfa', 0.55);
          ctx2.beginPath(); ctx2.moveTo(Math.cos(a) * rB, Math.sin(a) * rB); ctx2.lineTo(Math.cos(a) * (rB + hS), Math.sin(a) * (rB + hS)); ctx2.stroke();
          ctx2.strokeStyle = hex2rgba('#34d399', 0.6);
          ctx2.beginPath(); ctx2.moveTo(Math.cos(a) * rB, Math.sin(a) * rB); ctx2.lineTo(Math.cos(a) * (rB - hV), Math.sin(a) * (rB - hV)); ctx2.stroke();
        } else {
          var hV2 = ((r2.sv) / maxV) * spanOut * 0.85;
          ctx2.lineWidth = wBar;
          ctx2.strokeStyle = hex2rgba('#a78bfa', isSelDay ? 0.9 : 0.5);
          ctx2.beginPath(); ctx2.moveTo(Math.cos(a) * rB, Math.sin(a) * rB); ctx2.lineTo(Math.cos(a) * (rB + hS), Math.sin(a) * (rB + hS)); ctx2.stroke();
          ctx2.lineWidth = Math.max(1.2, wBar * 0.38);
          ctx2.strokeStyle = hex2rgba('#34d399', isSelDay ? 1 : 0.8);
          ctx2.beginPath(); ctx2.moveTo(Math.cos(a) * rB, Math.sin(a) * rB); ctx2.lineTo(Math.cos(a) * (rB + hV2), Math.sin(a) * (rB + hV2)); ctx2.stroke();
          ctx2.lineWidth = 1 / Z;
          ctx2.fillStyle = hex2rgba('#a78bfa', isSelDay ? 1 : 0.85);
          ctx2.beginPath(); ctx2.arc(Math.cos(a) * (rB + hS), Math.sin(a) * (rB + hS), (isSelDay ? 3.4 : 2.4) / Math.sqrt(Z), 0, 7); ctx2.fill();
          ctx2.fillStyle = hex2rgba('#34d399', isSelDay ? 1 : 0.85);
          ctx2.beginPath(); ctx2.arc(Math.cos(a) * (rB + hV2), Math.sin(a) * (rB + hV2), (isSelDay ? 2.8 : 2) / Math.sqrt(Z), 0, 7); ctx2.fill();
          if (isSelDay) { ctx2.strokeStyle = 'rgba(238,240,246,.5)'; ctx2.beginPath(); ctx2.arc(0, 0, rB, a - 0.02, a + 0.02); ctx2.stroke(); }
        }
        tokBins.push({ d: r2.d, sp: r2.sp, sv: r2.sv, cs: r2.cs, cv: r2.cv, a: a, rTip: rB + hS });
      });
      ctx2.lineWidth = 1 / Z;
      var pct = TOK.totS > 0 ? Math.round(100 * TOK.totV / TOK.totS) : 0;
      var nDays = Math.max(1, rows.length);
      lensLabels.push({ x: 0, y: g.R + 42, cap: true,
        t: cum
          ? 'tokens · cumulative · outward = spent ' + Math.round(TOK.totS) + 'M · inward = est. saved ' + TOK.totV.toFixed(1) + 'M (~' + pct + '%, from 12-token fact recalls vs ~3k replays)'
          : 'tokens · per day · avg ' + (cs / nDays).toFixed(1) + 'M/day spent · peak ' + maxS.toFixed(1) + 'M · est. saved avg ' + (cv2 / nDays * 1000).toFixed(0) + 'k/day' });
    }

    function drawLensInFrame(ctx2, g, time) {
      cells.forEach(function (c) { c._x = undefined; c._on = false; c._bx = undefined; });
      if (lens === 'data') { drawDataLens(ctx2, g); return; }
      if (lens === 'tokens') { drawTokensLens(ctx2, g); return; }
      if (lens === 'receipts') { drawReceiptsLens(ctx2, g, time); return; }
      var groups = lens === 'memory'
        ? [['gate', '#2dd4bf'], ['decision', '#a78bfa'], ['memory', '#8b96f2'], ['handoff', '#f5a623'], ['incident', '#ef4444']]
        : [['claude-work', '#8b96f2'], ['codex-work', '#22d3ee'], ['untraced', '#7e8595']];
      var keyOf = function (c) { return lens === 'memory' ? c.kind : (c.actor || 'untraced'); };
      var N2 = groups.length;
      groups.forEach(function (grp, gi) {
        var k2 = grp[0], hue2 = grp[1];
        var a0 = BASE + (gi / N2) * (TAU - SEAM), a1 = BASE + ((gi + 1) / N2) * (TAU - SEAM);
        ctx2.strokeStyle = 'rgba(255,255,255,.06)'; ctx2.lineWidth = 1 / Z;
        ctx2.beginPath(); ctx2.moveTo(Math.cos(a0) * g.r0, Math.sin(a0) * g.r0); ctx2.lineTo(Math.cos(a0) * g.R, Math.sin(a0) * g.R); ctx2.stroke();
        var members = cells.filter(function (c) { return keyOf(c) === k2 && c.day <= T && c.day >= S && c.day <= E && passFilter(c); });
        ctx2.strokeStyle = hex2rgba(hue2, 0.5); ctx2.lineWidth = 3 / Z;
        ctx2.beginPath(); ctx2.arc(0, 0, g.R + 3, a0 + 0.02, a1 - 0.02); ctx2.stroke();
        ctx2.lineWidth = 1 / Z;
        var mid = (a0 + a1) / 2;
        lensLabels.push({ x: Math.cos(mid) * (g.R + 20), y: Math.sin(mid) * (g.R + 20), t: k2 + ' · ' + members.length });
        members.forEach(function (c) {
          var a = a0 + (a1 - a0) * (0.08 + c.ja * 0.84);
          var r = dayR(g, c.day) * (0.995 + c.jr * 0.01);
          var x = Math.cos(a) * r, y = Math.sin(a) * r, isH = hover === c;
          var alpha = c.real ? 0.9 : 0.45;
          if (lens === 'memory') { var ageFrac = Math.max(0, Math.min(1, (T - c.day) / Math.max(0.5, E - S))); alpha *= 1 - 0.5 * ageFrac; }
          var rr = (c.real ? 3.2 : 2.4) * (isH ? 1.8 : 1);
          ctx2.fillStyle = hex2rgba(hue2, alpha * (hover && !isH ? 0.5 : 1));
          if (c.kind === 'gate' && c.real) {
            ctx2.beginPath(); ctx2.moveTo(x, y - rr - 1); ctx2.lineTo(x + rr, y); ctx2.lineTo(x, y + rr + 1); ctx2.lineTo(x - rr, y); ctx2.closePath(); ctx2.fill();
          } else { ctx2.beginPath(); ctx2.arc(x, y, rr, 0, 7); ctx2.fill(); }
          if (isH) { ctx2.strokeStyle = hex2rgba(hue2, 0.95); ctx2.beginPath(); ctx2.arc(x, y, rr + 4 / Z, 0, 7); ctx2.stroke(); }
          c._x = x; c._y = y; c._dr = rr; c._on = true;
        });
      });
      lensLabels.push({ x: 0, y: g.R + 42, cap: true,
        t: lens === 'memory' ? 'memory lens · sector = fact kind · ring = day · fade = age (decay illustrative)' : 'sessions lens · sector = agent passport · ring = day · untraced plans have no actor' });
    }
    function drawReceiptsLens(ctx2, g, time) {
      var teeth = 120;
      var sealedFrac = Math.max(0, Math.min(1, (T - S) / Math.max(0.5, E - S)));
      for (var i = 0; i < teeth; i++) {
        var a = BASE + (i / teeth) * (TAU - SEAM);
        var sealed = i / teeth <= sealedFrac;
        ctx2.strokeStyle = sealed ? 'rgba(52,211,153,.8)' : 'rgba(255,255,255,.10)'; ctx2.lineWidth = (sealed ? 1.8 : 1) / Z;
        ctx2.beginPath(); ctx2.moveTo(Math.cos(a) * g.R, Math.sin(a) * g.R); ctx2.lineTo(Math.cos(a) * (g.R + (sealed ? 9 : 6)), Math.sin(a) * (g.R + (sealed ? 9 : 6))); ctx2.stroke();
      }
      ctx2.lineWidth = 1 / Z;
      var n = Math.floor(90 * sealedFrac) + 8;
      for (var j = 0; j < n; j++) {
        var a2 = j * 2.399963;
        var r = g.r0 + (g.R - g.r0) * (0.12 + (j / 98) * 0.78);
        ctx2.fillStyle = hex2rgba('#34d399', 0.25 + (j / n) * 0.5);
        ctx2.beginPath(); ctx2.arc(Math.cos(a2) * r, Math.sin(a2) * r, 1.8, 0, 7); ctx2.fill();
      }
      lensLabels.push({ x: 0, y: g.R + 42, cap: true, t: 'receipts lens · chain ticks forward only · illustrative until /v1/receipts/export is wired' });
    }

    function kick() { if (rafId === null && cv.isConnected) { rafId = requestAnimationFrame(draw); } }

    // ---- controls ----
    function setPlaying(v) {
      playing = v;
      bPlay.textContent = v ? '⏸' : '▶';
      bPlay.setAttribute('aria-pressed', String(v));
      if (v && !showCompleted) { setCompleted(true); }
      if (v && !showLedger) { setLedger(true); }
    }
    function setLedger(v) { showLedger = v; bLedger.setAttribute('aria-pressed', String(v)); }
    function setCompleted(v) { showCompleted = v; bDone.setAttribute('aria-pressed', String(v)); }
    bPlay.addEventListener('click', function () { if (!playing && T >= E - 0.01) { T = S; } setPlaying(!playing); });
    bSpin.addEventListener('click', function () { spinning = !spinning; bSpin.setAttribute('aria-pressed', String(spinning)); });
    bDone.addEventListener('click', function () { setCompleted(!showCompleted); });
    bLedger.addEventListener('click', function () { setLedger(!showLedger); });
    bClock.addEventListener('click', function () { resetTween = true; spinning = false; bSpin.setAttribute('aria-pressed', 'false'); });
    bMode.addEventListener('click', function () { mode = mode === 'dots' ? 'bars' : 'dots'; bMode.setAttribute('aria-pressed', String(mode === 'bars')); });
    bDir.addEventListener('click', function () { dir = dir === 'out' ? 'in' : 'out'; bDir.textContent = dir === 'out' ? 'edge: outward' : 'edge: inward'; bDir.setAttribute('aria-pressed', String(dir === 'in')); });
    bAll.addEventListener('click', function () { showAll = !showAll; bAll.setAttribute('aria-pressed', String(showAll)); });
    bState.addEventListener('click', function () { colorByState = !colorByState; bState.setAttribute('aria-pressed', String(colorByState)); });
    bLin.addEventListener('click', function () { showLineage = !showLineage; bLin.setAttribute('aria-pressed', String(showLineage)); });
    sKind.addEventListener('change', function (e) { fKind = e.target.value; });
    sAgent.addEventListener('change', function (e) { fAgent = e.target.value; });
    function syncWindow() {
      var s = Math.min(rStart.value / 1000, rEnd.value / 1000 - 0.03);
      var e = Math.max(rEnd.value / 1000, rStart.value / 1000 + 0.03);
      S = 11 + s * (NOW - 11); E = 11 + e * (NOW - 11); T = Math.max(S, Math.min(E, T));
      rTime.value = Math.round((T - S) / Math.max(0.5, E - S) * 1000);
      cDate.textContent = dayDate(T); dStart.value = dayDate(S); dEnd.value = dayDate(E);
    }
    rStart.addEventListener('input', syncWindow);
    rEnd.addEventListener('input', syncWindow);
    function dateToDay(v) { return Date.parse(v + 'T00:00:00Z') / 86400000 - 20580; }
    dStart.addEventListener('change', function () { var d = Math.max(11, Math.min(NOW - 1, dateToDay(dStart.value))); rStart.value = Math.round((d - 11) / (NOW - 11) * 1000); syncWindow(); });
    dEnd.addEventListener('change', function () { var d = Math.max(12, Math.min(NOW, dateToDay(dEnd.value))); rEnd.value = Math.round((d - 11) / (NOW - 11) * 1000); syncWindow(); });
    rTime.addEventListener('input', function () { T = S + (rTime.value / 1000) * (E - S); setPlaying(false); cDate.textContent = dayDate(T); });
    function zoomAt(sx, sy, factor) { var g = geom(); var before = toDisc(g, sx, sy); Z = Math.max(0.6, Math.min(7, Z * factor)); var after = toScreen(g, before.x, before.y); panX += sx - after.x; panY += sy - after.y; }
    cv.addEventListener('wheel', function (e) { e.preventDefault(); var r = cv.getBoundingClientRect(); zoomAt(e.clientX - r.left, e.clientY - r.top, e.deltaY < 0 ? 1.15 : 1 / 1.15); }, { passive: false });
    bZin.addEventListener('click', function () { zoomAt(W / 2, H / 2, 1.35); });
    bZout.addEventListener('click', function () { zoomAt(W / 2, H / 2, 1 / 1.35); });
    bZfit.addEventListener('click', function () { Z = 1; panX = panY = 0; });
    cv.addEventListener('pointerdown', function (e) { dragging = true; dragMoved = 0; lastPX = e.clientX; lastPY = e.clientY; cv.setPointerCapture(e.pointerId); });
    cv.addEventListener('pointerup', function (e) { dragging = false; if (dragMoved < 5) { handleClick(e); } });
    cv.addEventListener('pointermove', function (e) {
      mxAbs = e.clientX; myAbs = e.clientY;
      if (dragging) {
        var dx = e.clientX - lastPX, dy = e.clientY - lastPY;
        dragMoved += Math.abs(dx) + Math.abs(dy);
        if (dragMoved > 5) { panX += dx; panY += dy; }
        lastPX = e.clientX; lastPY = e.clientY; return;
      }
      if (lens === 'tokens') {
        var g2 = geom();
        var pd = toDisc(g2, e.clientX - cv.getBoundingClientRect().left, e.clientY - cv.getBoundingClientRect().top);
        var pr2 = Math.hypot(pd.x, pd.y);
        var pa2 = Math.atan2(pd.y, pd.x); while (pa2 < BASE) { pa2 += TAU; }
        var bin = null, bd2 = 0.05;
        tokBins.forEach(function (b2) { var ba = b2.a; while (ba < BASE) { ba += TAU; } var da2 = Math.abs(pa2 - ba); if (da2 < bd2 && pr2 > g2.r0 * 0.7 && pr2 < g2.R) { bd2 = da2; bin = b2; } });
        if (bin) {
          showTip(e.clientX, e.clientY, [tb(dayDate(bin.d)), br(), tk('spent'), ' ' + bin.sp.toFixed(1) + 'M ', tk('day'), ' · ' + bin.cs.toFixed(1) + 'M ', tk('cum'), br(), tk('saved'), ' ' + bin.sv.toFixed(2) + 'M ', tk('day'), ' · ' + bin.cv.toFixed(2) + 'M ', tk('cum (est.)')]);
        } else { hideTip(); }
        hover = null; hoverSec = null; return;
      }
      hover = hitTest(e);
      hoverSec = hover && hover.p ? hover.p : sectorAt(e);
      if (hover && lens === 'data') {
        var n = hover;
        showTip(mxAbs, myAbs, [tb(n.k), br(), tk('entity'), ' ' + (n.e.length > 40 ? n.e.slice(0, 39) + '…' : n.e), br(), tk('source'), ' ' + dayDate(n.d) + (n.a ? '' : ''), (n.a ? tk('by') : null), (n.a ? ' ' + n.a : null), br(), tk('confidence'), ' ' + gEffConf(n).toFixed(2) + ' ', tk('(' + (n.h || 'none') + ')'), ' · ', tk('links'), ' ' + ((GADJ[n.i] || []).length)]);
        return;
      }
      if (hover) {
        var c = hover;
        if (c.real) {
          showTip(mxAbs, myAbs, [tb(c.key), (c.version > 1 ? ' ' : null), (c.version > 1 ? tk('v' + c.version) : null), br(), tk('plan'), ' ' + c.p.short, br(), tk('stored'), ' ' + dayDate(c.day) + ' ', tk('by'), ' ' + c.actor, br(), tk('kind'), ' ' + c.kind + ' · ', tk('horizon'), ' ' + c.horizon]);
        } else {
          showTip(mxAbs, myAbs, [tb(c.p.short), br(), tk(STATE[c.p.st] + ' · ' + c.p.done + '/' + c.p.total + ' · born ' + dayDate(c.p.b)), br(), tk(c.kind === 'gate' ? c.key : 'untraced density — one query_facts call away')]);
        }
      } else if (hoverSec) {
        var p = hoverSec;
        var nDepIn = DEP_EDGES.filter(function (ed) { return ed.b === p; }).length;
        var parts = [tb(p.short), br(), tk(STATE[p.st] + ' · ' + p.done + '/' + p.total), br(), tk('born'), ' ' + dayDate(p.b) + ' ', tk('· last'), ' ' + dayDate(p.e)];
        if (p.o) { parts.push(br(), tk('output'), ' ' + (p.o / 10).toFixed(1) + 'M tok'); }
        if (p.od.length) { parts.push(br(), tk('open decisions'), ' ' + p.od.join(' ')); }
        if (p.dep.length || nDepIn) { parts.push(br(), tk('lineage'), ' depends on ' + p.dep.length + ' · depended on by ' + nDepIn); }
        showTip(mxAbs, myAbs, parts);
      } else { hideTip(); }
    });
    function sectorAt(e) {
      if (lens !== 'work') { return null; }
      var r = cv.getBoundingClientRect(), g = geom();
      var p = toDisc(g, e.clientX - r.left, e.clientY - r.top);
      var pr = Math.hypot(p.x, p.y);
      if (pr < g.r0 * 0.85 || pr > g.R + 30) { return null; }
      var pa = Math.atan2(p.y, p.x);
      for (var i = 0; i < PLANS.length; i++) {
        var pl = PLANS[i];
        if (!pl.lay || pl.lay.alpha < 0.4) { continue; }
        var da = pa - pl.lay.a0; while (da < 0) { da += TAU; } while (da >= TAU) { da -= TAU; }
        if (da <= pl.lay.a1 - pl.lay.a0) { return pl; }
      }
      return null;
    }
    cv.addEventListener('pointerleave', function () { hover = null; hoverSec = null; hideTip(); });
    function hitTest(e) {
      var r = cv.getBoundingClientRect(), g = geom();
      var p = toDisc(g, e.clientX - r.left, e.clientY - r.top);
      var pr = Math.hypot(p.x, p.y), pa = Math.atan2(p.y, p.x);
      if (lens === 'data') {
        var best2 = null, bd2 = 9 / Z;
        GNODES.forEach(function (n) { if (!n._on || n._x === undefined) { return; } var d2 = Math.hypot(n._x - p.x, n._y - p.y); if (d2 < bd2 + n._dr) { bd2 = d2; best2 = n; } });
        return best2;
      }
      if (solo) {
        for (var si = 0; si < solo.cells.length; si++) {
          var c0 = solo.cells[si];
          if (c0._bx === undefined || c0.day > T) { continue; }
          if (Math.abs(p.x - c0._bx) < 6 / Z && p.y < 5 / Z && p.y > -(c0._bh + 9 / Z)) { return c0; }
        }
      }
      var best = null, bd = 10 / Z;
      for (var ci = 0; ci < cells.length; ci++) {
        var c = cells[ci];
        if (c._x === undefined || c.day > T || !c.p.lay || c.p.lay.alpha < 0.3 || !passFilter(c)) { continue; }
        var d = Math.hypot(c._x - p.x, c._y - p.y);
        if (d < bd + c._dr) { bd = d; best = c; }
        if (mode === 'bars' && !best) {
          var da = pa - c._a; while (da > Math.PI) { da -= TAU; } while (da < -Math.PI) { da += TAU; }
          if (Math.abs(da) * pr < 4 / Z && pr > g.r0 - 2 && pr < c._r + c._dr) { best = c; }
        }
      }
      return best;
    }
    function handleClick(e) {
      if (lens === 'data') { var hit0 = hitTest(e); gSel = (hit0 && hit0.i !== undefined) ? (gSel === hit0.i ? null : hit0.i) : null; return; }
      if (lens === 'tokens') {
        var r2 = cv.getBoundingClientRect(), g2 = geom();
        var pd = toDisc(g2, e.clientX - r2.left, e.clientY - r2.top);
        var pr2 = Math.hypot(pd.x, pd.y);
        var pa2 = Math.atan2(pd.y, pd.x); while (pa2 < BASE) { pa2 += TAU; }
        var bin = null, bd2 = 0.05;
        tokBins.forEach(function (b2) { var ba = b2.a; while (ba < BASE) { ba += TAU; } var da2 = Math.abs(pa2 - ba); if (da2 < bd2 && pr2 > g2.r0 * 0.7 && pr2 < g2.R + 14) { bd2 = da2; bin = b2; } });
        if (bin && tokSel !== bin.d) { tokSel = bin.d; renderTokenDayPane(bin); } else { tokSel = null; pane.classList.remove('open'); }
        return;
      }
      if (lens !== 'work') { return; }
      var r = cv.getBoundingClientRect();
      var cxp = e.clientX - r.left, cyp = e.clientY - r.top;
      for (var li = 0; li < ledgerRows.length; li++) {
        var row = ledgerRows[li];
        if (cxp >= row.x && cxp <= row.x + row.w && cyp >= row.y && cyp <= row.y + row.h) {
          if (solo === row.p) { setSel(null); solo = null; } else { solo = row.p; setSel({ type: 'plan', p: row.p }); }
          return;
        }
      }
      var hit = hitTest(e);
      if (hit) { setSel(sel && sel.c === hit ? null : { type: 'cell', c: hit }); return; }
      var sec = sectorAt(e);
      if (sec) { if (solo === sec) { setSel(null); solo = null; } else { solo = sec; setSel({ type: 'plan', p: sec }); } return; }
      if (solo) {
        var g3 = geom();
        var pd2 = toDisc(g3, cxp, cyp);
        var pr3 = Math.hypot(pd2.x, pd2.y);
        var pa3 = Math.atan2(pd2.y, pd2.x); if (pa3 < 0) { pa3 += TAU; }
        if (pr3 > g3.r0 && pr3 < g3.R + 12 && pa3 > Math.PI && pa3 < Math.PI * 1.5) { return; }
      }
      setSel(null); solo = null;
    }
    function setSel(s) { sel = s; pinned = s && s.type === 'cell' ? s.c : null; renderPane(); }

    // ---- detail pane (DOM builders; no innerHTML) ----
    function pRow(k, v) {
      var val = el('span', {});
      if (Array.isArray(v)) { v.forEach(function (x) { val.appendChild(typeof x === 'string' ? doc().createTextNode(x) : x); }); }
      else { val.textContent = String(v); }
      return el('div', { 'class': 'row' }, [el('span', { text: k }), val]);
    }
    function pSect(t) { return el('div', { 'class': 'sect', text: t }); }
    function joinBr(arr) { var out = []; arr.forEach(function (s, i) { if (i) { out.push(el('br')); } out.push(s); }); return out; }
    function tokChart(p) {
      var evs = p.cells.slice().sort(function (a, b) { return a.day - b.day; });
      if (!evs.length) { return null; }
      var W2 = 288, H2 = 92, padT = 10, padB = 20, padX = 2;
      var b = p.b, e = Math.max(p.e, b + 0.5);
      var tot = evs.reduce(function (a, c) { return a + c.tokW; }, 0) || 1;
      var hue = stateHue(p);
      var X2 = function (d) { return padX + Math.max(0, Math.min(1, (d - b) / (e - b))) * (W2 - 2 * padX); };
      var Y2 = function (f) { return (H2 - padB) - f * (H2 - padB - padT); };
      var cum = 0, pts = evs.map(function (c) { cum += c.tokW; return { x: X2(c.day), y: Y2(cum / tot), c: c }; });
      var line = 'M' + padX + ',' + Y2(0) + pts.map(function (pt) { return 'L' + pt.x.toFixed(1) + ',' + pt.y.toFixed(1); }).join('') + 'L' + (W2 - padX) + ',' + pts[pts.length - 1].y.toFixed(1);
      var area = line + 'L' + (W2 - padX) + ',' + Y2(0) + 'Z';
      var gid = 'rtg' + p.i;
      var wrap = el('div', {});
      wrap.appendChild(pSect('TOKEN USAGE' + (p.o ? ' · ' + (p.o / 10).toFixed(1) + 'M out' : '')));
      var svg = svgEl('svg', { width: '100%', viewBox: '0 0 ' + W2 + ' ' + H2, style: 'display:block;margin-top:6px', role: 'img', 'aria-label': "Cumulative token usage over the plan's life" });
      var defs = svgEl('defs');
      var grad = svgEl('linearGradient', { id: gid, x1: '0', y1: '0', x2: '0', y2: '1' });
      grad.appendChild(svgEl('stop', { offset: '0', 'stop-color': hue, 'stop-opacity': '.38' }));
      grad.appendChild(svgEl('stop', { offset: '1', 'stop-color': hue, 'stop-opacity': '0' }));
      defs.appendChild(grad); svg.appendChild(defs);
      svg.appendChild(svgEl('path', { d: area, fill: 'url(#' + gid + ')' }));
      svg.appendChild(svgEl('path', { d: line, fill: 'none', stroke: hue, 'stroke-opacity': '.85', 'stroke-width': '1.4' }));
      pts.forEach(function (pt) { svg.appendChild(svgEl('circle', { cx: pt.x.toFixed(1), cy: pt.y.toFixed(1), r: (pt.c.kind === 'gate' ? 3 : 2.2), fill: (KIND_HUE[pt.c.kind] || '#8b96f2') })); });
      svg.appendChild(svgEl('text', { x: padX, y: (H2 - 5), fill: 'rgba(126,133,149,.8)', 'font-size': '9', 'font-family': 'monospace' }));
      svg.lastChild.textContent = dayDate(b);
      svg.appendChild(svgEl('text', { x: (W2 - padX), y: (H2 - 5), 'text-anchor': 'end', fill: 'rgba(126,133,149,.8)', 'font-size': '9', 'font-family': 'monospace' }));
      svg.lastChild.textContent = dayDate(p.e);
      wrap.appendChild(svg);
      return wrap;
    }
    function planBlock(p) {
      var hue = stateHue(p);
      var nCells = p.cells.length, gates = p.cells.filter(function (c) { return c.kind === 'gate'; }).length;
      var frag = doc().createDocumentFragment();
      frag.appendChild(pSect('EXECPLAN'));
      frag.appendChild(el('h4', { text: p.slug }));
      var bar = el('div', { 'class': 'bar' }); var bi = el('i'); bi.style.width = Math.round(100 * p.done / p.total) + '%'; bi.style.background = hue; bar.appendChild(bi); frag.appendChild(bar);
      frag.appendChild(pRow('state', STATE[p.st] + ' · ' + p.done + '/' + p.total));
      frag.appendChild(pRow('born', dayDate(p.b)));
      frag.appendChild(pRow('last activity', dayDate(p.e)));
      if (p.o) { frag.appendChild(pRow('output tokens', (p.o / 10).toFixed(1) + 'M')); }
      frag.appendChild(pRow('nodes', nCells + ' (' + gates + ' gates)'));
      if (p.od.length) { frag.appendChild(pRow('open decisions', p.od.join(' · '))); }
      if (p.dep.length) { frag.appendChild(pRow('depends on', joinBr(p.dep.map(function (d) { return doc().createTextNode(d.replace(/-2026-\d\d-\d\d$/, '')); })))); }
      if (p.ext.length) { frag.appendChild(pRow('extended by', joinBr(p.ext.map(function (d) { return doc().createTextNode(d.replace(/-2026-\d\d-\d\d$/, '')); })))); }
      var tc = tokChart(p); if (tc) { frag.appendChild(tc); }
      if (p.traced) {
        frag.appendChild(pSect('FACTS (real)'));
        var ul = el('ul', { 'class': 'facts' });
        p.cells.slice().sort(function (a, b) { return a.day - b.day; }).forEach(function (c) {
          var li = el('li', (sel && sel.c === c) ? { 'class': 'sel' } : {}, [el('b', { text: c.key }), ' · ' + dayDate(c.day) + (c.actor ? ' · ' + c.actor : '')]);
          ul.appendChild(li);
        });
        frag.appendChild(ul);
      } else {
        var note2 = el('p', { 'class': 'note' }, ['Untraced plan — node density is milestone-derived. One call makes it real:', el('br'), el('code', { text: 'query_facts(entity="execplan:' + p.slug + '", token_budget=4000)' })]);
        frag.appendChild(note2);
      }
      return frag;
    }
    function renderPane() {
      if (!sel) { pane.classList.remove('open'); return; }
      pane.textContent = '';
      if (sel.type === 'cell') {
        var c = sel.c, hue = KIND_HUE[c.kind] || '#8b96f2';
        var h4 = el('h4', { text: c.key });
        if (c.version > 1) { var vspan = el('span', { text: ' v' + c.version }); vspan.style.color = 'var(--rings-ink3)'; h4.appendChild(vspan); }
        pane.appendChild(h4);
        pane.appendChild(el('span', { 'class': 'kindchip' }, [el('i', { style: 'background:' + hue }), c.kind + (c.real ? ' · real fact' : ' · illustrative')]));
        if (c.real) {
          pane.appendChild(pRow('stored', dayDate(c.day)));
          pane.appendChild(pRow('actor', c.actor));
          pane.appendChild(pRow('horizon', c.horizon));
          pane.appendChild(pRow('tokens', c.tokens));
          if (c.version > 1) { pane.appendChild(pRow('supersedes', 'v' + (c.version - 1) + ' of same key')); }
        } else {
          pane.appendChild(pRow('day', dayDate(c.day)));
        }
        pane.appendChild(planBlock(c.p));
      } else {
        pane.appendChild(planBlock(sel.p));
        if (solo === sel.p) { pane.appendChild(el('p', { 'class': 'note', text: 'Ring filtered to this plan — click the background to clear.' })); }
      }
      pane.classList.add('open');
    }
    function tokPaneChart(selDay) {
      var W2 = 288, H2 = 92, padT = 10, padB = 20, padX = 2;
      var d0 = Math.ceil(S), d1 = Math.floor(E);
      var days = [], mS = 0.001, mV = 0.001;
      for (var d3 = d0; d3 <= d1; d3++) { var sp = TOK.spent[d3] || 0, sv = TOK.saved[d3] || 0; days.push({ d: d3, sp: sp, sv: sv }); mS = Math.max(mS, sp); mV = Math.max(mV, sv); }
      if (!days.length) { return null; }
      var X2 = function (d3) { return padX + ((d3 - d0) / Math.max(1, d1 - d0)) * (W2 - 2 * padX); };
      var YS = function (v) { return (H2 - padB) - (v / mS) * (H2 - padB - padT); };
      var YV = function (v) { return (H2 - padB) - (v / mV) * (H2 - padB - padT); };
      var lineS = days.map(function (r2, i2) { return (i2 ? 'L' : 'M') + X2(r2.d).toFixed(1) + ',' + YS(r2.sp).toFixed(1); }).join('');
      var areaS = lineS + 'L' + X2(d1).toFixed(1) + ',' + (H2 - padB) + 'L' + X2(d0).toFixed(1) + ',' + (H2 - padB) + 'Z';
      var lineV = days.map(function (r2, i2) { return (i2 ? 'L' : 'M') + X2(r2.d).toFixed(1) + ',' + YV(r2.sv).toFixed(1); }).join('');
      var selX = X2(selDay).toFixed(1);
      var selRow = days.filter(function (r2) { return r2.d === selDay; })[0];
      var wrap = doc().createDocumentFragment();
      var svg = svgEl('svg', { width: '100%', viewBox: '0 0 ' + W2 + ' ' + H2, style: 'display:block;margin:10px 0 2px', role: 'img', 'aria-label': 'Daily token spend with the selected day marked' });
      var defs = svgEl('defs');
      var grad = svgEl('linearGradient', { id: 'rtp', x1: '0', y1: '0', x2: '0', y2: '1' });
      grad.appendChild(svgEl('stop', { offset: '0', 'stop-color': '#a78bfa', 'stop-opacity': '.4' }));
      grad.appendChild(svgEl('stop', { offset: '1', 'stop-color': '#a78bfa', 'stop-opacity': '0' }));
      defs.appendChild(grad); svg.appendChild(defs);
      svg.appendChild(svgEl('path', { d: areaS, fill: 'url(#rtp)' }));
      svg.appendChild(svgEl('path', { d: lineS, fill: 'none', stroke: '#a78bfa', 'stroke-opacity': '.9', 'stroke-width': '1.4' }));
      svg.appendChild(svgEl('path', { d: lineV, fill: 'none', stroke: '#34d399', 'stroke-opacity': '.8', 'stroke-width': '1.1' }));
      svg.appendChild(svgEl('line', { x1: selX, y1: padT, x2: selX, y2: (H2 - padB), stroke: 'rgba(238,240,246,.5)', 'stroke-dasharray': '2 3' }));
      if (selRow) {
        svg.appendChild(svgEl('circle', { cx: selX, cy: YS(selRow.sp).toFixed(1), r: '3.2', fill: '#a78bfa' }));
        svg.appendChild(svgEl('circle', { cx: selX, cy: YV(selRow.sv).toFixed(1), r: '2.4', fill: '#34d399' }));
      }
      var tx0 = svgEl('text', { x: padX, y: (H2 - 5), fill: 'rgba(126,133,149,.8)', 'font-size': '9', 'font-family': 'monospace' }); tx0.textContent = dayDate(d0); svg.appendChild(tx0);
      var tx1 = svgEl('text', { x: (W2 - padX), y: (H2 - 5), 'text-anchor': 'end', fill: 'rgba(126,133,149,.8)', 'font-size': '9', 'font-family': 'monospace' }); tx1.textContent = dayDate(d1); svg.appendChild(tx1);
      wrap.appendChild(svg);
      wrap.appendChild(el('p', { 'class': 'note', style: 'margin-top:0', text: 'purple = spent/day (max ' + mS.toFixed(1) + 'M) · green = est. saved/day (own scale, max ' + (mV * 1000).toFixed(0) + 'k)' }));
      return wrap;
    }
    function renderTokenDayPane(bin) {
      var d2 = bin.d;
      var act = PLANS.filter(function (p) { return p.b <= d2 && d2 <= p.e; }).map(function (p) {
        var dayCells = p.cells.filter(function (c) { return Math.floor(c.day) === d2; }).length;
        var sp = (p.o && p.cells.length) ? (p.o / 10) / p.cells.length * dayCells : 0;
        return { p: p, dayCells: dayCells, sp: sp };
      }).sort(function (x, y) { return y.sp - x.sp || y.dayCells - x.dayCells; });
      pane.textContent = '';
      pane.appendChild(el('h4', { text: dayDate(d2) }));
      pane.appendChild(el('span', { 'class': 'kindchip' }, [el('i', { style: 'background:#f5a623' }), 'token day']));
      pane.appendChild(pRow('spent', bin.sp.toFixed(1) + 'M day · ' + bin.cs.toFixed(1) + 'M cum'));
      pane.appendChild(pRow('saved (est.)', (bin.sv * 1000).toFixed(0) + 'k day · ' + bin.cv.toFixed(2) + 'M cum'));
      var tpc = tokPaneChart(d2); if (tpc) { pane.appendChild(tpc); }
      pane.appendChild(pSect('ACTIVE EXECPLANS · ' + act.length));
      if (act.length) {
        var ul = el('ul', { 'class': 'facts' });
        act.slice(0, 22).forEach(function (x2) {
          var dot = el('b', { text: '●' }); dot.style.color = stateHue(x2.p);
          ul.appendChild(el('li', {}, [dot, ' ', el('b', { text: x2.p.short.slice(0, 30) }), ' · ' + STATE[x2.p.st] + ' ' + x2.p.done + '/' + x2.p.total + (x2.sp ? ' · ~' + x2.sp.toFixed(1) + 'M' : '') + (x2.dayCells ? ' · ' + x2.dayCells + ' events' : '')]));
        });
        if (act.length > 22) { ul.appendChild(el('li', { text: '… +' + (act.length - 22) + ' more' })); }
        pane.appendChild(ul);
      } else {
        pane.appendChild(el('p', { 'class': 'note', text: 'no plans with activity spans covering this day' }));
      }
      pane.appendChild(el('p', { 'class': 'note', text: 'spend attribution: plan output-token totals distributed across their event days (estimate until per-day token_burn is wired)' }));
      pane.classList.add('open');
    }

    function onKey(e) { if (e.key === 'Escape') { setSel(null); solo = null; tokSel = null; } }
    if (typeof window !== 'undefined') { window.addEventListener('keydown', onKey); }

    // tiles: press to switch the lens
    Object.keys(tileByLens).forEach(function (ln) {
      tileByLens[ln].b.addEventListener('click', function () {
        lens = ln;
        Object.keys(tileByLens).forEach(function (x) { tileByLens[x].b.setAttribute('aria-pressed', String(x === ln)); });
        setSel(null); solo = null; hover = null; hoverSec = null; gSel = null; tokSel = null; hideTip();
        setLedger(false);
        if (lens === 'data') { var minD = Math.min.apply(null, GNODES.map(function (n) { return n.d; })) - 0.5; if (S < minD - 1) { rStart.value = Math.round((minD - 11) / (NOW - 11) * 1000); syncWindow(); } }
        grpTokViews.style.display = lens === 'tokens' ? 'flex' : 'none';
      });
    });
    function setTokView(v) { tokView = v; bTokCum.setAttribute('aria-pressed', String(v === 'cum')); bTokDay.setAttribute('aria-pressed', String(v === 'day')); }
    bTokCum.addEventListener('click', function () { setTokView('cum'); });
    bTokDay.addEventListener('click', function () { setTokView('day'); });

    // ---- teardown + boot ----
    function onVis() { kick(); }
    if (typeof document !== 'undefined') { document.addEventListener('visibilitychange', onVis); }
    function teardown() {
      if (rafId != null && typeof cancelAnimationFrame === 'function') { cancelAnimationFrame(rafId); }
      rafId = null;
      if (ro) { try { ro.disconnect(); } catch (e) { /* noop */ } }
      if (io) { try { io.disconnect(); } catch (e) { /* noop */ } }
      if (typeof document !== 'undefined') { document.removeEventListener('visibilitychange', onVis); }
      if (typeof window !== 'undefined') { window.removeEventListener('keydown', onKey); }
      if (__ringsCleanupFn === teardown) { __ringsCleanupFn = null; }
    }
    __ringsCleanupFn = teardown;

    syncWindow();
    resize();
    kick();

    // ---- live wire: swap the embedded snapshot for the real board when the
    //      daemon feeds are reachable (through the console's CruxApi client).
    //      Fails silently back to the snapshot on any absent/failed feed. ----
    (function liveInit() {
      var num = function (v) { return (v === null || v === undefined) ? '—' : Number(v).toLocaleString(); };
      fetchJSON('/v1/work?source=all').then(function (res) {
        if (res.ok && res.data) {
          var j = res.data;
          var items = (j.work || []).filter(function (w) {
            return w.id && w.id.indexOf('execplan:') === 0 && w.provenance && w.provenance.first_activity_unix_ms && ['in_progress', 'complete', 'blocked'].indexOf(w.state) >= 0;
          });
          if (items.length >= 50) {
            NOW = Math.max(76, Math.floor(Date.now() / 86400000) - 20580);
            var raws = items.map(function (w) {
              return { s: w.id.slice(9), st: w.state === 'in_progress' ? 1 : w.state === 'blocked' ? 2 : 0,
                d: w.milestones_done || 0, t: w.milestones_total || 1,
                b: Math.floor(w.provenance.first_activity_unix_ms / 86400000) - 20580,
                e: Math.floor(w.provenance.last_activity_unix_ms / 86400000) - 20580,
                o: Math.floor(((w.token_burn && w.token_burn.output_tokens) || 0) / 1e5),
                dep: w.depends_on || [], ext: w.extended_by || [], od: w.open_decisions || [] };
            });
            setSel(null); solo = null; hover = null; hoverSec = null; gSel = null; tokSel = null;
            loadPlans(raws); rebuildLineage(); buildCells(); refreshTok();
            if (TOK.totS < 1 && SNAP_TOK.totS >= 1) { TOK = SNAP_TOK; tTok.n.textContent = Math.round(TOK.totS) + 'M (snap)'; }
            dStart.max = dEnd.max = dayDate(NOW);
            syncWindow();
            dataSrc = 'live · prod-mirror';
            glExecplans.n.textContent = num(j.count);
            tWork.n.textContent = num(j.count);
            glSrc.textContent = 'live · ' + dayDate(NOW);
          }
        }
      });
      fetchJSON('/v1/console/summary').then(function (res) {
        if (res.ok && res.data) {
          var s2 = res.data;
          if (s2.stores) { glFacts.n.textContent = num(s2.stores.facts); glSessions.n.textContent = num(s2.stores.sessions); tSess.n.textContent = num(s2.stores.sessions); }
          if (s2.daemon && s2.daemon.mcp_agent_count !== undefined) { glMcp.n.textContent = num(s2.daemon.mcp_agent_count); }
          if (s2.integrations !== undefined) {
            var gi = s2.integrations;
            glInt.n.textContent = Array.isArray(gi) ? String(gi.length) : (gi && typeof gi === 'object') ? num(gi.builtin_pack_count !== undefined ? gi.builtin_pack_count : Object.keys(gi).length) : num(gi);
          }
          if (s2.daemon) { glEngine.n.textContent = s2.daemon.dataplane_enabled ? 'on' : 'off'; }
        }
      });
      // data graph: page the WHOLE visible store through /v1/facts/list (cursor
      // pagination, reserved included), up to a sane node cap. Snapshot stands on 404.
      (function walkFacts() {
        var NODE_CAP = 2000, seen = {}, seenCount = 0, total = null, cursor = null, capped = false, ok = false;
        function page2(count) {
          if (count > 40) { finish(); return; }
          var u = '/v1/facts/list?limit=200&include_reserved=1' + (cursor ? '&cursor=' + encodeURIComponent(cursor) : '');
          fetchJSON(u).then(function (res) {
            if (res.status === 404 || !res.ok || !res.data) { finish(); return; }
            var j3 = res.data; ok = true;
            if (total === null && j3.total_visible != null) { total = j3.total_visible; }
            (j3.facts || []).forEach(function (f) {
              if (capped || !f.fact_id || !f.stored_at || seen[f.fact_id]) { return; }
              var ms = Date.parse(f.stored_at); if (!isFinite(ms)) { return; }
              seen[f.fact_id] = { e: f.entity || '?', k: f.key || '?', d: ms / 86400000 - 20580, a: f.actor || null, h: f.horizon_class || 'none', c: f.confidence === undefined ? 1 : f.confidence, t: f.tokens || 100 };
              seenCount++; if (seenCount >= NODE_CAP) { capped = true; }
            });
            cursor = j3.next_cursor || null;
            if (capped || !cursor || !j3.has_more) { finish(); return; }
            page2(count + 1);
          });
        }
        function finish() {
          var live = [];
          for (var id in seen) { var n = seen[id]; if (isFinite(n.d) && n.d > 0) { live.push(n); } }
          if (ok && live.length) { gSel = null; loadGraph(live); gTotal = total; gCap = capped; tData.n.textContent = num(live.length); }
          else if (total) { gTotal = total; }
        }
        page2(0);
      })();
    })();
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
    // M5 (console-surfaces-remediation) — sessions × token-burn browser.
    renderCostBrowser: renderCostBrowser,
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
    // M10 (console-surfaces-remediation, review round 1) — the native Rings page
    // (canvas "clock of work"; replaced the embedded iframe mock).
    renderRings: renderRings,
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
