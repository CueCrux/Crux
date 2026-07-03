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
  var CONTROL_TYPES = ['search', 'input', 'textarea', 'select', 'toggle', 'btn', 'info', 'exp', 'rpcout', 'bar', 'theme', 'chart', 'disclose', 'repogrid'];
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
    var svg = svgEl('svg', { 'class': spark ? 'chart-svg spark' : 'chart-svg', viewBox: '0 0 ' + W + ' ' + H, role: 'img', 'aria-hidden': 'true' });
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
        var inp = el('input', { 'class': 'ctl-input' + (control.mono ? ' mono' : ''), type: control.secret ? 'password' : 'text', placeholder: control.ph || '', value: control.v != null ? control.v : '' });
        node = applyMutationGate(labelled(control, inp), control);
        break;
      }
      case 'textarea': {
        var ta = el('textarea', { 'class': 'ctl-input ctl-textarea' + (control.mono ? ' mono' : ''), rows: control.rows || 3, placeholder: control.ph || '', text: control.v != null ? control.v : '' });
        node = applyMutationGate(labelled(control, ta), control);
        break;
      }
      case 'select': {
        var sel = el('select', { 'class': 'ctl-input ctl-select' });
        var opts = control.options || [];
        for (var oi = 0; oi < opts.length; oi++) {
          var o = opts[oi];
          var val = (o && typeof o === 'object') ? (o.value != null ? o.value : o.v) : o;
          var lab = (o && typeof o === 'object') ? (o.label != null ? o.label : val) : o;
          var opt = el('option', { value: String(val), text: String(lab === '' ? '—' : lab) });
          if (String(val) === String(control.v)) { opt.setAttribute('selected', 'selected'); }
          sel.appendChild(opt);
        }
        node = applyMutationGate(labelled(control, sel), control);
        break;
      }
      case 'toggle': {
        // LED toggle (legacy .active-toggle, index.html:388-392): a squarer
        // family chip with an 8px LED that glows (--ok) when on. The .on class
        // reflects control.v (the server value); the input carries the a11y
        // state and is disabled by applyMutationGate on mut toggles.
        var box = el('label', { 'class': 'ctl-toggle' + (control.v ? ' on' : '') });
        var cb = el('input', { type: 'checkbox' });
        if (control.v) { cb.setAttribute('checked', 'checked'); }
        box.appendChild(cb);
        box.appendChild(el('span', { 'class': 'led', 'aria-hidden': 'true' }));
        box.appendChild(el('span', { 'class': 'ctl-toggle-label', text: control.label || '' }));
        var wrap = el('div', { 'class': 'ctl-row' }, [box]);
        if (control.desc) { wrap.appendChild(el('p', { 'class': 'ctl-desc', text: control.desc })); }
        node = applyMutationGate(wrap, control);
        break;
      }
      case 'btn': {
        if (control.href) {
          // Deep-machinery fallback links (Pro console / 3D substrate) — quiet family.
          node = el('a', { 'class': 'btn-quiet', href: control.href, title: control.hint || '' }, [control.label || 'Open']);
          break;
        }
        // Every page-level button is the quiet family; `danger` is a colour cue.
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
    for (var i = 0; i < sections.length; i++) {
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
      // Mini sparklines on the Facts + Sessions tiles — a REAL series bucketed
      // from /v1/activity (events/day), or a demo fixture when demo mode is on.
      // Never a series fabricated from the single scalar tile value.
      return addTileSparklines(card);
    });
  }
  function addTileSparklines(card) {
    return fetchJSON('/v1/activity?tenant_id=default&token_budget=1500').then(function (res) {
      var rows = (res.ok && res.data && res.data.rows) ? res.data.rows : [];
      attachSpark(card, 'Facts', seriesFor(rows, /fact/i, 'factsSpark'));
      attachSpark(card, 'Sessions', seriesFor(rows, /session/i, 'sessionsSpark'));
    });
  }
  function seriesFor(rows, re, demoKey) {
    var real = bucketActivityByDay(rows, function (r) { return re.test((r.kind || '') + ' ' + (r.tool || '')); }, 7);
    if (real) { return { vals: real, demo: false }; }
    var d = demoData(demoKey);
    return d ? { vals: d, demo: true } : null;
  }
  function attachSpark(card, label, s) {
    if (!s || !s.vals) { return; }
    var stats = card.querySelectorAll('.stat');
    for (var i = 0; i < stats.length; i++) {
      var k = stats[i].querySelector('.k');
      if (k && k.textContent.trim().toLowerCase() === label.toLowerCase()) {
        var sp = areaChart(s.vals, { spark: true });
        if (sp) { stats[i].appendChild(sp); if (s.demo) { stats[i].appendChild(demoChip(true)); } }
        return;
      }
    }
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

  // The Overwatch landing entry point (shell.html calls this for the overwatch
  // destination, above the page-pill row). Panels are appended in order first,
  // then filled async, so ordering is stable regardless of fetch timing.
  function renderOverwatchLanding(region, ctx) {
    ctx = ctx || {};
    region.textContent = '';
    var root = el('div', { 'class': 'ow-landing' });
    region.appendChild(root);
    // Tagline introducing the Overwatch view (concept apphead sub).
    root.appendChild(el('p', { 'class': 'ow-tagline', text: 'You steer. Agents work. Everything receipts.' }));
    // Stat tiles — full width, reused from the cx-overview build.
    var tileCard = el('div', { 'class': 'ow-tiles' }, [el('p', { 'class': 'v2card-sub', text: 'Loading…' })]);
    root.appendChild(tileCard);
    // 7fr / 5fr split: NEEDS YOU on the left; FLEET · ACTIVITY · ENGINE right.
    var cols = el('div', { 'class': 'ow-cols' });
    var left = el('div', { 'class': 'ow-col' });
    var right = el('div', { 'class': 'ow-col' });
    cols.appendChild(left); cols.appendChild(right);
    root.appendChild(cols);
    var needs = panel('Needs you', 'loading gate queue…', true);
    left.appendChild(needs);
    var fleet = panel('Fleet', 'loading live sessions…', true);
    var activity = panel('Activity', 'loading…', false, 'open log →', '/console/activity');
    var engine = panel('Engine', 'checking mediation…', false);
    right.appendChild(fleet);
    right.appendChild(activity);
    right.appendChild(engine);
    return Promise.all([
      fillTiles(tileCard, ctx),
      fillNeedsYou(needs),
      fillFleet(fleet),
      fillActivity(activity),
      fillEngine(engine)
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

  return {
    CONTROL_TYPES: CONTROL_TYPES,
    GATE_TITLE: GATE_TITLE,
    renderPage: renderPage,
    renderSections: renderSections,
    fetchJSON: fetchJSON,
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
    enrichAction: enrichAction
  };
});
