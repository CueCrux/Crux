// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.
//
// Unified Shell Console v2 — page registry (ExecPlan unified-shell-console-2026-07-03, M1).
// A no-build, dependency-free module (UMD: window.CruxPages in the browser,
// module.exports under node for the static-analysis smoke). It carries all 26
// legacy CX pages ported into the v2 IA — each page keeps the legacy control DSL
// (t:'search'|'input'|'textarea'|'select'|'toggle'|'btn'|'info'|'exp'|'rpcout'|
// 'bar'|'theme'|'approver'). Rendering lives in render.js; this file is pure data + pure
// build() transforms (no DOM, no fetch) so it can be required and audited.
//
// Customer-safe posture: any control that WRITES carries `mut:true`; render.js
// routes those through the operator posture gate (hidden unless operator; when
// operator, rendered disabled with title "wired in M3+"). MUTATING_ACTIONS lists
// them so the smoke can audit that every one is gated.
;(function (root, factory) {
  var api = factory();
  if (typeof module === 'object' && module.exports) { module.exports = api; }
  else { root.CruxPages = api; root.CruxDemo = api.CruxDemo; }   // window.CruxDemo for render.js demoData()
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // ---- Pure formatting + access helpers (no DOM) -------------------------
  function info(label, v) { return { t: 'info', label: label, v: v }; }
  // Mutating button: rendered only for operators, and disabled until M3+.
  function mbtn(label, extra) {
    var c = { t: 'btn', label: label, mut: true };
    if (extra) { for (var k in extra) { c[k] = extra[k]; } }
    return c;
  }
  // Read/inert button: visible to all, but no live behaviour in M1.
  function rbtn(label, extra) {
    var c = { t: 'btn', label: label };
    if (extra) { for (var k in extra) { c[k] = extra[k]; } }
    return c;
  }
  // Link button rendered as an <a> (deep-machinery fallbacks reuse this).
  function link(label, href, extra) {
    var c = { t: 'btn', label: label, href: href };
    if (extra) { for (var k in extra) { c[k] = extra[k]; } }
    return c;
  }

  // Runtime capability contract for rendered controls. Keys are stable control
  // ids; values name the /v1/version capability and every route that control can
  // reach. render.js consumes this as data through one generic gate, while the
  // smoke checks the capability names against product.rs. Keep writes on the
  // existing gated client: this map describes routes, it never dispatches them.
  var CONTROL_CAPABILITY_MAP = Object.freeze({
    'documents.living.load': Object.freeze({ capability: 'projection_queries', routes: Object.freeze([
      Object.freeze(['GET', '/v1/admin/projections/artifacts/{artifactId}/state']),
      Object.freeze(['GET', '/v1/admin/projections/artifacts/{artifactId}/relations']),
      Object.freeze(['GET', '/v1/admin/projections/artifacts/{artifactId}/dependents']),
      Object.freeze(['GET', '/v1/admin/projections/artifacts/{artifactId}/pressure-events'])
    ]) }),
    'documents.dependencies.expand': Object.freeze({ capability: 'graph_expand', routes: Object.freeze([
      Object.freeze(['POST', '/v1/query/graph-expand'])
    ]) })
  });
  // Cross-feature launch point → the Canvas relation graph, focused on this
  // node's neighbourhood (M9). A read-only nav-family LINK (t:'btn' + href), so
  // it is visible in BOTH postures (never a mutation); render.js renders it small
  // (.cx-graphlink) and the shell routes the hash to the graph view. `id` may
  // itself contain colons (e.g. execplan-prefixed work ids) — parseFocus splits
  // on the first colon only, so the composite id survives.
  function graphLink(type, id) {
    return { t: 'btn', label: 'View graph', href: '#/canvas/graph?focus=' + type + ':' + id, graphLaunch: true };
  }
  function get(obj, path) {
    var cur = obj;
    for (var i = 0; i < path.length; i++) { if (cur == null) { return undefined; } cur = cur[path[i]]; }
    return cur;
  }
  function fmtNum(n) {
    if (typeof n !== 'number' || !isFinite(n)) { return '—'; }
    try { return n.toLocaleString('en-US'); } catch (e) { return String(n); }
  }
  function fmtPct(r) {
    if (typeof r !== 'number' || !isFinite(r)) { return '—'; }
    return (r * 100).toFixed(r < 0.1 ? 1 : 0) + '%';
  }
  function fmtBytes(b) {
    if (typeof b !== 'number' || !isFinite(b) || b < 0) { return '—'; }
    var u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'], i = 0, v = b;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return (v >= 10 || i === 0 ? Math.round(v) : v.toFixed(1)) + ' ' + u[i];
  }
  function str(v) { return (v == null || v === '') ? '—' : String(v); }
  function clip(v, n) { var s = (typeof v === 'string' ? v : JSON.stringify(v || '')); return s.length > n ? s.slice(0, n) : s; }
  function arr(v) { return Array.isArray(v) ? v : []; }
  // Build result contract passed to every load.build(): { ok, status, data }.
  function degraded(status, message, extra) {
    var rows = [info(status === 0 ? 'unreachable' : ('HTTP ' + status), message)];
    if (extra) { rows = rows.concat(extra); }
    return rows;
  }

  // ---- AMR lanes (Tenants page) — ported from the legacy AMR_LANES -------
  var AMR_LANES = [
    ['dense', 'Dense — semantic similarity over embeddings: meaning, not spelling. BYOE or managed.', false],
    ['graph', 'Graph / topology — entity links walked at query time; facts that know each other.', false],
    ['entity', 'Entity & trait — who/what-keyed recall: ask about a person, get their dossier.', false],
    ['event', 'Event — time-anchored recall: what happened, when, in what order.', false],
    ['nav', 'Navigational — summary-tree descent for corpora too large to scan.', false],
    ['verbatim', 'Verbatim pointers — exact-quote recall without duplicating content. Free, local.', true]
  ];
  function amrLaneToggles(prefix) {
    var out = [
      { t: 'toggle', k: prefix + 'auto', label: 'automatic — let AMR choose lanes', v: true, mut: true,
        desc: 'Recommended. AMR reads the lane manifest and fuses the lanes that earn their tokens, per query.' },
      info('lexical (BM25)', 'always on · free · local')
    ];
    for (var i = 0; i < AMR_LANES.length; i++) {
      var l = AMR_LANES[i];
      out.push({ t: 'toggle', k: prefix + l[0], label: l[0] + ' lane', v: l[2], mut: true, desc: l[1] });
    }
    return out;
  }
  function tenantExpRow(id, sub, sys) {
    var p = 'tn_' + String(id).replace(/[^a-zA-Z0-9]/g, '_') + '_';
    return { t: 'exp', label: id, sub: sub || 'tenant', badge: sys ? 'system' : 'tenant', sys: !!sys, hideIf: sys ? 'hidesys' : null,
      controls: [{ t: 'toggle', k: p + 'inherit', label: 'use AMR defaults', v: true, mut: true,
        desc: 'Inherit the lane policy from the defaults panel above.' }]
        .concat(amrLaneToggles(p))
        .concat([rbtn('Collaborate with team', { hint: 'paid plan — teammates’ daemons can pull this tenant' })]) };
  }

  // ---- CoreCrux RRF lane weights (Lane weights page) --------------------
  var RRF_LANES = [
    ['bm25', 'BM25 lexical', 1], ['cosine', 'Dense / cosine', 1], ['sparse', 'Sparse', 1], ['hyde', 'HyDE', 1],
    ['topology', 'Topology', 0], ['vernacular', 'Vernacular', 0], ['indexing', 'Indexing', 0],
    ['topology_trait_expansion', 'Trait expansion', 0], ['navtree', 'Navtree', 0], ['events', 'Events', 0]
  ];
  function laneWeightControls() {
    return RRF_LANES.map(function (l) {
      return { t: 'input', k: 'w_' + l[0], label: l[1], ph: '0.0', v: String(l[2]), mono: true, mut: true,
        desc: 'Non-negative RRF multiplier for the ' + l[1] + ' lane.' };
    });
  }

  // ---- Work / gates / sessions helpers ----------------------------------
  var WORK_STAGES = [['in_progress', 'In progress'], ['blocked', 'Blocked'], ['planned', 'Planned'], ['done', 'Done']];
  function workStageOf(w) {
    var s = String(w.state || w.status || 'planned').toLowerCase();
    return ({ complete: 'done', deployed: 'done', archive: 'done', run: 'in_progress', ok: 'done', err: 'blocked', idle: 'planned' })[s] || s;
  }

  // =======================================================================
  //  Live build() transforms — pure data → sections[]. Each receives the
  //  fetch result { ok, status, data } and returns an array of sections.
  // =======================================================================

  function buildOverview(res) {
    var s = res.data;
    if (!res.ok || !s) {
      return [{ h: 'Daemon', sub: 'summary unavailable', wide: true,
        controls: degraded(res.status, res.status === 0
          ? 'Could not reach the daemon at this origin. Check corecruxd is running on :14800 and reload.'
          : '/v1/console/summary returned no data (it may require console-read auth). Navigation still works.') }];
    }
    // Build / auth mode / dataplane / node moved off the tiles: build/auth/
    // dataplane are now compact chips in the topbar, node id lives on System ›
    // Settings › Node (items 3 + 4). Tiles keep the six live counters.
    return [
      { h: 'Daemon at a glance', wide: true,
        tiles: [
          ['Facts', fmtNum(get(s, ['stores', 'facts']))],
          ['Sessions', fmtNum(get(s, ['stores', 'sessions']))],
          ['Shards', fmtNum(get(s, ['routing', 'shard_count'])), 'map v' + str(get(s, ['routing', 'shard_map_version']))],
          ['Storage free', fmtPct(get(s, ['capacity', 'free_ratio'])), 'of ' + fmtBytes(get(s, ['capacity', 'total_bytes']))],
          ['MCP agents', fmtNum(get(s, ['daemon', 'mcp_agent_count'])), get(s, ['daemon', 'mcp_enabled']) ? 'enabled' : 'off'],
          ['Integrations', fmtNum(get(s, ['integrations', 'builtin_pack_count'])), get(s, ['integrations', 'enabled']) ? 'enabled' : 'off']
        ], controls: [] }
    ];
  }

  function buildFacts(res) {
    if (!res.ok || !res.data) { return [{ h: 'Facts', wide: true, controls: [{ t: 'search', ph: 'Filter facts…' }].concat(degraded(res.status, 'Facts unavailable — GET /v1/console/facts')) }]; }
    var fs = arr(res.data.facts);
    if (!fs.length) { return [{ h: 'Facts', wide: true, controls: [{ t: 'search', ph: 'Filter facts…' }, info('none', 'no facts stored yet')] }]; }
    var groups = {};
    fs.forEach(function (f) {
      var ent = String(f.entity || '');
      var g = (ent.match(/^([a-z_]+):/i) || [])[1] || (/^__/.test(ent) ? ent.split('::')[0] + '::' : 'other');
      (groups[g] = groups[g] || []).push(f);
    });
    var rows = [{ t: 'search', ph: 'Filter facts…' }];
    Object.keys(groups).forEach(function (g) {
      var list = groups[g];
      rows.push({ t: 'exp', label: g.slice(-2) === '::' ? g + '*' : g + ':*', sub: list.length + ' recent facts', badge: 'group',
        controls: list.slice(0, 15).map(function (f) {
          return { t: 'exp', label: f.key || f.entity, sub: f.entity, badge: 'fact',
            meta: [f.fact_id || f.id, f.stored_at].filter(Boolean).join(' · '),   // Pro-mode mono metadata (ids/timestamps Standard elides)
            controls: [info('stored', str(f.stored_at)), info('value', clip(f.value, 140))] };
        }) });
    });
    return [{ h: 'Facts', sub: 'the durable record · grouped by entity prefix · ' + fs.length + ' recent', wide: true, controls: rows }];
  }

  function buildMemory(res) {
    if (!res.ok || !res.data) { return [{ h: 'Recent memory', wide: true, controls: [{ t: 'search', ph: 'Filter tenants…' }].concat(degraded(res.status, 'Memory feed unavailable — GET /v1/console/facts')) }]; }
    var fs = arr(res.data.facts);
    if (!fs.length) { return [{ h: 'Recent memory', wide: true, controls: [{ t: 'search', ph: 'Filter tenants…' }, info('none', 'no recent facts')] }]; }
    var groups = {};
    fs.forEach(function (f) {
      var tn = f.tenant || f.tenant_id || (/^__/.test(String(f.entity || '')) ? String(f.entity).split('::')[0] + '::' : 'default');
      (groups[tn] = groups[tn] || []).push(f);
    });
    var rows = [{ t: 'search', ph: 'Filter tenants…' },
      { t: 'toggle', k: 'hidesys', label: 'hide system tenants', v: true,
        desc: 'System tenants (__agent::, __ops::, __bootstrap__:: …) carry daemon internals.' }];
    Object.keys(groups).forEach(function (tn) {
      var sys = /^__/.test(tn);
      rows.push({ t: 'exp', label: tn, sub: (sys ? 'system store' : 'fact store') + ' · ' + groups[tn].length + ' recent', badge: sys ? 'system' : 'tenant', sys: sys, hideIf: sys ? 'hidesys' : null,
        controls: groups[tn].slice(0, 8).map(function (f) { return info(f.key || f.entity, clip(f.value, 100)); }) });
    });
    return [{ h: 'Recent memory', sub: 'recent facts per tenant · ' + fs.length + ' loaded', wide: true, controls: rows }];
  }

  function buildTenants(res) {
    // AMR defaults sits ABOVE the Tenants card but starts hidden; the cog in the
    // Tenants header reveals it upward. The "hide system tenants" view-filter is a
    // header control (top-right, same row as the Tenants title).
    var head = { h: 'AMR defaults — all tenants', id: 'amrDefaults', hidden: true,
      sub: 'Adaptive Manifest Routing picks lanes per query; set the default policy once — tenants inherit unless pinned', wide: true,
      controls: [info('subscription', 'inactive — CoreCrux lanes activate with a subscription · lexical + verbatim stay free/local')]
        .concat(amrLaneToggles('amr_'))
        .concat([mbtn('Apply defaults to all tenants', { hint: 'resets per-tenant pins back to inherit' })]) };
    var cog = { label: '⚙', variant: 'cog', title: 'AMR defaults', target: 'amrDefaults' };
    var hideSys = { t: 'toggle', k: 'hidesys', label: 'hide system tenants', v: true, hideKey: 'hidesys',
      desc: 'System tenants carry daemon internals.' };
    if (!res.ok || !res.data) {
      return [head, { h: 'Tenants', wide: true, headAction: cog, headControls: [hideSys], controls: [{ t: 'search', ph: 'Filter tenants…' }].concat(degraded(res.status, 'Tenants unavailable — GET /v1/console/tenants')) }];
    }
    var ts = arr(res.data.tenants);
    var rows = [{ t: 'search', ph: 'Filter tenants…' }];
    ts.forEach(function (t) {
      var id = t.tenant_id || t.id; var sys = (t.category === 'system') || /^__/.test(String(id));
      rows.push(tenantExpRow(id, [t.category, t.source].filter(Boolean).join(' · ') || 'tenant', sys));
    });
    if (!ts.length) { rows.push(info('none', 'no tenants registered')); }
    return [head, { h: 'Tenants', sub: ts.length + ' tenant' + (ts.length === 1 ? '' : 's') + ' · click to expand lane policy', wide: true, headAction: cog, headControls: [hideSys], controls: rows }];
  }

  function buildPassports(res) {
    // The mint form starts hidden; the Passports card header carries a "+" that
    // reveals it BELOW the list (not on top). See renderSection headAction.
    var form = { h: 'New passport', id: 'newPassportForm', hidden: true, sub: 'mint a passport and attach who owns it (POST /v1/passports)', wide: true,
      controls: [
        { t: 'input', k: 'pp_id', label: 'id', ph: 'lowercase, digits, - or _', mono: true, mut: true },
        { t: 'select', k: 'pp_category', label: 'category', options: ['work', 'personal', 'public'], v: 'work', mut: true },
        { t: 'input', k: 'pp_name', label: 'name', ph: 'display name', mut: true },
        { t: 'input', k: 'pp_owner', label: 'owner', ph: 'who owns / manages this passport', mut: true },
        { t: 'input', k: 'pp_position', label: 'position', ph: 'role / title', mut: true },
        { t: 'input', k: 'pp_company', label: 'company', ph: 'organisation', mut: true },
        { t: 'textarea', k: 'pp_notes', label: 'notes', rows: 2, ph: 'any other notes', mut: true },
        mbtn('Create passport', { hint: 'POST /v1/passports' })
      ] };
    var plus = { label: '+', variant: 'plus', title: 'New passport', target: 'newPassportForm' };
    if (!res.ok || !res.data) { return [{ h: 'Passports', wide: true, headAction: plus, controls: [{ t: 'search', ph: 'Filter passports…' }].concat(degraded(res.status, 'Passports unavailable — GET /v1/passports')) }, form]; }
    var ps = arr(res.data.passports);
    var rows = [{ t: 'search', ph: 'Filter passports…' }].concat(ps.map(function (p) {
      return { t: 'exp', label: p.name ? (p.name + ' · ' + p.id) : p.id,
        sub: [p.position, p.company, p.category, p.reputation_tier].filter(Boolean).join(' · '),
        badge: p.category || 'passport',
        controls: [['id', p.id], ['name', p.name], ['owner', p.owner], ['position', p.position], ['company', p.company], ['category', p.category], ['tier', p.reputation_tier], ['receipts', p.receipt_count]]
          .filter(function (kv) { return kv[1] != null && kv[1] !== ''; }).map(function (kv) { return info(kv[0], String(kv[1])); })
          .concat(p.notes ? [info('notes', String(p.notes))] : []) };
    }));
    if (!ps.length) { rows.push(info('none', 'no passports yet')); }
    return [{ h: 'Passports', sub: ps.length + ' passport' + (ps.length === 1 ? '' : 's') + ' · loaded from /v1/passports', wide: true, headAction: plus, controls: rows }, form];
  }

  // Compact token count → "148k" (keeps the bar label short).
  function fmtK(n) {
    if (typeof n !== 'number' || !isFinite(n)) { return null; }
    if (n >= 1000) { return (n / 1000 >= 100 ? Math.round(n / 1000) : (n / 1000).toFixed(n < 10000 ? 1 : 0)) + 'k'; }
    return String(n);
  }
  function buildSessions(res) {
    // Demo mode: real saved sessions are bare id rows locally, so a demoOn()-guarded
    // fixture paints richer resume/audit detail (execplan · passport · turns · token/progress bars).
    if (typeof window !== 'undefined' && window.CRUX_DEMO && CruxDemo.sessions) { res = { ok: true, data: { sessions: CruxDemo.sessions } }; }
    if (!res.ok || !res.data) { return [{ h: 'Sessions', wide: true, controls: [{ t: 'search', ph: 'Filter sessions…' }].concat(degraded(res.status, 'Sessions unavailable — GET /v1/console/sessions')) }]; }
    var list = arr(res.data.sessions || res.data.items || res.data);
    var live = list.filter(function (s) { return !s.archived; });
    var arch = list.filter(function (s) { return s.archived; });
    // A session renders as a rich card: id + status, the execplan + passport it
    // carries, and two horizontal gradient bars — token usage and progress.
    var row = function (s) {
      var used = (typeof s.token_used === 'number') ? s.token_used : null;
      var lim = (typeof s.token_limit === 'number') ? s.token_limit : null;
      var tokPct = (used != null && lim) ? Math.round((used / lim) * 100) : null;
      var mDone = s.milestones_done, mTot = s.milestones_total;
      var progPct = (typeof s.progress === 'number') ? Math.round(s.progress * 100)
        : (mTot ? Math.round(((mDone || 0) / mTot) * 100) : null);
      var progLabel = progPct != null ? (progPct + '%' + (mTot ? (' · M' + (mDone || 0) + '/' + mTot) : '')) : null;
      return { t: 'sesscard', id: s.session_id || s.id || s.label || 'session',
        status: s.archived ? 'archived' : (s.status || 'session'),
        execplan: s.execplan_slug || null, passport: s.passport_id || null, tenant: s.tenant_id || null,
        turns: (s.turn_count != null) ? s.turn_count : null, updated: s.updated_at || s.last_active || null,
        tokPct: tokPct, tokLabel: (used != null && lim) ? (fmtK(used) + ' / ' + fmtK(lim)) : null,
        progPct: progPct, progLabel: progLabel,
        focusId: s.session_id || s.id || null };
    };
    return [
      { h: 'Active & idle', sub: live.length + ' session' + (live.length === 1 ? '' : 's') + ' · token usage · progress · attached execplan + passport · /v1/console/sessions', wide: true,
        controls: [{ t: 'search', ph: 'Filter sessions…' }].concat(live.length ? live.map(row) : [info('none', 'no live sessions')]) },
      { h: 'Archived', sub: arch.length + ' archived', wide: true, controls: arch.length ? arch.map(row) : [info('—', 'no archived sessions')] }
    ];
  }

  // cx-projects (item 2): real projects from GET /v1/projects render as
  // expandable cards (collapsed by default) carrying the pro-board left strip;
  // each expanded card shows real fields + a repo card grid (repogrid, fetched
  // per-project by render.js). "＋ New project" / "＋ Add repos" are nav-family
  // disclosure buttons (data-requires:operator) that reveal their mut-gated
  // forms on click — the forms never render immediately.
  // Per-project "＋ Add repos" disclosure — one per expanded project card, so the
  // repo actions target that specific project (not a global control at the top).
  function projectAddRepos(p) {
    return { t: 'disclose', label: '＋ Add repos', requires: 'operator',
      controls: [
        info('github', 'not connected — connect under Integrations to add repos'),
        { t: 'select', k: 'gh_addrepo_' + p.id, label: 'repo', options: ['— connect GitHub first —'], v: '— connect GitHub first —', mut: true },
        mbtn('Add repo', { hint: 'POST /v1/projects/' + p.id + '/repos' }),
        mbtn('Set as planning repo', { hint: 'designates where ExecPlans live' })
      ] };
  }
  function buildProjects(res) {
    // "New project" is a top-right "+" on the card header that reveals this form
    // BELOW the list (mirrors the Passports pattern). See renderSection headAction.
    var form = { h: 'New project', id: 'newProjectForm', hidden: true, sub: 'a project pairs repos to track + search with a planning repo for ExecPlans (POST /v1/projects)', wide: true,
      controls: [
        { t: 'input', k: 'proj_name', label: 'name', ph: 'My project', mut: true },
        { t: 'input', k: 'proj_id', label: 'id', ph: 'proj-slug', mono: true, mut: true },
        { t: 'select', k: 'proj_storage', label: 'execplan storage', options: ['planning repo (recommended)', 'daemon-native', 'hybrid — repo files + daemon kanban'], v: 'planning repo (recommended)', mut: true },
        mbtn('Create project', { hint: 'POST /v1/projects' })
      ] };
    var plus = { label: '+', variant: 'plus', title: 'New project', target: 'newProjectForm' };
    // Demo mode: override with the projects fixture so the layout shows a fuller
    // portfolio than a fresh local daemon's single default project.
    if (typeof window !== 'undefined' && window.CRUX_DEMO && CruxDemo.projects) { res = { ok: true, data: { projects: CruxDemo.projects } }; }
    var ps = (res && res.ok && res.data) ? arr(res.data.projects) : [];
    if (!ps.length && (!res || !res.ok || !res.data)) {
      return [{ h: 'Projects', sub: 'a project pairs repos to track + search, a planning repo for ExecPlans, passports and working tenants', wide: true, headAction: plus,
        controls: [{ t: 'search', ph: 'Filter projects…' }].concat(degraded((res && res.status) || 0, 'Projects unavailable — GET /v1/projects (needs admin:read)')) }, form];
    }
    var rows = [{ t: 'search', ph: 'Filter projects…' }];
    ps.forEach(function (p) {
      var strip = p.archived ? 'done' : (p.is_default ? 'in_progress' : 'planned');   // pro-board left strip
      var infos = [['id', p.id], ['name', p.name], ['planning target', p.planning_target], ['default passport', p.default_passport_id],
        ['created', p.created_at_unix_ms ? new Date(p.created_at_unix_ms).toISOString().slice(0, 10) : null]]
        .filter(function (kv) { return kv[1] != null && kv[1] !== ''; }).map(function (kv) { return info(kv[0], String(kv[1])); });
      rows.push({ t: 'exp', strip: strip, label: p.name || p.id,
        sub: [p.id, p.planning_target, p.is_default ? 'default' : null, p.archived ? 'archived' : null].filter(Boolean).join(' · ') || 'project',
        badge: p.archived ? 'archived' : (p.is_default ? 'default' : 'project'),
        controls: infos.concat([{ t: 'repogrid', projectId: p.id }, projectAddRepos(p), graphLink('project', p.id)]) });
    });
    if (!ps.length) { rows.push(info('none', 'no projects yet — use the ＋ in the header')); }
    return [{ h: 'Projects', sub: ps.length + ' project' + (ps.length === 1 ? '' : 's') + ' · click to expand · /v1/projects', wide: true, headAction: plus, controls: rows }, form];
  }

  // Kanban column order (item: ExecPlans as a clean board). Matches the pro
  // board: Planned → In progress → Blocked → Shipped (recently done).
  var KANBAN_COLS = [['planned', 'Planned'], ['in_progress', 'In progress'], ['blocked', 'Blocked'], ['done', 'Shipped · 7d']];
  // Derive a short execplan slug from a plan path or id (drops the dir + .md +
  // the execplan: prefix), so the card carries the readable plan name.
  function planSlug(w) {
    if (w.plan_path) { return String(w.plan_path).split('/').pop().replace(/\.md$/, ''); }
    return String(w.id || '').replace(/^execplan:/, '');
  }
  function buildWork(res) {
    var head = { h: 'ExecPlans', sub: 'kanban board — live milestone work plans · /v1/work?source=all', wide: true, controls: [{ t: 'search', ph: 'Filter plans…' }] };
    var items = (res && res.ok && res.data) ? arr(res.data.work || res.data.items) : [];
    // Demo mode: fall back to the demoOn()-guarded work fixture when the board is empty.
    if (!items.length && typeof window !== 'undefined' && window.CRUX_DEMO && CruxDemo.work) { items = CruxDemo.work; }
    if (!items.length) { return [head, { h: 'Work', wide: true, controls: degraded((res && res.status) || 0, 'Work board unavailable — GET /v1/work?source=all') }]; }
    var card = function (w) {
      var stage = workStageOf(w);   // planned | in_progress | blocked | done — keys the card's left strip
      var done = w.milestones_done || 0, total = w.milestones_total || 0;
      var pct = total ? Math.round((done / total) * 100) : (stage === 'done' ? 100 : 0);
      return { strip: stage, risk: w.risk_class || null, slug: planSlug(w), title: w.title || w.id,
        milestone: w.current_milestone || null, pct: pct, prog: total ? (done + '/' + total) : null,
        passport: w.assignee_passport || null, note: w.linked_pr || null,
        graph: graphLink('work', w.id) };   // cross-feature launch → the relation graph, focused on this plan
    };
    var columns = KANBAN_COLS.map(function (st) {
      return { key: st[0], title: st[1], cards: items.filter(function (w) { return workStageOf(w) === st[0]; }).map(card) };
    });
    return [{ h: 'ExecPlans', sub: head.sub, wide: true, controls: [{ t: 'search', ph: 'Filter plans…' }, { t: 'kanban', columns: columns }] }];
  }

  function buildGates(res) {
    if (!res.ok || !res.data) { return [{ h: 'Awaiting approval', wide: true, controls: [{ t: 'search', ph: 'Filter pending gates…' }].concat(degraded(res.status, 'Gates unavailable — GET /v1/work/gate/pending')) }]; }
    var pend = arr(res.data.pending).filter(function (p) { return (p.status || 'pending') === 'pending'; });
    var rows = [{ t: 'search', ph: 'Filter pending gates…' }].concat(pend.slice(0, 20).map(function (p) {
      return { t: 'exp', label: p.work_id, sub: (p.requested_action || 'update_state') + (p.target_state ? ' → ' + p.target_state : '') + ' · requested by ' + (p.requested_by_passport || '?'), badge: (p.risk_class || 'gated').toUpperCase(),
        desc: 'Approval is passport-attributed (Art. 14); one approval never extends to other actions.',
        controls: [info('action id', p.action_id), info('requested', p.requested_at || '—'),
          mbtn('Approve ' + p.action_id, { hint: 'records approving passport + timestamp' }),
          mbtn('Reject ' + p.action_id), graphLink('work', p.work_id)] };
    }));
    if (!pend.length) { rows.push(info('none pending', 'gated transitions appear here when an agent requests a high-risk state change')); }
    rows.push(mbtn('Withhold all', { hint: 'keeps gates pending' }));
    return [{ h: 'Awaiting approval', sub: '/v1/work/gate/pending · ' + pend.length + ' pending', wide: true, controls: rows }];
  }

  function requestAge(unixMs) {
    var at = Number(unixMs);
    if (!isFinite(at) || at <= 0) { return 'age unknown'; }
    var elapsed = Math.max(0, Date.now() - at);
    var minutes = Math.floor(elapsed / 60000);
    if (minutes < 1) { return 'just now'; }
    if (minutes < 60) { return minutes + 'm ago'; }
    var hours = Math.floor(minutes / 60);
    if (hours < 24) { return hours + 'h ago'; }
    var days = Math.floor(hours / 24);
    return days + 'd ago';
  }

  // Passport mint requests are operator decisions, directly analogous to
  // cx-gates. The renderer owns the editable, attributed approve/reject form;
  // this transform stays pure data + formatting and degrades feature-off 404s
  // to an honest empty state.
  function buildMints(res) {
    var approver = { t: 'approver' };
    if (!res.ok || !res.data) {
      var message = res.status === 404
        ? 'Feature disabled — passport mint requests are not enabled on this daemon.'
        : 'Mint requests unavailable — GET /v1/passport/mint-requests/pending';
      return [{ h: 'Awaiting approval', wide: true, controls: [approver].concat(degraded(res.status, message)) }];
    }
    var pending = arr(res.data.pending).filter(function (p) { return (p.status || 'pending') === 'pending'; });
    var controls = [approver, { t: 'search', ph: 'Filter pending mint requests…' }];
    pending.slice(0, 50).forEach(function (p) {
      var requested = ['personal', 'work', 'public'].indexOf(p.requested_category) >= 0 ? p.requested_category : '';
      controls.push({ t: 'mintcard', request: p, category: requested, age: requestAge(p.requested_at_unix_ms) });
    });
    if (!pending.length) { controls.push(info('none pending', 'agent-requested passport mints appear here for operator approval')); }
    return [{ h: 'Awaiting approval', sub: '/v1/passport/mint-requests/pending · ' + pending.length + ' pending', wide: true, controls: controls }];
  }

  // Review-queue view (P1 widen): the surfaced `__consolidation_review__::`
  // runs written by the (default-OFF) consolidation scheduler, each carrying
  // its contradiction candidates AND expiry proposals (stale / low-confidence).
  // Read-only — resolution stays an explicit operator action.
  function buildReview(res) {
    var head = [{ t: 'search', ph: 'Filter runs…' }];
    var candSec;
    if (!res.ok || !res.data) {
      candSec = { h: 'Review queue', wide: true, controls: head.concat(degraded(res.status, 'Review queue unavailable — GET /v1/console/review/queue')) };
    } else {
      var schedOn = res.data.scheduler_enabled === true;
      var runs = arr(res.data.runs);
      var rows = head.concat([
        info('scheduler', schedOn ? 'on (CORECRUXD_CONSOLIDATION_SCHEDULER=1)' : 'off — no proposals will be surfaced'),
        info('surfaced runs', String(res.data.count || runs.length)),
      ]);
      if (!runs.length) {
        // Distinct states: scheduler-off (nothing will be surfaced) vs
        // scheduler-on-but-empty (a clean store) — review finding 6.
        rows.push(schedOn
          ? info('queue empty', 'scheduler is on and the store is currently clean — no contradiction or expiry proposals')
          : info('scheduler off', 'enable CORECRUXD_CONSOLIDATION_SCHEDULER=1 to surface contradiction + expiry proposals; live contradictions are shown below in the meantime'));
      } else {
        runs.forEach(function (run, i) {
          var rv = run.review || {};
          var cands = arr(rv.candidates);
          var exps = arr(rv.expiry_candidates);
          var controls = [
            info('surfaced', run.surfaced_at || rv.surfaced_at || '—'),
            info('contradictions', String(rv.count != null ? rv.count : cands.length)),
            info('expiry proposals', String(rv.expiry_count != null ? rv.expiry_count : exps.length)),
          ];
          cands.forEach(function (c) {
            controls.push(info('contradiction', (c.entity || '?') + ' · ' + (c.key || '?') + ' — ' + (c.polarity_a || '?') + ' vs ' + (c.polarity_b || '?') + ' [' + (arr(c.fact_ids).join(', ') || '—') + ']'));
          });
          exps.forEach(function (e) {
            controls.push(info(e.reason || 'expiry', (e.entity || '?') + ' · ' + (e.key || '?') + ' — conf ' + (e.confidence != null ? e.confidence : '?') + ' · ' + (e.fact_id || '?')));
          });
          rows.push({ t: 'exp', label: run.entity || ('run ' + (i + 1)), sub: (rv.count || 0) + ' contradictions · ' + (rv.expiry_count || 0) + ' expiry proposals', badge: 'run ' + (i + 1), controls: controls });
        });
      }
      candSec = { h: 'Review queue', sub: 'surfaced __consolidation_review__:: runs · read-only · ' + (res.data.count || 0) + ' runs', wide: true, controls: rows };
    }
    // Live contradiction pass — retained so the console still shows current
    // contradictions when the scheduler is OFF and nothing has been surfaced
    // (review finding 6). Read-only.
    var liveSec = null;
    if (res.ok && res.data) {
      var live = arr(res.data.live_contradictions);
      var liveRows = live.length
        ? live.map(function (c, i) {
          return { t: 'exp', label: (c.entity || 'entity') + ' · ' + (c.key || 'key'), sub: (c.reason || 'candidate') + ' · ' + (c.polarity_a || '?') + ' vs ' + (c.polarity_b || '?'), badge: 'live ' + (i + 1),
            controls: [info('fact ids', arr(c.fact_ids).join(', ') || '—'), info('values', arr(c.values).map(function (v) { return clip(v, 80); }).join(' | ') || '—')] };
        })
        : [info('none', 'no active opposite-polarity fact pairs right now')];
      liveSec = { h: 'Live contradictions', sub: 'read-only live pass · ' + (res.data.live_count || 0) + ' found', wide: true, controls: liveRows };
    }
    var consSec = { h: 'Consolidation', sub: 'creates one canonical fact and supersedes selected targets; protected facts are rejected', wide: true,
      controls: [
        { t: 'input', k: 'cr_entity', label: 'entity', ph: 'service:api', mono: true, mut: true },
        { t: 'input', k: 'cr_key', label: 'key', ph: 'enabled', mono: true, mut: true },
        { t: 'textarea', k: 'cr_value', label: 'canonical value', rows: 3, ph: 'the value to keep', mut: true },
        { t: 'textarea', k: 'cr_targets', label: 'target fact ids', rows: 3, ph: 'f_... , f_...', mono: true, mut: true },
        { t: 'textarea', k: 'cr_protected', label: 'protected fact ids', rows: 2, ph: 'optional pinned ids', mono: true, mut: true },
        { t: 'input', k: 'cr_conf', label: 'confidence', v: '0.8', mono: true, mut: true },
        { t: 'input', k: 'cr_floor', label: 'protect floor', v: '0.99', mono: true, mut: true },
        mbtn('Consolidate facts', { danger: true, hint: 'writes a canonical fact and supersedes selected target facts' })
      ] };
    return liveSec ? [candSec, liveSec, consSec] : [candSec, consSec];
  }

  function buildIntegrations(res) {
    var cat = { h: 'Catalog', sub: 'toggle = install / disable · grants are separate', wide: true,
      controls: [{ t: 'search', ph: 'Filter integrations…' }] };
    if (res.ok && res.data) {
      var packs = arr(res.data.packs);
      packs.forEach(function (p) {
        var id = p.id || p.name;
        cat.controls.push({ t: 'exp', k: 'pack_' + id, label: id, sub: p.description || p.kind || 'integration pack', badge: 'pack' + (p.version ? ' · v' + p.version : ''), v: (p.status ? p.status !== 'disabled' : !!(p.installed || p.enabled)), mut: true,
          desc: p.description || '', controls: [info('status', p.status || (p.installed ? 'installed' : 'available'))]
            .concat(arr(p.capabilities).length ? [info('capabilities', p.capabilities.join(' · '))] : []) });
      });
      if (!packs.length) { cat.controls.push(info('packs', 'no packs reported')); }
      cat.sub = (res.data.enabled ? 'enabled' : 'disabled') + (res.data.safe_mode ? ' · safe mode' : '') + ' · grants are separate';
    } else {
      cat.controls = cat.controls.concat(degraded(res.status, 'Integrations unavailable — GET /v1/console/integrations'));
    }
    // Source connectors (secrets held daemon-side; connect flows are mutating).
    cat.controls.push({ t: 'exp', label: 'GitHub', sub: 'repos · PRs · issues → facts', badge: 'source',
      desc: 'Sync GitHub into the fact store. The PAT is held encrypted by the daemon — never in browser storage.',
      controls: [info('status', 'not connected'),
        { t: 'input', k: 'gh_pat', label: 'personal access token', ph: 'ghp_…', mono: true, secret: true, mut: true },
        { t: 'toggle', k: 'gh_skiptls', label: 'skip TLS verify (dev only)', v: false, mut: true },
        mbtn('Verify connection')] });
    cat.controls.push({ t: 'exp', label: 'OpenAI-compatible LLM', sub: 'embeddings · chat · model discovery', badge: 'source',
      desc: 'Connect any OpenAI-compatible endpoint. The API key is held encrypted by the daemon.',
      controls: [info('status', 'not connected'),
        { t: 'select', k: 'oa_model', label: 'default model', options: ['none', 'gpt-5.5', 'gpt-4o'], v: 'none', mut: true },
        { t: 'input', k: 'oa_key', label: 'API key', ph: 'sk-…', mono: true, secret: true, mut: true },
        { t: 'input', k: 'oa_org', label: 'organisation', ph: 'org-…', mono: true, mut: true },
        mbtn('Test call')] });
    var grants = { h: 'Grants', sub: 'install alone never grants tool access', controls: [info('active grants', '—'), rbtn('Review grants')] };
    if (res.ok && res.data) {
      var n = Array.isArray(res.data.grants) ? res.data.grants.length : (res.data.grants && res.data.grants.count);
      if (n != null) { grants.controls[0].v = n + ' active'; }
    }
    return [cat, grants];
  }

  function buildExtensions(res) {
    var installed = { h: 'Installed', wide: true, controls: [{ t: 'search', ph: 'Filter extensions…' }] };
    if (res.ok && res.data) {
      var list = arr(res.data.extensions);
      installed.h = 'Installed · ' + (res.data.count != null ? res.data.count : list.length);
      if (list.length) {
        list.forEach(function (x) {
          var id = x.id || x.name;
          installed.controls.push({ t: 'exp', k: 'ext_' + String(id).replace(/[^a-zA-Z0-9]/g, '_'), label: id, sub: x.kind || 'extension', badge: x.version ? 'v' + x.version : 'installed', v: true,
            desc: x.description || '', controls: [info('kind', x.kind || 'extension')].concat(arr(x.capabilities).length ? [info('capabilities', x.capabilities.join(' · '))] : []) });
        });
      } else { installed.controls.push(info('none installed', res.data.allow_unsigned_dev ? 'unsigned dev installs allowed' : '—')); }
    } else { installed.controls = installed.controls.concat(degraded(res.status, 'Extensions unavailable — GET /v1/extensions')); }
    var keys = { h: 'Trusted signing keys', sub: 'manifests verify against this keyring', wide: true,
      controls: [
        { t: 'input', k: 'key_fpr', label: 'passport fingerprint', ph: 'fp:…', mono: true, mut: true },
        { t: 'select', k: 'key_tier', label: 'trust tier', options: ['unknown', 'community_reviewed', 'locally_signed', 'first_party'], v: 'community_reviewed', mut: true },
        { t: 'input', k: 'key_pub', label: 'public key', ph: 'ed25519:…', mono: true, mut: true },
        mbtn('Add key')
      ] };
    var install = { h: 'Install manifest', wide: true,
      controls: [{ t: 'input', k: 'manifest_url', label: 'manifest URL / path', ph: 'https://… or ./ext.json', mono: true, mut: true }, mbtn('Install')] };
    return [installed, keys, install];
  }

  function buildIdentity(res) {
    var head = { h: 'Candidates', sub: 'proposals only — candidates never resolve until confirmed', wide: true, controls: [{ t: 'search', ph: 'Filter identity candidates…' }] };
    if (res.ok && res.data) {
      var kids = arr(res.data.candidates);
      kids.forEach(function (c) {
        var id = c.candidate_id || c.id; var status = String(c.status || 'proposed');
        var actions = status === 'proposed'
          ? [mbtn('Stage confirm ' + id, { hint: 'fills the proof form below with candidate ids' }), mbtn('Reject ' + id, { danger: true })]
          : [];
        head.controls.push({ t: 'exp', label: id, sub: c.sub || (c.observed_subject || ''), badge: status,
          controls: [info('status', status), info('subject', c.observed_subject || '—')].concat(actions) });
      });
      if (!kids.length) { head.controls.push(info('none', 'no identity candidates')); }
      head.sub = kids.length + ' candidates · /v1/identity/candidates';
    } else { head.controls = head.controls.concat(degraded(res.status, 'Identity candidates unavailable — GET /v1/identity/candidates')); }
    var proof = { h: 'Confirmation proof', sub: 'paste the existing cross-signature ceremony output', wide: true,
      controls: [
        { t: 'input', k: 'ic_candidate_id', label: 'candidate id', ph: 'cl_…', mono: true, mut: true },
        { t: 'input', k: 'ic_local_passport_id', label: 'local passport id', v: 'personal-default', mono: true, mut: true },
        { t: 'input', k: 'ic_remote_fpr', label: 'remote fingerprint', ph: 'p_…', mono: true, mut: true },
        { t: 'input', k: 'ic_remote_public_key_hex', label: 'remote public key hex', ph: '64 hex chars', mono: true, mut: true },
        { t: 'input', k: 'ic_created_at', label: 'created at', ph: '2026-06-15T00:00:00Z', mono: true, mut: true },
        { t: 'input', k: 'ic_sig_local', label: 'sig local', ph: '128 hex chars', mono: true, mut: true },
        { t: 'input', k: 'ic_sig_remote', label: 'sig remote', ph: '128 hex chars', mono: true, mut: true },
        mbtn('Confirm candidate', { danger: true, hint: 'creates the resolving identity_link only after both signatures verify' })
      ] };
    return [head, proof];
  }

  function buildCoord(res) {
    if (res.status === 404 || res.status === 400) {
      return [{ h: 'Live board', sub: 'coordination plane off', wide: true, controls: [info('disabled', 'Coordination plane disabled — set CORECRUXD_COORD=1'), info('endpoint', 'GET /v1/coord/active · POST /v1/coord/announce')] }];
    }
    if (!res.ok || !res.data) { return [{ h: 'Live board', wide: true, controls: degraded(res.status, 'Live board unavailable — GET /v1/coord/active') }]; }
    var ses = arr(res.data.active_sessions);
    var now = res.data.now_unix_ms || Date.now();
    var ago = function (ms) { if (ms == null) { return null; } var s = Math.max(0, Math.round((now - ms) / 1000)); return s < 60 ? 'seen ' + s + 's ago' : 'seen ' + Math.round(s / 60) + 'm ago'; };
    var rows = ses.map(function (s) {
      var i = s.intent || {};
      return { t: 'exp', label: (s.session_id_hex || '?').slice(0, 8) + ' · ' + (s.passport_id || '—'), sub: [i.execplan_slug ? (i.execplan_slug + (i.milestone ? ' @ ' + i.milestone : '')) : null, i.note, ago(s.last_seen_at_unix_ms)].filter(Boolean).join(' · '), badge: 'live',
        controls: [['passport', s.passport_id], ['tenant', s.tenant_id], ['execplan', i.execplan_slug], ['milestone', i.milestone], ['paths', arr(i.paths).join(', ') || null], ['holds', arr(s.leases).map(function (l) { return l.resource; }).join(', ') || null]]
          .filter(function (kv) { return kv[1] != null && kv[1] !== ''; }).map(function (kv) { return info(kv[0], String(kv[1])); }) };
    });
    return [{ h: 'Live board', sub: ses.length + ' live session' + (ses.length === 1 ? '' : 's') + ' · /v1/coord/active', wide: true, controls: rows.length ? rows : [info('quiet', 'no sessions live right now')] }];
  }

  function buildOrchestrators(res) {
    if (res.status === 404) { return [{ h: 'Orchestrators', sub: 'off', wide: true, controls: [info('disabled', 'Orchestrators disabled — set CORECRUXD_ORCHESTRATORS=1'), info('mcp', 'create_orchestrator · attach · detach · list')] }]; }
    if (!res.ok || !res.data) { return [{ h: 'Orchestrators', wide: true, controls: degraded(res.status, 'Orchestrators unavailable — GET /v1/orchestrators') }]; }
    var orcs = arr(res.data.orchestrators || res.data);
    var rows = orcs.map(function (o) {
      return { t: 'exp', label: o.name || o.id, sub: (o.created_by_passport || '') + ' · ' + arr(o.members).length + ' members', badge: o.state || 'orchestrator',
        controls: [['id', o.id], ['assignee', o.created_by_passport], ['state', o.state], ['members', String(arr(o.members).length)]].filter(function (kv) { return kv[1] != null; }).map(function (kv) { return info(kv[0], String(kv[1])); }) };
    });
    return [{ h: 'Orchestrators', sub: orcs.length + ' orchestrator' + (orcs.length === 1 ? '' : 's') + ' · /v1/orchestrators', wide: true, controls: rows.length ? rows : [info('none', 'no orchestrators active')] }];
  }

  function buildPunchcards(res) {
    if (res.status === 404) { return [{ h: 'Punchcards', sub: 'off', wide: true, controls: [info('disabled', 'Punchcards disabled — set CORECRUXD_PUNCHCARD=advisory|enforce'), info('mcp', 'punch_in · punch_out · check_punchcard · list_punchcards')] }]; }
    if (!res.ok || !res.data) { return [{ h: 'Punchcards', wide: true, controls: degraded(res.status, 'Punchcards unavailable — GET /v1/punchcards') }]; }
    var cards = arr(res.data.punchcards || res.data);
    var byHolder = {};
    cards.forEach(function (c) { var h = c.holder_passport || c.holder || '—'; (byHolder[h] = byHolder[h] || []).push(c); });
    var rows = Object.keys(byHolder).map(function (h) {
      var ls = byHolder[h];
      return { t: 'exp', label: 'Holder · ' + h, sub: ls.length + ' held', badge: 'leases',
        controls: ls.map(function (c) { return info(c.resource, [c.status, c.mode].filter(Boolean).join(' · ')); }) };
    });
    return [{ h: 'Punchcards', sub: cards.length + ' lease' + (cards.length === 1 ? '' : 's') + ' · /v1/punchcards', wide: true, controls: rows.length ? rows : [info('none', 'no leases held')] }];
  }

  function buildLaneWeights(res) {
    // Whole page is operator-only; the read is only reached by operators.
    var d = (res.data && res.ok) ? res.data : {};
    var scopeRow = { h: 'Scope', sub: 'global defaults or tenant overlay', wide: true,
      controls: [
        { t: 'select', k: 'tenant_pick', label: 'tenant', options: ['', 'default', 'lme-m', 'lme-s', 'personal'], v: '', mut: true, desc: 'Pick global defaults or a discovered tenant.' },
        { t: 'input', k: 'tenant_id', label: 'custom tenant', ph: 'optional tenant id', mono: true, mut: true },
        { t: 'toggle', k: 'fusion_rrf', label: 'enable RRF fusion', v: !!d.fusion_rrf_enabled, mut: true },
        { t: 'input', k: 'reason', label: 'reason', ph: 'operator note for this change', mut: true },
        info('CoreCrux', res.ok ? [d.scope || 'global', d.source ? ('source ' + d.source) : null, d.fusion_rrf_enabled ? 'RRF on' : 'RRF off'].filter(Boolean).join(' · ') : ('unavailable · ' + (res.status || 'network'))),
        info('deep link', '#/memory/cx-lane-weights'),
        rbtn('Load lane weights', { hint: 'reads CoreCrux global/tenant boost overlay' }),
        mbtn('Apply lane weights', { hint: 'writes FUSION_RRF_LANE_WEIGHTS through the daemon to CoreCrux' })
      ] };
    var presetRow = { h: 'Presets', sub: 'staged locally only; review the form before applying', wide: true,
      controls: [
        { t: 'select', k: 'preset', label: 'preset', options: ['', 'baseline', 'lexical', 'dense', 'graph'], v: '', mut: true },
        rbtn('Stage preset', { hint: 'fills the weights form only' }),
        mbtn('Reset lane weights', { danger: true, hint: 'clears only the lane-weight overlay keys for this scope' })
      ] };
    var weights = laneWeightControls();
    // Seed live weights when present.
    if (res.ok && d.weights) { weights.forEach(function (c) { var k = c.k.slice(2); if (d.weights[k] != null) { c.v = String(d.weights[k]); } }); }
    var weightRow = { h: 'Weights', sub: (res.ok ? ('resolved from ' + (d.source || 'default') + ' overlay') : 'not loaded') + ' · non-negative RRF multipliers', wide: true, controls: weights };
    return [scopeRow, presetRow, weightRow];
  }

  function buildSettings(res) {
    var s = (res.ok && res.data) ? res.data : {};
    var a = s.auth || {}, e = s.embedding || {};
    // The status pill dropped the origin + node id (item 3); they land here.
    var origin = (typeof window !== 'undefined' && window.location && window.location.origin) ? window.location.origin : '—';
    return [
      { h: 'Node', sub: 'this daemon origin + identity',
        controls: [
          info('origin', origin),
          info('node id', str(get(s, ['node_id']) || get(s, ['daemon', 'node_id']))),
          info('build', str(get(s, ['daemon', 'build', 'version'])))
        ] },
      { h: 'Access posture', sub: 'who may call :14800',
        controls: [
          { t: 'select', k: 'auth_mode', label: 'auth mode', options: arr(a.supported_modes).length ? a.supported_modes.slice() : ['off', 'dev_scopes', 'jwt_hs256', 'jwt_jwks'], v: a.chosen_mode || a.running_mode || 'off', mut: true },
          { t: 'toggle', k: 'require_bind', label: 'require passport binding', v: true, mut: true }
        ] },
      { h: 'Embedding (semantic retrieval)', sub: 'Crux ships no embedding model — point at your endpoint',
        controls: [
          { t: 'toggle', k: 'embed_on', label: 'enable embedding retrieval', v: e.enabled_intent != null ? !!e.enabled_intent : !!e.active, mut: true },
          { t: 'input', k: 'embed_url', label: 'endpoint URL', ph: 'http://localhost:11434', v: e.chosen_url || e.active_url || '', mono: true, mut: true },
          mbtn('Probe endpoint', { hint: 'fetches available models' }),
          { t: 'select', k: 'embed_model', label: 'model', options: ['—', 'bge-m3', 'nomic-embed-text', 'e5-large-v2'], v: e.chosen_model || e.active_model || '—', mut: true }
        ] },
      { h: 'Memory & freshness', sub: 'decay engine horizons',
        controls: [
          { t: 'toggle', k: 'decay_on', label: 'decay engine', v: true, mut: true },
          { t: 'select', k: 'h_volatile', label: 'volatile horizon', options: ['12h', '24h', '48h'], v: '24h', mut: true },
          { t: 'select', k: 'h_medium', label: 'medium horizon', options: ['7d', '35d', '90d'], v: '35d', mut: true },
          { t: 'select', k: 'h_stable', label: 'stable horizon', options: ['180d', '365d'], v: '365d', mut: true },
          mbtn('Run sweep now', { hint: 'memory_sweep_candidates' })
        ] },
      { h: 'Coordination & leases',
        controls: [
          { t: 'select', k: 'punchcards', label: 'punchcards', options: ['off', 'advisory', 'enforce'], v: 'advisory', mut: true },
          { t: 'toggle', k: 'coord_on', label: 'coordination plane (CORECRUXD_COORD)', v: true, mut: true },
          { t: 'toggle', k: 'observe_on', label: 'observe / audit trail (CORECRUXD_OBSERVE)', v: false, mut: true }
        ] },
      { h: 'Retention',
        controls: [
          { t: 'input', k: 'receipt_days', label: 'receipts (days)', v: '90', mono: true, mut: true },
          info('execplan facts', 'indefinite — operator delete only'),
          mbtn('Export audit bundle', { hint: 'audit_export_bundle' })
        ] },
      { h: 'Onboarding', controls: [mbtn('Re-run onboarding', { hint: 'first-run wizard shows on next load' })] },
      { h: 'Daemon',
        controls: [
          info('build', s && s.daemon ? [get(s, ['daemon', 'build', 'version']), ':14800'].filter(Boolean).join(' · ') : ':14800'),
          mbtn('Restart daemon', { danger: true, hint: 'needs restart: unless-stopped policy' })
        ] },
      { h: 'Appearance', sub: 'applies immediately', controls: [{ t: 'theme' }, info('canvas', '2D | 3D toolbar switch')] }
    ];
  }

  // A full-width trend card (item 5). No real time-series endpoint exists for
  // the cost lens yet, so the chart renders from a demo fixture when demo mode
  // is on, else an honest empty state — never a series faked from one scalar.
  function costTrend() {
    return { h: 'Spend over time', wide: true, controls: [
      { t: 'chart', title: 'Tokens in', sub: 'measured usage over time (message.usage)', demoKey: 'costSeries', fmt: 'compact', range: 'week',
        hint: 'the cost lens has no bucketed series endpoint yet — enable demo mode (?demo=1) to preview' }
    ] };
  }
  function buildCost(res) {
    var sel = { h: 'Session', sub: 'measured from the transcript message.usage (not an estimate)', wide: true, controls: [{ t: 'select', k: 'sess', label: 'session', options: ['latest'], v: 'latest' }] };
    if (!res.ok || !res.data) {
      sel.controls.push(info('status', 'cost lens off or unreachable — set CORECRUXD_FEATURE_COST_LENS=1'));
      return [sel, { h: 'Headline', wide: true, controls: [info('no data', 'run:  corecruxctl session cost --post')] }, costTrend()];
    }
    var d = res.data;
    if (!d.has_report) {
      sel.controls.push(info('status', arr(d.sessions).length ? 'pick a session above' : 'no reports posted yet'));
      return [sel, { h: 'Headline', wide: true, controls: [info('get started', 'run:  corecruxctl session cost --post   (then refresh)')] }, costTrend()];
    }
    var r = (d.report && d.report.report) || {}, h = r.headline || {}, m = r.measured || {};
    sel.controls.push(info('status', (r.source || 'report') + ' · received ' + String((d.report && d.report.received_at) || '').slice(0, 16).replace('T', ' ')));
    var head = { h: 'Headline', sub: 'carried context per model call', wide: true, controls: [
      info('context / turn', fmtNum(h.context_tokens_per_turn) + ' tokens re-read per model call'),
      info('cache replay', Math.round(h.cache_read_to_output_ratio || 0) + '× output'),
      info('turns / tasks', (h.assistant_turns || 0) + ' / ' + (h.tasks || 0) + ' · ' + (h.segments || 0) + ' segment(s)'),
      info('fixed prefix', Math.round(h.prefix_pct || 0) + '% of carried context (re-read every turn)')
    ] };
    var mx = Math.max.apply(null, [1].concat(arr(r.buckets).map(function (b) { return b.pct; })));
    var where = { h: 'Where it goes', sub: 'carried-cost buckets', wide: true, controls: arr(r.buckets).map(function (b) {
      return { t: 'bar', label: b.source, pct: Math.max(2, Math.round(100 * b.pct / mx)), v: Math.round(b.pct) + '%', tone: (b.source === 'session_prefix' || b.pct >= 20) ? 'err' : undefined };
    }) };
    if (!where.controls.length) { where.controls = [info('—', 'no buckets')]; }
    var levers = { h: 'What you can do to reduce burn', sub: arr(r.levers).length + ' grounded recommendation(s)', wide: true, controls: arr(r.levers).map(function (lv) {
      return { t: 'exp', label: (lv.severity ? '● ' + String(lv.severity).toUpperCase() + '  ' : '') + lv.title, sub: lv.est_pct ? ('addresses ~' + Math.round(lv.est_pct) + '% of carried cost') : '', badge: lv.severity || 'lever', controls: [info('how', lv.detail || '')] };
    }) };
    if (!levers.controls.length) { levers.controls = [info('—', 'already lean')]; }
    return [sel, head, where, levers, costTrend()];
  }

  // ---- Engine mediation (M4) — read-only, daemon-mediated summary card ----
  // Both Trust › Mediation and Meters › Usage surface the Engine through the
  // daemon proxy GET /v1/console/engine/summary (CruxApi allowlist literal).
  // The browser never addresses the Engine directly. 404 ⇒ mediation is off
  // (CORECRUXD_ENGINE_BASE_URL unset on the daemon) ⇒ feature-off copy; other
  // failures ⇒ the existing degraded pattern.
  function engineMediatedSection(res) {
    var sec = { h: 'Engine (mediated)', sub: 'read-only · via daemon origin · never browser → Engine', wide: true };
    if (res && res.status === 404) {
      sec.controls = [info('mediation', 'off')]
        .concat(degraded(res.status, 'Engine mediation off — set CORECRUXD_ENGINE_BASE_URL on the daemon'));
      return sec;
    }
    if (!res || !res.ok || !res.data) {
      sec.controls = degraded(res ? res.status : 0, 'Engine summary unavailable — GET /v1/console/engine/summary');
      return sec;
    }
    var d = res.data;
    sec.controls = [
      info('mediated', d.mediated === true ? 'yes · daemon-proxied' : '—'),
      info('engine', d.engine_reachable ? ('reachable · ' + str(d.engine_latency_ms) + ' ms') : 'unreachable'),
      info('fetched', str(d.fetched_at_unix_ms))
    ];
    return sec;
  }
  // cx-usage gets a full-width trend card too (item 5). Same posture as the cost
  // trend: demo fixture when demo mode is on, else an honest empty state.
  function usageTrend() {
    return { h: 'Call volume over time', wide: true, controls: [
      { t: 'chart', title: 'Tokens in / period', sub: 'aggregate call volume', demoKey: 'usageSeries', fmt: 'compact', range: 'week',
        hint: '/v1/observations/aggregate has no bucketed series yet — enable demo mode (?demo=1) to preview' }
    ] };
  }
  function buildUsageEngine(res) { return STATIC['cx-usage'].concat([usageTrend(), engineMediatedSection(res)]); }
  function buildMediationEngine(res) { return STATIC['cx-mediation'].concat([engineMediatedSection(res)]); }

  // =======================================================================
  //  Ported legacy scopes (Professional mode only). The legacy console
  //  (crates/corecruxd/console/index.html) carried four scopes beyond CX —
  //  DX (Docs), GX (Global), AX (Agent), IX (Infra). Each portable-with-a-real-
  //  GET-endpoint section is ported here as a Pro-mode page; the rest are folded
  //  into an existing v2 home or explicitly deferred. The LEGACY_PORT manifest
  //  (below) is the machine-readable checklist that proves nothing is dropped.
  // =======================================================================

  // IX / Infra — one real endpoint (/v1/console/infra/summary, in the api.js
  // allowlist) feeds all five legacy IX panels: onboarding checklist, machines,
  // auth rails, config bundles and session sync. Ported from the legacy
  // txInfra* transforms (index.html:1513-1546).
  function buildInfra(res) {
    if (!res.ok || !res.data) {
      return [{ h: 'Infra', wide: true, controls: degraded(res.status, 'Infra summary unavailable — GET /v1/console/infra/summary (needs console:read)') }];
    }
    var d = res.data, s = d.s || d, c = s.checklist || {}, r = s.rails || {};
    var tick = function (b) { return b ? '✓' : '○'; };
    var checklist = { h: 'Onboarding checklist', sub: 'machine setup · corecruxctl login', wide: true, controls: [
      info('login auth', tick(c.auth_configured) + ' ' + (s.auth_mode || '?')),
      info('MCP', tick(c.mcp_enabled) + ' ' + (c.mcp_enabled ? 'enabled' : 'disabled')),
      info('machines captured', (c.machines_registered || 0) + ' registered · ' + (c.machines_with_hooks || 0) + ' with hooks')
    ] };
    var rails = { h: 'Auth rails', sub: 'what is enabled', wide: true, controls: [
      info('tailscale identity', r.tailscale ? 'enabled' : 'disabled'),
      info('device grant', r.device ? 'enabled' : 'disabled'),
      info('agent token → HTTP', r.http_accept_agent_tokens ? 'enabled' : 'disabled')
    ] };
    var machines = arr(d.machines);
    var mSec = { h: 'Machines', sub: machines.length + ' logged into this daemon', wide: true,
      controls: [{ t: 'search', ph: 'Filter machines…' }].concat(machines.length ? machines.map(function (m) {
        var rec = m.record || {};
        return { t: 'exp', label: m.id, sub: [rec.os, rec.rail].filter(Boolean).join(' · ') || 'machine', badge: rec.hooks_installed ? 'hooks' : 'no hooks',
          meta: [rec.tailnet_ip, rec.ctl_version].filter(Boolean).join(' · '),
          controls: [['tailnet_ip', rec.tailnet_ip], ['os', (rec.os || '?') + '/' + (rec.arch || '?')], ['rail', rec.rail], ['hooks', rec.hooks_installed ? 'yes' : 'no'], ['ctl', rec.ctl_version]]
            .filter(function (kv) { return kv[1] != null; }).map(function (kv) { return info(kv[0], String(kv[1])); }) };
      }) : [info('none', 'no machines captured — run corecruxctl login')]) };
    var configs = arr(d.configs);
    var cfgSec = { h: 'Config bundles', sub: 'saved ~/.claude configs (secrets redacted)', wide: true,
      controls: configs.length ? configs.map(function (cf) { return info(cf.name, (cf.files || 0) + ' files · from ' + (cf.source_host || '?')); }) : [info('none', 'no config bundles — corecruxctl config push <name>')] };
    var syncs = arr(d.sessions);
    var syncSec = { h: 'Session sync', sub: 'shared session snapshots across machines', wide: true,
      controls: syncs.length ? syncs.map(function (ss) { return info(ss.id, (ss.bytes || 0) + ' bytes · from ' + (ss.source_host || '?')); }) : [info('none', 'no shared session snapshots')] };
    return [checklist, rails, mSec, cfgSec, syncSec];
  }

  // GX / Global — shared surfaces that outlive a session. Engrams load live
  // (/v1/engrams, allowlisted); the ScoreCrux bench board + hypernym sites have
  // no local endpoint (deferred, honest notes); the fact store's real home is
  // Memory › Facts.
  function buildGlobal(res) {
    var engrams;
    if (!res.ok || !res.data) {
      engrams = { h: 'Engrams', sub: 'shared memory pinned into every boot', wide: true, controls: [{ t: 'search', ph: 'Filter engrams…' }].concat(degraded(res.status, 'Engrams unavailable — GET /v1/engrams')) };
    } else {
      var list = arr(res.data.engrams || res.data.items || res.data);
      engrams = { h: 'Engrams', sub: list.length + ' shared engram' + (list.length === 1 ? '' : 's') + ' · /v1/engrams', wide: true,
        controls: [{ t: 'search', ph: 'Filter engrams…' }].concat(list.length ? list.map(function (e) {
          var id = e.name || e.id || e.entity || 'engram';
          return { t: 'exp', label: id, sub: [e.kind, e.scope].filter(Boolean).join(' · ') || 'engram', badge: e.pinned ? 'pinned' : 'engram',
            meta: str(e.updated_at || e.stored_at || ''),
            controls: [info('kind', e.kind || 'engram')].concat((e.summary || e.value) ? [info('summary', clip(e.summary || e.value, 140))] : []) };
        }) : [info('none', 'no shared engrams')]) };
    }
    var bench = { h: 'Bench', sub: 'ScoreCrux benchmark board', wide: true, controls: [
      info('deferred', 'the ScoreCrux board is an external surface — this daemon has no local bench endpoint'),
      info('scorecrux.com', 'the published leaderboard lives off-daemon')
    ] };
    var sites = { h: 'Sites', sub: 'hypernym surface', wide: true, controls: [
      info('deferred', 'no hypernym-sites endpoint on this daemon build')
    ] };
    var factstore = { h: 'Fact store', sub: 'the durable record', wide: true, controls: [
      info('home', 'the fact store surfaces at Memory › Facts and Memory › Memory'),
      info('endpoint', 'GET /v1/console/facts')
    ] };
    return [engrams, bench, sites, factstore];
  }

  // AX / Agent — the agent-side cockpit. MCP tools load live with their
  // 30-day call rollup (/v1/mcp/tools/usage — catalog joined against the
  // agent.tool_invocation.v1 ledger, sorted by calls desc, zeros included);
  // activity / memory / snapshots already have v2 homes; graph opens on the
  // Pro 3D substrate; bulk / handoff / storybook / story / dossiers have no
  // daemon read endpoint (deferred, honest notes).
  function buildAgent(res) {
    var sections = [];
    var tools;
    if (!res.ok || !res.data) {
      tools = { h: 'MCP tools', sub: 'catalog × call ledger · /v1/mcp/tools/usage', wide: true, controls: [{ t: 'search', ph: 'Filter tools…' }].concat(degraded(res.status, 'Tool usage unavailable — GET /v1/mcp/tools/usage')) };
    } else {
      var d = res.data;
      var list = arr(d.tools);
      var errPct = d.calls_total > 0 ? Math.round((d.errors_total / d.calls_total) * 1000) / 10 : 0;
      sections.push({ h: 'Tool surface health', sub: 'window ' + str(d.window) + ' · ledger agent.tool_invocation.v1 · /v1/mcp/tools/usage', wide: true, controls: [
        info('calls', String(d.calls_total || 0) + ' calls · ' + String(d.passports_total || 0) + ' passports · ' + errPct + '% errors'),
        info('catalog', String(d.tools_in_catalog || 0) + ' tools · ' + String(d.tools_called || 0) + ' called · ' + String(d.tools_never_called || 0) + ' never called in window'),
        info('triage', 'unused = demote-from-surface candidates · high err% = friction to fix · filter "unused" or "errors" below')
      ] });
      tools = { h: 'MCP tools', sub: list.length + ' tool' + (list.length === 1 ? '' : 's') + ' · sorted by calls (' + str(d.window) + ') · zeros = never called in window', wide: true,
        controls: [{ t: 'search', ph: 'Filter tools… (try: unused · errors · uncataloged)' }].concat(list.length ? list.map(function (tl) {
          var name = tl.tool || tl.name || 'tool';
          var calls = tl.calls || 0;
          var toolErrPct = calls > 0 ? Math.round(((tl.errors || 0) / calls) * 1000) / 10 : 0;
          // agent.tools_offered.v1 split: 'ignored' = offered to sessions but
          // never called; 'never offered' = absent from every session surface;
          // plain 'unused' = no offered data accrued yet (honest default).
          var unusedBadge = tl.classification === 'never_offered' ? 'never offered'
            : tl.classification === 'offered_never_called' ? 'ignored' : 'unused';
          var badge = calls > 0 ? (String(calls) + '×' + (tl.errors ? ' · errors' : '')) : unusedBadge;
          var meta = calls > 0
            ? (String(tl.passports || 0) + ' passports · p50 ' + str(tl.p50_ms) + 'ms · ~' + String(tl.avg_tokens || 0) + ' tok · last ' + clip(str(tl.last_called), 10))
            : (tl.in_catalog === false ? 'uncataloged (removed/renamed?)'
              : tl.classification === 'never_offered' ? 'in catalog but absent from every session surface'
              : tl.classification === 'offered_never_called' ? ('offered to ' + String(tl.offered_passports || 0) + ' passport(s), never called')
              : 'never called in window');
          return { t: 'exp', label: name, sub: clip(tl.description || '', 90) || (tl.in_catalog === false ? 'not in the current catalog' : 'mcp tool'), badge: badge,
            meta: meta,
            controls: [
              info('description', clip(tl.description || '—', 300)),
              info('calls', String(calls) + (calls > 0 ? ' · ' + String(tl.errors || 0) + ' errors (' + toolErrPct + '%)' : '')),
              info('reach', String(tl.passports || 0) + ' distinct passports'),
              info('cost', 'avg ~' + String(tl.avg_tokens || 0) + ' tokens · p50 ' + str(tl.p50_ms) + ' ms'),
              info('last called', str(tl.last_called)),
              info('in catalog', tl.in_catalog === false ? 'no — called historically but absent from tools/list now' : 'yes')
            ] };
        }) : [info('none', 'no tools reported')]) };
    }
    var cockpit = { h: 'Agent cockpit', sub: 'agent observability — where each legacy AX surface lives now', wide: true, controls: [
      info('activity', 'live tool stream → Overwatch › Activity'),
      info('memory recall', 'agent recall → Memory › Facts / Memory'),
      info('snapshots', 'session captures → Work › Sessions'),
      info('graph', 'context graph → the Pro 3D substrate (below)'),
      link('Open the 3D substrate', '/console-3d/index.html?embed=1', { hint: 'entity graph · shard topology · lane overlay' })
    ] };
    var deferred = { h: 'Not yet ported', sub: 'surfaces with no read endpoint on this daemon', wide: true, controls: [
      info('bulk ops', 'batch import / sweep are mutations — no read surface'),
      info('handoff', 'create_handoff is MCP-only — no list endpoint'),
      info('storybook', 'tile/pattern catalog is a design artifact, not a data feed'),
      info('story', 'call-tree story view stays on the Pro / 3D canvas'),
      info('dossiers', 'per-project — see Work › Projects (/v1/projects/{id}/dossiers)')
    ] };
    sections.push(tools, cockpit, deferred);
    return sections;
  }

  // CX / Workbench (M13a) — the operator deep-machinery surface, ported native
  // (was a link-only fallback to /console/legacy). READ tools load LIVE over
  // /v1/workbench/* (GET): the page loads the contract (/v1/workbench/contract)
  // to enumerate every surface + its live entitlement, and the readsSec panels
  // self-load the GET reads through the api.js client (wbread → CruxApi GET,
  // never a mutation). WRITE tools (context-pack, impact-preflight, policy-
  // simulation, route-probe, capability-audit) stay operator-gated + disabled in
  // STATIC['cx-workbench'] — genuine live writes are deferred to M13b. Legacy
  // ref: index.html cx-workbench PAGES def (index.html:4008-4038, 24 controls:
  // 11 btn / 5 info / 5 input / 3 select).
  function wbBadge(status) {
    if (status === 'enabled') { return 'enabled'; }
    if (status === 'pro_required') { return 'pro'; }
    if (status === 'entitled_not_enabled') { return 'entitled'; }
    return status || 'surface';
  }
  function buildWorkbench(res) {
    var surfaces = (res.ok && res.data) ? arr(res.data.surfaces) : [];
    var rows = surfaces.length ? surfaces.map(function (s) {
      var method = String(s.method || '?');
      var kind = (method.indexOf('GET') >= 0) ? 'read' : 'write · gated (M13b)';
      return { t: 'exp', label: String(s.capability || 'surface'), sub: method + ' ' + str(s.path), badge: wbBadge(s.status),
        controls: [info('method', method), info('path', str(s.path)), info('status', str(s.status)), info('kind', kind)] };
    }) : (res.ok ? [info('surfaces', 'no surfaces reported')] : degraded(res.status, 'Workbench contract unavailable — GET /v1/workbench/contract'));
    var contractSec = { h: 'Workbench contract', sub: 'live tool surface + entitlement · GET /v1/workbench/contract', wide: true,
      controls: [{ t: 'search', ph: 'Filter tools…' }].concat(rows) };
    var readsSec = { h: 'Live read tools', sub: 'GET /v1/workbench/* — pro capabilities gate the payload; nothing here writes', wide: true,
      controls: [
        { t: 'wbread', label: 'API drift', api: 'workbenchApiDrift', query: { tenant_id: 'default' }, hint: 'GET /v1/workbench/api-drift' },
        { t: 'wbread', label: 'Command ledger', api: 'workbenchCommandLedger', query: { tenant_id: 'default' }, hint: 'GET /v1/workbench/command-ledger' },
        { t: 'wbread', label: 'Reasoning timeline', api: 'workbenchReasoningTimeline', query: { tenant_id: 'default' }, hint: 'GET /v1/workbench/reasoning-timeline' },
        { t: 'wbread', label: 'Audit triage', api: 'workbenchAuditTriage', query: { tenant_id: 'default' }, hint: 'GET /v1/workbench/audit-triage' },
        { t: 'wbread', label: 'Agent brief', api: 'workbenchBrief', query: { tenant_id: 'default' }, hint: 'GET /v1/workbench/brief' }
      ] };
    return STATIC['cx-workbench'].concat([contractSec, readsSec]);
  }

  // =======================================================================
  //  Static pages — sections ported directly from the legacy PAGES DSL.
  // =======================================================================

  var STATIC = {
    'cx-activity': [
      { h: 'Live activity', sub: 'the rolling activity log is folded into Work › Activity in this console', wide: true,
        controls: [
          info('stream', 'GET /v1/events/stream?types=activity.appended'),
          info('note', 'the full receipt-cross-walked activity log is the Work › Activity surface in this console — no separate page')
        ] }
    ],
    'cx-usage': [
      { h: 'Periods', sub: 'derived from save_session / pre-compact hooks · /v1/observations/aggregate', wide: true,
        controls: [
          { t: 'select', k: 'win', label: 'window', options: ['7d', '30d', '90d'], v: '7d' },
          { t: 'search', ph: 'Filter sessions / plans…' },
          info('daily avg', '~83k in · 11k out'),
          info('this week', '517k in · 67k out · 75 turns'),
          info('this month', '2.22M in · 288k out · 13 sessions')
        ] },
      { h: 'Savings vs standard session', sub: 'estimate — boot banner + injected facts replace context re-reads', wide: true,
        controls: [
          { t: 'bar', label: 'standard session (est.)', pct: 100, v: '750k in/wk', tone: 'err' },
          { t: 'bar', label: 'with Crux Daemon', pct: 69, v: '517k in/wk', tone: 'ok' },
          info('saved', '≈233k in tokens/week · −31%')
        ] }
    ],
    'cx-documents': [
      { h: 'Tenants & documents', sub: '/v1/console/tenants · click a tenant to expand its documents', wide: true,
        controls: [
          { t: 'search', ph: 'Filter tenants / documents…' },
          { t: 'exp', label: 'lme-s', sub: 'work · 3 docs · 25 chunks · ingested 2026-05-16', badge: 'tenant',
            controls: [info('sess_7f3a · travel', '12 chunks · 2026-05-16'), info('sess_91be · hotels', '8 chunks'), info('sess_c401 · diet', '5 chunks')] },
          { t: 'exp', label: 'personal', sub: '1 doc · private — never syncs', badge: 'private', controls: [info('note_01', 'private')] }
        ] },
      { h: 'Add documents', sub: 'ingest is receipted like any other write', wide: true,
        controls: [
          rbtn('Choose folder…', { hint: 'browser picker fills the doc prefix' }),
          { t: 'input', k: 'ing_path', label: 'source path / glob', ph: '~/docs/**/*.md or /srv/corpus/', mono: true, mut: true },
          { t: 'input', k: 'ing_prefix', label: 'doc prefix', ph: 'auto from selection — e.g. docs/', mono: true, mut: true },
          { t: 'select', k: 'ing_tenant', label: 'target tenant', options: ['default', 'lme-s', 'lme-m', 'personal', 'new tenant…'], v: 'default', mut: true },
          { t: 'select', k: 'ing_chunking', label: 'chunking profile', options: ['default · 512 tok', 'markdown-aware', 'code-aware'], v: 'default · 512 tok', mut: true },
          { t: 'toggle', k: 'ing_ner', label: 'extract entities (NER)', v: true, mut: true },
          mbtn('Scan path', { hint: '/v1/workspace/scan — counts candidates first' }),
          mbtn('Queue ingest', { hint: 'stores ingest:queue fact — the agent picks it up' })
        ] }
    ],
    'cx-receipts': [
      { h: 'CROWN receipts', sub: 'browser-local lookup history — the daemon has no list endpoint; verify by id', wide: true,
        controls: [
          { t: 'search', ph: 'Filter receipts…' },
          { t: 'input', k: 'rcpt_id', label: 'receipt id', ph: 'crn_…', mono: true },
          rbtn('Verify receipt', { hint: 'opens the verify dock — GET /verification + /signature' }),
          { t: 'exp', label: 'CROWN crn_8f21…', sub: 'default · demo · drill →', badge: 'verified',
            controls: [info('receipt_id', 'crn_8f21…'), info('tenant', 'default'), info('seq', '1'), info('payload_hash', '9f2c41d8…'), info('↳ verification', 'PASS · Ed25519 signature valid'), info('↳ signature', 'seq 2 · application/cbor')] }
        ] }
    ],
    'cx-mediation': [
      { h: 'Mediation plane', sub: 'the gateway plane — identity, capability ladder, foresight', wide: true,
        controls: [
          { t: 'search', ph: 'Filter mediation rows…' },
          { t: 'exp', label: 'Principal', sub: 'ce:…:local · tier basic', badge: 'identity',
            controls: [info('passport', 'resolved at session bind'), info('capabilities', '14 loaded at session bind'), rbtn('Resolve principal', { hint: 'GET /v1/principal/resolve' })] },
          { t: 'exp', label: 'Capability ladder', sub: 'tiered capabilities — free → gated', badge: 'policy',
            controls: [info('session_context · journal_append', 'free tier'), info('approval.risk_tiered', 'gated · Art.14'), rbtn('View full ladder', { hint: 'GET /v1/policy/capabilities' })] },
          { t: 'exp', label: 'Foresight (Art. 15)', sub: 'predict consequences before a high-risk action runs', badge: 'enrich',
            controls: [{ t: 'input', k: 'enrich_action', label: 'action to preview', ph: 'delete tenant lme-s', mono: true }, rbtn('Preview consequences', { hint: 'POST /v1/actions/enrich — read-only foresight' })] }
        ] },
      { h: 'Results', sub: 'ladder / principal / foresight responses land here', wide: true, controls: [info('—', 'run an action above to populate this card')] }
    ],
    // cx-workbench (M13a) — native port. The live contract + read panels are
    // appended by buildWorkbench (over GET /v1/workbench/contract); these STATIC
    // sections carry the ported legacy tool cards (index.html:4008-4038): read
    // tools as info/inert-read buttons, write tools as operator-gated mbtn
    // placeholders (mut:true → hidden for customers, disabled "wired in M3+" for
    // operators). No live write is introduced here — writes land in M13b.
    'cx-workbench': [
      { h: 'Workbench', sub: 'operator tooling over /v1/workbench/* — read tools load live; write tools are gated (M13b)', wide: true,
        controls: [
          info('surface', '/v1/workbench/contract enumerates every tool + its entitlement'),
          { t: 'input', k: 'wb_tenant', label: 'tenant (read scope)', ph: 'default', v: 'default', mono: true },
          info('note', 'reads run through the GET client; writes stay operator-gated until M13b')
        ] },
      { h: 'Briefing & context', sub: 'agent brief + command ledger (reads) · context pack (write, live)', wide: true,
        controls: [
          info('agent brief', 'GET /v1/workbench/brief — tenant memory, sessions, constraints, open work'),
          info('command ledger', 'GET /v1/workbench/command-ledger — recorded command metadata'),
          { t: 'input', k: 'wb_ctx_tenant', label: 'pack tenant', v: 'default', mono: true, mut: true },
          { t: 'input', k: 'wb_ctx_query', label: 'pack query', ph: 'what to assemble context for', mut: true },
          mbtn('Build context pack', { hint: 'POST /v1/workbench/context-pack — writes a receipted pack fact' })
        ] },
      { h: 'Preflight & policy', sub: 'impact preflight · policy simulation (writes, live)', wide: true,
        controls: [
          { t: 'input', k: 'wb_target', label: 'impact target · changed paths', ph: 'crates/corecruxd/src/http, crates/x/y.rs', mono: true, mut: true },
          mbtn('Run impact preflight', { hint: 'POST /v1/workbench/impact-preflight — writes a preflight fact' }),
          { t: 'select', k: 'wb_policy', label: 'policy profile', options: ['eu-ai-act', 'workspace', 'none'], v: 'eu-ai-act', mut: true },
          { t: 'input', k: 'wb_sim_action', label: 'action to simulate', ph: 'deploy corecruxd to gpu-1', mut: true },
          mbtn('Simulate policy', { hint: 'POST /v1/workbench/policy-simulation — writes a simulation fact' })
        ] },
      { h: 'Drift & timeline', sub: 'api drift · reasoning timeline (reads) · route probe (write, live)', wide: true,
        controls: [
          info('api drift', 'GET /v1/workbench/api-drift — route/tool contract drift'),
          info('reasoning timeline', 'GET /v1/workbench/reasoning-timeline — receipted event stream'),
          { t: 'input', k: 'wb_route', label: 'route to probe', ph: 'POST /v1/work/gate/{id}/approve', mono: true, mut: true },
          mbtn('Probe route', { hint: 'POST /v1/workbench/route-probe — admin:write scoped' })
        ] },
      { h: 'Feature registry', sub: '/v1/features/capabilities — gap + promise coverage (reads) · audit (write, live)', wide: true,
        controls: [
          info('gap analysis', 'GET /v1/features/capabilities/analysis/gaps'),
          info('promise coverage', 'GET /v1/features/capabilities/analysis/promises'),
          { t: 'input', k: 'wb_cap_id', label: 'capability id', ph: 'cap-…', mono: true, mut: true },
          { t: 'select', k: 'wb_cap_status', label: 'audit status', options: ['pass', 'partial', 'fail'], v: 'pass', mut: true },
          { t: 'input', k: 'wb_cap_notes', label: 'audit notes', ph: 'what was audited', mut: true },
          mbtn('Record capability audit', { hint: 'POST …/capabilities/{id}/audit — writes an audit' })
        ] },
      { h: 'Query workbench', sub: '/v1/query/* curated read-POST lanes — the live search surface is Explorer', wide: true,
        controls: [
          { t: 'search', ph: 'Filter query lanes…' },
          { t: 'input', k: 'wbq_tenant', label: 'tenant', v: 'default', mono: true },
          { t: 'input', k: 'wbq_query', label: 'text search', ph: 'retrieval cascade', mono: true },
          rbtn('Run text search', { hint: 'POST /v1/query/text-search — curated read-POST · runs live in Explorer' }),
          { t: 'input', k: 'wbq_seeds', label: 'graph seeds · artifact ids', ph: '12, 44', mono: true },
          rbtn('Graph expand', { hint: 'POST /v1/query/graph-expand — curated read-POST' }),
          { t: 'select', k: 'wbq_window', label: 'time window', options: ['24h', '7d', '30d'], v: '24h' },
          rbtn('Time range', { hint: 'POST /v1/query/time-range — curated read-POST' }),
          rbtn('Browse results as graph', { hint: 'opens the Canvas relation graph' })
        ] },
      { h: 'Entities', sub: '/v1/entities/{kind}/{id} + /history (read)', wide: true,
        controls: [
          { t: 'select', k: 'wbe_kind', label: 'kind', options: ['capability'], v: 'capability' },
          { t: 'input', k: 'wbe_id', label: 'id', ph: 'entity id', mono: true },
          rbtn('Load entity', { hint: 'GET /v1/entities/{kind}/{id}' })
        ] },
      { h: '3D substrate', sub: 'the graph/topology view renders on the Pro 3D canvas', wide: true,
        controls: [
          info('view', 'entity graph · shard topology · lane overlay'),
          link('Open the 3D substrate', '/console-3d/index.html?embed=1', { hint: 'opens the Pro 3D substrate view' })
        ] },
      // Retirement (M10→M12): the deep-machinery workbench is native now, and the
      // legacy console has been fully removed — /console/legacy now 404s. This v2
      // console is the sole replacement, not a "kept as fallback" surface (the
      // smoke's retirement check asserts the removal copy + that no live
      // /console/legacy link survives).
      { h: 'Legacy console removed', sub: 'the workbench is native now; the legacy console has been fully removed', wide: true,
        controls: [
          info('legacy console', '(legacy — removed, fully replaced by this console)')
        ] }
    ],
    // DX / Docs — daemon reference + platform docs. No live docs endpoint on
    // this build (the legacy reader merged a docs:: fact group), so this is a
    // static Pro-mode page; the eventual home is the reserved 'documents' mode.
    'dx-docs': [
      { h: 'Bundled docs', sub: 'daemon reference shipped with this build · live mode merges docs:: facts', wide: true,
        controls: [
          { t: 'search', ph: 'Filter docs…' },
          { t: 'exp', label: 'mcp-system-prompt.md', sub: 'tool surface reference', badge: 'doc', controls: [info('scope', 'the MCP tool surface + capability ladder')] },
          { t: 'exp', label: 'PLANS.md', sub: 'ExecPlan format', badge: 'doc', controls: [info('required sections', 'Purpose · Non-goals · Context · Constraints · Milestones · Test plan · Risks · Progress · Decision log')] },
          { t: 'exp', label: 'agent-guide.md', sub: 'QC / threat references', badge: 'doc', controls: [info('scope', 'quality-control gates + threat model refs')] }
        ] },
      { h: 'README · corecruxd', sub: '17 crates · port 14800', wide: true,
        controls: [
          info('build', 'cargo build --release (CPU-only)'),
          info('architecture', 'axum HTTP :14800 + tonic gRPC · append-only shard store · Ed25519 CROWN receipts'),
          info('key rules', 'no GPU/CUDA · CCL licence · port 14800 fixed')
        ] },
      { h: 'External docs', sub: 'platform surfaces (open in a browser tab)', wide: true,
        controls: [
          info('cuecrux.com', 'marketing + product'),
          info('signals.cuecrux.com', 'status + signals')
        ] }
    ],
    'cx-raw': [
      { h: 'Request', controls: [
        { t: 'select', k: 'rpc_method', label: 'method', options: ['tools/list', 'tools/call · query', 'tools/call · store_fact', 'resources/list'], v: 'tools/list', mut: true },
        { t: 'textarea', k: 'rpc_params', label: 'params', v: '{ "token_budget": 500 }', rows: 4, mut: true },
        mbtn('Send', { hint: 'POST /mcp · :14801' })
      ] },
      { h: 'Response', controls: [{ t: 'rpcout' }] },
      { h: 'Transport', controls: [
        info('endpoint', 'POST /mcp · :14801'),
        { t: 'input', k: 'rpc_scopes', label: 'X-Corecrux-Scopes', v: 'read', mono: true, mut: true }
      ] }
    ]
  };

  // =======================================================================
  //  Page registry — 26 legacy CX pages mapped into the v2 IA.
  //  { id, legacyId, dest, title, sub, sections, operatorOnly?, load? }
  // =======================================================================

  function page(id, dest, title, sub, opts) {
    var p = { id: id, legacyId: id, dest: dest, title: title, sub: sub, sections: (STATIC[id] || []).slice() };
    if (opts) { for (var k in opts) { p[k] = opts[k]; } }
    return p;
  }

  var PAGES = {
    // ---- Overwatch -------------------------------------------------------
    // pill:false — folded out of the Overwatch pill row (item 0). The landing
    // tiles ARE the overview (render.js fillTiles reuses this page's build), so
    // cx-overview stays in PAGES (reachable via the tiles + direct #/overwatch/
    // cx-overview) but is never shown as a pill nor used as the default page.
    'cx-overview': page('cx-overview', 'overwatch', 'Overview', 'daemon posture, readiness, and capacity at a glance', { pill: false, load: { endpoint: '/v1/console/summary', build: buildOverview } }),
    'cx-activity': page('cx-activity', 'overwatch', 'Activity', 'all sessions · live rolling log'),
    'cx-coord': page('cx-coord', 'overwatch', 'Live board', 'who is working right now · /v1/coord/active', { load: { endpoint: '/v1/coord/active', build: buildCoord } }),
    'cx-orchestrators': page('cx-orchestrators', 'overwatch', 'Orchestrators', 'group plans for a session · /v1/orchestrators', { load: { endpoint: '/v1/orchestrators', build: buildOrchestrators } }),
    'cx-punchcards': page('cx-punchcards', 'overwatch', 'Punchcards', 'advisory path leases grouped by session · /v1/punchcards', { load: { endpoint: '/v1/punchcards', build: buildPunchcards } }),
    // ---- Work ------------------------------------------------------------
    'cx-work': page('cx-work', 'work', 'ExecPlans', 'read-time projection over .agent/execplans/*.md · /v1/work', { load: { endpoint: '/v1/work?source=all', build: buildWork } }),
    // Activity — the human-lane rolling activity log (ported from /console/activity
    // into the v2 theme). Custom-rendered by render.js renderActivityLog (see the
    // renderPage id switch); no section build.
    'cx-activity-log': page('cx-activity-log', 'work', 'Activity', 'live rolling activity log — streaming events + receipt cross-walk'),
    'cx-projects': page('cx-projects', 'work', 'Projects', 'repos to track + search, a planning repo, passports and working tenants', { load: { endpoint: '/v1/projects', build: buildProjects } }),
    'cx-sessions': page('cx-sessions', 'work', 'Sessions', 'saved session snapshots for resume + audit · /v1/console/sessions', { load: { endpoint: '/v1/console/sessions', build: buildSessions } }),
    // ---- Memory ----------------------------------------------------------
    // cx-facts is custom-rendered by render.js renderFactsBrowser (see the
    // renderPage id switch): a paged, searchable browser over GET /v1/facts/list
    // (the whole visible store, not a recent window). The load below is the
    // static/degradation section builder the smoke walk exercises + the honest
    // fallback shape; the interactive surface supersedes it at runtime.
    'cx-facts': page('cx-facts', 'memory', 'Facts', 'the durable record — the whole visible store, paged and searchable', { load: { endpoint: '/v1/facts/list?limit=100', build: buildFacts } }),
    'cx-memory': page('cx-memory', 'memory', 'Memory', 'recent facts per tenant — system tenants hidden by default', { load: { endpoint: '/v1/console/facts?top_k=50', build: buildMemory } }),
    'cx-tenants': page('cx-tenants', 'memory', 'Tenants', 'memory stores · AMR lane routing', { load: { endpoint: '/v1/console/tenants', build: buildTenants } }),
    'cx-documents': page('cx-documents', 'memory', 'Documents', 'what the daemon has read, per tenant — and how to feed it more'),
    'cx-review': page('cx-review', 'memory', 'Review', 'surfaced consolidation-review queue · guarded fact consolidation', { load: { endpoint: '/v1/console/review/queue?limit=50', build: buildReview } }),
    'cx-lane-weights': page('cx-lane-weights', 'memory', 'Lane weights', 'CoreCrux RRF overlay · same-origin console proxy', { operatorOnly: true, load: { endpoint: '/v1/console/corecrux/lane-weights', build: buildLaneWeights } }),
    // ---- Trust -----------------------------------------------------------
    'cx-receipts': page('cx-receipts', 'trust', 'Receipts', 'CROWN · verify Ed25519 proofs offline with the key'),
    'cx-gates': page('cx-gates', 'trust', 'Gates', 'human approvals — destructive / high-risk transitions wait here (Art. 14)', { load: { endpoint: '/v1/work/gate/pending', build: buildGates } }),
    'cx-mints': page('cx-mints', 'trust', 'Pending mints', 'agent-requested passports — review details, then accept or reject', { operatorOnly: true, load: { endpoint: '/v1/passport/mint-requests/pending', build: buildMints } }),
    'cx-passport': page('cx-passport', 'trust', 'Passport', 'agent + people identities · create and view passports', { load: { endpoint: '/v1/passports', build: buildPassports } }),
    'cx-identity': page('cx-identity', 'trust', 'Identity', 'candidate links — inference proposes, consent disposes', { load: { endpoint: '/v1/identity/candidates', build: buildIdentity } }),
    'cx-mediation': page('cx-mediation', 'trust', 'Mediation', 'the gateway plane — identity, capability ladder, foresight', { load: { endpoint: '/v1/console/engine/summary', build: buildMediationEngine } }),
    // ---- Meters ----------------------------------------------------------
    'cx-cost': page('cx-cost', 'meters', 'Token Burn (Session)', 'ground-truth cost lens — what each session cost + how to cut it', { load: { endpoint: '/v1/cost/report?tenant_id=default&token_budget=4000', build: buildCost } }),
    'cx-usage': page('cx-usage', 'meters', 'Average Token Usage', 'aggregate call volume and spend · /v1/observations/aggregate', { load: { endpoint: '/v1/console/engine/summary', build: buildUsageEngine } }),
    // ---- System ----------------------------------------------------------
    'cx-settings': page('cx-settings', 'system', 'Settings', 'daemon configuration and console preferences', { load: { endpoint: '/v1/console/settings', build: buildSettings } }),
    'cx-integrations': page('cx-integrations', 'system', 'Integrations', 'installed packs and their grants', { load: { endpoint: '/v1/console/integrations', build: buildIntegrations } }),
    'cx-extensions': page('cx-extensions', 'system', 'Extensions', 'signed third-party manifests · per-passport grants', { load: { endpoint: '/v1/extensions', build: buildExtensions } }),
    'cx-workbench': page('cx-workbench', 'system', 'Workbench', 'operator tooling over /v1/workbench/* — read tools live, writes gated (M13b)', { load: { endpoint: '/v1/workbench/contract', build: buildWorkbench } }),
    'cx-raw': page('cx-raw', 'system', 'Raw · JSON-RPC', '/mcp on :14801 · scopes header attaches automatically', { operatorOnly: true }),

    // ---- Ported legacy scopes (Professional mode only; pro:true) ----------
    // The legacy console's other four scopes (DX/GX/AX/IX) land here as Pro-only
    // pages so Standard mode stays the curated forward-facing surface. See the
    // LEGACY_PORT manifest below for the full section-by-section disposition.
    'ix-infra': page('ix-infra', 'system', 'Infra', 'machines, auth rails, config + session sync · /v1/console/infra/summary', { pro: true, load: { endpoint: '/v1/console/infra/summary', build: buildInfra } }),
    'dx-docs': page('dx-docs', 'system', 'Docs', 'daemon reference + platform docs', { pro: true }),
    'gx-global': page('gx-global', 'memory', 'Global', 'shared surfaces that outlive a session — engrams, bench, sites, fact store', { pro: true, load: { endpoint: '/v1/engrams', build: buildGlobal } }),
    'ax-agent': page('ax-agent', 'overwatch', 'Agent', 'agent-side cockpit — MCP tool usage, graph, and where each surface lives', { pro: true, load: { endpoint: '/v1/mcp/tools/usage?window_hours=720', build: buildAgent } })
  };

  // ---- Pro-ported page ids (the DX/GX/AX/IX pages above) ----------------
  // These are the ONLY page ids outside the legacy 26; each is pro:true (hidden
  // in Standard mode). The smoke asserts no page id exists beyond 26 ∪ this set.
  var PRO_PORTED_IDS = ['ix-infra', 'dx-docs', 'gx-global', 'ax-agent'];

  // ---- Destinations (rail order + pill grouping) ------------------------
  var DESTS = [
    { id: 'overwatch', label: 'Overwatch', icon: 'overwatch', key: '1', sub: 'Needs-you queue, fleet, and live activity.' },
    { id: 'work', label: 'Work', icon: 'work', key: '2', sub: 'ExecPlans, projects, and sessions.' },
    { id: 'memory', label: 'Memory', icon: 'memory', key: '3', sub: 'Facts, tenants, documents, and retrieval tuning.' },
    { id: 'trust', label: 'Trust', icon: 'trust', key: '4', sub: 'Receipts, gates, identity, and posture.' },
    { id: 'meters', label: 'Meters', icon: 'meters', key: '5', sub: 'Cost and usage.' },
    // railHidden — System lives in the bottom account roll-up menu (Settings ·
    // Language · Log out), not the Command rail; still routable at #/system/*.
    { id: 'system', label: 'System', icon: 'settings', railHidden: true, sub: 'Settings, integrations, and developer tools.' },
    // Canvas (M9) — a destination with no sub-pills: it IS the page. A
    // size-adaptive Board plus a real-edge relation Graph, switched by a
    // nav-family segmented control (deep-linkable #/canvas/board · #/canvas/graph).
    // Phone tier: lives in the "More" sheet (not one of the three direct tabs).
    { id: 'canvas', label: 'Canvas', icon: 'canvas', key: '6', sub: 'Size-adaptive dashboard + relation graph.' },
    // Explorer (M11) — a destination with no sub-pills: it IS a search surface.
    // A query box + a Local | WikiCrux backend toggle (nav-family, aria-pressed) +
    // a budget/top_k control; results as cards (title/snippet · source · score ·
    // tenant, real fields only). Both backends are READS, so Explorer is visible
    // in every posture. Local → daemon BM25 text-search; WikiCrux → the
    // daemon-mediated retrieval — both go through render.js's curated read-POST
    // client. Phone tier: lives in the "More" sheet (not a direct tab).
    // railHidden — Explorer is NOT in the Command rail; it's reached via the
    // top-right search field and from the top of the Explore (documents) menu.
    { id: 'explorer', label: 'Explorer', icon: 'search', railHidden: true, sub: 'Search the corpus — local retrieval or mediated WikiCrux.' },
    // Site map — a destination with no sub-pills: it IS a static reference page
    // (the flat rail rearranged into 5 destinations + System). Delegates to
    // render.js renderSiteMap; reads nothing, so it shows in every posture.
    { id: 'sitemap', label: 'Site map', icon: 'map', key: '7', sub: "the 26-item rail, rearranged into 5 destinations + System" },
    // Rings (prototype) — a destination with no sub-pills: it IS the page. Renders
    // the self-contained rings-clock landing mock (UI-prototype/rings-clock/
    // console-mock.html) in an isolated iframe via a base64 data: URL held in
    // RINGS_HTML_B64 below. Additive preview surface; the original Overwatch
    // landing (DESTS[0]) stays the default. Reads nothing, so it shows in every
    // posture. Snapshot data is embedded in the mock — live-wiring is a later step.
    { id: 'rings', label: 'Rings', icon: 'rings', key: '8', sub: 'Rings-clock landing prototype — live against this daemon when reachable.' }
  ];

  // ---- Legacy id inventory (the 26 CX pages this plan must keep reachable)
  var LEGACY_IDS = [
    'cx-overview', 'cx-activity', 'cx-cost', 'cx-projects', 'cx-work', 'cx-usage', 'cx-documents', 'cx-gates',
    'cx-review', 'cx-coord', 'cx-sessions', 'cx-orchestrators', 'cx-punchcards', 'cx-passport', 'cx-identity',
    'cx-receipts', 'cx-mediation', 'cx-workbench', 'cx-integrations', 'cx-extensions', 'cx-facts', 'cx-memory',
    'cx-tenants', 'cx-lane-weights', 'cx-settings', 'cx-raw'
  ];

  // ---- LEGACY_PORT — the port checklist (M8) ----------------------------
  // Every legacy console section (the 5 scopes in index.html:763 + the four
  // renderDash landing cards) mapped to its v2 disposition. Status is one of:
  //   'home:<v2-page-id>'    — already has a v2 home (the page id it lives on)
  //   'ported-pro:<target>'  — ported in M8 as a Pro-mode page/section (target =
  //                            a pro:true page id, or the overwatch dashboard strip)
  //   'deferred:<reason>'    — intentionally not ported (no read endpoint / stays
  //                            an embed / design artifact). Reason is required.
  // The smoke (check 24) embeds the expected legacy inventory and asserts this
  // manifest covers it EXACTLY — zero missing, zero unlabeled, zero stray. This
  // is the machine-readable proof that nothing from /console/legacy was dropped.
  var LEGACY_PORT = {
    // ── Retirement marker (M10) — the top-level metadata key. On this date the
    // legacy console was formally RETIRED; it has since been fully REMOVED —
    // crates/corecruxd/src/console.rs no longer serves it and /console/legacy
    // now 404s. The v2 unified shell is the sole surface (no fallback body). Not
    // a legacy section — the smoke's port-checklist integrity check skips this key
    // and asserts its value directly. See ExecPlan unified-shell-console-2026-07-03.
    retired_at: '2026-07-03',
    // ── CX (26) — the forward-facing scope, ported in M1; each keeps its id ──
    'cx-overview': 'home:cx-overview', 'cx-activity': 'home:cx-activity', 'cx-cost': 'home:cx-cost',
    'cx-projects': 'home:cx-projects', 'cx-work': 'home:cx-work', 'cx-usage': 'home:cx-usage',
    'cx-documents': 'home:cx-documents', 'cx-gates': 'home:cx-gates', 'cx-review': 'home:cx-review',
    'cx-coord': 'home:cx-coord', 'cx-sessions': 'home:cx-sessions', 'cx-orchestrators': 'home:cx-orchestrators',
    'cx-punchcards': 'home:cx-punchcards', 'cx-passport': 'home:cx-passport', 'cx-identity': 'home:cx-identity',
    'cx-receipts': 'home:cx-receipts', 'cx-mediation': 'home:cx-mediation', 'cx-workbench': 'home:cx-workbench',
    'cx-integrations': 'home:cx-integrations', 'cx-extensions': 'home:cx-extensions', 'cx-facts': 'home:cx-facts',
    'cx-memory': 'home:cx-memory', 'cx-tenants': 'home:cx-tenants', 'cx-lane-weights': 'home:cx-lane-weights',
    'cx-settings': 'home:cx-settings', 'cx-raw': 'home:cx-raw',
    // ── DX (Docs) — no live docs endpoint → one static Pro page ──
    'dx-articles': 'ported-pro:dx-docs', 'dx-readme': 'ported-pro:dx-docs', 'dx-sites': 'ported-pro:dx-docs',
    // ── GX (Global) — engrams live; fact store has a home; bench/sites deferred ──
    'gx-engrams': 'ported-pro:gx-global',
    'gx-factstore': 'home:cx-facts',
    'gx-bench': 'deferred:no local ScoreCrux bench endpoint (external board)',
    'gx-sites': 'deferred:no hypernym-sites endpoint on this daemon build',
    // ── AX (Agent) — tools/graph/overview ported; activity/memory/snapshots have homes; rest deferred ──
    'ax-overview': 'ported-pro:ax-agent', 'ax-tools': 'ported-pro:ax-agent', 'ax-graph': 'ported-pro:ax-agent',
    'ax-activity': 'home:cx-activity', 'ax-memory': 'home:cx-memory', 'ax-snapshots': 'home:cx-sessions',
    'ax-bulk': 'deferred:batch ops are mutations — no read surface',
    'ax-handoff': 'deferred:create_handoff is MCP-only — no list endpoint',
    'ax-storybook': 'deferred:tile/pattern catalog is a design artifact, not a data feed',
    'ax-story': 'deferred:call-tree story view stays on the Pro / 3D canvas',
    'ax-dossiers': 'deferred:per-project — /v1/projects/{id}/dossiers is per-project (see Work › Projects)',
    // ── IX (Infra) — all five panels fed by one live endpoint → one Pro page ──
    'ix-index': 'ported-pro:ix-infra', 'ix-machines': 'ported-pro:ix-infra', 'ix-rails': 'ported-pro:ix-infra',
    'ix-config': 'ported-pro:ix-infra', 'ix-sync': 'ported-pro:ix-infra',
    // ── Legacy CX dashboard (renderDash) top cards — homes + the new Pro strip ──
    'dash-daemon': 'home:cx-overview',          // Overwatch landing stat tiles
    'dash-execplans': 'home:cx-work',           // Work › ExecPlans (+ Pro dashboard strip)
    'dash-usage': 'home:cx-usage',              // Meters › Token usage
    'dash-mcp': 'ported-pro:overwatch-dashboard-strip'   // NEW: the MCP-gateway card had no v2 home
  };

  // ---- MUTATING_ACTIONS — single source of truth for the posture gate ---
  // Every label here corresponds to a control tagged `mut:true`; render.js
  // routes those through the operator gate (hidden unless operator; disabled
  // with title "wired in M3+" when operator). The smoke audits both halves.
  var MUTATING_ACTIONS = [
    'Create passport',                 // cx-passport
    'Consolidate facts',               // cx-review
    'Apply lane weights',              // cx-lane-weights
    'Reset lane weights',              // cx-lane-weights
    'Apply defaults to all tenants',   // cx-tenants (category / policy write)
    'Restart daemon',                  // cx-settings
    'Run sweep now',                   // cx-settings
    'Re-run onboarding',               // cx-settings (onboarding restart)
    'Probe endpoint',                  // cx-settings
    'Export audit bundle',             // cx-settings
    'Verify connection',               // cx-integrations (install/grant)
    'Test call',                       // cx-integrations (install/grant)
    'Add key',                         // cx-extensions
    'Install',                         // cx-extensions
    'Send',                            // cx-raw (JSON-RPC send)
    'Queue ingest',                    // cx-documents (facts add / ingest)
    'Scan path',                       // cx-documents
    'Confirm candidate',               // cx-identity
    'Withhold all',                    // cx-gates
    'Create project',                  // cx-projects (＋ New project disclosure)
    'Add repo',                        // cx-projects (＋ Add repos disclosure)
    'Set as planning repo',            // cx-projects (＋ Add repos disclosure)
    // ---- M13a: native workbench write tools (gated placeholders; live in M13b)
    'Build context pack',              // cx-workbench — POST /v1/workbench/context-pack (writes fact)
    'Run impact preflight',            // cx-workbench — POST /v1/workbench/impact-preflight (writes fact)
    'Simulate policy',                 // cx-workbench — POST /v1/workbench/policy-simulation (writes fact)
    'Probe route',                     // cx-workbench — POST /v1/workbench/route-probe (admin:write scoped)
    'Record capability audit'          // cx-workbench — POST …/capabilities/{id}/audit (writes audit)
  ];

  // =======================================================================
  //  CONTROL_DIFF (M13a) — per-legacy-CX-page control-parity manifest.
  //  For each legacy CX page: the grounded legacy control inventory (by type,
  //  from index.html PAGES — the interactive control DSL, index.html:3520-4038),
  //  the v2 read/display controls now PRESENT, the non-destructive read/display
  //  controls still MISSING (the M13a-eligible worklist, added where safe), and
  //  the write controls that stay operator-GATED (the M13b worklist).
  //
  //  This is the M13a gate evidence: v2 Pro was ~52% of legacy interactive
  //  controls (audit console-control-parity-audit-2026-07-04.md). M13a closes the
  //  NON-destructive half — the native workbench port + the missing read/display
  //  controls — and enumerates the genuine writes for M13b.
  //
  //  `legacy` counts: pages whose legacy sections are generator-built (list/graph
  //  projections: cx-overview/activity/work/sessions/identity/receipts/facts/coord/
  //  orchestrators/punchcards) carry `{ projection: '<kind>' }` instead of a static
  //  type tally — their v2 home is a live read over the named endpoint.
  // =======================================================================
  var CONTROL_DIFF = {
    // ── Item 3 grounding: the 5 controls the audit flagged as possibly-mislabeled
    //    "mutations". Each was GROUNDED against its handler; ALL retain a real
    //    side effect, so all stay operator-gated and defer to M13b (conservative
    //    per the M13a hard-safety rule "when unsure, gate it"). No safe read among
    //    them was wired live; the newly-wired safe ops are the workbench GET reads.
    // M13b live-wiring flip (operator greenlit read-mostly → state-mutating).
    // 19 write controls are now LIVE behind the guard harness (render.js
    // WIRED_WRITES: operatorGatedCall → the gated write client, bound-passport Art.14
    // refusal, a confirm dialog on the destructive subset, and a REAL receipt/
    // response render). 8 controls stay operator-GATED + disabled for the honest
    // reasons below — each is ungroundable in this UI or would break the curated
    // no-arbitrary-mutation invariant. Every wired route is a curated row in the
    // curated gated-mutation allowlist (route_spec_drift.rs GATED_MUTATIONS).
    _grounding: {
      'Add repo': 'GATED — POST /v1/projects/{id}/repos (projects.rs:324) needs a project id + a real repo; the ＋Add repos disclosure has neither (GitHub unconnected, placeholder select). No groundable body.',
      'Set as planning repo': 'GATED — same as Add repo: the disclosure form carries no project id / repo to target PATCH /v1/projects/{id} (projects.rs:133).',
      'Queue ingest': 'GATED — the only real route (POST /v1/local/ingest, local_ingest.rs:183) is a SYNCHRONOUS ingest needing a documents[] payload; the control models "queue a path fact for the agent". Shape mismatch — no path→documents bridge to ground.',
      'Install': 'GATED — POST /v1/extensions/register (extensions.rs:117) wants a full IntegrationManifest object and install-from-registry wants {id,index_path}; the form supplies only a URL/path. No groundable body.',
      'Apply defaults to all tenants': 'GATED — no bulk route; only per-tenant PATCH /v1/console/tenants/{id}/category (console.rs:1953). "All" would be an unbounded client loop over every tenant — out of scope for a curated single-call mutation.',
      'Run sweep now': 'GATED — no HTTP route: memory_sweep_candidates is an MCP tool (dry-run) and the real sweep is a background timer (ephemeral_gc::run_sweep_once) with no daemon endpoint.',
      'Export audit bundle': 'GATED — GET /v1/observe/sessions/{id}/audit/export (observe_audit.rs:481) is a READ needing a session id + CORECRUXD_OBSERVE; not a write, and no unparameterised console trigger.',
      'Send': 'GATED — POST /v1/openai/invoke (openai_shim.rs:218) dispatches an ARBITRARY MCP tools/call; a live console control there is an arbitrary-write surface that breaks the curated no-arbitrary-mutation invariant (also env-gated CORECRUXD_OPENAI_SHIM).',
      _wired: 'Create project · Create passport · Add key · Probe endpoint · Verify connection · Scan path · Build context pack · Run impact preflight · Simulate policy · Probe route · Record capability audit · Test call(confirm=spend) · Consolidate facts(confirm) · Confirm candidate(confirm) · Apply lane weights(confirm) · Reset lane weights(confirm) · Restart daemon(confirm) · Re-run onboarding(confirm) · Withhold all(confirm; loops gateReject over pending) — all via operatorGatedCall + Art.14 + real receipt.'
    },
    'cx-overview':      { legacy: { projection: 'panel' }, v2_present: ['live /v1/console/summary', 'stat tiles'], v2_missing_read: [], v2_gated_write: [] },
    'cx-activity':      { legacy: { projection: 'stream' }, v2_present: ['stream link', 'info rows'], v2_missing_read: ['in-page rolling log (dedicated streaming surface)'], v2_gated_write: [] },
    'cx-cost':          { legacy: { select: 1, info: 1 }, v2_present: ['live /v1/cost/report', 'D/W/M chart', 'window select'], v2_missing_read: [], v2_gated_write: [] },
    'cx-projects':      { legacy: { search: 1, btn: 8, exp: 1, select: 6, toggle: 8, input: 5, info: 1 }, v2_present: ['live /v1/projects', 'repo grid', 'search', 'disclosure'], v2_missing_read: ['per-repo role/plane display selects'], v2_gated_write: ['Create project', 'Add repo', 'Set as planning repo'] },
    'cx-work':          { legacy: { projection: 'kanban' }, v2_present: ['live /v1/work?source=all', 'state strips', 'graph link'], v2_missing_read: [], v2_gated_write: [] },
    'cx-usage':         { legacy: { select: 1, search: 1, info: 7, bar: 12, exp: 10 }, v2_present: ['window select', 'search', 'info rows', 'savings bars', 'D/W/M chart'], v2_missing_read: [], v2_gated_write: [] },
    'cx-documents':     { legacy: { search: 1, exp: 3, info: 9, btn: 5, input: 2, select: 2, toggle: 3 }, v2_present: ['live /v1/console/tenants', 'search', 'ingest inputs/selects (read)'], v2_missing_read: ['per-tenant chunk/doc counts display'], v2_gated_write: ['Queue ingest', 'Scan path'] },
    'cx-gates':         { legacy: { search: 1, exp: 2, info: 3, btn: 5 }, v2_present: ['live /v1/work/gate/pending', 'search', 'approve/reject (operator-gated, wired)'], v2_missing_read: [], v2_gated_write: ['Withhold all'] },
    'cx-review':        { legacy: { search: 1, info: 3, btn: 6, input: 6, textarea: 3, select: 2, toggle: 1 }, v2_present: ['live /v1/console/review/contradictions', 'search'], v2_missing_read: ['side-by-side contradiction display rows'], v2_gated_write: ['Consolidate facts'] },
    'cx-coord':         { legacy: { projection: 'panel' }, v2_present: ['live /v1/coord/active'], v2_missing_read: [], v2_gated_write: [] },
    'cx-sessions':      { legacy: { projection: 'list' }, v2_present: ['live /v1/console/sessions', 'search'], v2_missing_read: [], v2_gated_write: [] },
    'cx-orchestrators': { legacy: { projection: 'panel' }, v2_present: ['live /v1/orchestrators'], v2_missing_read: [], v2_gated_write: [] },
    'cx-punchcards':    { legacy: { projection: 'panel' }, v2_present: ['live /v1/punchcards'], v2_missing_read: [], v2_gated_write: [] },
    'cx-passport':      { legacy: { input: 5, select: 1, textarea: 1, btn: 2, search: 1 }, v2_present: ['live /v1/passports', 'search'], v2_missing_read: ['capability list display'], v2_gated_write: ['Create passport'] },
    'cx-identity':      { legacy: { projection: 'list' }, v2_present: ['live /v1/identity/candidates'], v2_missing_read: [], v2_gated_write: ['Confirm candidate'] },
    'cx-receipts':      { legacy: { projection: 'list' }, v2_present: ['browser-local lookup', 'search', 'verify dock (read)'], v2_missing_read: [], v2_gated_write: [] },
    'cx-mediation':     { legacy: { search: 1, exp: 4, info: 7, btn: 4, input: 1 }, v2_present: ['live /v1/console/engine/summary', 'principal/ladder/foresight info', 'search'], v2_missing_read: [], v2_gated_write: [] },
    'cx-workbench':     { legacy: { btn: 11, info: 5, input: 5, select: 3 }, v2_present: ['live /v1/workbench/contract', 'api-drift (read)', 'command-ledger (read)', 'reasoning-timeline (read)', 'audit-triage (read)', 'brief (read)', 'tenant filter', 'search', 'query inputs/selects'], v2_missing_read: ['live text-search/graph-expand/time-range in-page (available in Explorer)', 'live entity loader'], v2_gated_write: ['Build context pack', 'Run impact preflight', 'Simulate policy', 'Probe route', 'Record capability audit'] },
    'cx-integrations':  { legacy: { search: 1, exp: 14, info: 18, input: 3, toggle: 1, btn: 4, select: 1 }, v2_present: ['live /v1/console/integrations', 'pack expanders', 'grants (read)', 'search'], v2_missing_read: ['per-pack capability display rows'], v2_gated_write: ['Verify connection', 'Test call'] },
    'cx-extensions':    { legacy: { search: 1, exp: 2, info: 5, input: 3, select: 1, btn: 2 }, v2_present: ['live /v1/extensions', 'manifest expanders', 'search'], v2_missing_read: ['per-grant scope display'], v2_gated_write: ['Add key', 'Install'] },
    'cx-facts':         { legacy: { projection: 'cascade' }, v2_present: ['live /v1/facts/list (paged full store)', 'entity-prefix groups + quick-filter chips', 'server-side search (q=)', 'as_of time-machine (as_of_unix_ms)', 'superseded + reserved toggles', 'row detail (full value by id)'], v2_missing_read: [], v2_gated_write: [] },
    'cx-memory':        { legacy: { search: 1, toggle: 1, exp: 2, info: 4, btn: 1 }, v2_present: ['live /v1/console/facts', 'per-tenant groups', 'hide-system toggle (display)', 'search'], v2_missing_read: [], v2_gated_write: [] },
    'cx-tenants':       { legacy: { info: 1, btn: 2, search: 1, toggle: 1 }, v2_present: ['live /v1/console/tenants', 'AMR lane toggles (display)', 'search'], v2_missing_read: [], v2_gated_write: ['Apply defaults to all tenants'] },
    'cx-lane-weights':  { legacy: { projection: 'panel' }, v2_present: ['live /v1/console/corecrux/lane-weights', 'weight inputs (display)'], v2_missing_read: [], v2_gated_write: ['Apply lane weights', 'Reset lane weights'] },
    'cx-settings':      { legacy: { select: 7, toggle: 6, info: 8, input: 3, btn: 5, theme: 1 }, v2_present: ['live /v1/console/settings', 'auth/embedding/retention info', 'display selects/toggles', 'theme'], v2_missing_read: ['ops health / bootstrap status info rows'], v2_gated_write: ['Restart daemon', 'Run sweep now', 'Re-run onboarding', 'Probe endpoint', 'Export audit bundle'] },
    'cx-raw':           { legacy: { select: 1, textarea: 1, btn: 2, rpcout: 1, info: 1, input: 1 }, v2_present: ['method select', 'params textarea', 'rpcout', 'scopes input'], v2_missing_read: [], v2_gated_write: ['Send'] }
  };

  // =======================================================================
  //  Demo mode fixtures (labelled, gated). Representative populated states,
  //  surfaced ONLY when ?demo=1 (window.CRUX_DEMO) AND the matching real panel
  //  came back empty/degraded. render.js reads these exclusively through its
  //  single demoData() choke point, so nothing here can render without the demo
  //  flag — and real data always wins where an endpoint answers.
  // =======================================================================
  var CruxDemo = (function () {
    var NOW = Date.now(), MIN = 60000, HOUR = 3600000, DAY = 86400000;
    function wave(n, base, amp, seed) {
      var out = [];
      for (var i = 0; i < n; i++) {
        var v = base + amp * Math.sin((i + seed) / 2) + amp * 0.4 * Math.sin(i / 1.3 + seed);
        out.push(Math.max(0, Math.round(v)));
      }
      return out;
    }
    return {
      // 2 pending gates — the first carries foresight consequences.
      needsYou: [
        { action_id: 'act_9f21c4', work_id: 'execplan:corecrux-trait-expansion', requested_action: 'update_state', target_state: 'deployed',
          risk_class: 'high', requested_by_passport: 'p_sonnet_ce4e6c', requested_at_unix_ms: NOW - 8 * MIN,
          narrative: 'Flipping the trait-expansion lane to default-on touches every tenant’s retrieval path.',
          consequences: [
            { consequence_type: 'blast_radius', detail: 'all 50 pilot tenants re-rank on next query', target: 'lme-m' },
            { consequence_type: 'reversibility', detail: 'revertible via overlay flag; no data migration' },
            { consequence_type: 'latency', detail: '+6 ms p50 on the fused lane' }
          ] },
        { action_id: 'act_3b70de', work_id: 'execplan:unified-shell-console', requested_action: 'update_state', target_state: 'done',
          risk_class: 'medium', requested_by_passport: 'p_opus_local', requested_at_unix_ms: NOW - 41 * MIN }
      ],
      // 3 live sessions — the middle one has a ⚠ overlap.
      fleet: [
        { sessionHex: '7f3a1c2b', passport: 'p_opus_local', execplan: 'unified-shell-console', milestone: 'M7', intent: 'restyle round 2',
          leases: ['tree://crates/corecruxd/console/v2'], orchestrators: ['orc_7a1c'], snapshot: '9c5a9271' },
        { sessionHex: '2be40d19', passport: 'p_sonnet_ce4e6c', execplan: 'corecrux-trait-expansion', milestone: 'M3', intent: 'default-on pilot',
          leases: ['file://crates/corecrux-retrieval/src/fuse.rs'], overlaps: [{ resource: 'fuse.rs' }] },
        { sessionHex: null, passport: 'p_haiku_bench', intent: null, leases: [], snapshot: 'a1b2c3d4' }
      ],
      // 12 activity rows, each with a receipt id.
      activity: (function () {
        var kinds = [
          ['store_fact', 'store_fact', 'gate:M6 recorded'], ['work', 'update_state', 'execplan → in_progress'],
          ['receipt', null, 'CROWN signed'], ['query', 'query_scan', 'retrieval · 12 hits'],
          ['session', 'save_session', 'pre-compact snapshot'], ['gate', 'approve', 'Art.14 approval'],
          ['fact', 'store_fact', 'decision:packaging'], ['activity', null, 'appended'],
          ['work', 'comment', 'return note to requester'], ['query', 'query_expand', 'expand · 4 lanes'],
          ['session', 'save_session', 'resume point'], ['store_fact', 'store_fact', 'bench:cdb-v1']
        ];
        return kinds.map(function (k, i) {
          return { kind: k[0], tool: k[1], preview: k[2], ts: new Date(NOW - i * 7 * MIN).toISOString().slice(11, 16),
            receipt_ids: ['crn_' + (0x8f21 + i * 37).toString(16)] };
        });
      })(),
      engine: { mediated: true, engine_reachable: true, engine_latency_ms: 41, fetched_at_unix_ms: NOW - 2 * MIN },
      // Repo card grid fixture (item 2b) — fills an expanded project's repo grid
      // ONLY when the real /v1/projects/{id}/repos list is empty AND demo is on.
      projectRepos: [
        { owner: 'cuecrux', repo: 'PlanCrux', role: 'planning', plane_id: 'shared' },
        { owner: 'cuecrux', repo: 'Crux', role: 'work' },
        { owner: 'cuecrux', repo: 'AuditCrux', role: 'reference' }
      ],
      // Cost / usage time-series: 24h (hourly) · 7d · 30d.
      costSeries: { day: wave(24, 42000, 12000, 1), week: wave(7, 480000, 90000, 2), month: wave(30, 2100000, 300000, 3) },
      usageSeries: { day: wave(24, 39000, 9000, 4), week: wave(7, 517000, 70000, 5), month: wave(30, 2220000, 260000, 6) },
      // Tile sparkline series (events/day) for Facts + Sessions.
      factsSpark: wave(7, 40, 18, 7),
      sessionsSpark: wave(7, 6, 4, 8),
      // Demo-only tile series for pure scalars with no real time-series (MCP
      // agents / Integrations counts) + the engine latency micro-series. These
      // render ONLY behind demoOn() (demo-chipped) — never as fabricated real lines.
      mcpSeries: wave(7, 5, 3, 9),
      integrationsSeries: wave(7, 8, 4, 10),
      engineLatencySeries: wave(12, 41, 9, 11),
      // Representative work + memory states (fixtures kept complete).
      work: [
        { id: 'execplan:unified-shell-console', title: 'unified-shell-console', state: 'in_progress', risk_class: 'medium', current_milestone: 'M7', milestones_total: 8, milestones_done: 6, plan_path: '.agent/execplans/unified-shell-console.md', project_id: 'crux-daemon', assignee_passport: 'p_opus_local', linked_pr: 'CueCrux/Crux#332', updated_at: new Date(NOW - 8 * MIN).toISOString() },
        { id: 'execplan:corecrux-trait-expansion', title: 'corecrux-trait-expansion', state: 'blocked', risk_class: 'high', current_milestone: 'M3', milestones_total: 5, milestones_done: 2, plan_path: '.agent/execplans/corecrux-trait-expansion.md', project_id: 'crux-daemon', assignee_passport: 'p_sonnet_ce4e6c', updated_at: new Date(NOW - 41 * MIN).toISOString() },
        { id: 'execplan:cruxengine-carry-all', title: 'cruxengine-carry-all', state: 'planned', risk_class: 'low', current_milestone: 'M1', milestones_total: 6, milestones_done: 0, plan_path: '.agent/execplans/cruxengine-carry-all.md', project_id: 'cruxengine', updated_at: new Date(NOW - 3 * HOUR).toISOString() },
        { id: 'execplan:context-custody-surface', title: 'context-custody-surface', state: 'done', risk_class: 'medium', current_milestone: 'M4', milestones_total: 4, milestones_done: 4, plan_path: '.agent/execplans/context-custody-surface.md', project_id: 'crux-daemon', assignee_passport: 'p_opus_local', linked_pr: 'CueCrux/Crux#318', updated_at: new Date(NOW - 2 * DAY).toISOString() }
      ],
      // Saved sessions — richer than the bare id rows a fresh local daemon holds,
      // so the resume/audit surface reads well in demo mode.
      sessions: [
        { session_id: 'sess_7f3a1c2b', execplan_slug: 'unified-shell-console', passport_id: 'p_opus_local', status: 'active', turn_count: 214, tenant_id: 'default', token_used: 148200, token_limit: 200000, milestones_done: 6, milestones_total: 8, updated_at: new Date(NOW - 4 * MIN).toISOString() },
        { session_id: 'sess_2be40d19', execplan_slug: 'corecrux-trait-expansion', passport_id: 'p_sonnet_ce4e6c', status: 'active', turn_count: 89, tenant_id: 'default', token_used: 96400, token_limit: 200000, milestones_done: 2, milestones_total: 5, updated_at: new Date(NOW - 12 * MIN).toISOString() },
        { session_id: 'handoff:context-custody', execplan_slug: 'context-custody-surface', passport_id: 'p_opus_local', status: 'idle', turn_count: 47, tenant_id: 'default', token_used: 61800, token_limit: 200000, milestones_done: 4, milestones_total: 4, updated_at: new Date(NOW - 2 * HOUR).toISOString() },
        { session_id: 'sess_a1b2c3d4', execplan_slug: 'cruxengine-carry-all', passport_id: 'p_haiku_bench', status: 'idle', turn_count: 12, tenant_id: 'bench', token_used: 18300, token_limit: 128000, milestones_done: 0, milestones_total: 6, updated_at: new Date(NOW - 6 * HOUR).toISOString() },
        { session_id: 'sess_9c5a9271', execplan_slug: 'unified-shell-console', passport_id: 'p_opus_local', status: 'idle', turn_count: 156, tenant_id: 'default', token_used: 132900, token_limit: 200000, milestones_done: 5, milestones_total: 8, updated_at: new Date(NOW - 1 * DAY).toISOString() },
        { session_id: 'sess_e6f81234', execplan_slug: 'wikicrux-agent-first', passport_id: 'p_sonnet_ce4e6c', status: 'archived', archived: true, turn_count: 73, tenant_id: 'default', token_used: 87600, token_limit: 200000, milestones_done: 3, milestones_total: 7, updated_at: new Date(NOW - 3 * DAY).toISOString() }
      ],
      // Activity log fixture (ACT_KINDS-typed rows) — a fresh daemon gates the
      // real log, so ?demo=1 paints this so the Activity surface reads populated.
      activityLog: (function () {
        var rows = [
          ['question', null, 'restyle round 2', 'convert the ExecPlans surface to a kanban board'],
          ['reasoning', null, 'plan', 'columns keyed by work state; cards carry risk + progress'],
          ['command', 'edit_file', 'console/v2/pages.js', 'buildWork → kanban columns'],
          ['fact', 'store_fact', 'gate:M6', 'decision:packaging → hybrid keep-vow'],
          ['answer', null, 'render', 'kanban control + gradient bars wired into render.js'],
          ['execplan', 'update_state', 'unified-shell-console', 'M6 → in_progress · milestone advanced'],
          ['command', 'run_test', 'node smoke.cjs', '26/26 checks green'],
          ['handoff', 'save_session', 'pre-compact snapshot', 'resume point written · snapshot 9c5a9271'],
          ['error', null, 'lint', 'clippy warning resolved in fuse.rs'],
          ['answer', null, 'summary', 'five Work-surface improvements applied']
        ];
        return rows.map(function (r, i) {
          return { kind: r[0], seq: rows.length - i, ts: new Date(NOW - i * 3 * MIN).toISOString().slice(11, 19),
            turn_id: null, tool: r[1], intent: r[2], preview: r[3], confidence: null };
        });
      })(),
      // Projects — a project pairs repos + a planning repo for ExecPlans (repo grid
      // fills from projectRepos above when a card is expanded in demo mode).
      projects: [
        { id: 'crux-daemon', name: 'Crux Daemon', is_default: true, planning_target: 'PlanCrux', default_passport_id: 'p_opus_local', created_at_unix_ms: NOW - 90 * DAY },
        { id: 'cruxengine', name: 'CruxEngine', planning_target: 'PlanCrux', default_passport_id: 'p_sonnet_ce4e6c', created_at_unix_ms: NOW - 60 * DAY },
        { id: 'wikicrux', name: 'WikiCrux', planning_target: 'PlanCrux', created_at_unix_ms: NOW - 30 * DAY }
      ],
      facts: [
        { entity: 'execplan:unified-shell-console', key: 'gate:M6', value: '{ status: passing, commit_sha: 1a60d25 }', stored_at: new Date(NOW - 3 * HOUR).toISOString() },
        { entity: 'bench:cdb-v1', key: 'result', value: 'crux ties vendor-native on static recall', stored_at: new Date(NOW - 20 * HOUR).toISOString() },
        { entity: 'decision:packaging', key: 'scenario', value: 'hybrid keep-vow + free-verifier', stored_at: new Date(NOW - 2 * DAY).toISOString() }
      ],
      // Documents mode (M10) fixture — the WebCrux Proof reader narrative
      // (webcrux-surfaces-demo-v3.jsx PROOF), ported so the reader shows its
      // full Section/Card composition + evidence material in demo mode. Surfaced
      // ONLY behind demoOn() via demoData('docsReader'); every panel is demo-
      // chipped. The reading body composes as sections → chunks (each with a
      // coverage label + score); the evidence side rail carries support/context/
      // challenge EvidenceCards, a coverage breakdown, and CROWN receipt rows.
      docsReader: {
        title: 'Q3 2025 Market Outlook — European Semiconductor Supply Chain',
        subtitle: 'Internal Research Brief · Compliance Review Requested',
        mode: 'verified', receiptId: 'rcpt_4f8a2b1c9e3d7f6a',
        coverage: { label: 'Medium', score: 0.61, fragility: 0.42,
          components: [['retrieval', 0.68], ['domains', 0.57], ['temporal', 0.65], ['clusters', 0.58]] },
        sections: [
          { title: 'Executive Summary', chunks: [
            { id: 'c01', label: 'supported', cov: { label: 'High', score: 0.82 },
              text: 'European chip manufacturers have committed to investing €43 billion in domestic fabrication capacity by 2030, aiming to double the region’s share of global production from 10% to 20%.',
              claims: ['EU Chips Act investment figure of €43bn', 'Current EU share approximately 10%', 'Target of 20% by 2030'] },
            { id: 'c02', label: 'contested', cov: { label: 'Medium', score: 0.45 }, fragile: true,
              text: 'ASML’s latest EUV lithography systems are now capable of producing chips at the 2nm node, positioning the Netherlands as the critical bottleneck in global advanced semiconductor supply chains.',
              claims: ['ASML EUV systems at 2nm production capability', 'Netherlands as critical single-point bottleneck'] } ] },
          { title: 'Supply Chain Analysis', chunks: [
            { id: 'c03', label: 'supported', cov: { label: 'High', score: 0.74 },
              text: 'Germany’s new semiconductor cluster in Dresden, anchored by Intel’s planned €30 billion facility and TSMC’s joint venture with Bosch, NXP, and Infineon, represents the largest single investment in European chip manufacturing history.',
              claims: ['Intel €30bn Dresden facility', 'TSMC-Bosch-NXP-Infineon joint venture'] },
            { id: 'c04', label: 'thin', cov: { label: 'Low', score: 0.28 },
              text: 'Legacy chip shortages continue to affect European automotive manufacturers, with lead times for microcontrollers still averaging 32 weeks as of July 2025.',
              claims: ['Ongoing legacy chip shortages', 'MCU lead times at 32 weeks as of July 2025'] } ] },
          { title: 'Conclusion', chunks: [
            { id: 'c12', label: 'supported', cov: { label: 'Medium', score: 0.62 },
              text: 'Structural dependencies on ASML lithography, Asian packaging expertise, and specialised materials supply chains mean European strategic autonomy in semiconductors remains aspirational rather than achievable within the current planning horizon.',
              claims: ['ASML lithography dependency', 'Asian packaging dependency'] } ] }
        ],
        evidence: [
          { role: 'support', domain: 'eur-lex.europa.eu', score: 0.94, source: 'EU Chips Act Official Text (2023)', observedAt: '2025-09-20',
            quote: '…mobilise more than 43 billion euros in public and private investment…' },
          { role: 'support', domain: 'semi.org', score: 0.87, source: 'SEMI Industry Report Q2 2025', observedAt: '2025-08-15',
            quote: '…European share of global semiconductor manufacturing stood at 9.8%…' },
          { role: 'context', domain: 'brookings.edu', source: 'US CHIPS Act Comparison',
            summary: 'US allocated $52.7bn under the CHIPS and Science Act, creating competitive dynamics with EU policy.' },
          { role: 'challenge', domain: 'spectrum.ieee.org', type: 'counterfactual', source: 'IEEE Spectrum Analysis',
            summary: 'Multiple lithography vendors including Canon’s NIL approach may reduce single-vendor dependency at advanced nodes.' }
        ],
        receipts: [
          { id: 'rcpt_4f8a2b1c9e3d7f6a', label: 'proof · verified', ts: '2025-10-14 09:32' },
          { id: 'rcpt_2b4c6d8e0f1a3g5i', label: 'replay · deterministic', ts: '2025-10-14 09:52' }
        ]
      },
      // Explorer (M11) fixture — sample search cards, surfaced ONLY behind
      // demoOn() via demoData('explorer') and ONLY when the chosen backend is
      // unreachable/off (real results always win). Each card is demo-chipped. The
      // field names mirror the REAL response shapes so the demo composes exactly
      // like a live search: WikiCrux (/v1/retrieve RetrievalResult) carries
      // title/content/score/source/tenantId.
      explorer: [
        { title: 'Albert Einstein', snippet: 'Albert Einstein (1879–1955) was a German-born theoretical physicist who developed the theory of relativity.', source: 'tenant', score: 0.93, tenant: 'wikicrux' },
        { title: 'Theory of relativity', snippet: 'The theory of relativity usually encompasses two interrelated theories by Einstein: special and general relativity.', source: 'commons', score: 0.81, tenant: 'wikicrux' },
        { title: 'Photoelectric effect', snippet: 'Einstein’s 1905 explanation of the photoelectric effect earned him the 1921 Nobel Prize in Physics.', source: 'tenant', score: 0.76, tenant: 'wikicrux' }
      ],
      // Documents-mode surface fixtures (M12) — the JSX's own data consts
      // (webcrux-surfaces-demo-v3.jsx), ported so the ten non-Proof surfaces show
      // their full composition in demo mode. Surfaced ONLY behind demoOn() via
      // demoData('surfaces') → render.js's surfaceDemo() choke point; every panel
      // is demo-chipped. A surface with a real endpoint (watch/diff/lanes/domains)
      // uses this only as an empty/degraded fallback — real data always wins.
      surfaces: {
        // Watch (WATCHES) — watched items with epistemic status + change log.
        watch: [
          { type: 'Answer', name: 'What are the DORA compliance requirements for third-party ICT providers?', status: 'Stable', band: 'High', dependents: 0, lastChecked: '2025-10-14', history: [] },
          { type: 'Answer', name: 'How does the EU AI Act classify foundation model providers?', status: 'Updated', band: 'Medium', dependents: 3, lastChecked: '2025-10-14',
            history: [{ what: 'Confidence band shifted: High → Medium', why: 'Load-bearing evidence (EC draft guidelines) was superseded by final published text with material differences.', codes: ['evidence_superseded', 'confidence_band_crossed'], cBefore: 'High', cAfter: 'Medium' }] },
          { type: 'Artefact', name: 'NIST AI RMF Playbook v1.0', status: 'Stable', band: 'High', dependents: 7, lastChecked: '2025-10-14',
            history: [{ what: 'New version detected (v1.1 draft published)', why: 'NIST published updated playbook; source artefact integrity hash changed.', codes: ['artefact_version_change'], cBefore: 'High', cAfter: 'High' }] },
          { type: 'Domain', name: 'eur-lex.europa.eu', status: 'Attention', band: 'Low', dependents: 23, lastChecked: '2025-10-14',
            history: [{ what: '3 answers depending on this domain lost coverage', why: 'Domain ingestion pipeline returned errors for 48h; 3 load-bearing artefacts are stale beyond threshold.', codes: ['domain_ingestion_failure', 'temporal_threshold_exceeded'], cBefore: 'Medium', cAfter: 'Low' }] }
        ],
        // Ask (ASK + THREAD) — verified answer canvas with claim↔evidence links.
        ask: {
          mode: 'verified', query: 'What are the key compliance requirements under the EU AI Act for high-risk AI systems?',
          cov: { label: 'High', score: 0.78, comp: { retrieval: 0.85, domains: 0.72, temporal: 0.81, clusters: 0.74 } },
          thread: [{ label: 'Original question', type: 'ask' }, { label: 'Narrowed to transparency', type: 'alter_query' }, { label: 'Removed EC draft guidelines', type: 'exclude_source' }],
          paragraphs: [
            'High-risk AI systems under the EU AI Act must satisfy a comprehensive set of requirements before they can be placed on the market or put into service within the EU.',
            'Risk management must be established as a continuous, iterative process throughout the entire lifecycle of the system.',
            'Data governance requirements mandate that training, validation, and testing datasets meet specific quality criteria.',
            'Technical documentation must be drawn up before the system is placed on the market and kept up to date.',
            'Transparency obligations require that high-risk AI systems be designed to ensure their operation is sufficiently transparent for users.',
            'Human oversight measures must allow natural persons to effectively oversee the AI system during its period of use.',
            'Accuracy, robustness, and cybersecurity requirements ensure the system is resilient and protected against manipulation.'
          ],
          claims: [
            { id: 'cl1', text: 'Risk management as continuous iterative lifecycle process', status: 'supported' },
            { id: 'cl2', text: 'Data governance with quality criteria for training data', status: 'supported' },
            { id: 'cl3', text: 'Technical documentation before market placement', status: 'supported' },
            { id: 'cl4', text: 'Transparency for user interpretability', status: 'supported' },
            { id: 'cl5', text: 'Human oversight with intervention capability', status: 'supported' },
            { id: 'cl6', text: 'Accuracy, robustness, cybersecurity standards', status: 'supported' }
          ],
          evidence: [
            { id: 'art_01', title: 'EU AI Act — Regulation 2024/1689', domain: 'eur-lex.europa.eu', role: 'primary', score: 0.96 },
            { id: 'art_02', title: 'European Commission AI Act Guidelines (Draft)', domain: 'ec.europa.eu', role: 'supporting', score: 0.88 },
            { id: 'art_03', title: 'OECD AI Principles Alignment Analysis', domain: 'oecd.org', role: 'context', score: 0.72 },
            { id: 'art_04', title: 'BSI AI Standard Landscape Report', domain: 'bsigroup.com', role: 'supporting', score: 0.65 }
          ]
        },
        // Living Objects (LIVING) — artefacts with state, pressure, relations.
        living: [
          { id: 'art_01', title: 'EU AI Act — Regulation 2024/1689', domain: 'eur-lex.europa.eu', state: 'fresh', confidence: 'High', trunkTier: 3, lane: 'dense_1536', pressureLevel: 0,
            dependents: { answers: 14, mises: 8, collections: 3 },
            relations: [{ target: 'EU AI Act Guidelines (Draft)', type: 'supersedes', confidence: 0.91, method: 'version_chain' }, { target: 'OECD AI Principles', type: 'supports', confidence: 0.74, method: 'semantic_similarity' }, { target: 'UK AI White Paper', type: 'contradicts', confidence: 0.42, method: 'claim_comparison' }],
            pressure: [], versions: [{ v: 'v3', date: '2025-07-01', hash: 'blake3:9f2a...' }, { v: 'v2', date: '2024-08-01', hash: 'blake3:7b1c...' }, { v: 'v1', date: '2024-03-13', hash: 'blake3:3e4d...' }] },
          { id: 'art_02', title: 'European Commission AI Act Guidelines (Draft)', domain: 'ec.europa.eu', state: 'stale', confidence: 'Medium', trunkTier: 2, lane: 'dense_1024', pressureLevel: 2,
            dependents: { answers: 6, mises: 4, collections: 1 },
            relations: [{ target: 'EU AI Act — Regulation 2024/1689', type: 'superseded_by', confidence: 0.91, method: 'version_chain' }, { target: 'AI Act Compliance Checklist v2', type: 'supports', confidence: 0.68, method: 'semantic_similarity' }],
            pressure: [{ code: 'FRESHNESS_DECAY', severity: 2, summary: 'Last validated 43 days ago. Exceeds 30-day freshness threshold for tier-2 trunk artefacts.', action: 'Re-validate or mark superseded' }, { code: 'SUPERSEDED_BY_FINAL', severity: 2, summary: 'Final regulation text published, superseding this draft. 6 dependent answers may need rebuild.', action: 'Trigger dependent rebuild' }],
            versions: [{ v: 'v2 (draft)', date: '2025-03-15', hash: 'blake3:5a2b...' }, { v: 'v1 (draft)', date: '2024-11-20', hash: 'blake3:1c3d...' }] },
          { id: 'art_03', title: 'NIST AI RMF Playbook v1.0', domain: 'nist.gov', state: 'fresh', confidence: 'High', trunkTier: 3, lane: 'dense_1536', pressureLevel: 1,
            dependents: { answers: 9, mises: 6, collections: 2 },
            relations: [{ target: 'ISO 42001 AI Management', type: 'supports', confidence: 0.82, method: 'semantic_similarity' }, { target: 'NIST AI RMF Playbook v1.1 (draft)', type: 'superseded_by', confidence: 0.65, method: 'version_chain' }],
            pressure: [{ code: 'USAGE_SPIKE', severity: 1, summary: 'Query volume referencing this artefact increased 340% over the 7-day average.', action: 'Monitor; consider lane upgrade if sustained' }],
            versions: [{ v: 'v1.0', date: '2024-01-26', hash: 'blake3:8d7e...' }] },
          { id: 'art_04', title: 'BCG Manufacturing Cost Analysis', domain: 'bcg.com', state: 'contested', confidence: 'Low', trunkTier: 1, lane: 'dense_768', pressureLevel: 3,
            dependents: { answers: 3, mises: 2, collections: 0 },
            relations: [{ target: 'Roland Berger Energy Report', type: 'contradicted_by', confidence: 0.61, method: 'claim_comparison' }, { target: 'McKinsey Semiconductor Cost Study', type: 'supports', confidence: 0.53, method: 'semantic_similarity' }],
            pressure: [{ code: 'CONTRADICTION_SPIKE', severity: 3, summary: 'New evidence from Roland Berger directly contradicts key cost projections.', action: 'Trigger dependent answer rebuild' }, { code: 'ANCHOR_DRIFT', severity: 2, summary: 'Anchor set Jaccard similarity dropped below 0.6 threshold.', action: 'Re-embed with current anchor set' }],
            versions: [{ v: 'v1', date: '2025-04-10', hash: 'blake3:2f1a...' }] }
        ],
        // Dependencies (DEP_TREE) — assumption-loaded dependency tree (2 levels).
        deps: {
          query: 'What are the key compliance requirements under the EU AI Act for high-risk AI systems?',
          root: { id: 'answer', label: 'Answer', sublabel: 'EU AI Act High-Risk Requirements', confidence: 0.78, fragility: 0.35, assumptionLoad: 0.22, coverageContribution: 1.0, trunkTier: null, type: 'answer',
            children: [
              { id: 'ev_1', label: 'EU AI Act — Reg. 2024/1689', sublabel: 'eur-lex.europa.eu', confidence: 0.96, fragility: 0.08, assumptionLoad: 0.05, coverageContribution: 0.42, trunkTier: 3, type: 'primary',
                children: [
                  { id: 'd_1b', label: 'Translation accuracy (EN)', sublabel: 'Authentic language version', confidence: 0.94, fragility: 0.12, assumptionLoad: 0.18, coverageContribution: 0.08, type: 'assumption', children: [] },
                  { id: 'd_1c', label: 'Regulation in force', sublabel: 'Not yet repealed or amended', confidence: 0.98, fragility: 0.04, assumptionLoad: 0.06, coverageContribution: 0.12, type: 'temporal', children: [] }
                ] },
              { id: 'ev_2', label: 'EC AI Act Guidelines (Draft)', sublabel: 'ec.europa.eu', confidence: 0.88, fragility: 0.52, assumptionLoad: 0.48, coverageContribution: 0.28, trunkTier: 2, type: 'supporting',
                children: [
                  { id: 'd_2b', label: 'Draft ≈ Final alignment', sublabel: 'Material changes possible', confidence: 0.54, fragility: 0.85, assumptionLoad: 0.82, coverageContribution: 0.06, type: 'assumption', children: [] }
                ] },
              { id: 'ev_3', label: 'OECD AI Principles Analysis', sublabel: 'oecd.org', confidence: 0.72, fragility: 0.41, assumptionLoad: 0.38, coverageContribution: 0.18, trunkTier: 2, type: 'context', children: [] },
              { id: 'ev_4', label: 'BSI AI Standard Report', sublabel: 'bsigroup.com', confidence: 0.65, fragility: 0.58, assumptionLoad: 0.52, coverageContribution: 0.12, trunkTier: 1, type: 'supporting',
                children: [{ id: 'd_4b', label: 'Standard still current', sublabel: 'No superseding publication', confidence: 0.49, fragility: 0.82, assumptionLoad: 0.84, coverageContribution: 0.03, type: 'temporal', children: [] }] }
            ] }
        },
        // Signals (SIGNALS) — epistemic status-change feed.
        signals: [
          { id: 'sig_01', type: 'confidence_band_crossed', severity: 'high', title: 'EU AI Act classification answer — confidence dropped High → Medium', target: { type: 'Answer' }, what: 'Confidence band crossed from High to Medium after load-bearing evidence was superseded.', why: 'EC draft guidelines superseded by final published regulation text with material differences in provider obligation scope.', codes: ['evidence_superseded', 'confidence_band_crossed', 'mises_recomputed'], cBefore: 'High', cAfter: 'Medium', rBefore: 'rcpt_a1b2c3d4', rAfter: 'rcpt_e5f6g7h8', depImpact: { answers: 3, artefacts: 1 }, publishedAt: '2025-10-13' },
          { id: 'sig_02', type: 'trunk_tier_shift', severity: 'medium', title: 'NIST AI RMF Playbook promoted to Trunk Tier 3', target: { type: 'Artefact' }, what: 'Trunk tier promoted from T2 to T3 after sustained dependency growth.', why: '9 answers and 6 MiSES sets now depend on this artefact. Promotion score crossed the 80 threshold.', codes: ['DEPENDENCY_GROWTH', 'trunk_tier_shift'], cBefore: 'High', cAfter: 'High', rBefore: null, rAfter: null, depImpact: { answers: 9, artefacts: 4 }, publishedAt: '2025-10-12' },
          { id: 'sig_03', type: 'load_bearing_swap', severity: 'high', title: 'BCG cost analysis contradicted — 3 dependent answers weakened', target: { type: 'Artefact' }, what: 'Load-bearing evidence contradicted by new source. 3 dependent answers lost coverage.', why: 'Roland Berger Energy Report published with directly contradicting cost projections. Anchor set Jaccard dropped below 0.6.', codes: ['CONTRADICTION_SPIKE', 'ANCHOR_DRIFT', 'dependent_rebuild_triggered'], cBefore: 'Medium', cAfter: 'Low', rBefore: 'rcpt_d4e5f6', rAfter: 'rcpt_g7h8i9', depImpact: { answers: 3, artefacts: 2 }, publishedAt: '2025-10-10' },
          { id: 'sig_04', type: 'rebuild_triggered', severity: 'low', title: 'DORA compliance answer rebuilt — confidence stable', target: { type: 'Answer' }, what: 'Scheduled rebuild completed. New receipt minted. Confidence unchanged.', why: 'Periodic rebuild triggered by freshness schedule. Candidate digest stable (Jaccard 0.96).', codes: ['scheduled_rebuild', 'receipt_lineage_updated'], cBefore: 'High', cAfter: 'High', rBefore: 'rcpt_x1y2z3', rAfter: 'rcpt_m4n5o6', depImpact: { answers: 0, artefacts: 0 }, publishedAt: '2025-10-14' },
          { id: 'sig_05', type: 'anchor_drift', severity: 'medium', title: 'Semiconductor supply chain domain — retrieval regression detected', target: { type: 'Domain' }, what: 'Anchor drift threshold crossed for 4 answers in this domain.', why: 'Bulk re-ingestion of semi.org content changed chunk boundaries. Prior anchor sets no longer align.', codes: ['ANCHOR_DRIFT', 'RETRIEVAL_REGRESSION', 'bulk_reindex'], cBefore: 'High', cAfter: 'Medium', rBefore: null, rAfter: null, depImpact: { answers: 4, artefacts: 12 }, publishedAt: '2025-10-11' }
        ],
        // Receipt Diff (DIFF_DATA) — before/after CROWN snapshot comparison.
        diff: {
          before: { id: 'rcpt_a1b2c3d4', mode: 'verified', ts: '2025-10-01 09:00', confidence: { band: 'High', score: 0.81 }, coverage: { retrieval: 0.82, domains: 0.71, temporal: 0.79, clusters: 0.72 } },
          after: { id: 'rcpt_e5f6g7h8', mode: 'verified', ts: '2025-10-13 14:25', confidence: { band: 'Medium', score: 0.62 }, coverage: { retrieval: 0.72, domains: 0.58, temporal: 0.68, clusters: 0.58 },
            dropped: [{ id: 'ev_01', title: 'EC AI Act Guidelines (Draft)', domain: 'ec.europa.eu', reason: 'Superseded by final text' }] }
        },
        // Sourcing (SOURCING) — coverage-gap → structured sourcing lifecycle.
        sourcing: [
          { id: 'sr_01', query: 'What are the EU AI Act penalties for non-compliance?', covLabel: 'Low', covScore: 0.24, fragility: 0.78, status: 'discovering', quoteEstimate: null,
            suggestions: [{ url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689', rationale: 'Official regulation text — Chapter XII contains penalty provisions', status: 'accepted', lane: 'fast' }, { url: 'https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai', rationale: 'EC implementation guidance and penalty schedule references', status: 'proposed', lane: 'slow' }],
            discoveredDomains: ['eur-lex.europa.eu', 'digital-strategy.ec.europa.eu', 'edpb.europa.eu'] },
          { id: 'sr_02', query: 'How do automotive OEMs comply with UNECE R155 cybersecurity requirements?', covLabel: 'Low', covScore: 0.18, fragility: 0.85, status: 'quoted', quoteEstimate: { crux: 12, gbp: 0.12, chunks: 45 },
            suggestions: [{ url: 'https://unece.org/transport/documents/2021/03/standards/un-regulation-no-155', rationale: 'Official UNECE R155 regulation text', status: 'accepted', lane: 'fast' }, { url: 'https://www.iso.org/standard/70918.html', rationale: 'ISO/SAE 21434 road vehicle cybersecurity engineering', status: 'accepted', lane: 'slow' }],
            discoveredDomains: ['unece.org', 'iso.org', 'enisa.europa.eu'] },
          { id: 'sr_03', query: 'What are the current CBAM reporting obligations for semiconductor imports?', covLabel: 'Low', covScore: 0.0, fragility: 0, status: 'awaiting_user_choice', quoteEstimate: { crux: 8, gbp: 0.08, chunks: 30 },
            suggestions: [{ url: 'https://taxation-customs.ec.europa.eu/carbon-border-adjustment-mechanism_en', rationale: 'Official CBAM implementation page', status: 'proposed', lane: 'fast' }],
            discoveredDomains: ['taxation-customs.ec.europa.eu'] },
          { id: 'sr_04', query: 'What is the current status of the EU-US Data Privacy Framework adequacy decision?', covLabel: 'Medium', covScore: 0.41, fragility: 0.62, status: 'completed', quoteEstimate: { crux: 5, gbp: 0.05, chunks: 22 },
            suggestions: [{ url: 'https://commission.europa.eu/document/fa09cbad-dd7d-4684-ae60-be03fcb0fddf_en', rationale: 'EC adequacy decision document', status: 'ingested', lane: 'fast' }],
            discoveredDomains: ['commission.europa.eu', 'edpb.europa.eu'] }
        ],
        // Lanes (LANES + PROMOTIONS) — embedding lane stack + promotion feed.
        lanes: {
          lanes: [
            { tier: 'Base', dim: 768, provider: 'ollama (local)', model: 'nomic-embed-text', desc: 'Broad recall · every artefact, always', stats: { artefacts: 24680, backlog: 42, throughput: '1,240/min', cost: '£0.00/day', p95: '8ms' }, modes: ['light', 'verified', 'audit'] },
            { tier: 'Premium', dim: 1024, provider: 'voyage', model: 'voyage-3.5-lite', desc: 'Better semantic neighbourhoods · promoted artefacts', stats: { artefacts: 3842, backlog: 156, throughput: '320/min', cost: '£2.40/day', p95: '45ms' }, modes: ['verified', 'audit'] },
            { tier: 'Premium+', dim: 1536, provider: 'openai', model: 'text-embedding-3-small', desc: 'High-quality retrieval · paid + high-score auto', stats: { artefacts: 892, backlog: 23, throughput: '80/min', cost: '£4.80/day', p95: '120ms' }, modes: ['verified', 'audit'] },
            { tier: 'Pro', dim: 3072, provider: 'openai', model: 'text-embedding-3-large', desc: 'Highest precision · critical content only', stats: { artefacts: 124, backlog: 3, throughput: '12/min', cost: '£8.60/day', p95: '280ms' }, modes: ['audit'] }
          ],
          promotions: [
            { artefact: 'EU AI Act — Regulation 2024/1689', from: 'Lane 1', to: 'Lane 2', reason: 'auto_score', score: 84, status: 'done' },
            { artefact: 'NIST AI RMF Playbook v1.0', from: 'Lane 0', to: 'Lane 1', reason: 'auto_score', score: 67, status: 'done' },
            { artefact: 'BCG Manufacturing Cost Analysis', from: 'Lane 0', to: 'Lane 1', reason: 'watchcrux', score: 52, status: 'pending' },
            { artefact: 'BSI AI Standard Report', from: 'Lane 1', to: 'Lane 2', reason: 'paid', score: null, status: 'running', budget: '£0.04' }
          ]
        },
        // Domains (DOMAINS) — source-corpus health.
        domains: [
          { slug: 'eur-lex.europa.eu', name: 'EUR-Lex', type: 'Regulator', artefacts: 342, coverage: 0.84, freshness: 0.91, trust: 0.96, contradiction: 0.02, ingestionStatus: 'healthy', dependents: { answers: 47, mises: 32 }, flags: [] },
          { slug: 'ec.europa.eu', name: 'European Commission', type: 'Regulator', artefacts: 218, coverage: 0.72, freshness: 0.68, trust: 0.89, contradiction: 0.05, ingestionStatus: 'stale', dependents: { answers: 31, mises: 22 }, flags: [{ msg: '6 days since last successful ingestion' }] },
          { slug: 'nist.gov', name: 'NIST', type: 'Standards Body', artefacts: 156, coverage: 0.78, freshness: 0.85, trust: 0.94, contradiction: 0.01, ingestionStatus: 'healthy', dependents: { answers: 22, mises: 16 }, flags: [] },
          { slug: 'semi.org', name: 'SEMI', type: 'Industry Association', artefacts: 89, coverage: 0.58, freshness: 0.52, trust: 0.81, contradiction: 0.08, ingestionStatus: 'error', dependents: { answers: 12, mises: 8 }, flags: [{ msg: 'Pipeline errors for 48h — 3 load-bearing artefacts stale' }, { msg: 'Contradiction rate 8% exceeds 5% threshold' }] },
          { slug: 'bsigroup.com', name: 'BSI Group', type: 'Standards Body', artefacts: 64, coverage: 0.45, freshness: 0.38, trust: 0.72, contradiction: 0.11, ingestionStatus: 'stale', dependents: { answers: 8, mises: 5 }, flags: [{ msg: '16 days since last ingestion' }, { msg: 'Contradiction rate 11% — multiple superseded standards' }] }
        ],
        // Reverse (REVERSE_DATA) — assertion verification + counterfactuals.
        reverse: {
          assertion: 'The EU AI Act requires high-risk AI systems to undergo conformity assessments before being placed on the market, and non-compliance can result in fines of up to €35 million or 7% of global turnover.',
          analysis: { verdict: 'Mostly accurate', verdictColor: 'amber', confidence: 0.74, covLabel: 'High', covScore: 0.82, fragility: 0.31,
            issues: [{ severity: 'medium', text: 'The €35M/7% figure is the maximum tier for prohibited practices, not specifically for high-risk system non-compliance. High-risk violations face €15M/3%. The assertion conflates penalty tiers.' }, { severity: 'low', text: 'Conformity assessments vary: third-party for biometric high-risk, self-assessment for most Annex III systems. The assertion implies a single process.' }] },
          evidence: [
            { id: 'rv_e1', title: 'EU AI Act — Regulation 2024/1689', domain: 'eur-lex.europa.eu', role: 'primary', score: 0.97, supports: ['Conformity assessment required for high-risk systems (Art. 43)', 'Fines up to €35M or 7% turnover for prohibited practices (Art. 99)'], note: 'Directly confirms both claims.' },
            { id: 'rv_e2', title: 'European Commission AI Act Guidelines (Draft)', domain: 'ec.europa.eu', role: 'supporting', score: 0.84, supports: ['Conformity assessment process includes technical documentation review'], note: 'Elaborates the conformity procedure. Draft status — may be superseded.' },
            { id: 'rv_e3', title: 'Bird & Bird: EU AI Act Penalties Analysis', domain: 'twobirds.com', role: 'supporting', score: 0.76, supports: ['€35M/7% is the maximum tier — applies to prohibited AI practices', 'Lower tiers: €15M/3% for most high-risk violations'], note: 'Clarifies that €35M/7% is the top tier.' },
            { id: 'rv_e4', title: 'OECD AI Policy Observatory: EU AI Act Summary', domain: 'oecd.ai', role: 'context', score: 0.62, supports: ['Overview confirms conformity assessment framework'], note: 'General confirmation at lower specificity.' }
          ],
          counterfactuals: {
            rv_e1: { verdict: 'Unsupported', verdictColor: 'red', confidence: 0.18, answer: 'Without the primary regulation text, the assertion cannot be verified from secondary sources alone. Exact figures and article numbers come only from the regulation itself.', warning: 'Removing the primary legal source collapses confidence. This is a load-bearing source.' },
            rv_e2: { verdict: 'Mostly accurate', verdictColor: 'amber', confidence: 0.71, answer: 'Without the EC draft guidelines, practical implementation detail is reduced. The core legal claims remain supported by the regulation text and third-party analysis.', warning: null },
            rv_e3: { verdict: 'Accurate but incomplete', verdictColor: 'amber', confidence: 0.69, answer: 'Without the penalty tier analysis, the distinction between violation levels is less clear.', warning: 'Losing the penalty analysis source makes it harder to flag the tier conflation issue.' },
            rv_e4: { verdict: 'Mostly accurate', verdictColor: 'amber', confidence: 0.73, answer: 'Removing the OECD summary has minimal impact — it provided general corroboration already covered by higher-authority sources.', warning: null }
          }
        }
      }
    };
  })();

  // ---- JSX_PORT — the M12 surface-port manifest -------------------------
  // Every WebCrux Proof surface (webcrux-surfaces-demo-v3.jsx) → its v2
  // disposition: the JSX source line, whether it renders REAL daemon data (and
  // which endpoint) or is a demo-only surface, and the render.js component. The
  // smoke (check 32) asserts all 11 NAV ids are present + covered; check 33 that
  // every 'real:' surface reads via the api.js client and every 'demo-surface'
  // renders its fixture only behind demoOn(). Proof reuses the M11 reader.
  var JSX_PORT = {
    proof: { source_line: 246, status: 'real:reader (/v1/console/tenants+/v1/console/facts+/v1/activity)', component: 'renderDocuments' },
    watch: { source_line: 696, status: 'real:/v1/activity', component: 'renderDocSurface_watch' },
    ask: { source_line: 860, status: 'real:/v1/query/text-search', component: 'renderDocSurface_ask' },
    living: { source_line: 1250, status: 'real:/v1/admin/projections/artifacts/{id}/state', component: 'renderDocSurface_living' },
    deps: { source_line: 1487, status: 'real:/v1/query/graph-expand', component: 'renderDocSurface_deps' },
    signals: { source_line: 1934, status: 'demo-surface', component: 'renderDocSurface_signals' },
    diff: { source_line: 2074, status: 'real:/v1/activity', component: 'renderDocSurface_diff' },
    sourcing: { source_line: 2268, status: 'demo-surface', component: 'renderDocSurface_sourcing' },
    lanes: { source_line: 2415, status: 'real:/v1/console/corecrux/lane-weights', component: 'renderDocSurface_lanes' },
    domains: { source_line: 2574, status: 'real:/v1/features/capabilities/analysis/coverage', component: 'renderDocSurface_domains' },
    reverse: { source_line: 2781, status: 'demo-surface', component: 'renderDocSurface_reverse' }
  };

  // Rings-clock landing prototype, embedded as a base64 data: URL so the
  // self-contained mock renders in an isolated iframe (see the 'rings'
  // destination + the renderDestination rings branch in shell.html). Wrapped
  // with <!doctype html><meta charset=utf-8> before encoding for standards mode.
  var RINGS_HTML_B64 = 'PCFkb2N0eXBlIGh0bWw+CjxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KPHRpdGxlPkNydXggQ29uc29sZSDigJQgUmluZ3MgbGFuZGluZyBtb2NrPC90aXRsZT4KPHN0eWxlPgo6cm9vdCwgOnJvb3RbZGF0YS10aGVtZT0ibGlnaHQiXSwgOnJvb3RbZGF0YS10aGVtZT0iZGFyayJdIHsKICAtLWJnMDogIzBiMGQxMzsgLS1iZzE6ICMxMjE1MWQ7CiAgLS1wYW5lbDogcmdiYSgyNTUsMjU1LDI1NSwuMDM1KTsgLS1wYW5lbC1zdHJvbmc6IHJnYmEoMjU1LDI1NSwyNTUsLjA2KTsKICAtLWhhaXJsaW5lOiByZ2JhKDI1NSwyNTUsMjU1LC4wOSk7IC0taGFpcmxpbmUtc3Ryb25nOiByZ2JhKDI1NSwyNTUsMjU1LC4xOCk7CiAgLS1pbms6ICNlZWYwZjY7IC0taW5rMjogI2I2YmNjOTsgLS1pbmszOiAjN2U4NTk1OwogIC0tYWNjZW50OiAjOGI5NmYyOyAtLWFjY2VudC1kZWVwOiAjNWU2YWQyOwogIC0tdGVhbDogIzJkZDRiZjsgLS1hbWJlcjogI2Y1YTYyMzsgLS12aW9sZXQ6ICNhNzhiZmE7IC0tZXJyOiAjZWY0NDQ0OwogIC0tZm9udC1zYW5zOiAnUHVibGljIFNhbnMnLCB1aS1zYW5zLXNlcmlmLCBzeXN0ZW0tdWksIC1hcHBsZS1zeXN0ZW0sICdTZWdvZSBVSScsIFJvYm90bywgQXJpYWwsIHNhbnMtc2VyaWY7CiAgLS1mb250LW1vbm86ICdKZXRCcmFpbnMgTW9ubycsIHVpLW1vbm9zcGFjZSwgU0ZNb25vLVJlZ3VsYXIsIE1lbmxvLCBDb25zb2xhcywgbW9ub3NwYWNlOwogIGNvbG9yLXNjaGVtZTogZGFyazsKfQoqIHsgYm94LXNpemluZzogYm9yZGVyLWJveDsgfQpodG1sLCBib2R5IHsgbWFyZ2luOiAwOyB9CmJvZHkgewogIGJhY2tncm91bmQ6IHJhZGlhbC1ncmFkaWVudCgxMjAwcHggNzAwcHggYXQgNzAlIC0xMCUsIHJnYmEoOTQsMTA2LDIxMCwuMTApLCB0cmFuc3BhcmVudCA2MCUpLCB2YXIoLS1iZzApOwogIGNvbG9yOiB2YXIoLS1pbmspOyBmb250LWZhbWlseTogdmFyKC0tZm9udC1zYW5zKTsgbGluZS1oZWlnaHQ6IDEuNTU7CiAgLXdlYmtpdC1mb250LXNtb290aGluZzogYW50aWFsaWFzZWQ7Cn0KYSB7IGNvbG9yOiB2YXIoLS1hY2NlbnQpOyB0ZXh0LWRlY29yYXRpb246IG5vbmU7IH0KYTpob3ZlciB7IHRleHQtZGVjb3JhdGlvbjogdW5kZXJsaW5lOyB0ZXh0LXVuZGVybGluZS1vZmZzZXQ6IDNweDsgfQpjb2RlIHsgZm9udC1mYW1pbHk6IHZhcigtLWZvbnQtbW9ubyk7IGZvbnQtc2l6ZTogLjllbTsgYmFja2dyb3VuZDogdmFyKC0tcGFuZWwtc3Ryb25nKTsgcGFkZGluZzogLjFlbSAuMzVlbTsgYm9yZGVyLXJhZGl1czogNXB4OyB9CgovKiDilIDilIAgY29uc29sZSB0b3BiYXIg4pSA4pSAICovCiN0b3BiYXIgewogIGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGdhcDogMTJweDsKICBwYWRkaW5nOiAxMnB4IGNsYW1wKDE2cHgsIDN2dywgMzJweCk7CiAgYm9yZGVyLWJvdHRvbTogMXB4IHNvbGlkIHZhcigtLWhhaXJsaW5lKTsKICBmb250LWZhbWlseTogdmFyKC0tZm9udC1tb25vKTsgZm9udC1zaXplOiAxMnB4OyBjb2xvcjogdmFyKC0taW5rMyk7Cn0KI3RvcGJhciAuYnJhbmQgeyBmb250OiA4MDAgMTVweCB2YXIoLS1mb250LXNhbnMpOyBjb2xvcjogdmFyKC0taW5rKTsgbGV0dGVyLXNwYWNpbmc6IC0uMDFlbTsgfQojdG9wYmFyIC5icmFuZCBzcGFuIHsgY29sb3I6IHZhcigtLWluazMpOyBmb250LXdlaWdodDogNTAwOyB9CiN0b3BiYXIgLnBpbGwgewogIGRpc3BsYXk6IGlubGluZS1mbGV4OyBhbGlnbi1pdGVtczogY2VudGVyOyBnYXA6IDdweDsKICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1oYWlybGluZS1zdHJvbmcpOyBib3JkZXItcmFkaXVzOiA5OTlweDsgcGFkZGluZzogM3B4IDEycHg7Cn0KI3RvcGJhciAucGlsbCAuZG90IHsgd2lkdGg6IDdweDsgaGVpZ2h0OiA3cHg7IGJvcmRlci1yYWRpdXM6IDUwJTsgYmFja2dyb3VuZDogdmFyKC0tdGVhbCk7IH0KI3RvcGJhciAuc3AgeyBtYXJnaW4tbGVmdDogYXV0bzsgfQoKLyogZnJhbWVkIGluc2lkZSB0aGUgY29uc29sZTogaXRzIGNocm9tZSBhbHJlYWR5IHByb3ZpZGVzIHRoZSB0b3AgYmFyICovCi5mcmFtZWQgI3RvcGJhciB7IGRpc3BsYXk6IG5vbmU7IH0KCi8qIOKUgOKUgCBsZW5zIHRpbGVzOiBjb21wYWN0IHJvdyBkb2NrZWQgYXQgdGhlIGJvdHRvbSAoYWJvdmUgdGhlIGNvbnRyb2wgYmFyKSDilIDilIAgKi8KI3RpbGVzIHsKICBwb3NpdGlvbjogYWJzb2x1dGU7IGJvdHRvbTogMTA4cHg7IHJpZ2h0OiAxNnB4OyB6LWluZGV4OiAxNTsKICBkaXNwbGF5OiBmbGV4OyBmbGV4LWRpcmVjdGlvbjogcm93OyBmbGV4LXdyYXA6IHdyYXA7IGp1c3RpZnktY29udGVudDogZmxleC1lbmQ7CiAgZ2FwOiA2cHg7IG1heC13aWR0aDogNjB2dzsKfQoKLyog4pSA4pSAIGRhZW1vbiBhdCBhIGdsYW5jZTogdG9wLXJpZ2h0LCBsaXZlIGZyb20gL3YxL2NvbnNvbGUvc3VtbWFyeSDilIDilIAgKi8KI2dsYW5jZSB7CiAgcG9zaXRpb246IGFic29sdXRlOyB0b3A6IDE0cHg7IHJpZ2h0OiAxNnB4OyB6LWluZGV4OiAxNDsKICBkaXNwbGF5OiBncmlkOyBncmlkLXRlbXBsYXRlLWNvbHVtbnM6IDFmciAxZnI7IGdhcDogNnB4OyB3aWR0aDogMjMwcHg7Cn0KLmdsIHsKICB0ZXh0LWFsaWduOiBsZWZ0OyBjdXJzb3I6IGRlZmF1bHQ7CiAgYmFja2dyb3VuZDogcmdiYSgxNCwxNiwyNCwuODgpOyBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1oYWlybGluZSk7CiAgYm9yZGVyLXJhZGl1czogMTBweDsgcGFkZGluZzogN3B4IDExcHggNnB4OwogIGNvbG9yOiB2YXIoLS1pbmsyKTsgZm9udC1mYW1pbHk6IHZhcigtLWZvbnQtc2Fucyk7Cn0KLmdsIC50IHsgZGlzcGxheTogYmxvY2s7IGZvbnQ6IDYwMCA5LjVweCB2YXIoLS1mb250LW1vbm8pOyBsZXR0ZXItc3BhY2luZzogLjA0ZW07IGNvbG9yOiB2YXIoLS1pbmszKTsgdGV4dC10cmFuc2Zvcm06IHVwcGVyY2FzZTsgfQouZ2wgLm4geyBkaXNwbGF5OiBibG9jazsgZm9udDogNzAwIDE1cHggdmFyKC0tZm9udC1zYW5zKTsgY29sb3I6IHZhcigtLWluayk7IGxldHRlci1zcGFjaW5nOiAtLjAxZW07IGZvbnQtdmFyaWFudC1udW1lcmljOiB0YWJ1bGFyLW51bXM7IG1hcmdpbi10b3A6IDFweDsgfQojZ2xhbmNlIC5zcmMgeyBncmlkLWNvbHVtbjogMSAvIC0xOyBmb250OiAxMHB4IHZhcigtLWZvbnQtbW9ubyk7IGNvbG9yOiB2YXIoLS1pbmszKTsgdGV4dC1hbGlnbjogcmlnaHQ7IHBhZGRpbmctcmlnaHQ6IDJweDsgfQoudGlsZSB7CiAgdGV4dC1hbGlnbjogbGVmdDsgY3Vyc29yOiBwb2ludGVyOwogIGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBiYXNlbGluZTsgZ2FwOiA4cHg7CiAgYmFja2dyb3VuZDogcmdiYSgxNCwxNiwyNCwuODgpOyBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1oYWlybGluZSk7CiAgYm9yZGVyLXJhZGl1czogMTBweDsgcGFkZGluZzogN3B4IDEycHg7CiAgY29sb3I6IHZhcigtLWluazIpOyBmb250LWZhbWlseTogdmFyKC0tZm9udC1zYW5zKTsKICB0cmFuc2l0aW9uOiBib3JkZXItY29sb3IgLjE1cywgYmFja2dyb3VuZCAuMTVzOwp9Ci50aWxlOmhvdmVyIHsgYm9yZGVyLWNvbG9yOiB2YXIoLS1oYWlybGluZS1zdHJvbmcpOyBiYWNrZ3JvdW5kOiByZ2JhKDIwLDIzLDMzLC45NSk7IH0KLnRpbGU6Zm9jdXMtdmlzaWJsZSB7IG91dGxpbmU6IDJweCBzb2xpZCB2YXIoLS1hY2NlbnQpOyBvdXRsaW5lLW9mZnNldDogMnB4OyB9Ci50aWxlW2FyaWEtcHJlc3NlZD0idHJ1ZSJdIHsgYm9yZGVyLWNvbG9yOiByZ2JhKDEzOSwxNTAsMjQyLC42KTsgYmFja2dyb3VuZDogcmdiYSgxMzksMTUwLDI0MiwuMTQpOyB9Ci50aWxlIC50IHsgZm9udDogNjAwIDEycHggdmFyKC0tZm9udC1zYW5zKTsgY29sb3I6IHZhcigtLWluazIpOyBkaXNwbGF5OiBmbGV4OyBhbGlnbi1pdGVtczogY2VudGVyOyBnYXA6IDdweDsgZmxleDogMTsgfQoudGlsZSAudCBpIHsgd2lkdGg6IDdweDsgaGVpZ2h0OiA3cHg7IGJvcmRlci1yYWRpdXM6IDUwJTsgZGlzcGxheTogaW5saW5lLWJsb2NrOyB9Ci50aWxlIC5uIHsgZm9udDogNzAwIDE0cHggdmFyKC0tZm9udC1zYW5zKTsgY29sb3I6IHZhcigtLWluayk7IGxldHRlci1zcGFjaW5nOiAtLjAxZW07IGZvbnQtdmFyaWFudC1udW1lcmljOiB0YWJ1bGFyLW51bXM7IH0KLnRpbGUgLnMgeyBkaXNwbGF5OiBub25lOyB9Ci50aWxlW2FyaWEtcHJlc3NlZD0idHJ1ZSJdIC50IHsgY29sb3I6IHZhcigtLWFjY2VudCk7IH0KQG1lZGlhIChtYXgtd2lkdGg6IDc2MHB4KSB7ICN0aWxlcyB7IHBvc2l0aW9uOiBzdGF0aWM7IGZsZXgtZGlyZWN0aW9uOiByb3c7IGZsZXgtd3JhcDogd3JhcDsgd2lkdGg6IGF1dG87IG1hcmdpbjogMTBweCAxNnB4IDA7IH0gfQoKLyogaWNvbiBidXR0b25zICsgZGF0ZSBwaWNrZXJzICovCi5zdGFnZWJhciBidXR0b24uaWMgeyBmb250LXNpemU6IDEzcHg7IHBhZGRpbmc6IDRweCA5cHg7IG1pbi13aWR0aDogMzBweDsgdGV4dC1hbGlnbjogY2VudGVyOyB9Ci5zdGFnZWJhciBpbnB1dFt0eXBlPWRhdGVdIHsKICBmb250OiA2MDAgMTFweCB2YXIoLS1mb250LW1vbm8pOyBjb2xvcjogdmFyKC0taW5rMik7CiAgYmFja2dyb3VuZDogcmdiYSgyNTUsMjU1LDI1NSwuMDcpOyBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1oYWlybGluZS1zdHJvbmcpOwogIGJvcmRlci1yYWRpdXM6IDdweDsgcGFkZGluZzogM3B4IDZweDsgY29sb3Itc2NoZW1lOiBkYXJrOwp9CgpzZWN0aW9uLmNvbmNlcHQgeyBtYXgtd2lkdGg6IDE1NjBweDsgbWFyZ2luOiAyNnB4IGF1dG8gMDsgcGFkZGluZzogMCBjbGFtcCgxMnB4LCAzdncsIDM2cHgpOyB9Ci8qIGRlLWNhcmRlZDogdGhlIHJpbmdzIHNpdCBkaXJlY3RseSBvbiB0aGUgcGFnZSAqLwouc3RhZ2V3cmFwIHsKICBwb3NpdGlvbjogcmVsYXRpdmU7IGJvcmRlcjogMDsgYm9yZGVyLXJhZGl1czogMDsKICBiYWNrZ3JvdW5kOiB0cmFuc3BhcmVudDsKICBvdmVyZmxvdzogaGlkZGVuOyBib3gtc2hhZG93OiBub25lOwp9Ci5zdGFnZXdyYXAgY2FudmFzIHsgZGlzcGxheTogYmxvY2s7IHdpZHRoOiAxMDAlOyBoZWlnaHQ6IGNsYW1wKDUyMHB4LCA3NHZoLCA4MjBweCk7IGN1cnNvcjogY3Jvc3NoYWlyOyB0b3VjaC1hY3Rpb246IG5vbmU7IH0KLnN0YWdlYmFyIHsKICBwb3NpdGlvbjogYWJzb2x1dGU7IGxlZnQ6IDA7IHJpZ2h0OiAwOyBib3R0b206IDA7CiAgZGlzcGxheTogZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsgZ2FwOiA5cHg7IGZsZXgtd3JhcDogd3JhcDsKICBwYWRkaW5nOiAxMHB4IDE2cHg7CiAgZm9udC1mYW1pbHk6IHZhcigtLWZvbnQtbW9ubyk7IGZvbnQtc2l6ZTogMTEuNXB4OyBjb2xvcjogdmFyKC0taW5rMyk7CiAgYmFja2dyb3VuZDogbGluZWFyLWdyYWRpZW50KHRyYW5zcGFyZW50LCByZ2JhKDExLDEzLDE5LC44NSkgNDUlKTsKICBwb2ludGVyLWV2ZW50czogbm9uZTsKfQouc3RhZ2ViYXIgPiAqIHsgcG9pbnRlci1ldmVudHM6IGF1dG87IH0KLnN0YWdlYmFyIC5ncnAgeyBkaXNwbGF5OiBmbGV4OyBhbGlnbi1pdGVtczogY2VudGVyOyBnYXA6IDZweDsgd2hpdGUtc3BhY2U6IG5vd3JhcDsgfQouc3RhZ2ViYXIgLmhpbnQgeyBtYXJnaW4tbGVmdDogYXV0bzsgdGV4dC1hbGlnbjogcmlnaHQ7IH0KLnN0YWdlYmFyIGJ1dHRvbiB7CiAgZm9udDogNjAwIDExLjVweCB2YXIoLS1mb250LW1vbm8pOyBjb2xvcjogdmFyKC0taW5rMik7CiAgYmFja2dyb3VuZDogcmdiYSgyNTUsMjU1LDI1NSwuMDcpOyBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1oYWlybGluZS1zdHJvbmcpOwogIGJvcmRlci1yYWRpdXM6IDdweDsgcGFkZGluZzogNHB4IDExcHg7IGN1cnNvcjogcG9pbnRlcjsKfQouc3RhZ2ViYXIgYnV0dG9uOmhvdmVyIHsgY29sb3I6IHZhcigtLWluayk7IGJhY2tncm91bmQ6IHJnYmEoMjU1LDI1NSwyNTUsLjEyKTsgfQouc3RhZ2ViYXIgYnV0dG9uW2FyaWEtcHJlc3NlZD0idHJ1ZSJdIHsgY29sb3I6IHZhcigtLWFjY2VudCk7IGJvcmRlci1jb2xvcjogcmdiYSgxMzksMTUwLDI0MiwuNTUpOyBiYWNrZ3JvdW5kOiByZ2JhKDEzOSwxNTAsMjQyLC4xMik7IH0KLnN0YWdlYmFyIGJ1dHRvbjpmb2N1cy12aXNpYmxlLCAuc3RhZ2ViYXIgaW5wdXQ6Zm9jdXMtdmlzaWJsZSwgLnN0YWdlYmFyIHNlbGVjdDpmb2N1cy12aXNpYmxlIHsgb3V0bGluZTogMnB4IHNvbGlkIHZhcigtLWFjY2VudCk7IG91dGxpbmUtb2Zmc2V0OiAycHg7IH0KLnN0YWdlYmFyIHNlbGVjdCB7CiAgZm9udDogNjAwIDExLjVweCB2YXIoLS1mb250LW1vbm8pOyBjb2xvcjogdmFyKC0taW5rMik7CiAgYmFja2dyb3VuZDogcmdiYSgyNTUsMjU1LDI1NSwuMDcpOyBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1oYWlybGluZS1zdHJvbmcpOwogIGJvcmRlci1yYWRpdXM6IDdweDsgcGFkZGluZzogNHB4IDhweDsgY3Vyc29yOiBwb2ludGVyOwp9Ci5zdGFnZWJhciBzZWxlY3Q6aG92ZXIgeyBjb2xvcjogdmFyKC0taW5rKTsgYmFja2dyb3VuZDogcmdiYSgyNTUsMjU1LDI1NSwuMTIpOyB9Ci5zdGFnZWJhciBpbnB1dFt0eXBlPXJhbmdlXSB7IGFjY2VudC1jb2xvcjogdmFyKC0tYWNjZW50LWRlZXApOyB3aWR0aDogbWluKDE1MHB4LCAxN3Z3KTsgfQouc3RhZ2ViYXIgbGFiZWwgeyBjb2xvcjogdmFyKC0taW5rMyk7IH0KLnN0YWdlYmFyIC5jaGlwIHsgYmFja2dyb3VuZDogcmdiYSgxMzksMTUwLDI0MiwuMTQpOyBib3JkZXI6IDFweCBzb2xpZCByZ2JhKDEzOSwxNTAsMjQyLC40KTsgY29sb3I6IHZhcigtLWFjY2VudCk7IGJvcmRlci1yYWRpdXM6IDk5OXB4OyBwYWRkaW5nOiAzcHggMTFweDsgZm9udC13ZWlnaHQ6IDYwMDsgd2hpdGUtc3BhY2U6IG5vd3JhcDsgfQoKLmNub3RlcyB7IG1heC13aWR0aDogMTEwMHB4OyBtYXJnaW46IDIwcHggYXV0byAwOyBwYWRkaW5nOiAwIDRweDsgZGlzcGxheTogZ3JpZDsgZ3JpZC10ZW1wbGF0ZS1jb2x1bW5zOiBtaW5tYXgoMzAwcHgsIDNmcikgbWlubWF4KDI4MHB4LCAyZnIpOyBnYXA6IDIwcHggNDRweDsgfQpAbWVkaWEgKG1heC13aWR0aDogODYwcHgpIHsgLmNub3RlcyB7IGdyaWQtdGVtcGxhdGUtY29sdW1uczogMWZyOyB9IH0KLmNub3RlcyBoMyB7IGZvbnQtc2l6ZTogMTNweDsgZm9udC13ZWlnaHQ6IDcwMDsgbGV0dGVyLXNwYWNpbmc6IC4wMmVtOyBjb2xvcjogdmFyKC0taW5rMik7IG1hcmdpbjogMCAwIDEwcHg7IH0KLmNub3RlcyAud2h5IHAgeyBjb2xvcjogdmFyKC0taW5rMik7IGZvbnQtc2l6ZTogMTQuNXB4OyBtYXJnaW46IDAgMCAxMHB4OyBtYXgtd2lkdGg6IDY0Y2g7IH0KLmNub3RlcyAud2h5IHAgYiB7IGNvbG9yOiB2YXIoLS1pbmspOyBmb250LXdlaWdodDogNjUwOyB9CnRhYmxlLm1hcCB7IGJvcmRlci1jb2xsYXBzZTogY29sbGFwc2U7IHdpZHRoOiAxMDAlOyBmb250LXNpemU6IDEzcHg7IH0KdGFibGUubWFwIHRkIHsgcGFkZGluZzogNnB4IDEwcHggNnB4IDA7IHZlcnRpY2FsLWFsaWduOiB0b3A7IGJvcmRlci1ib3R0b206IDFweCBzb2xpZCB2YXIoLS1oYWlybGluZSk7IH0KdGFibGUubWFwIHRkOmZpcnN0LWNoaWxkIHsgZm9udC1mYW1pbHk6IHZhcigtLWZvbnQtbW9ubyk7IGZvbnQtc2l6ZTogMTEuNXB4OyBjb2xvcjogdmFyKC0taW5rMyk7IHdoaXRlLXNwYWNlOiBub3dyYXA7IHdpZHRoOiAxJTsgcGFkZGluZy1yaWdodDogMTZweDsgfQp0YWJsZS5tYXAgdGQ6bGFzdC1jaGlsZCB7IGNvbG9yOiB2YXIoLS1pbmsyKTsgfQp0YWJsZS5tYXAgdGQ6bGFzdC1jaGlsZCBiIHsgY29sb3I6IHZhcigtLWluayk7IGZvbnQtd2VpZ2h0OiA2MDA7IH0KCi8qIOKUgOKUgCBzbGlkZS1vdXQgZGV0YWlsIHBhbmUg4pSA4pSAICovCiNwYW5lIHsKICBwb3NpdGlvbjogYWJzb2x1dGU7IHRvcDogMDsgcmlnaHQ6IDA7IGJvdHRvbTogMDsgei1pbmRleDogMjA7CiAgd2lkdGg6IG1pbigzMzBweCwgODZ2dyk7CiAgYmFja2dyb3VuZDogcmdiYSgxNCwxNiwyNCwuOTcpOwogIGJvcmRlci1sZWZ0OiAxcHggc29saWQgdmFyKC0taGFpcmxpbmUtc3Ryb25nKTsKICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoMTA1JSk7CiAgdHJhbnNpdGlvbjogdHJhbnNmb3JtIC4zMHMgY3ViaWMtYmV6aWVyKC4xNiwxLC4zLDEpOwogIHBhZGRpbmc6IDE4cHggMThweCA2MHB4OwogIG92ZXJmbG93LXk6IGF1dG87CiAgZm9udC1mYW1pbHk6IHZhcigtLWZvbnQtbW9ubyk7IGZvbnQtc2l6ZTogMTEuNXB4OyBsaW5lLWhlaWdodDogMS42OyBjb2xvcjogdmFyKC0taW5rMik7Cn0KI3BhbmUub3BlbiB7IHRyYW5zZm9ybTogdHJhbnNsYXRlWCgwKTsgfQojcGFuZSBoNCB7IGZvbnQ6IDcwMCAxM3B4IHZhcigtLWZvbnQtbW9ubyk7IGNvbG9yOiB2YXIoLS1pbmspOyBtYXJnaW46IDAgMCAycHg7IG92ZXJmbG93LXdyYXA6IGFueXdoZXJlOyB9CiNwYW5lIC5raW5kY2hpcCB7IGRpc3BsYXk6IGlubGluZS1mbGV4OyBhbGlnbi1pdGVtczogY2VudGVyOyBnYXA6IDZweDsgZm9udC1zaXplOiAxMC41cHg7IGNvbG9yOiB2YXIoLS1pbmszKTsKICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1oYWlybGluZS1zdHJvbmcpOyBib3JkZXItcmFkaXVzOiA5OTlweDsgcGFkZGluZzogMnB4IDEwcHg7IG1hcmdpbjogNnB4IDAgMTJweDsgfQojcGFuZSAua2luZGNoaXAgaSB7IHdpZHRoOiA3cHg7IGhlaWdodDogN3B4OyBib3JkZXItcmFkaXVzOiA1MCU7IGRpc3BsYXk6IGlubGluZS1ibG9jazsgfQojcGFuZSAucm93IHsgZGlzcGxheTogZmxleDsganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOyBnYXA6IDEycHg7IHBhZGRpbmc6IDVweCAwOyBib3JkZXItYm90dG9tOiAxcHggc29saWQgdmFyKC0taGFpcmxpbmUpOyB9CiNwYW5lIC5yb3cgc3BhbjpmaXJzdC1jaGlsZCB7IGNvbG9yOiB2YXIoLS1pbmszKTsgd2hpdGUtc3BhY2U6IG5vd3JhcDsgfQojcGFuZSAucm93IHNwYW46bGFzdC1jaGlsZCB7IGNvbG9yOiB2YXIoLS1pbmsyKTsgdGV4dC1hbGlnbjogcmlnaHQ7IG92ZXJmbG93LXdyYXA6IGFueXdoZXJlOyB9CiNwYW5lIC5zZWN0IHsgbWFyZ2luLXRvcDogMTZweDsgZm9udDogNzAwIDEwLjVweCB2YXIoLS1mb250LW1vbm8pOyBsZXR0ZXItc3BhY2luZzogLjA0ZW07IGNvbG9yOiB2YXIoLS1pbmszKTsgfQojcGFuZSAuYmFyIHsgaGVpZ2h0OiA1cHg7IGJvcmRlci1yYWRpdXM6IDNweDsgYmFja2dyb3VuZDogcmdiYSgyNTUsMjU1LDI1NSwuMDgpOyBtYXJnaW46IDhweCAwIDRweDsgb3ZlcmZsb3c6IGhpZGRlbjsgfQojcGFuZSAuYmFyIGkgeyBkaXNwbGF5OiBibG9jazsgaGVpZ2h0OiAxMDAlOyBib3JkZXItcmFkaXVzOiAzcHg7IH0KI3BhbmUgdWwuZmFjdHMgeyBsaXN0LXN0eWxlOiBub25lOyBtYXJnaW46IDhweCAwIDA7IHBhZGRpbmc6IDA7IH0KI3BhbmUgdWwuZmFjdHMgbGkgeyBwYWRkaW5nOiA0cHggMCA0cHggMTRweDsgcG9zaXRpb246IHJlbGF0aXZlOyBmb250LXNpemU6IDEwLjVweDsgY29sb3I6IHZhcigtLWluazMpOyB9CiNwYW5lIHVsLmZhY3RzIGxpOjpiZWZvcmUgeyBjb250ZW50OiAnJzsgcG9zaXRpb246IGFic29sdXRlOyBsZWZ0OiAycHg7IHRvcDogOXB4OyB3aWR0aDogNnB4OyBoZWlnaHQ6IDZweDsgYm9yZGVyLXJhZGl1czogNTAlOyBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQpOyBvcGFjaXR5OiAuNjsgfQojcGFuZSB1bC5mYWN0cyBsaS5zZWwgeyBjb2xvcjogdmFyKC0taW5rKTsgfQojcGFuZSB1bC5mYWN0cyBsaSBiIHsgY29sb3I6IHZhcigtLWluazIpOyBmb250LXdlaWdodDogNjAwOyB9CiNwYW5lIC5ub3RlIHsgbWFyZ2luLXRvcDogMTJweDsgZm9udC1zaXplOiAxMC41cHg7IGNvbG9yOiB2YXIoLS1pbmszKTsgfQpAbWVkaWEgKHByZWZlcnMtcmVkdWNlZC1tb3Rpb246IHJlZHVjZSkgeyAjcGFuZSB7IHRyYW5zaXRpb246IG5vbmU7IH0gfQoKI3RpcCB7CiAgcG9zaXRpb246IGZpeGVkOyB6LWluZGV4OiA5MDsgcG9pbnRlci1ldmVudHM6IG5vbmU7CiAgYmFja2dyb3VuZDogcmdiYSgxOCwyMCwyOSwuOTcpOyBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1oYWlybGluZS1zdHJvbmcpOwogIGJvcmRlci1yYWRpdXM6IDEwcHg7IHBhZGRpbmc6IDhweCAxMnB4OwogIGZvbnQtZmFtaWx5OiB2YXIoLS1mb250LW1vbm8pOyBmb250LXNpemU6IDExLjVweDsgbGluZS1oZWlnaHQ6IDEuNTU7CiAgY29sb3I6IHZhcigtLWluazIpOyBib3gtc2hhZG93OiAwIDEwcHggMzBweCByZ2JhKDAsMCwwLC41KTsKICBtYXgtd2lkdGg6IDMyMHB4OyBvcGFjaXR5OiAwOyB0cmFuc2l0aW9uOiBvcGFjaXR5IC4xMnM7Cn0KI3RpcCBiIHsgY29sb3I6IHZhcigtLWluayk7IGZvbnQtd2VpZ2h0OiA2MDA7IH0KI3RpcCAuayB7IGNvbG9yOiB2YXIoLS1pbmszKTsgfQpmb290ZXIgeyBtYXgtd2lkdGg6IDExMDBweDsgbWFyZ2luOiA0OHB4IGF1dG8gMDsgcGFkZGluZzogMjBweCBjbGFtcCgxNnB4LCA0dncsIDQwcHgpIDUwcHg7IGJvcmRlci10b3A6IDFweCBzb2xpZCB2YXIoLS1oYWlybGluZSk7IGZvbnQtZmFtaWx5OiB2YXIoLS1mb250LW1vbm8pOyBmb250LXNpemU6IDExLjVweDsgY29sb3I6IHZhcigtLWluazMpOyB9CkBtZWRpYSAocHJlZmVycy1yZWR1Y2VkLW1vdGlvbjogcmVkdWNlKSB7ICN0aXAgeyB0cmFuc2l0aW9uOiBub25lOyB9IH0KPC9zdHlsZT4KCjxzY3JpcHQ+aWYgKHdpbmRvdy5zZWxmICE9PSB3aW5kb3cudG9wKSBkb2N1bWVudC5kb2N1bWVudEVsZW1lbnQuY2xhc3NMaXN0LmFkZCgnZnJhbWVkJyk7PC9zY3JpcHQ+CjxoZWFkZXIgaWQ9InRvcGJhciI+CiAgPHNwYW4gY2xhc3M9ImJyYW5kIj5jcnV4IDxzcGFuPsK3IGNvbnNvbGU8L3NwYW4+PC9zcGFuPgogIDxzcGFuIGNsYXNzPSJwaWxsIj48c3BhbiBjbGFzcz0iZG90Ij48L3NwYW4+ZGFlbW9uIMK3IGxvY2FsPC9zcGFuPgogIDxzcGFuIGNsYXNzPSJwaWxsIj5odHRwIDoxNDgwMCDCtyBtY3AgOjE0ODAxPC9zcGFuPgogIDxzcGFuIGNsYXNzPSJzcCI+PC9zcGFuPgogIDxzcGFuIGNsYXNzPSJwaWxsIj5zbmFwc2hvdCDCtyAyMDI2LTA3LTIyPC9zcGFuPgo8L2hlYWRlcj4KCgo8c2VjdGlvbiBjbGFzcz0iY29uY2VwdCIgaWQ9InJpbmdzIj4KICA8ZGl2IGNsYXNzPSJzdGFnZXdyYXAiPgogICAgPGNhbnZhcyBpZD0iY3YiIGFyaWEtbGFiZWw9IlJpbmdzOiByZWFsIGV4ZWNwbGFuIHBvcnRmb2xpbyByZXBsYXllZCBhcyBhbiBhbmltYXRlZCBjbG9jazsgdGlsZXMgc3dpdGNoIHRoZSBsZW5zIj48L2NhbnZhcz4KICAgIDxkaXYgaWQ9InRpbGVzIiByb2xlPSJncm91cCIgYXJpYS1sYWJlbD0iUmluZyBsZW5zZXMiPgogICAgICA8YnV0dG9uIGNsYXNzPSJ0aWxlIiBkYXRhLWxlbnM9IndvcmsiIGFyaWEtcHJlc3NlZD0idHJ1ZSI+CiAgICAgICAgPHNwYW4gY2xhc3M9InQiPjxpIHN0eWxlPSJiYWNrZ3JvdW5kOiNhNzhiZmEiPjwvaT5FeGVjUGxhbnM8L3NwYW4+PHNwYW4gY2xhc3M9Im4iPjEsMDQwPC9zcGFuPgogICAgICA8L2J1dHRvbj4KICAgICAgPGJ1dHRvbiBjbGFzcz0idGlsZSIgZGF0YS1sZW5zPSJkYXRhIiBhcmlhLXByZXNzZWQ9ImZhbHNlIj4KICAgICAgICA8c3BhbiBjbGFzcz0idCI+PGkgc3R5bGU9ImJhY2tncm91bmQ6IzhiOTZmMiI+PC9pPkRhdGEgZ3JhcGg8L3NwYW4+PHNwYW4gY2xhc3M9Im4iIGlkPSJ0aWxlLWRhdGEiPjY2PC9zcGFuPgogICAgICA8L2J1dHRvbj4KICAgICAgPGJ1dHRvbiBjbGFzcz0idGlsZSIgZGF0YS1sZW5zPSJtZW1vcnkiIGFyaWEtcHJlc3NlZD0iZmFsc2UiPgogICAgICAgIDxzcGFuIGNsYXNzPSJ0Ij48aSBzdHlsZT0iYmFja2dyb3VuZDojMmRkNGJmIj48L2k+TWVtb3J5PC9zcGFuPjxzcGFuIGNsYXNzPSJuIj4yMTwvc3Bhbj4KICAgICAgPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9InRpbGUiIGRhdGEtbGVucz0ic2Vzc2lvbnMiIGFyaWEtcHJlc3NlZD0iZmFsc2UiPgogICAgICAgIDxzcGFuIGNsYXNzPSJ0Ij48aSBzdHlsZT0iYmFja2dyb3VuZDojMjJkM2VlIj48L2k+U2Vzc2lvbnM8L3NwYW4+PHNwYW4gY2xhc3M9Im4iIGlkPSJ0aWxlLXNlc3Npb25zIj4zMjwvc3Bhbj4KICAgICAgPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9InRpbGUiIGRhdGEtbGVucz0idG9rZW5zIiBhcmlhLXByZXNzZWQ9ImZhbHNlIj4KICAgICAgICA8c3BhbiBjbGFzcz0idCI+PGkgc3R5bGU9ImJhY2tncm91bmQ6I2Y1YTYyMyI+PC9pPlRva2Vuczwvc3Bhbj48c3BhbiBjbGFzcz0ibiIgaWQ9InRpbGUtdG9rIj7igJQ8L3NwYW4+CiAgICAgIDwvYnV0dG9uPgogICAgPC9kaXY+CiAgICA8ZGl2IGlkPSJnbGFuY2UiIHJvbGU9Imdyb3VwIiBhcmlhLWxhYmVsPSJEYWVtb24gYXQgYSBnbGFuY2UiPgogICAgICA8YnV0dG9uIGNsYXNzPSJnbCI+PHNwYW4gY2xhc3M9InQiPmZhY3RzPC9zcGFuPjxzcGFuIGNsYXNzPSJuIiBpZD0iZ2wtZmFjdHMiPjUsMDI2PC9zcGFuPjwvYnV0dG9uPgogICAgICA8YnV0dG9uIGNsYXNzPSJnbCI+PHNwYW4gY2xhc3M9InQiPnNlc3Npb25zPC9zcGFuPjxzcGFuIGNsYXNzPSJuIiBpZD0iZ2wtc2Vzc2lvbnMiPjc2PC9zcGFuPjwvYnV0dG9uPgogICAgICA8YnV0dG9uIGNsYXNzPSJnbCI+PHNwYW4gY2xhc3M9InQiPmV4ZWNwbGFuczwvc3Bhbj48c3BhbiBjbGFzcz0ibiIgaWQ9ImdsLWV4ZWNwbGFucyI+MSwwODE8L3NwYW4+PC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9ImdsIj48c3BhbiBjbGFzcz0idCI+bWNwIGFnZW50czwvc3Bhbj48c3BhbiBjbGFzcz0ibiIgaWQ9ImdsLW1jcCI+NTwvc3Bhbj48L2J1dHRvbj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iZ2wiPjxzcGFuIGNsYXNzPSJ0Ij5pbnRlZ3JhdGlvbnM8L3NwYW4+PHNwYW4gY2xhc3M9Im4iIGlkPSJnbC1pbnQiPjM8L3NwYW4+PC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9ImdsIj48c3BhbiBjbGFzcz0idCI+ZW5naW5lPC9zcGFuPjxzcGFuIGNsYXNzPSJuIiBpZD0iZ2wtZW5naW5lIj5vZmY8L3NwYW4+PC9idXR0b24+CiAgICAgIDxzcGFuIGNsYXNzPSJzcmMiIGlkPSJnbC1zcmMiPnNuYXBzaG90IMK3IDIwMjYtMDctMjI8L3NwYW4+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9InN0YWdlYmFyIj4KICAgICAgPHNwYW4gY2xhc3M9ImdycCI+CiAgICAgICAgPGJ1dHRvbiBpZD0iYi1zcGluIiBjbGFzcz0iaWMiIGFyaWEtcHJlc3NlZD0idHJ1ZSIgdGl0bGU9IkFtYmllbnQgc3BpbiI+4p+zPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBpZD0iYi1jbG9jayIgY2xhc3M9ImljIiB0aXRsZT0iUmVzZXQgY2xvY2sgdG8gMTIgKGFsc28gc3RvcHMgc3BpbikiPuKXtzwvYnV0dG9uPgogICAgICAgIDxidXR0b24gaWQ9ImItbW9kZSIgY2xhc3M9ImljIiBhcmlhLXByZXNzZWQ9InRydWUiIHRpdGxlPSJCYXJzOiBzcG9rZSBmcm9tIGNlbnRyZSB0byBlYWNoIG5vZGUiPuKWpTwvYnV0dG9uPgogICAgICAgIDxidXR0b24gaWQ9ImItZGlyIiBjbGFzcz0iaWMiIGFyaWEtcHJlc3NlZD0iZmFsc2UiIHRpdGxlPSJUaW1lIGVkZ2U6IG91dHdhcmQgKHJpbmdzIGdyb3cpIC8gaW53YXJkIChub2RlcyBzaW5rIGZyb20gcmltKSI+4oeFPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBpZD0iYi1hbGwiIGNsYXNzPSJpYyIgYXJpYS1wcmVzc2VkPSJmYWxzZSIgdGl0bGU9IkNlbnN1czogZXZlcnkgcGxhbiBzdGF5cyBvbiB0aGUgY2xvY2s7IGhvdmVyIG5hbWVzIHNlY3RvcnMiPuKXjDwvYnV0dG9uPgogICAgICAgIDxidXR0b24gaWQ9ImItZG9uZSIgY2xhc3M9ImljIiBhcmlhLXByZXNzZWQ9ImZhbHNlIiB0aXRsZT0iU2hvdyBjb21wbGV0ZWQgcGxhbnMgb24gdGhlIGNsb2NrIChhdXRvLW9uIGR1cmluZyBwbGF5YmFjaykiPuKckzwvYnV0dG9uPgogICAgICAgIDxidXR0b24gaWQ9ImItbGVkZ2VyIiBjbGFzcz0iaWMiIGFyaWEtcHJlc3NlZD0iZmFsc2UiIHRpdGxlPSJDb21wbGV0ZWQtcGxhbnMgbGlzdCAobGVmdCkuIEF1dG8tc2hvd3MgZHVyaW5nIHBsYXliYWNrOyBoaWRlcyBvbiBsZW5zIHN3YXAuIj7iiaE8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGlkPSJiLXN0YXRlIiBjbGFzcz0iaWMiIGFyaWEtcHJlc3NlZD0iZmFsc2UiIHRpdGxlPSJTdGF0ZSBjb2xvdXJzOiBjb21wbGV0ZSBncmVlbiDCtyBpbiBwcm9ncmVzcyBwdXJwbGUgwrcgYmxvY2tlZCByZWQiPuKXkTwvYnV0dG9uPgogICAgICAgIDxidXR0b24gaWQ9ImItbGluIiBjbGFzcz0iaWMiIGFyaWEtcHJlc3NlZD0iZmFsc2UiIHRpdGxlPSJMaW5lYWdlIGNob3JkcyAoZGVwZW5kc19vbikiPuKMhzwvYnV0dG9uPgogICAgICA8L3NwYW4+CiAgICAgIDxzcGFuIGNsYXNzPSJncnAiPgogICAgICAgIDxzZWxlY3QgaWQ9InMta2luZCIgYXJpYS1sYWJlbD0iRmlsdGVyIGJ5IG5vZGUga2luZCI+CiAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJhbGwiPmFsbCBraW5kczwvb3B0aW9uPgogICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iZ2F0ZSI+Z2F0ZXMgb25seTwvb3B0aW9uPgogICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iZGVjaXNpb24iPmRlY2lzaW9ucyAoT0QpIG9ubHk8L29wdGlvbj4KICAgICAgICAgIDxvcHRpb24gdmFsdWU9Im1lbW9yeSI+bWVtb3J5IG9ubHk8L29wdGlvbj4KICAgICAgICAgIDxvcHRpb24gdmFsdWU9ImhhbmRvZmYiPmhhbmRvZmZzIG9ubHk8L29wdGlvbj4KICAgICAgICA8L3NlbGVjdD4KICAgICAgICA8c2VsZWN0IGlkPSJzLWFnZW50IiBhcmlhLWxhYmVsPSJGaWx0ZXIgYnkgYWdlbnQgcGFzc3BvcnQiPgogICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iYWxsIj5hbGwgYWdlbnRzPC9vcHRpb24+CiAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJjbGF1ZGUtd29yayI+Y2xhdWRlLXdvcms8L29wdGlvbj4KICAgICAgICAgIDxvcHRpb24gdmFsdWU9ImNvZGV4LXdvcmsiPmNvZGV4LXdvcms8L29wdGlvbj4KICAgICAgICA8L3NlbGVjdD4KICAgICAgPC9zcGFuPgogICAgICA8c3BhbiBjbGFzcz0iZ3JwIiBpZD0idG9rLXZpZXdzIiBzdHlsZT0iZGlzcGxheTpub25lIj4KICAgICAgICA8YnV0dG9uIGlkPSJiLXRvay1jdW0iIGFyaWEtcHJlc3NlZD0idHJ1ZSIgdGl0bGU9IlJ1bm5pbmcgdG90YWwgYWNyb3NzIHRoZSB3aW5kb3ciPmN1bXVsYXRpdmU8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGlkPSJiLXRvay1kYXkiIGFyaWEtcHJlc3NlZD0iZmFsc2UiIHRpdGxlPSJUb2tlbnMgcGVyIGRheSI+cGVyIGRheTwvYnV0dG9uPgogICAgICA8L3NwYW4+CiAgICAgIDxzcGFuIGNsYXNzPSJncnAiPgogICAgICAgIDxpbnB1dCBpZD0iZC1zdGFydCIgdHlwZT0iZGF0ZSIgbWluPSIyMDI2LTA1LTE4IiBtYXg9IjIwMjYtMDctMjIiIHZhbHVlPSIyMDI2LTA1LTE4IiBhcmlhLWxhYmVsPSJXaW5kb3cgc3RhcnQgZGF0ZSI+CiAgICAgICAgPGlucHV0IGlkPSJyLXN0YXJ0IiB0eXBlPSJyYW5nZSIgbWluPSIwIiBtYXg9IjEwMDAiIHZhbHVlPSIwIiBzdHlsZT0id2lkdGg6NzBweCIgYXJpYS1sYWJlbD0iV2luZG93IHN0YXJ0Ij4KICAgICAgICA8aW5wdXQgaWQ9InItZW5kIiB0eXBlPSJyYW5nZSIgbWluPSIwIiBtYXg9IjEwMDAiIHZhbHVlPSIxMDAwIiBzdHlsZT0id2lkdGg6NzBweCIgYXJpYS1sYWJlbD0iV2luZG93IGVuZCI+CiAgICAgICAgPGlucHV0IGlkPSJkLWVuZCIgdHlwZT0iZGF0ZSIgbWluPSIyMDI2LTA1LTE4IiBtYXg9IjIwMjYtMDctMjIiIHZhbHVlPSIyMDI2LTA3LTIyIiBhcmlhLWxhYmVsPSJXaW5kb3cgZW5kIGRhdGUiPgogICAgICA8L3NwYW4+CiAgICAgIDxzcGFuIGNsYXNzPSJncnAiPgogICAgICAgIDxidXR0b24gaWQ9ImItcGxheSIgY2xhc3M9ImljIiBhcmlhLXByZXNzZWQ9ImZhbHNlIiB0aXRsZT0iUmVwbGF5IHRoZSB3aW5kb3ciPuKWtjwvYnV0dG9uPgogICAgICAgIDxpbnB1dCBpZD0ici10aW1lIiB0eXBlPSJyYW5nZSIgbWluPSIwIiBtYXg9IjEwMDAiIHZhbHVlPSIxMDAwIiBhcmlhLWxhYmVsPSJUaW1lIj4KICAgICAgICA8c3BhbiBpZD0iYy1kYXRlIiBjbGFzcz0iY2hpcCI+MjAyNi0wNy0yMjwvc3Bhbj4KICAgICAgPC9zcGFuPgogICAgICA8c3BhbiBjbGFzcz0iZ3JwIj4KICAgICAgICA8YnV0dG9uIGlkPSJiLXppbiIgYXJpYS1sYWJlbD0iWm9vbSBpbiI+KzwvYnV0dG9uPgogICAgICAgIDxidXR0b24gaWQ9ImItem91dCIgYXJpYS1sYWJlbD0iWm9vbSBvdXQiPuKIkjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gaWQ9ImItemZpdCI+Zml0PC9idXR0b24+CiAgICAgIDwvc3Bhbj4KICAgICAgPHNwYW4gY2xhc3M9ImhpbnQiIGlkPSJoaW50Ij53aGVlbCA9IHpvb20gwrcgZHJhZyA9IHBhbiDCtyBjbGljayBub2RlIC8gc2VjdG9yIC8gbGVkZ2VyIMK3IGJhY2tncm91bmQgY2xlYXJzPC9zcGFuPgogICAgPC9kaXY+CiAgICA8YXNpZGUgaWQ9InBhbmUiIGFyaWEtbGFiZWw9IkRldGFpbCBwYW5lIj48L2FzaWRlPgogIDwvZGl2PgogIDxwIHN0eWxlPSJtYXgtd2lkdGg6MTI0MHB4O21hcmdpbjoxMHB4IGF1dG8gMDtwYWRkaW5nOjAgY2xhbXAoMTZweCwzdncsMzJweCk7Zm9udDoxMXB4IHZhcigtLWZvbnQtbW9ubyk7Y29sb3I6dmFyKC0taW5rMykiPm1vY2sgwrcgdGlsZXMgc3dpdGNoIHRoZSBsZW5zIMK3IEV4ZWNQbGFucyBsZW5zIGtlZXBzIHNvbG8gLyBsZWRnZXIgLyBsaW5lYWdlIC8gZmlsdGVycyDCtyBzbmFwc2hvdCBkYXRhLCBsaXZlLXdpcmU6IC92MS93b3JrIMK3IC92MS9mYWN0cy9saXN0IMK3IHJlY2VpcHRzIGJ5IHNlcTwvcD4KPC9zZWN0aW9uPgoKCjxkaXYgaWQ9InRpcCIgcm9sZT0ic3RhdHVzIj48L2Rpdj4KCjxzY3JpcHQ+CihmdW5jdGlvbiAoKSB7Cid1c2Ugc3RyaWN0JzsKY29uc3QgUExBTlNfUkFXID0gW3sicyI6ImNvcmVjcnV4LW9iamVjdC1zdG9yYWdlLXRpZXItMjAyNi0wNy0wNyIsInN0IjowLCJkIjo2LCJ0Ijo2LCJiIjo2MSwiZSI6NzYsIm8iOjU5LCJkZXAiOlsiY29yZWNydXgtbWVtb3J5LW1hbmFnZXItMjAyNi0wNy0wNSJdLCJleHQiOltdLCJvZCI6W119LHsicyI6InRpZXItcGFja2FnaW5nLXAxLXJlbWVkaWF0aW9uLTIwMjYtMDctMTMiLCJzdCI6MSwiZCI6MCwidCI6MSwiYiI6NjcsImUiOjc2LCJvIjo1NSwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LWRhZW1vbi1idXllci1maXQtYnVpbGRvdXQtMjAyNi0wNy0xMyIsInN0IjoxLCJkIjoxLCJ0Ijo4LCJiIjo2NywiZSI6NzYsIm8iOjY0LCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtYXVkaXQtdjItY2xvc2VvdXQtMjAyNi0wNy0xNSIsInN0IjowLCJkIjo3LCJ0Ijo3LCJiIjo2OSwiZSI6NzUsIm8iOjU2LCJkZXAiOlsiY3J1eC1hdWRpdC12Mi1yZW1lZGlhdGlvbi0yMDI2LTA3LTEzIl0sImV4dCI6W10sIm9kIjpbXX0seyJzIjoidmF1bHQtY29uc29saWRhdGlvbi0yMDI2LTA0LTA3Iiwic3QiOjEsImQiOjAsInQiOjgsImIiOjU0LCJlIjo3NSwibyI6ODAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3Jvc3Mtc2l0ZS1hdXRoLXNzby1jdWVjcnV4LTIwMjYtMDctMTMiLCJzdCI6MSwiZCI6MywidCI6NiwiYiI6NjcsImUiOjc1LCJvIjo2NywiZGVwIjpbInBhZGRsZS1iaWxsaW5nLXN0YXRlLTIwMjYtMDctMTMiLCJ1bmlmaWVkLXNoZWxsLWNvbnNvbGUtMjAyNi0wNy0wMyJdLCJleHQiOlsiY3VlY3J1eC1zZWxmc2VydmUtbGF1bmNoLXJlYWRpbmVzcy0yMDI2LTA3LTE2Il0sIm9kIjpbXX0seyJzIjoid2lraWNydXgtYWdlbnQtcHVibGlzaC1wbGFuZS1zaGFyZWQtdGVuYW50LTIwMjYtMDctMDkiLCJzdCI6MSwiZCI6MSwidCI6NiwiYiI6NzMsImUiOjc0LCJvIjo1LCJkZXAiOlsid2lraWNydXgtYWdlbnQtYWRvcHRpb24tc2VxdWVuY2UtMjAyNi0wNy0wOCIsIndpa2ljcnV4LWFnZW50LWZpcnN0LXdpa2ktc2VydmljZS0yMDI2LTA2LTExIl0sImV4dCI6WyJ3aWtpY3J1eC1hZG9wdGlvbi10ZWxlbWV0cnktYW5kLWNvcnB1cy1mbHl3aGVlbC0yMDI2LTA3LTA5Il0sIm9kIjpbXX0seyJzIjoicG9ydGZvbGlvLWJ1cm4tZG93bi1vcmNoZXN0cmF0aW9uLTIwMjYtMDctMTAiLCJzdCI6MiwiZCI6MiwidCI6OCwiYiI6NjQsImUiOjc0LCJvIjo1NCwiZGVwIjpbImNvbW1lcmNlLXBhZGRsZS1iaWxsaW5nLTIwMjYtMDYtMTEiLCJjcnV4LWNyZWRpdC1idXJuLXJhaWwtMjAyNi0wNi0yMiIsInByb2R1Y3Rpb24tY3V0b3Zlci1vcmNoZXN0cmF0aW9uLTIwMjYtMDctMDciXSwiZXh0IjpbXSwib2QiOlsiT0QtMSJdfSx7InMiOiJjb21tZXJjZS1wYWRkbGUtYmlsbGluZy0yMDI2LTA2LTExIiwic3QiOjEsImQiOjAsInQiOjgsImIiOjU4LCJlIjo3MiwibyI6NTEsImRlcCI6W10sImV4dCI6WyJwb3J0Zm9saW8tYnVybi1kb3duLW9yY2hlc3RyYXRpb24tMjAyNi0wNy0xMCJdLCJvZCI6W119LHsicyI6ImRhZW1vbi1kaXN0cmlidXRpb24tcGFja2FnaW5nLTIwMjYtMDYtMTEiLCJzdCI6MCwiZCI6NywidCI6NywiYiI6MzYsImUiOjcyLCJvIjoxMzcsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiZXNpLXYyLW5vLWJsaW5kc3BvdC1saXZlLXdyaXRlLTIwMjYtMDYtMDMiLCJzdCI6MiwiZCI6MywidCI6NiwiYiI6MjcsImUiOjcyLCJvIjoxMzcsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoidW5pZmllZC1zaGVsbC1jb25zb2xlLTIwMjYtMDctMDMiLCJzdCI6MSwiZCI6MTIsInQiOjEzLCJiIjo1NywiZSI6NTgsIm8iOjE3LCJkZXAiOlsib3Blbi1lbmdpbmUtY29vcmRpbmF0aW9uLXN1cmZhY2VzLTIwMjYtMDYtMzAiXSwiZXh0IjpbImNyb3NzLXNpdGUtYXV0aC1zc28tY3VlY3J1eC0yMDI2LTA3LTEzIl0sIm9kIjpbXX0seyJzIjoid2lraWNydXgtcHJvc2UtZGVuc2UtcmVlbWJlZC1mbG9hdDE2LXBvb2wtMjAyNi0wNi0yNyIsInN0IjowLCJkIjozLCJ0Ijo1LCJiIjo1MSwiZSI6NTEsIm8iOjcsImRlcCI6W10sImV4dCI6WyJ3aWtpY3J1eC1yZXRyaWV2YWwtcXVhbGl0eS1oYXJkZW5pbmctMjAyNi0wNi0yOCJdLCJvZCI6W119LHsicyI6Indpa2ljcnV4LXB1YmxpYy1jb2RlbWFwcy0yMDI2LTA3LTEwIiwic3QiOjEsImQiOjQsInQiOjQsImIiOjY0LCJlIjo2NCwibyI6MCwiZGVwIjpbXSwiZXh0IjpbImNvZGVtYXBzLWNyb3NzLXJlcG8tZ3JhcGgtYW5kLXZhbHVlLWV4cGFuc2lvbi0yMDI2LTA3LTEwIl0sIm9kIjpbXX0seyJzIjoid2lraWNydXgtcmV0cmlldmFsLXF1YWxpdHktaGFyZGVuaW5nLTIwMjYtMDYtMjgiLCJzdCI6MCwiZCI6NiwidCI6NywiYiI6NTIsImUiOjUyLCJvIjoxMSwiZGVwIjpbIndpa2ljcnV4LXByb3NlLWRlbnNlLXJlZW1iZWQtZmxvYXQxNi1wb29sLTIwMjYtMDYtMjciXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJ3aWtpLXByb3NlLXJlc2lkdWFsLWV4dHJhY3Rpb24tMjAyNi0wNi0zMCIsInN0IjowLCJkIjozLCJ0Ijo0LCJiIjo1NCwiZSI6NTUsIm8iOjE1LCJkZXAiOltdLCJleHQiOlsidW5pZmllZC1yZXRyaWV2YWwtaGFyZGVuaW5nLTIwMjYtMDctMDIiXSwib2QiOltdfSx7InMiOiJ2ZXJuYWN1bGFyLXJldHJpZXZhbC1saWZ0LWNoZWNrLTIwMjYtMDUtMjEiLCJzdCI6MCwiZCI6MCwidCI6NywiYiI6MTQsImUiOjE0LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6Indpa2ktY3VlY3J1eC1jb20tcHJvZC1kZXBsb3ktMjAyNi0wNy0wOCIsInN0IjowLCJkIjowLCJ0Ijo1LCJiIjo2MiwiZSI6NjIsIm8iOjQsImRlcCI6WyJ3aWtpY3J1eC1hZ2VudC1maXJzdC13aWtpLXNlcnZpY2UtMjAyNi0wNi0xMSIsIndpa2ljcnV4LWdyb3VuZGluZy1wb2lzb25pbmctZGVmZW5zZS0yMDI2LTA3LTA4Il0sImV4dCI6WyJ3aWtpY3J1eC1hZG9wdGlvbi10ZWxlbWV0cnktYW5kLWNvcnB1cy1mbHl3aGVlbC0yMDI2LTA3LTA5Il0sIm9kIjpbXX0seyJzIjoid2lraWNydXgtYWdlbnQtbGFuZ3VhZ2UtZW5jb2RlLTIwMjYtMDYtMjgiLCJzdCI6MSwiZCI6NSwidCI6MTAsImIiOjUyLCJlIjo1MywibyI6MzAsImRlcCI6WyJjbGFzc2ljYWwtbmVyLWF0LWluZ2VzdC0yMDI2LTA1LTA1Iiwid2lraWNydXgtYWdlbnQtZmlyc3Qtd2lraS1zZXJ2aWNlLTIwMjYtMDYtMTEiLCJ3aWtpY3J1eC1mdWxsLWVud2lraS1pbmdlc3QtMjAyNi0wNi0yOCJdLCJleHQiOlsidW5pZmllZC1yZWFzb25lci1lbmNvZGUtZXZpZGVuY2UtMjAyNi0wNi0yOSJdLCJvZCI6W119LHsicyI6Indpa2ljcnV4LWdyb3VuZGluZy1wb2lzb25pbmctZGVmZW5zZS0yMDI2LTA3LTA4Iiwic3QiOjAsImQiOjUsInQiOjYsImIiOjYyLCJlIjo2MiwibyI6NCwiZGVwIjpbIndpa2ljcnV4LWFnZW50LWZpcnN0LXdpa2ktc2VydmljZS0yMDI2LTA2LTExIl0sImV4dCI6WyJ3aWtpLWN1ZWNydXgtY29tLXByb2QtZGVwbG95LTIwMjYtMDctMDgiLCJ3aWtpY3J1eC1hZG9wdGlvbi10ZWxlbWV0cnktYW5kLWNvcnB1cy1mbHl3aGVlbC0yMDI2LTA3LTA5Il0sIm9kIjpbXX0seyJzIjoidmF1bHRjcnV4LXNlYXJjaC1vdXRjb21lLWNvcnB1cy1wb2xsdXRpb24tMjAyNi0wNS0zMSIsInN0IjowLCJkIjoyLCJ0IjozLCJiIjoyNCwiZSI6MjQsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoid2lraWNydXgtaWRlbXBvdGVudC1pbmdlc3Rpb24tMjAyNi0wNi0xNCIsInN0IjoxLCJkIjo0LCJ0IjoxMCwiYiI6MzgsImUiOjUyLCJvIjo0OCwiZGVwIjpbXSwiZXh0IjpbIndpa2ljcnV4LWFkb3B0aW9uLXRlbGVtZXRyeS1hbmQtY29ycHVzLWZseXdoZWVsLTIwMjYtMDctMDkiXSwib2QiOltdfSx7InMiOiJ3aWtpY3J1eC1hZ2VudC1maXJzdC13aWtpLXNlcnZpY2UtMjAyNi0wNi0xMSIsInN0IjoxLCJkIjozLCJ0Ijo4LCJiIjozNSwiZSI6MzcsIm8iOjEsImRlcCI6W10sImV4dCI6WyJ3aWtpLWN1ZWNydXgtY29tLXByb2QtZGVwbG95LTIwMjYtMDctMDgiLCJ3aWtpY3J1eC1hZG9wdGlvbi10ZWxlbWV0cnktYW5kLWNvcnB1cy1mbHl3aGVlbC0yMDI2LTA3LTA5Iiwid2lraWNydXgtYWdlbnQtYWRvcHRpb24tc2VxdWVuY2UtMjAyNi0wNy0wOCIsIndpa2ljcnV4LWFnZW50LWxhbmd1YWdlLWVuY29kZS0yMDI2LTA2LTI4Iiwid2lraWNydXgtYWdlbnQtcHVibGlzaC1wbGFuZS1zaGFyZWQtdGVuYW50LTIwMjYtMDctMDkiLCJ3aWtpY3J1eC1ncm91bmRpbmctcG9pc29uaW5nLWRlZmVuc2UtMjAyNi0wNy0wOCJdLCJvZCI6W119LHsicyI6Indpa2ljcnV4LWZ1bGwtZW53aWtpLWluZ2VzdC0yMDI2LTA2LTI4Iiwic3QiOjEsImQiOjIsInQiOjksImIiOjUyLCJlIjo1NCwibyI6MzMsImRlcCI6W10sImV4dCI6WyJlbndpa2ktcHJvc2UtZGVkaWNhdGVkLXNlcnZpbmctZGF0YS0xLTIwMjYtMDctMDMiLCJ3aWtpY3J1eC1hZG9wdGlvbi10ZWxlbWV0cnktYW5kLWNvcnB1cy1mbHl3aGVlbC0yMDI2LTA3LTA5Iiwid2lraWNydXgtYWdlbnQtbGFuZ3VhZ2UtZW5jb2RlLTIwMjYtMDYtMjgiXSwib2QiOltdfSx7InMiOiJ3aWtpY3J1eC1hZG9wdGlvbi10ZWxlbWV0cnktYW5kLWNvcnB1cy1mbHl3aGVlbC0yMDI2LTA3LTA5Iiwic3QiOjEsImQiOjUsInQiOjEwLCJiIjo2MywiZSI6NjcsIm8iOjgsImRlcCI6WyJlbndpa2ktcHJvc2UtZGVkaWNhdGVkLXNlcnZpbmctZGF0YS0xLTIwMjYtMDctMDMiLCJ3aWtpLWN1ZWNydXgtY29tLXByb2QtZGVwbG95LTIwMjYtMDctMDgiLCJ3aWtpY3J1eC1hZ2VudC1hZG9wdGlvbi1zZXF1ZW5jZS0yMDI2LTA3LTA4Iiwid2lraWNydXgtYWdlbnQtZmlyc3Qtd2lraS1zZXJ2aWNlLTIwMjYtMDYtMTEiLCJ3aWtpY3J1eC1hZ2VudC1wdWJsaXNoLXBsYW5lLXNoYXJlZC10ZW5hbnQtMjAyNi0wNy0wOSIsIndpa2ljcnV4LWZ1bGwtZW53aWtpLWluZ2VzdC0yMDI2LTA2LTI4Iiwid2lraWNydXgtZ3JvdW5kaW5nLXBvaXNvbmluZy1kZWZlbnNlLTIwMjYtMDctMDgiLCJ3aWtpY3J1eC1pZGVtcG90ZW50LWluZ2VzdGlvbi0yMDI2LTA2LTE0Il0sImV4dCI6W10sIm9kIjpbXX0seyJzIjoidmF1bHRjcnV4LWNvbXBhbmlvbi1sYW5lLXRyYW5zZm9ybXMtYW5kLWNjeGV2LTIwMjYtMDUtMjAiLCJzdCI6MCwiZCI6MCwidCI6MTAsImIiOjE1LCJlIjoxNSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJ2YXVsdGNydXgtbXVsdGktcHJlZGljYXRlLWVudW1lcmF0ZS0yMDI2LTA0LTI5Iiwic3QiOjAsImQiOjAsInQiOjMsImIiOjIwLCJlIjoyMCwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJ2YXVsdGNydXgtbXVsdGktcHJlZGljYXRlLW0zLXZlcmlmeS1idWlsZC0yMDI2LTA2LTA5Iiwic3QiOjAsImQiOjEsInQiOjUsImIiOjM0LCJlIjozNCwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJ0ZW5hbnQtaXNvbGF0aW9uLXBvbGljeS1hbmQtc2lsby0yMDI2LTA2LTI0Iiwic3QiOjAsImQiOjcsInQiOjcsImIiOjQ4LCJlIjo1MCwibyI6MjUsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoicmVsZWFzZS1yZWFkaW5lc3MtbWFzdGVyLTIwMjYtMDYtMTEiLCJzdCI6MSwiZCI6MCwidCI6NiwiYiI6MzUsImUiOjQ5LCJvIjo1MiwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJ0aWVyMC1kZXRlcm1pbmlzdGljLWxldmVycy0yMDI2LTA2LTMwIiwic3QiOjAsImQiOjUsInQiOjUsImIiOjU0LCJlIjo1NCwibyI6NiwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJzY29yZWNydXgtY29kaW5nLWludGVsbGlnZW5jZS1yZWZyZXNoLTIwMjYtMDYtMjUiLCJzdCI6MSwiZCI6MCwidCI6NSwiYiI6NDksImUiOjUwLCJvIjo1LCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6InRpZXItcGFja2FnaW5nLWFuZC1zaXRlLXJlZnJhbWUtMjAyNi0wNy0xMyIsInN0IjoxLCJkIjo3LCJ0Ijo4LCJiIjo2NiwiZSI6NjcsIm8iOjUsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoidW5pZmllZC1yZXRyaWV2YWwtaGFyZGVuaW5nLTIwMjYtMDctMDIiLCJzdCI6MiwiZCI6NywidCI6MTAsImIiOjU1LCJlIjo1NiwibyI6MSwiZGVwIjpbImNjeGktcXVlcnktc2hhcGUtcm91dGluZy0yMDI2LTA2LTMwIiwiY29yZWNydXgtb2ZmbGluZS1hdHRhY2gtY2FuZGlkYXRlLXNlbGVjdGlvbi0yMDI2LTA3LTAxIiwiZW1iZWRkZXItcG9vbC1kaXN0cmlidXRpb24tbWFuYWdlci0yMDI2LTA3LTAxIiwidW5pZmllZC1wcm9kdWN0aW9uLWNsYWltcy1zb3VyY2UtMjAyNi0wNi0zMCIsInVuaWZpZWQtcmVhc29uZXItZW5jb2RlLWV2aWRlbmNlLTIwMjYtMDYtMjkiLCJ3aWtpLXByb3NlLXJlc2lkdWFsLWV4dHJhY3Rpb24tMjAyNi0wNi0zMCJdLCJleHQiOltdLCJvZCI6WyJPRC0xIiwiT0QtMiIsIk9ELTMiXX0seyJzIjoicHJvb2YtY2FycnlpbmctYWRhcHRpdmUtcGFja3MtMjAyNi0wNy0xMyIsInN0IjoxLCJkIjowLCJ0Ijo3LCJiIjo2NywiZSI6NjcsIm8iOjUsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoic2VjdXJpdHktY3JpdGljYWwtNy10ZW5hbnQtaXNvbGF0aW9uLTIwMjYtMDYtMTEiLCJzdCI6MCwiZCI6NCwidCI6NywiYiI6NjUsImUiOjY1LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6InRvcG9sb2d5LWNjeG4tZW50aXR5LWNvdmVyYWdlLWJhY2tmaWxsLWxtZS1zLTIwMjYtMDYtMDYiLCJzdCI6MCwiZCI6MywidCI6NSwiYiI6MzEsImUiOjMxLCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6InRva2VuLWJ1cm4tcHJlY2lzZS1hdHRyaWJ1dGlvbi0yMDI2LTA2LTI2Iiwic3QiOjAsImQiOjMsInQiOjMsImIiOjUwLCJlIjo1MCwibyI6NywiZGVwIjpbImV4ZWNwbGFuLXRva2VuLWJ1cm4tcGVyLWV4ZWNwbGFuLTIwMjYtMDYtMjYiXSwiZXh0IjpbXSwib2QiOlsiT0QtMjgiXX0seyJzIjoidW5pZmllZC1yZWFzb25lci1lbmNvZGUtZXZpZGVuY2UtMjAyNi0wNi0yOSIsInN0IjoxLCJkIjowLCJ0IjoxLCJiIjo1MywiZSI6NTQsIm8iOjI1LCJkZXAiOlsibG1lLXMtYWdncmVnYXRpb24tcHJvamVjdGlvbi1sYW5lLXdpa2ljcnV4LWJyaWRnZS0yMDI2LTA2LTI4Iiwid2lraWNydXgtYWdlbnQtbGFuZ3VhZ2UtZW5jb2RlLTIwMjYtMDYtMjgiXSwiZXh0IjpbImNjeGktcXVlcnktc2hhcGUtcm91dGluZy0yMDI2LTA2LTMwIiwidW5pZmllZC1yZXRyaWV2YWwtaGFyZGVuaW5nLTIwMjYtMDctMDIiXSwib2QiOltdfSx7InMiOiJ1bmlmaWVkLXByb2R1Y3Rpb24tY2xhaW1zLXNvdXJjZS0yMDI2LTA2LTMwIiwic3QiOjEsImQiOjMsInQiOjQsImIiOjU0LCJlIjo1NCwibyI6NiwiZGVwIjpbXSwiZXh0IjpbImNjeGktcXVlcnktc2hhcGUtcm91dGluZy0yMDI2LTA2LTMwIiwiZW53aWtpLXByb3NlLWRlZGljYXRlZC1zZXJ2aW5nLWRhdGEtMS0yMDI2LTA3LTAzIiwidW5pZmllZC1yZXRyaWV2YWwtaGFyZGVuaW5nLTIwMjYtMDctMDIiXSwib2QiOltdfSx7InMiOiJyY3gtcmVnaXN0cnktZGVwbG95bWVudC1yZWFkaW5lc3MtMjAyNi0wNi0xNCIsInN0IjowLCJkIjo1LCJ0Ijo1LCJiIjozOCwiZSI6MzgsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoicHJvZHVjdGlvbi1jdXRvdmVyLW9yY2hlc3RyYXRpb24tMjAyNi0wNy0wNyIsInN0IjoxLCJkIjozOSwidCI6NDAsImIiOjYxLCJlIjo2NSwibyI6MiwiZGVwIjpbXSwiZXh0IjpbInBvcnRmb2xpby1idXJuLWRvd24tb3JjaGVzdHJhdGlvbi0yMDI2LTA3LTEwIl0sIm9kIjpbXX0seyJzIjoicHJvdmlkZXItaW50ZWdyYXRpb24tc3VyZmFjZXMtMjAyNi0wNi0xMSIsInN0IjoxLCJkIjo1LCJ0Ijo2LCJiIjozNiwiZSI6MzYsIm8iOjEsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoic2NyYXRjaHBhZC1zdXJ2aXZhbC13aXphcmQtc3RhbmRhcmQtMjAyNi0wNi0zMCIsInN0IjoxLCJkIjo0LCJ0Ijo0LCJiIjo1NCwiZSI6NTUsIm8iOjgsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoidG9wb2xvZ3ktY2N4bi13ZWlnaHQtYW5kLW5vaXNlLXR1bmUtbG1lLXMtMjAyNi0wNi0wNyIsInN0IjowLCJkIjo0LCJ0Ijo0LCJiIjozMSwiZSI6MzEsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoidG9rZW5idXJuLWFiLWhhcm5lc3MtMjAyNi0wNi0xMCIsInN0IjowLCJkIjoxLCJ0Ijo3LCJiIjozNCwiZSI6MzQsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoicHJvZC1lbmdpbmUtcmVjb25jaWxlLWRlcGxveS0yMDI2LTA2LTI2Iiwic3QiOjAsImQiOjAsInQiOjEsImIiOjUwLCJlIjo1MCwibyI6NCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJwaGFzZS10LXVzYWdlLXJlY2VpcHRzLTIwMjYtMDctMDMiLCJzdCI6MCwiZCI6MywidCI6MywiYiI6NjQsImUiOjY0LCJvIjozLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImxtZS1zLWdhdGVkLWFjY3VyYWN5LXB1c2gtMjAyNi0wNS0yOSIsInN0IjowLCJkIjowLCJ0Ijo1LCJiIjoyMiwiZSI6MjgsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoicGhhc2UtdC1jcm9zcy12ZW5kb3ItaW5zdHJ1bWVudGF0aW9uLTIwMjYtMDctMDMiLCJzdCI6MSwiZCI6MSwidCI6MywiYiI6NjEsImUiOjY0LCJvIjo1LCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6InBhc3Nwb3J0LXJldm9jYXRpb24tYW5kLWFnZW50LWNhcmQtZGlzY292ZXJ5LTIwMjYtMDYtMjkiLCJzdCI6MCwiZCI6NywidCI6NywiYiI6NTMsImUiOjUzLCJvIjoyNiwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJwaGFzZS0wLWh5Z2llbmUtZGVidC0yMDI2LTA3LTAyIiwic3QiOjEsImQiOjMsInQiOjEwLCJiIjo1NiwiZSI6NjAsIm8iOjI3LCJkZXAiOlsibWFzdGVyLXBsYW4tcmVmcmVzaC1hbmQtZG9jcy11bmlmaWNhdGlvbi0yMDI2LTA3LTAyIl0sImV4dCI6W10sIm9kIjpbXX0seyJzIjoicGhhc2UtdC11c2FnZS1yZWNlaXB0cy1hdXRvZW1pdC12ZXJzaW9uLW5vdGlmeS0yMDI2LTA3LTAzIiwic3QiOjAsImQiOjMsInQiOjMsImIiOjU3LCJlIjo1NywibyI6MywiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJtYXN0ZXItcGxhbi1jYW5vbmljYWwtY29uc29saWRhdGlvbi0yMDI2LTA2LTE0Iiwic3QiOjAsImQiOjQsInQiOjQsImIiOjM4LCJlIjozOCwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJwb3J0Zm9saW8tc3RhdHVzLWRlY2lzaW9ucy1yZWdpc3RyeS0yMDI2LTA2LTExIiwic3QiOjAsImQiOjAsInQiOjQsImIiOjM2LCJlIjozNiwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJvcGVuLWVuZ2luZS1jb29yZGluYXRpb24tc3VyZmFjZXMtMjAyNi0wNi0zMCIsInN0IjowLCJkIjowLCJ0Ijo1LCJiIjo1NCwiZSI6NTUsIm8iOjksImRlcCI6W10sImV4dCI6WyJ1bmlmaWVkLXNoZWxsLWNvbnNvbGUtMjAyNi0wNy0wMyJdLCJvZCI6W119LHsicyI6InBsYW5jcnV4LXJldGlyZW1lbnQtbWFzdGVyLTIwMjYtMDUtMTkiLCJzdCI6MSwiZCI6MCwidCI6OSwiYiI6MTIsImUiOjM0LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6Im1oLWFiLXYyLWhhcm5lc3MtYnVpbGQtMjAyNi0wNi0xMiIsInN0IjowLCJkIjoxLCJ0Ijo1LCJiIjozNiwiZSI6MzYsIm8iOjAsImRlcCI6W10sImV4dCI6WyJjb250ZXh0LWRlcGVuZGVuY2UtYmVuY2htYXJrLXNjb3JlY3J1eC0yMDI2LTA3LTAzIl0sIm9kIjpbXX0seyJzIjoibG1lLXMtbXVsdGktbGFuZS1yZXRyaWV2YWwtZ2VtbWEtMjAyNi0wNS0yMyIsInN0IjowLCJkIjowLCJ0Ijo3LCJiIjoxNiwiZSI6MTYsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoibG1lLWtub3dsZWRnZS1yZWluZ2VzdC1hbmQtbGVnYWN5LXNlZ21lbnQtcmV0aXJlLTIwMjYtMDUtMjkiLCJzdCI6MCwiZCI6MCwidCI6MSwiYiI6MjIsImUiOjIyLCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImxhbmUtY292ZXJhZ2UtYmFja2ZpbGwtMjAyNi0wNS0yMiIsInN0IjowLCJkIjoyLCJ0Ijo1LCJiIjoxNSwiZSI6MTUsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoibG1lLW9yZGVyaW5nLWRheS1wcmVjaXNpb24tZXh0cmFjdGlvbi0yMDI2LTA2LTEyIiwic3QiOjEsImQiOjMsInQiOjYsImIiOjM2LCJlIjozNywibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJsbWUtcy04LWxldmVyLWRlZXBkaXZlLTIwMjYtMDYtMDQiLCJzdCI6MCwiZCI6MCwidCI6MSwiYiI6MjgsImUiOjI5LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImxtZS1zLWFnZ3JlZ2F0aW9uLXByb2plY3Rpb24tbGFuZS13aWtpY3J1eC1icmlkZ2UtMjAyNi0wNi0yOCIsInN0IjoxLCJkIjowLCJ0Ijo2LCJiIjo1MiwiZSI6NTMsIm8iOjI2LCJkZXAiOlsibG1lLXMtYWdncmVnYXRpb24tY291bnQtZXh0cmFjdGlvbi0yMDI2LTA2LTE4Il0sImV4dCI6WyJ1bmlmaWVkLXJlYXNvbmVyLWVuY29kZS1ldmlkZW5jZS0yMDI2LTA2LTI5Il0sIm9kIjpbXX0seyJzIjoibG1lLWFnZW50LW5hdGl2ZS1yZXRyaWV2YWwtaGFybmVzcy0yMDI2LTA1LTMwIiwic3QiOjAsImQiOjIsInQiOjUsImIiOjIzLCJlIjozMiwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJsbWUtcy1hZ2dyZWdhdGlvbi1jb3VudC1leHRyYWN0aW9uLTIwMjYtMDYtMTgiLCJzdCI6MCwiZCI6NSwidCI6NSwiYiI6NDIsImUiOjQ3LCJvIjo1OSwiZGVwIjpbXSwiZXh0IjpbImxtZS1zLWFnZ3JlZ2F0aW9uLXByb2plY3Rpb24tbGFuZS13aWtpY3J1eC1icmlkZ2UtMjAyNi0wNi0yOCJdLCJvZCI6W119LHsicyI6Imtub3dsZWRnZS1zdGF0ZS1wcm9kdWN0aW9uLWhvb2tzLTIwMjYtMDYtMTMiLCJzdCI6MCwiZCI6NiwidCI6NiwiYiI6MzcsImUiOjM5LCJvIjo5LCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImV4dHJhY3Rpb24tbGFuZS1vYnNlcnZhYmlsaXR5LTIwMjYtMDUtMjEiLCJzdCI6MCwiZCI6NywidCI6NywiYiI6MTQsImUiOjM1LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImV4ZWNwbGFuLWxpbmVhZ2UtcHJvdmVuYW5jZS1vcGVuLXF1ZXN0aW9ucy0yMDI2LTA2LTI1Iiwic3QiOjAsImQiOjQsInQiOjUsImIiOjQ5LCJlIjo0OSwibyI6NSwiZGVwIjpbImNvb3JkLXBsYW5lLXAxLWV4ZWNwbGFuLWJvYXJkLTIwMjYtMDYtMjMiLCJjcnV4LXdvcmstcGFuZWwtZXhlY3BsYW5zLWFzLXRydWVub3J0aC0yMDI2LTA1LTI2Il0sImV4dCI6WyJleGVjcGxhbi1ib2FyZC1maWRlbGl0eS1zdGF0ZXMtY29uc29sZS1jb3N0LTIwMjYtMDYtMjYiXSwib2QiOlsiT0QtMyIsIk9ELTI0Il19LHsicyI6ImdlbmVyYXRpdmUtZXhlY3BsYW5zLWFuZC1kZXBsb3ktY29vcmRpbmF0aW9uLTIwMjYtMDYtMjYiLCJzdCI6MCwiZCI6MCwidCI6MSwiYiI6NTAsImUiOjUzLCJvIjoyNywiZGVwIjpbImNydXgtd29yay1wYW5lbC1leGVjcGxhbnMtYXMtdHJ1ZW5vcnRoLTIwMjYtMDUtMjYiLCJleGVjcGxhbi1ib2FyZC1maWRlbGl0eS1zdGF0ZXMtY29uc29sZS1jb3N0LTIwMjYtMDYtMjYiXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJpZGVudGl0eS1tZW1vcnktcG9ydGFiaWxpdHktMjAyNi0wNi0xMSIsInN0IjowLCJkIjo2LCJ0Ijo2LCJiIjozNiwiZSI6MzYsIm8iOjEsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiZmFibGU1LWQxLXJlZHRlYW0ta2lsbC1yaXNrLXJlZ2lzdGVyLTIwMjYtMDctMDIiLCJzdCI6MCwiZCI6NiwidCI6NiwiYiI6NTYsImUiOjU2LCJvIjo2LCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImdhdGVkLXRpZXJlZC1hZ2dyZWdhdGlvbi1wcm9tcHQtZml4ZXMtMjAyNi0wNS0yNCIsInN0IjowLCJkIjowLCJ0Ijo4LCJiIjoxNywiZSI6MzMsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiZXhlY3BsYW4tdG9rZW4tYnVybi1wZXItZXhlY3BsYW4tMjAyNi0wNi0yNiIsInN0IjowLCJkIjoyLCJ0IjozLCJiIjo1MCwiZSI6NTAsIm8iOjEyLCJkZXAiOlsiZXhlY3BsYW4tYm9hcmQtZmlkZWxpdHktc3RhdGVzLWNvbnNvbGUtY29zdC0yMDI2LTA2LTI2Il0sImV4dCI6WyJ0b2tlbi1idXJuLXByZWNpc2UtYXR0cmlidXRpb24tMjAyNi0wNi0yNiJdLCJvZCI6WyJPRC0yOCJdfSx7InMiOiJldmVudC1sYW5lLXNlbWFudGljLXJlY2FsbC0yMDI2LTA2LTA1Iiwic3QiOjAsImQiOjYsInQiOjcsImIiOjI5LCJlIjozMCwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJnbGFzc2JveC1ldS1haS1hY3Qtc29jMi1jb21wbGlhbmNlLWJlbmNoLTIwMjYtMDYtMjYiLCJzdCI6MCwiZCI6MTEsInQiOjExLCJiIjo1MCwiZSI6NTEsIm8iOjIyLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImV2ZW50LWNvdW50ZXItbm9pc2UtcmVkdWN0aW9uLTIwMjYtMDYtMDYiLCJzdCI6MCwiZCI6NiwidCI6NywiYiI6MzAsImUiOjMwLCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImZyb250ZG9vci1hZ2VudC11eC1udXh0LWZlYXR1cmUtZmxhZy13aXJpbmctMjAyNi0wNS0yOSIsInN0IjoxLCJkIjowLCJ0Ijo4LCJiIjoyMSwiZSI6MjIsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiZ29sZC1mcmVlLWV4dHJhY3Rpb24tYXV0b21hdGlvbi0yMDI2LTA1LTMxIiwic3QiOjEsImQiOjIsInQiOjExLCJiIjoyNCwiZSI6MjgsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiZXhlY3BsYW4tYm9hcmQtZmlkZWxpdHktc3RhdGVzLWNvbnNvbGUtY29zdC0yMDI2LTA2LTI2Iiwic3QiOjAsImQiOjMsInQiOjQsImIiOjUwLCJlIjo1MCwibyI6NSwiZGVwIjpbImV4ZWNwbGFuLWxpbmVhZ2UtcHJvdmVuYW5jZS1vcGVuLXF1ZXN0aW9ucy0yMDI2LTA2LTI1Il0sImV4dCI6WyJleGVjcGxhbi10b2tlbi1idXJuLXBlci1leGVjcGxhbi0yMDI2LTA2LTI2IiwiZ2VuZXJhdGl2ZS1leGVjcGxhbnMtYW5kLWRlcGxveS1jb29yZGluYXRpb24tMjAyNi0wNi0yNiJdLCJvZCI6W119LHsicyI6ImVtYmVkZGVyLXBvb2wtZGlzdHJpYnV0aW9uLW1hbmFnZXItMjAyNi0wNy0wMSIsInN0IjoxLCJkIjoyLCJ0Ijo2LCJiIjo1NSwiZSI6NTUsIm8iOjExLCJkZXAiOltdLCJleHQiOlsidW5pZmllZC1yZXRyaWV2YWwtaGFyZGVuaW5nLTIwMjYtMDctMDIiXSwib2QiOltdfSx7InMiOiJlbndpa2ktcHJvc2UtZGVkaWNhdGVkLXNlcnZpbmctZGF0YS0xLTIwMjYtMDctMDMiLCJzdCI6MCwiZCI6MSwidCI6NiwiYiI6NjQsImUiOjY0LCJvIjowLCJkZXAiOlsiY2xhaW1zLXJlc2lkZW50LWJtMjUtYW5kLW5leHQtc3RlcHMtMjAyNi0wNi0zMCIsInVuaWZpZWQtcHJvZHVjdGlvbi1jbGFpbXMtc291cmNlLTIwMjYtMDYtMzAiLCJ3aWtpY3J1eC1mdWxsLWVud2lraS1pbmdlc3QtMjAyNi0wNi0yOCJdLCJleHQiOlsid2lraWNydXgtYWRvcHRpb24tdGVsZW1ldHJ5LWFuZC1jb3JwdXMtZmx5d2hlZWwtMjAyNi0wNy0wOSJdLCJvZCI6W119LHsicyI6ImVtYmVkZGVyLXBvb2wtcGVyLXRlbmFudC1idW5kbGUtMjAyNi0wNi0xNiIsInN0IjowLCJkIjo1LCJ0Ijo1LCJiIjo0MCwiZSI6NDAsIm8iOjEyLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImVud2lraS1jbGFpbXMtY292ZXJhZ2UtZXhwYW5zaW9uLTIwMjYtMDctMDQiLCJzdCI6MSwiZCI6MiwidCI6NiwiYiI6NjQsImUiOjY0LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImVzaS12Mi1saXZlLWZhY3Qtd3JpdGUtcGF0aC0yMDI2LTA2LTAzIiwic3QiOjAsImQiOjAsInQiOjQsImIiOjI3LCJlIjoyNywibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJlbmdpbmUtY2ktbGF5ZXItNy1yZW1haW5pbmctaGlnaHMtMjAyNi0wNS0yMSIsInN0IjowLCJkIjowLCJ0Ijo0LCJiIjoxNCwiZSI6MTQsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiZW53aWtpLXByb3NlLXJhbmtpbmctcXVhbGl0eS0yMDI2LTA3LTAzIiwic3QiOjAsImQiOjMsInQiOjUsImIiOjY0LCJlIjo2NCwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOlsiT0QtMSIsIk9ELTIiXX0seyJzIjoiY3VlY3J1eC1mZWF0dXJlLXJlZ2lzdHJ5LWFuZC1yb3V0ZXItMjAyNi0wNS0yNiIsInN0IjowLCJkIjowLCJ0IjoxNywiYiI6MTksImUiOjE5LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtaHR0cC1pbmdyZXNzLWhhcmRlbmluZy0yMDI2LTA2LTExIiwic3QiOjEsImQiOjQsInQiOjUsImIiOjM1LCJlIjozNiwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LXNlbGYtaG9zdGluZy1oeWdpZW5lLTIwMjYtMDYtMDUiLCJzdCI6MCwiZCI6NCwidCI6NSwiYiI6MjksImUiOjI5LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtcHJvZC1kZXBsb3ktMjAyNi0wNi0wNSIsInN0IjowLCJkIjozLCJ0Ijo0LCJiIjoyOSwiZSI6MjksIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1nYXRld2F5LXByb2R1Y3Rpb24tMjAyNi0wNi0xMCIsInN0IjowLCJkIjowLCJ0IjoxLCJiIjozNCwiZSI6MzUsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1tY3Atb2F1dGgtZm9yLWhvc3RlZC1jbGllbnRzLTIwMjYtMDYtMjMiLCJzdCI6MSwiZCI6NSwidCI6OCwiYiI6NDcsImUiOjQ5LCJvIjo0NCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOlsiT0QtMyIsIk9ELTI0Il19LHsicyI6ImNydXgtc2Vzc2lvbi1jYXBhYmlsaXR5LWdyYXBoLWNvbXBsZXRpb24tMjAyNi0wNi0wOCIsInN0IjoxLCJkIjoxLCJ0Ijo1LCJiIjozMiwiZSI6MzIsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eGVuZ2luZS1jb21wYW5pb24taW5zdGFsbGVyLWRlcGxveS1oYXJkZW5pbmctMjAyNi0wNy0xMiIsInN0IjowLCJkIjo0LCJ0Ijo0LCJiIjo2NiwiZSI6NjYsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1yZXBvLWF1ZGl0LWZpeGluZy0yMDI2LTA2LTE1Iiwic3QiOjAsImQiOjgsInQiOjgsImIiOjM5LCJlIjozOSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LW1vYXQtbTQtbWVtb3J5LWhvb2stbTgtYnV5ZXItcGFja2FnZS0yMDI2LTA2LTExIiwic3QiOjAsImQiOjAsInQiOjIsImIiOjM1LCJlIjozNSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LXJlcG8tYXVkaXQtaGFyZGVuaW5nLWZvbGxvd3VwLTIwMjYtMDYtMTUiLCJzdCI6MCwiZCI6MCwidCI6MSwiYiI6MzksImUiOjM5LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtc2lnbmVkLXNlc3Npb24tcmVjb3JkZXItMjAyNi0wNi0yMSIsInN0IjowLCJkIjozLCJ0IjozLCJiIjo0NiwiZSI6NDYsIm8iOjQwLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtaG9vay1jbGllbnQtd2lyZS1hY3Rpdml0eS0yMDI2LTA2LTIyIiwic3QiOjAsImQiOjUsInQiOjUsImIiOjQ2LCJlIjo0NiwibyI6MzgsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1oZWFkcm9vbS10b2tlbi1lZmZpY2llbmN5LWxlYXJuaW5ncy0yMDI2LTA2LTI0Iiwic3QiOjAsImQiOjMsInQiOjYsImIiOjQ4LCJlIjo0OSwibyI6MTcsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1vcmNoZXN0cmF0b3Itb3JjcGxhbi0yMDI2LTA1LTI5Iiwic3QiOjAsImQiOjAsInQiOjcsImIiOjIyLCJlIjoyMiwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LXB1bmNoY2FyZC1yZXNvdXJjZS1sZWFzZXMtMjAyNi0wNS0yOSIsInN0IjowLCJkIjowLCJ0Ijo3LCJiIjoyMiwiZSI6MjIsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1zZXNzaW9uLWFyY2hpdmUtYW5kLWZyaWVuZGx5LXRpdGxlcy0yMDI2LTA2LTEzIiwic3QiOjAsImQiOjIsInQiOjcsImIiOjM3LCJlIjozNywibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LWdyb3d0aC11cHNlbGwtbWFzdGVyLTIwMjYtMDYtMTEiLCJzdCI6MSwiZCI6MCwidCI6NCwiYiI6MzUsImUiOjM2LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtbWNwLW5vdGlmaWNhdGlvbi0yMDItbmF0aXZlLWh0dHAtMjAyNi0wNy0wNiIsInN0IjowLCJkIjoxLCJ0IjozLCJiIjo2MCwiZSI6NjEsIm8iOjQsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC13b3JrLXBhbmVsLWV4ZWNwbGFucy1hcy10cnVlbm9ydGgtMjAyNi0wNS0yNiIsInN0IjowLCJkIjo4LCJ0Ijo4LCJiIjoxOSwiZSI6MjAsIm8iOjAsImRlcCI6W10sImV4dCI6WyJleGVjcGxhbi1saW5lYWdlLXByb3ZlbmFuY2Utb3Blbi1xdWVzdGlvbnMtMjAyNi0wNi0yNSIsImdlbmVyYXRpdmUtZXhlY3BsYW5zLWFuZC1kZXBsb3ktY29vcmRpbmF0aW9uLTIwMjYtMDYtMjYiXSwib2QiOltdfSx7InMiOiJjcnV4LXRlbmFudC1jYXRlZ29yeS1tb2RlbC0yMDI2LTA1LTIyIiwic3QiOjAsImQiOjcsInQiOjcsImIiOjE1LCJlIjoxNSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LW5ldy10b29sLXByb2JlLWZpeGVzLTIwMjYtMDYtMDUiLCJzdCI6MCwiZCI6MywidCI6OCwiYiI6MjksImUiOjI5LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtcmVzcG9uc2UtY29udHJhY3QtdjEtZGVmYXVsdC1zY2hlbWEtMjAyNi0wNi0wOCIsInN0IjowLCJkIjo2LCJ0Ijo3LCJiIjozMiwiZSI6MzQsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1zdXBwbHktY2hhaW4tYXR0ZXN0YXRpb24tMjAyNi0wNi0xMSIsInN0IjowLCJkIjo1LCJ0Ijo1LCJiIjozNSwiZSI6NDgsIm8iOjQ3LCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXhlbmdpbmUtY29tcGFuaW9uLWxhbmUtcG9ydC0yMDI2LTA2LTA5Iiwic3QiOjAsImQiOjcsInQiOjcsImIiOjMzLCJlIjozNCwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LW1jcC1keW5hbWljLXRvb2wtc3VyZmFjZS0yMDI2LTA2LTA4Iiwic3QiOjAsImQiOjEsInQiOjYsImIiOjMyLCJlIjozNCwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LWxvZy1yZWRhY3Rpb24tMjAyNi0wNi0xMSIsInN0IjoxLCJkIjozLCJ0Ijo1LCJiIjozNSwiZSI6MzYsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1pbnRlZ3JhdGlvbi1wbGF0Zm9ybS1zdXJmYWNlcyIsInN0IjowLCJkIjowLCJ0Ijo3LCJiIjozMSwiZSI6MzEsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1zZXNzaW9uLWNhcGFiaWxpdHktY2F0YWxvZy1yZWZyZXNoLTIwMjYtMDUtMjkiLCJzdCI6MCwiZCI6MCwidCI6NiwiYiI6MjEsImUiOjIxLCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtc2VnbWVudC1pbnRlZ3JpdHktYXVkaXQtcmVtZWRpYXRpb24tMjAyNi0wNi0xMyIsInN0IjowLCJkIjo3LCJ0Ijo3LCJiIjozNywiZSI6MzcsIm8iOjIsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1tb2F0LXRyYWNrLW1hc3Rlci0yMDI2LTA2LTA1Iiwic3QiOjEsImQiOjAsInQiOjksImIiOjM1LCJlIjo2NiwibyI6OTAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1hZ2VudC1wcmVzZW5jZS1jb29yZGluYXRpb24tMjAyNi0wNi0xMSIsInN0IjowLCJkIjowLCJ0Ijo3LCJiIjozNSwiZSI6MzUsIm8iOjEsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1jb25maWctd2l6YXJkLWRlZHVwLWxpbnQtMjAyNi0wNi0yMyIsInN0IjowLCJkIjo1LCJ0Ijo1LCJiIjo0NywiZSI6NDcsIm8iOjM3LCJkZXAiOltdLCJleHQiOltdLCJvZCI6WyJPRC0xOCJdfSx7InMiOiJjcnV4LWF1ZGl0LWlpLWdhcC1jbG9zdXJlLWNvZGViYXNlLWF1ZGl0LTIwMjYtMDYtMTMiLCJzdCI6MCwiZCI6NCwidCI6NCwiYiI6MzcsImUiOjM3LCJvIjoyLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtYWdlbnQtcGFzc3BvcnQtZ3JvdXBlZC1jb2xsYWJvcmF0aW9uLTIwMjYtMDYtMDUiLCJzdCI6MCwiZCI6NSwidCI6NSwiYiI6MjksImUiOjI5LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtY29uc29sZS1ncmFwaC1jdXRvdmVyLTIwMjYtMDUtMzAiLCJzdCI6MCwiZCI6MCwidCI6MSwiYiI6MjMsImUiOjIzLCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtY29uc29sZS1wdWJsaWMtZXhwb3N1cmUtMjAyNi0wNS0xNyIsInN0IjoxLCJkIjowLCJ0Ijo2LCJiIjoxMSwiZSI6MTEsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1kYWVtb24tZnVsbC1hdWRpdC0yMDI2LTA2LTA1Iiwic3QiOjAsImQiOjYsInQiOjYsImIiOjI5LCJlIjoyOSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LWR1YWwtc3VyZmFjZS1hY3Rpdml0eS1sb2ctMjAyNi0wNi0xOCIsInN0IjowLCJkIjo1LCJ0Ijo1LCJiIjo0MiwiZSI6NDYsIm8iOjUxLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNyb3NzLW1vZGVsLWFncmVlbWVudC1yb3V0ZXItMjAyNi0wNi0wNCIsInN0IjowLCJkIjoyLCJ0IjozLCJiIjoyOCwiZSI6MjgsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1hdWRpdC1paS1nYXAtY2xvc3VyZS1pbXBsZW1lbnRhdGlvbi0yMDI2LTA2LTE0Iiwic3QiOjAsImQiOjE0LCJ0IjoxNCwiYiI6MzgsImUiOjM4LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtY29uc29sZS0zZC1zdWJzdHJhdGUtY29uY2VwdC0yMDI2LTA2LTExIiwic3QiOjAsImQiOjEsInQiOjQsImIiOjM1LCJlIjozNSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LWRhZW1vbi1zZWN1cml0eS1nYXAtc2Nhbi0yMDI2LTA2LTEyIiwic3QiOjAsImQiOjMsInQiOjQsImIiOjM2LCJlIjozNiwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnVjaWJsZS1nYXRld2F5LXN1cGVyc2VkZS1jbGF3ZC0yMDI2LTA2LTI2Iiwic3QiOjAsImQiOjAsInQiOjEsImIiOjUwLCJlIjo1MCwibyI6NSwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LWZyZXNobmVzcy1kb2dmb29kLTIwMjYtMDYtMDQiLCJzdCI6MCwiZCI6NCwidCI6OCwiYiI6MjgsImUiOjI5LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtZGFlbW9uLWNvbnNvbGUtbGFuZS13ZWlnaHRzLTIwMjYtMDYtMTMiLCJzdCI6MCwiZCI6NywidCI6NywiYiI6MzcsImUiOjM3LCJvIjoyLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtY3JlZGl0LWJ1cm4tcmFpbC0yMDI2LTA2LTIyIiwic3QiOjEsImQiOjEsInQiOjcsImIiOjYxLCJlIjo2MiwibyI6MiwiZGVwIjpbXSwiZXh0IjpbInBvcnRmb2xpby1idXJuLWRvd24tb3JjaGVzdHJhdGlvbi0yMDI2LTA3LTEwIl0sIm9kIjpbXX0seyJzIjoiY3J1eC1kYWVtb24tdjgtY292ZXJhZ2Utc2Nhbi0yMDI2LTA2LTEzIiwic3QiOjAsImQiOjMsInQiOjMsImIiOjM3LCJlIjozNywibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LWRvbWFpbi1zdWJzdHJhdGUtYW5kLWZlYXR1cmVzLWxlbnMtMjAyNi0wNS0xOCIsInN0IjowLCJkIjo2LCJ0Ijo3LCJiIjoxMSwiZSI6MTEsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1Y2libGUtY29udHJvbC1wbGFuZS1hbmQtZGVlcC1yZXRyaWV2YWwtMjAyNi0wNi0xOCIsInN0IjoxLCJkIjowLCJ0IjoxLCJiIjo0OCwiZSI6NTAsIm8iOjUzLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtY29uc29sZS1kYXRhLXBsYW5lLXdpcmluZy0yMDI2LTA1LTIxIiwic3QiOjAsImQiOjMsInQiOjYsImIiOjE0LCJlIjoxNCwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LWV4dGVybmFsLWZpbmRpbmdzLXJlbWVkaWF0aW9uLTIwMjYtMDctMTAiLCJzdCI6MCwiZCI6NywidCI6NywiYiI6NjQsImUiOjY1LCJvIjozLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtZGFlbW9uLWhhcmRlbmluZy1hdWRpdC1maW5kaW5ncy0yMDI2LTA2LTA3Iiwic3QiOjAsImQiOjYsInQiOjYsImIiOjMxLCJlIjozMSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcm9zcy1zZXNzaW9uLWlkZW50aXR5LXJlc29sdXRpb24tMjAyNi0wNi0xNSIsInN0IjowLCJkIjo3LCJ0Ijo3LCJiIjozOSwiZSI6MzksIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1jb25zb2xlLWxhbmUtd2VpZ2h0LXBvbGlzaC0yMDI2LTA2LTE0Iiwic3QiOjAsImQiOjYsInQiOjYsImIiOjM4LCJlIjozOCwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LWNpLW1lcmdlLXF1ZXVlLXdpcmluZy0yMDI2LTA2LTI2Iiwic3QiOjAsImQiOjMsInQiOjQsImIiOjUwLCJlIjo1MywibyI6MjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1hZ2VudC1hY3Rpb24tbGVkZ2VyLXRva2VuLWFjY291bnRpbmctMjAyNi0wNi0xMSIsInN0IjowLCJkIjo2LCJ0Ijo2LCJiIjozNSwiZSI6NDgsIm8iOjQ3LCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtYWN0aXZpdHktbG9nLWNvbXBsZXRpb24tMjAyNi0wNi0yMyIsInN0IjowLCJkIjo0LCJ0Ijo1LCJiIjo0NywiZSI6NDgsIm8iOjM4LCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtY29kZXgtYXV0aGVudGljYXRpb24tMjAyNi0wNi0xMiIsInN0IjowLCJkIjo0LCJ0Ijo0LCJiIjozNiwiZSI6NTcsIm8iOjc2LCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtYXVkaXQtY2hhaW4tZGF0YS1jb250cmFjdC0yMDI2LTA1LTI5Iiwic3QiOjAsImQiOjEsInQiOjcsImIiOjIyLCJlIjoyMiwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LWFnZW50LXBhc3Nwb3J0LW1jcC1iaW5kaW5nLTIwMjYtMDYtMTAiLCJzdCI6MCwiZCI6MCwidCI6MSwiYiI6MzQsImUiOjM0LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNvcmVjcnV4LXNraXAtY29tcGFuaW9ucy1wcm9qZWN0aW9uLWNvbnRyb2wtMjAyNi0wNS0yOSIsInN0IjowLCJkIjowLCJ0IjoxLCJiIjoyMSwiZSI6MjIsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY29yZWNydXhkLWMycGEtdmF1bHQtcGtpLXJ1bnRpbWUtZW5hYmxlbWVudC0yMDI2LTA1LTI5Iiwic3QiOjEsImQiOjAsInQiOjcsImIiOjIxLCJlIjoyMSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjb3JlY3J1eGQtYm9vc3Qtb3ZlcmxheS1wZXJzaXN0ZW5jZS0yMDI2LTA1LTIxIiwic3QiOjAsImQiOjEsInQiOjYsImIiOjE0LCJlIjoxNSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjb3JlY3J1eC10dXJib3F1YW50LWNjeGUtcXVhbnQtbW9kZSIsInN0IjoxLCJkIjowLCJ0Ijo2LCJiIjozNiwiZSI6MzYsIm8iOjExLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNvcmVjcnV4LXRyYWl0LWV4cGFuc2lvbi1sbWUtcy1zdHJ1Y3R1cmFsLWxvc3Nlcy0yMDI2LTA1LTIxIiwic3QiOjAsImQiOjMsInQiOjYsImIiOjE0LCJlIjoxNSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjb3JlY3J1eC12ZXJuYWN1bGFyLXY0LXNjaGVtYS1hbmQtcHJlZmlsdGVyLTIwMjYtMDUtMjAiLCJzdCI6MCwiZCI6MCwidCI6OCwiYiI6MTMsImUiOjEzLCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNvcmVjcnV4LXRleHQtc2VhcmNoLXRlbmFudC1pc29sYXRpb24tMjAyNi0wNi0zMCIsInN0IjowLCJkIjo1LCJ0Ijo2LCJiIjo1NCwiZSI6NTQsIm8iOjIsImRlcCI6WyJjb3JlY3J1eC1vZmZsaW5lLXNlcnZpbmctY29tcGFuaW9ucy0yMDI2LTA2LTMwIl0sImV4dCI6WyJjY3hpLXF1ZXJ5LXNoYXBlLXJvdXRpbmctMjAyNi0wNi0zMCJdLCJvZCI6W119LHsicyI6ImNvcnB1cy1zZWdyZWdhdGlvbi1idWxrLXJlcGFydGl0aW9uLTIwMjYtMDYtMjYiLCJzdCI6MCwiZCI6NCwidCI6NiwiYiI6NTAsImUiOjUyLCJvIjozMywiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjb3JlY3J1eC10cmFuc2l0aW9uLWRvYy1jb250ZW50LXBsYW5lLWNvbnRhbWluYXRpb24tMjAyNi0wNi0xMiIsInN0IjowLCJkIjoyLCJ0Ijo2LCJiIjozNiwiZSI6MzcsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY29yZWNydXgtdG9wb2xvZ3ktbm8tbGluay1wcnVuZS0yMDI2LTA1LTI3Iiwic3QiOjAsImQiOjMsInQiOjYsImIiOjIwLCJlIjoyMSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjb3JlY3J1eC10cmFpdC1leHBhbnNpb24tZ2xvYmFsLWRlZmF1bHQtb24tMjAyNi0wNS0yMSIsInN0IjoxLCJkIjowLCJ0Ijo2LCJiIjoxNCwiZSI6MzMsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY29yZWNydXgtdHJhaXQtZXhwYW5zaW9uLXN1YnN0cmF0ZS1kZW5zaXR5LWF1dG8tdHVuZS0yMDI2LTA1LTIxIiwic3QiOjAsImQiOjQsInQiOjYsImIiOjE0LCJlIjoxNSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjb3JlY3J1eGQtY29tcGFuaW9uLWhvdC1yZWxvYWQtMjAyNi0wNS0xOCIsInN0IjowLCJkIjowLCJ0Ijo2LCJiIjoxMSwiZSI6MzUsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY29yZWNydXgtb2ZmbGluZS1zZXJ2aW5nLWNvbXBhbmlvbnMtMjAyNi0wNi0zMCIsInN0IjowLCJkIjo2LCJ0Ijo2LCJiIjo1NCwiZSI6NTQsIm8iOjM0LCJkZXAiOltdLCJleHQiOlsiY2N4aS1xdWVyeS1zaGFwZS1yb3V0aW5nLTIwMjYtMDYtMzAiLCJjb3JlY3J1eC10ZXh0LXNlYXJjaC10ZW5hbnQtaXNvbGF0aW9uLTIwMjYtMDYtMzAiXSwib2QiOltdfSx7InMiOiJjb3JlY3J1eC1yZWNzdHlsZS1rZXl3b3JkLWV4dGVuc2lvbi0yMDI2LTA1LTIxIiwic3QiOjAsImQiOjMsInQiOjUsImIiOjE0LCJlIjoxNCwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjb3JlY3J1eC1wcm9tZXRoZXVzLWluZGV4bWFuYWdlci1kb3VibGUtY291bnQtMjAyNi0wNS0yOCIsInN0IjowLCJkIjowLCJ0IjozLCJiIjoyMSwiZSI6MjEsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY29yZWNydXgtc2VhbC1zaGFyZC12cy10aWNrLXNoYXJkLW1pc21hdGNoLTIwMjYtMDYtMDEiLCJzdCI6MCwiZCI6MCwidCI6MSwiYiI6MjUsImUiOjI1LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNvcmVjcnV4LXF1ZXJ5LWV4cGFuc2lvbi12aWEtdHJhaXQtZW1iZWRkaW5ncy0yMDI2LTA1LTIwIiwic3QiOjAsImQiOjQsInQiOjYsImIiOjE0LCJlIjoxNCwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjb3JlY3J1eC1pbmdlc3QtZXh0cmFjdGlvbi1mb2xsb3d1cHMtMjAyNi0wNi0xMSIsInN0IjoxLCJkIjo2LCJ0Ijo5LCJiIjozNSwiZSI6MzYsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY29yZWNydXgtcmV0cmlldmUtYWdlbnQtc2hhcGVkLXBheWxvYWQtMjAyNi0wNS0xNSIsInN0IjoxLCJkIjoyLCJ0Ijo5LCJiIjoyMywiZSI6MjQsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY29yZWNydXgtbG9hZGVkc2VnbWVudC1tZW1zdGF0cy0yMDI2LTA1LTIzIiwic3QiOjAsImQiOjMsInQiOjYsImIiOjE1LCJlIjoxNSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjb3JlY3J1eC1ncHUxLW1lbW9yeS1zdGFiaWxpemF0aW9uLTIwMjYtMDUtMjgiLCJzdCI6MCwiZCI6MiwidCI6NiwiYiI6MjEsImUiOjI0LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNvcmVjcnV4LWluZ2VzdC1leHRyYWN0aW9uLXRvcDEwLTIwMjYtMDYtMTEiLCJzdCI6MCwiZCI6MCwidCI6MSwiYiI6MzUsImUiOjM1LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNvcmVjcnV4LXF1ZXJ5LWV4cGFuc2lvbi1yb2xsb3V0LWNvbXBsZXRpb24tMjAyNi0wNS0yMSIsInN0IjowLCJkIjozLCJ0Ijo1LCJiIjoxNCwiZSI6MzUsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY29yZWNydXgtbm8tbGluay1wcnVuZS1zdWJzdHJhdGUtcmVidWlsZC0yMDI2LTA1LTI5Iiwic3QiOjAsImQiOjAsInQiOjEsImIiOjIxLCJlIjoyMSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjb3JlY3J1eC1kYWVtb24tZmFzdC1zdGFydHVwLTIwMjYtMDYtMTYiLCJzdCI6MCwiZCI6NCwidCI6NiwiYiI6NDAsImUiOjQwLCJvIjoxNywiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjb3JlY3J1eC1ldmljdG9yLWNvbnZlcmdlbmNlLTIwMjYtMDUtMzEiLCJzdCI6MCwiZCI6MywidCI6NCwiYiI6MjQsImUiOjI0LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNvZGV4LWNydXgtc2Vzc2lvbi1iYW5uZXItMjAyNi0wNi0wMSIsInN0IjowLCJkIjo4LCJ0Ijo4LCJiIjoyNSwiZSI6MjksIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY2hhaW5jcnV4LXBoYXNlMS01LWV2ZW50LWVkZ2VzLWFuZC10ZW1wb3JhbC1maWx0ZXItMjAyNi0wNS0yMiIsInN0IjowLCJkIjowLCJ0Ijo4LCJiIjoxNywiZSI6MTcsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY29udGV4dC1tZWRpYXRpb24taW5qZWN0aW9uLTIwMjYtMDYtMTEiLCJzdCI6MSwiZCI6NiwidCI6NywiYiI6MzYsImUiOjM2LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNvcmVjcnV4LWJtMjUtNjRiaXQtdGVuYW50LWZpbHRlci0yMDI2LTA2LTEzIiwic3QiOjEsImQiOjAsInQiOjEsImIiOjM3LCJlIjozNywibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjb3JlY3J1eC1jYXNjYWRlLWVuZ2FnZW1lbnQtbG1lLXMtMjAyNi0wNS0yMiIsInN0IjowLCJkIjoyLCJ0Ijo2LCJiIjoxNSwiZSI6MTUsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY2xhdWRlY2xhdy1zdWJzY3JpcHRpb24tc29ubmV0LWJhY2tlbmQtMjAyNi0wNi0wMyIsInN0IjowLCJkIjo2LCJ0Ijo2LCJiIjoyNywiZSI6MjgsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY29udGV4dC1iZW5jaC12Mi0xMDBwb2ludC10aGlyZHBhcnR5LWJvYXJkLTIwMjYtMDctMDMiLCJzdCI6MSwiZCI6NiwidCI6NywiYiI6NTcsImUiOjY1LCJvIjoyMiwiZGVwIjpbImNvbnRleHQtZGVwZW5kZW5jZS1iZW5jaG1hcmstc2NvcmVjcnV4LTIwMjYtMDctMDMiXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjb3JlY3J1eC1kb2N1bWVudC1pbmRleC1sYW5lLTIwMjYtMDUtMTUiLCJzdCI6MCwiZCI6MCwidCI6MTEsImIiOjExLCJlIjoxMSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjaGFpbmNydXgtcGhhc2UxLXByb3ZlLWVhcm5lZC1lZGdlLTIwMjYtMDUtMjIiLCJzdCI6MCwiZCI6MCwidCI6NywiYiI6MTUsImUiOjE1LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNvcmVjcnV4LWJ1bGstaW5nZXN0LWF0LXNjYWxlLTIwMjYtMDYtMTQiLCJzdCI6MCwiZCI6MCwidCI6MSwiYiI6MzgsImUiOjQ4LCJvIjo2MSwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjb3JlY3J1eC1idWxrLWluZ2VzdC1wb2xpc2gtMjAyNi0wNS0wMyIsInN0IjoxLCJkIjowLCJ0IjoxLCJiIjo2NCwiZSI6NjQsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY29kZW1hcC1lbmRwb2ludC1hbmQtYWdlbnQtZG9jcy1oYXJkZW5pbmctMjAyNi0wNy0xMCIsInN0IjowLCJkIjo0LCJ0Ijo0LCJiIjo2MywiZSI6NjMsIm8iOjAsImRlcCI6W10sImV4dCI6WyJjb2RlbWFwcy1jcm9zcy1yZXBvLWdyYXBoLWFuZC12YWx1ZS1leHBhbnNpb24tMjAyNi0wNy0xMCJdLCJvZCI6W119LHsicyI6ImNsYXdkLXVuaWZpZWQtZGFlbW9uLXJlbG9jYXRpb24tZGF0YTEtMjAyNi0wNi0xMyIsInN0IjowLCJkIjo3LCJ0Ijo3LCJiIjozNiwiZSI6MzcsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY29yZWNydXgtZXZpZGVuY2UtaGFzaC1yZXBsYXktZGVkdXAtMjAyNi0wNi0yMyIsInN0IjowLCJkIjo1LCJ0Ijo1LCJiIjo0NywiZSI6NDgsIm8iOjQ0LCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNvbXBhbmlvbi1idWlsZC00MjktaGFyZGVuaW5nLTIwMjYtMDYtMTYiLCJzdCI6MCwiZCI6NiwidCI6NiwiYiI6NDAsImUiOjQwLCJvIjo3LCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNoYWluY3J1eC16ZXJvLWV2ZW50cy1zdWJzdHJhdGUtaW52ZXN0aWdhdGlvbi0yMDI2LTA1LTI4Iiwic3QiOjEsImQiOjAsInQiOjUsImIiOjIxLCJlIjoyMSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjb2RlbWFwcy1mYWNldC1jb3ZlcmFnZS1jb21wbGV0aW9uLTIwMjYtMDctMTIiLCJzdCI6MSwiZCI6MCwidCI6NiwiYiI6NjYsImUiOjY2LCJvIjowLCJkZXAiOlsiY29kZW1hcHMtY3Jvc3MtcmVwby1ncmFwaC1hbmQtdmFsdWUtZXhwYW5zaW9uLTIwMjYtMDctMTAiXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjb3JlY3J1eC1jdXJhdG9yLWNsdXN0ZXJpbmctc3Bpa2UtMjAyNi0wNy0wNyIsInN0IjowLCJkIjoyLCJ0IjozLCJiIjo2MSwiZSI6NjEsIm8iOjAsImRlcCI6WyJjb3JlY3J1eC1tZW1vcnktbWFuYWdlci0yMDI2LTA3LTA1Il0sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY29yZWNydXgtZXZlbnQtbGFuZS1ycmYtd2lyaW5nLTIwMjYtMDUtMjQiLCJzdCI6MCwiZCI6MCwidCI6OCwiYiI6MTcsImUiOjE3LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNvbnRleHQtY3VzdG9keS1zdXJmYWNlLTIwMjYtMDYtMzAiLCJzdCI6MCwiZCI6MCwidCI6MSwiYiI6NTQsImUiOjU0LCJvIjo2LCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNvbnRleHQtZGVwZW5kZW5jZS1iZW5jaG1hcmstc2NvcmVjcnV4LTIwMjYtMDctMDMiLCJzdCI6MCwiZCI6MSwidCI6NywiYiI6NTYsImUiOjU3LCJvIjoxNSwiZGVwIjpbIm1oLWFiLXYyLWhhcm5lc3MtYnVpbGQtMjAyNi0wNi0xMiJdLCJleHQiOlsiY29udGV4dC1iZW5jaC12Mi0xMDBwb2ludC10aGlyZHBhcnR5LWJvYXJkLTIwMjYtMDctMDMiXSwib2QiOltdfSx7InMiOiJjb3JlY3J1eC1mbGVldC1jb250cm9sLXBsYW5lLTIwMjYtMDctMDMiLCJzdCI6MSwiZCI6MSwidCI6NywiYiI6NjQsImUiOjY0LCJvIjoyLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNvZGV4Y2xhdy1kZXRlcm1pbmlzdGljLWdhdGUtb3JjaGVzdHJhdGlvbi0yMDI2LTA1LTI2Iiwic3QiOjAsImQiOjEsInQiOjgsImIiOjE5LCJlIjozNSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjaGFpbmNydXgtY2FzY2FkZS1yb3V0ZS1pbnRlZ3JhdGlvbi0yMDI2LTA1LTI1Iiwic3QiOjAsImQiOjQsInQiOjgsImIiOjE4LCJlIjoyMSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjY3hpLXF1ZXJ5LXNoYXBlLXJvdXRpbmctMjAyNi0wNi0zMCIsInN0IjoxLCJkIjo0LCJ0Ijo2LCJiIjo1NCwiZSI6NTQsIm8iOjMsImRlcCI6WyJjb3JlY3J1eC1vZmZsaW5lLXNlcnZpbmctY29tcGFuaW9ucy0yMDI2LTA2LTMwIiwiY29yZWNydXgtdGV4dC1zZWFyY2gtdGVuYW50LWlzb2xhdGlvbi0yMDI2LTA2LTMwIiwidW5pZmllZC1wcm9kdWN0aW9uLWNsYWltcy1zb3VyY2UtMjAyNi0wNi0zMCIsInVuaWZpZWQtcmVhc29uZXItZW5jb2RlLWV2aWRlbmNlLTIwMjYtMDYtMjkiXSwiZXh0IjpbInVuaWZpZWQtcmV0cmlldmFsLWhhcmRlbmluZy0yMDI2LTA3LTAyIl0sIm9kIjpbXX0seyJzIjoiYXVkaXQtaWktZ2FwLWNsb3N1cmUtaGFyZGVuaW5nLTIwMjYtMDYtMTQiLCJzdCI6MCwiZCI6MCwidCI6MTAsImIiOjQ3LCJlIjo0NywibyI6MzMsImRlcCI6W10sImV4dCI6WyJkb21haW4taW5kZXgtc291cmNlLWF1dGhvcml0eS1zaWduYWwtMjAyNi0wNy0wOCJdLCJvZCI6W119LHsicyI6ImFzdC1wb2x5Z2xvdC1jb2RlLWdyYXBoLWFuZC1yZXBvLXdhdGNoLTIwMjYtMDctMDgiLCJzdCI6MCwiZCI6MTAsInQiOjEwLCJiIjo2MiwiZSI6NjMsIm8iOjIsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiYXVkaXQtaWktb3BlcmF0aW9uYWwtaGFyZGVuaW5nLXJvbGxvdXQtMjAyNi0wNi0xNCIsInN0IjowLCJkIjoxMCwidCI6MTAsImIiOjM4LCJlIjozOCwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJhdGxhcy1tYW5pZmVzdC1yb3V0aW5nLXByb2R1Y3Rpb24tMjAyNi0wNi0wNSIsInN0IjowLCJkIjoxMSwidCI6MTEsImIiOjI5LCJlIjo2NCwibyI6OTAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbIk9ELTEwIl19LHsicyI6ImFnZW50LXV4LTAyLWFja25vd2xlZGdlZC1tZW1vcnktdXNlLTIwMjYtMDUtMjciLCJzdCI6MCwiZCI6NCwidCI6NCwiYiI6MjAsImUiOjIwLCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImFnZW50LW5hdGl2ZS1ub2lzZS1yZWR1Y3Rpb24tMjAyNi0wNi0wOCIsInN0IjoxLCJkIjowLCJ0Ijo4LCJiIjozMiwiZSI6NjUsIm8iOjkwLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImFnZW50LXV4LTAzLWZyZXNobmVzcy1kZWNheS0yMDI2LTA1LTI3Iiwic3QiOjAsImQiOjUsInQiOjYsImIiOjIwLCJlIjoyMCwibyI6MCwiZGVwIjpbXSwiZXh0IjpbImRlbnNlLWxhbmUtYW5kLWV4dHJhY3Rpb24tdXBzZWxsLTIwMjYtMDYtMjYiXSwib2QiOltdfSx7InMiOiJhZ2VudC1xdWVyeS1ldmFsLWNvcnB1cy0yMDI2LTA2LTA3Iiwic3QiOjAsImQiOjAsInQiOjYsImIiOjMxLCJlIjozMSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJhZ2VudC11eC1iZXN0LWluLWNsYXNzLW1hc3Rlci0yMDI2LTA1LTI3Iiwic3QiOjAsImQiOjEsInQiOjksImIiOjIwLCJlIjoyMSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJhZ2VudC11eC0wOC1pZGVudGl0eS1jb250aW51aXR5LTIwMjYtMDUtMjciLCJzdCI6MCwiZCI6MywidCI6NSwiYiI6MjEsImUiOjIxLCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImFnZW50LXV4LTA1LXJpc2stdGllcmVkLWhpdGwtMjAyNi0wNS0yNyIsInN0IjowLCJkIjozLCJ0Ijo2LCJiIjoyMSwiZSI6MjEsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiYWdlbnQtdXgtMDctdmVyaWZpYWJsZS1vdXRwdXQtcmVjZWlwdHMtMjAyNi0wNS0yNyIsInN0IjowLCJkIjo1LCJ0Ijo2LCJiIjoyMSwiZSI6MjEsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiYWdlbnQtdXgtMDQtc291cmNlLWxpbmtlZC10cmFjZWFiaWxpdHktMjAyNi0wNS0yNyIsInN0IjowLCJkIjozLCJ0Ijo1LCJiIjoyMCwiZSI6MjEsIm8iOjAsImRlcCI6W10sImV4dCI6WyJkb21haW4taW5kZXgtc291cmNlLWF1dGhvcml0eS1zaWduYWwtMjAyNi0wNy0wOCJdLCJvZCI6W119LHsicyI6ImFnZW50LXV4LTA2LXR5cGVkLWFjdGlvbi10cmFjZXMtMjAyNi0wNS0yNyIsInN0IjowLCJkIjo1LCJ0Ijo4LCJiIjoyMCwiZSI6MjAsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiYWdlbnQtdXgtMTEtYnlvLWF1ZGl0LXRyYWlsLTIwMjYtMDUtMjciLCJzdCI6MSwiZCI6NCwidCI6NiwiYiI6MjAsImUiOjIwLCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImFnZW50LXF1ZXJ5LWV2YWwtbGFuZXMtb24tcmV0ZXN0LTIwMjYtMDYtMDgiLCJzdCI6MCwiZCI6MCwidCI6NSwiYiI6MzIsImUiOjMzLCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImFnZW50LXV4LTEwLXZpc2libGUtYXV0b25vbXktY29udHJhY3QtMjAyNi0wNS0yNyIsInN0IjowLCJkIjoyLCJ0Ijo2LCJiIjoyMCwiZSI6MjAsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiYW1yLWxhbmUtYXV0aG9yaXR5LWNyZWRpdC1nYXRpbmctMjAyNi0wNi0wNyIsInN0IjoxLCJkIjoyLCJ0Ijo3LCJiIjozMSwiZSI6MzIsIm8iOjAsImRlcCI6W10sImV4dCI6WyJkb21haW4taW5kZXgtc291cmNlLWF1dGhvcml0eS1zaWduYWwtMjAyNi0wNy0wOCJdLCJvZCI6W119LHsicyI6ImFnZW50LWNvbmZpZy13aXphcmQtMjAyNi0wNS0xOSIsInN0IjowLCJkIjozLCJ0Ijo4LCJiIjoxMiwiZSI6MTIsIm8iOjUsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiYWdlbnQtdXgtMDEtcmVhZGFibGUtZWRpdGFibGUtbWVtb3J5LTIwMjYtMDUtMjciLCJzdCI6MCwiZCI6NCwidCI6NCwiYiI6MjAsImUiOjIwLCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImFnZW50LWhhcm5lc3MtdGVzdGJlbmNoLW1lc3N5d29ybGQtMjAyNi0wNi0xOCIsInN0IjoxLCJkIjowLCJ0Ijo3LCJiIjo0MSwiZSI6NjUsIm8iOjk0LCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImFnZW50LXV4LTEyLWNhbG0tZGVmZXJyZWQtb3V0cHV0LTIwMjYtMDUtMjciLCJzdCI6MCwiZCI6MCwidCI6NiwiYiI6MjEsImUiOjIxLCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImFnZW50LXV4LTA5LXNjb3BlZC1mb3JnZXQtMjAyNi0wNS0yNyIsInN0IjowLCJkIjoyLCJ0Ijo1LCJiIjoyMCwiZSI6MjAsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX1dOwoKLyog4pSA4pSAIHBsdW1iaW5nIOKUgOKUgCAqLwpmdW5jdGlvbiBtdWxiZXJyeTMyKGEpIHsKICByZXR1cm4gZnVuY3Rpb24gKCkgewogICAgYSB8PSAwOyBhID0gYSArIDB4NkQyQjc5RjUgfCAwOwogICAgbGV0IHQgPSBNYXRoLmltdWwoYSBeIGEgPj4+IDE1LCAxIHwgYSk7CiAgICB0ID0gdCArIE1hdGguaW11bCh0IF4gdCA+Pj4gNywgNjEgfCB0KSBeIHQ7CiAgICByZXR1cm4gKCh0IF4gdCA+Pj4gMTQpID4+PiAwKSAvIDQyOTQ5NjcyOTY7CiAgfTsKfQpjb25zdCBSRURVQ0VEID0gbWF0Y2hNZWRpYSgnKHByZWZlcnMtcmVkdWNlZC1tb3Rpb246IHJlZHVjZSknKS5tYXRjaGVzOwpjb25zdCBNT05PID0gIidKZXRCcmFpbnMgTW9ubycsIHVpLW1vbm9zcGFjZSwgU0ZNb25vLVJlZ3VsYXIsIE1lbmxvLCBtb25vc3BhY2UiOwpjb25zdCBzcyA9IHQgPT4gdCA8PSAwID8gMCA6IHQgPj0gMSA/IDEgOiB0ICogdCAqICgzIC0gMiAqIHQpOwpjb25zdCBtaXggPSAoYSwgYiwgaykgPT4gYSArIChiIC0gYSkgKiBrOwpjb25zdCBUQVUgPSBNYXRoLlBJICogMjsKZnVuY3Rpb24gaGV4MnJnYmEoaGV4LCBhKSB7CiAgY29uc3QgbiA9IHBhcnNlSW50KGhleC5zbGljZSgxKSwgMTYpOwogIHJldHVybiAncmdiYSgnICsgKG4gPj4gMTYgJiAyNTUpICsgJywnICsgKG4gPj4gOCAmIDI1NSkgKyAnLCcgKyAobiAmIDI1NSkgKyAnLCcgKyBNYXRoLm1heCgwLCBNYXRoLm1pbigxLCBhKSkgKyAnKSc7Cn0KY29uc3QgdGlwID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RpcCcpOwpmdW5jdGlvbiBzaG93VGlwKHgsIHksIGh0bWwpIHsKICB0aXAuaW5uZXJIVE1MID0gaHRtbDsKICBjb25zdCBwYWQgPSAxNCwgdyA9IHRpcC5vZmZzZXRXaWR0aCB8fCAyMjA7CiAgdGlwLnN0eWxlLmxlZnQgPSBNYXRoLm1pbih4ICsgcGFkLCBpbm5lcldpZHRoIC0gdyAtIDEwKSArICdweCc7CiAgdGlwLnN0eWxlLnRvcCA9ICh5ICsgcGFkICsgdGlwLm9mZnNldEhlaWdodCA+IGlubmVySGVpZ2h0ID8geSAtIHRpcC5vZmZzZXRIZWlnaHQgLSA4IDogeSArIHBhZCkgKyAncHgnOwogIHRpcC5zdHlsZS5vcGFjaXR5ID0gMTsKfQpmdW5jdGlvbiBoaWRlVGlwKCkgeyB0aXAuc3R5bGUub3BhY2l0eSA9IDA7IH0KCi8qIOKUgOKUgCB0aW1lIGJhc2U6IGRheSAwID0gMjAyNi0wNS0wNyDilIDilIAgKi8KbGV0IE5PVyA9IDc2OyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLyogMjAyNi0wNy0yMiBzbmFwc2hvdDsgZXh0ZW5kcyB3aGVuIGxpdmUgZGF0YSBsb2FkcyAqLwpsZXQgZGF0YVNyYyA9ICdzbmFwc2hvdCc7ICAgICAgICAgICAgICAgICAgICAgICAgICAvKiBzbmFwc2hvdCB8IGxpdmUgwrcgcHJvZC1taXJyb3IgKi8KZnVuY3Rpb24gZGF5RGF0ZShkKSB7CiAgcmV0dXJuIG5ldyBEYXRlKERhdGUuVVRDKDIwMjYsIDQsIDcpICsgZCAqIDg2NDAwMDAwKS50b0lTT1N0cmluZygpLnNsaWNlKDAsIDEwKTsKfQoKLyog4pSA4pSAIGRhdGFzZXQg4pSA4pSAICovCmNvbnN0IEtJTkRfSFVFID0geyBnYXRlOiAnIzJkZDRiZicsIGRlY2lzaW9uOiAnI2E3OGJmYScsIG1lbW9yeTogJyM4Yjk2ZjInLCBoYW5kb2ZmOiAnI2Y1YTYyMycsIGluY2lkZW50OiAnI2VmNDQ0NCcgfTsKY29uc3QgU1RBVEUgPSB7IDA6ICdjb21wbGV0ZScsIDE6ICdpbl9wcm9ncmVzcycsIDI6ICdibG9ja2VkJyB9OwovKiBzdGF0ZSBwYWxldHRlOiBjb21wbGV0ZSBncmVlbiDCtyBpbiBwcm9ncmVzcyBwdXJwbGUgwrcgYmxvY2tlZCByZWQgKi8KY29uc3QgU1RBVEVfSFVFID0geyAwOiAnIzM0ZDM5OScsIDE6ICcjYTc4YmZhJywgMjogJyNlZjQ0NDQnIH07CmNvbnN0IHN0YXRlSHVlID0gcCA9PiBTVEFURV9IVUVbcC5zdF07CmNvbnN0IFBBUktfREFZUyA9IDE4OyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8qIFdvcmtJdGVtLnN0YWxlIHNlbWFudGljcyAqLwoKLyogUExBTlMgaXMgcmVidWlsZGFibGU6IGJvb3RzIGZyb20gdGhlIGVtYmVkZGVkIHNuYXBzaG90LCB0aGVuIHN3YXBzIHRvIHRoZQogICBkYWVtb24ncyBsaXZlIHdvcmsgYm9hcmQgd2hlbiBzZXJ2ZWQgc2FtZS1vcmlnaW4gKHRoZSBjb25zb2xlIG1pcnJvcikuICovCmNvbnN0IFBMQU5TID0gW107CmZ1bmN0aW9uIG1hcFJhdyhwLCBpKSB7CiAgY29uc3Qgc2hvcnQgPSBwLnMucmVwbGFjZSgvLTIwMjYtXGRcZC1cZFxkJC8sICcnKS5yZXBsYWNlKC8tMjAyNiQvLCAnJyk7CiAgLyogZXhpdCBkYXk6IGNvbXBsZXRlIOKGkiBlICsgMS41OyBpbl9wcm9ncmVzcy9ibG9ja2VkIOKGkiBwYXJrIGF0IGUgKyBQQVJLX0RBWVMgKG5ldmVyIGlmIHJlY2VudCkgKi8KICBjb25zdCBleGl0ID0gcC5zdCA9PT0gMCA/IHAuZSArIDEuNSA6IChOT1cgLSBwLmUgPiBQQVJLX0RBWVMgPyBwLmUgKyBQQVJLX0RBWVMgOiBJbmZpbml0eSk7CiAgcmV0dXJuIHsgaSwgc2x1ZzogcC5zLCBzaG9ydCwgc3Q6IHAuc3QsIGRvbmU6IHAuZCwgdG90YWw6IHAudCB8fCAxLCBiOiBNYXRoLm1heCgwLCBwLmIpLCBlOiBwLmUsIG86IHAubywgZXhpdCwKICAgICAgICAgICBkZXA6IHAuZGVwIHx8IFtdLCBleHQ6IHAuZXh0IHx8IFtdLCBvZDogcC5vZCB8fCBbXSwKICAgICAgICAgICB0cmFjZWQ6IHAucy5zdGFydHNXaXRoKCdjcnV4LWRhZW1vbi1idXllci1maXQnKSB8fCBwLnMuc3RhcnRzV2l0aCgnY3Jvc3Mtc2l0ZS1hdXRoLXNzbycpIH07Cn0KZnVuY3Rpb24gbG9hZFBsYW5zKHJhd3MpIHsKICBQTEFOUy5sZW5ndGggPSAwOwogIHJhd3MuZm9yRWFjaCgocCwgaSkgPT4gUExBTlMucHVzaChtYXBSYXcocCwgaSkpKTsKfQovKiBsaW5lYWdlIGVkZ2VzIHJlc29sdmFibGUgd2l0aGluIHRoZSBjdXJyZW50IHNldDogYSBkZXBlbmRzX29uIGIgKi8KY29uc3QgREVQX0VER0VTID0gW107CmZ1bmN0aW9uIHJlYnVpbGRMaW5lYWdlKCkgewogIERFUF9FREdFUy5sZW5ndGggPSAwOwogIGNvbnN0IGJ5U2x1ZyA9IE9iamVjdC5mcm9tRW50cmllcyhQTEFOUy5tYXAocCA9PiBbcC5zbHVnLCBwXSkpOwogIGZvciAoY29uc3QgcCBvZiBQTEFOUykgZm9yIChjb25zdCBkIG9mIHAuZGVwKSB7CiAgICBjb25zdCB0MiA9IGJ5U2x1Z1tkXTsKICAgIGlmICh0MikgREVQX0VER0VTLnB1c2goeyBhOiBwLCBiOiB0MiB9KTsKICB9Cn0KbG9hZFBsYW5zKFBMQU5TX1JBVyk7CnJlYnVpbGRMaW5lYWdlKCk7CgovKiByZWFsIGZhY3RzIGZvciB0aGUgdHdvIHRyYWNlZCBwbGFucyAoZGF5ID0gNjcgKyBvZmZzZXQgZnJvbSBKdWwgMTMpICovCmNvbnN0IEoxMyA9IDY3OyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8qIDIwMjYtMDctMTMgYXMgZGF5IGluZGV4ICovCmNvbnN0IFJGQUNUUyA9IFsKICBbJ3NzbycsICdicmllZicsICdtZW1vcnknLCAwLjkyMCwgJ2NvZGV4LXdvcmsnLCAnbWVkaXVtJywgMjA1LCAxXSwKICBbJ3NzbycsICdnYXRlOk0wJywgJ2dhdGUnLCAwLjkzNiwgJ2NvZGV4LXdvcmsnLCAnbWVkaXVtJywgMjA1LCAxXSwKICBbJ3NzbycsICdkZWNpc2lvbjp0b3BvbG9neS1jb3JyZWN0ZWQtY3J1eGVuZ2luZScsICdkZWNpc2lvbicsIDAuOTQ4LCAnY29kZXgtd29yaycsICdtZWRpdW0nLCAyMDcsIDFdLAogIFsnc3NvJywgJ21pbGVzdG9uZTpNMS1wYXJ0aWFsJywgJ21lbW9yeScsIDAuOTkwLCAnY29kZXgtd29yaycsICdtZWRpdW0nLCAyNzUsIDFdLAogIFsnYmYnLCAnZ2F0ZTpNMCcsICdnYXRlJywgMS4zNTYsICdjb2RleC13b3JrJywgJ3N0YWJsZScsIDQxMiwgMV0sCiAgWydzc28nLCAnZ2F0ZTpNMScsICdnYXRlJywgMS4zODEsICdjb2RleC13b3JrJywgJ21lZGl1bScsIDI5NiwgMV0sCiAgWydzc28nLCAnZ2F0ZTpNMicsICdnYXRlJywgMS42NDksICdjb2RleC13b3JrJywgJ21lZGl1bScsIDIzNiwgMV0sCiAgWydiZicsICdnYXRlOk0xJywgJ2dhdGUnLCAxLjY2OSwgJ2NvZGV4LXdvcmsnLCAnc3RhYmxlJywgNTM2LCAxXSwKICBbJ3NzbycsICdnYXRlOk0zLU00JywgJ2dhdGUnLCAxLjgyOSwgJ2NvZGV4LXdvcmsnLCAnbWVkaXVtJywgMzI4LCAxXSwKICBbJ2JmJywgJ2dhdGU6TTInLCAnZ2F0ZScsIDEuODQ3LCAnY29kZXgtd29yaycsICdzdGFibGUnLCA0NjMsIDFdLAogIFsnYmYnLCAnZ2F0ZTpNNCcsICdnYXRlJywgMS44NTgsICdjb2RleC13b3JrJywgJ3N0YWJsZScsIDQwOSwgMV0sCiAgWydiZicsICdoYW5kb2ZmOjIwMjYtMDctMTQnLCAnaGFuZG9mZicsIDEuODgyLCAnY29kZXgtd29yaycsICdzdGFibGUnLCA0MDksIDFdLAogIFsnc3NvJywgJ2NvbnNvbGUtdjEtcmVtb3ZlZCcsICdtZW1vcnknLCAxLjg5MiwgJ2NvZGV4LXdvcmsnLCAnbWVkaXVtJywgMjg4LCAxXSwKICBbJ2JmJywgJ3Byb2dyZXNzOk0zJywgJ21lbW9yeScsIDEuOTA5LCAnY29kZXgtd29yaycsICd2b2xhdGlsZScsIDI3NCwgMV0sCiAgWydiZicsICdnYXRlOk0zJywgJ2dhdGUnLCAxLjk1MSwgJ2NvZGV4LXdvcmsnLCAnc3RhYmxlJywgMzE2LCAxXSwKICBbJ2JmJywgJ2dhdGU6TTMnLCAnZ2F0ZScsIDIuMDMyLCAnY29kZXgtd29yaycsICdzdGFibGUnLCAyMTUsIDJdLAogIFsnc3NvJywgJ2NvbnNvbGUtdjEtcmVtb3ZlZC1mb2xsb3d1cC1kb25lJywgJ21lbW9yeScsIDIuODkxLCAnY29kZXgtd29yaycsICdtZWRpdW0nLCAzMjksIDFdLAogIFsnc3NvJywgJ2dhdGU6TTEtUi1jb2RlJywgJ2dhdGUnLCA4LjU5NywgJ2NsYXVkZS13b3JrJywgJ21lZGl1bScsIDEyNywgMV0sCiAgWydzc28nLCAnZGVjaXNpb246dmF1bHQtdGFyZ2V0LXJlZ3Jlc3Npb24tcmVwYWlyJywgJ2RlY2lzaW9uJywgOC41OTcsICdjbGF1ZGUtd29yaycsICdzdGFibGUnLCAxNTUsIDFdLAogIFsnYmYnLCAnZ2F0ZTpNNWInLCAnZ2F0ZScsIDkuMzY3LCAnY2xhdWRlLXdvcmsnLCAnc3RhYmxlJywgMTg0LCAxXSwKICBbJ2JmJywgJ2RlY2lzaW9uOm01Yi1pbnN0YWxsZXItdHJhbnNhY3Rpb24nLCAnZGVjaXNpb24nLCA5LjM2NywgJ2NsYXVkZS13b3JrJywgJ3N0YWJsZScsIDIzMiwgMV0sCl07CgovKiBjZWxsczogcmVhbCBmb3IgdHJhY2VkIHBsYW5zLCBtaWxlc3RvbmUtZGVyaXZlZCBmb3IgdGhlIHJlc3QgKHJlYnVpbGRhYmxlKSAqLwpjb25zdCBjZWxscyA9IFtdOwpmdW5jdGlvbiBidWlsZENlbGxzKCkgewogIGNlbGxzLmxlbmd0aCA9IDA7CiAgY29uc3QgcnIgPSBtdWxiZXJyeTMyKDB4QzRDNCk7CiAgZm9yIChjb25zdCBwIG9mIFBMQU5TKSB7CiAgICBpZiAocC50cmFjZWQpIHsKICAgICAgY29uc3QgdGFnID0gcC5zbHVnLnN0YXJ0c1dpdGgoJ2NydXgtZGFlbW9uLWJ1eWVyLWZpdCcpID8gJ2JmJyA6ICdzc28nOwogICAgICBmb3IgKGNvbnN0IHIgb2YgUkZBQ1RTKSB7CiAgICAgICAgaWYgKHJbMF0gIT09IHRhZykgY29udGludWU7CiAgICAgICAgY2VsbHMucHVzaCh7IHAsIGtleTogclsxXSwga2luZDogclsyXSwgZGF5OiBKMTMgKyByWzNdLCBhY3Rvcjogcls0XSwgaG9yaXpvbjogcls1XSwKICAgICAgICAgICAgICAgICAgICAgdG9rZW5zOiByWzZdLCB2ZXJzaW9uOiByWzddLCByZWFsOiB0cnVlLCBqYTogcnIoKSwganI6IHJyKCkgfSk7CiAgICAgIH0KICAgICAgY29udGludWU7CiAgICB9CiAgICBjb25zdCBzcGFuID0gTWF0aC5tYXgoMC41LCBwLmUgLSBwLmIpOwogICAgY29uc3QgbkdhdGVzID0gTWF0aC5taW4ocC5kb25lLCAxMik7CiAgICBmb3IgKGxldCBtID0gMDsgbSA8IG5HYXRlczsgbSsrKSB7CiAgICAgIGNlbGxzLnB1c2goeyBwLCBrZXk6ICdnYXRlOk0nICsgbSwga2luZDogJ2dhdGUnLCBkYXk6IHAuYiArIHNwYW4gKiAoKG0gKyAxKSAvIChuR2F0ZXMgKyAxKSksCiAgICAgICAgICAgICAgICAgICByZWFsOiBmYWxzZSwgamE6IHJyKCksIGpyOiBycigpIH0pOwogICAgfQogICAgY29uc3Qgbk1lbSA9IE1hdGgubWF4KDEsIE1hdGgubWluKDYsIE1hdGgucm91bmQoc3BhbiAvIDYpICsgKHAubyA+IDAgPyAyIDogMCkpKTsKICAgIGZvciAobGV0IG0gPSAwOyBtIDwgbk1lbTsgbSsrKSB7CiAgICAgIGNvbnN0IGtpbmRzID0gWydtZW1vcnknLCAnbWVtb3J5JywgJ2RlY2lzaW9uJ107CiAgICAgIGNvbnN0IGtrID0ga2luZHNbTWF0aC5mbG9vcihycigpICogMyldOwogICAgICBjZWxscy5wdXNoKHsgcCwga2V5OiBraywga2luZDoga2ssIGRheTogcC5iICsgc3BhbiAqIHJyKCksCiAgICAgICAgICAgICAgICAgICByZWFsOiBmYWxzZSwgamE6IHJyKCksIGpyOiBycigpIH0pOwogICAgfQogIH0KICAvKiBwZXItcGxhbiBkcmF3IGxpc3QsIG9sZGVzdCBMQVNUIChzbyBvbGRlciBiYXJzIHBhaW50IG9uIHRvcCk7CiAgICAgZGF5LXJhbmsgZHJpdmVzIHRoZSBjbG9ja3dpc2UgaW4tc2VjdG9yIHNwcmVhZCAqLwogIGZvciAoY29uc3QgcCBvZiBQTEFOUykgewogICAgcC5jZWxscyA9IGNlbGxzLmZpbHRlcihjID0+IGMucCA9PT0gcCkuc29ydCgoYSwgYikgPT4gYi5kYXkgLSBhLmRheSk7CiAgICBjb25zdCBhc2MgPSBbLi4ucC5jZWxsc10uc29ydCgoYSwgYikgPT4gYS5kYXkgLSBiLmRheSk7CiAgICBhc2MuZm9yRWFjaCgoYywgaykgPT4geyBjLnJhbmsgPSBrOyBjLm4gPSBhc2MubGVuZ3RoOyB9KTsKICAgIC8qIHJpbSB0b2tlbiB3ZWlnaHQgcGVyIEVWRU5UIOKAlCB0aGUgY2hhcnQgaXMgYW5jaG9yZWQgdG8gdGhlIGV2ZW50IGxpbmVzICovCiAgICBmb3IgKGNvbnN0IGMgb2YgYXNjKSB7CiAgICAgIGMudG9rVyA9IChjLmtpbmQgPT09ICdnYXRlJyA/IDMgOiBjLmtpbmQgPT09ICdkZWNpc2lvbicgPyAyIDogMSkgKyAoYy50b2tlbnMgPyBjLnRva2VucyAvIDI1MCA6IDApOwogICAgfQogICAgcC50b2tNYXggPSBNYXRoLm1heCgwLjAwMSwgLi4uYXNjLm1hcChjID0+IGMudG9rVykpOwogICAgLyogaGVpZ2h0IHNjYWxlOiBoZWF2aWVyIHBsYW5zIChvdXRwdXQgdG9rZW5zKSBnZXQgdGFsbGVyIHJpbSBjaGFydHMgKi8KICAgIHAudG9rU2NhbGUgPSAwLjM1ICsgMC42NSAqIE1hdGgubWluKDEsIE1hdGgubG9nKDEgKyBwLm8pIC8gTWF0aC5sb2coODEpKTsKICB9Cn0KYnVpbGRDZWxscygpOwoKLyog4pSA4pSAIHZpZXcgc3RhdGUg4pSA4pSAICovCmxldCByb3QgPSAwLCBzcGlubmluZyA9ICFSRURVQ0VELCByZXNldFR3ZWVuID0gZmFsc2U7CmxldCBtb2RlID0gJ2JhcnMnOyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8qIGRvdHMgfCBiYXJzIOKAlCBiYXJzIGJ5IGRlZmF1bHQgKi8KbGV0IHNob3dDb21wbGV0ZWQgPSBmYWxzZTsgICAgICAgICAgICAgICAgICAgICAgICAgLyogY29tcGxldGVkIHBsYW5zIG9uIHRoZSBjbG9jazsgYXV0by1vbiB3aGlsZSBwbGF5aW5nICovCmxldCBzaG93TGVkZ2VyID0gZmFsc2U7ICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8qIGNvbXBsZXRlZCBsaXN0IChsZWZ0KTsgYXV0by1vbiBkdXJpbmcgcGxheSwgb2ZmIG9uIGxlbnMgc3dhcCAqLwpsZXQgZGlyID0gJ291dCc7ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvKiBvdXQ6IHJpbmdzIGdyb3cgZnJvbSBjZW50cmUgwrcgaW46IG5vZGVzIHNpbmsgZnJvbSByaW0gKi8KbGV0IHNob3dBbGwgPSBmYWxzZTsgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLyogY2Vuc3VzIG1vZGU6IG5vdGhpbmcgcmV0aXJlcyBvZmYgdGhlIGNsb2NrICovCmxldCBob3ZlclNlYyA9IG51bGw7ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8qIHBsYW4gd2hvc2Ugc2VjdG9yIGlzIHVuZGVyIHRoZSBwb2ludGVyICovCmxldCBjb2xvckJ5U3RhdGUgPSBmYWxzZTsgICAgICAgICAgICAgICAgICAgICAgICAgIC8qIG5vZGVzIGNvbG91cmVkIGJ5IHBsYW4gc3RhdGUgaW5zdGVhZCBvZiBraW5kICovCmxldCBzaG93TGluZWFnZSA9IGZhbHNlOyAgICAgICAgICAgICAgICAgICAgICAgICAgIC8qIGFsbCBkZXBlbmRzX29uIGNob3JkcyBmYWludGx5IHZpc2libGUgKi8KbGV0IGxlbnMgPSAnd29yayc7ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLyogd29yayB8IG1lbW9yeSB8IHNlc3Npb25zIHwgcmVjZWlwdHMgKi8KbGV0IGxlbnNMYWJlbHMgPSBbXTsgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLyogc2NyZWVuLXNwYWNlIGxhYmVscyBzZXQgYnkgbGVucyByZW5kZXJlcnMgKi8KbGV0IGZLaW5kID0gJ2FsbCcsIGZBZ2VudCA9ICdhbGwnOyAgICAgICAgICAgICAgICAgLyogbm9kZSBmaWx0ZXJzICovCmNvbnN0IHBhc3NGaWx0ZXIgPSBjID0+CiAgKGZLaW5kID09PSAnYWxsJyB8fCBjLmtpbmQgPT09IGZLaW5kKSAmJgogIChmQWdlbnQgPT09ICdhbGwnIHx8IGMuYWN0b3IgPT09IGZBZ2VudCk7CmxldCBTID0gMTEsIEUgPSBOT1csIFQgPSBOT1c7ICAgICAgICAgICAgICAgICAgICAgIC8qIHdpbmRvdyArIHBsYXloZWFkIChkYXlzKSAqLwpsZXQgcGxheWluZyA9IGZhbHNlOwpsZXQgWiA9IDEsIHBhblggPSAwLCBwYW5ZID0gMDsKbGV0IGhvdmVyID0gbnVsbCwgcGlubmVkID0gbnVsbDsgICAgICAgICAgICAgICAgICAgLyogcGlubmVkID0gc2VsZWN0ZWQgY2VsbCAoaGlnaGxpZ2h0IHJpbmcpICovCmxldCBzZWwgPSBudWxsOyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8qIHt0eXBlOidjZWxsJywgY30gfCB7dHlwZToncGxhbicsIHB9IOKGkiBwYW5lICovCmxldCBzb2xvID0gbnVsbDsgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8qIGxlZGdlciBmaWx0ZXI6IHNob3cgb25seSB0aGlzIHBsYW4gKi8KbGV0IGxlZGdlclJvd3MgPSBbXTsgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLyogc2NyZWVuIHJlY3RzIGZvciBsZWRnZXIgaGl0LXRlc3RpbmcgKi8KbGV0IG14QWJzID0gMCwgbXlBYnMgPSAwOwpsZXQgZHJhZ2dpbmcgPSBmYWxzZSwgZHJhZ01vdmVkID0gMCwgbGFzdFBYID0gMCwgbGFzdFBZID0gMDsKY29uc3QgZmxhc2hlcyA9IFtdOyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLyoge2FuZzAsIGFuZzEsIHIsIGh1ZSwgdDB9IGV4aXQvZW50ZXIgZmxhc2hlcyAqLwoKY29uc3QgYlNwaW4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYi1zcGluJyk7CmNvbnN0IGJDbG9jayA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdiLWNsb2NrJyk7CmNvbnN0IGJNb2RlID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2ItbW9kZScpOwpjb25zdCBiUGxheSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdiLXBsYXknKTsKY29uc3QgclN0YXJ0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3Itc3RhcnQnKTsKY29uc3QgckVuZCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdyLWVuZCcpOwpjb25zdCByVGltZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdyLXRpbWUnKTsKY29uc3QgY0RhdGUgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYy1kYXRlJyk7CgovKiDilIDilIAgYWN0aXZlIHNldCArIGFuaW1hdGVkIHNlY3RvciBsYXlvdXQg4pSA4pSAICovCi8qIGVhY2ggcGxhbjogbGF5ID0ge2EwLCBhMSwgYWxwaGF9IGxlcnBlZCB0b3dhcmQgdGFyZ2V0cyAqLwpjb25zdCBTRUFNID0gMC4xMDsgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvKiBnYXAgYXQgMTIgbydjbG9jayAqLwpjb25zdCBCQVNFID0gLU1hdGguUEkgLyAyICsgU0VBTSAvIDI7ICAgICAgICAgICAgICAvKiAxMjowMSAqLwpmdW5jdGlvbiBhY3RpdmVQbGFucyh0KSB7CiAgaWYgKHNvbG8pIHJldHVybiBbc29sb107CiAgbGV0IG91dDsKICBpZiAoc2hvd0FsbCkgb3V0ID0gUExBTlMuZmlsdGVyKHAgPT4gcC5iIDw9IHQgJiYgcC5lID49IFMgLSAwLjAwMSAmJiBwLmIgPD0gRSk7CiAgZWxzZSBvdXQgPSBQTEFOUy5maWx0ZXIocCA9PiBwLmIgPD0gdCAmJiB0IDwgcC5leGl0ICYmIHAuZSA+PSBTIC0gMC4wMDEgJiYgcC5iIDw9IEUpOwogIGlmICghc2hvd0NvbXBsZXRlZCkgb3V0ID0gb3V0LmZpbHRlcihwID0+IHAuc3QgIT09IDApOwogIHJldHVybiBvdXQ7Cn0KZnVuY3Rpb24gbGF5b3V0VGFyZ2V0cyh0KSB7CiAgaWYgKHNvbG8pIHsKICAgIC8qIHNvbG86IHRoZSBwbGFuIHNwYW5zIDEyIOKGkiA5IG8nY2xvY2s7IHRoZSA54oaSMTIgcXVhZHJhbnQgYmVjb21lcyB0aGUKICAgICAgIGV2ZW50IGxlZGdlciAqLwogICAgY29uc3Qgb3V0ID0gbmV3IE1hcCgpOwogICAgb3V0LnNldChzb2xvLmksIHsgYTA6IC1NYXRoLlBJIC8gMiArIDAuMDIsIGExOiBNYXRoLlBJIC0gMC4wMiB9KTsKICAgIHJldHVybiBvdXQ7CiAgfQogIGNvbnN0IGFjdCA9IGFjdGl2ZVBsYW5zKHQpLnNvcnQoKGEsIGIpID0+IGIuYiAtIGEuYiB8fCBhLmkgLSBiLmkpOyAgLyogbmV3ZXN0IGZpcnN0ICovCiAgY29uc3Qgd2lkdGggPSAoVEFVIC0gU0VBTSkgLyBNYXRoLm1heCgxLCBhY3QubGVuZ3RoKTsKICBjb25zdCBvdXQgPSBuZXcgTWFwKCk7CiAgYWN0LmZvckVhY2goKHAsIGspID0+IG91dC5zZXQocC5pLCB7IGEwOiBCQVNFICsgayAqIHdpZHRoLCBhMTogQkFTRSArIChrICsgMSkgKiB3aWR0aCB9KSk7CiAgcmV0dXJuIG91dDsKfQpmdW5jdGlvbiBzdGVwTGF5b3V0KGR0KSB7CiAgY29uc3QgdGFyZ2V0cyA9IGxheW91dFRhcmdldHMoVCk7CiAgY29uc3QgayA9IFJFRFVDRUQgPyAxIDogTWF0aC5taW4oMSwgZHQgKiA3KTsKICBmb3IgKGNvbnN0IHAgb2YgUExBTlMpIHsKICAgIGNvbnN0IHRnID0gdGFyZ2V0cy5nZXQocC5pKTsKICAgIGlmICh0ZykgewogICAgICBpZiAoIXAubGF5KSB7ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvKiBlbnRlcjogYmxvb20gZnJvbSB0YXJnZXQgbWlkICovCiAgICAgICAgY29uc3QgbWlkID0gKHRnLmEwICsgdGcuYTEpIC8gMjsKICAgICAgICBwLmxheSA9IHsgYTA6IG1pZCwgYTE6IG1pZCwgYWxwaGE6IDAgfTsKICAgICAgICBpZiAoZmxhc2hlcy5sZW5ndGggPCA0MCkgICAgICAgICAgICAgICAgICAgLyogY2FwOiB0b2dnbGluZyBjZW5zdXMgbW9kZSBiaXJ0aHMgMTYwKyBhdCBvbmNlICovCiAgICAgICAgICBmbGFzaGVzLnB1c2goeyBraW5kOiAnZW50ZXInLCBhbmc6IG1pZCwgdDA6IHBlcmZvcm1hbmNlLm5vdygpIC8gMTAwMCwgaHVlOiAnIzhiOTZmMicgfSk7CiAgICAgIH0KICAgICAgcC5sYXkuYTAgPSBtaXgocC5sYXkuYTAsIHRnLmEwLCBrKTsKICAgICAgcC5sYXkuYTEgPSBtaXgocC5sYXkuYTEsIHRnLmExLCBrKTsKICAgICAgcC5sYXkuYWxwaGEgPSBtaXgocC5sYXkuYWxwaGEsIDEsIGspOwogICAgfSBlbHNlIGlmIChwLmxheSkgeyAgICAgICAgICAgICAgICAgICAgICAgICAgICAvKiBleGl0OiBjb2xsYXBzZSArIGZsYXNoIG9uY2UgKi8KICAgICAgaWYgKCFwLmxheS5leGl0aW5nKSB7CiAgICAgICAgcC5sYXkuZXhpdGluZyA9IHRydWU7CiAgICAgICAgY29uc3QgbWlkID0gKHAubGF5LmEwICsgcC5sYXkuYTEpIC8gMjsKICAgICAgICBjb25zdCBodWUgPSBwLnN0ID09PSAwID8gJyMzNGQzOTknIDogcC5zdCA9PT0gMiA/ICcjZWY0NDQ0JyA6ICcjN2U4NTk1JzsKICAgICAgICBmbGFzaGVzLnB1c2goeyBraW5kOiAnZXhpdCcsIGFuZzogbWlkLCB0MDogcGVyZm9ybWFuY2Uubm93KCkgLyAxMDAwLCBodWUgfSk7CiAgICAgIH0KICAgICAgY29uc3QgbWlkID0gKHAubGF5LmEwICsgcC5sYXkuYTEpIC8gMjsKICAgICAgcC5sYXkuYTAgPSBtaXgocC5sYXkuYTAsIG1pZCwgayk7CiAgICAgIHAubGF5LmExID0gbWl4KHAubGF5LmExLCBtaWQsIGspOwogICAgICBwLmxheS5hbHBoYSA9IG1peChwLmxheS5hbHBoYSwgMCwgayk7CiAgICAgIGlmIChwLmxheS5hbHBoYSA8IDAuMDIpIHAubGF5ID0gbnVsbDsKICAgIH0KICAgIGlmIChwLmxheSAmJiAhdGFyZ2V0cy5nZXQocC5pKSkgeyAvKiBrZWVwIGV4aXRpbmcgKi8gfQogICAgZWxzZSBpZiAocC5sYXkpIHAubGF5LmV4aXRpbmcgPSBmYWxzZTsKICB9Cn0KCi8qIOKUgOKUgCBzdGFnZSDilIDilIAgKi8KY29uc3QgY3YgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnY3YnKTsKY29uc3QgY3R4ID0gY3YuZ2V0Q29udGV4dCgnMmQnKTsKbGV0IFcgPSAwLCBIID0gMCwgdmlzaWJsZSA9IHRydWUsIHJhZklkID0gbnVsbCwgbGFzdFQgPSBwZXJmb3JtYW5jZS5ub3coKTsKZnVuY3Rpb24gcmVzaXplKCkgewogIGNvbnN0IHIgPSBjdi5nZXRCb3VuZGluZ0NsaWVudFJlY3QoKSwgZHByID0gTWF0aC5taW4oZGV2aWNlUGl4ZWxSYXRpbyB8fCAxLCAyKTsKICBXID0gci53aWR0aDsgSCA9IHIuaGVpZ2h0OwogIGN2LndpZHRoID0gTWF0aC5yb3VuZChXICogZHByKTsgY3YuaGVpZ2h0ID0gTWF0aC5yb3VuZChIICogZHByKTsKICBjdHguc2V0VHJhbnNmb3JtKGRwciwgMCwgMCwgZHByLCAwLCAwKTsKfQpuZXcgUmVzaXplT2JzZXJ2ZXIocmVzaXplKS5vYnNlcnZlKGN2KTsKbmV3IEludGVyc2VjdGlvbk9ic2VydmVyKGVzID0+IHsgdmlzaWJsZSA9IGVzWzBdLmlzSW50ZXJzZWN0aW5nOyB9LCB7IHJvb3RNYXJnaW46ICc2MHB4JyB9KS5vYnNlcnZlKGN2KTsKCmNvbnN0IEVQT0NIX1JJTkdTID0gMTA7CmZ1bmN0aW9uIGdlb20oKSB7CiAgY29uc3QgY3ggPSBXIC8gMiwgY3kgPSBIIC8gMjsKICBjb25zdCBSID0gTWF0aC5taW4oVyAqIDAuOSwgSCAqIDAuNzgpICogMC40NDsKICBjb25zdCByMCA9IFIgKiAwLjEzOwogIHJldHVybiB7IGN4LCBjeSwgUiwgcjAgfTsKfQovKiByYWRpdXMgZm9yIGEgZGF5LgogICBvdXQ6IHJhZGl1cyBmaXhlZCBieSBiaXJ0aCB0aW1lIOKAlCBlYXJseSBpbm5lciwgbGF0ZSBvdXRlciwgZWRnZSBzd2VlcHMgb3V0LgogICBpbiA6IHJhZGl1cyBieSBBR0UgYXQgVCDigJQgYm9ybiBhdCB0aGUgcmltLCBzaW5rcyB0b3dhcmQgdGhlIGhlYXJ0d29vZC4KICAgUkFEX0xPIGlzIHRoZSByYWRpYWwgdGltZSBmbG9vcjogaW4gdGhlIGFjdGl2ZS1wbGFucyB3b3JrIHZpZXcgaXQgc25hcHMgdG8KICAgdGhlIG9sZGVzdCBWSVNJQkxFIG5vZGUgc28gcmluZyAxIGlzIGFsd2F5cyBvY2N1cGllZCDigJQgb3RoZXJ3aXNlLCB5ZWFycwogICBpbiwgZXZlcnkgbGl2ZSBub2RlIHdvdWxkIGNyb3dkIHRoZSBvdXRlciByaW0uIENlbnN1cy9zb2xvL290aGVyIGxlbnNlcwogICBrZWVwIHRoZSBmdWxsIHdpbmRvdy4gKi8KbGV0IFJBRF9MTyA9IDExOwpmdW5jdGlvbiBkYXlSKGcsIGRheSkgewogIGlmIChkaXIgPT09ICdpbicpIHsKICAgIGNvbnN0IGFnZSA9IE1hdGgubWF4KDAsIE1hdGgubWluKDEsIChUIC0gZGF5KSAvIE1hdGgubWF4KDAuNSwgVCAtIFJBRF9MTykpKTsKICAgIHJldHVybiBnLnIwICsgKGcuUiAtIGcucjApICogKDAuOTYgLSAwLjg4ICogYWdlKTsKICB9CiAgY29uc3QgZiA9IE1hdGgubWF4KDAsIE1hdGgubWluKDEsIChkYXkgLSBSQURfTE8pIC8gTWF0aC5tYXgoMC41LCBFIC0gUkFEX0xPKSkpOwogIHJldHVybiBnLnIwICsgKGcuUiAtIGcucjApICogKDAuMDggKyAwLjg4ICogZik7Cn0KZnVuY3Rpb24gdXBkYXRlUmFkTG8oKSB7CiAgUkFEX0xPID0gUzsKICBpZiAobGVucyAhPT0gJ3dvcmsnIHx8IHNob3dBbGwgfHwgc29sbykgcmV0dXJuOwogIGxldCBsbyA9IEluZmluaXR5OwogIGZvciAoY29uc3QgcCBvZiBhY3RpdmVQbGFucyhUKSkgewogICAgZm9yIChjb25zdCBjIG9mIHAuY2VsbHMpIHsKICAgICAgaWYgKGMuZGF5IDw9IFQgJiYgYy5kYXkgPj0gUyAmJiBjLmRheSA8PSBFICYmIGMuZGF5IDwgbG8pIGxvID0gYy5kYXk7CiAgICB9CiAgfQogIGlmIChsbyA8IEluZmluaXR5KSBSQURfTE8gPSBNYXRoLm1heChTLCBNYXRoLm1pbihsbywgRSAtIDEpKTsKfQovKiBkaXNjIOKGkiBzY3JlZW4gKi8KZnVuY3Rpb24gdG9TY3JlZW4oZywgeCwgeSkgewogIGNvbnN0IGMgPSBNYXRoLmNvcyhyb3QpLCBzID0gTWF0aC5zaW4ocm90KTsKICByZXR1cm4geyB4OiBnLmN4ICsgcGFuWCArICh4ICogYyAtIHkgKiBzKSAqIFosIHk6IGcuY3kgKyBwYW5ZICsgKHggKiBzICsgeSAqIGMpICogWiB9Owp9Ci8qIHNjcmVlbiDihpIgZGlzYyAqLwpmdW5jdGlvbiB0b0Rpc2MoZywgc3gsIHN5KSB7CiAgY29uc3QgdXggPSAoc3ggLSBnLmN4IC0gcGFuWCkgLyBaLCB1eSA9IChzeSAtIGcuY3kgLSBwYW5ZKSAvIFo7CiAgY29uc3QgYyA9IE1hdGguY29zKC1yb3QpLCBzID0gTWF0aC5zaW4oLXJvdCk7CiAgcmV0dXJuIHsgeDogdXggKiBjIC0gdXkgKiBzLCB5OiB1eCAqIHMgKyB1eSAqIGMgfTsKfQoKY29uc3Qgc29sb1JpbmdSID0gKGcsIGMpID0+IHsKICAvKiBzb2xvOiBvbmUgcmluZyBwZXIgZXZlbnQg4oCUIGVhcmxpZXN0IG91dGVybW9zdCwgbGF0ZXN0IGlubmVybW9zdCAqLwogIGNvbnN0IHVuaXQgPSBnLlIgLSBnLnIwOwogIGNvbnN0IHJNYXggPSBnLnIwICsgdW5pdCAqIDAuOTIsIHJNaW4gPSBnLnIwICsgdW5pdCAqIDAuMTg7CiAgcmV0dXJuIGMubiA+IDEgPyByTWF4IC0gKHJNYXggLSByTWluKSAqIChjLnJhbmsgLyAoYy5uIC0gMSkpIDogKHJNYXggKyByTWluKSAvIDI7Cn07CmZ1bmN0aW9uIGNlbGxQb3MoZywgYykgewogIGlmICghYy5wLmxheSkgcmV0dXJuIG51bGw7CiAgLyogY2xvY2t3aXNlIGJ5IGRheSBvcmRlcjogZWFybGllc3QgYXQgdGhlIHNlY3RvcidzIGxlYWRpbmcgZWRnZSAqLwogIGNvbnN0IGZyYWMgPSBjLm4gPiAxID8gKGMucmFuayArIDAuNSkgLyBjLm4gOiAwLjU7CiAgY29uc3QgYSA9IGMucC5sYXkuYTAgKyAoYy5wLmxheS5hMSAtIGMucC5sYXkuYTApICogKDAuMDYgKyAwLjg4ICogZnJhYyk7CiAgY29uc3QgciA9IHNvbG8gPT09IGMucCA/IHNvbG9SaW5nUihnLCBjKSA6IGRheVIoZywgYy5kYXkpICogKDAuOTk1ICsgYy5qciAqIDAuMDEpOwogIHJldHVybiB7IGEsIHIsIHg6IE1hdGguY29zKGEpICogciwgeTogTWF0aC5zaW4oYSkgKiByIH07Cn0KZnVuY3Rpb24gZG90UihjKSB7CiAgcmV0dXJuIChjLnJlYWwgPyAzLjQgKyAoYy50b2tlbnMgfHwgMjAwKSAvIDI2MCA6IGMua2luZCA9PT0gJ2dhdGUnID8gMy4yIDogMi42KTsKfQoKZnVuY3Rpb24gZHJhdyhub3cpIHsKICBjb25zdCBkdCA9IE1hdGgubWluKDAuMDUsIChub3cgLSBsYXN0VCkgLyAxMDAwKTsgbGFzdFQgPSBub3c7CiAgY29uc3QgdGltZSA9IG5vdyAvIDEwMDA7CiAgaWYgKHNwaW5uaW5nICYmICFSRURVQ0VEICYmICFyZXNldFR3ZWVuKSByb3QgKz0gZHQgKiAwLjAyOwogIGlmIChyZXNldFR3ZWVuKSB7CiAgICBsZXQgdGFyZ2V0ID0gcm90IC0gKCgocm90ICUgVEFVKSArIFRBVSkgJSBUQVUpOyAgICAgICAgICAgLyogbmVhcmVzdCBmdWxsIHR1cm4gYmVsb3cgKi8KICAgIGlmICgoKHJvdCAlIFRBVSkgKyBUQVUpICUgVEFVID4gTWF0aC5QSSkgdGFyZ2V0ICs9IFRBVTsgICAvKiBnbyB0aGUgc2hvcnQgd2F5ICovCiAgICByb3QgPSBtaXgocm90LCB0YXJnZXQsIFJFRFVDRUQgPyAxIDogMC4xMik7CiAgICBpZiAoTWF0aC5hYnMocm90IC0gdGFyZ2V0KSA8IDAuMDAyKSB7IHJvdCA9IDA7IHJlc2V0VHdlZW4gPSBmYWxzZTsgfQogIH0KICBpZiAocGxheWluZykgewogICAgVCArPSBkdCAqIChFIC0gUykgLyAyNDsgICAgICAgICAgICAgICAgICAgICAgICAvKiBmdWxsIHdpbmRvdyBpbiB+MjRzIChzbG93ZWQgMjUlKSAqLwogICAgaWYgKFQgPj0gRSkgeyBUID0gRTsgc2V0UGxheWluZyhmYWxzZSk7IH0KICAgIHJUaW1lLnZhbHVlID0gTWF0aC5yb3VuZCgoVCAtIFMpIC8gTWF0aC5tYXgoMC41LCBFIC0gUykgKiAxMDAwKTsKICAgIGNEYXRlLnRleHRDb250ZW50ID0gZGF5RGF0ZShUKTsKICB9CiAgaWYgKGxlbnMgPT09ICd3b3JrJykgc3RlcExheW91dChkdCk7CiAgdXBkYXRlUmFkTG8oKTsKICBjb25zdCBnID0gZ2VvbSgpOwogIGN0eC5jbGVhclJlY3QoMCwgMCwgVywgSCk7CgogIC8qIOKVkOKVkCBkaXNjIGZyYW1lIOKVkOKVkCAqLwogIGN0eC5zYXZlKCk7CiAgY3R4LnRyYW5zbGF0ZShnLmN4ICsgcGFuWCwgZy5jeSArIHBhblkpOwogIGN0eC5zY2FsZShaLCBaKTsKICBjdHgucm90YXRlKHJvdCk7CgogIC8qIGVwb2NoIHJpbmdzIChzdXBwcmVzc2VkIGluIHNvbG8g4oCUIHRoZXJlLCByaW5ncyBBUkUgZXZlbnRzKSAqLwogIGlmICghc29sbykgewogICAgZm9yIChsZXQgaSA9IDE7IGkgPD0gRVBPQ0hfUklOR1M7IGkrKykgewogICAgICBjb25zdCByID0gZy5yMCArIChnLlIgLSBnLnIwKSAqIChpIC8gRVBPQ0hfUklOR1MpOwogICAgICBjdHguc3Ryb2tlU3R5bGUgPSAncmdiYSgyNTUsMjU1LDI1NSwuMDkpJzsKICAgICAgY3R4LmxpbmVXaWR0aCA9IDEgLyBaOwogICAgICBjdHguYmVnaW5QYXRoKCk7IGN0eC5hcmMoMCwgMCwgciwgMCwgNyk7IGN0eC5zdHJva2UoKTsKICAgIH0KICB9CgogIC8qIHNlYW0gYXQgMTI6IHRoZSAibm93IiBub3RjaCAqLwogIGN0eC5zdHJva2VTdHlsZSA9ICdyZ2JhKDEzOSwxNTAsMjQyLC42KSc7CiAgY3R4LmxpbmVXaWR0aCA9IDEuNSAvIFo7CiAgY3R4LmJlZ2luUGF0aCgpOwogIGN0eC5tb3ZlVG8oTWF0aC5jb3MoLU1hdGguUEkgLyAyKSAqIGcucjAgKiAwLjksIE1hdGguc2luKC1NYXRoLlBJIC8gMikgKiBnLnIwICogMC45KTsKICBjdHgubGluZVRvKE1hdGguY29zKC1NYXRoLlBJIC8gMikgKiAoZy5SICsgMTApLCBNYXRoLnNpbigtTWF0aC5QSSAvIDIpICogKGcuUiArIDEwKSk7CiAgY3R4LnN0cm9rZSgpOwoKICAvKiBzZWN0b3JzICovCiAgbGVuc0xhYmVscyA9IFtdOwogIGxldCBzb2xvTGFiZWxzID0gbnVsbDsKICBpZiAobGVucyAhPT0gJ3dvcmsnKSB7CiAgICBkcmF3TGVuc0luRnJhbWUoY3R4LCBnLCB0aW1lKTsKICB9IGVsc2UgewogIGN0eC5saW5lV2lkdGggPSAxIC8gWjsKICBmb3IgKGNvbnN0IHAgb2YgUExBTlMpIHsKICAgIGlmICghcC5sYXkgfHwgcC5sYXkuYWxwaGEgPCAwLjAyKSBjb250aW51ZTsKICAgIGNvbnN0IEwgPSBwLmxheSwgYWwgPSBMLmFscGhhOwogICAgY29uc3Qgd1NlYyA9IEwuYTEgLSBMLmEwOwogICAgLyogZGl2aWRlciDigJQgc2tpcHBlZCB3aGVuIHNlY3RvcnMgYXJlIHRvbyB0aGluIHRvIHNlcGFyYXRlICovCiAgICBpZiAod1NlYyAqIGcuUiAqIFogPiA4KSB7CiAgICAgIGN0eC5zdHJva2VTdHlsZSA9ICdyZ2JhKDI1NSwyNTUsMjU1LCcgKyAwLjA2ICogYWwgKyAnKSc7CiAgICAgIGN0eC5iZWdpblBhdGgoKTsKICAgICAgY3R4Lm1vdmVUbyhNYXRoLmNvcyhMLmEwKSAqIGcucjAsIE1hdGguc2luKEwuYTApICogZy5yMCk7CiAgICAgIGN0eC5saW5lVG8oTWF0aC5jb3MoTC5hMCkgKiBnLlIsIE1hdGguc2luKEwuYTApICogZy5SKTsKICAgICAgY3R4LnN0cm9rZSgpOwogICAgfQogICAgLyogcmltOiBmdWxsLWV4dGVudCB0cmFjayBhcmMgKHNlZ21lbnQgc3RhcnQg4oaSIGZpbmlzaCwgZ2FwcGVkIGZyb20gdGhlCiAgICAgICBuZWlnaGJvdXIpIHdpdGggdGhlIHRoaWNrIHByb2dyZXNzIGFyYyBvbiB0b3AuIEEgY29tcGxldGUgcGxhbidzCiAgICAgICBwcm9ncmVzcyBjb3ZlcnMgdGhlIHdob2xlIHRyYWNrIOKAlCBvbmUgc29saWQgdGhpY2sgYmFyLiAqLwogICAgY29uc3QgaHVlID0gc3RhdGVIdWUocCk7CiAgICAvKiBob3ZlcmVkIHNlY3RvcjogZnVsbC1hcmMgaGlnaGxpZ2h0ICovCiAgICBpZiAocCA9PT0gaG92ZXJTZWMpIHsKICAgICAgY3R4LnN0cm9rZVN0eWxlID0gaGV4MnJnYmEoaHVlLCAwLjI4ICogYWwpOwogICAgICBjdHgubGluZVdpZHRoID0gMTAgLyBaOwogICAgICBjdHguYmVnaW5QYXRoKCk7IGN0eC5hcmMoMCwgMCwgZy5SIC0gNSAvIFosIEwuYTAsIEwuYTEpOyBjdHguc3Ryb2tlKCk7CiAgICAgIGN0eC5saW5lV2lkdGggPSAxIC8gWjsKICAgIH0KICAgIGNvbnN0IGFQYWQgPSBNYXRoLm1pbigwLjAyLCB3U2VjICogMC4xMCk7CiAgICBjdHguc3Ryb2tlU3R5bGUgPSBoZXgycmdiYShodWUsIDAuMjggKiBhbCk7CiAgICBjdHgubGluZVdpZHRoID0gMS42IC8gWjsKICAgIGN0eC5iZWdpblBhdGgoKTsgY3R4LmFyYygwLCAwLCBnLlIgKyAzLCBMLmEwICsgYVBhZCwgTC5hMSAtIGFQYWQpOyBjdHguc3Ryb2tlKCk7CiAgICBjdHguc3Ryb2tlU3R5bGUgPSBoZXgycmdiYShodWUsIDAuOCAqIGFsKTsKICAgIGN0eC5saW5lV2lkdGggPSA0LjUgLyBaOwogICAgY3R4LmJlZ2luUGF0aCgpOwogICAgY3R4LmFyYygwLCAwLCBnLlIgKyAzLCBMLmEwICsgYVBhZCwgTC5hMCArIGFQYWQgKyBNYXRoLm1heCgwLjAwOCwgKHdTZWMgLSAyICogYVBhZCkgKiAocC5kb25lIC8gcC50b3RhbCkpKTsKICAgIGN0eC5zdHJva2UoKTsKICAgIGN0eC5saW5lV2lkdGggPSAxIC8gWjsKICAgIC8qIG9wZW4gZGVjaXNpb25zOiBhbWJlciBPRCB0aWNrcyBqdXN0IG91dHNpZGUgdGhlIHRyYWNrICovCiAgICBpZiAocC5vZC5sZW5ndGgpIHsKICAgICAgY29uc3QgblQgPSBNYXRoLm1pbihwLm9kLmxlbmd0aCwgTWF0aC5tYXgoMSwgTWF0aC5mbG9vcigod1NlYyAtIDIgKiBhUGFkKSAvIDAuMDIpKSk7CiAgICAgIGN0eC5zdHJva2VTdHlsZSA9IGhleDJyZ2JhKCcjZjVhNjIzJywgMC45NSAqIGFsKTsKICAgICAgY3R4LmxpbmVXaWR0aCA9IDEuOCAvIFo7CiAgICAgIGZvciAobGV0IG9pID0gMDsgb2kgPCBuVDsgb2krKykgewogICAgICAgIGNvbnN0IG9hID0gTC5hMCArIGFQYWQgKyAob2kgKyAwLjUpICogMC4wMTk7CiAgICAgICAgY3R4LmJlZ2luUGF0aCgpOwogICAgICAgIGN0eC5tb3ZlVG8oTWF0aC5jb3Mob2EpICogKGcuUiArIDgpLCBNYXRoLnNpbihvYSkgKiAoZy5SICsgOCkpOwogICAgICAgIGN0eC5saW5lVG8oTWF0aC5jb3Mob2EpICogKGcuUiArIDEzKSwgTWF0aC5zaW4ob2EpICogKGcuUiArIDEzKSk7CiAgICAgICAgY3R4LnN0cm9rZSgpOwogICAgICB9CiAgICAgIGN0eC5saW5lV2lkdGggPSAxIC8gWjsKICAgIH0KICAgIC8qIGJsb2NrZWQgcHVsc2Ugb24gcmltICovCiAgICBpZiAocC5zdCA9PT0gMikgewogICAgICBjb25zdCBwdWxzZSA9IFJFRFVDRUQgPyAwLjUgOiAwLjM1ICsgMC4zICogTWF0aC5zaW4odGltZSAqIDQpOwogICAgICBjdHguc3Ryb2tlU3R5bGUgPSBoZXgycmdiYSgnI2VmNDQ0NCcsIHB1bHNlICogYWwpOwogICAgICBjdHguYmVnaW5QYXRoKCk7IGN0eC5hcmMoMCwgMCwgZy5SICsgOCwgTC5hMCArIDAuMDEsIEwuYTEgLSAwLjAxKTsgY3R4LnN0cm9rZSgpOwogICAgfQogICAgLyogKHRva2VuIHVzYWdlIGNoYXJ0IG1vdmVkIGludG8gdGhlIGRldGFpbCBwYW5lIOKAlCByaW0gc3RheXMgY2xlYW4pICovCiAgICAvKiBsYWJlbCBpZiB3aWRlIGVub3VnaCBvbiBzY3JlZW4g4oCUIG9yIGhvdmVyZWQgKGNlbnN1cyBtb2RlIG5hbWVzIG9uIGhvdmVyKSAqLwogICAgY29uc3QgaXNIb3ZTZWMgPSBwID09PSBob3ZlclNlYzsKICAgIGlmICgod1NlYyAqIGcuUiAqIFogPiA0NiB8fCBpc0hvdlNlYykgJiYgc29sbyAhPT0gcCkgeyAgLyogc29sbyBuYW1lcyBpdHNlbGYgYXQgdGhlIHNlYW0gKi8KICAgICAgY29uc3QgbWlkQSA9IChMLmEwICsgTC5hMSkgLyAyLCBsciA9IGcuUiArIDE0OwogICAgICBjdHguc2F2ZSgpOwogICAgICBjdHgudHJhbnNsYXRlKE1hdGguY29zKG1pZEEpICogbHIsIE1hdGguc2luKG1pZEEpICogbHIpOwogICAgICBjdHgucm90YXRlKG1pZEEgKyAoTWF0aC5jb3MobWlkQSArIHJvdCkgPCAwID8gTWF0aC5QSSA6IDApKTsKICAgICAgY3R4LmZpbGxTdHlsZSA9IGlzSG92U2VjID8gJ3JnYmEoMjM4LDI0MCwyNDYsMSknIDogJ3JnYmEoMjAwLDIwNiwyMTksJyArIDAuOTUgKiBhbCArICcpJzsKICAgICAgY3R4LmZvbnQgPSAnNzAwICcgKyAoMTIgLyBaKSArICdweCAnICsgTU9OTzsKICAgICAgY3R4LnRleHRBbGlnbiA9IE1hdGguY29zKG1pZEEgKyByb3QpIDwgMCA/ICdyaWdodCcgOiAnbGVmdCc7CiAgICAgIGN0eC50ZXh0QmFzZWxpbmUgPSAnbWlkZGxlJzsKICAgICAgY29uc3QgbGJsID0gaXNIb3ZTZWMgPyAocC5zaG9ydC5sZW5ndGggPiAzNCA/IHAuc2hvcnQuc2xpY2UoMCwgMzMpICsgJ+KApicgOiBwLnNob3J0KQogICAgICAgICAgICAgICAgICAgICAgICAgICA6IChwLnNob3J0Lmxlbmd0aCA+IDE2ID8gcC5zaG9ydC5zbGljZSgwLCAxNSkgKyAn4oCmJyA6IHAuc2hvcnQpOwogICAgICBjdHguZmlsbFRleHQobGJsICsgJyAnICsgcC5kb25lICsgJy8nICsgcC50b3RhbCwgMCwgMCk7CiAgICAgIGN0eC5yZXN0b3JlKCk7CiAgICB9CiAgICAvKiBiYXJzICsgZG90cyAob2xkZXIgYmFycyBwYWludGVkIGxhc3QgPSBvbiB0b3ApICovCiAgICBmb3IgKGNvbnN0IGMgb2YgcC5jZWxscykgewogICAgICBpZiAoYy5kYXkgPiBUIHx8IGMuZGF5IDwgUyB8fCBjLmRheSA+IEUpIGNvbnRpbnVlOwogICAgICBpZiAoIXBhc3NGaWx0ZXIoYykpIHsgYy5feCA9IHVuZGVmaW5lZDsgY29udGludWU7IH0KICAgICAgY29uc3QgcG9zID0gY2VsbFBvcyhnLCBjKTsKICAgICAgaWYgKCFwb3MpIGNvbnRpbnVlOwogICAgICBjb25zdCBjaHVlID0gY29sb3JCeVN0YXRlID8gc3RhdGVIdWUoYy5wKSA6IChLSU5EX0hVRVtjLmtpbmRdIHx8ICcjOGI5NmYyJyk7CiAgICAgIGNvbnN0IGlzU2VsID0gKGhvdmVyID09PSBjIHx8IHBpbm5lZCA9PT0gYyk7CiAgICAgIGNvbnN0IGFnZSA9IFQgLSBjLmRheTsKICAgICAgY29uc3QgcG9wID0gUkVEVUNFRCA/IDEgOiBNYXRoLm1pbigxLCBhZ2UgLyAwLjgpOyAgICAgICAgICAgLyogYmlydGggcG9wICovCiAgICAgIGNvbnN0IHJyID0gZG90UihjKSAqIChpc1NlbCA/IDEuNyA6IDEpICogKDAuNCArIDAuNiAqIHBvcCk7CiAgICAgIGlmIChtb2RlID09PSAnYmFycycpIHsKICAgICAgICBjdHguc3Ryb2tlU3R5bGUgPSBoZXgycmdiYShjaHVlLCAoMC4zNCArIChjLnJlYWwgPyAwLjMgOiAwKSkgKiBhbCAqIHBvcCk7CiAgICAgICAgY3R4LmxpbmVXaWR0aCA9IChpc1NlbCA/IDMuNiA6IDIuNikgLyBNYXRoLnNxcnQoWik7CiAgICAgICAgY3R4LmJlZ2luUGF0aCgpOwogICAgICAgIGN0eC5tb3ZlVG8oTWF0aC5jb3MocG9zLmEpICogZy5yMCwgTWF0aC5zaW4ocG9zLmEpICogZy5yMCk7CiAgICAgICAgY3R4LmxpbmVUbyhwb3MueCwgcG9zLnkpOwogICAgICAgIGN0eC5zdHJva2UoKTsKICAgICAgfQogICAgICBjdHguZmlsbFN0eWxlID0gaGV4MnJnYmEoY2h1ZSwgKGMucmVhbCA/IDAuOTIgOiAwLjU1KSAqIGFsICogcG9wKTsKICAgICAgaWYgKGMua2luZCA9PT0gJ2dhdGUnICYmIGMucmVhbCkgewogICAgICAgIGN0eC5iZWdpblBhdGgoKTsKICAgICAgICBjdHgubW92ZVRvKHBvcy54LCBwb3MueSAtIHJyIC0gMSk7IGN0eC5saW5lVG8ocG9zLnggKyByciwgcG9zLnkpOyBjdHgubGluZVRvKHBvcy54LCBwb3MueSArIHJyICsgMSk7IGN0eC5saW5lVG8ocG9zLnggLSByciwgcG9zLnkpOwogICAgICAgIGN0eC5jbG9zZVBhdGgoKTsgY3R4LmZpbGwoKTsKICAgICAgfSBlbHNlIHsKICAgICAgICBjdHguYmVnaW5QYXRoKCk7IGN0eC5hcmMocG9zLngsIHBvcy55LCByciwgMCwgNyk7IGN0eC5maWxsKCk7CiAgICAgIH0KICAgICAgaWYgKGMudmVyc2lvbiA+IDEpIHsKICAgICAgICBjdHguc3Ryb2tlU3R5bGUgPSBoZXgycmdiYShjaHVlLCAwLjggKiBhbCk7CiAgICAgICAgY3R4LmxpbmVXaWR0aCA9IDEgLyBaOwogICAgICAgIGN0eC5iZWdpblBhdGgoKTsgY3R4LmFyYyhwb3MueCwgcG9zLnksIHJyICsgMi41IC8gWiwgMCwgNyk7IGN0eC5zdHJva2UoKTsKICAgICAgfQogICAgICBpZiAoIVJFRFVDRUQgJiYgYWdlIDwgMC44KSB7ICAgICAgICAgICAgICAgICAvKiBiaXJ0aCBoYWxvICovCiAgICAgICAgY3R4LnN0cm9rZVN0eWxlID0gaGV4MnJnYmEoY2h1ZSwgKDEgLSBhZ2UgLyAwLjgpICogMC44KTsKICAgICAgICBjdHgubGluZVdpZHRoID0gMS41IC8gWjsKICAgICAgICBjdHguYmVnaW5QYXRoKCk7IGN0eC5hcmMocG9zLngsIHBvcy55LCByciArIChhZ2UgLyAwLjgpICogMTQsIDAsIDcpOyBjdHguc3Ryb2tlKCk7CiAgICAgIH0KICAgICAgaWYgKGlzU2VsKSB7CiAgICAgICAgY3R4LnN0cm9rZVN0eWxlID0gaGV4MnJnYmEoY2h1ZSwgMC45NSk7CiAgICAgICAgY3R4LmxpbmVXaWR0aCA9IDEuNSAvIFo7CiAgICAgICAgY3R4LmJlZ2luUGF0aCgpOyBjdHguYXJjKHBvcy54LCBwb3MueSwgcnIgKyA0IC8gWiwgMCwgNyk7IGN0eC5zdHJva2UoKTsKICAgICAgfQogICAgICBjLl94ID0gcG9zLng7IGMuX3kgPSBwb3MueTsgYy5fYSA9IHBvcy5hOyBjLl9yID0gcG9zLnI7IGMuX2RyID0gcnI7CiAgICB9CiAgfQoKICAvKiDilIDilIAgbGluZWFnZSBjaG9yZHM6IGEgZGVwZW5kc19vbiBiLCBkcmF3biByaW0g4oaSIHJpbSB0aHJvdWdoIHRoZSBkaXNjLgogICAgIEFsbCBmYWludCB3aGVuIHRoZSBsaW5lYWdlIHRvZ2dsZSBpcyBvbjsgYSBob3ZlcmVkIHNlY3RvcidzIG93biBlZGdlcwogICAgIGFsd2F5cyBsaWdodC4gRG90IG1hcmtzIHRoZSBkZXBlbmRlbmN5ICh0aGUgcGxhbiBiZWluZyBzdG9vZCBvbikuIOKUgOKUgCAqLwogIGlmICghc29sbykgewogICAgZm9yIChjb25zdCBlZCBvZiBERVBfRURHRVMpIHsKICAgICAgY29uc3QgbGl0ID0gaG92ZXJTZWMgPT09IGVkLmEgfHwgaG92ZXJTZWMgPT09IGVkLmI7CiAgICAgIGlmICghc2hvd0xpbmVhZ2UgJiYgIWxpdCkgY29udGludWU7CiAgICAgIGlmICghZWQuYS5sYXkgfHwgIWVkLmIubGF5IHx8IGVkLmEubGF5LmFscGhhIDwgMC4zIHx8IGVkLmIubGF5LmFscGhhIDwgMC4zKSBjb250aW51ZTsKICAgICAgY29uc3QgYW0gPSAoZWQuYS5sYXkuYTAgKyBlZC5hLmxheS5hMSkgLyAyLCBibSA9IChlZC5iLmxheS5hMCArIGVkLmIubGF5LmExKSAvIDI7CiAgICAgIGNvbnN0IHIxID0gZy5SICogMC45NzsKICAgICAgY29uc3QgYXggPSBNYXRoLmNvcyhhbSkgKiByMSwgYXkgPSBNYXRoLnNpbihhbSkgKiByMTsKICAgICAgY29uc3QgYnggPSBNYXRoLmNvcyhibSkgKiByMSwgYnkgPSBNYXRoLnNpbihibSkgKiByMTsKICAgICAgY29uc3QgYWxwaGEyID0gbGl0ID8gMC42NSA6IDAuMTA7CiAgICAgIGN0eC5zdHJva2VTdHlsZSA9IGhleDJyZ2JhKCcjOGI5NmYyJywgYWxwaGEyKTsKICAgICAgY3R4LmxpbmVXaWR0aCA9IChsaXQgPyAxLjYgOiAxLjEpIC8gWjsKICAgICAgY3R4LmJlZ2luUGF0aCgpOwogICAgICBjdHgubW92ZVRvKGF4LCBheSk7CiAgICAgIGN0eC5xdWFkcmF0aWNDdXJ2ZVRvKChheCArIGJ4KSAvIDIgKiAwLjIsIChheSArIGJ5KSAvIDIgKiAwLjIsIGJ4LCBieSk7CiAgICAgIGN0eC5zdHJva2UoKTsKICAgICAgY3R4LmZpbGxTdHlsZSA9IGhleDJyZ2JhKCcjOGI5NmYyJywgTWF0aC5taW4oMSwgYWxwaGEyICogMS42KSk7CiAgICAgIGN0eC5iZWdpblBhdGgoKTsgY3R4LmFyYyhieCwgYnksIChsaXQgPyAzIDogMi4yKSAvIFosIDAsIDcpOyBjdHguZmlsbCgpOwogICAgfQogICAgY3R4LmxpbmVXaWR0aCA9IDEgLyBaOwogIH0KCiAgLyog4pSA4pSAIHNvbG8gZXZlbnQgbGVkZ2VyOiBvbmUgcmluZyBwZXIgZXZlbnQgKGVhcmxpZXN0IG91dGVybW9zdCkuIEVhY2gKICAgICBldmVudCdzIHJpbmcgdHJhY2tzIGFyb3VuZCB0byA5IG8nY2xvY2ssIHRoZW4gc3RhbmRzIHN0cmFpZ2h0IHVwIGFzIGEKICAgICB2ZXJ0aWNhbCBzdGFja2VkIGJhciDigJQgdG9rZW5zIChpbmRpZ28pICsgZmFjdCBraW5kICsgdmVyc2lvbiBjYXAuCiAgICAgU2FtZS1kYXkgZXZlbnRzIGtlZXAgdGhlaXIgZXhhY3QgdGltZSBvcmRlcjogYWRqYWNlbnQgcmluZ3MuIOKUgOKUgCAqLwogIGlmIChzb2xvICYmIHNvbG8ubGF5ICYmIHNvbG8ubGF5LmFscGhhID4gMC41KSB7CiAgICBzb2xvTGFiZWxzID0gW107CiAgICBjb25zdCB1bml0ID0gZy5SIC0gZy5yMDsKICAgIGNvbnN0IEwgPSBzb2xvLmxheTsKICAgIGNvbnN0IGV2cyA9IFsuLi5zb2xvLmNlbGxzXS5zb3J0KChhLCBiKSA9PiBhLmRheSAtIGIuZGF5KQogICAgICAuZmlsdGVyKGMgPT4gYy5kYXkgPD0gVCAmJiBjLmRheSA+PSBTICYmIGMuZGF5IDw9IEUgJiYgcGFzc0ZpbHRlcihjKSk7CiAgICAvKiA5IG8nY2xvY2sgYmFzZWxpbmUgdGhlIGJhcnMgc3RhbmQgb24gKi8KICAgIGN0eC5zdHJva2VTdHlsZSA9ICdyZ2JhKDI1NSwyNTUsMjU1LC4xNiknOwogICAgY3R4LmxpbmVXaWR0aCA9IDEgLyBaOwogICAgY3R4LmJlZ2luUGF0aCgpOyBjdHgubW92ZVRvKC0oZy5SICsgMTApLCAwKTsgY3R4LmxpbmVUbygtZy5yMCAqIDAuNzIsIDApOyBjdHguc3Ryb2tlKCk7CiAgICBmb3IgKGNvbnN0IGMgb2YgZXZzKSB7CiAgICAgIGNvbnN0IHIgPSBzb2xvUmluZ1IoZywgYyk7CiAgICAgIGNvbnN0IGZyYWMgPSBjLm4gPiAxID8gKGMucmFuayArIDAuNSkgLyBjLm4gOiAwLjU7CiAgICAgIGNvbnN0IGFOb2RlID0gTC5hMCArIChMLmExIC0gTC5hMCkgKiAoMC4wNiArIDAuODggKiBmcmFjKTsKICAgICAgY29uc3QgY2h1ZSA9IEtJTkRfSFVFW2Mua2luZF0gfHwgJyM4Yjk2ZjInOwogICAgICBjb25zdCBpc1NlbEJhciA9IHBpbm5lZCA9PT0gYzsKICAgICAgLyogZmFpbnQgZnVsbCByaW5nIGFjcm9zcyB0aGUgc2VjdG9yLCBicmlnaHRlciB0cmFjayBub2RlIOKGkiA5IG8nY2xvY2sgKi8KICAgICAgY3R4LnN0cm9rZVN0eWxlID0gaGV4MnJnYmEoY2h1ZSwgMC4wNyk7CiAgICAgIGN0eC5saW5lV2lkdGggPSAxIC8gWjsKICAgICAgY3R4LmJlZ2luUGF0aCgpOyBjdHguYXJjKDAsIDAsIHIsIEwuYTAsIGFOb2RlKTsgY3R4LnN0cm9rZSgpOwogICAgICBjdHguc3Ryb2tlU3R5bGUgPSBoZXgycmdiYShjaHVlLCBpc1NlbEJhciA/IDAuNzUgOiAwLjMwKTsKICAgICAgY3R4LmxpbmVXaWR0aCA9IChpc1NlbEJhciA/IDIgOiAxLjMpIC8gWjsKICAgICAgY3R4LmJlZ2luUGF0aCgpOyBjdHguYXJjKDAsIDAsIHIsIGFOb2RlLCBNYXRoLlBJKTsgY3R4LnN0cm9rZSgpOwogICAgICAvKiBlbGJvdyBhdCAo4oiSciwgMCk6IHRoZSBiYXIgZ29lcyBzdHJhaWdodCB1cCAqLwogICAgICBsZXQgeTEgPSAwOwogICAgICBjb25zdCBzZWdzID0gWwogICAgICAgIHsgaDogdW5pdCAqICgwLjA2ICsgTWF0aC5taW4oMC4zMCwgKChjLnRva2VucyB8fCAxNjApIC8gNTUwKSAqIDAuMzQpKSwgY29sOiBoZXgycmdiYSgnIzhiOTZmMicsIDAuNTUpIH0sCiAgICAgICAgeyBoOiB1bml0ICogMC4wNTUsIGNvbDogaGV4MnJnYmEoY2h1ZSwgMC45NSkgfSwKICAgICAgXTsKICAgICAgaWYgKGMudmVyc2lvbiA+IDEpIHNlZ3MucHVzaCh7IGg6IHVuaXQgKiAwLjAyMiwgY29sOiAncmdiYSgyMzgsMjQwLDI0NiwuODUpJyB9KTsKICAgICAgZm9yIChjb25zdCBzZyBvZiBzZWdzKSB7CiAgICAgICAgY3R4LnN0cm9rZVN0eWxlID0gc2cuY29sOwogICAgICAgIGN0eC5saW5lV2lkdGggPSAoNSAvIFopICogKGlzU2VsQmFyID8gMS41IDogMSk7CiAgICAgICAgY3R4LmJlZ2luUGF0aCgpOwogICAgICAgIGN0eC5tb3ZlVG8oLXIsIC15MSk7CiAgICAgICAgeTEgKz0gc2cuaDsKICAgICAgICBjdHgubGluZVRvKC1yLCAteTEpOwogICAgICAgIGN0eC5zdHJva2UoKTsKICAgICAgfQogICAgICBjLl9ieCA9IC1yOyBjLl9iaCA9IHkxOwogICAgfQogICAgY3R4LmxpbmVXaWR0aCA9IDEgLyBaOwogICAgLyogZGF0ZSBsYWJlbHMgdW5kZXIgdGhlIGF4aXM6IGZpcnN0IC8gbWlkIC8gbGFzdCB2aXNpYmxlIGV2ZW50ICovCiAgICBjb25zdCBwaWNrcyA9IGV2cy5sZW5ndGggPyBbZXZzWzBdLCBldnNbTWF0aC5mbG9vcigoZXZzLmxlbmd0aCAtIDEpIC8gMildLCBldnNbZXZzLmxlbmd0aCAtIDFdXSA6IFtdOwogICAgY29uc3Qgc2VlbiA9IG5ldyBTZXQoKTsKICAgIGZvciAoY29uc3QgYyBvZiBwaWNrcykgewogICAgICBpZiAoc2Vlbi5oYXMoYy5yYW5rKSkgY29udGludWU7CiAgICAgIHNlZW4uYWRkKGMucmFuayk7CiAgICAgIHNvbG9MYWJlbHMucHVzaCh7IHg6IC1zb2xvUmluZ1IoZywgYyksIHk6IDE2LCB0OiBkYXlEYXRlKGMuZGF5KSB9KTsKICAgIH0KICAgIHNvbG9MYWJlbHMucHVzaCh7IHg6IC0oZy5yMCArIHVuaXQgKiAwLjU1KSwgeTogLSh1bml0ICogMC42MiksIHQ6ICdldmVudCBsZWRnZXIgwrcgb3V0ZXIgcmluZyA9IGZpcnN0IGV2ZW50JywgY2FwOiB0cnVlIH0pOwogIH0KCiAgfSAgLyogZW5kIHdvcmstbGVucyBpbi1mcmFtZSAqLwoKICAvKiBsaXZlIGVkZ2U6IG91dHdhcmQgbW9kZSBzd2VlcHMgd2l0aCBUOyBpbndhcmQgbW9kZSBJUyB0aGUgcmltICovCiAgewogICAgY29uc3QgZXIgPSBkaXIgPT09ICdpbicgPyBnLnIwICsgKGcuUiAtIGcucjApICogMC45NiA6IGRheVIoZywgVCk7CiAgICBpZiAoZGlyID09PSAnaW4nIHx8IFQgPCBFIC0gMC4wMSkgewogICAgICBjb25zdCBncm93ID0gUkVEVUNFRCA/IDAuODYgOiAoMC41NSArIDAuNDUgKiAoKHRpbWUgKiAwLjA2KSAlIDEpKTsKICAgICAgY3R4LnN0cm9rZVN0eWxlID0gJ3JnYmEoMTM5LDE1MCwyNDIsLjcpJzsKICAgICAgY3R4LmxpbmVXaWR0aCA9IDEuNiAvIFo7CiAgICAgIGN0eC5zZXRMaW5lRGFzaChbNSAvIFosIDcgLyBaXSk7CiAgICAgIGN0eC5iZWdpblBhdGgoKTsgY3R4LmFyYygwLCAwLCBlciwgLU1hdGguUEkgLyAyLCAtTWF0aC5QSSAvIDIgKyBUQVUgKiBncm93KTsgY3R4LnN0cm9rZSgpOwogICAgICBjdHguc2V0TGluZURhc2goW10pOwogICAgfQogIH0KCiAgLyogZW50ZXIvZXhpdCBmbGFzaGVzICovCiAgZm9yIChsZXQgaSA9IGZsYXNoZXMubGVuZ3RoIC0gMTsgaSA+PSAwOyBpLS0pIHsKICAgIGNvbnN0IGYgPSBmbGFzaGVzW2ldOwogICAgY29uc3QgayA9ICh0aW1lIC0gZi50MCkgLyAxLjE7CiAgICBpZiAoayA+IDEpIHsgZmxhc2hlcy5zcGxpY2UoaSwgMSk7IGNvbnRpbnVlOyB9CiAgICBpZiAoUkVEVUNFRCkgY29udGludWU7CiAgICBjb25zdCByciA9IGYua2luZCA9PT0gJ2V4aXQnID8gZy5SICogKDEgKyBrICogMC4xNCkgOiBnLlIgKiAoMS4xNCAtIGsgKiAwLjE0KTsKICAgIGN0eC5zdHJva2VTdHlsZSA9IGhleDJyZ2JhKGYuaHVlLCAoMSAtIGspICogMC45KTsKICAgIGN0eC5saW5lV2lkdGggPSAoMi41ICogKDEgLSBrKSArIDAuNSkgLyBaOwogICAgY3R4LmJlZ2luUGF0aCgpOyBjdHguYXJjKDAsIDAsIHJyLCBmLmFuZyAtIDAuMyAqICgxIC0gayAqIDAuNSksIGYuYW5nICsgMC4zICogKDEgLSBrICogMC41KSk7IGN0eC5zdHJva2UoKTsKICB9CiAgY3R4LmxpbmVXaWR0aCA9IDE7CgogIC8qIGhlYXJ0d29vZCAqLwogIGNvbnN0IGdsb3cgPSBjdHguY3JlYXRlUmFkaWFsR3JhZGllbnQoMCwgMCwgMCwgMCwgMCwgZy5yMCAqIDEuNSk7CiAgZ2xvdy5hZGRDb2xvclN0b3AoMCwgJ3JnYmEoMTM5LDE1MCwyNDIsLjUpJyk7CiAgZ2xvdy5hZGRDb2xvclN0b3AoMSwgJ3RyYW5zcGFyZW50Jyk7CiAgY3R4LmZpbGxTdHlsZSA9IGdsb3c7CiAgY3R4LmJlZ2luUGF0aCgpOyBjdHguYXJjKDAsIDAsIGcucjAgKiAxLjUsIDAsIDcpOyBjdHguZmlsbCgpOwogIGN0eC5maWxsU3R5bGUgPSAnIzEyMTUxZCc7CiAgY3R4LmJlZ2luUGF0aCgpOyBjdHguYXJjKDAsIDAsIGcucjAgKiAwLjcsIDAsIDcpOyBjdHguZmlsbCgpOwogIGN0eC5zdHJva2VTdHlsZSA9ICdyZ2JhKDEzOSwxNTAsMjQyLC44NSknOwogIGN0eC5saW5lV2lkdGggPSAxIC8gWjsKICBjdHguYmVnaW5QYXRoKCk7IGN0eC5hcmMoMCwgMCwgZy5yMCAqIDAuNywgMCwgNyk7IGN0eC5zdHJva2UoKTsKICBjdHgucmVzdG9yZSgpOwoKICAvKiDilZDilZAgc2NyZWVuIHNwYWNlIOKVkOKVkCAqLwogIGNvbnN0IG5BY3QgPSBhY3RpdmVQbGFucyhUKS5sZW5ndGg7CiAgY3R4LmZpbGxTdHlsZSA9ICdyZ2JhKDIzOCwyNDAsMjQ2LC45NSknOwogIGN0eC5mb250ID0gJzYwMCAxMC41cHggJyArIE1PTk87CiAgY3R4LnRleHRBbGlnbiA9ICdjZW50ZXInOyBjdHgudGV4dEJhc2VsaW5lID0gJ21pZGRsZSc7CiAgY29uc3QgY29yZSA9IHRvU2NyZWVuKGcsIDAsIDApOwogIGN0eC5maWxsVGV4dCgnY3J1eCcsIGNvcmUueCwgY29yZS55IC0gNik7CiAgY3R4LmZpbGxTdHlsZSA9ICdyZ2JhKDEyNiwxMzMsMTQ5LC45KSc7CiAgY3R4LmZvbnQgPSAnOC41cHggJyArIE1PTk87CiAgY3R4LmZpbGxUZXh0KGxlbnMgPT09ICd3b3JrJyA/IG5BY3QgKyAoc2hvd0FsbCA/ICcgcGxhbnMnIDogJyBsaXZlJykgOiBsZW5zLCBjb3JlLngsIGNvcmUueSArIDcpOwogIGN0eC50ZXh0QWxpZ24gPSAnbGVmdCc7IGN0eC50ZXh0QmFzZWxpbmUgPSAnYWxwaGFiZXRpYyc7CgogIC8qIGNvcm5lciBzdGF0dXMgKi8KICBjdHguZmlsbFN0eWxlID0gJ3JnYmEoMTI2LDEzMywxNDksLjgpJzsKICBjdHguZm9udCA9ICc5LjVweCAnICsgTU9OTzsKICBjdHguZmlsbFRleHQoZGF5RGF0ZShTKSArICcg4oaSICcgKyBkYXlEYXRlKEUpICsgJyDCtyBUID0gJyArIGRheURhdGUoVCkgKyAnIMK3ICcgKyBuQWN0ICsgJyBsaXZlIMK3IHpvb20gJyArIFoudG9GaXhlZCgxKSArICfDlycKICAgICsgKFJBRF9MTyA+IFMgKyAwLjUgPyAnIMK3IHJpbmdzIGZyb20gJyArIGRheURhdGUoUkFEX0xPKSA6ICcnKSArICcgwrcgJyArIGRhdGFTcmMsIDE4LCAyNCk7CgogIC8qIHNvbG86IGxlZGdlciBsYWJlbHMgKyB0aGUgc2VhbSdzIG1pbuKGkm1heCByYW5nZSBmb3IgVEhJUyBwbGFuICovCiAgaWYgKHNvbG9MYWJlbHMpIHsKICAgIGN0eC5mb250ID0gJzlweCAnICsgTU9OTzsKICAgIGN0eC50ZXh0QWxpZ24gPSAnY2VudGVyJzsKICAgIGZvciAoY29uc3QgTDIgb2Ygc29sb0xhYmVscykgewogICAgICBjb25zdCBzcCA9IHRvU2NyZWVuKGcsIEwyLngsIEwyLnkpOwogICAgICBjdHguZmlsbFN0eWxlID0gTDIuY2FwID8gJ3JnYmEoMTgyLDE4OCwyMDEsLjkpJyA6ICdyZ2JhKDEyNiwxMzMsMTQ5LC44NSknOwogICAgICBjdHguZmlsbFRleHQoTDIudCwgc3AueCwgc3AueSk7CiAgICB9CiAgICBjb25zdCB0aXAyID0gdG9TY3JlZW4oZywgMCwgLShnLlIgKyAyNCkpOwogICAgY3R4LmZpbGxTdHlsZSA9ICdyZ2JhKDIzOCwyNDAsMjQ2LC45MiknOwogICAgY3R4LmZvbnQgPSAnNzAwIDEwcHggJyArIE1PTk87CiAgICBjdHguZmlsbFRleHQoZGF5RGF0ZShzb2xvLmIpICsgJyDihpIgJyArIGRheURhdGUoc29sby5lKSwgdGlwMi54LCB0aXAyLnkpOwogICAgY3R4LnRleHRBbGlnbiA9ICdsZWZ0JzsKICB9CgogIC8qIGxlbnMgY2FwdGlvbnMgKHNjcmVlbiBzcGFjZSkgKi8KICBpZiAobGVuc0xhYmVscy5sZW5ndGgpIHsKICAgIGN0eC5mb250ID0gJzkuNXB4ICcgKyBNT05POwogICAgY3R4LnRleHRBbGlnbiA9ICdjZW50ZXInOwogICAgZm9yIChjb25zdCBMMiBvZiBsZW5zTGFiZWxzKSB7CiAgICAgIGNvbnN0IHNwID0gdG9TY3JlZW4oZywgTDIueCwgTDIueSk7CiAgICAgIGN0eC5zYXZlKCk7CiAgICAgIGlmIChMMi5yb3QgIT09IHVuZGVmaW5lZCkgeyBjdHgudHJhbnNsYXRlKHNwLngsIHNwLnkpOyBjdHgucm90YXRlKEwyLnJvdCArIHJvdCk7IGN0eC50cmFuc2xhdGUoLXNwLngsIC1zcC55KTsgfQogICAgICBjdHguZmlsbFN0eWxlID0gTDIuY2FwID8gJ3JnYmEoMTgyLDE4OCwyMDEsLjkpJyA6ICdyZ2JhKDIwMCwyMDYsMjE5LC45NSknOwogICAgICBpZiAoIUwyLmNhcCkgY3R4LmZvbnQgPSAnNzAwIDExcHggJyArIE1PTk87CiAgICAgIGN0eC5maWxsVGV4dChMMi50LCBzcC54LCBzcC55KTsKICAgICAgY3R4LnJlc3RvcmUoKTsKICAgICAgY3R4LmZvbnQgPSAnOS41cHggJyArIE1PTk87CiAgICB9CiAgICBjdHgudGV4dEFsaWduID0gJ2xlZnQnOwogIH0KCiAgLyogY29tcGxldGVkIGxlZGdlciDigJQgcGxhbnMgcmV0aXJlIG9mZiB0aGUgY2xvY2sgaW50byB0aGUgbGVmdCBlZGdlLgogICAgIFJvd3MgYXJlIGNsaWNrYWJsZTogZmlsdGVyIHRoZSByaW5nIGRvd24gdG8gdGhhdCBvbmUgcGxhbi4KICAgICBIaWRkZW4gYnkgZGVmYXVsdDsg4omhIHRvZ2dsZXMsIHBsYXliYWNrIGF1dG8tc2hvd3MsIGxlbnMgc3dhcCBoaWRlcy4gKi8KICBsZWRnZXJSb3dzID0gW107CiAgaWYgKGxlbnMgPT09ICd3b3JrJyAmJiBzaG93TGVkZ2VyKSB7CiAgICBjb25zdCBkb25lTGlzdCA9IFBMQU5TCiAgICAgIC5maWx0ZXIocCA9PiBwLnN0ID09PSAwICYmIHAuZXhpdCA8PSBUICYmIHAuYiA8PSBFICYmIHAuZSA+PSBTIC0gMC4wMDEpCiAgICAgIC5zb3J0KChhLCBiKSA9PiBiLmV4aXQgLSBhLmV4aXQpOwogICAgY3R4LmZvbnQgPSAnNzAwIDExcHggJyArIE1PTk87CiAgICBjdHguZmlsbFN0eWxlID0gJ3JnYmEoNDUsMjEyLDE5MSwuOSknOwogICAgY3R4LmZpbGxUZXh0KCdjb21wbGV0ZWQgwrcgJyArIGRvbmVMaXN0Lmxlbmd0aCArIChzb2xvID8gJyAgKGZpbHRlcmluZyDigJQgY2xpY2sgcm93IGFnYWluIG9yIGJhY2tncm91bmQgdG8gY2xlYXIpJyA6ICcnKSwgMTgsIDUyKTsKICAgIGN0eC5mb250ID0gJzkuNXB4ICcgKyBNT05POwogICAgY29uc3QgbWF4Um93cyA9IE1hdGguZmxvb3IoKEggLSAxNDApIC8gMTYpOwogICAgZG9uZUxpc3Quc2xpY2UoMCwgbWF4Um93cykuZm9yRWFjaCgocCwgaykgPT4gewogICAgICBjb25zdCBmcmVzaCA9IFQgLSBwLmV4aXQgPCAyLjA7CiAgICAgIGNvbnN0IGlzU29sbyA9IHNvbG8gPT09IHA7CiAgICAgIGNvbnN0IHkgPSA3MCArIGsgKiAxNjsKICAgICAgaWYgKGlzU29sbykgewogICAgICAgIGN0eC5maWxsU3R5bGUgPSAncmdiYSgxMzksMTUwLDI0MiwuMTYpJzsKICAgICAgICBjdHguZmlsbFJlY3QoMTIsIHkgLSAxMSwgMjE4LCAxNSk7CiAgICAgIH0KICAgICAgY3R4LmZpbGxTdHlsZSA9IGZyZXNoIHx8IGlzU29sbyA/ICdyZ2JhKDQ1LDIxMiwxOTEsLjk1KScgOiAncmdiYSgxMjYsMTMzLDE0OSwuNzUpJzsKICAgICAgY3R4LmZpbGxUZXh0KCfinJMnLCAxOCwgeSk7CiAgICAgIGN0eC5maWxsU3R5bGUgPSBpc1NvbG8gPyAncmdiYSgyMzgsMjQwLDI0NiwxKScgOiBmcmVzaCA/ICdyZ2JhKDIzOCwyNDAsMjQ2LC45NSknIDogJ3JnYmEoMTI2LDEzMywxNDksLjgpJzsKICAgICAgY29uc3QgbGJsID0gcC5zaG9ydC5sZW5ndGggPiAyNiA/IHAuc2hvcnQuc2xpY2UoMCwgMjUpICsgJ+KApicgOiBwLnNob3J0OwogICAgICBjdHguZmlsbFRleHQobGJsLCAzMiwgeSk7CiAgICAgIGN0eC5maWxsU3R5bGUgPSAncmdiYSgxMjYsMTMzLDE0OSwuNTUpJzsKICAgICAgY3R4LmZpbGxUZXh0KGRheURhdGUocC5leGl0KS5zbGljZSg1KSwgMzIgKyAyNyAqIDYuMCwgeSk7CiAgICAgIGxlZGdlclJvd3MucHVzaCh7IHg6IDEyLCB5OiB5IC0gMTEsIHc6IDIxOCwgaDogMTUsIHAgfSk7CiAgICB9KTsKICAgIGlmIChkb25lTGlzdC5sZW5ndGggPiBtYXhSb3dzKSB7CiAgICAgIGN0eC5maWxsU3R5bGUgPSAncmdiYSgxMjYsMTMzLDE0OSwuNiknOwogICAgICBjdHguZmlsbFRleHQoJ+KApiArJyArIChkb25lTGlzdC5sZW5ndGggLSBtYXhSb3dzKSArICcgbW9yZScsIDE4LCA3MCArIG1heFJvd3MgKiAxNik7CiAgICB9CiAgfQoKICByYWZJZCA9IG51bGw7CiAgaWYgKHZpc2libGUgJiYgIWRvY3VtZW50LmhpZGRlbikgcmFmSWQgPSByZXF1ZXN0QW5pbWF0aW9uRnJhbWUoZHJhdyk7Cn0KCi8qIOKUgOKUgCBkYXRhIGdyYXBoIGxlbnM6IDY2IHJlYWwgZmFjdHMgcHVsbGVkIGxpdmUgZnJvbSB0aGUgZGFlbW9uLgogICBBbmdsZSA9IHNvdXJjZSBkYXRlIG9uIHRoZSBjbG9jayDCtyByYWRpdXMgPSBlZmZlY3RpdmUgY29uZmlkZW5jZQogICAoaGlnaCBuZWFyIHRoZSBoZWFydHdvb2QsIGRlY2F5ZWQvbG93IGZ1cnRoZXIgb3V0KSDCtyBlZGdlcyA9IGZhY3RzCiAgIHNoYXJpbmcgYW4gZW50aXR5LCBpbiB0aW1lIG9yZGVyIMK3IGNsaWNrID0gMi1ob3AgbmVpZ2hib3VyaG9vZC4g4pSA4pSAICovCmNvbnN0IEdSQVBIX1JBVyA9IFt7ImUiOiJleGVjcGxhbjpjcm9zcy1zaXRlLWF1dGgtc3NvLWN1ZWNydXgtMjAyNi0wNy0xMyIsImsiOiJnYXRlOk0xLVItY29kZSIsImQiOjc1LjU5Njk2NzU5MjU5MTY4LCJhIjoiY2xhdWRlLXdvcmsiLCJoIjoibWVkaXVtIiwiYyI6MS4wLCJ0IjoxMjd9LHsiZSI6ImV4ZWNwbGFuOnZlcmlmaWFibGUtcmVjb3JkLXByb2R1Y3RzLTIwMjYtMDctMTciLCJrIjoiZ2F0ZTpNMy1jb3JlLXBvaW50ZXItcHJvZHVjZXItY29kZS0yMDI2LTA3LTIyIiwiZCI6NzYuNzU4NjU3NDA3NDA4NDYsImEiOiJjbGF1ZGUtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjE1OH0seyJlIjoiZXhlY3BsYW46Y3J1eC1kYWVtb24tYnV5ZXItZml0LWJ1aWxkb3V0LTIwMjYtMDctMTMiLCJrIjoiZ2F0ZTpNMyIsImQiOjY4Ljk1MDcyOTE2NjY2Njg2LCJhIjoiY29kZXgtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjMxNn0seyJlIjoiaW5jaWRlbnQ6MjAyNi0wNy0yMiIsImsiOiJncHUxLWNhcmdvLWRlcGxveS1oZWxwLXNpZGUtZWZmZWN0IiwiZCI6NzYuNDMwMjg5MzUxODUwNjYsImEiOiJjbGF1ZGUtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjI5MX0seyJlIjoiZXhlY3BsYW46Y3Jvc3Mtc2l0ZS1hdXRoLXNzby1jdWVjcnV4LTIwMjYtMDctMTMiLCJrIjoiZGVjaXNpb246dmF1bHQtdGFyZ2V0LXJlZ3Jlc3Npb24tcmVwYWlyIiwiZCI6NzUuNTk2OTY3NTkyNTkxNjgsImEiOiJjbGF1ZGUtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjE1NX0seyJlIjoiZXhlY3BsYW46Y3J1eC1kYWVtb24tYnV5ZXItZml0LWJ1aWxkb3V0LTIwMjYtMDctMTMiLCJrIjoicHJvZ3Jlc3M6TTMiLCJkIjo2OC45MDk3MTA2NDgxNDk0OCwiYSI6ImNvZGV4LXdvcmsiLCJoIjoidm9sYXRpbGUiLCJjIjoxLjAsInQiOjI3NH0seyJlIjoiZXhlY3BsYW46cHJvZHVjdGlvbi1ldGhvcy1hdWRpdC1oYXJuZXNzLTIwMjYtMDctMTciLCJrIjoiZ2F0ZTpNNSIsImQiOjc0LjYwNTg5MTIwMzcwNDIzLCJhIjoiY29kZXgtd29yayIsImgiOiJ2b2xhdGlsZSIsImMiOjEuMCwidCI6MzIzfSx7ImUiOiJleGVjcGxhbjpjcm9zcy1zaXRlLWF1dGgtc3NvLWN1ZWNydXgtMjAyNi0wNy0xMyIsImsiOiJnYXRlOk0xIiwiZCI6NjguMzgxNTc0MDc0MDc1NjIsImEiOiJjb2RleC13b3JrIiwiaCI6Im1lZGl1bSIsImMiOjEuMCwidCI6Mjk2fSx7ImUiOiJleGVjcGxhbjp3aWtpY3J1eC1wdWJsaWMtcmVhZGluZXNzLWhhcmRlbmluZy0yMDI2LTA3LTIxIiwiayI6ImdhdGU6TTNiLWJsb2NrZWQiLCJkIjo3NS44Mjc3MzE0ODE0ODA0NCwiYSI6ImRyaXZldy1ob3N0IiwiaCI6InN0YWJsZSIsImMiOjEuMCwidCI6MjIxfSx7ImUiOiJleGVjcGxhbjpjcnV4LWRhZW1vbi1idXllci1maXQtYnVpbGRvdXQtMjAyNi0wNy0xMyIsImsiOiJkZWNpc2lvbjptNWItaW5zdGFsbGVyLXRyYW5zYWN0aW9uIiwiZCI6NzYuMzY3ODkzNTE4NTE5ODUsImEiOiJjbGF1ZGUtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjIzMn0seyJlIjoiaW5jaWRlbnQ6MjAyNi0wNy0yMiIsImsiOiJjcmMtdjEtcmVzaWRlbnQtb3JkaW5hbC1oYW5kbGUtYWxpYXMiLCJkIjo3Ni40Nzk2MDY0ODE0OCwiYSI6ImNsYXVkZS13b3JrIiwiaCI6InN0YWJsZSIsImMiOjEuMCwidCI6MTg1fSx7ImUiOiJleGVjcGxhbjp2ZXJpZmlhYmxlLXJlY29yZC1wcm9kdWN0cy0yMDI2LTA3LTE3IiwiayI6ImdhdGU6TTktZXZpZGVuY2UtcHVibGljYXRpb24iLCJkIjo3Ni42NzExNTc0MDc0MDcwMSwiYSI6ImNsYXVkZS13b3JrIiwiaCI6InN0YWJsZSIsImMiOjEuMCwidCI6MTI1fSx7ImUiOiJleGVjcGxhbjpjcm9zcy1zaXRlLWF1dGgtc3NvLWN1ZWNydXgtMjAyNi0wNy0xMyIsImsiOiJicmllZiIsImQiOjY3LjkyMDY4Mjg3MDM3MTgyLCJhIjoiY29kZXgtd29yayIsImgiOiJtZWRpdW0iLCJjIjoxLjAsInQiOjIwNX0seyJlIjoiZXhlY3BsYW46d2lraWNydXgtbTUtcHJpY2luZy1lbmZvcmNlbWVudC0yMDI2LTA3LTE3IiwiayI6ImRlY2lzaW9uOm0zYi1yZWZ1bmQtY29udHJhY3QtcGFyaXR5IiwiZCI6NzYuMDI1MzQ3MjIyMjIxMTcsImEiOiJjbGF1ZGUtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjE1M30seyJlIjoiZXhlY3BsYW46dmVyaWZpYWJsZS1yZWNvcmQtcHJvZHVjdHMtMjAyNi0wNy0xNyIsImsiOiJnYXRlOk0zLWVuZ2luZS1jb25zdW1lci1kZXBsb3ktMjAyNi0wNy0yMiIsImQiOjc2LjczOTU3MTc1OTI1ODk4LCJhIjoiY2xhdWRlLXdvcmsiLCJoIjoic3RhYmxlIiwiYyI6MS4wLCJ0IjoyMjN9LHsiZSI6ImV4ZWNwbGFuOmNyb3NzLXNpdGUtYXV0aC1zc28tY3VlY3J1eC0yMDI2LTA3LTEzIiwiayI6ImdhdGU6TTAiLCJkIjo2Ny45MzU4NjgwNTU1NTYwNiwiYSI6ImNvZGV4LXdvcmsiLCJoIjoibWVkaXVtIiwiYyI6MS4wLCJ0IjoyMDV9LHsiZSI6ImV4ZWNwbGFuOmNydXgtbWFjYXJvb24tdG9rZW4tYXR0ZW51YXRpb24tMjAyNi0wNy0xNiIsImsiOiJkZXNpZ246c3luYy1kZWxlZ2F0aW9uLWNvbnZlbnRpb24iLCJkIjo3Ni40OTc5NzQ1MzcwMzY1LCJhIjoiY29kZXgtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjQwOH0seyJlIjoiZXhlY3BsYW46Y3J1eC1tYWNhcm9vbi10b2tlbi1hdHRlbnVhdGlvbi0yMDI2LTA3LTE2IiwiayI6ImdhdGU6TTJwcmltZS1ob3RmaXgtcmV2aWV3ZWQtYW5kLXJlY29uY2lsaWF0aW9uLXBsYW4iLCJkIjo3Ni40MTgxMzY1NzQwNzMyOSwiYSI6ImNvZGV4LXdvcmsiLCJoIjoic3RhYmxlIiwiYyI6MS4wLCJ0Ijo3NDN9LHsiZSI6ImV4ZWNwbGFuOndpa2ljcnV4LW1hcmtldC13ZWRnZS1vZmZlcnMtMjAyNi0wNy0xNiIsImsiOiJkZWNpc2lvbjpjYW5vbmljYWwtcHJpY2luZyIsImQiOjc1LjgyMjI1Njk0NDQ0NDIzLCJhIjoiY2xhdWRlLXdvcmsiLCJoIjoic3RhYmxlIiwiYyI6MS4wLCJ0IjoxNDZ9LHsiZSI6ImV4ZWNwbGFuOndpa2ljcnV4LW01LXByaWNpbmctZW5mb3JjZW1lbnQtMjAyNi0wNy0xNyIsImsiOiJnYXRlOk0zYiIsImQiOjc2LjAyNTM0NzIyMjIyMTE3LCJhIjoiY2xhdWRlLXdvcmsiLCJoIjoic3RhYmxlIiwiYyI6MS4wLCJ0IjoyMjN9LHsiZSI6ImV4ZWNwbGFuOnZlcmlmaWFibGUtcmVjb3JkLXByb2R1Y3RzLTIwMjYtMDctMTciLCJrIjoiZ2F0ZTpNMyIsImQiOjc2Ljc0Njg1MTg1MTg1MDgsImEiOiJjbGF1ZGUtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjE1MH0seyJlIjoiZXhlY3BsYW46Y3VlY3J1eC1zZWxmc2VydmUtbGF1bmNoLXJlYWRpbmVzcy0yMDI2LTA3LTE2IiwiayI6ImdhdGU6TTgtZWRnZS1yZXBhaXIiLCJkIjo3Ni41NDgwMDkyNTkyNTg4MywiYSI6ImNsYXVkZS13b3JrIiwiaCI6Im5vbmUiLCJjIjoxLjAsInQiOjI1NH0seyJlIjoiYmVuY2g6cHJvdmVuYW5jZS1ieW9rLWxvY2FsLTIwMjYwNzIxVDE3NDc1MVotOGU3MTExNTAiLCJrIjoicmVzdWx0IiwiZCI6NzUuNzQzNjkyMTI5NjI4NDcsImEiOiJjbGF1ZGUtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjE0NX0seyJlIjoiZXhlY3BsYW46Y3Jvc3Mtc2l0ZS1hdXRoLXNzby1jdWVjcnV4LTIwMjYtMDctMTMiLCJrIjoiZ2F0ZTpNMy1NNCIsImQiOjY4LjgyOTc0NTM3MDM3MDgsImEiOiJjb2RleC13b3JrIiwiaCI6Im1lZGl1bSIsImMiOjEuMCwidCI6MzI4fSx7ImUiOiJleGVjcGxhbjpjcm9zcy1zaXRlLWF1dGgtc3NvLWN1ZWNydXgtMjAyNi0wNy0xMyIsImsiOiJjb25zb2xlLXYxLXJlbW92ZWQtZm9sbG93dXAtZG9uZSIsImQiOjY5Ljg5MTU5NzIyMjIyMzk0LCJhIjoiY29kZXgtd29yayIsImgiOiJtZWRpdW0iLCJjIjoxLjAsInQiOjMyOX0seyJlIjoiZXhlY3BsYW46Y3Jvc3Mtc2l0ZS1hdXRoLXNzby1jdWVjcnV4LTIwMjYtMDctMTMiLCJrIjoiZ2F0ZTpNMiIsImQiOjY4LjY0ODgxOTQ0NDQ0Mjc4LCJhIjoiY29kZXgtd29yayIsImgiOiJtZWRpdW0iLCJjIjoxLjAsInQiOjIzNn0seyJlIjoiZXhlY3BsYW46Y3J1eC1tYWNhcm9vbi10b2tlbi1hdHRlbnVhdGlvbi0yMDI2LTA3LTE2IiwiayI6ImRlc2lnbjpNM3ByaW1lLXN5bmMtZW5mb3JjZW1lbnQtb24tdjExIiwiZCI6NzYuNDM1Mjc3Nzc3Nzc4NTQsImEiOiJjb2RleC13b3JrIiwiaCI6InN0YWJsZSIsImMiOjEuMCwidCI6ODcwfSx7ImUiOiJpbmNpZGVudDoyMDI2LTA3LTIyIiwiayI6InJlbGVhc2UtdjAuNS40OC1tYWNvcy1zb2NrZXQtZml4dHVyZSIsImQiOjc2LjU2NjEyMjY4NTE4NDM4LCJhIjoiY2xhdWRlLXdvcmsiLCJoIjoic3RhYmxlIiwiYyI6MS4wLCJ0IjoxNDd9LHsiZSI6ImV4ZWNwbGFuOndpa2ljcnV4LXB1YmxpYy1yZWFkaW5lc3MtaGFyZGVuaW5nLTIwMjYtMDctMjEiLCJrIjoiZ2F0ZTpNM2IiLCJkIjo3NS44NDI2MDQxNjY2NjgwMiwiYSI6ImRyaXZldy1ob3N0IiwiaCI6InN0YWJsZSIsImMiOjEuMCwidCI6Mjg3fSx7ImUiOiJleGVjcGxhbjp3aWtpY3J1eC1tYXJrZXQtd2VkZ2Utb2ZmZXJzLTIwMjYtMDctMTYiLCJrIjoiZ2F0ZTpNMCIsImQiOjc1LjgyMjI1Njk0NDQ0NDIzLCJhIjoiY2xhdWRlLXdvcmsiLCJoIjoic3RhYmxlIiwiYyI6MS4wLCJ0Ijo3NH0seyJlIjoiZXhlY3BsYW46Y29yZWNydXgtb2JqZWN0LXN0b3JhZ2UtdGllci0yMDI2LTA3LTA3IiwiayI6ImdhdGU6RzMtY29kZS1tZXJnZSIsImQiOjc2LjYzMTAwNjk0NDQ0NDM4LCJhIjoiY2xhdWRlLXdvcmsiLCJoIjoic3RhYmxlIiwiYyI6MS4wLCJ0IjoxMjV9LHsiZSI6ImV4ZWNwbGFuOmNydXgtZGFlbW9uLWJ1eWVyLWZpdC1idWlsZG91dC0yMDI2LTA3LTEzIiwiayI6ImdhdGU6TTEiLCJkIjo2OC42Njk4OTU4MzMzMzI3LCJhIjoiY29kZXgtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjUzNn0seyJlIjoiZXhlY3BsYW46d2lraWNydXgtbTUtcHJpY2luZy1lbmZvcmNlbWVudC0yMDI2LTA3LTE3IiwiayI6ImdhdGU6TTVhIiwiZCI6NzUuNzk1MTA0MTY2NjY3NDQsImEiOiJjbGF1ZGUtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjIzMH0seyJlIjoiZXhlY3BsYW46Y3Jvc3Mtc2l0ZS1hdXRoLXNzby1jdWVjcnV4LTIwMjYtMDctMTMiLCJrIjoiZGVjaXNpb246dG9wb2xvZ3ktY29ycmVjdGVkLWNydXhlbmdpbmUtMTQzNDMiLCJkIjo2Ny45NDgwNzg3MDM3MDI3OCwiYSI6ImNvZGV4LXdvcmsiLCJoIjoibWVkaXVtIiwiYyI6MS4wLCJ0IjoyMDd9LHsiZSI6ImluY2lkZW50OjIwMjYtMDctMjIiLCJrIjoicGFzc3BvcnQtbWludC1wcmUtbTItYXBwcm92YWwtbGl2ZSIsImQiOjc2Ljc1MDY0ODE0ODE0Njg3LCJhIjoiY2xhdWRlLXdvcmsiLCJoIjoic3RhYmxlIiwiYyI6MS4wLCJ0IjoyMDN9LHsiZSI6ImluY2lkZW50OjIwMjYtMDctMjIiLCJrIjoiY29yZS1zaWRlY2FyLXNuYXBzaG90LXBhdGgiLCJkIjo3Ni44MTAwNjk0NDQ0NDM4LCJhIjoiY2xhdWRlLXdvcmsiLCJoIjoic3RhYmxlIiwiYyI6MS4wLCJ0IjoxNzJ9LHsiZSI6ImV4ZWNwbGFuOmNydXgtZGFlbW9uLWJ1eWVyLWZpdC1idWlsZG91dC0yMDI2LTA3LTEzIiwiayI6ImdhdGU6TTViIiwiZCI6NzYuMzY3ODkzNTE4NTE5ODUsImEiOiJjbGF1ZGUtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjE4NH0seyJlIjoiZXhlY3BsYW46Y3J1eC1kYWVtb24tYnV5ZXItZml0LWJ1aWxkb3V0LTIwMjYtMDctMTMiLCJrIjoiaGFuZG9mZjoyMDI2LTA3LTE0IiwiZCI6NjguODgyMTc1OTI1OTI2MjgsImEiOiJjb2RleC13b3JrIiwiaCI6InN0YWJsZSIsImMiOjEuMCwidCI6NDA5fSx7ImUiOiJleGVjcGxhbjpjcm9zcy1zaXRlLWF1dGgtc3NvLWN1ZWNydXgtMjAyNi0wNy0xMyIsImsiOiJtaWxlc3RvbmU6TTEtcGFydGlhbCIsImQiOjY3Ljk5MDcyOTE2NjY2NzczLCJhIjoiY29kZXgtd29yayIsImgiOiJtZWRpdW0iLCJjIjoxLjAsInQiOjI3NX0seyJlIjoiZXhlY3BsYW46Y3J1eC1tYWNhcm9vbi10b2tlbi1hdHRlbnVhdGlvbi0yMDI2LTA3LTE2IiwiayI6ImdhdGU6TTItcnVzdGRvYy1maXgtYW5kLU0zLWdyb3VuZGluZyIsImQiOjc1LjgyOTg4NDI1OTI1OTQyLCJhIjoiY29kZXgtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjczMn0seyJlIjoiZXhlY3BsYW46c2RrY3J1eC1kZXBlbmRlbmN5LXZ1bG4tcmVtZWRpYXRpb24tMjAyNi0wNy0yMCIsImsiOiJhdWRpdC1zbmFwc2hvdCIsImQiOjc0LjU2MTkzMjg3MDM2ODc2LCJhIjoiY29kZXgtd29yayIsImgiOiJ2b2xhdGlsZSIsImMiOjEuMCwidCI6NDE1fSx7ImUiOiJleGVjcGxhbjpjcnV4LWRhZW1vbi1idXllci1maXQtYnVpbGRvdXQtMjAyNi0wNy0xMyIsImsiOiJnYXRlOk0wIiwiZCI6NjguMzU2NTc0MDc0MDc0MTYsImEiOiJjb2RleC13b3JrIiwiaCI6InN0YWJsZSIsImMiOjEuMCwidCI6NDEyfSx7ImUiOiJleGVjcGxhbjpjcnV4LXBhc3Nwb3J0LW1pbnQtcmVxdWVzdC1nYXRlLTIwMjYtMDctMTciLCJrIjoiZ2F0ZTpNMi4xLWludGVncmF0aW9uIiwiZCI6NzYuNjUwMzI0MDc0MDc0ODksImEiOiJjbGF1ZGUtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjIwN30seyJlIjoiZXhlY3BsYW46Y3VlY3J1eC1zZWxmc2VydmUtbGF1bmNoLXJlYWRpbmVzcy0yMDI2LTA3LTE2IiwiayI6ImRlY2lzaW9uOmVkZ2UtY3V0b3Zlci1nYXRlIiwiZCI6NzYuNTQzNDk1MzcwMzY5NzgsImEiOiJjbGF1ZGUtd29yayIsImgiOiJub25lIiwiYyI6MS4wLCJ0IjoxNjd9LHsiZSI6ImluY2lkZW50OjIwMjYtMDctMjAiLCJrIjoic2RrY3J1eC1jaS1ydW5uZXItbW92ZS1hbmQtc3RhY2tlZC1mYWlsdXJlcyIsImQiOjc0LjU0NzY3MzYxMTExMjI2LCJhIjoiY29kZXgtd29yayIsImgiOiJ2b2xhdGlsZSIsImMiOjEuMCwidCI6NTY0fSx7ImUiOiJleGVjcGxhbjpwcm9kdWN0aW9uLWV0aG9zLWF1ZGl0LWhhcm5lc3MtMjAyNi0wNy0xNyIsImsiOiJnYXRlOk03IiwiZCI6NzUuNjEyNjE1NzQwNzQxNiwiYSI6ImNsYXVkZS13b3JrIiwiaCI6InN0YWJsZSIsImMiOjEuMCwidCI6MTE2fSx7ImUiOiJleGVjcGxhbjpjcnV4LWRhZW1vbi1idXllci1maXQtYnVpbGRvdXQtMjAyNi0wNy0xMyIsImsiOiJnYXRlOk0yIiwiZCI6NjguODQ2NzU5MjU5MjYwNTgsImEiOiJjb2RleC13b3JrIiwiaCI6InN0YWJsZSIsImMiOjEuMCwidCI6NDYzfSx7ImUiOiJleGVjcGxhbjpjcnV4LWJhbm5lci1yZWRlc2lnbi0yMDI2LTA3LTIxIiwiayI6ImdhdGU6ZGVwbG95LXYwLjUuNDciLCJkIjo3Ni4zOTUxMDQxNjY2NjU5OSwiYSI6ImNvZGV4LXdvcmsiLCJoIjoidm9sYXRpbGUiLCJjIjoxLjAsInQiOjIxNn0seyJlIjoiZXhlY3BsYW46d2lraWNydXgtbWFya2V0LXdlZGdlLW9mZmVycy0yMDI2LTA3LTE2IiwiayI6ImdhdGU6TTEiLCJkIjo3NS44MjIyNTY5NDQ0NDQyMywiYSI6ImNsYXVkZS13b3JrIiwiaCI6Im1lZGl1bSIsImMiOjEuMCwidCI6MTYyfSx7ImUiOiJleGVjcGxhbjp2ZXJpZmlhYmxlLXJlY29yZC1wcm9kdWN0cy0yMDI2LTA3LTE3IiwiayI6ImdhdGU6TTMtZGVwbG95LWF1dG9tYXRpb24tMjAyNi0wNy0yMiIsImQiOjc2Ljc1Njk1NjAxODUxODQsImEiOiJjbGF1ZGUtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjE3NX0seyJlIjoiZXhlY3BsYW46Y3J1eC1tYWNhcm9vbi10b2tlbi1hdHRlbnVhdGlvbi0yMDI2LTA3LTE2IiwiayI6ImluY2lkZW50Ok0zLU00LWNvbGxpc2lvbi13aXRoLWNvbmN1cnJlbnQtc2VjdXJpdHktaG90Zml4IiwiZCI6NzUuOTI3NjM4ODg4ODkwMjEsImEiOiJjb2RleC13b3JrIiwiaCI6InN0YWJsZSIsImMiOjEuMCwidCI6ODIyfSx7ImUiOiJleGVjcGxhbjpjcnV4LW1hY2Fyb29uLXRva2VuLWF0dGVudWF0aW9uLTIwMjYtMDctMTYiLCJrIjoiZ2F0ZTpNM3ByaW1lLXN5bmMtZGVsZWdhdGlvbiIsImQiOjc2LjYxNTgzMzMzMzMzMzI4LCJhIjoiY29kZXgtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjYzOH0seyJlIjoiX193b3JrX2NvbW1lbnRfXzo6d181MTc1MjY0N2NhNmU0YmRiYmU0YzNiNDVkMzAyNDFjOTo6Y185YTcyODVjYmY2NjA0MTUyYmU5NjRlODFkN2RlMDM2NyIsImsiOiJyZWNvcmQiLCJkIjo3Ni43MzkyMDEzODg4ODkzNCwiYSI6bnVsbCwiaCI6Im5vbmUiLCJjIjoxLjAsInQiOjE3M30seyJlIjoiZXhlY3BsYW46Y3J1eC1wYXNzcG9ydC1taW50LXJlcXVlc3QtZ2F0ZS0yMDI2LTA3LTE3IiwiayI6ImdhdGU6TTItbGl2ZS1jb250YWlubWVudC0yMDI2LTA3LTIyIiwiZCI6NzYuNzUwNjQ4MTQ4MTQ2ODcsImEiOiJjbGF1ZGUtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjE1OX0seyJlIjoiZXhlY3BsYW46c2RrY3J1eC1kZXBlbmRlbmN5LXZ1bG4tcmVtZWRpYXRpb24tMjAyNi0wNy0yMCIsImsiOiJnYXRlOk00IiwiZCI6NzQuNTgzMTgyODcwMzcwMzYsImEiOiJjb2RleC13b3JrIiwiaCI6InZvbGF0aWxlIiwiYyI6MS4wLCJ0IjoyMjB9LHsiZSI6ImV4ZWNwbGFuOmNvcmVjcnV4LW9iamVjdC1zdG9yYWdlLXRpZXItMjAyNi0wNy0wNyIsImsiOiJnYXRlOkczLXByb2Qtc2FmZXR5LXJlY2hlY2siLCJkIjo3Ni42NTgzOTEyMDM3MDIyLCJhIjoiY2xhdWRlLXdvcmsiLCJoIjoidm9sYXRpbGUiLCJjIjoxLjAsInQiOjEzMX0seyJlIjoiZXhlY3BsYW46d2lraWNydXgtbTUtcHJpY2luZy1lbmZvcmNlbWVudC0yMDI2LTA3LTE3IiwiayI6ImdhdGU6TTNhLWhhcm5lc3MiLCJkIjo3NS45MTY1NjI0OTk5OTg2OSwiYSI6ImNsYXVkZS13b3JrIiwiaCI6InN0YWJsZSIsImMiOjEuMCwidCI6MjQ0fSx7ImUiOiJleGVjcGxhbjpwcm9kdWN0aW9uLWV0aG9zLWF1ZGl0LWhhcm5lc3MtMjAyNi0wNy0xNyIsImsiOiJnYXRlOk00IiwiZCI6NzQuNTc4MTI1LCJhIjoiY29kZXgtd29yayIsImgiOiJ2b2xhdGlsZSIsImMiOjEuMCwidCI6MzQ0fSx7ImUiOiJleGVjcGxhbjpjcnV4LWRhZW1vbi1idXllci1maXQtYnVpbGRvdXQtMjAyNi0wNy0xMyIsImsiOiJnYXRlOk00IiwiZCI6NjguODU4ODE5NDQ0NDQ1NTQsImEiOiJjb2RleC13b3JrIiwiaCI6InN0YWJsZSIsImMiOjEuMCwidCI6NDA5fSx7ImUiOiJleGVjcGxhbjpjcnV4LXBhc3Nwb3J0LW1pbnQtcmVxdWVzdC1nYXRlLTIwMjYtMDctMTciLCJrIjoiZ2F0ZTpNMi4xLWludGVncmF0aW9uIiwiZCI6NzYuNjQ3ODM1NjQ4MTQ5MzQsImEiOiJjbGF1ZGUtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjE4NX0seyJlIjoiZXhlY3BsYW46d2lraWNydXgtcHVibGljLXJlYWRpbmVzcy1oYXJkZW5pbmctMjAyNi0wNy0yMSIsImsiOiJnYXRlOk0zYiIsImQiOjc1LjkxMzYxMTExMTExMTEsImEiOiJkcml2ZXctaG9zdCIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjI5M30seyJlIjoiZXhlY3BsYW46Y3Jvc3Mtc2l0ZS1hdXRoLXNzby1jdWVjcnV4LTIwMjYtMDctMTMiLCJrIjoiY29uc29sZS12MS1yZW1vdmVkIiwiZCI6NjguODkxODYzNDI1OTI0MzgsImEiOiJjb2RleC13b3JrIiwiaCI6Im1lZGl1bSIsImMiOjEuMCwidCI6Mjg4fSx7ImUiOiJpbmNpZGVudDoyMDI2LTA3LTIyIiwiayI6InZhdWx0Y3J1eC1wdWJsaWMtZWRnZS1sb29wYmFjay1yZWdyZXNzaW9uIiwiZCI6NzYuNTQ4MDA5MjU5MjU4ODMsImEiOiJjbGF1ZGUtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjE1N30seyJlIjoiaW5jaWRlbnQ6MjAyNi0wNy0yMiIsImsiOiJsZWdhbC1ob2xkLWNhbmFyeS1tY3AtYXV0aC1taXNtYXRjaCIsImQiOjc2LjQzOTM1MTg1MTg1MTgyLCJhIjoiY29kZXgtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjIxNH0seyJlIjoiZXhlY3BsYW46Y3J1eC1kYWVtb24tYnV5ZXItZml0LWJ1aWxkb3V0LTIwMjYtMDctMTMiLCJrIjoiZ2F0ZTpNMyIsImQiOjY5LjAzMjExODA1NTU1NDc1LCJhIjoiY29kZXgtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjIxNX0seyJlIjoiaW5jaWRlbnQ6MjAyNi0wNy0yMiIsImsiOiJsZWdhbC1ob2xkLWNhbmFyeS1tY3AtYXV0aC1taXNtYXRjaCIsImQiOjc2LjQzODkzNTE4NTE4NTk4LCJhIjoiY29kZXgtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjIxNH1dOwpjb25zdCBHTk9ERVMgPSBbXTsKY29uc3QgR0VER0VTID0gW107CmNvbnN0IEdBREogPSB7fTsKbGV0IGdUb3RhbCA9IG51bGw7ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLyogc3RvcmUtd2lkZSB2aXNpYmxlIGZhY3QgY291bnQgd2hlbiBsaXZlICovCmxldCBnQ2FwID0gZmFsc2U7ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8qIHRydWUgd2hlbiB0aGUgbm9kZSB3YWxrIGhpdCBpdHMgY2FwICovCmZ1bmN0aW9uIGxvYWRHcmFwaChyYXdzKSB7CiAgR05PREVTLmxlbmd0aCA9IDA7IEdFREdFUy5sZW5ndGggPSAwOwogIGZvciAoY29uc3QgazIgaW4gR0FESikgZGVsZXRlIEdBREpbazJdOwogIHJhd3MuZm9yRWFjaCgobiwgaSkgPT4gR05PREVTLnB1c2goeyAuLi5uLCBpIH0pKTsKICBjb25zdCBieUUgPSB7fTsKICBmb3IgKGNvbnN0IG4gb2YgR05PREVTKSAoYnlFW24uZV0gPSBieUVbbi5lXSB8fCBbXSkucHVzaChuKTsKICBmb3IgKGNvbnN0IGUgaW4gYnlFKSB7CiAgICBjb25zdCBhcnIgPSBieUVbZV0uc29ydCgoYSwgYikgPT4gYS5kIC0gYi5kKTsKICAgIGZvciAobGV0IGkgPSAxOyBpIDwgYXJyLmxlbmd0aDsgaSsrKSBHRURHRVMucHVzaCh7IGE6IGFycltpIC0gMV0sIGI6IGFycltpXSB9KTsKICB9CiAgZm9yIChjb25zdCBlZCBvZiBHRURHRVMpIHsKICAgIChHQURKW2VkLmEuaV0gPSBHQURKW2VkLmEuaV0gfHwgW10pLnB1c2goZWQuYi5pKTsKICAgIChHQURKW2VkLmIuaV0gPSBHQURKW2VkLmIuaV0gfHwgW10pLnB1c2goZWQuYS5pKTsKICB9Cn0KbG9hZEdyYXBoKEdSQVBIX1JBVyk7CmxldCBnU2VsID0gbnVsbDsgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8qIHNlbGVjdGVkIG5vZGUgaW5kZXgg4oaSIDItaG9wIGhpZ2hsaWdodCAqLwpmdW5jdGlvbiBnSG9wcyhpMCkgewogIGNvbnN0IGwxID0gbmV3IFNldChHQURKW2kwXSB8fCBbXSk7CiAgY29uc3QgbDIgPSBuZXcgU2V0KCk7CiAgZm9yIChjb25zdCBqIG9mIGwxKSBmb3IgKGNvbnN0IGsyIG9mIChHQURKW2pdIHx8IFtdKSkgaWYgKGsyICE9PSBpMCAmJiAhbDEuaGFzKGsyKSkgbDIuYWRkKGsyKTsKICByZXR1cm4geyBsMSwgbDIgfTsKfQpjb25zdCBHX0ZBTV9IVUUgPSBlID0+CiAgZS5zdGFydHNXaXRoKCdleGVjcGxhbjonKSA/ICcjYTc4YmZhJyA6CiAgZS5zdGFydHNXaXRoKCdiZW5jaDonKSA/ICcjZjVhNjIzJyA6CiAgZS5zdGFydHNXaXRoKCdpbmNpZGVudDonKSA/ICcjZWY0NDQ0JyA6CiAgZS5zdGFydHNXaXRoKCdkZXNpZ246JykgPyAnIzIyZDNlZScgOgogIGUuc3RhcnRzV2l0aCgnX193b3JrX2NvbW1lbnRfXycpID8gJyMzNGQzOTknIDogJyM3ZTg1OTUnOwpjb25zdCBHX1RIUiA9IHsgdm9sYXRpbGU6IDEsIG1lZGl1bTogMzUsIHN0YWJsZTogMzY1LCBub25lOiBJbmZpbml0eSB9OwpmdW5jdGlvbiBnRWZmQ29uZihuKSB7CiAgY29uc3QgYWdlID0gTWF0aC5tYXgoMCwgVCAtIG4uZCk7CiAgY29uc3QgdGhyID0gR19USFJbbi5oXSB8fCBJbmZpbml0eTsKICBpZiAodGhyID09PSBJbmZpbml0eSkgcmV0dXJuIG4uYzsKICByZXR1cm4gYWdlID4gdGhyID8gbi5jICogMC41IDogbi5jICogKDEgLSAwLjM1ICogKGFnZSAvIHRocikpOwp9CmZ1bmN0aW9uIGRyYXdEYXRhTGVucyhjdHgyLCBnKSB7CiAgZm9yIChjb25zdCBuIG9mIEdOT0RFUykgeyBuLl94ID0gdW5kZWZpbmVkOyBuLl9vbiA9IGZhbHNlOyB9CiAgY29uc3Qgc3BhbiA9IE1hdGgubWF4KDAuNSwgRSAtIFMpOwogIGNvbnN0IHJJbiA9IGcucjAgKiAxLjI1LCByT3V0ID0gZy5SICogMC45NjsKICAvKiByYWRpdXMgPSBjb25maWRlbmNlIFJBTksgd2l0aGluIHRoZSB2aXNpYmxlIHNldCAocmVhbCBjb25maWRlbmNlcyBhcmUKICAgICB1bmlmb3JtbHkgfjEuMCB0b2RheTsgbm9ybWFsaXNpbmcga2VlcHMgImhpZ2hlciA9IG5lYXJlciB0aGUgY2VudHJlIgogICAgIG1lYW5pbmdmdWwgaW5zdGVhZCBvZiBjbHVtcGluZyBldmVyeXRoaW5nIGF0IHRoZSBoZWFydHdvb2QpICovCiAgY29uc3QgdmlzID0gR05PREVTLmZpbHRlcihuID0+IG4uZCA8PSBUICYmIG4uZCA+PSBTICYmIG4uZCA8PSBFKTsKICBsZXQgY01pbiA9IDEsIGNNYXggPSAwOwogIGZvciAoY29uc3QgbiBvZiB2aXMpIHsgY29uc3QgZWMgPSBnRWZmQ29uZihuKTsgaWYgKGVjIDwgY01pbikgY01pbiA9IGVjOyBpZiAoZWMgPiBjTWF4KSBjTWF4ID0gZWM7IH0KICBjb25zdCBjU3BhbiA9IE1hdGgubWF4KDAuMDIsIGNNYXggLSBjTWluKTsKICBjb25zdCBwb3NPZiA9IG4gPT4gewogICAgY29uc3QgYSA9IEJBU0UgKyAoVEFVIC0gU0VBTSkgKiBNYXRoLm1heCgwLCBNYXRoLm1pbigxLCAobi5kIC0gUykgLyBzcGFuKSk7CiAgICBjb25zdCBub3JtID0gKGdFZmZDb25mKG4pIC0gY01pbikgLyBjU3BhbjsKICAgIGNvbnN0IHIgPSBySW4gKyAock91dCAtIHJJbikgKiAoMSAtICgwLjA4ICsgMC44NCAqIG5vcm0pKTsKICAgIHJldHVybiB7IGEsIHg6IE1hdGguY29zKGEpICogciwgeTogTWF0aC5zaW4oYSkgKiByIH07CiAgfTsKICBjb25zdCBob3BzID0gZ1NlbCAhPT0gbnVsbCA/IGdIb3BzKGdTZWwpIDogbnVsbDsKICBjb25zdCBpbkZvY3VzID0gaTIgPT4gZ1NlbCA9PT0gbnVsbCA/IG51bGwgOiAoaTIgPT09IGdTZWwgPyAwIDogaG9wcy5sMS5oYXMoaTIpID8gMSA6IGhvcHMubDIuaGFzKGkyKSA/IDIgOiAtMSk7CiAgLyogY29uZmlkZW5jZSBndWlkZSByaW5ncyAqLwogIGZvciAoY29uc3QgY2Ygb2YgWzAuMjUsIDAuNSwgMC43NV0pIHsKICAgIGN0eDIuc3Ryb2tlU3R5bGUgPSAncmdiYSgyNTUsMjU1LDI1NSwuMDQpJzsKICAgIGN0eDIubGluZVdpZHRoID0gMSAvIFo7CiAgICBjdHgyLmJlZ2luUGF0aCgpOyBjdHgyLmFyYygwLCAwLCBySW4gKyAock91dCAtIHJJbikgKiBjZiwgMCwgNyk7IGN0eDIuc3Ryb2tlKCk7CiAgfQogIGxlbnNMYWJlbHMucHVzaCh7IHg6IDAsIHk6IC0ockluICsgKHJPdXQgLSBySW4pICogMC4wMikgKyAxMCwgdDogJycgfSk7CiAgLyogZWRnZXMgKi8KICBmb3IgKGNvbnN0IGVkIG9mIEdFREdFUykgewogICAgaWYgKGVkLmEuZCA+IFQgfHwgZWQuYi5kID4gVCB8fCBlZC5hLmQgPCBTIHx8IGVkLmIuZCA8IFMpIGNvbnRpbnVlOwogICAgY29uc3QgcGEyID0gcG9zT2YoZWQuYSksIHBiMiA9IHBvc09mKGVkLmIpOwogICAgbGV0IGFscGhhID0gMC4xNjsKICAgIGlmIChob3BzKSB7CiAgICAgIGNvbnN0IGZhID0gaW5Gb2N1cyhlZC5hLmkpLCBmYiA9IGluRm9jdXMoZWQuYi5pKTsKICAgICAgYWxwaGEgPSAoZmEgPj0gMCAmJiBmYiA+PSAwKSA/IDAuNiA6IDAuMDM7CiAgICB9CiAgICBjdHgyLnN0cm9rZVN0eWxlID0gaGV4MnJnYmEoR19GQU1fSFVFKGVkLmEuZSksIGFscGhhKTsKICAgIGN0eDIubGluZVdpZHRoID0gMS4xIC8gWjsKICAgIGN0eDIuYmVnaW5QYXRoKCk7CiAgICBjdHgyLm1vdmVUbyhwYTIueCwgcGEyLnkpOwogICAgY3R4Mi5xdWFkcmF0aWNDdXJ2ZVRvKChwYTIueCArIHBiMi54KSAvIDIgKiAwLjU1LCAocGEyLnkgKyBwYjIueSkgLyAyICogMC41NSwgcGIyLngsIHBiMi55KTsKICAgIGN0eDIuc3Ryb2tlKCk7CiAgfQogIC8qIG5vZGVzICovCiAgZm9yIChjb25zdCBuIG9mIEdOT0RFUykgewogICAgaWYgKG4uZCA+IFQgfHwgbi5kIDwgUyB8fCBuLmQgPiBFKSBjb250aW51ZTsKICAgIGNvbnN0IHAyID0gcG9zT2Yobik7CiAgICBjb25zdCBodWUyID0gR19GQU1fSFVFKG4uZSk7CiAgICBjb25zdCBmMiA9IGluRm9jdXMobi5pKTsKICAgIGNvbnN0IGlzSCA9IGhvdmVyID09PSBuOwogICAgbGV0IGFscGhhID0gMC44NTsKICAgIGlmIChmMiAhPT0gbnVsbCkgYWxwaGEgPSBmMiA9PT0gLTEgPyAwLjEwIDogZjIgPT09IDAgPyAxIDogZjIgPT09IDEgPyAwLjk1IDogMC42OwogICAgY29uc3QgcnIgPSAoMi4yICsgTWF0aC5taW4oMywgKG4udCB8fCAxNTApIC8gMTgwKSkgKiAoaXNIIHx8IGYyID09PSAwID8gMS43IDogMSk7CiAgICBjdHgyLmZpbGxTdHlsZSA9IGhleDJyZ2JhKGh1ZTIsIGFscGhhKTsKICAgIGN0eDIuYmVnaW5QYXRoKCk7IGN0eDIuYXJjKHAyLngsIHAyLnksIHJyLCAwLCA3KTsgY3R4Mi5maWxsKCk7CiAgICBpZiAoZjIgPT09IDApIHsKICAgICAgY3R4Mi5zdHJva2VTdHlsZSA9IGhleDJyZ2JhKGh1ZTIsIDAuOTUpOwogICAgICBjdHgyLmxpbmVXaWR0aCA9IDEuNSAvIFo7CiAgICAgIGN0eDIuYmVnaW5QYXRoKCk7IGN0eDIuYXJjKHAyLngsIHAyLnksIHJyICsgNSAvIFosIDAsIDcpOyBjdHgyLnN0cm9rZSgpOwogICAgfQogICAgaWYgKGlzSCkgeyBjdHgyLnN0cm9rZVN0eWxlID0gaGV4MnJnYmEoaHVlMiwgMC45KTsgY3R4Mi5iZWdpblBhdGgoKTsgY3R4Mi5hcmMocDIueCwgcDIueSwgcnIgKyA0IC8gWiwgMCwgNyk7IGN0eDIuc3Ryb2tlKCk7IH0KICAgIG4uX3ggPSBwMi54OyBuLl95ID0gcDIueTsgbi5fZHIgPSBycjsgbi5fb24gPSB0cnVlOwogIH0KICBsZW5zTGFiZWxzLnB1c2goeyB4OiAwLCB5OiBnLlIgKyA0MiwgY2FwOiB0cnVlLAogICAgICAgICAgICAgICAgICAgIHQ6ICdkYXRhIGdyYXBoIMK3ICcgKyBHTk9ERVMubGVuZ3RoICsgKGdUb3RhbCA/ICcgb2YgJyArIGdUb3RhbC50b0xvY2FsZVN0cmluZygpICsgJyB2aXNpYmxlIGZhY3RzJyArIChnQ2FwID8gJyAobm9kZSBjYXApJyA6ICcnKSA6ICcgbGl2ZSBmYWN0cycpICsKICAgICAgICAgICAgICAgICAgICAgICAnIMK3IGFuZ2xlID0gc291cmNlIGRhdGUgwrcgY2VudHJlID0gaGlnaGVyIGNvbmZpZGVuY2UgKHJhbmstc2NhbGVkICcgKyBjTWluLnRvRml4ZWQoMikgKyAn4oCTJyArIGNNYXgudG9GaXhlZCgyKSArICcpIMK3IGVkZ2UgPSBzaGFyZWQgZW50aXR5IMK3IGNsaWNrID0gMi1ob3AnIH0pOwp9CgovKiDilIDilIAgdG9rZW5zIGxlbnM6IHdvcmtzcGFjZS10b3RhbCBzcGVuZCArIGVzdGltYXRlZCBzYXZpbmdzIG92ZXIgdGltZS4KICAgU3BlbmQ6IGVhY2ggcGxhbidzIHJlYWwgb3V0cHV0LXRva2VuIHRvdGFsIGRpc3RyaWJ1dGVkIGFjcm9zcyBpdHMgb3duCiAgIGV2ZW50IGRheXMuIFNhdmluZ3M6IHRoZSBkYWVtb24ncyBwdWJsaXNoZWQgcGF0dGVybiBtYXRoIOKAlCBhIHJlY2FsbGVkCiAgIGZhY3Qg4omIIDEyIHRva2VucyB2cyB+M2sgcmVwbGF5aW5nIHRoZSBjb252ZXJzYXRpb24gaXQgY2FtZSBmcm9tIOKAlCBhcHBsaWVkCiAgIHRvIHRoZSBmYWN0cyB3cml0dGVuIGVhY2ggZGF5LiBCYXJzOiBzcGVudCBncm93cyBPVVRXQVJEIChwdXJwbGUpLCBzYXZlZAogICBncm93cyBJTldBUkQgdG93YXJkIHRoZSBoZWFydHdvb2QgKGdyZWVuKS4g4palIHRvZ2dsZXMgY3VtdWxhdGl2ZS9kYWlseS4g4pSA4pSAICovCmxldCBUT0sgPSBudWxsOwpmdW5jdGlvbiBidWlsZFRvaygpIHsKICBjb25zdCBzcGVudCA9IHt9LCBzYXZlZCA9IHt9OwogIGZvciAoY29uc3QgcCBvZiBQTEFOUykgewogICAgaWYgKCFwLmNlbGxzLmxlbmd0aCB8fCAhcC5vKSBjb250aW51ZTsKICAgIGNvbnN0IHBlciA9IChwLm8gLyAxMCkgLyBwLmNlbGxzLmxlbmd0aDsgICAgICAgLyogTSB0b2tlbnMgcGVyIGV2ZW50ICovCiAgICBmb3IgKGNvbnN0IGMgb2YgcC5jZWxscykgewogICAgICBjb25zdCBkMiA9IE1hdGguZmxvb3IoYy5kYXkpOwogICAgICBzcGVudFtkMl0gPSAoc3BlbnRbZDJdIHx8IDApICsgcGVyOwogICAgfQogIH0KICBmb3IgKGNvbnN0IGMgb2YgY2VsbHMpIHsKICAgIGNvbnN0IGQyID0gTWF0aC5mbG9vcihjLmRheSk7CiAgICBzYXZlZFtkMl0gPSAoc2F2ZWRbZDJdIHx8IDApICsgMC4wMDM7ICAgICAgICAgIC8qIOKJiDNrIHRva2VucyByZXBsYXkgYXZvaWRlZCBwZXIgZmFjdCAqLwogIH0KICBsZXQgdG90UyA9IDAsIHRvdFYgPSAwOwogIGZvciAoY29uc3QgZDIgaW4gc3BlbnQpIHRvdFMgKz0gc3BlbnRbZDJdOwogIGZvciAoY29uc3QgZDIgaW4gc2F2ZWQpIHRvdFYgKz0gc2F2ZWRbZDJdOwogIHJldHVybiB7IHNwZW50LCBzYXZlZCwgdG90UywgdG90ViB9Owp9CmZ1bmN0aW9uIHJlZnJlc2hUb2soKSB7CiAgVE9LID0gYnVpbGRUb2soKTsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGlsZS10b2snKS50ZXh0Q29udGVudCA9IE1hdGgucm91bmQoVE9LLnRvdFMpICsgJ00nOwp9CnJlZnJlc2hUb2soKTsKY29uc3QgU05BUF9UT0sgPSBUT0s7ICAgLyogc25hcHNob3QgdG9rZW4gcHJvZmlsZSDigJQgZmFsbGJhY2sgd2hlbiBhIGxpdmUgYm9hcmQgY2FycmllcyBubyB0b2tlbl9idXJuICovCmxldCB0b2tCaW5zID0gW107ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8qIHBlci1mcmFtZSBiaW4gZ2VvbWV0cnkgZm9yIGhvdmVyICovCmxldCB0b2tWaWV3ID0gJ2N1bSc7ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8qIGN1bSB8IGRheSDigJQgZXhwbGljaXQgc3ViLXZpZXcgKi8KbGV0IHRva1NlbCA9IG51bGw7ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLyogc2VsZWN0ZWQgZGF5IOKGkiBwYW5lIGxpc3RzIGFjdGl2ZSBwbGFucyAqLwpmdW5jdGlvbiBkcmF3VG9rZW5zTGVucyhjdHgyLCBnKSB7CiAgdG9rQmlucyA9IFtdOwogIGNvbnN0IGN1bSA9IHRva1ZpZXcgPT09ICdjdW0nOwogIGNvbnN0IHJCID0gZy5yMCAqIDEuNzsKICBjb25zdCBzcGFuT3V0ID0gZy5SICogMC45NCAtIHJCLCBzcGFuSW4gPSByQiAtIGcucjAgKiAwLjg7CiAgY29uc3QgZDAgPSBNYXRoLmNlaWwoUyksIGQxID0gTWF0aC5mbG9vcihNYXRoLm1pbihULCBFKSk7CiAgLyogc2VyaWVzICsgbm9ybWFsaXNhdGlvbiAqLwogIGxldCBjcyA9IDAsIGN2ID0gMCwgbWF4UyA9IDAuMDAxLCBtYXhWID0gMC4wMDE7CiAgY29uc3Qgcm93cyA9IFtdOwogIGZvciAobGV0IGQyID0gZDA7IGQyIDw9IGQxOyBkMisrKSB7CiAgICBjb25zdCBzcCA9IFRPSy5zcGVudFtkMl0gfHwgMCwgc3YgPSBUT0suc2F2ZWRbZDJdIHx8IDA7CiAgICBjcyArPSBzcDsgY3YgKz0gc3Y7CiAgICByb3dzLnB1c2goeyBkOiBkMiwgc3AsIHN2LCBjcywgY3YgfSk7CiAgfQogIGZvciAoY29uc3QgcjIgb2Ygcm93cykgeyBtYXhTID0gTWF0aC5tYXgobWF4UywgY3VtID8gcjIuY3MgOiByMi5zcCk7IG1heFYgPSBNYXRoLm1heChtYXhWLCBjdW0gPyByMi5jdiA6IHIyLnN2KTsgfQogIGNvbnN0IHdBID0gKFRBVSAtIFNFQU0pIC8gTWF0aC5tYXgoMSwgKE1hdGguZmxvb3IoRSkgLSBNYXRoLmNlaWwoUykgKyAxKSk7CiAgY3R4Mi5zdHJva2VTdHlsZSA9ICdyZ2JhKDI1NSwyNTUsMjU1LC4xMiknOwogIGN0eDIubGluZVdpZHRoID0gMSAvIFo7CiAgY3R4Mi5iZWdpblBhdGgoKTsgY3R4Mi5hcmMoMCwgMCwgckIsIEJBU0UsIEJBU0UgKyBUQVUgLSBTRUFNKTsgY3R4Mi5zdHJva2UoKTsKICBmb3IgKGNvbnN0IHIyIG9mIHJvd3MpIHsKICAgIGNvbnN0IGEgPSBCQVNFICsgKFRBVSAtIFNFQU0pICogKChyMi5kICsgMC41IC0gUykgLyBNYXRoLm1heCgwLjUsIEUgLSBTKSk7CiAgICBjb25zdCBoUyA9ICgoY3VtID8gcjIuY3MgOiByMi5zcCkgLyBtYXhTKSAqIHNwYW5PdXQ7CiAgICBjb25zdCB3QmFyID0gTWF0aC5tYXgoMS41LCB3QSAqIHJCICogMC41NSkgLyBNYXRoLm1heCgxLCBNYXRoLnNxcnQoWikpOwogICAgY29uc3QgaXNTZWxEYXkgPSB0b2tTZWwgPT09IHIyLmQ7CiAgICBpZiAoY3VtKSB7CiAgICAgIGNvbnN0IGhWID0gKChyMi5jdikgLyBtYXhWKSAqIHNwYW5JbjsKICAgICAgY3R4Mi5saW5lV2lkdGggPSB3QmFyOwogICAgICBjdHgyLnN0cm9rZVN0eWxlID0gaGV4MnJnYmEoJyNhNzhiZmEnLCAwLjU1KTsgIC8qIHNwZW50IOKGkiBvdXR3YXJkICovCiAgICAgIGN0eDIuYmVnaW5QYXRoKCk7CiAgICAgIGN0eDIubW92ZVRvKE1hdGguY29zKGEpICogckIsIE1hdGguc2luKGEpICogckIpOwogICAgICBjdHgyLmxpbmVUbyhNYXRoLmNvcyhhKSAqIChyQiArIGhTKSwgTWF0aC5zaW4oYSkgKiAockIgKyBoUykpOwogICAgICBjdHgyLnN0cm9rZSgpOwogICAgICBjdHgyLnN0cm9rZVN0eWxlID0gaGV4MnJnYmEoJyMzNGQzOTknLCAwLjYpOyAgIC8qIHNhdmVkIOKGkiBpbndhcmQgKi8KICAgICAgY3R4Mi5iZWdpblBhdGgoKTsKICAgICAgY3R4Mi5tb3ZlVG8oTWF0aC5jb3MoYSkgKiByQiwgTWF0aC5zaW4oYSkgKiByQik7CiAgICAgIGN0eDIubGluZVRvKE1hdGguY29zKGEpICogKHJCIC0gaFYpLCBNYXRoLnNpbihhKSAqIChyQiAtIGhWKSk7CiAgICAgIGN0eDIuc3Ryb2tlKCk7CiAgICB9IGVsc2UgewogICAgICAvKiBwZXIgZGF5OiBPTkUgam9pbmVkIGJhciDigJQgcHVycGxlIHNwZW5kIHdpdGggYSBncmVlbiBzYXZpbmdzIGNvcmUKICAgICAgICAgb3ZlcmxhaWQgb24gdGhlIHNhbWUgc3Bva2UgKGVhY2ggc2VyaWVzIGtlZXBzIGl0cyBvd24gc2NhbGUpICovCiAgICAgIGNvbnN0IGhWID0gKChyMi5zdikgLyBtYXhWKSAqIHNwYW5PdXQgKiAwLjg1OwogICAgICBjdHgyLmxpbmVXaWR0aCA9IHdCYXI7CiAgICAgIGN0eDIuc3Ryb2tlU3R5bGUgPSBoZXgycmdiYSgnI2E3OGJmYScsIGlzU2VsRGF5ID8gMC45IDogMC41KTsKICAgICAgY3R4Mi5iZWdpblBhdGgoKTsKICAgICAgY3R4Mi5tb3ZlVG8oTWF0aC5jb3MoYSkgKiByQiwgTWF0aC5zaW4oYSkgKiByQik7CiAgICAgIGN0eDIubGluZVRvKE1hdGguY29zKGEpICogKHJCICsgaFMpLCBNYXRoLnNpbihhKSAqIChyQiArIGhTKSk7CiAgICAgIGN0eDIuc3Ryb2tlKCk7CiAgICAgIGN0eDIubGluZVdpZHRoID0gTWF0aC5tYXgoMS4yLCB3QmFyICogMC4zOCk7CiAgICAgIGN0eDIuc3Ryb2tlU3R5bGUgPSBoZXgycmdiYSgnIzM0ZDM5OScsIGlzU2VsRGF5ID8gMSA6IDAuOCk7CiAgICAgIGN0eDIuYmVnaW5QYXRoKCk7CiAgICAgIGN0eDIubW92ZVRvKE1hdGguY29zKGEpICogckIsIE1hdGguc2luKGEpICogckIpOwogICAgICBjdHgyLmxpbmVUbyhNYXRoLmNvcyhhKSAqIChyQiArIGhWKSwgTWF0aC5zaW4oYSkgKiAockIgKyBoVikpOwogICAgICBjdHgyLnN0cm9rZSgpOwogICAgICBjdHgyLmxpbmVXaWR0aCA9IDEgLyBaOwogICAgICBjdHgyLmZpbGxTdHlsZSA9IGhleDJyZ2JhKCcjYTc4YmZhJywgaXNTZWxEYXkgPyAxIDogMC44NSk7CiAgICAgIGN0eDIuYmVnaW5QYXRoKCk7IGN0eDIuYXJjKE1hdGguY29zKGEpICogKHJCICsgaFMpLCBNYXRoLnNpbihhKSAqIChyQiArIGhTKSwgKGlzU2VsRGF5ID8gMy40IDogMi40KSAvIE1hdGguc3FydChaKSwgMCwgNyk7IGN0eDIuZmlsbCgpOwogICAgICBjdHgyLmZpbGxTdHlsZSA9IGhleDJyZ2JhKCcjMzRkMzk5JywgaXNTZWxEYXkgPyAxIDogMC44NSk7CiAgICAgIGN0eDIuYmVnaW5QYXRoKCk7IGN0eDIuYXJjKE1hdGguY29zKGEpICogKHJCICsgaFYpLCBNYXRoLnNpbihhKSAqIChyQiArIGhWKSwgKGlzU2VsRGF5ID8gMi44IDogMikgLyBNYXRoLnNxcnQoWiksIDAsIDcpOyBjdHgyLmZpbGwoKTsKICAgICAgaWYgKGlzU2VsRGF5KSB7CiAgICAgICAgY3R4Mi5zdHJva2VTdHlsZSA9ICdyZ2JhKDIzOCwyNDAsMjQ2LC41KSc7CiAgICAgICAgY3R4Mi5iZWdpblBhdGgoKTsgY3R4Mi5hcmMoMCwgMCwgckIsIGEgLSAwLjAyLCBhICsgMC4wMik7IGN0eDIuc3Ryb2tlKCk7CiAgICAgIH0KICAgIH0KICAgIHRva0JpbnMucHVzaCh7IC4uLnIyLCBhLCByVGlwOiByQiArIGhTIH0pOwogIH0KICBjdHgyLmxpbmVXaWR0aCA9IDEgLyBaOwogIGNvbnN0IHBjdCA9IFRPSy50b3RTID4gMCA/IE1hdGgucm91bmQoMTAwICogVE9LLnRvdFYgLyBUT0sudG90UykgOiAwOwogIGNvbnN0IG5EYXlzID0gTWF0aC5tYXgoMSwgcm93cy5sZW5ndGgpOwogIGxlbnNMYWJlbHMucHVzaCh7IHg6IDAsIHk6IGcuUiArIDQyLCBjYXA6IHRydWUsCiAgICB0OiBjdW0KICAgICAgPyAndG9rZW5zIMK3IGN1bXVsYXRpdmUgwrcgb3V0d2FyZCA9IHNwZW50ICcgKyBNYXRoLnJvdW5kKFRPSy50b3RTKSArICdNIMK3IGlud2FyZCA9IGVzdC4gc2F2ZWQgJyArIFRPSy50b3RWLnRvRml4ZWQoMSkgKyAnTSAoficgKyBwY3QgKyAnJSwgZnJvbSAxMi10b2tlbiBmYWN0IHJlY2FsbHMgdnMgfjNrIHJlcGxheXMpJwogICAgICA6ICd0b2tlbnMgwrcgcGVyIGRheSDCtyBhdmcgJyArIChjcyAvIG5EYXlzKS50b0ZpeGVkKDEpICsgJ00vZGF5IHNwZW50IMK3IHBlYWsgJyArIG1heFMudG9GaXhlZCgxKSArICdNIMK3IGVzdC4gc2F2ZWQgYXZnICcgKyAoY3YgLyBuRGF5cyAqIDEwMDApLnRvRml4ZWQoMCkgKyAnay9kYXknIH0pOwp9CgovKiDilIDilIAgYWx0ZXJuYXRpdmUgbGVuc2VzOiBzYW1lIGRpc2MsIGRpZmZlcmVudCBzdWJzdHJhdGUgY3V0IOKUgOKUgCAqLwpmdW5jdGlvbiBkcmF3TGVuc0luRnJhbWUoY3R4MiwgZywgdGltZSkgewogIGZvciAoY29uc3QgYyBvZiBjZWxscykgeyBjLl94ID0gdW5kZWZpbmVkOyBjLl9vbiA9IGZhbHNlOyBjLl9ieCA9IHVuZGVmaW5lZDsgfQogIGlmIChsZW5zID09PSAnZGF0YScpIHsgZHJhd0RhdGFMZW5zKGN0eDIsIGcpOyByZXR1cm47IH0KICBpZiAobGVucyA9PT0gJ3Rva2VucycpIHsgZHJhd1Rva2Vuc0xlbnMoY3R4MiwgZyk7IHJldHVybjsgfQogIGlmIChsZW5zID09PSAncmVjZWlwdHMnKSB7IGRyYXdSZWNlaXB0c0xlbnMoY3R4MiwgZywgdGltZSk7IHJldHVybjsgfQogIGNvbnN0IGdyb3VwcyA9IGxlbnMgPT09ICdtZW1vcnknCiAgICA/IFtbJ2dhdGUnLCAnIzJkZDRiZiddLCBbJ2RlY2lzaW9uJywgJyNhNzhiZmEnXSwgWydtZW1vcnknLCAnIzhiOTZmMiddLCBbJ2hhbmRvZmYnLCAnI2Y1YTYyMyddLCBbJ2luY2lkZW50JywgJyNlZjQ0NDQnXV0KICAgIDogW1snY2xhdWRlLXdvcmsnLCAnIzhiOTZmMiddLCBbJ2NvZGV4LXdvcmsnLCAnIzIyZDNlZSddLCBbJ3VudHJhY2VkJywgJyM3ZTg1OTUnXV07CiAgY29uc3Qga2V5T2YgPSBjID0+IGxlbnMgPT09ICdtZW1vcnknID8gYy5raW5kIDogKGMuYWN0b3IgfHwgJ3VudHJhY2VkJyk7CiAgY29uc3QgTjIgPSBncm91cHMubGVuZ3RoOwogIGdyb3Vwcy5mb3JFYWNoKChncnAsIGdpKSA9PiB7CiAgICBjb25zdCBrMiA9IGdycFswXSwgaHVlMiA9IGdycFsxXTsKICAgIGNvbnN0IGEwID0gQkFTRSArIChnaSAvIE4yKSAqIChUQVUgLSBTRUFNKSwgYTEgPSBCQVNFICsgKChnaSArIDEpIC8gTjIpICogKFRBVSAtIFNFQU0pOwogICAgLyogZGl2aWRlciArIHJpbSBhcmMgKi8KICAgIGN0eDIuc3Ryb2tlU3R5bGUgPSAncmdiYSgyNTUsMjU1LDI1NSwuMDYpJzsKICAgIGN0eDIubGluZVdpZHRoID0gMSAvIFo7CiAgICBjdHgyLmJlZ2luUGF0aCgpOwogICAgY3R4Mi5tb3ZlVG8oTWF0aC5jb3MoYTApICogZy5yMCwgTWF0aC5zaW4oYTApICogZy5yMCk7CiAgICBjdHgyLmxpbmVUbyhNYXRoLmNvcyhhMCkgKiBnLlIsIE1hdGguc2luKGEwKSAqIGcuUik7CiAgICBjdHgyLnN0cm9rZSgpOwogICAgY29uc3QgbWVtYmVycyA9IGNlbGxzLmZpbHRlcihjID0+IGtleU9mKGMpID09PSBrMiAmJiBjLmRheSA8PSBUICYmIGMuZGF5ID49IFMgJiYgYy5kYXkgPD0gRSAmJiBwYXNzRmlsdGVyKGMpKTsKICAgIGN0eDIuc3Ryb2tlU3R5bGUgPSBoZXgycmdiYShodWUyLCAwLjUpOwogICAgY3R4Mi5saW5lV2lkdGggPSAzIC8gWjsKICAgIGN0eDIuYmVnaW5QYXRoKCk7IGN0eDIuYXJjKDAsIDAsIGcuUiArIDMsIGEwICsgMC4wMiwgYTEgLSAwLjAyKTsgY3R4Mi5zdHJva2UoKTsKICAgIGN0eDIubGluZVdpZHRoID0gMSAvIFo7CiAgICAvKiBsYWJlbCAqLwogICAgY29uc3QgbWlkID0gKGEwICsgYTEpIC8gMjsKICAgIGxlbnNMYWJlbHMucHVzaCh7IHg6IE1hdGguY29zKG1pZCkgKiAoZy5SICsgMjApLCB5OiBNYXRoLnNpbihtaWQpICogKGcuUiArIDIwKSwKICAgICAgICAgICAgICAgICAgICAgIHQ6IGsyICsgJyDCtyAnICsgbWVtYmVycy5sZW5ndGggfSk7CiAgICAvKiBjZWxsczogcmluZyA9IGRheSBlcG9jaCwgZmFkZSA9IGFnZSAobWVtb3J5IGxlbnMpICovCiAgICBmb3IgKGNvbnN0IGMgb2YgbWVtYmVycykgewogICAgICBjb25zdCBhID0gYTAgKyAoYTEgLSBhMCkgKiAoMC4wOCArIGMuamEgKiAwLjg0KTsKICAgICAgY29uc3QgciA9IGRheVIoZywgYy5kYXkpICogKDAuOTk1ICsgYy5qciAqIDAuMDEpOwogICAgICBjb25zdCB4ID0gTWF0aC5jb3MoYSkgKiByLCB5ID0gTWF0aC5zaW4oYSkgKiByOwogICAgICBjb25zdCBpc0ggPSBob3ZlciA9PT0gYzsKICAgICAgbGV0IGFscGhhID0gYy5yZWFsID8gMC45IDogMC40NTsKICAgICAgaWYgKGxlbnMgPT09ICdtZW1vcnknKSB7CiAgICAgICAgY29uc3QgYWdlRnJhYyA9IE1hdGgubWF4KDAsIE1hdGgubWluKDEsIChUIC0gYy5kYXkpIC8gTWF0aC5tYXgoMC41LCBFIC0gUykpKTsKICAgICAgICBhbHBoYSAqPSAxIC0gMC41ICogYWdlRnJhYzsgICAgICAgICAgICAgICAgIC8qIG9sZGVyIG1lbW9yeSBkaW1zIOKAlCBkZWNheSwgaWxsdXN0cmF0aXZlbHkgKi8KICAgICAgfQogICAgICBjb25zdCByciA9IChjLnJlYWwgPyAzLjIgOiAyLjQpICogKGlzSCA/IDEuOCA6IDEpOwogICAgICBjdHgyLmZpbGxTdHlsZSA9IGhleDJyZ2JhKGh1ZTIsIGFscGhhICogKGhvdmVyICYmICFpc0ggPyAwLjUgOiAxKSk7CiAgICAgIGlmIChjLmtpbmQgPT09ICdnYXRlJyAmJiBjLnJlYWwpIHsKICAgICAgICBjdHgyLmJlZ2luUGF0aCgpOwogICAgICAgIGN0eDIubW92ZVRvKHgsIHkgLSByciAtIDEpOyBjdHgyLmxpbmVUbyh4ICsgcnIsIHkpOyBjdHgyLmxpbmVUbyh4LCB5ICsgcnIgKyAxKTsgY3R4Mi5saW5lVG8oeCAtIHJyLCB5KTsKICAgICAgICBjdHgyLmNsb3NlUGF0aCgpOyBjdHgyLmZpbGwoKTsKICAgICAgfSBlbHNlIHsKICAgICAgICBjdHgyLmJlZ2luUGF0aCgpOyBjdHgyLmFyYyh4LCB5LCByciwgMCwgNyk7IGN0eDIuZmlsbCgpOwogICAgICB9CiAgICAgIGlmIChpc0gpIHsgY3R4Mi5zdHJva2VTdHlsZSA9IGhleDJyZ2JhKGh1ZTIsIDAuOTUpOyBjdHgyLmJlZ2luUGF0aCgpOyBjdHgyLmFyYyh4LCB5LCByciArIDQgLyBaLCAwLCA3KTsgY3R4Mi5zdHJva2UoKTsgfQogICAgICBjLl94ID0geDsgYy5feSA9IHk7IGMuX2RyID0gcnI7IGMuX29uID0gdHJ1ZTsKICAgIH0KICB9KTsKICBsZW5zTGFiZWxzLnB1c2goeyB4OiAwLCB5OiBnLlIgKyA0MiwgY2FwOiB0cnVlLAogICAgICAgICAgICAgICAgICAgIHQ6IGxlbnMgPT09ICdtZW1vcnknCiAgICAgICAgICAgICAgICAgICAgICA/ICdtZW1vcnkgbGVucyDCtyBzZWN0b3IgPSBmYWN0IGtpbmQgwrcgcmluZyA9IGRheSDCtyBmYWRlID0gYWdlIChkZWNheSBpbGx1c3RyYXRpdmUpJwogICAgICAgICAgICAgICAgICAgICAgOiAnc2Vzc2lvbnMgbGVucyDCtyBzZWN0b3IgPSBhZ2VudCBwYXNzcG9ydCDCtyByaW5nID0gZGF5IMK3IHVudHJhY2VkIHBsYW5zIGhhdmUgbm8gYWN0b3InIH0pOwp9CmZ1bmN0aW9uIGRyYXdSZWNlaXB0c0xlbnMoY3R4MiwgZywgdGltZSkgewogIGNvbnN0IHRlZXRoID0gMTIwOwogIGNvbnN0IHNlYWxlZEZyYWMgPSBNYXRoLm1heCgwLCBNYXRoLm1pbigxLCAoVCAtIFMpIC8gTWF0aC5tYXgoMC41LCBFIC0gUykpKTsKICBmb3IgKGxldCBpID0gMDsgaSA8IHRlZXRoOyBpKyspIHsKICAgIGNvbnN0IGEgPSBCQVNFICsgKGkgLyB0ZWV0aCkgKiAoVEFVIC0gU0VBTSk7CiAgICBjb25zdCBzZWFsZWQgPSBpIC8gdGVldGggPD0gc2VhbGVkRnJhYzsKICAgIGN0eDIuc3Ryb2tlU3R5bGUgPSBzZWFsZWQgPyAncmdiYSg1MiwyMTEsMTUzLC44KScgOiAncmdiYSgyNTUsMjU1LDI1NSwuMTApJzsKICAgIGN0eDIubGluZVdpZHRoID0gKHNlYWxlZCA/IDEuOCA6IDEpIC8gWjsKICAgIGN0eDIuYmVnaW5QYXRoKCk7CiAgICBjdHgyLm1vdmVUbyhNYXRoLmNvcyhhKSAqIGcuUiwgTWF0aC5zaW4oYSkgKiBnLlIpOwogICAgY3R4Mi5saW5lVG8oTWF0aC5jb3MoYSkgKiAoZy5SICsgKHNlYWxlZCA/IDkgOiA2KSksIE1hdGguc2luKGEpICogKGcuUiArIChzZWFsZWQgPyA5IDogNikpKTsKICAgIGN0eDIuc3Ryb2tlKCk7CiAgfQogIGN0eDIubGluZVdpZHRoID0gMSAvIFo7CiAgLyogcml2ZXQgc3BpcmFsOiByZWNlaXB0cyBhY2N1bXVsYXRpbmcgaW53YXJkLW91dCAoZ29sZGVuIGFuZ2xlKSAqLwogIGNvbnN0IG4gPSBNYXRoLmZsb29yKDkwICogc2VhbGVkRnJhYykgKyA4OwogIGZvciAobGV0IGkgPSAwOyBpIDwgbjsgaSsrKSB7CiAgICBjb25zdCBhID0gaSAqIDIuMzk5OTYzOwogICAgY29uc3QgciA9IGcucjAgKyAoZy5SIC0gZy5yMCkgKiAoMC4xMiArIChpIC8gOTgpICogMC43OCk7CiAgICBjdHgyLmZpbGxTdHlsZSA9IGhleDJyZ2JhKCcjMzRkMzk5JywgMC4yNSArIChpIC8gbikgKiAwLjUpOwogICAgY3R4Mi5iZWdpblBhdGgoKTsgY3R4Mi5hcmMoTWF0aC5jb3MoYSkgKiByLCBNYXRoLnNpbihhKSAqIHIsIDEuOCwgMCwgNyk7IGN0eDIuZmlsbCgpOwogIH0KICBsZW5zTGFiZWxzLnB1c2goeyB4OiAwLCB5OiBnLlIgKyA0MiwgY2FwOiB0cnVlLAogICAgICAgICAgICAgICAgICAgIHQ6ICdyZWNlaXB0cyBsZW5zIMK3IGNoYWluIHRpY2tzIGZvcndhcmQgb25seSDCtyBpbGx1c3RyYXRpdmUgdW50aWwgL3YxL3JlY2VpcHRzL2V4cG9ydCBpcyB3aXJlZCcgfSk7Cn0KCi8qIGtpY2sgKi8KZnVuY3Rpb24ga2ljaygpIHsgaWYgKHJhZklkID09PSBudWxsKSByYWZJZCA9IHJlcXVlc3RBbmltYXRpb25GcmFtZShkcmF3KTsgfQpkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCd2aXNpYmlsaXR5Y2hhbmdlJywga2ljayk7CmtpY2soKTsKCi8qIOKUgOKUgCBjb250cm9scyDilIDilIAgKi8KZnVuY3Rpb24gc2V0UGxheWluZyh2KSB7CiAgcGxheWluZyA9IHY7CiAgYlBsYXkudGV4dENvbnRlbnQgPSB2ID8gJ+KPuCcgOiAn4pa2JzsKICBiUGxheS5zZXRBdHRyaWJ1dGUoJ2FyaWEtcHJlc3NlZCcsIFN0cmluZyh2KSk7CiAgaWYgKHYgJiYgIXNob3dDb21wbGV0ZWQpIHNldENvbXBsZXRlZCh0cnVlKTsgICAgIC8qIHBsYXliYWNrIG5lZWRzIHRoZSBhZGQvcmVtb3ZlIHN0b3J5ICovCiAgaWYgKHYgJiYgIXNob3dMZWRnZXIpIHNldExlZGdlcih0cnVlKTsgICAgICAgICAgIC8qIOKApmFuZCB0aGUgcmV0aXJlIGxpc3QgYWxvbmdzaWRlIGl0ICovCn0KZnVuY3Rpb24gc2V0TGVkZ2VyKHYpIHsKICBzaG93TGVkZ2VyID0gdjsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYi1sZWRnZXInKS5zZXRBdHRyaWJ1dGUoJ2FyaWEtcHJlc3NlZCcsIFN0cmluZyh2KSk7Cn0KZnVuY3Rpb24gc2V0Q29tcGxldGVkKHYpIHsKICBzaG93Q29tcGxldGVkID0gdjsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYi1kb25lJykuc2V0QXR0cmlidXRlKCdhcmlhLXByZXNzZWQnLCBTdHJpbmcodikpOwp9CmJQbGF5LmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogIGlmICghcGxheWluZyAmJiBUID49IEUgLSAwLjAxKSBUID0gUzsgICAgICAgICAgICAvKiByZXBsYXkgZnJvbSB3aW5kb3cgc3RhcnQgKi8KICBzZXRQbGF5aW5nKCFwbGF5aW5nKTsKfSk7CmJTcGluLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogIHNwaW5uaW5nID0gIXNwaW5uaW5nOwogIGJTcGluLnNldEF0dHJpYnV0ZSgnYXJpYS1wcmVzc2VkJywgU3RyaW5nKHNwaW5uaW5nKSk7Cn0pOwpkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYi1kb25lJykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiBzZXRDb21wbGV0ZWQoIXNob3dDb21wbGV0ZWQpKTsKZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2ItbGVkZ2VyJykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiBzZXRMZWRnZXIoIXNob3dMZWRnZXIpKTsKYkNsb2NrLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogIHJlc2V0VHdlZW4gPSB0cnVlOwogIHNwaW5uaW5nID0gZmFsc2U7ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvKiByZXNldCBhbHNvIHN0b3BzIHRoZSBzcGluICovCiAgYlNwaW4uc2V0QXR0cmlidXRlKCdhcmlhLXByZXNzZWQnLCAnZmFsc2UnKTsKfSk7CmJNb2RlLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogIG1vZGUgPSBtb2RlID09PSAnZG90cycgPyAnYmFycycgOiAnZG90cyc7CiAgYk1vZGUuc2V0QXR0cmlidXRlKCdhcmlhLXByZXNzZWQnLCBTdHJpbmcobW9kZSA9PT0gJ2JhcnMnKSk7Cn0pOwpjb25zdCBiRGlyID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2ItZGlyJyk7CmJEaXIuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB7CiAgZGlyID0gZGlyID09PSAnb3V0JyA/ICdpbicgOiAnb3V0JzsKICBiRGlyLnRleHRDb250ZW50ID0gZGlyID09PSAnb3V0JyA/ICdlZGdlOiBvdXR3YXJkJyA6ICdlZGdlOiBpbndhcmQnOwogIGJEaXIuc2V0QXR0cmlidXRlKCdhcmlhLXByZXNzZWQnLCBTdHJpbmcoZGlyID09PSAnaW4nKSk7Cn0pOwpjb25zdCBiQWxsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2ItYWxsJyk7CmJBbGwuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB7CiAgc2hvd0FsbCA9ICFzaG93QWxsOwogIGJBbGwuc2V0QXR0cmlidXRlKCdhcmlhLXByZXNzZWQnLCBTdHJpbmcoc2hvd0FsbCkpOwp9KTsKY29uc3QgYlN0YXRlID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2Itc3RhdGUnKTsKYlN0YXRlLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogIGNvbG9yQnlTdGF0ZSA9ICFjb2xvckJ5U3RhdGU7CiAgYlN0YXRlLnNldEF0dHJpYnV0ZSgnYXJpYS1wcmVzc2VkJywgU3RyaW5nKGNvbG9yQnlTdGF0ZSkpOwp9KTsKY29uc3QgYkxpbiA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdiLWxpbicpOwpiTGluLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogIHNob3dMaW5lYWdlID0gIXNob3dMaW5lYWdlOwogIGJMaW4uc2V0QXR0cmlidXRlKCdhcmlhLXByZXNzZWQnLCBTdHJpbmcoc2hvd0xpbmVhZ2UpKTsKfSk7CmRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzLWtpbmQnKS5hZGRFdmVudExpc3RlbmVyKCdjaGFuZ2UnLCBlID0+IHsgZktpbmQgPSBlLnRhcmdldC52YWx1ZTsgfSk7CmRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzLWFnZW50JykuYWRkRXZlbnRMaXN0ZW5lcignY2hhbmdlJywgZSA9PiB7IGZBZ2VudCA9IGUudGFyZ2V0LnZhbHVlOyB9KTsKY29uc3QgZFN0YXJ0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2Qtc3RhcnQnKTsKY29uc3QgZEVuZCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdkLWVuZCcpOwpmdW5jdGlvbiBzeW5jV2luZG93KCkgewogIGNvbnN0IHMgPSBNYXRoLm1pbihyU3RhcnQudmFsdWUgLyAxMDAwLCByRW5kLnZhbHVlIC8gMTAwMCAtIDAuMDMpOwogIGNvbnN0IGUgPSBNYXRoLm1heChyRW5kLnZhbHVlIC8gMTAwMCwgclN0YXJ0LnZhbHVlIC8gMTAwMCArIDAuMDMpOwogIFMgPSAxMSArIHMgKiAoTk9XIC0gMTEpOwogIEUgPSAxMSArIGUgKiAoTk9XIC0gMTEpOwogIFQgPSBNYXRoLm1heChTLCBNYXRoLm1pbihFLCBUKSk7CiAgclRpbWUudmFsdWUgPSBNYXRoLnJvdW5kKChUIC0gUykgLyBNYXRoLm1heCgwLjUsIEUgLSBTKSAqIDEwMDApOwogIGNEYXRlLnRleHRDb250ZW50ID0gZGF5RGF0ZShUKTsKICBkU3RhcnQudmFsdWUgPSBkYXlEYXRlKFMpOwogIGRFbmQudmFsdWUgPSBkYXlEYXRlKEUpOwp9CnJTdGFydC5hZGRFdmVudExpc3RlbmVyKCdpbnB1dCcsIHN5bmNXaW5kb3cpOwpyRW5kLmFkZEV2ZW50TGlzdGVuZXIoJ2lucHV0Jywgc3luY1dpbmRvdyk7Ci8qIGRhdGUgcGlja2VycyBkcml2ZSB0aGUgc2FtZSB3aW5kb3cgKi8KZnVuY3Rpb24gZGF0ZVRvRGF5KHYpIHsgcmV0dXJuIERhdGUucGFyc2UodiArICdUMDA6MDA6MDBaJykgLyA4NjQwMDAwMCAtIDIwNTgwOyB9CmRTdGFydC5hZGRFdmVudExpc3RlbmVyKCdjaGFuZ2UnLCAoKSA9PiB7CiAgY29uc3QgZCA9IE1hdGgubWF4KDExLCBNYXRoLm1pbihOT1cgLSAxLCBkYXRlVG9EYXkoZFN0YXJ0LnZhbHVlKSkpOwogIHJTdGFydC52YWx1ZSA9IE1hdGgucm91bmQoKGQgLSAxMSkgLyAoTk9XIC0gMTEpICogMTAwMCk7CiAgc3luY1dpbmRvdygpOwp9KTsKZEVuZC5hZGRFdmVudExpc3RlbmVyKCdjaGFuZ2UnLCAoKSA9PiB7CiAgY29uc3QgZCA9IE1hdGgubWF4KDEyLCBNYXRoLm1pbihOT1csIGRhdGVUb0RheShkRW5kLnZhbHVlKSkpOwogIHJFbmQudmFsdWUgPSBNYXRoLnJvdW5kKChkIC0gMTEpIC8gKE5PVyAtIDExKSAqIDEwMDApOwogIHN5bmNXaW5kb3coKTsKfSk7CnJUaW1lLmFkZEV2ZW50TGlzdGVuZXIoJ2lucHV0JywgKCkgPT4gewogIFQgPSBTICsgKHJUaW1lLnZhbHVlIC8gMTAwMCkgKiAoRSAtIFMpOwogIHNldFBsYXlpbmcoZmFsc2UpOwogIGNEYXRlLnRleHRDb250ZW50ID0gZGF5RGF0ZShUKTsKfSk7CgovKiB6b29tICsgcGFuICovCmZ1bmN0aW9uIHpvb21BdChzeCwgc3ksIGZhY3RvcikgewogIGNvbnN0IGcgPSBnZW9tKCk7CiAgY29uc3QgYmVmb3JlID0gdG9EaXNjKGcsIHN4LCBzeSk7CiAgWiA9IE1hdGgubWF4KDAuNiwgTWF0aC5taW4oNywgWiAqIGZhY3RvcikpOwogIGNvbnN0IGFmdGVyID0gdG9TY3JlZW4oZywgYmVmb3JlLngsIGJlZm9yZS55KTsKICBwYW5YICs9IHN4IC0gYWZ0ZXIueDsgcGFuWSArPSBzeSAtIGFmdGVyLnk7Cn0KY3YuYWRkRXZlbnRMaXN0ZW5lcignd2hlZWwnLCBlID0+IHsKICBlLnByZXZlbnREZWZhdWx0KCk7CiAgY29uc3QgciA9IGN2LmdldEJvdW5kaW5nQ2xpZW50UmVjdCgpOwogIHpvb21BdChlLmNsaWVudFggLSByLmxlZnQsIGUuY2xpZW50WSAtIHIudG9wLCBlLmRlbHRhWSA8IDAgPyAxLjE1IDogMSAvIDEuMTUpOwp9LCB7IHBhc3NpdmU6IGZhbHNlIH0pOwpkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYi16aW4nKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHpvb21BdChXIC8gMiwgSCAvIDIsIDEuMzUpKTsKZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2Item91dCcpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gem9vbUF0KFcgLyAyLCBIIC8gMiwgMSAvIDEuMzUpKTsKZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2ItemZpdCcpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4geyBaID0gMTsgcGFuWCA9IHBhblkgPSAwOyB9KTsKCmN2LmFkZEV2ZW50TGlzdGVuZXIoJ3BvaW50ZXJkb3duJywgZSA9PiB7CiAgZHJhZ2dpbmcgPSB0cnVlOyBkcmFnTW92ZWQgPSAwOwogIGxhc3RQWCA9IGUuY2xpZW50WDsgbGFzdFBZID0gZS5jbGllbnRZOwogIGN2LnNldFBvaW50ZXJDYXB0dXJlKGUucG9pbnRlcklkKTsKfSk7CmN2LmFkZEV2ZW50TGlzdGVuZXIoJ3BvaW50ZXJ1cCcsIGUgPT4gewogIGRyYWdnaW5nID0gZmFsc2U7CiAgaWYgKGRyYWdNb3ZlZCA8IDUpIGhhbmRsZUNsaWNrKGUpOwp9KTsKY3YuYWRkRXZlbnRMaXN0ZW5lcigncG9pbnRlcm1vdmUnLCBlID0+IHsKICBteEFicyA9IGUuY2xpZW50WDsgbXlBYnMgPSBlLmNsaWVudFk7CiAgaWYgKGRyYWdnaW5nKSB7CiAgICBjb25zdCBkeCA9IGUuY2xpZW50WCAtIGxhc3RQWCwgZHkgPSBlLmNsaWVudFkgLSBsYXN0UFk7CiAgICBkcmFnTW92ZWQgKz0gTWF0aC5hYnMoZHgpICsgTWF0aC5hYnMoZHkpOwogICAgaWYgKGRyYWdNb3ZlZCA+IDUpIHsgcGFuWCArPSBkeDsgcGFuWSArPSBkeTsgfQogICAgbGFzdFBYID0gZS5jbGllbnRYOyBsYXN0UFkgPSBlLmNsaWVudFk7CiAgICByZXR1cm47CiAgfQogIGlmIChsZW5zID09PSAndG9rZW5zJykgewogICAgY29uc3QgZzIgPSBnZW9tKCk7CiAgICBjb25zdCBwZCA9IHRvRGlzYyhnMiwgZS5jbGllbnRYIC0gY3YuZ2V0Qm91bmRpbmdDbGllbnRSZWN0KCkubGVmdCwgZS5jbGllbnRZIC0gY3YuZ2V0Qm91bmRpbmdDbGllbnRSZWN0KCkudG9wKTsKICAgIGNvbnN0IHByMiA9IE1hdGguaHlwb3QocGQueCwgcGQueSk7CiAgICBsZXQgcGEyID0gTWF0aC5hdGFuMihwZC55LCBwZC54KTsKICAgIHdoaWxlIChwYTIgPCBCQVNFKSBwYTIgKz0gVEFVOwogICAgbGV0IGJpbiA9IG51bGwsIGJkMiA9IDAuMDU7CiAgICBmb3IgKGNvbnN0IGIyIG9mIHRva0JpbnMpIHsKICAgICAgbGV0IGJhID0gYjIuYTsgd2hpbGUgKGJhIDwgQkFTRSkgYmEgKz0gVEFVOwogICAgICBjb25zdCBkYTIgPSBNYXRoLmFicyhwYTIgLSBiYSk7CiAgICAgIGlmIChkYTIgPCBiZDIgJiYgcHIyID4gZzIucjAgKiAwLjcgJiYgcHIyIDwgZzIuUikgeyBiZDIgPSBkYTI7IGJpbiA9IGIyOyB9CiAgICB9CiAgICBpZiAoYmluKSB7CiAgICAgIHNob3dUaXAoZS5jbGllbnRYLCBlLmNsaWVudFksCiAgICAgICAgJzxiPicgKyBkYXlEYXRlKGJpbi5kKSArICc8L2I+PGJyPicgKwogICAgICAgICc8c3BhbiBjbGFzcz0iayI+c3BlbnQ8L3NwYW4+ICcgKyBiaW4uc3AudG9GaXhlZCgxKSArICdNIDxzcGFuIGNsYXNzPSJrIj5kYXk8L3NwYW4+IMK3ICcgKyBiaW4uY3MudG9GaXhlZCgxKSArICdNIDxzcGFuIGNsYXNzPSJrIj5jdW08L3NwYW4+PGJyPicgKwogICAgICAgICc8c3BhbiBjbGFzcz0iayI+c2F2ZWQ8L3NwYW4+ICcgKyBiaW4uc3YudG9GaXhlZCgyKSArICdNIDxzcGFuIGNsYXNzPSJrIj5kYXk8L3NwYW4+IMK3ICcgKyBiaW4uY3YudG9GaXhlZCgyKSArICdNIDxzcGFuIGNsYXNzPSJrIj5jdW0gKGVzdC4pPC9zcGFuPicpOwogICAgfSBlbHNlIGhpZGVUaXAoKTsKICAgIGhvdmVyID0gbnVsbDsgaG92ZXJTZWMgPSBudWxsOwogICAgcmV0dXJuOwogIH0KICBob3ZlciA9IGhpdFRlc3QoZSk7CiAgaG92ZXJTZWMgPSBob3ZlciAmJiBob3Zlci5wID8gaG92ZXIucCA6IHNlY3RvckF0KGUpOwogIGlmIChob3ZlciAmJiBsZW5zID09PSAnZGF0YScpIHsKICAgIGNvbnN0IG4gPSBob3ZlcjsKICAgIHNob3dUaXAobXhBYnMsIG15QWJzLAogICAgICAnPGI+JyArIG4uayArICc8L2I+PGJyPicgKwogICAgICAnPHNwYW4gY2xhc3M9ImsiPmVudGl0eTwvc3Bhbj4gJyArIChuLmUubGVuZ3RoID4gNDAgPyBuLmUuc2xpY2UoMCwgMzkpICsgJ+KApicgOiBuLmUpICsgJzxicj4nICsKICAgICAgJzxzcGFuIGNsYXNzPSJrIj5zb3VyY2U8L3NwYW4+ICcgKyBkYXlEYXRlKG4uZCkgKyAobi5hID8gJyA8c3BhbiBjbGFzcz0iayI+Ynk8L3NwYW4+ICcgKyBuLmEgOiAnJykgKyAnPGJyPicgKwogICAgICAnPHNwYW4gY2xhc3M9ImsiPmNvbmZpZGVuY2U8L3NwYW4+ICcgKyBnRWZmQ29uZihuKS50b0ZpeGVkKDIpICsgJyA8c3BhbiBjbGFzcz0iayI+KCcgKyAobi5oIHx8ICdub25lJykgKyAnKTwvc3Bhbj4nICsKICAgICAgJyDCtyA8c3BhbiBjbGFzcz0iayI+bGlua3M8L3NwYW4+ICcgKyAoKEdBREpbbi5pXSB8fCBbXSkubGVuZ3RoKSk7CiAgICByZXR1cm47CiAgfQogIGlmIChob3ZlcikgewogICAgY29uc3QgYyA9IGhvdmVyOwogICAgc2hvd1RpcChteEFicywgbXlBYnMsIGMucmVhbAogICAgICA/ICc8Yj4nICsgYy5rZXkgKyAnPC9iPicgKyAoYy52ZXJzaW9uID4gMSA/ICcgPHNwYW4gY2xhc3M9ImsiPnYnICsgYy52ZXJzaW9uICsgJzwvc3Bhbj4nIDogJycpICsgJzxicj4nICsKICAgICAgICAnPHNwYW4gY2xhc3M9ImsiPnBsYW48L3NwYW4+ICcgKyBjLnAuc2hvcnQgKyAnPGJyPicgKwogICAgICAgICc8c3BhbiBjbGFzcz0iayI+c3RvcmVkPC9zcGFuPiAnICsgZGF5RGF0ZShjLmRheSkgKyAnIDxzcGFuIGNsYXNzPSJrIj5ieTwvc3Bhbj4gJyArIGMuYWN0b3IgKyAnPGJyPicgKwogICAgICAgICc8c3BhbiBjbGFzcz0iayI+a2luZDwvc3Bhbj4gJyArIGMua2luZCArICcgwrcgPHNwYW4gY2xhc3M9ImsiPmhvcml6b248L3NwYW4+ICcgKyBjLmhvcml6b24KICAgICAgOiAnPGI+JyArIGMucC5zaG9ydCArICc8L2I+PGJyPicgKwogICAgICAgICc8c3BhbiBjbGFzcz0iayI+JyArIFNUQVRFW2MucC5zdF0gKyAnIMK3ICcgKyBjLnAuZG9uZSArICcvJyArIGMucC50b3RhbCArICcgwrcgYm9ybiAnICsgZGF5RGF0ZShjLnAuYikgKyAnPC9zcGFuPjxicj4nICsKICAgICAgICAnPHNwYW4gY2xhc3M9ImsiPicgKyAoYy5raW5kID09PSAnZ2F0ZScgPyBjLmtleSA6ICd1bnRyYWNlZCBkZW5zaXR5IOKAlCBvbmUgcXVlcnlfZmFjdHMgY2FsbCBhd2F5JykgKyAnPC9zcGFuPicpOwogIH0gZWxzZSBpZiAoaG92ZXJTZWMpIHsKICAgIGNvbnN0IHAgPSBob3ZlclNlYzsKICAgIGNvbnN0IG5EZXBJbiA9IERFUF9FREdFUy5maWx0ZXIoZWQgPT4gZWQuYiA9PT0gcCkubGVuZ3RoOwogICAgc2hvd1RpcChteEFicywgbXlBYnMsCiAgICAgICc8Yj4nICsgcC5zaG9ydCArICc8L2I+PGJyPicgKwogICAgICAnPHNwYW4gY2xhc3M9ImsiPicgKyBTVEFURVtwLnN0XSArICcgwrcgJyArIHAuZG9uZSArICcvJyArIHAudG90YWwgKyAnPC9zcGFuPjxicj4nICsKICAgICAgJzxzcGFuIGNsYXNzPSJrIj5ib3JuPC9zcGFuPiAnICsgZGF5RGF0ZShwLmIpICsgJyA8c3BhbiBjbGFzcz0iayI+wrcgbGFzdDwvc3Bhbj4gJyArIGRheURhdGUocC5lKSArCiAgICAgIChwLm8gPyAnPGJyPjxzcGFuIGNsYXNzPSJrIj5vdXRwdXQ8L3NwYW4+ICcgKyAocC5vIC8gMTApLnRvRml4ZWQoMSkgKyAnTSB0b2snIDogJycpICsKICAgICAgKHAub2QubGVuZ3RoID8gJzxicj48c3BhbiBjbGFzcz0iayI+b3BlbiBkZWNpc2lvbnM8L3NwYW4+ICcgKyBwLm9kLmpvaW4oJyAnKSA6ICcnKSArCiAgICAgIChwLmRlcC5sZW5ndGggfHwgbkRlcEluCiAgICAgICAgPyAnPGJyPjxzcGFuIGNsYXNzPSJrIj5saW5lYWdlPC9zcGFuPiBkZXBlbmRzIG9uICcgKyBwLmRlcC5sZW5ndGggKyAnIMK3IGRlcGVuZGVkIG9uIGJ5ICcgKyBuRGVwSW4KICAgICAgICA6ICcnKSk7CiAgfSBlbHNlIGhpZGVUaXAoKTsKfSk7Ci8qIHdoaWNoIHBsYW4ncyBzZWN0b3IgaXMgdW5kZXIgdGhlIHBvaW50ZXIgKGFubnVsdXMgb25seSkgKi8KZnVuY3Rpb24gc2VjdG9yQXQoZSkgewogIGlmIChsZW5zICE9PSAnd29yaycpIHJldHVybiBudWxsOwogIGNvbnN0IHIgPSBjdi5nZXRCb3VuZGluZ0NsaWVudFJlY3QoKTsKICBjb25zdCBnID0gZ2VvbSgpOwogIGNvbnN0IHAgPSB0b0Rpc2MoZywgZS5jbGllbnRYIC0gci5sZWZ0LCBlLmNsaWVudFkgLSByLnRvcCk7CiAgY29uc3QgcHIgPSBNYXRoLmh5cG90KHAueCwgcC55KTsKICBpZiAocHIgPCBnLnIwICogMC44NSB8fCBwciA+IGcuUiArIDMwKSByZXR1cm4gbnVsbDsKICBjb25zdCBwYSA9IE1hdGguYXRhbjIocC55LCBwLngpOwogIGZvciAoY29uc3QgcGwgb2YgUExBTlMpIHsKICAgIGlmICghcGwubGF5IHx8IHBsLmxheS5hbHBoYSA8IDAuNCkgY29udGludWU7CiAgICBsZXQgZGEgPSBwYSAtIHBsLmxheS5hMDsKICAgIHdoaWxlIChkYSA8IDApIGRhICs9IFRBVTsKICAgIHdoaWxlIChkYSA+PSBUQVUpIGRhIC09IFRBVTsKICAgIGlmIChkYSA8PSBwbC5sYXkuYTEgLSBwbC5sYXkuYTApIHJldHVybiBwbDsKICB9CiAgcmV0dXJuIG51bGw7Cn0KY3YuYWRkRXZlbnRMaXN0ZW5lcigncG9pbnRlcmxlYXZlJywgKCkgPT4geyBob3ZlciA9IG51bGw7IGhvdmVyU2VjID0gbnVsbDsgaGlkZVRpcCgpOyB9KTsKCmZ1bmN0aW9uIGhpdFRlc3QoZSkgewogIGNvbnN0IHIgPSBjdi5nZXRCb3VuZGluZ0NsaWVudFJlY3QoKTsKICBjb25zdCBnID0gZ2VvbSgpOwogIGNvbnN0IHAgPSB0b0Rpc2MoZywgZS5jbGllbnRYIC0gci5sZWZ0LCBlLmNsaWVudFkgLSByLnRvcCk7CiAgY29uc3QgcHIgPSBNYXRoLmh5cG90KHAueCwgcC55KTsKICBjb25zdCBwYSA9IE1hdGguYXRhbjIocC55LCBwLngpOwogIC8qIGRhdGEgbGVuczogZ3JhcGggbm9kZXMgKi8KICBpZiAobGVucyA9PT0gJ2RhdGEnKSB7CiAgICBsZXQgYmVzdDIgPSBudWxsLCBiZDIgPSA5IC8gWjsKICAgIGZvciAoY29uc3QgbiBvZiBHTk9ERVMpIHsKICAgICAgaWYgKCFuLl9vbiB8fCBuLl94ID09PSB1bmRlZmluZWQpIGNvbnRpbnVlOwogICAgICBjb25zdCBkMiA9IE1hdGguaHlwb3Qobi5feCAtIHAueCwgbi5feSAtIHAueSk7CiAgICAgIGlmIChkMiA8IGJkMiArIG4uX2RyKSB7IGJkMiA9IGQyOyBiZXN0MiA9IG47IH0KICAgIH0KICAgIHJldHVybiBiZXN0MjsKICB9CiAgLyogc29sbzogZXZlbnQtbGVkZ2VyIHZlcnRpY2FsIGJhcnMgdGFrZSBwcmlvcml0eSAqLwogIGlmIChzb2xvKSB7CiAgICBmb3IgKGNvbnN0IGMgb2Ygc29sby5jZWxscykgewogICAgICBpZiAoYy5fYnggPT09IHVuZGVmaW5lZCB8fCBjLmRheSA+IFQpIGNvbnRpbnVlOwogICAgICBpZiAoTWF0aC5hYnMocC54IC0gYy5fYngpIDwgNiAvIFogJiYgcC55IDwgNSAvIFogJiYgcC55ID4gLShjLl9iaCArIDkgLyBaKSkgcmV0dXJuIGM7CiAgICB9CiAgfQogIGxldCBiZXN0ID0gbnVsbCwgYmQgPSAxMCAvIFo7CiAgZm9yIChjb25zdCBjIG9mIGNlbGxzKSB7CiAgICBpZiAoYy5feCA9PT0gdW5kZWZpbmVkIHx8IGMuZGF5ID4gVCB8fCAhYy5wLmxheSB8fCBjLnAubGF5LmFscGhhIDwgMC4zIHx8ICFwYXNzRmlsdGVyKGMpKSBjb250aW51ZTsKICAgIGNvbnN0IGQgPSBNYXRoLmh5cG90KGMuX3ggLSBwLngsIGMuX3kgLSBwLnkpOwogICAgaWYgKGQgPCBiZCArIGMuX2RyKSB7IGJkID0gZDsgYmVzdCA9IGM7IH0KICAgIGlmIChtb2RlID09PSAnYmFycycgJiYgIWJlc3QpIHsKICAgICAgLyogcmFkaWFsIGJhciBoaXQ6IHNhbWUgYW5nbGUgKHdpdGhpbiB+M3B4IGFyYyksIHJhZGl1cyB3aXRoaW4gW3IwLCBjZWxsUl0gKi8KICAgICAgbGV0IGRhID0gcGEgLSBjLl9hOwogICAgICB3aGlsZSAoZGEgPiBNYXRoLlBJKSBkYSAtPSBUQVU7CiAgICAgIHdoaWxlIChkYSA8IC1NYXRoLlBJKSBkYSArPSBUQVU7CiAgICAgIGlmIChNYXRoLmFicyhkYSkgKiBwciA8IDQgLyBaICYmIHByID4gZy5yMCAtIDIgJiYgcHIgPCBjLl9yICsgYy5fZHIpIGJlc3QgPSBjOwogICAgfQogIH0KICByZXR1cm4gYmVzdDsKfQpmdW5jdGlvbiBoYW5kbGVDbGljayhlKSB7CiAgaWYgKGxlbnMgPT09ICdkYXRhJykgeyAgICAgICAgICAgICAgICAgICAgICAgICAgIC8qIGdyYXBoOiB0b2dnbGUgMi1ob3AgbmVpZ2hib3VyaG9vZCAqLwogICAgY29uc3QgaGl0ID0gaGl0VGVzdChlKTsKICAgIGdTZWwgPSAoaGl0ICYmIGhpdC5pICE9PSB1bmRlZmluZWQpID8gKGdTZWwgPT09IGhpdC5pID8gbnVsbCA6IGhpdC5pKSA6IG51bGw7CiAgICByZXR1cm47CiAgfQogIGlmIChsZW5zID09PSAndG9rZW5zJykgeyAgICAgICAgICAgICAgICAgICAgICAgICAvKiBkYXkgYmFyIOKGkiB3aGljaCBwbGFucyB3ZXJlIGFjdGl2ZSAqLwogICAgY29uc3QgcjIgPSBjdi5nZXRCb3VuZGluZ0NsaWVudFJlY3QoKTsKICAgIGNvbnN0IGcyID0gZ2VvbSgpOwogICAgY29uc3QgcGQgPSB0b0Rpc2MoZzIsIGUuY2xpZW50WCAtIHIyLmxlZnQsIGUuY2xpZW50WSAtIHIyLnRvcCk7CiAgICBjb25zdCBwcjIgPSBNYXRoLmh5cG90KHBkLngsIHBkLnkpOwogICAgbGV0IHBhMiA9IE1hdGguYXRhbjIocGQueSwgcGQueCk7CiAgICB3aGlsZSAocGEyIDwgQkFTRSkgcGEyICs9IFRBVTsKICAgIGxldCBiaW4gPSBudWxsLCBiZDIgPSAwLjA1OwogICAgZm9yIChjb25zdCBiMiBvZiB0b2tCaW5zKSB7CiAgICAgIGxldCBiYSA9IGIyLmE7IHdoaWxlIChiYSA8IEJBU0UpIGJhICs9IFRBVTsKICAgICAgY29uc3QgZGEyID0gTWF0aC5hYnMocGEyIC0gYmEpOwogICAgICBpZiAoZGEyIDwgYmQyICYmIHByMiA+IGcyLnIwICogMC43ICYmIHByMiA8IGcyLlIgKyAxNCkgeyBiZDIgPSBkYTI7IGJpbiA9IGIyOyB9CiAgICB9CiAgICBpZiAoYmluICYmIHRva1NlbCAhPT0gYmluLmQpIHsgdG9rU2VsID0gYmluLmQ7IHJlbmRlclRva2VuRGF5UGFuZShiaW4pOyB9CiAgICBlbHNlIHsgdG9rU2VsID0gbnVsbDsgcGFuZS5jbGFzc0xpc3QucmVtb3ZlKCdvcGVuJyk7IH0KICAgIHJldHVybjsKICB9CiAgaWYgKGxlbnMgIT09ICd3b3JrJykgcmV0dXJuOyAgICAgICAgICAgICAgICAgICAgIC8qIG90aGVyIGxlbnMgdmlld3M6IGhvdmVyIG9ubHkgaW4gdGhpcyBtb2NrICovCiAgY29uc3QgciA9IGN2LmdldEJvdW5kaW5nQ2xpZW50UmVjdCgpOwogIGNvbnN0IGN4cCA9IGUuY2xpZW50WCAtIHIubGVmdCwgY3lwID0gZS5jbGllbnRZIC0gci50b3A7CiAgLyogMSDigJQgbGVkZ2VyIHJvd3M6IGZpbHRlciB0aGUgcmluZyB0byB0aGF0IHBsYW4gKi8KICBmb3IgKGNvbnN0IHJvdyBvZiBsZWRnZXJSb3dzKSB7CiAgICBpZiAoY3hwID49IHJvdy54ICYmIGN4cCA8PSByb3cueCArIHJvdy53ICYmIGN5cCA+PSByb3cueSAmJiBjeXAgPD0gcm93LnkgKyByb3cuaCkgewogICAgICBpZiAoc29sbyA9PT0gcm93LnApIHsgc2V0U2VsKG51bGwpOyBzb2xvID0gbnVsbDsgfQogICAgICBlbHNlIHsgc29sbyA9IHJvdy5wOyBzZXRTZWwoeyB0eXBlOiAncGxhbicsIHA6IHJvdy5wIH0pOyB9CiAgICAgIHJldHVybjsKICAgIH0KICB9CiAgLyogMiDigJQgbm9kZSAqLwogIGNvbnN0IGhpdCA9IGhpdFRlc3QoZSk7CiAgaWYgKGhpdCkgeyBzZXRTZWwoc2VsICYmIHNlbC5jID09PSBoaXQgPyBudWxsIDogeyB0eXBlOiAnY2VsbCcsIGM6IGhpdCB9KTsgcmV0dXJuOyB9CiAgLyogMyDigJQgc2VjdG9yOiBmb2N1cyB0aGUgcGxhbiBvbiBpdHMgb3duICgxMuKGkjkgKyBldmVudCBsZWRnZXIpICovCiAgY29uc3Qgc2VjID0gc2VjdG9yQXQoZSk7CiAgaWYgKHNlYykgewogICAgaWYgKHNvbG8gPT09IHNlYykgeyBzZXRTZWwobnVsbCk7IHNvbG8gPSBudWxsOyB9CiAgICBlbHNlIHsgc29sbyA9IHNlYzsgc2V0U2VsKHsgdHlwZTogJ3BsYW4nLCBwOiBzZWMgfSk7IH0KICAgIHJldHVybjsKICB9CiAgLyogMy41IOKAlCBjbGlja3MgaW5zaWRlIHRoZSBzb2xvIGV2ZW50LWxlZGdlciBxdWFkcmFudCBhcmUgbm90ICJiYWNrZ3JvdW5kIiAqLwogIGlmIChzb2xvKSB7CiAgICBjb25zdCBnMiA9IGdlb20oKTsKICAgIGNvbnN0IHBkID0gdG9EaXNjKGcyLCBjeHAsIGN5cCk7CiAgICBjb25zdCBwcjIgPSBNYXRoLmh5cG90KHBkLngsIHBkLnkpOwogICAgbGV0IHBhMiA9IE1hdGguYXRhbjIocGQueSwgcGQueCk7CiAgICBpZiAocGEyIDwgMCkgcGEyICs9IFRBVTsKICAgIGlmIChwcjIgPiBnMi5yMCAmJiBwcjIgPCBnMi5SICsgMTIgJiYgcGEyID4gTWF0aC5QSSAmJiBwYTIgPCBNYXRoLlBJICogMS41KSByZXR1cm47CiAgfQogIC8qIDQg4oCUIGJhY2tncm91bmQ6IGhpZGUgcGFuZSwgY2xlYXIgZmlsdGVyICovCiAgc2V0U2VsKG51bGwpOwogIHNvbG8gPSBudWxsOwp9CmZ1bmN0aW9uIHNldFNlbChzKSB7CiAgc2VsID0gczsKICBwaW5uZWQgPSBzICYmIHMudHlwZSA9PT0gJ2NlbGwnID8gcy5jIDogbnVsbDsKICByZW5kZXJQYW5lKCk7Cn0KY29uc3QgcGFuZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdwYW5lJyk7CmZ1bmN0aW9uIHJlbmRlclBhbmUoKSB7CiAgaWYgKCFzZWwpIHsgcGFuZS5jbGFzc0xpc3QucmVtb3ZlKCdvcGVuJyk7IHJldHVybjsgfQogIGNvbnN0IGVzYyA9IHQgPT4gU3RyaW5nKHQpLnJlcGxhY2UoLyYvZywgJyZhbXA7JykucmVwbGFjZSgvPC9nLCAnJmx0OycpOwogIC8qIHRva2VuIHVzYWdlIGFzIGEgaG9yaXpvbnRhbCBncmFkaWVudCBhcmVhIGNoYXJ0OiBjdW11bGF0aXZlIGV2ZW50IHdlaWdodAogICAgIG92ZXIgdGhlIHBsYW4ncyBsaWZlLCBldmVudCBkb3RzIGNvbG91cmVkIGJ5IGtpbmQgKi8KICBjb25zdCB0b2tDaGFydCA9IHAgPT4gewogICAgY29uc3QgZXZzID0gWy4uLnAuY2VsbHNdLnNvcnQoKGEsIGIpID0+IGEuZGF5IC0gYi5kYXkpOwogICAgaWYgKCFldnMubGVuZ3RoKSByZXR1cm4gJyc7CiAgICBjb25zdCBXMiA9IDI4OCwgSDIgPSA5MiwgcGFkVCA9IDEwLCBwYWRCID0gMjAsIHBhZFggPSAyOwogICAgY29uc3QgYiA9IHAuYiwgZSA9IE1hdGgubWF4KHAuZSwgYiArIDAuNSk7CiAgICBjb25zdCB0b3QgPSBldnMucmVkdWNlKChhLCBjKSA9PiBhICsgYy50b2tXLCAwKSB8fCAxOwogICAgY29uc3QgaHVlID0gc3RhdGVIdWUocCk7CiAgICBjb25zdCBYMiA9IGQgPT4gcGFkWCArIE1hdGgubWF4KDAsIE1hdGgubWluKDEsIChkIC0gYikgLyAoZSAtIGIpKSkgKiAoVzIgLSAyICogcGFkWCk7CiAgICBjb25zdCBZMiA9IGYgPT4gKEgyIC0gcGFkQikgLSBmICogKEgyIC0gcGFkQiAtIHBhZFQpOwogICAgbGV0IGN1bSA9IDA7CiAgICBjb25zdCBwdHMgPSBldnMubWFwKGMgPT4geyBjdW0gKz0gYy50b2tXOyByZXR1cm4geyB4OiBYMihjLmRheSksIHk6IFkyKGN1bSAvIHRvdCksIGMgfTsgfSk7CiAgICBjb25zdCBsaW5lID0gJ00nICsgcGFkWCArICcsJyArIFkyKDApICsgcHRzLm1hcChwdCA9PiAnTCcgKyBwdC54LnRvRml4ZWQoMSkgKyAnLCcgKyBwdC55LnRvRml4ZWQoMSkpLmpvaW4oJycpICsKICAgICAgICAgICAgICAgICAnTCcgKyAoVzIgLSBwYWRYKSArICcsJyArIHB0c1twdHMubGVuZ3RoIC0gMV0ueS50b0ZpeGVkKDEpOwogICAgY29uc3QgYXJlYSA9IGxpbmUgKyAnTCcgKyAoVzIgLSBwYWRYKSArICcsJyArIFkyKDApICsgJ1onOwogICAgY29uc3QgZ2lkID0gJ3RnJyArIHAuaTsKICAgIGNvbnN0IGRvdHMgPSBwdHMubWFwKHB0ID0+CiAgICAgICc8Y2lyY2xlIGN4PSInICsgcHQueC50b0ZpeGVkKDEpICsgJyIgY3k9IicgKyBwdC55LnRvRml4ZWQoMSkgKyAnIiByPSInICsgKHB0LmMua2luZCA9PT0gJ2dhdGUnID8gMyA6IDIuMikgKyAnIiBmaWxsPSInICsgKEtJTkRfSFVFW3B0LmMua2luZF0gfHwgJyM4Yjk2ZjInKSArICciLz4nKS5qb2luKCcnKTsKICAgIHJldHVybiAnPGRpdiBjbGFzcz0ic2VjdCI+VE9LRU4gVVNBR0UnICsgKHAubyA/ICcgwrcgJyArIChwLm8gLyAxMCkudG9GaXhlZCgxKSArICdNIG91dCcgOiAnJykgKyAnPC9kaXY+JyArCiAgICAgICc8c3ZnIHdpZHRoPSIxMDAlIiB2aWV3Qm94PSIwIDAgJyArIFcyICsgJyAnICsgSDIgKyAnIiBzdHlsZT0iZGlzcGxheTpibG9jazttYXJnaW4tdG9wOjZweCIgcm9sZT0iaW1nIiBhcmlhLWxhYmVsPSJDdW11bGF0aXZlIHRva2VuIHVzYWdlIG92ZXIgdGhlIHBsYW7igJlzIGxpZmUiPicgKwogICAgICAnPGRlZnM+PGxpbmVhckdyYWRpZW50IGlkPSInICsgZ2lkICsgJyIgeDE9IjAiIHkxPSIwIiB4Mj0iMCIgeTI9IjEiPicgKwogICAgICAnPHN0b3Agb2Zmc2V0PSIwIiBzdG9wLWNvbG9yPSInICsgaHVlICsgJyIgc3RvcC1vcGFjaXR5PSIuMzgiLz4nICsKICAgICAgJzxzdG9wIG9mZnNldD0iMSIgc3RvcC1jb2xvcj0iJyArIGh1ZSArICciIHN0b3Atb3BhY2l0eT0iMCIvPjwvbGluZWFyR3JhZGllbnQ+PC9kZWZzPicgKwogICAgICAnPHBhdGggZD0iJyArIGFyZWEgKyAnIiBmaWxsPSJ1cmwoIycgKyBnaWQgKyAnKSIvPicgKwogICAgICAnPHBhdGggZD0iJyArIGxpbmUgKyAnIiBmaWxsPSJub25lIiBzdHJva2U9IicgKyBodWUgKyAnIiBzdHJva2Utb3BhY2l0eT0iLjg1IiBzdHJva2Utd2lkdGg9IjEuNCIvPicgKwogICAgICBkb3RzICsKICAgICAgJzx0ZXh0IHg9IicgKyBwYWRYICsgJyIgeT0iJyArIChIMiAtIDUpICsgJyIgZmlsbD0icmdiYSgxMjYsMTMzLDE0OSwuOCkiIGZvbnQtc2l6ZT0iOSIgZm9udC1mYW1pbHk9IicgKyBNT05PLnJlcGxhY2UoLyIvZywgIiciKSArICciPicgKyBkYXlEYXRlKGIpICsgJzwvdGV4dD4nICsKICAgICAgJzx0ZXh0IHg9IicgKyAoVzIgLSBwYWRYKSArICciIHk9IicgKyAoSDIgLSA1KSArICciIHRleHQtYW5jaG9yPSJlbmQiIGZpbGw9InJnYmEoMTI2LDEzMywxNDksLjgpIiBmb250LXNpemU9IjkiIGZvbnQtZmFtaWx5PSInICsgTU9OTy5yZXBsYWNlKC8iL2csICInIikgKyAnIj4nICsgZGF5RGF0ZShwLmUpICsgJzwvdGV4dD4nICsKICAgICAgJzwvc3ZnPic7CiAgfTsKICBjb25zdCBwbGFuQmxvY2sgPSBwID0+IHsKICAgIGNvbnN0IGh1ZSA9IHN0YXRlSHVlKHApOwogICAgY29uc3QgbkNlbGxzID0gcC5jZWxscy5sZW5ndGg7CiAgICBjb25zdCBnYXRlcyA9IHAuY2VsbHMuZmlsdGVyKGMgPT4gYy5raW5kID09PSAnZ2F0ZScpLmxlbmd0aDsKICAgIHJldHVybiAnPGRpdiBjbGFzcz0ic2VjdCI+RVhFQ1BMQU48L2Rpdj4nICsKICAgICAgJzxoND4nICsgZXNjKHAuc2x1ZykgKyAnPC9oND4nICsKICAgICAgJzxkaXYgY2xhc3M9ImJhciI+PGkgc3R5bGU9IndpZHRoOicgKyBNYXRoLnJvdW5kKDEwMCAqIHAuZG9uZSAvIHAudG90YWwpICsgJyU7YmFja2dyb3VuZDonICsgaHVlICsgJyI+PC9pPjwvZGl2PicgKwogICAgICAnPGRpdiBjbGFzcz0icm93Ij48c3Bhbj5zdGF0ZTwvc3Bhbj48c3Bhbj4nICsgU1RBVEVbcC5zdF0gKyAnIMK3ICcgKyBwLmRvbmUgKyAnLycgKyBwLnRvdGFsICsgJzwvc3Bhbj48L2Rpdj4nICsKICAgICAgJzxkaXYgY2xhc3M9InJvdyI+PHNwYW4+Ym9ybjwvc3Bhbj48c3Bhbj4nICsgZGF5RGF0ZShwLmIpICsgJzwvc3Bhbj48L2Rpdj4nICsKICAgICAgJzxkaXYgY2xhc3M9InJvdyI+PHNwYW4+bGFzdCBhY3Rpdml0eTwvc3Bhbj48c3Bhbj4nICsgZGF5RGF0ZShwLmUpICsgJzwvc3Bhbj48L2Rpdj4nICsKICAgICAgKHAubyA/ICc8ZGl2IGNsYXNzPSJyb3ciPjxzcGFuPm91dHB1dCB0b2tlbnM8L3NwYW4+PHNwYW4+JyArIChwLm8gLyAxMCkudG9GaXhlZCgxKSArICdNPC9zcGFuPjwvZGl2PicgOiAnJykgKwogICAgICAnPGRpdiBjbGFzcz0icm93Ij48c3Bhbj5ub2Rlczwvc3Bhbj48c3Bhbj4nICsgbkNlbGxzICsgJyAoJyArIGdhdGVzICsgJyBnYXRlcyk8L3NwYW4+PC9kaXY+JyArCiAgICAgIChwLm9kLmxlbmd0aCA/ICc8ZGl2IGNsYXNzPSJyb3ciPjxzcGFuPm9wZW4gZGVjaXNpb25zPC9zcGFuPjxzcGFuPicgKyBwLm9kLm1hcChlc2MpLmpvaW4oJyDCtyAnKSArICc8L3NwYW4+PC9kaXY+JyA6ICcnKSArCiAgICAgIChwLmRlcC5sZW5ndGggPyAnPGRpdiBjbGFzcz0icm93Ij48c3Bhbj5kZXBlbmRzIG9uPC9zcGFuPjxzcGFuPicgKyBwLmRlcC5tYXAoZCA9PiBlc2MoZC5yZXBsYWNlKC8tMjAyNi1cZFxkLVxkXGQkLywgJycpKSkuam9pbignPGJyPicpICsgJzwvc3Bhbj48L2Rpdj4nIDogJycpICsKICAgICAgKHAuZXh0Lmxlbmd0aCA/ICc8ZGl2IGNsYXNzPSJyb3ciPjxzcGFuPmV4dGVuZGVkIGJ5PC9zcGFuPjxzcGFuPicgKyBwLmV4dC5tYXAoZCA9PiBlc2MoZC5yZXBsYWNlKC8tMjAyNi1cZFxkLVxkXGQkLywgJycpKSkuam9pbignPGJyPicpICsgJzwvc3Bhbj48L2Rpdj4nIDogJycpICsKICAgICAgdG9rQ2hhcnQocCkgKwogICAgICAocC50cmFjZWQKICAgICAgICA/ICc8ZGl2IGNsYXNzPSJzZWN0Ij5GQUNUUyAocmVhbCk8L2Rpdj48dWwgY2xhc3M9ImZhY3RzIj4nICsKICAgICAgICAgIFsuLi5wLmNlbGxzXS5zb3J0KChhLCBiKSA9PiBhLmRheSAtIGIuZGF5KS5tYXAoYyA9PgogICAgICAgICAgICAnPGxpJyArIChzZWwuYyA9PT0gYyA/ICcgY2xhc3M9InNlbCInIDogJycpICsgJz48Yj4nICsgZXNjKGMua2V5KSArICc8L2I+IMK3ICcgKyBkYXlEYXRlKGMuZGF5KSArCiAgICAgICAgICAgIChjLmFjdG9yID8gJyDCtyAnICsgZXNjKGMuYWN0b3IpIDogJycpICsgJzwvbGk+Jykuam9pbignJykgKyAnPC91bD4nCiAgICAgICAgOiAnPHAgY2xhc3M9Im5vdGUiPlVudHJhY2VkIHBsYW4g4oCUIG5vZGUgZGVuc2l0eSBpcyBtaWxlc3RvbmUtZGVyaXZlZC4gT25lIGNhbGwgbWFrZXMgaXQgcmVhbDo8YnI+PGNvZGU+cXVlcnlfZmFjdHMoZW50aXR5PSJleGVjcGxhbjonICsgZXNjKHAuc2x1ZykgKyAnIiwgdG9rZW5fYnVkZ2V0PTQwMDApPC9jb2RlPjwvcD4nKTsKICB9OwogIGlmIChzZWwudHlwZSA9PT0gJ2NlbGwnKSB7CiAgICBjb25zdCBjID0gc2VsLmMsIGh1ZSA9IEtJTkRfSFVFW2Mua2luZF0gfHwgJyM4Yjk2ZjInOwogICAgcGFuZS5pbm5lckhUTUwgPQogICAgICAnPGg0PicgKyBlc2MoYy5rZXkpICsgKGMudmVyc2lvbiA+IDEgPyAnIDxzcGFuIHN0eWxlPSJjb2xvcjp2YXIoLS1pbmszKSI+dicgKyBjLnZlcnNpb24gKyAnPC9zcGFuPicgOiAnJykgKyAnPC9oND4nICsKICAgICAgJzxzcGFuIGNsYXNzPSJraW5kY2hpcCI+PGkgc3R5bGU9ImJhY2tncm91bmQ6JyArIGh1ZSArICciPjwvaT4nICsgYy5raW5kICsgKGMucmVhbCA/ICcgwrcgcmVhbCBmYWN0JyA6ICcgwrcgaWxsdXN0cmF0aXZlJykgKyAnPC9zcGFuPicgKwogICAgICAoYy5yZWFsCiAgICAgICAgPyAnPGRpdiBjbGFzcz0icm93Ij48c3Bhbj5zdG9yZWQ8L3NwYW4+PHNwYW4+JyArIGRheURhdGUoYy5kYXkpICsgJzwvc3Bhbj48L2Rpdj4nICsKICAgICAgICAgICc8ZGl2IGNsYXNzPSJyb3ciPjxzcGFuPmFjdG9yPC9zcGFuPjxzcGFuPicgKyBlc2MoYy5hY3RvcikgKyAnPC9zcGFuPjwvZGl2PicgKwogICAgICAgICAgJzxkaXYgY2xhc3M9InJvdyI+PHNwYW4+aG9yaXpvbjwvc3Bhbj48c3Bhbj4nICsgYy5ob3Jpem9uICsgJzwvc3Bhbj48L2Rpdj4nICsKICAgICAgICAgICc8ZGl2IGNsYXNzPSJyb3ciPjxzcGFuPnRva2Vuczwvc3Bhbj48c3Bhbj4nICsgYy50b2tlbnMgKyAnPC9zcGFuPjwvZGl2PicgKwogICAgICAgICAgKGMudmVyc2lvbiA+IDEgPyAnPGRpdiBjbGFzcz0icm93Ij48c3Bhbj5zdXBlcnNlZGVzPC9zcGFuPjxzcGFuPnYnICsgKGMudmVyc2lvbiAtIDEpICsgJyBvZiBzYW1lIGtleTwvc3Bhbj48L2Rpdj4nIDogJycpCiAgICAgICAgOiAnPGRpdiBjbGFzcz0icm93Ij48c3Bhbj5kYXk8L3NwYW4+PHNwYW4+JyArIGRheURhdGUoYy5kYXkpICsgJzwvc3Bhbj48L2Rpdj4nKSArCiAgICAgIHBsYW5CbG9jayhjLnApOwogIH0gZWxzZSB7CiAgICBwYW5lLmlubmVySFRNTCA9IHBsYW5CbG9jayhzZWwucCkgKwogICAgICAoc29sbyA9PT0gc2VsLnAgPyAnPHAgY2xhc3M9Im5vdGUiPlJpbmcgZmlsdGVyZWQgdG8gdGhpcyBwbGFuIOKAlCBjbGljayB0aGUgYmFja2dyb3VuZCB0byBjbGVhci48L3A+JyA6ICcnKTsKICB9CiAgcGFuZS5jbGFzc0xpc3QuYWRkKCdvcGVuJyk7Cn0KYWRkRXZlbnRMaXN0ZW5lcigna2V5ZG93bicsIGUgPT4geyBpZiAoZS5rZXkgPT09ICdFc2NhcGUnKSB7IHNldFNlbChudWxsKTsgc29sbyA9IG51bGw7IHRva1NlbCA9IG51bGw7IH0gfSk7CgovKiB0aWxlczogcHJlc3MgdG8gc3dpdGNoIHRoZSBsZW5zICovCmRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJyN0aWxlcyAudGlsZScpLmZvckVhY2godDIgPT4gewogIHQyLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogICAgbGVucyA9IHQyLmRhdGFzZXQubGVuczsKICAgIGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJyN0aWxlcyAudGlsZScpLmZvckVhY2goeCA9PiB4LnNldEF0dHJpYnV0ZSgnYXJpYS1wcmVzc2VkJywgU3RyaW5nKHggPT09IHQyKSkpOwogICAgc2V0U2VsKG51bGwpOyBzb2xvID0gbnVsbDsgaG92ZXIgPSBudWxsOyBob3ZlclNlYyA9IG51bGw7IGdTZWwgPSBudWxsOyB0b2tTZWwgPSBudWxsOyBoaWRlVGlwKCk7CiAgICBzZXRMZWRnZXIoZmFsc2UpOyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8qIGxlbnMgc3dhcCBoaWRlcyB0aGUgY29tcGxldGVkIGxpc3QgKi8KICAgIGlmIChsZW5zID09PSAnZGF0YScpIHsKICAgICAgLyogYXV0by1maXQgdGhlIHdpbmRvdyB0byB0aGUgZGF0YSBleHRlbnQgc28gc291cmNlIGRhdGVzIHNwcmVhZCB0aGUgY2xvY2sgKi8KICAgICAgY29uc3QgbWluRCA9IE1hdGgubWluKC4uLkdOT0RFUy5tYXAobiA9PiBuLmQpKSAtIDAuNTsKICAgICAgaWYgKFMgPCBtaW5EIC0gMSkgeyByU3RhcnQudmFsdWUgPSBNYXRoLnJvdW5kKChtaW5EIC0gMTEpIC8gKE5PVyAtIDExKSAqIDEwMDApOyBzeW5jV2luZG93KCk7IH0KICAgIH0KICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0b2stdmlld3MnKS5zdHlsZS5kaXNwbGF5ID0gbGVucyA9PT0gJ3Rva2VucycgPyAnZmxleCcgOiAnbm9uZSc7CiAgfSk7Cn0pOwoKLyogdG9rZW5zOiBncmFkaWVudCBsaW5lIGNoYXJ0IG9mIHRoZSB3aG9sZSB3aW5kb3csIHNlbGVjdGVkIGRheSBtYXJrZWQgKi8KZnVuY3Rpb24gdG9rUGFuZUNoYXJ0KHNlbERheSkgewogIGNvbnN0IFcyID0gMjg4LCBIMiA9IDkyLCBwYWRUID0gMTAsIHBhZEIgPSAyMCwgcGFkWCA9IDI7CiAgY29uc3QgZDAgPSBNYXRoLmNlaWwoUyksIGQxID0gTWF0aC5mbG9vcihFKTsKICBjb25zdCBkYXlzID0gW107CiAgbGV0IG1TID0gMC4wMDEsIG1WID0gMC4wMDE7CiAgZm9yIChsZXQgZDMgPSBkMDsgZDMgPD0gZDE7IGQzKyspIHsKICAgIGNvbnN0IHNwID0gVE9LLnNwZW50W2QzXSB8fCAwLCBzdiA9IFRPSy5zYXZlZFtkM10gfHwgMDsKICAgIGRheXMucHVzaCh7IGQ6IGQzLCBzcCwgc3YgfSk7CiAgICBtUyA9IE1hdGgubWF4KG1TLCBzcCk7IG1WID0gTWF0aC5tYXgobVYsIHN2KTsKICB9CiAgaWYgKCFkYXlzLmxlbmd0aCkgcmV0dXJuICcnOwogIGNvbnN0IFgyID0gZDMgPT4gcGFkWCArICgoZDMgLSBkMCkgLyBNYXRoLm1heCgxLCBkMSAtIGQwKSkgKiAoVzIgLSAyICogcGFkWCk7CiAgY29uc3QgWVMgPSB2ID0+IChIMiAtIHBhZEIpIC0gKHYgLyBtUykgKiAoSDIgLSBwYWRCIC0gcGFkVCk7CiAgY29uc3QgWVYgPSB2ID0+IChIMiAtIHBhZEIpIC0gKHYgLyBtVikgKiAoSDIgLSBwYWRCIC0gcGFkVCk7CiAgY29uc3QgbGluZVMgPSBkYXlzLm1hcCgocjIsIGkyKSA9PiAoaTIgPyAnTCcgOiAnTScpICsgWDIocjIuZCkudG9GaXhlZCgxKSArICcsJyArIFlTKHIyLnNwKS50b0ZpeGVkKDEpKS5qb2luKCcnKTsKICBjb25zdCBhcmVhUyA9IGxpbmVTICsgJ0wnICsgWDIoZDEpLnRvRml4ZWQoMSkgKyAnLCcgKyAoSDIgLSBwYWRCKSArICdMJyArIFgyKGQwKS50b0ZpeGVkKDEpICsgJywnICsgKEgyIC0gcGFkQikgKyAnWic7CiAgY29uc3QgbGluZVYgPSBkYXlzLm1hcCgocjIsIGkyKSA9PiAoaTIgPyAnTCcgOiAnTScpICsgWDIocjIuZCkudG9GaXhlZCgxKSArICcsJyArIFlWKHIyLnN2KS50b0ZpeGVkKDEpKS5qb2luKCcnKTsKICBjb25zdCBzZWxYID0gWDIoc2VsRGF5KS50b0ZpeGVkKDEpOwogIGNvbnN0IHNlbFJvdyA9IGRheXMuZmluZChyMiA9PiByMi5kID09PSBzZWxEYXkpOwogIHJldHVybiAnPHN2ZyB3aWR0aD0iMTAwJSIgdmlld0JveD0iMCAwICcgKyBXMiArICcgJyArIEgyICsgJyIgc3R5bGU9ImRpc3BsYXk6YmxvY2s7bWFyZ2luOjEwcHggMCAycHgiIHJvbGU9ImltZyIgYXJpYS1sYWJlbD0iRGFpbHkgdG9rZW4gc3BlbmQgd2l0aCB0aGUgc2VsZWN0ZWQgZGF5IG1hcmtlZCI+JyArCiAgICAnPGRlZnM+PGxpbmVhckdyYWRpZW50IGlkPSJ0cCIgeDE9IjAiIHkxPSIwIiB4Mj0iMCIgeTI9IjEiPicgKwogICAgJzxzdG9wIG9mZnNldD0iMCIgc3RvcC1jb2xvcj0iI2E3OGJmYSIgc3RvcC1vcGFjaXR5PSIuNCIvPjxzdG9wIG9mZnNldD0iMSIgc3RvcC1jb2xvcj0iI2E3OGJmYSIgc3RvcC1vcGFjaXR5PSIwIi8+PC9saW5lYXJHcmFkaWVudD48L2RlZnM+JyArCiAgICAnPHBhdGggZD0iJyArIGFyZWFTICsgJyIgZmlsbD0idXJsKCN0cCkiLz4nICsKICAgICc8cGF0aCBkPSInICsgbGluZVMgKyAnIiBmaWxsPSJub25lIiBzdHJva2U9IiNhNzhiZmEiIHN0cm9rZS1vcGFjaXR5PSIuOSIgc3Ryb2tlLXdpZHRoPSIxLjQiLz4nICsKICAgICc8cGF0aCBkPSInICsgbGluZVYgKyAnIiBmaWxsPSJub25lIiBzdHJva2U9IiMzNGQzOTkiIHN0cm9rZS1vcGFjaXR5PSIuOCIgc3Ryb2tlLXdpZHRoPSIxLjEiLz4nICsKICAgICc8bGluZSB4MT0iJyArIHNlbFggKyAnIiB5MT0iJyArIHBhZFQgKyAnIiB4Mj0iJyArIHNlbFggKyAnIiB5Mj0iJyArIChIMiAtIHBhZEIpICsgJyIgc3Ryb2tlPSJyZ2JhKDIzOCwyNDAsMjQ2LC41KSIgc3Ryb2tlLWRhc2hhcnJheT0iMiAzIi8+JyArCiAgICAoc2VsUm93ID8gJzxjaXJjbGUgY3g9IicgKyBzZWxYICsgJyIgY3k9IicgKyBZUyhzZWxSb3cuc3ApLnRvRml4ZWQoMSkgKyAnIiByPSIzLjIiIGZpbGw9IiNhNzhiZmEiLz4nICsKICAgICAgICAgICAgICAnPGNpcmNsZSBjeD0iJyArIHNlbFggKyAnIiBjeT0iJyArIFlWKHNlbFJvdy5zdikudG9GaXhlZCgxKSArICciIHI9IjIuNCIgZmlsbD0iIzM0ZDM5OSIvPicgOiAnJykgKwogICAgJzx0ZXh0IHg9IicgKyBwYWRYICsgJyIgeT0iJyArIChIMiAtIDUpICsgJyIgZmlsbD0icmdiYSgxMjYsMTMzLDE0OSwuOCkiIGZvbnQtc2l6ZT0iOSIgZm9udC1mYW1pbHk9Im1vbm9zcGFjZSI+JyArIGRheURhdGUoZDApICsgJzwvdGV4dD4nICsKICAgICc8dGV4dCB4PSInICsgKFcyIC0gcGFkWCkgKyAnIiB5PSInICsgKEgyIC0gNSkgKyAnIiB0ZXh0LWFuY2hvcj0iZW5kIiBmaWxsPSJyZ2JhKDEyNiwxMzMsMTQ5LC44KSIgZm9udC1zaXplPSI5IiBmb250LWZhbWlseT0ibW9ub3NwYWNlIj4nICsgZGF5RGF0ZShkMSkgKyAnPC90ZXh0PicgKwogICAgJzwvc3ZnPicgKwogICAgJzxwIGNsYXNzPSJub3RlIiBzdHlsZT0ibWFyZ2luLXRvcDowIj5wdXJwbGUgPSBzcGVudC9kYXkgKG1heCAnICsgbVMudG9GaXhlZCgxKSArICdNKSDCtyBncmVlbiA9IGVzdC4gc2F2ZWQvZGF5IChvd24gc2NhbGUsIG1heCAnICsgKG1WICogMTAwMCkudG9GaXhlZCgwKSArICdrKTwvcD4nOwp9CgovKiB0b2tlbnM6IGRheSBwYW5lIOKAlCB3aGljaCBleGVjcGxhbnMgd2VyZSBhY3RpdmUgb24gdGhlIGNsaWNrZWQgZGF5ICovCmZ1bmN0aW9uIHJlbmRlclRva2VuRGF5UGFuZShiaW4pIHsKICBjb25zdCBlc2MgPSB0MiA9PiBTdHJpbmcodDIpLnJlcGxhY2UoLyYvZywgJyZhbXA7JykucmVwbGFjZSgvPC9nLCAnJmx0OycpOwogIGNvbnN0IGQyID0gYmluLmQ7CiAgY29uc3QgYWN0ID0gUExBTlMKICAgIC5maWx0ZXIocCA9PiBwLmIgPD0gZDIgJiYgZDIgPD0gcC5lKQogICAgLm1hcChwID0+IHsKICAgICAgY29uc3QgZGF5Q2VsbHMgPSBwLmNlbGxzLmZpbHRlcihjID0+IE1hdGguZmxvb3IoYy5kYXkpID09PSBkMikubGVuZ3RoOwogICAgICBjb25zdCBzcCA9IChwLm8gJiYgcC5jZWxscy5sZW5ndGgpID8gKHAubyAvIDEwKSAvIHAuY2VsbHMubGVuZ3RoICogZGF5Q2VsbHMgOiAwOwogICAgICByZXR1cm4geyBwLCBkYXlDZWxscywgc3AgfTsKICAgIH0pCiAgICAuc29ydCgoeCwgeSkgPT4geS5zcCAtIHguc3AgfHwgeS5kYXlDZWxscyAtIHguZGF5Q2VsbHMpOwogIHBhbmUuaW5uZXJIVE1MID0KICAgICc8aDQ+JyArIGRheURhdGUoZDIpICsgJzwvaDQ+JyArCiAgICAnPHNwYW4gY2xhc3M9ImtpbmRjaGlwIj48aSBzdHlsZT0iYmFja2dyb3VuZDojZjVhNjIzIj48L2k+dG9rZW4gZGF5PC9zcGFuPicgKwogICAgJzxkaXYgY2xhc3M9InJvdyI+PHNwYW4+c3BlbnQ8L3NwYW4+PHNwYW4+JyArIGJpbi5zcC50b0ZpeGVkKDEpICsgJ00gZGF5IMK3ICcgKyBiaW4uY3MudG9GaXhlZCgxKSArICdNIGN1bTwvc3Bhbj48L2Rpdj4nICsKICAgICc8ZGl2IGNsYXNzPSJyb3ciPjxzcGFuPnNhdmVkIChlc3QuKTwvc3Bhbj48c3Bhbj4nICsgKGJpbi5zdiAqIDEwMDApLnRvRml4ZWQoMCkgKyAnayBkYXkgwrcgJyArIGJpbi5jdi50b0ZpeGVkKDIpICsgJ00gY3VtPC9zcGFuPjwvZGl2PicgKwogICAgdG9rUGFuZUNoYXJ0KGQyKSArCiAgICAnPGRpdiBjbGFzcz0ic2VjdCI+QUNUSVZFIEVYRUNQTEFOUyDCtyAnICsgYWN0Lmxlbmd0aCArICc8L2Rpdj4nICsKICAgIChhY3QubGVuZ3RoCiAgICAgID8gJzx1bCBjbGFzcz0iZmFjdHMiPicgKyBhY3Quc2xpY2UoMCwgMjIpLm1hcCh4MiA9PgogICAgICAgICAgJzxsaT48YiBzdHlsZT0iY29sb3I6JyArIHN0YXRlSHVlKHgyLnApICsgJyI+4pePPC9iPiA8Yj4nICsgZXNjKHgyLnAuc2hvcnQuc2xpY2UoMCwgMzApKSArICc8L2I+IMK3ICcgKwogICAgICAgICAgU1RBVEVbeDIucC5zdF0gKyAnICcgKyB4Mi5wLmRvbmUgKyAnLycgKyB4Mi5wLnRvdGFsICsKICAgICAgICAgICh4Mi5zcCA/ICcgwrcgficgKyB4Mi5zcC50b0ZpeGVkKDEpICsgJ00nIDogJycpICsKICAgICAgICAgICh4Mi5kYXlDZWxscyA/ICcgwrcgJyArIHgyLmRheUNlbGxzICsgJyBldmVudHMnIDogJycpICsgJzwvbGk+Jykuam9pbignJykgKwogICAgICAgIChhY3QubGVuZ3RoID4gMjIgPyAnPGxpPuKApiArJyArIChhY3QubGVuZ3RoIC0gMjIpICsgJyBtb3JlPC9saT4nIDogJycpICsgJzwvdWw+JwogICAgICA6ICc8cCBjbGFzcz0ibm90ZSI+bm8gcGxhbnMgd2l0aCBhY3Rpdml0eSBzcGFucyBjb3ZlcmluZyB0aGlzIGRheTwvcD4nKSArCiAgICAnPHAgY2xhc3M9Im5vdGUiPnNwZW5kIGF0dHJpYnV0aW9uOiBwbGFuIG91dHB1dC10b2tlbiB0b3RhbHMgZGlzdHJpYnV0ZWQgYWNyb3NzIHRoZWlyIGV2ZW50IGRheXMgKGVzdGltYXRlIHVudGlsIHBlci1kYXkgdG9rZW5fYnVybiBpcyB3aXJlZCk8L3A+JzsKICBwYW5lLmNsYXNzTGlzdC5hZGQoJ29wZW4nKTsKfQoKLyogdG9rZW5zIHN1Yi12aWV3cyAqLwpmdW5jdGlvbiBzZXRUb2tWaWV3KHYpIHsKICB0b2tWaWV3ID0gdjsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYi10b2stY3VtJykuc2V0QXR0cmlidXRlKCdhcmlhLXByZXNzZWQnLCBTdHJpbmcodiA9PT0gJ2N1bScpKTsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYi10b2stZGF5Jykuc2V0QXR0cmlidXRlKCdhcmlhLXByZXNzZWQnLCBTdHJpbmcodiA9PT0gJ2RheScpKTsKfQpkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYi10b2stY3VtJykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiBzZXRUb2tWaWV3KCdjdW0nKSk7CmRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdiLXRvay1kYXknKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHNldFRva1ZpZXcoJ2RheScpKTsKCi8qIGluaXQgKi8Kc3luY1dpbmRvdygpOwoKLyog4pSA4pSAIGxpdmUgd2lyZTogd2hlbiBzZXJ2ZWQgc2FtZS1vcmlnaW4gYnkgdGhlIGRhZW1vbiAoY29uc29sZSBtaXJyb3IpLCBzd2FwCiAgIHRoZSBlbWJlZGRlZCBzbmFwc2hvdCBmb3IgdGhlIHJlYWwgd29yayBib2FyZCArIGdsYW5jZSBtZXRyaWNzLiBGYWlscwogICBzaWxlbnRseSBiYWNrIHRvIHRoZSBzbmFwc2hvdCBhbnl3aGVyZSBlbHNlIChhcnRpZmFjdCwgZmlsZTovLykuIOKUgOKUgCAqLwooYXN5bmMgZnVuY3Rpb24gbGl2ZUluaXQoKSB7CiAgY29uc3QgbnVtID0gdiA9PiAodiA9PT0gbnVsbCB8fCB2ID09PSB1bmRlZmluZWQpID8gJ+KAlCcgOiBOdW1iZXIodikudG9Mb2NhbGVTdHJpbmcoKTsKICB0cnkgewogICAgY29uc3QgciA9IGF3YWl0IGZldGNoKCcvdjEvd29yaz9zb3VyY2U9YWxsJywgeyBoZWFkZXJzOiB7IGFjY2VwdDogJ2FwcGxpY2F0aW9uL2pzb24nIH0gfSk7CiAgICBpZiAoci5vayAmJiAoci5oZWFkZXJzLmdldCgnY29udGVudC10eXBlJykgfHwgJycpLmluY2x1ZGVzKCdqc29uJykpIHsKICAgICAgY29uc3QgaiA9IGF3YWl0IHIuanNvbigpOwogICAgICBjb25zdCBpdGVtcyA9IChqLndvcmsgfHwgW10pLmZpbHRlcih3ID0+CiAgICAgICAgdy5pZCAmJiB3LmlkLnN0YXJ0c1dpdGgoJ2V4ZWNwbGFuOicpICYmCiAgICAgICAgdy5wcm92ZW5hbmNlICYmIHcucHJvdmVuYW5jZS5maXJzdF9hY3Rpdml0eV91bml4X21zICYmCiAgICAgICAgWydpbl9wcm9ncmVzcycsICdjb21wbGV0ZScsICdibG9ja2VkJ10uaW5jbHVkZXMody5zdGF0ZSkpOwogICAgICBpZiAoaXRlbXMubGVuZ3RoID49IDUwKSB7CiAgICAgICAgTk9XID0gTWF0aC5tYXgoNzYsIE1hdGguZmxvb3IoRGF0ZS5ub3coKSAvIDg2NDAwMDAwKSAtIDIwNTgwKTsKICAgICAgICBjb25zdCByYXdzID0gaXRlbXMubWFwKHcgPT4gKHsKICAgICAgICAgIHM6IHcuaWQuc2xpY2UoOSksCiAgICAgICAgICBzdDogdy5zdGF0ZSA9PT0gJ2luX3Byb2dyZXNzJyA/IDEgOiB3LnN0YXRlID09PSAnYmxvY2tlZCcgPyAyIDogMCwKICAgICAgICAgIGQ6IHcubWlsZXN0b25lc19kb25lIHx8IDAsIHQ6IHcubWlsZXN0b25lc190b3RhbCB8fCAxLAogICAgICAgICAgYjogTWF0aC5mbG9vcih3LnByb3ZlbmFuY2UuZmlyc3RfYWN0aXZpdHlfdW5peF9tcyAvIDg2NDAwMDAwKSAtIDIwNTgwLAogICAgICAgICAgZTogTWF0aC5mbG9vcih3LnByb3ZlbmFuY2UubGFzdF9hY3Rpdml0eV91bml4X21zIC8gODY0MDAwMDApIC0gMjA1ODAsCiAgICAgICAgICBvOiBNYXRoLmZsb29yKCgody50b2tlbl9idXJuICYmIHcudG9rZW5fYnVybi5vdXRwdXRfdG9rZW5zKSB8fCAwKSAvIDFlNSksCiAgICAgICAgICBkZXA6IHcuZGVwZW5kc19vbiB8fCBbXSwgZXh0OiB3LmV4dGVuZGVkX2J5IHx8IFtdLCBvZDogdy5vcGVuX2RlY2lzaW9ucyB8fCBbXSwKICAgICAgICB9KSk7CiAgICAgICAgc2V0U2VsKG51bGwpOyBzb2xvID0gbnVsbDsgaG92ZXIgPSBudWxsOyBob3ZlclNlYyA9IG51bGw7IGdTZWwgPSBudWxsOyB0b2tTZWwgPSBudWxsOwogICAgICAgIGxvYWRQbGFucyhyYXdzKTsKICAgICAgICByZWJ1aWxkTGluZWFnZSgpOwogICAgICAgIGJ1aWxkQ2VsbHMoKTsKICAgICAgICByZWZyZXNoVG9rKCk7CiAgICAgICAgLyogdGhpcyBtaXJyb3Igc2VydmVzIHRva2VuX2J1cm46IG51bGwgb24gd29yayBpdGVtcyAoYXR0cmlidXRpb24gbm90CiAgICAgICAgICAgbWF0ZXJpYWxpc2VkIGZyb20gdGhlIGNvcGllZCBzZXNzaW9uLWV2ZW50cykg4oCUIGtlZXAgdGhlIHNuYXBzaG90CiAgICAgICAgICAgdG9rZW4gcHJvZmlsZSByYXRoZXIgdGhhbiBzaG93aW5nIGFuIGFsbC16ZXJvIGxlbnMgKi8KICAgICAgICBpZiAoVE9LLnRvdFMgPCAxICYmIFNOQVBfVE9LLnRvdFMgPj0gMSkgewogICAgICAgICAgVE9LID0gU05BUF9UT0s7CiAgICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGlsZS10b2snKS50ZXh0Q29udGVudCA9IE1hdGgucm91bmQoVE9LLnRvdFMpICsgJ00gKHNuYXApJzsKICAgICAgICB9CiAgICAgICAgZFN0YXJ0Lm1heCA9IGRFbmQubWF4ID0gZGF5RGF0ZShOT1cpOwogICAgICAgIHN5bmNXaW5kb3coKTsKICAgICAgICBkYXRhU3JjID0gJ2xpdmUgwrcgcHJvZC1taXJyb3InOwogICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdnbC1leGVjcGxhbnMnKS50ZXh0Q29udGVudCA9IG51bShqLmNvdW50KTsKICAgICAgICBkb2N1bWVudC5xdWVyeVNlbGVjdG9yKCdbZGF0YS1sZW5zPSJ3b3JrIl0gLm4nKS50ZXh0Q29udGVudCA9IG51bShqLmNvdW50KTsKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZ2wtc3JjJykudGV4dENvbnRlbnQgPSAnbGl2ZSDCtyAnICsgZGF5RGF0ZShOT1cpOwogICAgICB9CiAgICB9CiAgfSBjYXRjaCAoZSkgeyAvKiBub3Qgc2FtZS1vcmlnaW4gd2l0aCBhIGRhZW1vbiDigJQgc25hcHNob3Qgc3RhbmRzICovIH0KICB0cnkgewogICAgY29uc3QgcjIgPSBhd2FpdCBmZXRjaCgnL3YxL2NvbnNvbGUvc3VtbWFyeScsIHsgaGVhZGVyczogeyBhY2NlcHQ6ICdhcHBsaWNhdGlvbi9qc29uJyB9IH0pOwogICAgaWYgKHIyLm9rICYmIChyMi5oZWFkZXJzLmdldCgnY29udGVudC10eXBlJykgfHwgJycpLmluY2x1ZGVzKCdqc29uJykpIHsKICAgICAgY29uc3QgczIgPSBhd2FpdCByMi5qc29uKCk7CiAgICAgIGlmIChzMi5zdG9yZXMpIHsKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZ2wtZmFjdHMnKS50ZXh0Q29udGVudCA9IG51bShzMi5zdG9yZXMuZmFjdHMpOwogICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdnbC1zZXNzaW9ucycpLnRleHRDb250ZW50ID0gbnVtKHMyLnN0b3Jlcy5zZXNzaW9ucyk7CiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RpbGUtc2Vzc2lvbnMnKS50ZXh0Q29udGVudCA9IG51bShzMi5zdG9yZXMuc2Vzc2lvbnMpOwogICAgICB9CiAgICAgIGlmIChzMi5kYWVtb24gJiYgczIuZGFlbW9uLm1jcF9hZ2VudF9jb3VudCAhPT0gdW5kZWZpbmVkKQogICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdnbC1tY3AnKS50ZXh0Q29udGVudCA9IG51bShzMi5kYWVtb24ubWNwX2FnZW50X2NvdW50KTsKICAgICAgaWYgKHMyLmludGVncmF0aW9ucyAhPT0gdW5kZWZpbmVkKSB7CiAgICAgICAgY29uc3QgZ2kgPSBzMi5pbnRlZ3JhdGlvbnM7CiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2dsLWludCcpLnRleHRDb250ZW50ID0KICAgICAgICAgIEFycmF5LmlzQXJyYXkoZ2kpID8gU3RyaW5nKGdpLmxlbmd0aCkKICAgICAgICAgIDogKGdpICYmIHR5cGVvZiBnaSA9PT0gJ29iamVjdCcpID8gbnVtKGdpLmJ1aWx0aW5fcGFja19jb3VudCAhPT0gdW5kZWZpbmVkID8gZ2kuYnVpbHRpbl9wYWNrX2NvdW50IDogT2JqZWN0LmtleXMoZ2kpLmxlbmd0aCkKICAgICAgICAgIDogbnVtKGdpKTsKICAgICAgfQogICAgICBpZiAoczIuZGFlbW9uKQogICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdnbC1lbmdpbmUnKS50ZXh0Q29udGVudCA9IHMyLmRhZW1vbi5kYXRhcGxhbmVfZW5hYmxlZCA/ICdvbicgOiAnb2ZmJzsKICAgIH0KICB9IGNhdGNoIChlKSB7IC8qIHNuYXBzaG90IGdsYW5jZSBzdGFuZHMgKi8gfQogIC8qIGRhdGEgZ3JhcGg6IHBhZ2UgdGhlIFdIT0xFIHZpc2libGUgc3RvcmUgdGhyb3VnaCB0aGUgTTIgbGlzdGluZyByb3V0ZQogICAgICgvdjEvZmFjdHMvbGlzdCDigJQgY3Vyc29yIHBhZ2luYXRpb24sIG5ld2VzdC1maXJzdCwgcmVzZXJ2ZWQgaW5jbHVkZWQgc28gdGhlCiAgICAgZ3JhcGggbWlycm9ycyB0aGUgc3RvcmUpLCB1cCB0byBhIHNhbmUgbm9kZSBjYXAuIEZhbGxzIGJhY2sgdG8gdGhlIGVtYmVkZGVkCiAgICAgc25hcHNob3Qgd2hlbiB0aGUgcm91dGUgaXMgYWJzZW50ICg0MDQgb24gYW4gb2xkZXIgZGFlbW9uKS4gKi8KICB0cnkgewogICAgY29uc3QgTk9ERV9DQVAgPSAyMDAwOwogICAgY29uc3Qgc2VlbiA9IG5ldyBNYXAoKTsKICAgIGxldCB0b3RhbCA9IG51bGwsIGN1cnNvciA9IG51bGwsIGNhcHBlZCA9IGZhbHNlLCBvayA9IGZhbHNlOwogICAgZm9yIChsZXQgcGFnZTIgPSAwOyBwYWdlMiA8IDQwOyBwYWdlMisrKSB7CiAgICAgIGNvbnN0IHUgPSAnL3YxL2ZhY3RzL2xpc3Q/bGltaXQ9MjAwJmluY2x1ZGVfcmVzZXJ2ZWQ9MScgKyAoY3Vyc29yID8gJyZjdXJzb3I9JyArIGVuY29kZVVSSUNvbXBvbmVudChjdXJzb3IpIDogJycpOwogICAgICBjb25zdCByMyA9IGF3YWl0IGZldGNoKHUsIHsgaGVhZGVyczogeyBhY2NlcHQ6ICdhcHBsaWNhdGlvbi9qc29uJyB9IH0pOwogICAgICBpZiAocjMuc3RhdHVzID09PSA0MDQpIGJyZWFrOyAgICAgICAgICAgICAgICAvKiBvbGRlciBkYWVtb24g4oCUIHNuYXBzaG90IHN0YW5kcyAqLwogICAgICBpZiAoIXIzLm9rIHx8ICEocjMuaGVhZGVycy5nZXQoJ2NvbnRlbnQtdHlwZScpIHx8ICcnKS5pbmNsdWRlcygnanNvbicpKSBicmVhazsKICAgICAgY29uc3QgajMgPSBhd2FpdCByMy5qc29uKCk7CiAgICAgIG9rID0gdHJ1ZTsKICAgICAgaWYgKHRvdGFsID09PSBudWxsICYmIGozLnRvdGFsX3Zpc2libGUgIT0gbnVsbCkgdG90YWwgPSBqMy50b3RhbF92aXNpYmxlOwogICAgICBmb3IgKGNvbnN0IGYgb2YgKGozLmZhY3RzIHx8IFtdKSkgewogICAgICAgIGlmICghZi5mYWN0X2lkIHx8ICFmLnN0b3JlZF9hdCB8fCBzZWVuLmhhcyhmLmZhY3RfaWQpKSBjb250aW51ZTsKICAgICAgICBjb25zdCBtcyA9IERhdGUucGFyc2UoZi5zdG9yZWRfYXQpOwogICAgICAgIGlmICghaXNGaW5pdGUobXMpKSBjb250aW51ZTsKICAgICAgICBzZWVuLnNldChmLmZhY3RfaWQsIHsKICAgICAgICAgIGU6IGYuZW50aXR5IHx8ICc/JywgazogZi5rZXkgfHwgJz8nLAogICAgICAgICAgZDogbXMgLyA4NjQwMDAwMCAtIDIwNTgwLAogICAgICAgICAgYTogZi5hY3RvciB8fCBudWxsLCBoOiBmLmhvcml6b25fY2xhc3MgfHwgJ25vbmUnLAogICAgICAgICAgYzogZi5jb25maWRlbmNlID09PSB1bmRlZmluZWQgPyAxIDogZi5jb25maWRlbmNlLCB0OiBmLnRva2VucyB8fCAxMDAsCiAgICAgICAgfSk7CiAgICAgICAgaWYgKHNlZW4uc2l6ZSA+PSBOT0RFX0NBUCkgeyBjYXBwZWQgPSB0cnVlOyBicmVhazsgfQogICAgICB9CiAgICAgIGN1cnNvciA9IGozLm5leHRfY3Vyc29yIHx8IG51bGw7CiAgICAgIGlmIChjYXBwZWQgfHwgIWN1cnNvciB8fCAhajMuaGFzX21vcmUpIGJyZWFrOwogICAgfQogICAgY29uc3QgbGl2ZSA9IFsuLi5zZWVuLnZhbHVlcygpXS5maWx0ZXIobiA9PiBpc0Zpbml0ZShuLmQpICYmIG4uZCA+IDApOwogICAgaWYgKG9rICYmIGxpdmUubGVuZ3RoKSB7CiAgICAgIGdTZWwgPSBudWxsOwogICAgICBsb2FkR3JhcGgobGl2ZSk7CiAgICAgIGdUb3RhbCA9IHRvdGFsOwogICAgICBnQ2FwID0gY2FwcGVkOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGlsZS1kYXRhJykudGV4dENvbnRlbnQgPSBudW0obGl2ZS5sZW5ndGgpOwogICAgfSBlbHNlIGlmICh0b3RhbCkgewogICAgICBnVG90YWwgPSB0b3RhbDsgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvKiBhdCBsZWFzdCByZXBvcnQgdHJ1ZSBzdG9yZSBzaXplICovCiAgICB9CiAgfSBjYXRjaCAoZSkgeyAvKiBlbWJlZGRlZCA2Ni1mYWN0IGdyYXBoIHN0YW5kcyAqLyB9Cn0pKCk7Cn0pKCk7Cjwvc2NyaXB0Pgo=';

  return {
    PAGES: PAGES,
    DESTS: DESTS,
    RINGS_HTML_B64: RINGS_HTML_B64,
    LEGACY_IDS: LEGACY_IDS,
    PRO_PORTED_IDS: PRO_PORTED_IDS,
    LEGACY_PORT: LEGACY_PORT,
    MUTATING_ACTIONS: MUTATING_ACTIONS,
    CONTROL_CAPABILITY_MAP: CONTROL_CAPABILITY_MAP,
    CONTROL_DIFF: CONTROL_DIFF,
    JSX_PORT: JSX_PORT,
    CruxDemo: CruxDemo,
    // Exposed for tests / render composition.
    _helpers: { workStageOf: workStageOf, laneWeightControls: laneWeightControls, amrLaneToggles: amrLaneToggles }
  };
});
