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
    'cx-facts': page('cx-facts', 'memory', 'Facts', 'the durable record — grouped by entity prefix', { load: { endpoint: '/v1/console/facts?top_k=100', build: buildFacts } }),
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
    { id: 'rings', label: 'Rings', icon: 'rings', key: '8', sub: 'Rings-clock landing prototype (embedded snapshot).' }
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
    'cx-facts':         { legacy: { projection: 'cascade' }, v2_present: ['live /v1/console/facts', 'entity-prefix groups', 'search'], v2_missing_read: [], v2_gated_write: [] },
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
  var RINGS_HTML_B64 = 'PCFkb2N0eXBlIGh0bWw+CjxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KPHRpdGxlPkNydXggQ29uc29sZSDigJQgUmluZ3MgbGFuZGluZyBtb2NrPC90aXRsZT4KPHN0eWxlPgo6cm9vdCwgOnJvb3RbZGF0YS10aGVtZT0ibGlnaHQiXSwgOnJvb3RbZGF0YS10aGVtZT0iZGFyayJdIHsKICAtLWJnMDogIzBiMGQxMzsgLS1iZzE6ICMxMjE1MWQ7CiAgLS1wYW5lbDogcmdiYSgyNTUsMjU1LDI1NSwuMDM1KTsgLS1wYW5lbC1zdHJvbmc6IHJnYmEoMjU1LDI1NSwyNTUsLjA2KTsKICAtLWhhaXJsaW5lOiByZ2JhKDI1NSwyNTUsMjU1LC4wOSk7IC0taGFpcmxpbmUtc3Ryb25nOiByZ2JhKDI1NSwyNTUsMjU1LC4xOCk7CiAgLS1pbms6ICNlZWYwZjY7IC0taW5rMjogI2I2YmNjOTsgLS1pbmszOiAjN2U4NTk1OwogIC0tYWNjZW50OiAjOGI5NmYyOyAtLWFjY2VudC1kZWVwOiAjNWU2YWQyOwogIC0tdGVhbDogIzJkZDRiZjsgLS1hbWJlcjogI2Y1YTYyMzsgLS12aW9sZXQ6ICNhNzhiZmE7IC0tZXJyOiAjZWY0NDQ0OwogIC0tZm9udC1zYW5zOiAnUHVibGljIFNhbnMnLCB1aS1zYW5zLXNlcmlmLCBzeXN0ZW0tdWksIC1hcHBsZS1zeXN0ZW0sICdTZWdvZSBVSScsIFJvYm90bywgQXJpYWwsIHNhbnMtc2VyaWY7CiAgLS1mb250LW1vbm86ICdKZXRCcmFpbnMgTW9ubycsIHVpLW1vbm9zcGFjZSwgU0ZNb25vLVJlZ3VsYXIsIE1lbmxvLCBDb25zb2xhcywgbW9ub3NwYWNlOwogIGNvbG9yLXNjaGVtZTogZGFyazsKfQoqIHsgYm94LXNpemluZzogYm9yZGVyLWJveDsgfQpodG1sLCBib2R5IHsgbWFyZ2luOiAwOyB9CmJvZHkgewogIGJhY2tncm91bmQ6IHJhZGlhbC1ncmFkaWVudCgxMjAwcHggNzAwcHggYXQgNzAlIC0xMCUsIHJnYmEoOTQsMTA2LDIxMCwuMTApLCB0cmFuc3BhcmVudCA2MCUpLCB2YXIoLS1iZzApOwogIGNvbG9yOiB2YXIoLS1pbmspOyBmb250LWZhbWlseTogdmFyKC0tZm9udC1zYW5zKTsgbGluZS1oZWlnaHQ6IDEuNTU7CiAgLXdlYmtpdC1mb250LXNtb290aGluZzogYW50aWFsaWFzZWQ7Cn0KYSB7IGNvbG9yOiB2YXIoLS1hY2NlbnQpOyB0ZXh0LWRlY29yYXRpb246IG5vbmU7IH0KYTpob3ZlciB7IHRleHQtZGVjb3JhdGlvbjogdW5kZXJsaW5lOyB0ZXh0LXVuZGVybGluZS1vZmZzZXQ6IDNweDsgfQpjb2RlIHsgZm9udC1mYW1pbHk6IHZhcigtLWZvbnQtbW9ubyk7IGZvbnQtc2l6ZTogLjllbTsgYmFja2dyb3VuZDogdmFyKC0tcGFuZWwtc3Ryb25nKTsgcGFkZGluZzogLjFlbSAuMzVlbTsgYm9yZGVyLXJhZGl1czogNXB4OyB9CgovKiDilIDilIAgY29uc29sZSB0b3BiYXIg4pSA4pSAICovCiN0b3BiYXIgewogIGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGdhcDogMTJweDsKICBwYWRkaW5nOiAxMnB4IGNsYW1wKDE2cHgsIDN2dywgMzJweCk7CiAgYm9yZGVyLWJvdHRvbTogMXB4IHNvbGlkIHZhcigtLWhhaXJsaW5lKTsKICBmb250LWZhbWlseTogdmFyKC0tZm9udC1tb25vKTsgZm9udC1zaXplOiAxMnB4OyBjb2xvcjogdmFyKC0taW5rMyk7Cn0KI3RvcGJhciAuYnJhbmQgeyBmb250OiA4MDAgMTVweCB2YXIoLS1mb250LXNhbnMpOyBjb2xvcjogdmFyKC0taW5rKTsgbGV0dGVyLXNwYWNpbmc6IC0uMDFlbTsgfQojdG9wYmFyIC5icmFuZCBzcGFuIHsgY29sb3I6IHZhcigtLWluazMpOyBmb250LXdlaWdodDogNTAwOyB9CiN0b3BiYXIgLnBpbGwgewogIGRpc3BsYXk6IGlubGluZS1mbGV4OyBhbGlnbi1pdGVtczogY2VudGVyOyBnYXA6IDdweDsKICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1oYWlybGluZS1zdHJvbmcpOyBib3JkZXItcmFkaXVzOiA5OTlweDsgcGFkZGluZzogM3B4IDEycHg7Cn0KI3RvcGJhciAucGlsbCAuZG90IHsgd2lkdGg6IDdweDsgaGVpZ2h0OiA3cHg7IGJvcmRlci1yYWRpdXM6IDUwJTsgYmFja2dyb3VuZDogdmFyKC0tdGVhbCk7IH0KI3RvcGJhciAuc3AgeyBtYXJnaW4tbGVmdDogYXV0bzsgfQoKLyog4pSA4pSAIGxlbnMgdGlsZXM6IGNvbXBhY3Qgc3RhY2ssIHRvcC1yaWdodCBvdmVyIHRoZSBzdGFnZSDilIDilIAgKi8KI3RpbGVzIHsKICBwb3NpdGlvbjogYWJzb2x1dGU7IHRvcDogMTRweDsgcmlnaHQ6IDE2cHg7IHotaW5kZXg6IDE1OwogIGRpc3BsYXk6IGZsZXg7IGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47IGdhcDogNnB4OyB3aWR0aDogMjAwcHg7Cn0KLnRpbGUgewogIHRleHQtYWxpZ246IGxlZnQ7IGN1cnNvcjogcG9pbnRlcjsKICBkaXNwbGF5OiBmbGV4OyBhbGlnbi1pdGVtczogYmFzZWxpbmU7IGdhcDogOHB4OwogIGJhY2tncm91bmQ6IHJnYmEoMTQsMTYsMjQsLjg4KTsgYm9yZGVyOiAxcHggc29saWQgdmFyKC0taGFpcmxpbmUpOwogIGJvcmRlci1yYWRpdXM6IDEwcHg7IHBhZGRpbmc6IDdweCAxMnB4OwogIGNvbG9yOiB2YXIoLS1pbmsyKTsgZm9udC1mYW1pbHk6IHZhcigtLWZvbnQtc2Fucyk7CiAgdHJhbnNpdGlvbjogYm9yZGVyLWNvbG9yIC4xNXMsIGJhY2tncm91bmQgLjE1czsKfQoudGlsZTpob3ZlciB7IGJvcmRlci1jb2xvcjogdmFyKC0taGFpcmxpbmUtc3Ryb25nKTsgYmFja2dyb3VuZDogcmdiYSgyMCwyMywzMywuOTUpOyB9Ci50aWxlOmZvY3VzLXZpc2libGUgeyBvdXRsaW5lOiAycHggc29saWQgdmFyKC0tYWNjZW50KTsgb3V0bGluZS1vZmZzZXQ6IDJweDsgfQoudGlsZVthcmlhLXByZXNzZWQ9InRydWUiXSB7IGJvcmRlci1jb2xvcjogcmdiYSgxMzksMTUwLDI0MiwuNik7IGJhY2tncm91bmQ6IHJnYmEoMTM5LDE1MCwyNDIsLjE0KTsgfQoudGlsZSAudCB7IGZvbnQ6IDYwMCAxMnB4IHZhcigtLWZvbnQtc2Fucyk7IGNvbG9yOiB2YXIoLS1pbmsyKTsgZGlzcGxheTogZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsgZ2FwOiA3cHg7IGZsZXg6IDE7IH0KLnRpbGUgLnQgaSB7IHdpZHRoOiA3cHg7IGhlaWdodDogN3B4OyBib3JkZXItcmFkaXVzOiA1MCU7IGRpc3BsYXk6IGlubGluZS1ibG9jazsgfQoudGlsZSAubiB7IGZvbnQ6IDcwMCAxNHB4IHZhcigtLWZvbnQtc2Fucyk7IGNvbG9yOiB2YXIoLS1pbmspOyBsZXR0ZXItc3BhY2luZzogLS4wMWVtOyBmb250LXZhcmlhbnQtbnVtZXJpYzogdGFidWxhci1udW1zOyB9Ci50aWxlIC5zIHsgZGlzcGxheTogbm9uZTsgfQoudGlsZVthcmlhLXByZXNzZWQ9InRydWUiXSAudCB7IGNvbG9yOiB2YXIoLS1hY2NlbnQpOyB9CkBtZWRpYSAobWF4LXdpZHRoOiA3NjBweCkgeyAjdGlsZXMgeyBwb3NpdGlvbjogc3RhdGljOyBmbGV4LWRpcmVjdGlvbjogcm93OyBmbGV4LXdyYXA6IHdyYXA7IHdpZHRoOiBhdXRvOyBtYXJnaW46IDEwcHggMTZweCAwOyB9IH0KCi8qIGljb24gYnV0dG9ucyArIGRhdGUgcGlja2VycyAqLwouc3RhZ2ViYXIgYnV0dG9uLmljIHsgZm9udC1zaXplOiAxM3B4OyBwYWRkaW5nOiA0cHggOXB4OyBtaW4td2lkdGg6IDMwcHg7IHRleHQtYWxpZ246IGNlbnRlcjsgfQouc3RhZ2ViYXIgaW5wdXRbdHlwZT1kYXRlXSB7CiAgZm9udDogNjAwIDExcHggdmFyKC0tZm9udC1tb25vKTsgY29sb3I6IHZhcigtLWluazIpOwogIGJhY2tncm91bmQ6IHJnYmEoMjU1LDI1NSwyNTUsLjA3KTsgYm9yZGVyOiAxcHggc29saWQgdmFyKC0taGFpcmxpbmUtc3Ryb25nKTsKICBib3JkZXItcmFkaXVzOiA3cHg7IHBhZGRpbmc6IDNweCA2cHg7IGNvbG9yLXNjaGVtZTogZGFyazsKfQoKc2VjdGlvbi5jb25jZXB0IHsgbWF4LXdpZHRoOiAxNTYwcHg7IG1hcmdpbjogMjZweCBhdXRvIDA7IHBhZGRpbmc6IDAgY2xhbXAoMTJweCwgM3Z3LCAzNnB4KTsgfQovKiBkZS1jYXJkZWQ6IHRoZSByaW5ncyBzaXQgZGlyZWN0bHkgb24gdGhlIHBhZ2UgKi8KLnN0YWdld3JhcCB7CiAgcG9zaXRpb246IHJlbGF0aXZlOyBib3JkZXI6IDA7IGJvcmRlci1yYWRpdXM6IDA7CiAgYmFja2dyb3VuZDogdHJhbnNwYXJlbnQ7CiAgb3ZlcmZsb3c6IGhpZGRlbjsgYm94LXNoYWRvdzogbm9uZTsKfQouc3RhZ2V3cmFwIGNhbnZhcyB7IGRpc3BsYXk6IGJsb2NrOyB3aWR0aDogMTAwJTsgaGVpZ2h0OiBjbGFtcCg1MjBweCwgNzR2aCwgODIwcHgpOyBjdXJzb3I6IGNyb3NzaGFpcjsgdG91Y2gtYWN0aW9uOiBub25lOyB9Ci5zdGFnZWJhciB7CiAgcG9zaXRpb246IGFic29sdXRlOyBsZWZ0OiAwOyByaWdodDogMDsgYm90dG9tOiAwOwogIGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGdhcDogOXB4OyBmbGV4LXdyYXA6IHdyYXA7CiAgcGFkZGluZzogMTBweCAxNnB4OwogIGZvbnQtZmFtaWx5OiB2YXIoLS1mb250LW1vbm8pOyBmb250LXNpemU6IDExLjVweDsgY29sb3I6IHZhcigtLWluazMpOwogIGJhY2tncm91bmQ6IGxpbmVhci1ncmFkaWVudCh0cmFuc3BhcmVudCwgcmdiYSgxMSwxMywxOSwuODUpIDQ1JSk7CiAgcG9pbnRlci1ldmVudHM6IG5vbmU7Cn0KLnN0YWdlYmFyID4gKiB7IHBvaW50ZXItZXZlbnRzOiBhdXRvOyB9Ci5zdGFnZWJhciAuZ3JwIHsgZGlzcGxheTogZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsgZ2FwOiA2cHg7IHdoaXRlLXNwYWNlOiBub3dyYXA7IH0KLnN0YWdlYmFyIC5oaW50IHsgbWFyZ2luLWxlZnQ6IGF1dG87IHRleHQtYWxpZ246IHJpZ2h0OyB9Ci5zdGFnZWJhciBidXR0b24gewogIGZvbnQ6IDYwMCAxMS41cHggdmFyKC0tZm9udC1tb25vKTsgY29sb3I6IHZhcigtLWluazIpOwogIGJhY2tncm91bmQ6IHJnYmEoMjU1LDI1NSwyNTUsLjA3KTsgYm9yZGVyOiAxcHggc29saWQgdmFyKC0taGFpcmxpbmUtc3Ryb25nKTsKICBib3JkZXItcmFkaXVzOiA3cHg7IHBhZGRpbmc6IDRweCAxMXB4OyBjdXJzb3I6IHBvaW50ZXI7Cn0KLnN0YWdlYmFyIGJ1dHRvbjpob3ZlciB7IGNvbG9yOiB2YXIoLS1pbmspOyBiYWNrZ3JvdW5kOiByZ2JhKDI1NSwyNTUsMjU1LC4xMik7IH0KLnN0YWdlYmFyIGJ1dHRvblthcmlhLXByZXNzZWQ9InRydWUiXSB7IGNvbG9yOiB2YXIoLS1hY2NlbnQpOyBib3JkZXItY29sb3I6IHJnYmEoMTM5LDE1MCwyNDIsLjU1KTsgYmFja2dyb3VuZDogcmdiYSgxMzksMTUwLDI0MiwuMTIpOyB9Ci5zdGFnZWJhciBidXR0b246Zm9jdXMtdmlzaWJsZSwgLnN0YWdlYmFyIGlucHV0OmZvY3VzLXZpc2libGUsIC5zdGFnZWJhciBzZWxlY3Q6Zm9jdXMtdmlzaWJsZSB7IG91dGxpbmU6IDJweCBzb2xpZCB2YXIoLS1hY2NlbnQpOyBvdXRsaW5lLW9mZnNldDogMnB4OyB9Ci5zdGFnZWJhciBzZWxlY3QgewogIGZvbnQ6IDYwMCAxMS41cHggdmFyKC0tZm9udC1tb25vKTsgY29sb3I6IHZhcigtLWluazIpOwogIGJhY2tncm91bmQ6IHJnYmEoMjU1LDI1NSwyNTUsLjA3KTsgYm9yZGVyOiAxcHggc29saWQgdmFyKC0taGFpcmxpbmUtc3Ryb25nKTsKICBib3JkZXItcmFkaXVzOiA3cHg7IHBhZGRpbmc6IDRweCA4cHg7IGN1cnNvcjogcG9pbnRlcjsKfQouc3RhZ2ViYXIgc2VsZWN0OmhvdmVyIHsgY29sb3I6IHZhcigtLWluayk7IGJhY2tncm91bmQ6IHJnYmEoMjU1LDI1NSwyNTUsLjEyKTsgfQouc3RhZ2ViYXIgaW5wdXRbdHlwZT1yYW5nZV0geyBhY2NlbnQtY29sb3I6IHZhcigtLWFjY2VudC1kZWVwKTsgd2lkdGg6IG1pbigxNTBweCwgMTd2dyk7IH0KLnN0YWdlYmFyIGxhYmVsIHsgY29sb3I6IHZhcigtLWluazMpOyB9Ci5zdGFnZWJhciAuY2hpcCB7IGJhY2tncm91bmQ6IHJnYmEoMTM5LDE1MCwyNDIsLjE0KTsgYm9yZGVyOiAxcHggc29saWQgcmdiYSgxMzksMTUwLDI0MiwuNCk7IGNvbG9yOiB2YXIoLS1hY2NlbnQpOyBib3JkZXItcmFkaXVzOiA5OTlweDsgcGFkZGluZzogM3B4IDExcHg7IGZvbnQtd2VpZ2h0OiA2MDA7IHdoaXRlLXNwYWNlOiBub3dyYXA7IH0KCi5jbm90ZXMgeyBtYXgtd2lkdGg6IDExMDBweDsgbWFyZ2luOiAyMHB4IGF1dG8gMDsgcGFkZGluZzogMCA0cHg7IGRpc3BsYXk6IGdyaWQ7IGdyaWQtdGVtcGxhdGUtY29sdW1uczogbWlubWF4KDMwMHB4LCAzZnIpIG1pbm1heCgyODBweCwgMmZyKTsgZ2FwOiAyMHB4IDQ0cHg7IH0KQG1lZGlhIChtYXgtd2lkdGg6IDg2MHB4KSB7IC5jbm90ZXMgeyBncmlkLXRlbXBsYXRlLWNvbHVtbnM6IDFmcjsgfSB9Ci5jbm90ZXMgaDMgeyBmb250LXNpemU6IDEzcHg7IGZvbnQtd2VpZ2h0OiA3MDA7IGxldHRlci1zcGFjaW5nOiAuMDJlbTsgY29sb3I6IHZhcigtLWluazIpOyBtYXJnaW46IDAgMCAxMHB4OyB9Ci5jbm90ZXMgLndoeSBwIHsgY29sb3I6IHZhcigtLWluazIpOyBmb250LXNpemU6IDE0LjVweDsgbWFyZ2luOiAwIDAgMTBweDsgbWF4LXdpZHRoOiA2NGNoOyB9Ci5jbm90ZXMgLndoeSBwIGIgeyBjb2xvcjogdmFyKC0taW5rKTsgZm9udC13ZWlnaHQ6IDY1MDsgfQp0YWJsZS5tYXAgeyBib3JkZXItY29sbGFwc2U6IGNvbGxhcHNlOyB3aWR0aDogMTAwJTsgZm9udC1zaXplOiAxM3B4OyB9CnRhYmxlLm1hcCB0ZCB7IHBhZGRpbmc6IDZweCAxMHB4IDZweCAwOyB2ZXJ0aWNhbC1hbGlnbjogdG9wOyBib3JkZXItYm90dG9tOiAxcHggc29saWQgdmFyKC0taGFpcmxpbmUpOyB9CnRhYmxlLm1hcCB0ZDpmaXJzdC1jaGlsZCB7IGZvbnQtZmFtaWx5OiB2YXIoLS1mb250LW1vbm8pOyBmb250LXNpemU6IDExLjVweDsgY29sb3I6IHZhcigtLWluazMpOyB3aGl0ZS1zcGFjZTogbm93cmFwOyB3aWR0aDogMSU7IHBhZGRpbmctcmlnaHQ6IDE2cHg7IH0KdGFibGUubWFwIHRkOmxhc3QtY2hpbGQgeyBjb2xvcjogdmFyKC0taW5rMik7IH0KdGFibGUubWFwIHRkOmxhc3QtY2hpbGQgYiB7IGNvbG9yOiB2YXIoLS1pbmspOyBmb250LXdlaWdodDogNjAwOyB9CgovKiDilIDilIAgc2xpZGUtb3V0IGRldGFpbCBwYW5lIOKUgOKUgCAqLwojcGFuZSB7CiAgcG9zaXRpb246IGFic29sdXRlOyB0b3A6IDA7IHJpZ2h0OiAwOyBib3R0b206IDA7IHotaW5kZXg6IDIwOwogIHdpZHRoOiBtaW4oMzMwcHgsIDg2dncpOwogIGJhY2tncm91bmQ6IHJnYmEoMTQsMTYsMjQsLjk3KTsKICBib3JkZXItbGVmdDogMXB4IHNvbGlkIHZhcigtLWhhaXJsaW5lLXN0cm9uZyk7CiAgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKDEwNSUpOwogIHRyYW5zaXRpb246IHRyYW5zZm9ybSAuMzBzIGN1YmljLWJlemllciguMTYsMSwuMywxKTsKICBwYWRkaW5nOiAxOHB4IDE4cHggNjBweDsKICBvdmVyZmxvdy15OiBhdXRvOwogIGZvbnQtZmFtaWx5OiB2YXIoLS1mb250LW1vbm8pOyBmb250LXNpemU6IDExLjVweDsgbGluZS1oZWlnaHQ6IDEuNjsgY29sb3I6IHZhcigtLWluazIpOwp9CiNwYW5lLm9wZW4geyB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoMCk7IH0KI3BhbmUgaDQgeyBmb250OiA3MDAgMTNweCB2YXIoLS1mb250LW1vbm8pOyBjb2xvcjogdmFyKC0taW5rKTsgbWFyZ2luOiAwIDAgMnB4OyBvdmVyZmxvdy13cmFwOiBhbnl3aGVyZTsgfQojcGFuZSAua2luZGNoaXAgeyBkaXNwbGF5OiBpbmxpbmUtZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsgZ2FwOiA2cHg7IGZvbnQtc2l6ZTogMTAuNXB4OyBjb2xvcjogdmFyKC0taW5rMyk7CiAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0taGFpcmxpbmUtc3Ryb25nKTsgYm9yZGVyLXJhZGl1czogOTk5cHg7IHBhZGRpbmc6IDJweCAxMHB4OyBtYXJnaW46IDZweCAwIDEycHg7IH0KI3BhbmUgLmtpbmRjaGlwIGkgeyB3aWR0aDogN3B4OyBoZWlnaHQ6IDdweDsgYm9yZGVyLXJhZGl1czogNTAlOyBkaXNwbGF5OiBpbmxpbmUtYmxvY2s7IH0KI3BhbmUgLnJvdyB7IGRpc3BsYXk6IGZsZXg7IGp1c3RpZnktY29udGVudDogc3BhY2UtYmV0d2VlbjsgZ2FwOiAxMnB4OyBwYWRkaW5nOiA1cHggMDsgYm9yZGVyLWJvdHRvbTogMXB4IHNvbGlkIHZhcigtLWhhaXJsaW5lKTsgfQojcGFuZSAucm93IHNwYW46Zmlyc3QtY2hpbGQgeyBjb2xvcjogdmFyKC0taW5rMyk7IHdoaXRlLXNwYWNlOiBub3dyYXA7IH0KI3BhbmUgLnJvdyBzcGFuOmxhc3QtY2hpbGQgeyBjb2xvcjogdmFyKC0taW5rMik7IHRleHQtYWxpZ246IHJpZ2h0OyBvdmVyZmxvdy13cmFwOiBhbnl3aGVyZTsgfQojcGFuZSAuc2VjdCB7IG1hcmdpbi10b3A6IDE2cHg7IGZvbnQ6IDcwMCAxMC41cHggdmFyKC0tZm9udC1tb25vKTsgbGV0dGVyLXNwYWNpbmc6IC4wNGVtOyBjb2xvcjogdmFyKC0taW5rMyk7IH0KI3BhbmUgLmJhciB7IGhlaWdodDogNXB4OyBib3JkZXItcmFkaXVzOiAzcHg7IGJhY2tncm91bmQ6IHJnYmEoMjU1LDI1NSwyNTUsLjA4KTsgbWFyZ2luOiA4cHggMCA0cHg7IG92ZXJmbG93OiBoaWRkZW47IH0KI3BhbmUgLmJhciBpIHsgZGlzcGxheTogYmxvY2s7IGhlaWdodDogMTAwJTsgYm9yZGVyLXJhZGl1czogM3B4OyB9CiNwYW5lIHVsLmZhY3RzIHsgbGlzdC1zdHlsZTogbm9uZTsgbWFyZ2luOiA4cHggMCAwOyBwYWRkaW5nOiAwOyB9CiNwYW5lIHVsLmZhY3RzIGxpIHsgcGFkZGluZzogNHB4IDAgNHB4IDE0cHg7IHBvc2l0aW9uOiByZWxhdGl2ZTsgZm9udC1zaXplOiAxMC41cHg7IGNvbG9yOiB2YXIoLS1pbmszKTsgfQojcGFuZSB1bC5mYWN0cyBsaTo6YmVmb3JlIHsgY29udGVudDogJyc7IHBvc2l0aW9uOiBhYnNvbHV0ZTsgbGVmdDogMnB4OyB0b3A6IDlweDsgd2lkdGg6IDZweDsgaGVpZ2h0OiA2cHg7IGJvcmRlci1yYWRpdXM6IDUwJTsgYmFja2dyb3VuZDogdmFyKC0tYWNjZW50KTsgb3BhY2l0eTogLjY7IH0KI3BhbmUgdWwuZmFjdHMgbGkuc2VsIHsgY29sb3I6IHZhcigtLWluayk7IH0KI3BhbmUgdWwuZmFjdHMgbGkgYiB7IGNvbG9yOiB2YXIoLS1pbmsyKTsgZm9udC13ZWlnaHQ6IDYwMDsgfQojcGFuZSAubm90ZSB7IG1hcmdpbi10b3A6IDEycHg7IGZvbnQtc2l6ZTogMTAuNXB4OyBjb2xvcjogdmFyKC0taW5rMyk7IH0KQG1lZGlhIChwcmVmZXJzLXJlZHVjZWQtbW90aW9uOiByZWR1Y2UpIHsgI3BhbmUgeyB0cmFuc2l0aW9uOiBub25lOyB9IH0KCiN0aXAgewogIHBvc2l0aW9uOiBmaXhlZDsgei1pbmRleDogOTA7IHBvaW50ZXItZXZlbnRzOiBub25lOwogIGJhY2tncm91bmQ6IHJnYmEoMTgsMjAsMjksLjk3KTsgYm9yZGVyOiAxcHggc29saWQgdmFyKC0taGFpcmxpbmUtc3Ryb25nKTsKICBib3JkZXItcmFkaXVzOiAxMHB4OyBwYWRkaW5nOiA4cHggMTJweDsKICBmb250LWZhbWlseTogdmFyKC0tZm9udC1tb25vKTsgZm9udC1zaXplOiAxMS41cHg7IGxpbmUtaGVpZ2h0OiAxLjU1OwogIGNvbG9yOiB2YXIoLS1pbmsyKTsgYm94LXNoYWRvdzogMCAxMHB4IDMwcHggcmdiYSgwLDAsMCwuNSk7CiAgbWF4LXdpZHRoOiAzMjBweDsgb3BhY2l0eTogMDsgdHJhbnNpdGlvbjogb3BhY2l0eSAuMTJzOwp9CiN0aXAgYiB7IGNvbG9yOiB2YXIoLS1pbmspOyBmb250LXdlaWdodDogNjAwOyB9CiN0aXAgLmsgeyBjb2xvcjogdmFyKC0taW5rMyk7IH0KZm9vdGVyIHsgbWF4LXdpZHRoOiAxMTAwcHg7IG1hcmdpbjogNDhweCBhdXRvIDA7IHBhZGRpbmc6IDIwcHggY2xhbXAoMTZweCwgNHZ3LCA0MHB4KSA1MHB4OyBib3JkZXItdG9wOiAxcHggc29saWQgdmFyKC0taGFpcmxpbmUpOyBmb250LWZhbWlseTogdmFyKC0tZm9udC1tb25vKTsgZm9udC1zaXplOiAxMS41cHg7IGNvbG9yOiB2YXIoLS1pbmszKTsgfQpAbWVkaWEgKHByZWZlcnMtcmVkdWNlZC1tb3Rpb246IHJlZHVjZSkgeyAjdGlwIHsgdHJhbnNpdGlvbjogbm9uZTsgfSB9Cjwvc3R5bGU+Cgo8aGVhZGVyIGlkPSJ0b3BiYXIiPgogIDxzcGFuIGNsYXNzPSJicmFuZCI+Y3J1eCA8c3Bhbj7CtyBjb25zb2xlPC9zcGFuPjwvc3Bhbj4KICA8c3BhbiBjbGFzcz0icGlsbCI+PHNwYW4gY2xhc3M9ImRvdCI+PC9zcGFuPmRhZW1vbiDCtyBsb2NhbDwvc3Bhbj4KICA8c3BhbiBjbGFzcz0icGlsbCI+aHR0cCA6MTQ4MDAgwrcgbWNwIDoxNDgwMTwvc3Bhbj4KICA8c3BhbiBjbGFzcz0ic3AiPjwvc3Bhbj4KICA8c3BhbiBjbGFzcz0icGlsbCI+c25hcHNob3QgwrcgMjAyNi0wNy0yMjwvc3Bhbj4KPC9oZWFkZXI+CgoKPHNlY3Rpb24gY2xhc3M9ImNvbmNlcHQiIGlkPSJyaW5ncyI+CiAgPGRpdiBjbGFzcz0ic3RhZ2V3cmFwIj4KICAgIDxjYW52YXMgaWQ9ImN2IiBhcmlhLWxhYmVsPSJSaW5nczogcmVhbCBleGVjcGxhbiBwb3J0Zm9saW8gcmVwbGF5ZWQgYXMgYW4gYW5pbWF0ZWQgY2xvY2s7IHRpbGVzIHN3aXRjaCB0aGUgbGVucyI+PC9jYW52YXM+CiAgICA8ZGl2IGlkPSJ0aWxlcyIgcm9sZT0iZ3JvdXAiIGFyaWEtbGFiZWw9IlJpbmcgbGVuc2VzIj4KICAgICAgPGJ1dHRvbiBjbGFzcz0idGlsZSIgZGF0YS1sZW5zPSJ3b3JrIiBhcmlhLXByZXNzZWQ9InRydWUiPgogICAgICAgIDxzcGFuIGNsYXNzPSJ0Ij48aSBzdHlsZT0iYmFja2dyb3VuZDojYTc4YmZhIj48L2k+RXhlY1BsYW5zPC9zcGFuPjxzcGFuIGNsYXNzPSJuIj4xLDA0MDwvc3Bhbj4KICAgICAgPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9InRpbGUiIGRhdGEtbGVucz0iZGF0YSIgYXJpYS1wcmVzc2VkPSJmYWxzZSI+CiAgICAgICAgPHNwYW4gY2xhc3M9InQiPjxpIHN0eWxlPSJiYWNrZ3JvdW5kOiM4Yjk2ZjIiPjwvaT5EYXRhIGdyYXBoPC9zcGFuPjxzcGFuIGNsYXNzPSJuIj42Njwvc3Bhbj4KICAgICAgPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9InRpbGUiIGRhdGEtbGVucz0ibWVtb3J5IiBhcmlhLXByZXNzZWQ9ImZhbHNlIj4KICAgICAgICA8c3BhbiBjbGFzcz0idCI+PGkgc3R5bGU9ImJhY2tncm91bmQ6IzJkZDRiZiI+PC9pPk1lbW9yeTwvc3Bhbj48c3BhbiBjbGFzcz0ibiI+MjE8L3NwYW4+CiAgICAgIDwvYnV0dG9uPgogICAgICA8YnV0dG9uIGNsYXNzPSJ0aWxlIiBkYXRhLWxlbnM9InNlc3Npb25zIiBhcmlhLXByZXNzZWQ9ImZhbHNlIj4KICAgICAgICA8c3BhbiBjbGFzcz0idCI+PGkgc3R5bGU9ImJhY2tncm91bmQ6IzIyZDNlZSI+PC9pPlNlc3Npb25zPC9zcGFuPjxzcGFuIGNsYXNzPSJuIj4zMjwvc3Bhbj4KICAgICAgPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9InRpbGUiIGRhdGEtbGVucz0idG9rZW5zIiBhcmlhLXByZXNzZWQ9ImZhbHNlIj4KICAgICAgICA8c3BhbiBjbGFzcz0idCI+PGkgc3R5bGU9ImJhY2tncm91bmQ6I2Y1YTYyMyI+PC9pPlRva2Vuczwvc3Bhbj48c3BhbiBjbGFzcz0ibiIgaWQ9InRpbGUtdG9rIj7igJQ8L3NwYW4+CiAgICAgIDwvYnV0dG9uPgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJzdGFnZWJhciI+CiAgICAgIDxzcGFuIGNsYXNzPSJncnAiPgogICAgICAgIDxidXR0b24gaWQ9ImItc3BpbiIgY2xhc3M9ImljIiBhcmlhLXByZXNzZWQ9InRydWUiIHRpdGxlPSJBbWJpZW50IHNwaW4iPuKfszwvYnV0dG9uPgogICAgICAgIDxidXR0b24gaWQ9ImItY2xvY2siIGNsYXNzPSJpYyIgdGl0bGU9IlJlc2V0IGNsb2NrIHRvIDEyIChhbHNvIHN0b3BzIHNwaW4pIj7il7c8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGlkPSJiLW1vZGUiIGNsYXNzPSJpYyIgYXJpYS1wcmVzc2VkPSJ0cnVlIiB0aXRsZT0iQmFyczogc3Bva2UgZnJvbSBjZW50cmUgdG8gZWFjaCBub2RlIj7ilqU8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGlkPSJiLWRpciIgY2xhc3M9ImljIiBhcmlhLXByZXNzZWQ9ImZhbHNlIiB0aXRsZT0iVGltZSBlZGdlOiBvdXR3YXJkIChyaW5ncyBncm93KSAvIGlud2FyZCAobm9kZXMgc2luayBmcm9tIHJpbSkiPuKHhTwvYnV0dG9uPgogICAgICAgIDxidXR0b24gaWQ9ImItYWxsIiBjbGFzcz0iaWMiIGFyaWEtcHJlc3NlZD0iZmFsc2UiIHRpdGxlPSJDZW5zdXM6IGV2ZXJ5IHBsYW4gc3RheXMgb24gdGhlIGNsb2NrOyBob3ZlciBuYW1lcyBzZWN0b3JzIj7il4w8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGlkPSJiLWRvbmUiIGNsYXNzPSJpYyIgYXJpYS1wcmVzc2VkPSJmYWxzZSIgdGl0bGU9IlNob3cgY29tcGxldGVkIHBsYW5zIG9uIHRoZSBjbG9jayAoYXV0by1vbiBkdXJpbmcgcGxheWJhY2spIj7inJM8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGlkPSJiLWxlZGdlciIgY2xhc3M9ImljIiBhcmlhLXByZXNzZWQ9ImZhbHNlIiB0aXRsZT0iQ29tcGxldGVkLXBsYW5zIGxpc3QgKGxlZnQpLiBBdXRvLXNob3dzIGR1cmluZyBwbGF5YmFjazsgaGlkZXMgb24gbGVucyBzd2FwLiI+4omhPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBpZD0iYi1zdGF0ZSIgY2xhc3M9ImljIiBhcmlhLXByZXNzZWQ9ImZhbHNlIiB0aXRsZT0iU3RhdGUgY29sb3VyczogY29tcGxldGUgZ3JlZW4gwrcgaW4gcHJvZ3Jlc3MgcHVycGxlIMK3IGJsb2NrZWQgcmVkIj7il5E8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGlkPSJiLWxpbiIgY2xhc3M9ImljIiBhcmlhLXByZXNzZWQ9ImZhbHNlIiB0aXRsZT0iTGluZWFnZSBjaG9yZHMgKGRlcGVuZHNfb24pIj7ijIc8L2J1dHRvbj4KICAgICAgPC9zcGFuPgogICAgICA8c3BhbiBjbGFzcz0iZ3JwIj4KICAgICAgICA8c2VsZWN0IGlkPSJzLWtpbmQiIGFyaWEtbGFiZWw9IkZpbHRlciBieSBub2RlIGtpbmQiPgogICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iYWxsIj5hbGwga2luZHM8L29wdGlvbj4KICAgICAgICAgIDxvcHRpb24gdmFsdWU9ImdhdGUiPmdhdGVzIG9ubHk8L29wdGlvbj4KICAgICAgICAgIDxvcHRpb24gdmFsdWU9ImRlY2lzaW9uIj5kZWNpc2lvbnMgKE9EKSBvbmx5PC9vcHRpb24+CiAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJtZW1vcnkiPm1lbW9yeSBvbmx5PC9vcHRpb24+CiAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJoYW5kb2ZmIj5oYW5kb2ZmcyBvbmx5PC9vcHRpb24+CiAgICAgICAgPC9zZWxlY3Q+CiAgICAgICAgPHNlbGVjdCBpZD0icy1hZ2VudCIgYXJpYS1sYWJlbD0iRmlsdGVyIGJ5IGFnZW50IHBhc3Nwb3J0Ij4KICAgICAgICAgIDxvcHRpb24gdmFsdWU9ImFsbCI+YWxsIGFnZW50czwvb3B0aW9uPgogICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iY2xhdWRlLXdvcmsiPmNsYXVkZS13b3JrPC9vcHRpb24+CiAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJjb2RleC13b3JrIj5jb2RleC13b3JrPC9vcHRpb24+CiAgICAgICAgPC9zZWxlY3Q+CiAgICAgIDwvc3Bhbj4KICAgICAgPHNwYW4gY2xhc3M9ImdycCIgaWQ9InRvay12aWV3cyIgc3R5bGU9ImRpc3BsYXk6bm9uZSI+CiAgICAgICAgPGJ1dHRvbiBpZD0iYi10b2stY3VtIiBhcmlhLXByZXNzZWQ9InRydWUiIHRpdGxlPSJSdW5uaW5nIHRvdGFsIGFjcm9zcyB0aGUgd2luZG93Ij5jdW11bGF0aXZlPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBpZD0iYi10b2stZGF5IiBhcmlhLXByZXNzZWQ9ImZhbHNlIiB0aXRsZT0iVG9rZW5zIHBlciBkYXkiPnBlciBkYXk8L2J1dHRvbj4KICAgICAgPC9zcGFuPgogICAgICA8c3BhbiBjbGFzcz0iZ3JwIj4KICAgICAgICA8aW5wdXQgaWQ9ImQtc3RhcnQiIHR5cGU9ImRhdGUiIG1pbj0iMjAyNi0wNS0xOCIgbWF4PSIyMDI2LTA3LTIyIiB2YWx1ZT0iMjAyNi0wNS0xOCIgYXJpYS1sYWJlbD0iV2luZG93IHN0YXJ0IGRhdGUiPgogICAgICAgIDxpbnB1dCBpZD0ici1zdGFydCIgdHlwZT0icmFuZ2UiIG1pbj0iMCIgbWF4PSIxMDAwIiB2YWx1ZT0iMCIgc3R5bGU9IndpZHRoOjcwcHgiIGFyaWEtbGFiZWw9IldpbmRvdyBzdGFydCI+CiAgICAgICAgPGlucHV0IGlkPSJyLWVuZCIgdHlwZT0icmFuZ2UiIG1pbj0iMCIgbWF4PSIxMDAwIiB2YWx1ZT0iMTAwMCIgc3R5bGU9IndpZHRoOjcwcHgiIGFyaWEtbGFiZWw9IldpbmRvdyBlbmQiPgogICAgICAgIDxpbnB1dCBpZD0iZC1lbmQiIHR5cGU9ImRhdGUiIG1pbj0iMjAyNi0wNS0xOCIgbWF4PSIyMDI2LTA3LTIyIiB2YWx1ZT0iMjAyNi0wNy0yMiIgYXJpYS1sYWJlbD0iV2luZG93IGVuZCBkYXRlIj4KICAgICAgPC9zcGFuPgogICAgICA8c3BhbiBjbGFzcz0iZ3JwIj4KICAgICAgICA8YnV0dG9uIGlkPSJiLXBsYXkiIGNsYXNzPSJpYyIgYXJpYS1wcmVzc2VkPSJmYWxzZSIgdGl0bGU9IlJlcGxheSB0aGUgd2luZG93Ij7ilrY8L2J1dHRvbj4KICAgICAgICA8aW5wdXQgaWQ9InItdGltZSIgdHlwZT0icmFuZ2UiIG1pbj0iMCIgbWF4PSIxMDAwIiB2YWx1ZT0iMTAwMCIgYXJpYS1sYWJlbD0iVGltZSI+CiAgICAgICAgPHNwYW4gaWQ9ImMtZGF0ZSIgY2xhc3M9ImNoaXAiPjIwMjYtMDctMjI8L3NwYW4+CiAgICAgIDwvc3Bhbj4KICAgICAgPHNwYW4gY2xhc3M9ImdycCI+CiAgICAgICAgPGJ1dHRvbiBpZD0iYi16aW4iIGFyaWEtbGFiZWw9Ilpvb20gaW4iPis8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGlkPSJiLXpvdXQiIGFyaWEtbGFiZWw9Ilpvb20gb3V0Ij7iiJI8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGlkPSJiLXpmaXQiPmZpdDwvYnV0dG9uPgogICAgICA8L3NwYW4+CiAgICAgIDxzcGFuIGNsYXNzPSJoaW50IiBpZD0iaGludCI+d2hlZWwgPSB6b29tIMK3IGRyYWcgPSBwYW4gwrcgY2xpY2sgbm9kZSAvIHNlY3RvciAvIGxlZGdlciDCtyBiYWNrZ3JvdW5kIGNsZWFyczwvc3Bhbj4KICAgIDwvZGl2PgogICAgPGFzaWRlIGlkPSJwYW5lIiBhcmlhLWxhYmVsPSJEZXRhaWwgcGFuZSI+PC9hc2lkZT4KICA8L2Rpdj4KICA8cCBzdHlsZT0ibWF4LXdpZHRoOjEyNDBweDttYXJnaW46MTBweCBhdXRvIDA7cGFkZGluZzowIGNsYW1wKDE2cHgsM3Z3LDMycHgpO2ZvbnQ6MTFweCB2YXIoLS1mb250LW1vbm8pO2NvbG9yOnZhcigtLWluazMpIj5tb2NrIMK3IHRpbGVzIHN3aXRjaCB0aGUgbGVucyDCtyBFeGVjUGxhbnMgbGVucyBrZWVwcyBzb2xvIC8gbGVkZ2VyIC8gbGluZWFnZSAvIGZpbHRlcnMgwrcgc25hcHNob3QgZGF0YSwgbGl2ZS13aXJlOiAvdjEvd29yayDCtyAvdjEvZmFjdHMgwrcgcmVjZWlwdHMgYnkgc2VxPC9wPgo8L3NlY3Rpb24+CgoKPGRpdiBpZD0idGlwIiByb2xlPSJzdGF0dXMiPjwvZGl2PgoKPHNjcmlwdD4KKGZ1bmN0aW9uICgpIHsKJ3VzZSBzdHJpY3QnOwpjb25zdCBQTEFOU19SQVcgPSBbeyJzIjoiY29yZWNydXgtb2JqZWN0LXN0b3JhZ2UtdGllci0yMDI2LTA3LTA3Iiwic3QiOjAsImQiOjYsInQiOjYsImIiOjYxLCJlIjo3NiwibyI6NTksImRlcCI6WyJjb3JlY3J1eC1tZW1vcnktbWFuYWdlci0yMDI2LTA3LTA1Il0sImV4dCI6W10sIm9kIjpbXX0seyJzIjoidGllci1wYWNrYWdpbmctcDEtcmVtZWRpYXRpb24tMjAyNi0wNy0xMyIsInN0IjoxLCJkIjowLCJ0IjoxLCJiIjo2NywiZSI6NzYsIm8iOjU1LCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtZGFlbW9uLWJ1eWVyLWZpdC1idWlsZG91dC0yMDI2LTA3LTEzIiwic3QiOjEsImQiOjEsInQiOjgsImIiOjY3LCJlIjo3NiwibyI6NjQsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1hdWRpdC12Mi1jbG9zZW91dC0yMDI2LTA3LTE1Iiwic3QiOjAsImQiOjcsInQiOjcsImIiOjY5LCJlIjo3NSwibyI6NTYsImRlcCI6WyJjcnV4LWF1ZGl0LXYyLXJlbWVkaWF0aW9uLTIwMjYtMDctMTMiXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJ2YXVsdC1jb25zb2xpZGF0aW9uLTIwMjYtMDQtMDciLCJzdCI6MSwiZCI6MCwidCI6OCwiYiI6NTQsImUiOjc1LCJvIjo4MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcm9zcy1zaXRlLWF1dGgtc3NvLWN1ZWNydXgtMjAyNi0wNy0xMyIsInN0IjoxLCJkIjozLCJ0Ijo2LCJiIjo2NywiZSI6NzUsIm8iOjY3LCJkZXAiOlsicGFkZGxlLWJpbGxpbmctc3RhdGUtMjAyNi0wNy0xMyIsInVuaWZpZWQtc2hlbGwtY29uc29sZS0yMDI2LTA3LTAzIl0sImV4dCI6WyJjdWVjcnV4LXNlbGZzZXJ2ZS1sYXVuY2gtcmVhZGluZXNzLTIwMjYtMDctMTYiXSwib2QiOltdfSx7InMiOiJ3aWtpY3J1eC1hZ2VudC1wdWJsaXNoLXBsYW5lLXNoYXJlZC10ZW5hbnQtMjAyNi0wNy0wOSIsInN0IjoxLCJkIjoxLCJ0Ijo2LCJiIjo3MywiZSI6NzQsIm8iOjUsImRlcCI6WyJ3aWtpY3J1eC1hZ2VudC1hZG9wdGlvbi1zZXF1ZW5jZS0yMDI2LTA3LTA4Iiwid2lraWNydXgtYWdlbnQtZmlyc3Qtd2lraS1zZXJ2aWNlLTIwMjYtMDYtMTEiXSwiZXh0IjpbIndpa2ljcnV4LWFkb3B0aW9uLXRlbGVtZXRyeS1hbmQtY29ycHVzLWZseXdoZWVsLTIwMjYtMDctMDkiXSwib2QiOltdfSx7InMiOiJwb3J0Zm9saW8tYnVybi1kb3duLW9yY2hlc3RyYXRpb24tMjAyNi0wNy0xMCIsInN0IjoyLCJkIjoyLCJ0Ijo4LCJiIjo2NCwiZSI6NzQsIm8iOjU0LCJkZXAiOlsiY29tbWVyY2UtcGFkZGxlLWJpbGxpbmctMjAyNi0wNi0xMSIsImNydXgtY3JlZGl0LWJ1cm4tcmFpbC0yMDI2LTA2LTIyIiwicHJvZHVjdGlvbi1jdXRvdmVyLW9yY2hlc3RyYXRpb24tMjAyNi0wNy0wNyJdLCJleHQiOltdLCJvZCI6WyJPRC0xIl19LHsicyI6ImNvbW1lcmNlLXBhZGRsZS1iaWxsaW5nLTIwMjYtMDYtMTEiLCJzdCI6MSwiZCI6MCwidCI6OCwiYiI6NTgsImUiOjcyLCJvIjo1MSwiZGVwIjpbXSwiZXh0IjpbInBvcnRmb2xpby1idXJuLWRvd24tb3JjaGVzdHJhdGlvbi0yMDI2LTA3LTEwIl0sIm9kIjpbXX0seyJzIjoiZGFlbW9uLWRpc3RyaWJ1dGlvbi1wYWNrYWdpbmctMjAyNi0wNi0xMSIsInN0IjowLCJkIjo3LCJ0Ijo3LCJiIjozNiwiZSI6NzIsIm8iOjEzNywiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJlc2ktdjItbm8tYmxpbmRzcG90LWxpdmUtd3JpdGUtMjAyNi0wNi0wMyIsInN0IjoyLCJkIjozLCJ0Ijo2LCJiIjoyNywiZSI6NzIsIm8iOjEzNywiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJ1bmlmaWVkLXNoZWxsLWNvbnNvbGUtMjAyNi0wNy0wMyIsInN0IjoxLCJkIjoxMiwidCI6MTMsImIiOjU3LCJlIjo1OCwibyI6MTcsImRlcCI6WyJvcGVuLWVuZ2luZS1jb29yZGluYXRpb24tc3VyZmFjZXMtMjAyNi0wNi0zMCJdLCJleHQiOlsiY3Jvc3Mtc2l0ZS1hdXRoLXNzby1jdWVjcnV4LTIwMjYtMDctMTMiXSwib2QiOltdfSx7InMiOiJ3aWtpY3J1eC1wcm9zZS1kZW5zZS1yZWVtYmVkLWZsb2F0MTYtcG9vbC0yMDI2LTA2LTI3Iiwic3QiOjAsImQiOjMsInQiOjUsImIiOjUxLCJlIjo1MSwibyI6NywiZGVwIjpbXSwiZXh0IjpbIndpa2ljcnV4LXJldHJpZXZhbC1xdWFsaXR5LWhhcmRlbmluZy0yMDI2LTA2LTI4Il0sIm9kIjpbXX0seyJzIjoid2lraWNydXgtcHVibGljLWNvZGVtYXBzLTIwMjYtMDctMTAiLCJzdCI6MSwiZCI6NCwidCI6NCwiYiI6NjQsImUiOjY0LCJvIjowLCJkZXAiOltdLCJleHQiOlsiY29kZW1hcHMtY3Jvc3MtcmVwby1ncmFwaC1hbmQtdmFsdWUtZXhwYW5zaW9uLTIwMjYtMDctMTAiXSwib2QiOltdfSx7InMiOiJ3aWtpY3J1eC1yZXRyaWV2YWwtcXVhbGl0eS1oYXJkZW5pbmctMjAyNi0wNi0yOCIsInN0IjowLCJkIjo2LCJ0Ijo3LCJiIjo1MiwiZSI6NTIsIm8iOjExLCJkZXAiOlsid2lraWNydXgtcHJvc2UtZGVuc2UtcmVlbWJlZC1mbG9hdDE2LXBvb2wtMjAyNi0wNi0yNyJdLCJleHQiOltdLCJvZCI6W119LHsicyI6Indpa2ktcHJvc2UtcmVzaWR1YWwtZXh0cmFjdGlvbi0yMDI2LTA2LTMwIiwic3QiOjAsImQiOjMsInQiOjQsImIiOjU0LCJlIjo1NSwibyI6MTUsImRlcCI6W10sImV4dCI6WyJ1bmlmaWVkLXJldHJpZXZhbC1oYXJkZW5pbmctMjAyNi0wNy0wMiJdLCJvZCI6W119LHsicyI6InZlcm5hY3VsYXItcmV0cmlldmFsLWxpZnQtY2hlY2stMjAyNi0wNS0yMSIsInN0IjowLCJkIjowLCJ0Ijo3LCJiIjoxNCwiZSI6MTQsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoid2lraS1jdWVjcnV4LWNvbS1wcm9kLWRlcGxveS0yMDI2LTA3LTA4Iiwic3QiOjAsImQiOjAsInQiOjUsImIiOjYyLCJlIjo2MiwibyI6NCwiZGVwIjpbIndpa2ljcnV4LWFnZW50LWZpcnN0LXdpa2ktc2VydmljZS0yMDI2LTA2LTExIiwid2lraWNydXgtZ3JvdW5kaW5nLXBvaXNvbmluZy1kZWZlbnNlLTIwMjYtMDctMDgiXSwiZXh0IjpbIndpa2ljcnV4LWFkb3B0aW9uLXRlbGVtZXRyeS1hbmQtY29ycHVzLWZseXdoZWVsLTIwMjYtMDctMDkiXSwib2QiOltdfSx7InMiOiJ3aWtpY3J1eC1hZ2VudC1sYW5ndWFnZS1lbmNvZGUtMjAyNi0wNi0yOCIsInN0IjoxLCJkIjo1LCJ0IjoxMCwiYiI6NTIsImUiOjUzLCJvIjozMCwiZGVwIjpbImNsYXNzaWNhbC1uZXItYXQtaW5nZXN0LTIwMjYtMDUtMDUiLCJ3aWtpY3J1eC1hZ2VudC1maXJzdC13aWtpLXNlcnZpY2UtMjAyNi0wNi0xMSIsIndpa2ljcnV4LWZ1bGwtZW53aWtpLWluZ2VzdC0yMDI2LTA2LTI4Il0sImV4dCI6WyJ1bmlmaWVkLXJlYXNvbmVyLWVuY29kZS1ldmlkZW5jZS0yMDI2LTA2LTI5Il0sIm9kIjpbXX0seyJzIjoid2lraWNydXgtZ3JvdW5kaW5nLXBvaXNvbmluZy1kZWZlbnNlLTIwMjYtMDctMDgiLCJzdCI6MCwiZCI6NSwidCI6NiwiYiI6NjIsImUiOjYyLCJvIjo0LCJkZXAiOlsid2lraWNydXgtYWdlbnQtZmlyc3Qtd2lraS1zZXJ2aWNlLTIwMjYtMDYtMTEiXSwiZXh0IjpbIndpa2ktY3VlY3J1eC1jb20tcHJvZC1kZXBsb3ktMjAyNi0wNy0wOCIsIndpa2ljcnV4LWFkb3B0aW9uLXRlbGVtZXRyeS1hbmQtY29ycHVzLWZseXdoZWVsLTIwMjYtMDctMDkiXSwib2QiOltdfSx7InMiOiJ2YXVsdGNydXgtc2VhcmNoLW91dGNvbWUtY29ycHVzLXBvbGx1dGlvbi0yMDI2LTA1LTMxIiwic3QiOjAsImQiOjIsInQiOjMsImIiOjI0LCJlIjoyNCwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJ3aWtpY3J1eC1pZGVtcG90ZW50LWluZ2VzdGlvbi0yMDI2LTA2LTE0Iiwic3QiOjEsImQiOjQsInQiOjEwLCJiIjozOCwiZSI6NTIsIm8iOjQ4LCJkZXAiOltdLCJleHQiOlsid2lraWNydXgtYWRvcHRpb24tdGVsZW1ldHJ5LWFuZC1jb3JwdXMtZmx5d2hlZWwtMjAyNi0wNy0wOSJdLCJvZCI6W119LHsicyI6Indpa2ljcnV4LWFnZW50LWZpcnN0LXdpa2ktc2VydmljZS0yMDI2LTA2LTExIiwic3QiOjEsImQiOjMsInQiOjgsImIiOjM1LCJlIjozNywibyI6MSwiZGVwIjpbXSwiZXh0IjpbIndpa2ktY3VlY3J1eC1jb20tcHJvZC1kZXBsb3ktMjAyNi0wNy0wOCIsIndpa2ljcnV4LWFkb3B0aW9uLXRlbGVtZXRyeS1hbmQtY29ycHVzLWZseXdoZWVsLTIwMjYtMDctMDkiLCJ3aWtpY3J1eC1hZ2VudC1hZG9wdGlvbi1zZXF1ZW5jZS0yMDI2LTA3LTA4Iiwid2lraWNydXgtYWdlbnQtbGFuZ3VhZ2UtZW5jb2RlLTIwMjYtMDYtMjgiLCJ3aWtpY3J1eC1hZ2VudC1wdWJsaXNoLXBsYW5lLXNoYXJlZC10ZW5hbnQtMjAyNi0wNy0wOSIsIndpa2ljcnV4LWdyb3VuZGluZy1wb2lzb25pbmctZGVmZW5zZS0yMDI2LTA3LTA4Il0sIm9kIjpbXX0seyJzIjoid2lraWNydXgtZnVsbC1lbndpa2ktaW5nZXN0LTIwMjYtMDYtMjgiLCJzdCI6MSwiZCI6MiwidCI6OSwiYiI6NTIsImUiOjU0LCJvIjozMywiZGVwIjpbXSwiZXh0IjpbImVud2lraS1wcm9zZS1kZWRpY2F0ZWQtc2VydmluZy1kYXRhLTEtMjAyNi0wNy0wMyIsIndpa2ljcnV4LWFkb3B0aW9uLXRlbGVtZXRyeS1hbmQtY29ycHVzLWZseXdoZWVsLTIwMjYtMDctMDkiLCJ3aWtpY3J1eC1hZ2VudC1sYW5ndWFnZS1lbmNvZGUtMjAyNi0wNi0yOCJdLCJvZCI6W119LHsicyI6Indpa2ljcnV4LWFkb3B0aW9uLXRlbGVtZXRyeS1hbmQtY29ycHVzLWZseXdoZWVsLTIwMjYtMDctMDkiLCJzdCI6MSwiZCI6NSwidCI6MTAsImIiOjYzLCJlIjo2NywibyI6OCwiZGVwIjpbImVud2lraS1wcm9zZS1kZWRpY2F0ZWQtc2VydmluZy1kYXRhLTEtMjAyNi0wNy0wMyIsIndpa2ktY3VlY3J1eC1jb20tcHJvZC1kZXBsb3ktMjAyNi0wNy0wOCIsIndpa2ljcnV4LWFnZW50LWFkb3B0aW9uLXNlcXVlbmNlLTIwMjYtMDctMDgiLCJ3aWtpY3J1eC1hZ2VudC1maXJzdC13aWtpLXNlcnZpY2UtMjAyNi0wNi0xMSIsIndpa2ljcnV4LWFnZW50LXB1Ymxpc2gtcGxhbmUtc2hhcmVkLXRlbmFudC0yMDI2LTA3LTA5Iiwid2lraWNydXgtZnVsbC1lbndpa2ktaW5nZXN0LTIwMjYtMDYtMjgiLCJ3aWtpY3J1eC1ncm91bmRpbmctcG9pc29uaW5nLWRlZmVuc2UtMjAyNi0wNy0wOCIsIndpa2ljcnV4LWlkZW1wb3RlbnQtaW5nZXN0aW9uLTIwMjYtMDYtMTQiXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJ2YXVsdGNydXgtY29tcGFuaW9uLWxhbmUtdHJhbnNmb3Jtcy1hbmQtY2N4ZXYtMjAyNi0wNS0yMCIsInN0IjowLCJkIjowLCJ0IjoxMCwiYiI6MTUsImUiOjE1LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6InZhdWx0Y3J1eC1tdWx0aS1wcmVkaWNhdGUtZW51bWVyYXRlLTIwMjYtMDQtMjkiLCJzdCI6MCwiZCI6MCwidCI6MywiYiI6MjAsImUiOjIwLCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6InZhdWx0Y3J1eC1tdWx0aS1wcmVkaWNhdGUtbTMtdmVyaWZ5LWJ1aWxkLTIwMjYtMDYtMDkiLCJzdCI6MCwiZCI6MSwidCI6NSwiYiI6MzQsImUiOjM0LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6InRlbmFudC1pc29sYXRpb24tcG9saWN5LWFuZC1zaWxvLTIwMjYtMDYtMjQiLCJzdCI6MCwiZCI6NywidCI6NywiYiI6NDgsImUiOjUwLCJvIjoyNSwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJyZWxlYXNlLXJlYWRpbmVzcy1tYXN0ZXItMjAyNi0wNi0xMSIsInN0IjoxLCJkIjowLCJ0Ijo2LCJiIjozNSwiZSI6NDksIm8iOjUyLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6InRpZXIwLWRldGVybWluaXN0aWMtbGV2ZXJzLTIwMjYtMDYtMzAiLCJzdCI6MCwiZCI6NSwidCI6NSwiYiI6NTQsImUiOjU0LCJvIjo2LCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6InNjb3JlY3J1eC1jb2RpbmctaW50ZWxsaWdlbmNlLXJlZnJlc2gtMjAyNi0wNi0yNSIsInN0IjoxLCJkIjowLCJ0Ijo1LCJiIjo0OSwiZSI6NTAsIm8iOjUsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoidGllci1wYWNrYWdpbmctYW5kLXNpdGUtcmVmcmFtZS0yMDI2LTA3LTEzIiwic3QiOjEsImQiOjcsInQiOjgsImIiOjY2LCJlIjo2NywibyI6NSwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJ1bmlmaWVkLXJldHJpZXZhbC1oYXJkZW5pbmctMjAyNi0wNy0wMiIsInN0IjoyLCJkIjo3LCJ0IjoxMCwiYiI6NTUsImUiOjU2LCJvIjoxLCJkZXAiOlsiY2N4aS1xdWVyeS1zaGFwZS1yb3V0aW5nLTIwMjYtMDYtMzAiLCJjb3JlY3J1eC1vZmZsaW5lLWF0dGFjaC1jYW5kaWRhdGUtc2VsZWN0aW9uLTIwMjYtMDctMDEiLCJlbWJlZGRlci1wb29sLWRpc3RyaWJ1dGlvbi1tYW5hZ2VyLTIwMjYtMDctMDEiLCJ1bmlmaWVkLXByb2R1Y3Rpb24tY2xhaW1zLXNvdXJjZS0yMDI2LTA2LTMwIiwidW5pZmllZC1yZWFzb25lci1lbmNvZGUtZXZpZGVuY2UtMjAyNi0wNi0yOSIsIndpa2ktcHJvc2UtcmVzaWR1YWwtZXh0cmFjdGlvbi0yMDI2LTA2LTMwIl0sImV4dCI6W10sIm9kIjpbIk9ELTEiLCJPRC0yIiwiT0QtMyJdfSx7InMiOiJwcm9vZi1jYXJyeWluZy1hZGFwdGl2ZS1wYWNrcy0yMDI2LTA3LTEzIiwic3QiOjEsImQiOjAsInQiOjcsImIiOjY3LCJlIjo2NywibyI6NSwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJzZWN1cml0eS1jcml0aWNhbC03LXRlbmFudC1pc29sYXRpb24tMjAyNi0wNi0xMSIsInN0IjowLCJkIjo0LCJ0Ijo3LCJiIjo2NSwiZSI6NjUsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoidG9wb2xvZ3ktY2N4bi1lbnRpdHktY292ZXJhZ2UtYmFja2ZpbGwtbG1lLXMtMjAyNi0wNi0wNiIsInN0IjowLCJkIjozLCJ0Ijo1LCJiIjozMSwiZSI6MzEsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoidG9rZW4tYnVybi1wcmVjaXNlLWF0dHJpYnV0aW9uLTIwMjYtMDYtMjYiLCJzdCI6MCwiZCI6MywidCI6MywiYiI6NTAsImUiOjUwLCJvIjo3LCJkZXAiOlsiZXhlY3BsYW4tdG9rZW4tYnVybi1wZXItZXhlY3BsYW4tMjAyNi0wNi0yNiJdLCJleHQiOltdLCJvZCI6WyJPRC0yOCJdfSx7InMiOiJ1bmlmaWVkLXJlYXNvbmVyLWVuY29kZS1ldmlkZW5jZS0yMDI2LTA2LTI5Iiwic3QiOjEsImQiOjAsInQiOjEsImIiOjUzLCJlIjo1NCwibyI6MjUsImRlcCI6WyJsbWUtcy1hZ2dyZWdhdGlvbi1wcm9qZWN0aW9uLWxhbmUtd2lraWNydXgtYnJpZGdlLTIwMjYtMDYtMjgiLCJ3aWtpY3J1eC1hZ2VudC1sYW5ndWFnZS1lbmNvZGUtMjAyNi0wNi0yOCJdLCJleHQiOlsiY2N4aS1xdWVyeS1zaGFwZS1yb3V0aW5nLTIwMjYtMDYtMzAiLCJ1bmlmaWVkLXJldHJpZXZhbC1oYXJkZW5pbmctMjAyNi0wNy0wMiJdLCJvZCI6W119LHsicyI6InVuaWZpZWQtcHJvZHVjdGlvbi1jbGFpbXMtc291cmNlLTIwMjYtMDYtMzAiLCJzdCI6MSwiZCI6MywidCI6NCwiYiI6NTQsImUiOjU0LCJvIjo2LCJkZXAiOltdLCJleHQiOlsiY2N4aS1xdWVyeS1zaGFwZS1yb3V0aW5nLTIwMjYtMDYtMzAiLCJlbndpa2ktcHJvc2UtZGVkaWNhdGVkLXNlcnZpbmctZGF0YS0xLTIwMjYtMDctMDMiLCJ1bmlmaWVkLXJldHJpZXZhbC1oYXJkZW5pbmctMjAyNi0wNy0wMiJdLCJvZCI6W119LHsicyI6InJjeC1yZWdpc3RyeS1kZXBsb3ltZW50LXJlYWRpbmVzcy0yMDI2LTA2LTE0Iiwic3QiOjAsImQiOjUsInQiOjUsImIiOjM4LCJlIjozOCwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJwcm9kdWN0aW9uLWN1dG92ZXItb3JjaGVzdHJhdGlvbi0yMDI2LTA3LTA3Iiwic3QiOjEsImQiOjM5LCJ0Ijo0MCwiYiI6NjEsImUiOjY1LCJvIjoyLCJkZXAiOltdLCJleHQiOlsicG9ydGZvbGlvLWJ1cm4tZG93bi1vcmNoZXN0cmF0aW9uLTIwMjYtMDctMTAiXSwib2QiOltdfSx7InMiOiJwcm92aWRlci1pbnRlZ3JhdGlvbi1zdXJmYWNlcy0yMDI2LTA2LTExIiwic3QiOjEsImQiOjUsInQiOjYsImIiOjM2LCJlIjozNiwibyI6MSwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJzY3JhdGNocGFkLXN1cnZpdmFsLXdpemFyZC1zdGFuZGFyZC0yMDI2LTA2LTMwIiwic3QiOjEsImQiOjQsInQiOjQsImIiOjU0LCJlIjo1NSwibyI6OCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJ0b3BvbG9neS1jY3huLXdlaWdodC1hbmQtbm9pc2UtdHVuZS1sbWUtcy0yMDI2LTA2LTA3Iiwic3QiOjAsImQiOjQsInQiOjQsImIiOjMxLCJlIjozMSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJ0b2tlbmJ1cm4tYWItaGFybmVzcy0yMDI2LTA2LTEwIiwic3QiOjAsImQiOjEsInQiOjcsImIiOjM0LCJlIjozNCwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJwcm9kLWVuZ2luZS1yZWNvbmNpbGUtZGVwbG95LTIwMjYtMDYtMjYiLCJzdCI6MCwiZCI6MCwidCI6MSwiYiI6NTAsImUiOjUwLCJvIjo0LCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6InBoYXNlLXQtdXNhZ2UtcmVjZWlwdHMtMjAyNi0wNy0wMyIsInN0IjowLCJkIjozLCJ0IjozLCJiIjo2NCwiZSI6NjQsIm8iOjMsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoibG1lLXMtZ2F0ZWQtYWNjdXJhY3ktcHVzaC0yMDI2LTA1LTI5Iiwic3QiOjAsImQiOjAsInQiOjUsImIiOjIyLCJlIjoyOCwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJwaGFzZS10LWNyb3NzLXZlbmRvci1pbnN0cnVtZW50YXRpb24tMjAyNi0wNy0wMyIsInN0IjoxLCJkIjoxLCJ0IjozLCJiIjo2MSwiZSI6NjQsIm8iOjUsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoicGFzc3BvcnQtcmV2b2NhdGlvbi1hbmQtYWdlbnQtY2FyZC1kaXNjb3ZlcnktMjAyNi0wNi0yOSIsInN0IjowLCJkIjo3LCJ0Ijo3LCJiIjo1MywiZSI6NTMsIm8iOjI2LCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6InBoYXNlLTAtaHlnaWVuZS1kZWJ0LTIwMjYtMDctMDIiLCJzdCI6MSwiZCI6MywidCI6MTAsImIiOjU2LCJlIjo2MCwibyI6MjcsImRlcCI6WyJtYXN0ZXItcGxhbi1yZWZyZXNoLWFuZC1kb2NzLXVuaWZpY2F0aW9uLTIwMjYtMDctMDIiXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJwaGFzZS10LXVzYWdlLXJlY2VpcHRzLWF1dG9lbWl0LXZlcnNpb24tbm90aWZ5LTIwMjYtMDctMDMiLCJzdCI6MCwiZCI6MywidCI6MywiYiI6NTcsImUiOjU3LCJvIjozLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6Im1hc3Rlci1wbGFuLWNhbm9uaWNhbC1jb25zb2xpZGF0aW9uLTIwMjYtMDYtMTQiLCJzdCI6MCwiZCI6NCwidCI6NCwiYiI6MzgsImUiOjM4LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6InBvcnRmb2xpby1zdGF0dXMtZGVjaXNpb25zLXJlZ2lzdHJ5LTIwMjYtMDYtMTEiLCJzdCI6MCwiZCI6MCwidCI6NCwiYiI6MzYsImUiOjM2LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6Im9wZW4tZW5naW5lLWNvb3JkaW5hdGlvbi1zdXJmYWNlcy0yMDI2LTA2LTMwIiwic3QiOjAsImQiOjAsInQiOjUsImIiOjU0LCJlIjo1NSwibyI6OSwiZGVwIjpbXSwiZXh0IjpbInVuaWZpZWQtc2hlbGwtY29uc29sZS0yMDI2LTA3LTAzIl0sIm9kIjpbXX0seyJzIjoicGxhbmNydXgtcmV0aXJlbWVudC1tYXN0ZXItMjAyNi0wNS0xOSIsInN0IjoxLCJkIjowLCJ0Ijo5LCJiIjoxMiwiZSI6MzQsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoibWgtYWItdjItaGFybmVzcy1idWlsZC0yMDI2LTA2LTEyIiwic3QiOjAsImQiOjEsInQiOjUsImIiOjM2LCJlIjozNiwibyI6MCwiZGVwIjpbXSwiZXh0IjpbImNvbnRleHQtZGVwZW5kZW5jZS1iZW5jaG1hcmstc2NvcmVjcnV4LTIwMjYtMDctMDMiXSwib2QiOltdfSx7InMiOiJsbWUtcy1tdWx0aS1sYW5lLXJldHJpZXZhbC1nZW1tYS0yMDI2LTA1LTIzIiwic3QiOjAsImQiOjAsInQiOjcsImIiOjE2LCJlIjoxNiwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJsbWUta25vd2xlZGdlLXJlaW5nZXN0LWFuZC1sZWdhY3ktc2VnbWVudC1yZXRpcmUtMjAyNi0wNS0yOSIsInN0IjowLCJkIjowLCJ0IjoxLCJiIjoyMiwiZSI6MjIsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoibGFuZS1jb3ZlcmFnZS1iYWNrZmlsbC0yMDI2LTA1LTIyIiwic3QiOjAsImQiOjIsInQiOjUsImIiOjE1LCJlIjoxNSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJsbWUtb3JkZXJpbmctZGF5LXByZWNpc2lvbi1leHRyYWN0aW9uLTIwMjYtMDYtMTIiLCJzdCI6MSwiZCI6MywidCI6NiwiYiI6MzYsImUiOjM3LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImxtZS1zLTgtbGV2ZXItZGVlcGRpdmUtMjAyNi0wNi0wNCIsInN0IjowLCJkIjowLCJ0IjoxLCJiIjoyOCwiZSI6MjksIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoibG1lLXMtYWdncmVnYXRpb24tcHJvamVjdGlvbi1sYW5lLXdpa2ljcnV4LWJyaWRnZS0yMDI2LTA2LTI4Iiwic3QiOjEsImQiOjAsInQiOjYsImIiOjUyLCJlIjo1MywibyI6MjYsImRlcCI6WyJsbWUtcy1hZ2dyZWdhdGlvbi1jb3VudC1leHRyYWN0aW9uLTIwMjYtMDYtMTgiXSwiZXh0IjpbInVuaWZpZWQtcmVhc29uZXItZW5jb2RlLWV2aWRlbmNlLTIwMjYtMDYtMjkiXSwib2QiOltdfSx7InMiOiJsbWUtYWdlbnQtbmF0aXZlLXJldHJpZXZhbC1oYXJuZXNzLTIwMjYtMDUtMzAiLCJzdCI6MCwiZCI6MiwidCI6NSwiYiI6MjMsImUiOjMyLCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImxtZS1zLWFnZ3JlZ2F0aW9uLWNvdW50LWV4dHJhY3Rpb24tMjAyNi0wNi0xOCIsInN0IjowLCJkIjo1LCJ0Ijo1LCJiIjo0MiwiZSI6NDcsIm8iOjU5LCJkZXAiOltdLCJleHQiOlsibG1lLXMtYWdncmVnYXRpb24tcHJvamVjdGlvbi1sYW5lLXdpa2ljcnV4LWJyaWRnZS0yMDI2LTA2LTI4Il0sIm9kIjpbXX0seyJzIjoia25vd2xlZGdlLXN0YXRlLXByb2R1Y3Rpb24taG9va3MtMjAyNi0wNi0xMyIsInN0IjowLCJkIjo2LCJ0Ijo2LCJiIjozNywiZSI6MzksIm8iOjksImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiZXh0cmFjdGlvbi1sYW5lLW9ic2VydmFiaWxpdHktMjAyNi0wNS0yMSIsInN0IjowLCJkIjo3LCJ0Ijo3LCJiIjoxNCwiZSI6MzUsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiZXhlY3BsYW4tbGluZWFnZS1wcm92ZW5hbmNlLW9wZW4tcXVlc3Rpb25zLTIwMjYtMDYtMjUiLCJzdCI6MCwiZCI6NCwidCI6NSwiYiI6NDksImUiOjQ5LCJvIjo1LCJkZXAiOlsiY29vcmQtcGxhbmUtcDEtZXhlY3BsYW4tYm9hcmQtMjAyNi0wNi0yMyIsImNydXgtd29yay1wYW5lbC1leGVjcGxhbnMtYXMtdHJ1ZW5vcnRoLTIwMjYtMDUtMjYiXSwiZXh0IjpbImV4ZWNwbGFuLWJvYXJkLWZpZGVsaXR5LXN0YXRlcy1jb25zb2xlLWNvc3QtMjAyNi0wNi0yNiJdLCJvZCI6WyJPRC0zIiwiT0QtMjQiXX0seyJzIjoiZ2VuZXJhdGl2ZS1leGVjcGxhbnMtYW5kLWRlcGxveS1jb29yZGluYXRpb24tMjAyNi0wNi0yNiIsInN0IjowLCJkIjowLCJ0IjoxLCJiIjo1MCwiZSI6NTMsIm8iOjI3LCJkZXAiOlsiY3J1eC13b3JrLXBhbmVsLWV4ZWNwbGFucy1hcy10cnVlbm9ydGgtMjAyNi0wNS0yNiIsImV4ZWNwbGFuLWJvYXJkLWZpZGVsaXR5LXN0YXRlcy1jb25zb2xlLWNvc3QtMjAyNi0wNi0yNiJdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImlkZW50aXR5LW1lbW9yeS1wb3J0YWJpbGl0eS0yMDI2LTA2LTExIiwic3QiOjAsImQiOjYsInQiOjYsImIiOjM2LCJlIjozNiwibyI6MSwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJmYWJsZTUtZDEtcmVkdGVhbS1raWxsLXJpc2stcmVnaXN0ZXItMjAyNi0wNy0wMiIsInN0IjowLCJkIjo2LCJ0Ijo2LCJiIjo1NiwiZSI6NTYsIm8iOjYsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiZ2F0ZWQtdGllcmVkLWFnZ3JlZ2F0aW9uLXByb21wdC1maXhlcy0yMDI2LTA1LTI0Iiwic3QiOjAsImQiOjAsInQiOjgsImIiOjE3LCJlIjozMywibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJleGVjcGxhbi10b2tlbi1idXJuLXBlci1leGVjcGxhbi0yMDI2LTA2LTI2Iiwic3QiOjAsImQiOjIsInQiOjMsImIiOjUwLCJlIjo1MCwibyI6MTIsImRlcCI6WyJleGVjcGxhbi1ib2FyZC1maWRlbGl0eS1zdGF0ZXMtY29uc29sZS1jb3N0LTIwMjYtMDYtMjYiXSwiZXh0IjpbInRva2VuLWJ1cm4tcHJlY2lzZS1hdHRyaWJ1dGlvbi0yMDI2LTA2LTI2Il0sIm9kIjpbIk9ELTI4Il19LHsicyI6ImV2ZW50LWxhbmUtc2VtYW50aWMtcmVjYWxsLTIwMjYtMDYtMDUiLCJzdCI6MCwiZCI6NiwidCI6NywiYiI6MjksImUiOjMwLCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImdsYXNzYm94LWV1LWFpLWFjdC1zb2MyLWNvbXBsaWFuY2UtYmVuY2gtMjAyNi0wNi0yNiIsInN0IjowLCJkIjoxMSwidCI6MTEsImIiOjUwLCJlIjo1MSwibyI6MjIsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiZXZlbnQtY291bnRlci1ub2lzZS1yZWR1Y3Rpb24tMjAyNi0wNi0wNiIsInN0IjowLCJkIjo2LCJ0Ijo3LCJiIjozMCwiZSI6MzAsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiZnJvbnRkb29yLWFnZW50LXV4LW51eHQtZmVhdHVyZS1mbGFnLXdpcmluZy0yMDI2LTA1LTI5Iiwic3QiOjEsImQiOjAsInQiOjgsImIiOjIxLCJlIjoyMiwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJnb2xkLWZyZWUtZXh0cmFjdGlvbi1hdXRvbWF0aW9uLTIwMjYtMDUtMzEiLCJzdCI6MSwiZCI6MiwidCI6MTEsImIiOjI0LCJlIjoyOCwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJleGVjcGxhbi1ib2FyZC1maWRlbGl0eS1zdGF0ZXMtY29uc29sZS1jb3N0LTIwMjYtMDYtMjYiLCJzdCI6MCwiZCI6MywidCI6NCwiYiI6NTAsImUiOjUwLCJvIjo1LCJkZXAiOlsiZXhlY3BsYW4tbGluZWFnZS1wcm92ZW5hbmNlLW9wZW4tcXVlc3Rpb25zLTIwMjYtMDYtMjUiXSwiZXh0IjpbImV4ZWNwbGFuLXRva2VuLWJ1cm4tcGVyLWV4ZWNwbGFuLTIwMjYtMDYtMjYiLCJnZW5lcmF0aXZlLWV4ZWNwbGFucy1hbmQtZGVwbG95LWNvb3JkaW5hdGlvbi0yMDI2LTA2LTI2Il0sIm9kIjpbXX0seyJzIjoiZW1iZWRkZXItcG9vbC1kaXN0cmlidXRpb24tbWFuYWdlci0yMDI2LTA3LTAxIiwic3QiOjEsImQiOjIsInQiOjYsImIiOjU1LCJlIjo1NSwibyI6MTEsImRlcCI6W10sImV4dCI6WyJ1bmlmaWVkLXJldHJpZXZhbC1oYXJkZW5pbmctMjAyNi0wNy0wMiJdLCJvZCI6W119LHsicyI6ImVud2lraS1wcm9zZS1kZWRpY2F0ZWQtc2VydmluZy1kYXRhLTEtMjAyNi0wNy0wMyIsInN0IjowLCJkIjoxLCJ0Ijo2LCJiIjo2NCwiZSI6NjQsIm8iOjAsImRlcCI6WyJjbGFpbXMtcmVzaWRlbnQtYm0yNS1hbmQtbmV4dC1zdGVwcy0yMDI2LTA2LTMwIiwidW5pZmllZC1wcm9kdWN0aW9uLWNsYWltcy1zb3VyY2UtMjAyNi0wNi0zMCIsIndpa2ljcnV4LWZ1bGwtZW53aWtpLWluZ2VzdC0yMDI2LTA2LTI4Il0sImV4dCI6WyJ3aWtpY3J1eC1hZG9wdGlvbi10ZWxlbWV0cnktYW5kLWNvcnB1cy1mbHl3aGVlbC0yMDI2LTA3LTA5Il0sIm9kIjpbXX0seyJzIjoiZW1iZWRkZXItcG9vbC1wZXItdGVuYW50LWJ1bmRsZS0yMDI2LTA2LTE2Iiwic3QiOjAsImQiOjUsInQiOjUsImIiOjQwLCJlIjo0MCwibyI6MTIsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiZW53aWtpLWNsYWltcy1jb3ZlcmFnZS1leHBhbnNpb24tMjAyNi0wNy0wNCIsInN0IjoxLCJkIjoyLCJ0Ijo2LCJiIjo2NCwiZSI6NjQsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiZXNpLXYyLWxpdmUtZmFjdC13cml0ZS1wYXRoLTIwMjYtMDYtMDMiLCJzdCI6MCwiZCI6MCwidCI6NCwiYiI6MjcsImUiOjI3LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImVuZ2luZS1jaS1sYXllci03LXJlbWFpbmluZy1oaWdocy0yMDI2LTA1LTIxIiwic3QiOjAsImQiOjAsInQiOjQsImIiOjE0LCJlIjoxNCwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJlbndpa2ktcHJvc2UtcmFua2luZy1xdWFsaXR5LTIwMjYtMDctMDMiLCJzdCI6MCwiZCI6MywidCI6NSwiYiI6NjQsImUiOjY0LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6WyJPRC0xIiwiT0QtMiJdfSx7InMiOiJjdWVjcnV4LWZlYXR1cmUtcmVnaXN0cnktYW5kLXJvdXRlci0yMDI2LTA1LTI2Iiwic3QiOjAsImQiOjAsInQiOjE3LCJiIjoxOSwiZSI6MTksIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1odHRwLWluZ3Jlc3MtaGFyZGVuaW5nLTIwMjYtMDYtMTEiLCJzdCI6MSwiZCI6NCwidCI6NSwiYiI6MzUsImUiOjM2LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtc2VsZi1ob3N0aW5nLWh5Z2llbmUtMjAyNi0wNi0wNSIsInN0IjowLCJkIjo0LCJ0Ijo1LCJiIjoyOSwiZSI6MjksIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1wcm9kLWRlcGxveS0yMDI2LTA2LTA1Iiwic3QiOjAsImQiOjMsInQiOjQsImIiOjI5LCJlIjoyOSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LWdhdGV3YXktcHJvZHVjdGlvbi0yMDI2LTA2LTEwIiwic3QiOjAsImQiOjAsInQiOjEsImIiOjM0LCJlIjozNSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LW1jcC1vYXV0aC1mb3ItaG9zdGVkLWNsaWVudHMtMjAyNi0wNi0yMyIsInN0IjoxLCJkIjo1LCJ0Ijo4LCJiIjo0NywiZSI6NDksIm8iOjQ0LCJkZXAiOltdLCJleHQiOltdLCJvZCI6WyJPRC0zIiwiT0QtMjQiXX0seyJzIjoiY3J1eC1zZXNzaW9uLWNhcGFiaWxpdHktZ3JhcGgtY29tcGxldGlvbi0yMDI2LTA2LTA4Iiwic3QiOjEsImQiOjEsInQiOjUsImIiOjMyLCJlIjozMiwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4ZW5naW5lLWNvbXBhbmlvbi1pbnN0YWxsZXItZGVwbG95LWhhcmRlbmluZy0yMDI2LTA3LTEyIiwic3QiOjAsImQiOjQsInQiOjQsImIiOjY2LCJlIjo2NiwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LXJlcG8tYXVkaXQtZml4aW5nLTIwMjYtMDYtMTUiLCJzdCI6MCwiZCI6OCwidCI6OCwiYiI6MzksImUiOjM5LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtbW9hdC1tNC1tZW1vcnktaG9vay1tOC1idXllci1wYWNrYWdlLTIwMjYtMDYtMTEiLCJzdCI6MCwiZCI6MCwidCI6MiwiYiI6MzUsImUiOjM1LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtcmVwby1hdWRpdC1oYXJkZW5pbmctZm9sbG93dXAtMjAyNi0wNi0xNSIsInN0IjowLCJkIjowLCJ0IjoxLCJiIjozOSwiZSI6MzksIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1zaWduZWQtc2Vzc2lvbi1yZWNvcmRlci0yMDI2LTA2LTIxIiwic3QiOjAsImQiOjMsInQiOjMsImIiOjQ2LCJlIjo0NiwibyI6NDAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1ob29rLWNsaWVudC13aXJlLWFjdGl2aXR5LTIwMjYtMDYtMjIiLCJzdCI6MCwiZCI6NSwidCI6NSwiYiI6NDYsImUiOjQ2LCJvIjozOCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LWhlYWRyb29tLXRva2VuLWVmZmljaWVuY3ktbGVhcm5pbmdzLTIwMjYtMDYtMjQiLCJzdCI6MCwiZCI6MywidCI6NiwiYiI6NDgsImUiOjQ5LCJvIjoxNywiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LW9yY2hlc3RyYXRvci1vcmNwbGFuLTIwMjYtMDUtMjkiLCJzdCI6MCwiZCI6MCwidCI6NywiYiI6MjIsImUiOjIyLCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtcHVuY2hjYXJkLXJlc291cmNlLWxlYXNlcy0yMDI2LTA1LTI5Iiwic3QiOjAsImQiOjAsInQiOjcsImIiOjIyLCJlIjoyMiwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LXNlc3Npb24tYXJjaGl2ZS1hbmQtZnJpZW5kbHktdGl0bGVzLTIwMjYtMDYtMTMiLCJzdCI6MCwiZCI6MiwidCI6NywiYiI6MzcsImUiOjM3LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtZ3Jvd3RoLXVwc2VsbC1tYXN0ZXItMjAyNi0wNi0xMSIsInN0IjoxLCJkIjowLCJ0Ijo0LCJiIjozNSwiZSI6MzYsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1tY3Atbm90aWZpY2F0aW9uLTIwMi1uYXRpdmUtaHR0cC0yMDI2LTA3LTA2Iiwic3QiOjAsImQiOjEsInQiOjMsImIiOjYwLCJlIjo2MSwibyI6NCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LXdvcmstcGFuZWwtZXhlY3BsYW5zLWFzLXRydWVub3J0aC0yMDI2LTA1LTI2Iiwic3QiOjAsImQiOjgsInQiOjgsImIiOjE5LCJlIjoyMCwibyI6MCwiZGVwIjpbXSwiZXh0IjpbImV4ZWNwbGFuLWxpbmVhZ2UtcHJvdmVuYW5jZS1vcGVuLXF1ZXN0aW9ucy0yMDI2LTA2LTI1IiwiZ2VuZXJhdGl2ZS1leGVjcGxhbnMtYW5kLWRlcGxveS1jb29yZGluYXRpb24tMjAyNi0wNi0yNiJdLCJvZCI6W119LHsicyI6ImNydXgtdGVuYW50LWNhdGVnb3J5LW1vZGVsLTIwMjYtMDUtMjIiLCJzdCI6MCwiZCI6NywidCI6NywiYiI6MTUsImUiOjE1LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtbmV3LXRvb2wtcHJvYmUtZml4ZXMtMjAyNi0wNi0wNSIsInN0IjowLCJkIjozLCJ0Ijo4LCJiIjoyOSwiZSI6MjksIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1yZXNwb25zZS1jb250cmFjdC12MS1kZWZhdWx0LXNjaGVtYS0yMDI2LTA2LTA4Iiwic3QiOjAsImQiOjYsInQiOjcsImIiOjMyLCJlIjozNCwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LXN1cHBseS1jaGFpbi1hdHRlc3RhdGlvbi0yMDI2LTA2LTExIiwic3QiOjAsImQiOjUsInQiOjUsImIiOjM1LCJlIjo0OCwibyI6NDcsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eGVuZ2luZS1jb21wYW5pb24tbGFuZS1wb3J0LTIwMjYtMDYtMDkiLCJzdCI6MCwiZCI6NywidCI6NywiYiI6MzMsImUiOjM0LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtbWNwLWR5bmFtaWMtdG9vbC1zdXJmYWNlLTIwMjYtMDYtMDgiLCJzdCI6MCwiZCI6MSwidCI6NiwiYiI6MzIsImUiOjM0LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtbG9nLXJlZGFjdGlvbi0yMDI2LTA2LTExIiwic3QiOjEsImQiOjMsInQiOjUsImIiOjM1LCJlIjozNiwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LWludGVncmF0aW9uLXBsYXRmb3JtLXN1cmZhY2VzIiwic3QiOjAsImQiOjAsInQiOjcsImIiOjMxLCJlIjozMSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LXNlc3Npb24tY2FwYWJpbGl0eS1jYXRhbG9nLXJlZnJlc2gtMjAyNi0wNS0yOSIsInN0IjowLCJkIjowLCJ0Ijo2LCJiIjoyMSwiZSI6MjEsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1zZWdtZW50LWludGVncml0eS1hdWRpdC1yZW1lZGlhdGlvbi0yMDI2LTA2LTEzIiwic3QiOjAsImQiOjcsInQiOjcsImIiOjM3LCJlIjozNywibyI6MiwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LW1vYXQtdHJhY2stbWFzdGVyLTIwMjYtMDYtMDUiLCJzdCI6MSwiZCI6MCwidCI6OSwiYiI6MzUsImUiOjY2LCJvIjo5MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LWFnZW50LXByZXNlbmNlLWNvb3JkaW5hdGlvbi0yMDI2LTA2LTExIiwic3QiOjAsImQiOjAsInQiOjcsImIiOjM1LCJlIjozNSwibyI6MSwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LWNvbmZpZy13aXphcmQtZGVkdXAtbGludC0yMDI2LTA2LTIzIiwic3QiOjAsImQiOjUsInQiOjUsImIiOjQ3LCJlIjo0NywibyI6MzcsImRlcCI6W10sImV4dCI6W10sIm9kIjpbIk9ELTE4Il19LHsicyI6ImNydXgtYXVkaXQtaWktZ2FwLWNsb3N1cmUtY29kZWJhc2UtYXVkaXQtMjAyNi0wNi0xMyIsInN0IjowLCJkIjo0LCJ0Ijo0LCJiIjozNywiZSI6MzcsIm8iOjIsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1hZ2VudC1wYXNzcG9ydC1ncm91cGVkLWNvbGxhYm9yYXRpb24tMjAyNi0wNi0wNSIsInN0IjowLCJkIjo1LCJ0Ijo1LCJiIjoyOSwiZSI6MjksIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1jb25zb2xlLWdyYXBoLWN1dG92ZXItMjAyNi0wNS0zMCIsInN0IjowLCJkIjowLCJ0IjoxLCJiIjoyMywiZSI6MjMsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1jb25zb2xlLXB1YmxpYy1leHBvc3VyZS0yMDI2LTA1LTE3Iiwic3QiOjEsImQiOjAsInQiOjYsImIiOjExLCJlIjoxMSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LWRhZW1vbi1mdWxsLWF1ZGl0LTIwMjYtMDYtMDUiLCJzdCI6MCwiZCI6NiwidCI6NiwiYiI6MjksImUiOjI5LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtZHVhbC1zdXJmYWNlLWFjdGl2aXR5LWxvZy0yMDI2LTA2LTE4Iiwic3QiOjAsImQiOjUsInQiOjUsImIiOjQyLCJlIjo0NiwibyI6NTEsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3Jvc3MtbW9kZWwtYWdyZWVtZW50LXJvdXRlci0yMDI2LTA2LTA0Iiwic3QiOjAsImQiOjIsInQiOjMsImIiOjI4LCJlIjoyOCwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LWF1ZGl0LWlpLWdhcC1jbG9zdXJlLWltcGxlbWVudGF0aW9uLTIwMjYtMDYtMTQiLCJzdCI6MCwiZCI6MTQsInQiOjE0LCJiIjozOCwiZSI6MzgsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1jb25zb2xlLTNkLXN1YnN0cmF0ZS1jb25jZXB0LTIwMjYtMDYtMTEiLCJzdCI6MCwiZCI6MSwidCI6NCwiYiI6MzUsImUiOjM1LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtZGFlbW9uLXNlY3VyaXR5LWdhcC1zY2FuLTIwMjYtMDYtMTIiLCJzdCI6MCwiZCI6MywidCI6NCwiYiI6MzYsImUiOjM2LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydWNpYmxlLWdhdGV3YXktc3VwZXJzZWRlLWNsYXdkLTIwMjYtMDYtMjYiLCJzdCI6MCwiZCI6MCwidCI6MSwiYiI6NTAsImUiOjUwLCJvIjo1LCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtZnJlc2huZXNzLWRvZ2Zvb2QtMjAyNi0wNi0wNCIsInN0IjowLCJkIjo0LCJ0Ijo4LCJiIjoyOCwiZSI6MjksIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1kYWVtb24tY29uc29sZS1sYW5lLXdlaWdodHMtMjAyNi0wNi0xMyIsInN0IjowLCJkIjo3LCJ0Ijo3LCJiIjozNywiZSI6MzcsIm8iOjIsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1jcmVkaXQtYnVybi1yYWlsLTIwMjYtMDYtMjIiLCJzdCI6MSwiZCI6MSwidCI6NywiYiI6NjEsImUiOjYyLCJvIjoyLCJkZXAiOltdLCJleHQiOlsicG9ydGZvbGlvLWJ1cm4tZG93bi1vcmNoZXN0cmF0aW9uLTIwMjYtMDctMTAiXSwib2QiOltdfSx7InMiOiJjcnV4LWRhZW1vbi12OC1jb3ZlcmFnZS1zY2FuLTIwMjYtMDYtMTMiLCJzdCI6MCwiZCI6MywidCI6MywiYiI6MzcsImUiOjM3LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtZG9tYWluLXN1YnN0cmF0ZS1hbmQtZmVhdHVyZXMtbGVucy0yMDI2LTA1LTE4Iiwic3QiOjAsImQiOjYsInQiOjcsImIiOjExLCJlIjoxMSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnVjaWJsZS1jb250cm9sLXBsYW5lLWFuZC1kZWVwLXJldHJpZXZhbC0yMDI2LTA2LTE4Iiwic3QiOjEsImQiOjAsInQiOjEsImIiOjQ4LCJlIjo1MCwibyI6NTMsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1jb25zb2xlLWRhdGEtcGxhbmUtd2lyaW5nLTIwMjYtMDUtMjEiLCJzdCI6MCwiZCI6MywidCI6NiwiYiI6MTQsImUiOjE0LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtZXh0ZXJuYWwtZmluZGluZ3MtcmVtZWRpYXRpb24tMjAyNi0wNy0xMCIsInN0IjowLCJkIjo3LCJ0Ijo3LCJiIjo2NCwiZSI6NjUsIm8iOjMsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1kYWVtb24taGFyZGVuaW5nLWF1ZGl0LWZpbmRpbmdzLTIwMjYtMDYtMDciLCJzdCI6MCwiZCI6NiwidCI6NiwiYiI6MzEsImUiOjMxLCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNyb3NzLXNlc3Npb24taWRlbnRpdHktcmVzb2x1dGlvbi0yMDI2LTA2LTE1Iiwic3QiOjAsImQiOjcsInQiOjcsImIiOjM5LCJlIjozOSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LWNvbnNvbGUtbGFuZS13ZWlnaHQtcG9saXNoLTIwMjYtMDYtMTQiLCJzdCI6MCwiZCI6NiwidCI6NiwiYiI6MzgsImUiOjM4LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtY2ktbWVyZ2UtcXVldWUtd2lyaW5nLTIwMjYtMDYtMjYiLCJzdCI6MCwiZCI6MywidCI6NCwiYiI6NTAsImUiOjUzLCJvIjoyMCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjcnV4LWFnZW50LWFjdGlvbi1sZWRnZXItdG9rZW4tYWNjb3VudGluZy0yMDI2LTA2LTExIiwic3QiOjAsImQiOjYsInQiOjYsImIiOjM1LCJlIjo0OCwibyI6NDcsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1hY3Rpdml0eS1sb2ctY29tcGxldGlvbi0yMDI2LTA2LTIzIiwic3QiOjAsImQiOjQsInQiOjUsImIiOjQ3LCJlIjo0OCwibyI6MzgsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1jb2RleC1hdXRoZW50aWNhdGlvbi0yMDI2LTA2LTEyIiwic3QiOjAsImQiOjQsInQiOjQsImIiOjM2LCJlIjo1NywibyI6NzYsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY3J1eC1hdWRpdC1jaGFpbi1kYXRhLWNvbnRyYWN0LTIwMjYtMDUtMjkiLCJzdCI6MCwiZCI6MSwidCI6NywiYiI6MjIsImUiOjIyLCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNydXgtYWdlbnQtcGFzc3BvcnQtbWNwLWJpbmRpbmctMjAyNi0wNi0xMCIsInN0IjowLCJkIjowLCJ0IjoxLCJiIjozNCwiZSI6MzQsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY29yZWNydXgtc2tpcC1jb21wYW5pb25zLXByb2plY3Rpb24tY29udHJvbC0yMDI2LTA1LTI5Iiwic3QiOjAsImQiOjAsInQiOjEsImIiOjIxLCJlIjoyMiwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjb3JlY3J1eGQtYzJwYS12YXVsdC1wa2ktcnVudGltZS1lbmFibGVtZW50LTIwMjYtMDUtMjkiLCJzdCI6MSwiZCI6MCwidCI6NywiYiI6MjEsImUiOjIxLCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNvcmVjcnV4ZC1ib29zdC1vdmVybGF5LXBlcnNpc3RlbmNlLTIwMjYtMDUtMjEiLCJzdCI6MCwiZCI6MSwidCI6NiwiYiI6MTQsImUiOjE1LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNvcmVjcnV4LXR1cmJvcXVhbnQtY2N4ZS1xdWFudC1tb2RlIiwic3QiOjEsImQiOjAsInQiOjYsImIiOjM2LCJlIjozNiwibyI6MTEsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY29yZWNydXgtdHJhaXQtZXhwYW5zaW9uLWxtZS1zLXN0cnVjdHVyYWwtbG9zc2VzLTIwMjYtMDUtMjEiLCJzdCI6MCwiZCI6MywidCI6NiwiYiI6MTQsImUiOjE1LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNvcmVjcnV4LXZlcm5hY3VsYXItdjQtc2NoZW1hLWFuZC1wcmVmaWx0ZXItMjAyNi0wNS0yMCIsInN0IjowLCJkIjowLCJ0Ijo4LCJiIjoxMywiZSI6MTMsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY29yZWNydXgtdGV4dC1zZWFyY2gtdGVuYW50LWlzb2xhdGlvbi0yMDI2LTA2LTMwIiwic3QiOjAsImQiOjUsInQiOjYsImIiOjU0LCJlIjo1NCwibyI6MiwiZGVwIjpbImNvcmVjcnV4LW9mZmxpbmUtc2VydmluZy1jb21wYW5pb25zLTIwMjYtMDYtMzAiXSwiZXh0IjpbImNjeGktcXVlcnktc2hhcGUtcm91dGluZy0yMDI2LTA2LTMwIl0sIm9kIjpbXX0seyJzIjoiY29ycHVzLXNlZ3JlZ2F0aW9uLWJ1bGstcmVwYXJ0aXRpb24tMjAyNi0wNi0yNiIsInN0IjowLCJkIjo0LCJ0Ijo2LCJiIjo1MCwiZSI6NTIsIm8iOjMzLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNvcmVjcnV4LXRyYW5zaXRpb24tZG9jLWNvbnRlbnQtcGxhbmUtY29udGFtaW5hdGlvbi0yMDI2LTA2LTEyIiwic3QiOjAsImQiOjIsInQiOjYsImIiOjM2LCJlIjozNywibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjb3JlY3J1eC10b3BvbG9neS1uby1saW5rLXBydW5lLTIwMjYtMDUtMjciLCJzdCI6MCwiZCI6MywidCI6NiwiYiI6MjAsImUiOjIxLCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNvcmVjcnV4LXRyYWl0LWV4cGFuc2lvbi1nbG9iYWwtZGVmYXVsdC1vbi0yMDI2LTA1LTIxIiwic3QiOjEsImQiOjAsInQiOjYsImIiOjE0LCJlIjozMywibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjb3JlY3J1eC10cmFpdC1leHBhbnNpb24tc3Vic3RyYXRlLWRlbnNpdHktYXV0by10dW5lLTIwMjYtMDUtMjEiLCJzdCI6MCwiZCI6NCwidCI6NiwiYiI6MTQsImUiOjE1LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNvcmVjcnV4ZC1jb21wYW5pb24taG90LXJlbG9hZC0yMDI2LTA1LTE4Iiwic3QiOjAsImQiOjAsInQiOjYsImIiOjExLCJlIjozNSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjb3JlY3J1eC1vZmZsaW5lLXNlcnZpbmctY29tcGFuaW9ucy0yMDI2LTA2LTMwIiwic3QiOjAsImQiOjYsInQiOjYsImIiOjU0LCJlIjo1NCwibyI6MzQsImRlcCI6W10sImV4dCI6WyJjY3hpLXF1ZXJ5LXNoYXBlLXJvdXRpbmctMjAyNi0wNi0zMCIsImNvcmVjcnV4LXRleHQtc2VhcmNoLXRlbmFudC1pc29sYXRpb24tMjAyNi0wNi0zMCJdLCJvZCI6W119LHsicyI6ImNvcmVjcnV4LXJlY3N0eWxlLWtleXdvcmQtZXh0ZW5zaW9uLTIwMjYtMDUtMjEiLCJzdCI6MCwiZCI6MywidCI6NSwiYiI6MTQsImUiOjE0LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNvcmVjcnV4LXByb21ldGhldXMtaW5kZXhtYW5hZ2VyLWRvdWJsZS1jb3VudC0yMDI2LTA1LTI4Iiwic3QiOjAsImQiOjAsInQiOjMsImIiOjIxLCJlIjoyMSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjb3JlY3J1eC1zZWFsLXNoYXJkLXZzLXRpY2stc2hhcmQtbWlzbWF0Y2gtMjAyNi0wNi0wMSIsInN0IjowLCJkIjowLCJ0IjoxLCJiIjoyNSwiZSI6MjUsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY29yZWNydXgtcXVlcnktZXhwYW5zaW9uLXZpYS10cmFpdC1lbWJlZGRpbmdzLTIwMjYtMDUtMjAiLCJzdCI6MCwiZCI6NCwidCI6NiwiYiI6MTQsImUiOjE0LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNvcmVjcnV4LWluZ2VzdC1leHRyYWN0aW9uLWZvbGxvd3Vwcy0yMDI2LTA2LTExIiwic3QiOjEsImQiOjYsInQiOjksImIiOjM1LCJlIjozNiwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjb3JlY3J1eC1yZXRyaWV2ZS1hZ2VudC1zaGFwZWQtcGF5bG9hZC0yMDI2LTA1LTE1Iiwic3QiOjEsImQiOjIsInQiOjksImIiOjIzLCJlIjoyNCwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjb3JlY3J1eC1sb2FkZWRzZWdtZW50LW1lbXN0YXRzLTIwMjYtMDUtMjMiLCJzdCI6MCwiZCI6MywidCI6NiwiYiI6MTUsImUiOjE1LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNvcmVjcnV4LWdwdTEtbWVtb3J5LXN0YWJpbGl6YXRpb24tMjAyNi0wNS0yOCIsInN0IjowLCJkIjoyLCJ0Ijo2LCJiIjoyMSwiZSI6MjQsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY29yZWNydXgtaW5nZXN0LWV4dHJhY3Rpb24tdG9wMTAtMjAyNi0wNi0xMSIsInN0IjowLCJkIjowLCJ0IjoxLCJiIjozNSwiZSI6MzUsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY29yZWNydXgtcXVlcnktZXhwYW5zaW9uLXJvbGxvdXQtY29tcGxldGlvbi0yMDI2LTA1LTIxIiwic3QiOjAsImQiOjMsInQiOjUsImIiOjE0LCJlIjozNSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjb3JlY3J1eC1uby1saW5rLXBydW5lLXN1YnN0cmF0ZS1yZWJ1aWxkLTIwMjYtMDUtMjkiLCJzdCI6MCwiZCI6MCwidCI6MSwiYiI6MjEsImUiOjIxLCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNvcmVjcnV4LWRhZW1vbi1mYXN0LXN0YXJ0dXAtMjAyNi0wNi0xNiIsInN0IjowLCJkIjo0LCJ0Ijo2LCJiIjo0MCwiZSI6NDAsIm8iOjE3LCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNvcmVjcnV4LWV2aWN0b3ItY29udmVyZ2VuY2UtMjAyNi0wNS0zMSIsInN0IjowLCJkIjozLCJ0Ijo0LCJiIjoyNCwiZSI6MjQsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY29kZXgtY3J1eC1zZXNzaW9uLWJhbm5lci0yMDI2LTA2LTAxIiwic3QiOjAsImQiOjgsInQiOjgsImIiOjI1LCJlIjoyOSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjaGFpbmNydXgtcGhhc2UxLTUtZXZlbnQtZWRnZXMtYW5kLXRlbXBvcmFsLWZpbHRlci0yMDI2LTA1LTIyIiwic3QiOjAsImQiOjAsInQiOjgsImIiOjE3LCJlIjoxNywibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjb250ZXh0LW1lZGlhdGlvbi1pbmplY3Rpb24tMjAyNi0wNi0xMSIsInN0IjoxLCJkIjo2LCJ0Ijo3LCJiIjozNiwiZSI6MzYsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY29yZWNydXgtYm0yNS02NGJpdC10ZW5hbnQtZmlsdGVyLTIwMjYtMDYtMTMiLCJzdCI6MSwiZCI6MCwidCI6MSwiYiI6MzcsImUiOjM3LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNvcmVjcnV4LWNhc2NhZGUtZW5nYWdlbWVudC1sbWUtcy0yMDI2LTA1LTIyIiwic3QiOjAsImQiOjIsInQiOjYsImIiOjE1LCJlIjoxNSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjbGF1ZGVjbGF3LXN1YnNjcmlwdGlvbi1zb25uZXQtYmFja2VuZC0yMDI2LTA2LTAzIiwic3QiOjAsImQiOjYsInQiOjYsImIiOjI3LCJlIjoyOCwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjb250ZXh0LWJlbmNoLXYyLTEwMHBvaW50LXRoaXJkcGFydHktYm9hcmQtMjAyNi0wNy0wMyIsInN0IjoxLCJkIjo2LCJ0Ijo3LCJiIjo1NywiZSI6NjUsIm8iOjIyLCJkZXAiOlsiY29udGV4dC1kZXBlbmRlbmNlLWJlbmNobWFyay1zY29yZWNydXgtMjAyNi0wNy0wMyJdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNvcmVjcnV4LWRvY3VtZW50LWluZGV4LWxhbmUtMjAyNi0wNS0xNSIsInN0IjowLCJkIjowLCJ0IjoxMSwiYiI6MTEsImUiOjExLCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNoYWluY3J1eC1waGFzZTEtcHJvdmUtZWFybmVkLWVkZ2UtMjAyNi0wNS0yMiIsInN0IjowLCJkIjowLCJ0Ijo3LCJiIjoxNSwiZSI6MTUsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY29yZWNydXgtYnVsay1pbmdlc3QtYXQtc2NhbGUtMjAyNi0wNi0xNCIsInN0IjowLCJkIjowLCJ0IjoxLCJiIjozOCwiZSI6NDgsIm8iOjYxLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNvcmVjcnV4LWJ1bGstaW5nZXN0LXBvbGlzaC0yMDI2LTA1LTAzIiwic3QiOjEsImQiOjAsInQiOjEsImIiOjY0LCJlIjo2NCwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjb2RlbWFwLWVuZHBvaW50LWFuZC1hZ2VudC1kb2NzLWhhcmRlbmluZy0yMDI2LTA3LTEwIiwic3QiOjAsImQiOjQsInQiOjQsImIiOjYzLCJlIjo2MywibyI6MCwiZGVwIjpbXSwiZXh0IjpbImNvZGVtYXBzLWNyb3NzLXJlcG8tZ3JhcGgtYW5kLXZhbHVlLWV4cGFuc2lvbi0yMDI2LTA3LTEwIl0sIm9kIjpbXX0seyJzIjoiY2xhd2QtdW5pZmllZC1kYWVtb24tcmVsb2NhdGlvbi1kYXRhMS0yMDI2LTA2LTEzIiwic3QiOjAsImQiOjcsInQiOjcsImIiOjM2LCJlIjozNywibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjb3JlY3J1eC1ldmlkZW5jZS1oYXNoLXJlcGxheS1kZWR1cC0yMDI2LTA2LTIzIiwic3QiOjAsImQiOjUsInQiOjUsImIiOjQ3LCJlIjo0OCwibyI6NDQsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY29tcGFuaW9uLWJ1aWxkLTQyOS1oYXJkZW5pbmctMjAyNi0wNi0xNiIsInN0IjowLCJkIjo2LCJ0Ijo2LCJiIjo0MCwiZSI6NDAsIm8iOjcsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY2hhaW5jcnV4LXplcm8tZXZlbnRzLXN1YnN0cmF0ZS1pbnZlc3RpZ2F0aW9uLTIwMjYtMDUtMjgiLCJzdCI6MSwiZCI6MCwidCI6NSwiYiI6MjEsImUiOjIxLCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNvZGVtYXBzLWZhY2V0LWNvdmVyYWdlLWNvbXBsZXRpb24tMjAyNi0wNy0xMiIsInN0IjoxLCJkIjowLCJ0Ijo2LCJiIjo2NiwiZSI6NjYsIm8iOjAsImRlcCI6WyJjb2RlbWFwcy1jcm9zcy1yZXBvLWdyYXBoLWFuZC12YWx1ZS1leHBhbnNpb24tMjAyNi0wNy0xMCJdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNvcmVjcnV4LWN1cmF0b3ItY2x1c3RlcmluZy1zcGlrZS0yMDI2LTA3LTA3Iiwic3QiOjAsImQiOjIsInQiOjMsImIiOjYxLCJlIjo2MSwibyI6MCwiZGVwIjpbImNvcmVjcnV4LW1lbW9yeS1tYW5hZ2VyLTIwMjYtMDctMDUiXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJjb3JlY3J1eC1ldmVudC1sYW5lLXJyZi13aXJpbmctMjAyNi0wNS0yNCIsInN0IjowLCJkIjowLCJ0Ijo4LCJiIjoxNywiZSI6MTcsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY29udGV4dC1jdXN0b2R5LXN1cmZhY2UtMjAyNi0wNi0zMCIsInN0IjowLCJkIjowLCJ0IjoxLCJiIjo1NCwiZSI6NTQsIm8iOjYsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY29udGV4dC1kZXBlbmRlbmNlLWJlbmNobWFyay1zY29yZWNydXgtMjAyNi0wNy0wMyIsInN0IjowLCJkIjoxLCJ0Ijo3LCJiIjo1NiwiZSI6NTcsIm8iOjE1LCJkZXAiOlsibWgtYWItdjItaGFybmVzcy1idWlsZC0yMDI2LTA2LTEyIl0sImV4dCI6WyJjb250ZXh0LWJlbmNoLXYyLTEwMHBvaW50LXRoaXJkcGFydHktYm9hcmQtMjAyNi0wNy0wMyJdLCJvZCI6W119LHsicyI6ImNvcmVjcnV4LWZsZWV0LWNvbnRyb2wtcGxhbmUtMjAyNi0wNy0wMyIsInN0IjoxLCJkIjoxLCJ0Ijo3LCJiIjo2NCwiZSI6NjQsIm8iOjIsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiY29kZXhjbGF3LWRldGVybWluaXN0aWMtZ2F0ZS1vcmNoZXN0cmF0aW9uLTIwMjYtMDUtMjYiLCJzdCI6MCwiZCI6MSwidCI6OCwiYiI6MTksImUiOjM1LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNoYWluY3J1eC1jYXNjYWRlLXJvdXRlLWludGVncmF0aW9uLTIwMjYtMDUtMjUiLCJzdCI6MCwiZCI6NCwidCI6OCwiYiI6MTgsImUiOjIxLCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImNjeGktcXVlcnktc2hhcGUtcm91dGluZy0yMDI2LTA2LTMwIiwic3QiOjEsImQiOjQsInQiOjYsImIiOjU0LCJlIjo1NCwibyI6MywiZGVwIjpbImNvcmVjcnV4LW9mZmxpbmUtc2VydmluZy1jb21wYW5pb25zLTIwMjYtMDYtMzAiLCJjb3JlY3J1eC10ZXh0LXNlYXJjaC10ZW5hbnQtaXNvbGF0aW9uLTIwMjYtMDYtMzAiLCJ1bmlmaWVkLXByb2R1Y3Rpb24tY2xhaW1zLXNvdXJjZS0yMDI2LTA2LTMwIiwidW5pZmllZC1yZWFzb25lci1lbmNvZGUtZXZpZGVuY2UtMjAyNi0wNi0yOSJdLCJleHQiOlsidW5pZmllZC1yZXRyaWV2YWwtaGFyZGVuaW5nLTIwMjYtMDctMDIiXSwib2QiOltdfSx7InMiOiJhdWRpdC1paS1nYXAtY2xvc3VyZS1oYXJkZW5pbmctMjAyNi0wNi0xNCIsInN0IjowLCJkIjowLCJ0IjoxMCwiYiI6NDcsImUiOjQ3LCJvIjozMywiZGVwIjpbXSwiZXh0IjpbImRvbWFpbi1pbmRleC1zb3VyY2UtYXV0aG9yaXR5LXNpZ25hbC0yMDI2LTA3LTA4Il0sIm9kIjpbXX0seyJzIjoiYXN0LXBvbHlnbG90LWNvZGUtZ3JhcGgtYW5kLXJlcG8td2F0Y2gtMjAyNi0wNy0wOCIsInN0IjowLCJkIjoxMCwidCI6MTAsImIiOjYyLCJlIjo2MywibyI6MiwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJhdWRpdC1paS1vcGVyYXRpb25hbC1oYXJkZW5pbmctcm9sbG91dC0yMDI2LTA2LTE0Iiwic3QiOjAsImQiOjEwLCJ0IjoxMCwiYiI6MzgsImUiOjM4LCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImF0bGFzLW1hbmlmZXN0LXJvdXRpbmctcHJvZHVjdGlvbi0yMDI2LTA2LTA1Iiwic3QiOjAsImQiOjExLCJ0IjoxMSwiYiI6MjksImUiOjY0LCJvIjo5MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOlsiT0QtMTAiXX0seyJzIjoiYWdlbnQtdXgtMDItYWNrbm93bGVkZ2VkLW1lbW9yeS11c2UtMjAyNi0wNS0yNyIsInN0IjowLCJkIjo0LCJ0Ijo0LCJiIjoyMCwiZSI6MjAsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiYWdlbnQtbmF0aXZlLW5vaXNlLXJlZHVjdGlvbi0yMDI2LTA2LTA4Iiwic3QiOjEsImQiOjAsInQiOjgsImIiOjMyLCJlIjo2NSwibyI6OTAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiYWdlbnQtdXgtMDMtZnJlc2huZXNzLWRlY2F5LTIwMjYtMDUtMjciLCJzdCI6MCwiZCI6NSwidCI6NiwiYiI6MjAsImUiOjIwLCJvIjowLCJkZXAiOltdLCJleHQiOlsiZGVuc2UtbGFuZS1hbmQtZXh0cmFjdGlvbi11cHNlbGwtMjAyNi0wNi0yNiJdLCJvZCI6W119LHsicyI6ImFnZW50LXF1ZXJ5LWV2YWwtY29ycHVzLTIwMjYtMDYtMDciLCJzdCI6MCwiZCI6MCwidCI6NiwiYiI6MzEsImUiOjMxLCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImFnZW50LXV4LWJlc3QtaW4tY2xhc3MtbWFzdGVyLTIwMjYtMDUtMjciLCJzdCI6MCwiZCI6MSwidCI6OSwiYiI6MjAsImUiOjIxLCJvIjowLCJkZXAiOltdLCJleHQiOltdLCJvZCI6W119LHsicyI6ImFnZW50LXV4LTA4LWlkZW50aXR5LWNvbnRpbnVpdHktMjAyNi0wNS0yNyIsInN0IjowLCJkIjozLCJ0Ijo1LCJiIjoyMSwiZSI6MjEsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiYWdlbnQtdXgtMDUtcmlzay10aWVyZWQtaGl0bC0yMDI2LTA1LTI3Iiwic3QiOjAsImQiOjMsInQiOjYsImIiOjIxLCJlIjoyMSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJhZ2VudC11eC0wNy12ZXJpZmlhYmxlLW91dHB1dC1yZWNlaXB0cy0yMDI2LTA1LTI3Iiwic3QiOjAsImQiOjUsInQiOjYsImIiOjIxLCJlIjoyMSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJhZ2VudC11eC0wNC1zb3VyY2UtbGlua2VkLXRyYWNlYWJpbGl0eS0yMDI2LTA1LTI3Iiwic3QiOjAsImQiOjMsInQiOjUsImIiOjIwLCJlIjoyMSwibyI6MCwiZGVwIjpbXSwiZXh0IjpbImRvbWFpbi1pbmRleC1zb3VyY2UtYXV0aG9yaXR5LXNpZ25hbC0yMDI2LTA3LTA4Il0sIm9kIjpbXX0seyJzIjoiYWdlbnQtdXgtMDYtdHlwZWQtYWN0aW9uLXRyYWNlcy0yMDI2LTA1LTI3Iiwic3QiOjAsImQiOjUsInQiOjgsImIiOjIwLCJlIjoyMCwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJhZ2VudC11eC0xMS1ieW8tYXVkaXQtdHJhaWwtMjAyNi0wNS0yNyIsInN0IjoxLCJkIjo0LCJ0Ijo2LCJiIjoyMCwiZSI6MjAsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiYWdlbnQtcXVlcnktZXZhbC1sYW5lcy1vbi1yZXRlc3QtMjAyNi0wNi0wOCIsInN0IjowLCJkIjowLCJ0Ijo1LCJiIjozMiwiZSI6MzMsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiYWdlbnQtdXgtMTAtdmlzaWJsZS1hdXRvbm9teS1jb250cmFjdC0yMDI2LTA1LTI3Iiwic3QiOjAsImQiOjIsInQiOjYsImIiOjIwLCJlIjoyMCwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJhbXItbGFuZS1hdXRob3JpdHktY3JlZGl0LWdhdGluZy0yMDI2LTA2LTA3Iiwic3QiOjEsImQiOjIsInQiOjcsImIiOjMxLCJlIjozMiwibyI6MCwiZGVwIjpbXSwiZXh0IjpbImRvbWFpbi1pbmRleC1zb3VyY2UtYXV0aG9yaXR5LXNpZ25hbC0yMDI2LTA3LTA4Il0sIm9kIjpbXX0seyJzIjoiYWdlbnQtY29uZmlnLXdpemFyZC0yMDI2LTA1LTE5Iiwic3QiOjAsImQiOjMsInQiOjgsImIiOjEyLCJlIjoxMiwibyI6NSwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfSx7InMiOiJhZ2VudC11eC0wMS1yZWFkYWJsZS1lZGl0YWJsZS1tZW1vcnktMjAyNi0wNS0yNyIsInN0IjowLCJkIjo0LCJ0Ijo0LCJiIjoyMCwiZSI6MjAsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiYWdlbnQtaGFybmVzcy10ZXN0YmVuY2gtbWVzc3l3b3JsZC0yMDI2LTA2LTE4Iiwic3QiOjEsImQiOjAsInQiOjcsImIiOjQxLCJlIjo2NSwibyI6OTQsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiYWdlbnQtdXgtMTItY2FsbS1kZWZlcnJlZC1vdXRwdXQtMjAyNi0wNS0yNyIsInN0IjowLCJkIjowLCJ0Ijo2LCJiIjoyMSwiZSI6MjEsIm8iOjAsImRlcCI6W10sImV4dCI6W10sIm9kIjpbXX0seyJzIjoiYWdlbnQtdXgtMDktc2NvcGVkLWZvcmdldC0yMDI2LTA1LTI3Iiwic3QiOjAsImQiOjIsInQiOjUsImIiOjIwLCJlIjoyMCwibyI6MCwiZGVwIjpbXSwiZXh0IjpbXSwib2QiOltdfV07CgovKiDilIDilIAgcGx1bWJpbmcg4pSA4pSAICovCmZ1bmN0aW9uIG11bGJlcnJ5MzIoYSkgewogIHJldHVybiBmdW5jdGlvbiAoKSB7CiAgICBhIHw9IDA7IGEgPSBhICsgMHg2RDJCNzlGNSB8IDA7CiAgICBsZXQgdCA9IE1hdGguaW11bChhIF4gYSA+Pj4gMTUsIDEgfCBhKTsKICAgIHQgPSB0ICsgTWF0aC5pbXVsKHQgXiB0ID4+PiA3LCA2MSB8IHQpIF4gdDsKICAgIHJldHVybiAoKHQgXiB0ID4+PiAxNCkgPj4+IDApIC8gNDI5NDk2NzI5NjsKICB9Owp9CmNvbnN0IFJFRFVDRUQgPSBtYXRjaE1lZGlhKCcocHJlZmVycy1yZWR1Y2VkLW1vdGlvbjogcmVkdWNlKScpLm1hdGNoZXM7CmNvbnN0IE1PTk8gPSAiJ0pldEJyYWlucyBNb25vJywgdWktbW9ub3NwYWNlLCBTRk1vbm8tUmVndWxhciwgTWVubG8sIG1vbm9zcGFjZSI7CmNvbnN0IHNzID0gdCA9PiB0IDw9IDAgPyAwIDogdCA+PSAxID8gMSA6IHQgKiB0ICogKDMgLSAyICogdCk7CmNvbnN0IG1peCA9IChhLCBiLCBrKSA9PiBhICsgKGIgLSBhKSAqIGs7CmNvbnN0IFRBVSA9IE1hdGguUEkgKiAyOwpmdW5jdGlvbiBoZXgycmdiYShoZXgsIGEpIHsKICBjb25zdCBuID0gcGFyc2VJbnQoaGV4LnNsaWNlKDEpLCAxNik7CiAgcmV0dXJuICdyZ2JhKCcgKyAobiA+PiAxNiAmIDI1NSkgKyAnLCcgKyAobiA+PiA4ICYgMjU1KSArICcsJyArIChuICYgMjU1KSArICcsJyArIE1hdGgubWF4KDAsIE1hdGgubWluKDEsIGEpKSArICcpJzsKfQpjb25zdCB0aXAgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGlwJyk7CmZ1bmN0aW9uIHNob3dUaXAoeCwgeSwgaHRtbCkgewogIHRpcC5pbm5lckhUTUwgPSBodG1sOwogIGNvbnN0IHBhZCA9IDE0LCB3ID0gdGlwLm9mZnNldFdpZHRoIHx8IDIyMDsKICB0aXAuc3R5bGUubGVmdCA9IE1hdGgubWluKHggKyBwYWQsIGlubmVyV2lkdGggLSB3IC0gMTApICsgJ3B4JzsKICB0aXAuc3R5bGUudG9wID0gKHkgKyBwYWQgKyB0aXAub2Zmc2V0SGVpZ2h0ID4gaW5uZXJIZWlnaHQgPyB5IC0gdGlwLm9mZnNldEhlaWdodCAtIDggOiB5ICsgcGFkKSArICdweCc7CiAgdGlwLnN0eWxlLm9wYWNpdHkgPSAxOwp9CmZ1bmN0aW9uIGhpZGVUaXAoKSB7IHRpcC5zdHlsZS5vcGFjaXR5ID0gMDsgfQoKLyog4pSA4pSAIHRpbWUgYmFzZTogZGF5IDAgPSAyMDI2LTA1LTA3IOKUgOKUgCAqLwpjb25zdCBOT1cgPSA3NjsgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvKiAyMDI2LTA3LTIyICovCmZ1bmN0aW9uIGRheURhdGUoZCkgewogIHJldHVybiBuZXcgRGF0ZShEYXRlLlVUQygyMDI2LCA0LCA3KSArIGQgKiA4NjQwMDAwMCkudG9JU09TdHJpbmcoKS5zbGljZSgwLCAxMCk7Cn0KCi8qIOKUgOKUgCBkYXRhc2V0IOKUgOKUgCAqLwpjb25zdCBLSU5EX0hVRSA9IHsgZ2F0ZTogJyMyZGQ0YmYnLCBkZWNpc2lvbjogJyNhNzhiZmEnLCBtZW1vcnk6ICcjOGI5NmYyJywgaGFuZG9mZjogJyNmNWE2MjMnLCBpbmNpZGVudDogJyNlZjQ0NDQnIH07CmNvbnN0IFNUQVRFID0geyAwOiAnY29tcGxldGUnLCAxOiAnaW5fcHJvZ3Jlc3MnLCAyOiAnYmxvY2tlZCcgfTsKLyogc3RhdGUgcGFsZXR0ZTogY29tcGxldGUgZ3JlZW4gwrcgaW4gcHJvZ3Jlc3MgcHVycGxlIMK3IGJsb2NrZWQgcmVkICovCmNvbnN0IFNUQVRFX0hVRSA9IHsgMDogJyMzNGQzOTknLCAxOiAnI2E3OGJmYScsIDI6ICcjZWY0NDQ0JyB9Owpjb25zdCBzdGF0ZUh1ZSA9IHAgPT4gU1RBVEVfSFVFW3Auc3RdOwpjb25zdCBQQVJLX0RBWVMgPSAxODsgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvKiBXb3JrSXRlbS5zdGFsZSBzZW1hbnRpY3MgKi8KCmNvbnN0IFBMQU5TID0gUExBTlNfUkFXLm1hcCgocCwgaSkgPT4gewogIGNvbnN0IHNob3J0ID0gcC5zLnJlcGxhY2UoLy0yMDI2LVxkXGQtXGRcZCQvLCAnJykucmVwbGFjZSgvLTIwMjYkLywgJycpOwogIC8qIGV4aXQgZGF5OiBjb21wbGV0ZSDihpIgZSArIDEuNTsgaW5fcHJvZ3Jlc3MvYmxvY2tlZCDihpIgcGFyayBhdCBlICsgUEFSS19EQVlTIChuZXZlciBpZiByZWNlbnQpICovCiAgY29uc3QgZXhpdCA9IHAuc3QgPT09IDAgPyBwLmUgKyAxLjUgOiAoTk9XIC0gcC5lID4gUEFSS19EQVlTID8gcC5lICsgUEFSS19EQVlTIDogSW5maW5pdHkpOwogIHJldHVybiB7IGksIHNsdWc6IHAucywgc2hvcnQsIHN0OiBwLnN0LCBkb25lOiBwLmQsIHRvdGFsOiBwLnQgfHwgMSwgYjogTWF0aC5tYXgoMCwgcC5iKSwgZTogcC5lLCBvOiBwLm8sIGV4aXQsCiAgICAgICAgICAgZGVwOiBwLmRlcCB8fCBbXSwgZXh0OiBwLmV4dCB8fCBbXSwgb2Q6IHAub2QgfHwgW10sCiAgICAgICAgICAgdHJhY2VkOiBwLnMuc3RhcnRzV2l0aCgnY3J1eC1kYWVtb24tYnV5ZXItZml0JykgfHwgcC5zLnN0YXJ0c1dpdGgoJ2Nyb3NzLXNpdGUtYXV0aC1zc28nKSB9Owp9KTsKLyogbGluZWFnZSBlZGdlcyByZXNvbHZhYmxlIHdpdGhpbiB0aGUgZW1iZWRkZWQgc2V0OiBhIGRlcGVuZHNfb24gYiAqLwpjb25zdCBieVNsdWcgPSBPYmplY3QuZnJvbUVudHJpZXMoUExBTlMubWFwKHAgPT4gW3Auc2x1ZywgcF0pKTsKY29uc3QgREVQX0VER0VTID0gW107CmZvciAoY29uc3QgcCBvZiBQTEFOUykgZm9yIChjb25zdCBkIG9mIHAuZGVwKSB7CiAgY29uc3QgdDIgPSBieVNsdWdbZF07CiAgaWYgKHQyKSBERVBfRURHRVMucHVzaCh7IGE6IHAsIGI6IHQyIH0pOwp9CgovKiByZWFsIGZhY3RzIGZvciB0aGUgdHdvIHRyYWNlZCBwbGFucyAoZGF5ID0gNjcgKyBvZmZzZXQgZnJvbSBKdWwgMTMpICovCmNvbnN0IEoxMyA9IDY3OyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8qIDIwMjYtMDctMTMgYXMgZGF5IGluZGV4ICovCmNvbnN0IFJGQUNUUyA9IFsKICBbJ3NzbycsICdicmllZicsICdtZW1vcnknLCAwLjkyMCwgJ2NvZGV4LXdvcmsnLCAnbWVkaXVtJywgMjA1LCAxXSwKICBbJ3NzbycsICdnYXRlOk0wJywgJ2dhdGUnLCAwLjkzNiwgJ2NvZGV4LXdvcmsnLCAnbWVkaXVtJywgMjA1LCAxXSwKICBbJ3NzbycsICdkZWNpc2lvbjp0b3BvbG9neS1jb3JyZWN0ZWQtY3J1eGVuZ2luZScsICdkZWNpc2lvbicsIDAuOTQ4LCAnY29kZXgtd29yaycsICdtZWRpdW0nLCAyMDcsIDFdLAogIFsnc3NvJywgJ21pbGVzdG9uZTpNMS1wYXJ0aWFsJywgJ21lbW9yeScsIDAuOTkwLCAnY29kZXgtd29yaycsICdtZWRpdW0nLCAyNzUsIDFdLAogIFsnYmYnLCAnZ2F0ZTpNMCcsICdnYXRlJywgMS4zNTYsICdjb2RleC13b3JrJywgJ3N0YWJsZScsIDQxMiwgMV0sCiAgWydzc28nLCAnZ2F0ZTpNMScsICdnYXRlJywgMS4zODEsICdjb2RleC13b3JrJywgJ21lZGl1bScsIDI5NiwgMV0sCiAgWydzc28nLCAnZ2F0ZTpNMicsICdnYXRlJywgMS42NDksICdjb2RleC13b3JrJywgJ21lZGl1bScsIDIzNiwgMV0sCiAgWydiZicsICdnYXRlOk0xJywgJ2dhdGUnLCAxLjY2OSwgJ2NvZGV4LXdvcmsnLCAnc3RhYmxlJywgNTM2LCAxXSwKICBbJ3NzbycsICdnYXRlOk0zLU00JywgJ2dhdGUnLCAxLjgyOSwgJ2NvZGV4LXdvcmsnLCAnbWVkaXVtJywgMzI4LCAxXSwKICBbJ2JmJywgJ2dhdGU6TTInLCAnZ2F0ZScsIDEuODQ3LCAnY29kZXgtd29yaycsICdzdGFibGUnLCA0NjMsIDFdLAogIFsnYmYnLCAnZ2F0ZTpNNCcsICdnYXRlJywgMS44NTgsICdjb2RleC13b3JrJywgJ3N0YWJsZScsIDQwOSwgMV0sCiAgWydiZicsICdoYW5kb2ZmOjIwMjYtMDctMTQnLCAnaGFuZG9mZicsIDEuODgyLCAnY29kZXgtd29yaycsICdzdGFibGUnLCA0MDksIDFdLAogIFsnc3NvJywgJ2NvbnNvbGUtdjEtcmVtb3ZlZCcsICdtZW1vcnknLCAxLjg5MiwgJ2NvZGV4LXdvcmsnLCAnbWVkaXVtJywgMjg4LCAxXSwKICBbJ2JmJywgJ3Byb2dyZXNzOk0zJywgJ21lbW9yeScsIDEuOTA5LCAnY29kZXgtd29yaycsICd2b2xhdGlsZScsIDI3NCwgMV0sCiAgWydiZicsICdnYXRlOk0zJywgJ2dhdGUnLCAxLjk1MSwgJ2NvZGV4LXdvcmsnLCAnc3RhYmxlJywgMzE2LCAxXSwKICBbJ2JmJywgJ2dhdGU6TTMnLCAnZ2F0ZScsIDIuMDMyLCAnY29kZXgtd29yaycsICdzdGFibGUnLCAyMTUsIDJdLAogIFsnc3NvJywgJ2NvbnNvbGUtdjEtcmVtb3ZlZC1mb2xsb3d1cC1kb25lJywgJ21lbW9yeScsIDIuODkxLCAnY29kZXgtd29yaycsICdtZWRpdW0nLCAzMjksIDFdLAogIFsnc3NvJywgJ2dhdGU6TTEtUi1jb2RlJywgJ2dhdGUnLCA4LjU5NywgJ2NsYXVkZS13b3JrJywgJ21lZGl1bScsIDEyNywgMV0sCiAgWydzc28nLCAnZGVjaXNpb246dmF1bHQtdGFyZ2V0LXJlZ3Jlc3Npb24tcmVwYWlyJywgJ2RlY2lzaW9uJywgOC41OTcsICdjbGF1ZGUtd29yaycsICdzdGFibGUnLCAxNTUsIDFdLAogIFsnYmYnLCAnZ2F0ZTpNNWInLCAnZ2F0ZScsIDkuMzY3LCAnY2xhdWRlLXdvcmsnLCAnc3RhYmxlJywgMTg0LCAxXSwKICBbJ2JmJywgJ2RlY2lzaW9uOm01Yi1pbnN0YWxsZXItdHJhbnNhY3Rpb24nLCAnZGVjaXNpb24nLCA5LjM2NywgJ2NsYXVkZS13b3JrJywgJ3N0YWJsZScsIDIzMiwgMV0sCl07CgovKiBjZWxsczogcmVhbCBmb3IgdHJhY2VkIHBsYW5zLCBtaWxlc3RvbmUtZGVyaXZlZCBmb3IgdGhlIHJlc3QgKi8KY29uc3QgY2VsbHMgPSBbXTsKKGZ1bmN0aW9uIG1ha2VDZWxscygpIHsKICBjb25zdCByciA9IG11bGJlcnJ5MzIoMHhDNEM0KTsKICBmb3IgKGNvbnN0IHAgb2YgUExBTlMpIHsKICAgIGlmIChwLnRyYWNlZCkgewogICAgICBjb25zdCB0YWcgPSBwLnNsdWcuc3RhcnRzV2l0aCgnY3J1eC1kYWVtb24tYnV5ZXItZml0JykgPyAnYmYnIDogJ3Nzbyc7CiAgICAgIGZvciAoY29uc3QgciBvZiBSRkFDVFMpIHsKICAgICAgICBpZiAoclswXSAhPT0gdGFnKSBjb250aW51ZTsKICAgICAgICBjZWxscy5wdXNoKHsgcCwga2V5OiByWzFdLCBraW5kOiByWzJdLCBkYXk6IEoxMyArIHJbM10sIGFjdG9yOiByWzRdLCBob3Jpem9uOiByWzVdLAogICAgICAgICAgICAgICAgICAgICB0b2tlbnM6IHJbNl0sIHZlcnNpb246IHJbN10sIHJlYWw6IHRydWUsIGphOiBycigpLCBqcjogcnIoKSB9KTsKICAgICAgfQogICAgICBjb250aW51ZTsKICAgIH0KICAgIGNvbnN0IHNwYW4gPSBNYXRoLm1heCgwLjUsIHAuZSAtIHAuYik7CiAgICBjb25zdCBuR2F0ZXMgPSBNYXRoLm1pbihwLmRvbmUsIDEyKTsKICAgIGZvciAobGV0IG0gPSAwOyBtIDwgbkdhdGVzOyBtKyspIHsKICAgICAgY2VsbHMucHVzaCh7IHAsIGtleTogJ2dhdGU6TScgKyBtLCBraW5kOiAnZ2F0ZScsIGRheTogcC5iICsgc3BhbiAqICgobSArIDEpIC8gKG5HYXRlcyArIDEpKSwKICAgICAgICAgICAgICAgICAgIHJlYWw6IGZhbHNlLCBqYTogcnIoKSwganI6IHJyKCkgfSk7CiAgICB9CiAgICBjb25zdCBuTWVtID0gTWF0aC5tYXgoMSwgTWF0aC5taW4oNiwgTWF0aC5yb3VuZChzcGFuIC8gNikgKyAocC5vID4gMCA/IDIgOiAwKSkpOwogICAgZm9yIChsZXQgbSA9IDA7IG0gPCBuTWVtOyBtKyspIHsKICAgICAgY29uc3Qga2luZHMgPSBbJ21lbW9yeScsICdtZW1vcnknLCAnZGVjaXNpb24nXTsKICAgICAgY29uc3Qga2sgPSBraW5kc1tNYXRoLmZsb29yKHJyKCkgKiAzKV07CiAgICAgIGNlbGxzLnB1c2goeyBwLCBrZXk6IGtrLCBraW5kOiBraywgZGF5OiBwLmIgKyBzcGFuICogcnIoKSwKICAgICAgICAgICAgICAgICAgIHJlYWw6IGZhbHNlLCBqYTogcnIoKSwganI6IHJyKCkgfSk7CiAgICB9CiAgfQogIC8qIHBlci1wbGFuIGRyYXcgbGlzdCwgb2xkZXN0IExBU1QgKHNvIG9sZGVyIGJhcnMgcGFpbnQgb24gdG9wKTsKICAgICBkYXktcmFuayBkcml2ZXMgdGhlIGNsb2Nrd2lzZSBpbi1zZWN0b3Igc3ByZWFkICovCiAgZm9yIChjb25zdCBwIG9mIFBMQU5TKSB7CiAgICBwLmNlbGxzID0gY2VsbHMuZmlsdGVyKGMgPT4gYy5wID09PSBwKS5zb3J0KChhLCBiKSA9PiBiLmRheSAtIGEuZGF5KTsKICAgIGNvbnN0IGFzYyA9IFsuLi5wLmNlbGxzXS5zb3J0KChhLCBiKSA9PiBhLmRheSAtIGIuZGF5KTsKICAgIGFzYy5mb3JFYWNoKChjLCBrKSA9PiB7IGMucmFuayA9IGs7IGMubiA9IGFzYy5sZW5ndGg7IH0pOwogICAgLyogcmltIHRva2VuIHdlaWdodCBwZXIgRVZFTlQg4oCUIHRoZSBjaGFydCBpcyBhbmNob3JlZCB0byB0aGUgZXZlbnQgbGluZXMgKi8KICAgIGZvciAoY29uc3QgYyBvZiBhc2MpIHsKICAgICAgYy50b2tXID0gKGMua2luZCA9PT0gJ2dhdGUnID8gMyA6IGMua2luZCA9PT0gJ2RlY2lzaW9uJyA/IDIgOiAxKSArIChjLnRva2VucyA/IGMudG9rZW5zIC8gMjUwIDogMCk7CiAgICB9CiAgICBwLnRva01heCA9IE1hdGgubWF4KDAuMDAxLCAuLi5hc2MubWFwKGMgPT4gYy50b2tXKSk7CiAgICAvKiBoZWlnaHQgc2NhbGU6IGhlYXZpZXIgcGxhbnMgKG91dHB1dCB0b2tlbnMpIGdldCB0YWxsZXIgcmltIGNoYXJ0cyAqLwogICAgcC50b2tTY2FsZSA9IDAuMzUgKyAwLjY1ICogTWF0aC5taW4oMSwgTWF0aC5sb2coMSArIHAubykgLyBNYXRoLmxvZyg4MSkpOwogIH0KfSkoKTsKCi8qIOKUgOKUgCB2aWV3IHN0YXRlIOKUgOKUgCAqLwpsZXQgcm90ID0gMCwgc3Bpbm5pbmcgPSAhUkVEVUNFRCwgcmVzZXRUd2VlbiA9IGZhbHNlOwpsZXQgbW9kZSA9ICdiYXJzJzsgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvKiBkb3RzIHwgYmFycyDigJQgYmFycyBieSBkZWZhdWx0ICovCmxldCBzaG93Q29tcGxldGVkID0gZmFsc2U7ICAgICAgICAgICAgICAgICAgICAgICAgIC8qIGNvbXBsZXRlZCBwbGFucyBvbiB0aGUgY2xvY2s7IGF1dG8tb24gd2hpbGUgcGxheWluZyAqLwpsZXQgc2hvd0xlZGdlciA9IGZhbHNlOyAgICAgICAgICAgICAgICAgICAgICAgICAgICAvKiBjb21wbGV0ZWQgbGlzdCAobGVmdCk7IGF1dG8tb24gZHVyaW5nIHBsYXksIG9mZiBvbiBsZW5zIHN3YXAgKi8KbGV0IGRpciA9ICdvdXQnOyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLyogb3V0OiByaW5ncyBncm93IGZyb20gY2VudHJlIMK3IGluOiBub2RlcyBzaW5rIGZyb20gcmltICovCmxldCBzaG93QWxsID0gZmFsc2U7ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8qIGNlbnN1cyBtb2RlOiBub3RoaW5nIHJldGlyZXMgb2ZmIHRoZSBjbG9jayAqLwpsZXQgaG92ZXJTZWMgPSBudWxsOyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvKiBwbGFuIHdob3NlIHNlY3RvciBpcyB1bmRlciB0aGUgcG9pbnRlciAqLwpsZXQgY29sb3JCeVN0YXRlID0gZmFsc2U7ICAgICAgICAgICAgICAgICAgICAgICAgICAvKiBub2RlcyBjb2xvdXJlZCBieSBwbGFuIHN0YXRlIGluc3RlYWQgb2Yga2luZCAqLwpsZXQgc2hvd0xpbmVhZ2UgPSBmYWxzZTsgICAgICAgICAgICAgICAgICAgICAgICAgICAvKiBhbGwgZGVwZW5kc19vbiBjaG9yZHMgZmFpbnRseSB2aXNpYmxlICovCmxldCBsZW5zID0gJ3dvcmsnOyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8qIHdvcmsgfCBtZW1vcnkgfCBzZXNzaW9ucyB8IHJlY2VpcHRzICovCmxldCBsZW5zTGFiZWxzID0gW107ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8qIHNjcmVlbi1zcGFjZSBsYWJlbHMgc2V0IGJ5IGxlbnMgcmVuZGVyZXJzICovCmxldCBmS2luZCA9ICdhbGwnLCBmQWdlbnQgPSAnYWxsJzsgICAgICAgICAgICAgICAgIC8qIG5vZGUgZmlsdGVycyAqLwpjb25zdCBwYXNzRmlsdGVyID0gYyA9PgogIChmS2luZCA9PT0gJ2FsbCcgfHwgYy5raW5kID09PSBmS2luZCkgJiYKICAoZkFnZW50ID09PSAnYWxsJyB8fCBjLmFjdG9yID09PSBmQWdlbnQpOwpsZXQgUyA9IDExLCBFID0gTk9XLCBUID0gTk9XOyAgICAgICAgICAgICAgICAgICAgICAvKiB3aW5kb3cgKyBwbGF5aGVhZCAoZGF5cykgKi8KbGV0IHBsYXlpbmcgPSBmYWxzZTsKbGV0IFogPSAxLCBwYW5YID0gMCwgcGFuWSA9IDA7CmxldCBob3ZlciA9IG51bGwsIHBpbm5lZCA9IG51bGw7ICAgICAgICAgICAgICAgICAgIC8qIHBpbm5lZCA9IHNlbGVjdGVkIGNlbGwgKGhpZ2hsaWdodCByaW5nKSAqLwpsZXQgc2VsID0gbnVsbDsgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvKiB7dHlwZTonY2VsbCcsIGN9IHwge3R5cGU6J3BsYW4nLCBwfSDihpIgcGFuZSAqLwpsZXQgc29sbyA9IG51bGw7ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvKiBsZWRnZXIgZmlsdGVyOiBzaG93IG9ubHkgdGhpcyBwbGFuICovCmxldCBsZWRnZXJSb3dzID0gW107ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8qIHNjcmVlbiByZWN0cyBmb3IgbGVkZ2VyIGhpdC10ZXN0aW5nICovCmxldCBteEFicyA9IDAsIG15QWJzID0gMDsKbGV0IGRyYWdnaW5nID0gZmFsc2UsIGRyYWdNb3ZlZCA9IDAsIGxhc3RQWCA9IDAsIGxhc3RQWSA9IDA7CmNvbnN0IGZsYXNoZXMgPSBbXTsgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8qIHthbmcwLCBhbmcxLCByLCBodWUsIHQwfSBleGl0L2VudGVyIGZsYXNoZXMgKi8KCmNvbnN0IGJTcGluID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2Itc3BpbicpOwpjb25zdCBiQ2xvY2sgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYi1jbG9jaycpOwpjb25zdCBiTW9kZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdiLW1vZGUnKTsKY29uc3QgYlBsYXkgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYi1wbGF5Jyk7CmNvbnN0IHJTdGFydCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdyLXN0YXJ0Jyk7CmNvbnN0IHJFbmQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnci1lbmQnKTsKY29uc3QgclRpbWUgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnci10aW1lJyk7CmNvbnN0IGNEYXRlID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2MtZGF0ZScpOwoKLyog4pSA4pSAIGFjdGl2ZSBzZXQgKyBhbmltYXRlZCBzZWN0b3IgbGF5b3V0IOKUgOKUgCAqLwovKiBlYWNoIHBsYW46IGxheSA9IHthMCwgYTEsIGFscGhhfSBsZXJwZWQgdG93YXJkIHRhcmdldHMgKi8KY29uc3QgU0VBTSA9IDAuMTA7ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLyogZ2FwIGF0IDEyIG8nY2xvY2sgKi8KY29uc3QgQkFTRSA9IC1NYXRoLlBJIC8gMiArIFNFQU0gLyAyOyAgICAgICAgICAgICAgLyogMTI6MDEgKi8KZnVuY3Rpb24gYWN0aXZlUGxhbnModCkgewogIGlmIChzb2xvKSByZXR1cm4gW3NvbG9dOwogIGxldCBvdXQ7CiAgaWYgKHNob3dBbGwpIG91dCA9IFBMQU5TLmZpbHRlcihwID0+IHAuYiA8PSB0ICYmIHAuZSA+PSBTIC0gMC4wMDEgJiYgcC5iIDw9IEUpOwogIGVsc2Ugb3V0ID0gUExBTlMuZmlsdGVyKHAgPT4gcC5iIDw9IHQgJiYgdCA8IHAuZXhpdCAmJiBwLmUgPj0gUyAtIDAuMDAxICYmIHAuYiA8PSBFKTsKICBpZiAoIXNob3dDb21wbGV0ZWQpIG91dCA9IG91dC5maWx0ZXIocCA9PiBwLnN0ICE9PSAwKTsKICByZXR1cm4gb3V0Owp9CmZ1bmN0aW9uIGxheW91dFRhcmdldHModCkgewogIGlmIChzb2xvKSB7CiAgICAvKiBzb2xvOiB0aGUgcGxhbiBzcGFucyAxMiDihpIgOSBvJ2Nsb2NrOyB0aGUgOeKGkjEyIHF1YWRyYW50IGJlY29tZXMgdGhlCiAgICAgICBldmVudCBsZWRnZXIgKi8KICAgIGNvbnN0IG91dCA9IG5ldyBNYXAoKTsKICAgIG91dC5zZXQoc29sby5pLCB7IGEwOiAtTWF0aC5QSSAvIDIgKyAwLjAyLCBhMTogTWF0aC5QSSAtIDAuMDIgfSk7CiAgICByZXR1cm4gb3V0OwogIH0KICBjb25zdCBhY3QgPSBhY3RpdmVQbGFucyh0KS5zb3J0KChhLCBiKSA9PiBiLmIgLSBhLmIgfHwgYS5pIC0gYi5pKTsgIC8qIG5ld2VzdCBmaXJzdCAqLwogIGNvbnN0IHdpZHRoID0gKFRBVSAtIFNFQU0pIC8gTWF0aC5tYXgoMSwgYWN0Lmxlbmd0aCk7CiAgY29uc3Qgb3V0ID0gbmV3IE1hcCgpOwogIGFjdC5mb3JFYWNoKChwLCBrKSA9PiBvdXQuc2V0KHAuaSwgeyBhMDogQkFTRSArIGsgKiB3aWR0aCwgYTE6IEJBU0UgKyAoayArIDEpICogd2lkdGggfSkpOwogIHJldHVybiBvdXQ7Cn0KZnVuY3Rpb24gc3RlcExheW91dChkdCkgewogIGNvbnN0IHRhcmdldHMgPSBsYXlvdXRUYXJnZXRzKFQpOwogIGNvbnN0IGsgPSBSRURVQ0VEID8gMSA6IE1hdGgubWluKDEsIGR0ICogNyk7CiAgZm9yIChjb25zdCBwIG9mIFBMQU5TKSB7CiAgICBjb25zdCB0ZyA9IHRhcmdldHMuZ2V0KHAuaSk7CiAgICBpZiAodGcpIHsKICAgICAgaWYgKCFwLmxheSkgeyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLyogZW50ZXI6IGJsb29tIGZyb20gdGFyZ2V0IG1pZCAqLwogICAgICAgIGNvbnN0IG1pZCA9ICh0Zy5hMCArIHRnLmExKSAvIDI7CiAgICAgICAgcC5sYXkgPSB7IGEwOiBtaWQsIGExOiBtaWQsIGFscGhhOiAwIH07CiAgICAgICAgaWYgKGZsYXNoZXMubGVuZ3RoIDwgNDApICAgICAgICAgICAgICAgICAgIC8qIGNhcDogdG9nZ2xpbmcgY2Vuc3VzIG1vZGUgYmlydGhzIDE2MCsgYXQgb25jZSAqLwogICAgICAgICAgZmxhc2hlcy5wdXNoKHsga2luZDogJ2VudGVyJywgYW5nOiBtaWQsIHQwOiBwZXJmb3JtYW5jZS5ub3coKSAvIDEwMDAsIGh1ZTogJyM4Yjk2ZjInIH0pOwogICAgICB9CiAgICAgIHAubGF5LmEwID0gbWl4KHAubGF5LmEwLCB0Zy5hMCwgayk7CiAgICAgIHAubGF5LmExID0gbWl4KHAubGF5LmExLCB0Zy5hMSwgayk7CiAgICAgIHAubGF5LmFscGhhID0gbWl4KHAubGF5LmFscGhhLCAxLCBrKTsKICAgIH0gZWxzZSBpZiAocC5sYXkpIHsgICAgICAgICAgICAgICAgICAgICAgICAgICAgLyogZXhpdDogY29sbGFwc2UgKyBmbGFzaCBvbmNlICovCiAgICAgIGlmICghcC5sYXkuZXhpdGluZykgewogICAgICAgIHAubGF5LmV4aXRpbmcgPSB0cnVlOwogICAgICAgIGNvbnN0IG1pZCA9IChwLmxheS5hMCArIHAubGF5LmExKSAvIDI7CiAgICAgICAgY29uc3QgaHVlID0gcC5zdCA9PT0gMCA/ICcjMzRkMzk5JyA6IHAuc3QgPT09IDIgPyAnI2VmNDQ0NCcgOiAnIzdlODU5NSc7CiAgICAgICAgZmxhc2hlcy5wdXNoKHsga2luZDogJ2V4aXQnLCBhbmc6IG1pZCwgdDA6IHBlcmZvcm1hbmNlLm5vdygpIC8gMTAwMCwgaHVlIH0pOwogICAgICB9CiAgICAgIGNvbnN0IG1pZCA9IChwLmxheS5hMCArIHAubGF5LmExKSAvIDI7CiAgICAgIHAubGF5LmEwID0gbWl4KHAubGF5LmEwLCBtaWQsIGspOwogICAgICBwLmxheS5hMSA9IG1peChwLmxheS5hMSwgbWlkLCBrKTsKICAgICAgcC5sYXkuYWxwaGEgPSBtaXgocC5sYXkuYWxwaGEsIDAsIGspOwogICAgICBpZiAocC5sYXkuYWxwaGEgPCAwLjAyKSBwLmxheSA9IG51bGw7CiAgICB9CiAgICBpZiAocC5sYXkgJiYgIXRhcmdldHMuZ2V0KHAuaSkpIHsgLyoga2VlcCBleGl0aW5nICovIH0KICAgIGVsc2UgaWYgKHAubGF5KSBwLmxheS5leGl0aW5nID0gZmFsc2U7CiAgfQp9CgovKiDilIDilIAgc3RhZ2Ug4pSA4pSAICovCmNvbnN0IGN2ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2N2Jyk7CmNvbnN0IGN0eCA9IGN2LmdldENvbnRleHQoJzJkJyk7CmxldCBXID0gMCwgSCA9IDAsIHZpc2libGUgPSB0cnVlLCByYWZJZCA9IG51bGwsIGxhc3RUID0gcGVyZm9ybWFuY2Uubm93KCk7CmZ1bmN0aW9uIHJlc2l6ZSgpIHsKICBjb25zdCByID0gY3YuZ2V0Qm91bmRpbmdDbGllbnRSZWN0KCksIGRwciA9IE1hdGgubWluKGRldmljZVBpeGVsUmF0aW8gfHwgMSwgMik7CiAgVyA9IHIud2lkdGg7IEggPSByLmhlaWdodDsKICBjdi53aWR0aCA9IE1hdGgucm91bmQoVyAqIGRwcik7IGN2LmhlaWdodCA9IE1hdGgucm91bmQoSCAqIGRwcik7CiAgY3R4LnNldFRyYW5zZm9ybShkcHIsIDAsIDAsIGRwciwgMCwgMCk7Cn0KbmV3IFJlc2l6ZU9ic2VydmVyKHJlc2l6ZSkub2JzZXJ2ZShjdik7Cm5ldyBJbnRlcnNlY3Rpb25PYnNlcnZlcihlcyA9PiB7IHZpc2libGUgPSBlc1swXS5pc0ludGVyc2VjdGluZzsgfSwgeyByb290TWFyZ2luOiAnNjBweCcgfSkub2JzZXJ2ZShjdik7Cgpjb25zdCBFUE9DSF9SSU5HUyA9IDEwOwpmdW5jdGlvbiBnZW9tKCkgewogIGNvbnN0IGN4ID0gVyAvIDIsIGN5ID0gSCAvIDI7CiAgY29uc3QgUiA9IE1hdGgubWluKFcgKiAwLjksIEggKiAwLjc4KSAqIDAuNDQ7CiAgY29uc3QgcjAgPSBSICogMC4xMzsKICByZXR1cm4geyBjeCwgY3ksIFIsIHIwIH07Cn0KLyogcmFkaXVzIGZvciBhIGRheS4KICAgb3V0OiByYWRpdXMgZml4ZWQgYnkgYmlydGggdGltZSDigJQgZWFybHkgaW5uZXIsIGxhdGUgb3V0ZXIsIGVkZ2Ugc3dlZXBzIG91dC4KICAgaW4gOiByYWRpdXMgYnkgQUdFIGF0IFQg4oCUIGJvcm4gYXQgdGhlIHJpbSwgc2lua3MgdG93YXJkIHRoZSBoZWFydHdvb2QuCiAgIFJBRF9MTyBpcyB0aGUgcmFkaWFsIHRpbWUgZmxvb3I6IGluIHRoZSBhY3RpdmUtcGxhbnMgd29yayB2aWV3IGl0IHNuYXBzIHRvCiAgIHRoZSBvbGRlc3QgVklTSUJMRSBub2RlIHNvIHJpbmcgMSBpcyBhbHdheXMgb2NjdXBpZWQg4oCUIG90aGVyd2lzZSwgeWVhcnMKICAgaW4sIGV2ZXJ5IGxpdmUgbm9kZSB3b3VsZCBjcm93ZCB0aGUgb3V0ZXIgcmltLiBDZW5zdXMvc29sby9vdGhlciBsZW5zZXMKICAga2VlcCB0aGUgZnVsbCB3aW5kb3cuICovCmxldCBSQURfTE8gPSAxMTsKZnVuY3Rpb24gZGF5UihnLCBkYXkpIHsKICBpZiAoZGlyID09PSAnaW4nKSB7CiAgICBjb25zdCBhZ2UgPSBNYXRoLm1heCgwLCBNYXRoLm1pbigxLCAoVCAtIGRheSkgLyBNYXRoLm1heCgwLjUsIFQgLSBSQURfTE8pKSk7CiAgICByZXR1cm4gZy5yMCArIChnLlIgLSBnLnIwKSAqICgwLjk2IC0gMC44OCAqIGFnZSk7CiAgfQogIGNvbnN0IGYgPSBNYXRoLm1heCgwLCBNYXRoLm1pbigxLCAoZGF5IC0gUkFEX0xPKSAvIE1hdGgubWF4KDAuNSwgRSAtIFJBRF9MTykpKTsKICByZXR1cm4gZy5yMCArIChnLlIgLSBnLnIwKSAqICgwLjA4ICsgMC44OCAqIGYpOwp9CmZ1bmN0aW9uIHVwZGF0ZVJhZExvKCkgewogIFJBRF9MTyA9IFM7CiAgaWYgKGxlbnMgIT09ICd3b3JrJyB8fCBzaG93QWxsIHx8IHNvbG8pIHJldHVybjsKICBsZXQgbG8gPSBJbmZpbml0eTsKICBmb3IgKGNvbnN0IHAgb2YgYWN0aXZlUGxhbnMoVCkpIHsKICAgIGZvciAoY29uc3QgYyBvZiBwLmNlbGxzKSB7CiAgICAgIGlmIChjLmRheSA8PSBUICYmIGMuZGF5ID49IFMgJiYgYy5kYXkgPD0gRSAmJiBjLmRheSA8IGxvKSBsbyA9IGMuZGF5OwogICAgfQogIH0KICBpZiAobG8gPCBJbmZpbml0eSkgUkFEX0xPID0gTWF0aC5tYXgoUywgTWF0aC5taW4obG8sIEUgLSAxKSk7Cn0KLyogZGlzYyDihpIgc2NyZWVuICovCmZ1bmN0aW9uIHRvU2NyZWVuKGcsIHgsIHkpIHsKICBjb25zdCBjID0gTWF0aC5jb3Mocm90KSwgcyA9IE1hdGguc2luKHJvdCk7CiAgcmV0dXJuIHsgeDogZy5jeCArIHBhblggKyAoeCAqIGMgLSB5ICogcykgKiBaLCB5OiBnLmN5ICsgcGFuWSArICh4ICogcyArIHkgKiBjKSAqIFogfTsKfQovKiBzY3JlZW4g4oaSIGRpc2MgKi8KZnVuY3Rpb24gdG9EaXNjKGcsIHN4LCBzeSkgewogIGNvbnN0IHV4ID0gKHN4IC0gZy5jeCAtIHBhblgpIC8gWiwgdXkgPSAoc3kgLSBnLmN5IC0gcGFuWSkgLyBaOwogIGNvbnN0IGMgPSBNYXRoLmNvcygtcm90KSwgcyA9IE1hdGguc2luKC1yb3QpOwogIHJldHVybiB7IHg6IHV4ICogYyAtIHV5ICogcywgeTogdXggKiBzICsgdXkgKiBjIH07Cn0KCmNvbnN0IHNvbG9SaW5nUiA9IChnLCBjKSA9PiB7CiAgLyogc29sbzogb25lIHJpbmcgcGVyIGV2ZW50IOKAlCBlYXJsaWVzdCBvdXRlcm1vc3QsIGxhdGVzdCBpbm5lcm1vc3QgKi8KICBjb25zdCB1bml0ID0gZy5SIC0gZy5yMDsKICBjb25zdCByTWF4ID0gZy5yMCArIHVuaXQgKiAwLjkyLCByTWluID0gZy5yMCArIHVuaXQgKiAwLjE4OwogIHJldHVybiBjLm4gPiAxID8gck1heCAtIChyTWF4IC0gck1pbikgKiAoYy5yYW5rIC8gKGMubiAtIDEpKSA6IChyTWF4ICsgck1pbikgLyAyOwp9OwpmdW5jdGlvbiBjZWxsUG9zKGcsIGMpIHsKICBpZiAoIWMucC5sYXkpIHJldHVybiBudWxsOwogIC8qIGNsb2Nrd2lzZSBieSBkYXkgb3JkZXI6IGVhcmxpZXN0IGF0IHRoZSBzZWN0b3IncyBsZWFkaW5nIGVkZ2UgKi8KICBjb25zdCBmcmFjID0gYy5uID4gMSA/IChjLnJhbmsgKyAwLjUpIC8gYy5uIDogMC41OwogIGNvbnN0IGEgPSBjLnAubGF5LmEwICsgKGMucC5sYXkuYTEgLSBjLnAubGF5LmEwKSAqICgwLjA2ICsgMC44OCAqIGZyYWMpOwogIGNvbnN0IHIgPSBzb2xvID09PSBjLnAgPyBzb2xvUmluZ1IoZywgYykgOiBkYXlSKGcsIGMuZGF5KSAqICgwLjk5NSArIGMuanIgKiAwLjAxKTsKICByZXR1cm4geyBhLCByLCB4OiBNYXRoLmNvcyhhKSAqIHIsIHk6IE1hdGguc2luKGEpICogciB9Owp9CmZ1bmN0aW9uIGRvdFIoYykgewogIHJldHVybiAoYy5yZWFsID8gMy40ICsgKGMudG9rZW5zIHx8IDIwMCkgLyAyNjAgOiBjLmtpbmQgPT09ICdnYXRlJyA/IDMuMiA6IDIuNik7Cn0KCmZ1bmN0aW9uIGRyYXcobm93KSB7CiAgY29uc3QgZHQgPSBNYXRoLm1pbigwLjA1LCAobm93IC0gbGFzdFQpIC8gMTAwMCk7IGxhc3RUID0gbm93OwogIGNvbnN0IHRpbWUgPSBub3cgLyAxMDAwOwogIGlmIChzcGlubmluZyAmJiAhUkVEVUNFRCAmJiAhcmVzZXRUd2Vlbikgcm90ICs9IGR0ICogMC4wMjsKICBpZiAocmVzZXRUd2VlbikgewogICAgbGV0IHRhcmdldCA9IHJvdCAtICgoKHJvdCAlIFRBVSkgKyBUQVUpICUgVEFVKTsgICAgICAgICAgIC8qIG5lYXJlc3QgZnVsbCB0dXJuIGJlbG93ICovCiAgICBpZiAoKChyb3QgJSBUQVUpICsgVEFVKSAlIFRBVSA+IE1hdGguUEkpIHRhcmdldCArPSBUQVU7ICAgLyogZ28gdGhlIHNob3J0IHdheSAqLwogICAgcm90ID0gbWl4KHJvdCwgdGFyZ2V0LCBSRURVQ0VEID8gMSA6IDAuMTIpOwogICAgaWYgKE1hdGguYWJzKHJvdCAtIHRhcmdldCkgPCAwLjAwMikgeyByb3QgPSAwOyByZXNldFR3ZWVuID0gZmFsc2U7IH0KICB9CiAgaWYgKHBsYXlpbmcpIHsKICAgIFQgKz0gZHQgKiAoRSAtIFMpIC8gMjQ7ICAgICAgICAgICAgICAgICAgICAgICAgLyogZnVsbCB3aW5kb3cgaW4gfjI0cyAoc2xvd2VkIDI1JSkgKi8KICAgIGlmIChUID49IEUpIHsgVCA9IEU7IHNldFBsYXlpbmcoZmFsc2UpOyB9CiAgICByVGltZS52YWx1ZSA9IE1hdGgucm91bmQoKFQgLSBTKSAvIE1hdGgubWF4KDAuNSwgRSAtIFMpICogMTAwMCk7CiAgICBjRGF0ZS50ZXh0Q29udGVudCA9IGRheURhdGUoVCk7CiAgfQogIGlmIChsZW5zID09PSAnd29yaycpIHN0ZXBMYXlvdXQoZHQpOwogIHVwZGF0ZVJhZExvKCk7CiAgY29uc3QgZyA9IGdlb20oKTsKICBjdHguY2xlYXJSZWN0KDAsIDAsIFcsIEgpOwoKICAvKiDilZDilZAgZGlzYyBmcmFtZSDilZDilZAgKi8KICBjdHguc2F2ZSgpOwogIGN0eC50cmFuc2xhdGUoZy5jeCArIHBhblgsIGcuY3kgKyBwYW5ZKTsKICBjdHguc2NhbGUoWiwgWik7CiAgY3R4LnJvdGF0ZShyb3QpOwoKICAvKiBlcG9jaCByaW5ncyAoc3VwcHJlc3NlZCBpbiBzb2xvIOKAlCB0aGVyZSwgcmluZ3MgQVJFIGV2ZW50cykgKi8KICBpZiAoIXNvbG8pIHsKICAgIGZvciAobGV0IGkgPSAxOyBpIDw9IEVQT0NIX1JJTkdTOyBpKyspIHsKICAgICAgY29uc3QgciA9IGcucjAgKyAoZy5SIC0gZy5yMCkgKiAoaSAvIEVQT0NIX1JJTkdTKTsKICAgICAgY3R4LnN0cm9rZVN0eWxlID0gJ3JnYmEoMjU1LDI1NSwyNTUsLjA5KSc7CiAgICAgIGN0eC5saW5lV2lkdGggPSAxIC8gWjsKICAgICAgY3R4LmJlZ2luUGF0aCgpOyBjdHguYXJjKDAsIDAsIHIsIDAsIDcpOyBjdHguc3Ryb2tlKCk7CiAgICB9CiAgfQoKICAvKiBzZWFtIGF0IDEyOiB0aGUgIm5vdyIgbm90Y2ggKi8KICBjdHguc3Ryb2tlU3R5bGUgPSAncmdiYSgxMzksMTUwLDI0MiwuNiknOwogIGN0eC5saW5lV2lkdGggPSAxLjUgLyBaOwogIGN0eC5iZWdpblBhdGgoKTsKICBjdHgubW92ZVRvKE1hdGguY29zKC1NYXRoLlBJIC8gMikgKiBnLnIwICogMC45LCBNYXRoLnNpbigtTWF0aC5QSSAvIDIpICogZy5yMCAqIDAuOSk7CiAgY3R4LmxpbmVUbyhNYXRoLmNvcygtTWF0aC5QSSAvIDIpICogKGcuUiArIDEwKSwgTWF0aC5zaW4oLU1hdGguUEkgLyAyKSAqIChnLlIgKyAxMCkpOwogIGN0eC5zdHJva2UoKTsKCiAgLyogc2VjdG9ycyAqLwogIGxlbnNMYWJlbHMgPSBbXTsKICBsZXQgc29sb0xhYmVscyA9IG51bGw7CiAgaWYgKGxlbnMgIT09ICd3b3JrJykgewogICAgZHJhd0xlbnNJbkZyYW1lKGN0eCwgZywgdGltZSk7CiAgfSBlbHNlIHsKICBjdHgubGluZVdpZHRoID0gMSAvIFo7CiAgZm9yIChjb25zdCBwIG9mIFBMQU5TKSB7CiAgICBpZiAoIXAubGF5IHx8IHAubGF5LmFscGhhIDwgMC4wMikgY29udGludWU7CiAgICBjb25zdCBMID0gcC5sYXksIGFsID0gTC5hbHBoYTsKICAgIGNvbnN0IHdTZWMgPSBMLmExIC0gTC5hMDsKICAgIC8qIGRpdmlkZXIg4oCUIHNraXBwZWQgd2hlbiBzZWN0b3JzIGFyZSB0b28gdGhpbiB0byBzZXBhcmF0ZSAqLwogICAgaWYgKHdTZWMgKiBnLlIgKiBaID4gOCkgewogICAgICBjdHguc3Ryb2tlU3R5bGUgPSAncmdiYSgyNTUsMjU1LDI1NSwnICsgMC4wNiAqIGFsICsgJyknOwogICAgICBjdHguYmVnaW5QYXRoKCk7CiAgICAgIGN0eC5tb3ZlVG8oTWF0aC5jb3MoTC5hMCkgKiBnLnIwLCBNYXRoLnNpbihMLmEwKSAqIGcucjApOwogICAgICBjdHgubGluZVRvKE1hdGguY29zKEwuYTApICogZy5SLCBNYXRoLnNpbihMLmEwKSAqIGcuUik7CiAgICAgIGN0eC5zdHJva2UoKTsKICAgIH0KICAgIC8qIHJpbTogZnVsbC1leHRlbnQgdHJhY2sgYXJjIChzZWdtZW50IHN0YXJ0IOKGkiBmaW5pc2gsIGdhcHBlZCBmcm9tIHRoZQogICAgICAgbmVpZ2hib3VyKSB3aXRoIHRoZSB0aGljayBwcm9ncmVzcyBhcmMgb24gdG9wLiBBIGNvbXBsZXRlIHBsYW4ncwogICAgICAgcHJvZ3Jlc3MgY292ZXJzIHRoZSB3aG9sZSB0cmFjayDigJQgb25lIHNvbGlkIHRoaWNrIGJhci4gKi8KICAgIGNvbnN0IGh1ZSA9IHN0YXRlSHVlKHApOwogICAgLyogaG92ZXJlZCBzZWN0b3I6IGZ1bGwtYXJjIGhpZ2hsaWdodCAqLwogICAgaWYgKHAgPT09IGhvdmVyU2VjKSB7CiAgICAgIGN0eC5zdHJva2VTdHlsZSA9IGhleDJyZ2JhKGh1ZSwgMC4yOCAqIGFsKTsKICAgICAgY3R4LmxpbmVXaWR0aCA9IDEwIC8gWjsKICAgICAgY3R4LmJlZ2luUGF0aCgpOyBjdHguYXJjKDAsIDAsIGcuUiAtIDUgLyBaLCBMLmEwLCBMLmExKTsgY3R4LnN0cm9rZSgpOwogICAgICBjdHgubGluZVdpZHRoID0gMSAvIFo7CiAgICB9CiAgICBjb25zdCBhUGFkID0gTWF0aC5taW4oMC4wMiwgd1NlYyAqIDAuMTApOwogICAgY3R4LnN0cm9rZVN0eWxlID0gaGV4MnJnYmEoaHVlLCAwLjI4ICogYWwpOwogICAgY3R4LmxpbmVXaWR0aCA9IDEuNiAvIFo7CiAgICBjdHguYmVnaW5QYXRoKCk7IGN0eC5hcmMoMCwgMCwgZy5SICsgMywgTC5hMCArIGFQYWQsIEwuYTEgLSBhUGFkKTsgY3R4LnN0cm9rZSgpOwogICAgY3R4LnN0cm9rZVN0eWxlID0gaGV4MnJnYmEoaHVlLCAwLjggKiBhbCk7CiAgICBjdHgubGluZVdpZHRoID0gNC41IC8gWjsKICAgIGN0eC5iZWdpblBhdGgoKTsKICAgIGN0eC5hcmMoMCwgMCwgZy5SICsgMywgTC5hMCArIGFQYWQsIEwuYTAgKyBhUGFkICsgTWF0aC5tYXgoMC4wMDgsICh3U2VjIC0gMiAqIGFQYWQpICogKHAuZG9uZSAvIHAudG90YWwpKSk7CiAgICBjdHguc3Ryb2tlKCk7CiAgICBjdHgubGluZVdpZHRoID0gMSAvIFo7CiAgICAvKiBvcGVuIGRlY2lzaW9uczogYW1iZXIgT0QgdGlja3MganVzdCBvdXRzaWRlIHRoZSB0cmFjayAqLwogICAgaWYgKHAub2QubGVuZ3RoKSB7CiAgICAgIGNvbnN0IG5UID0gTWF0aC5taW4ocC5vZC5sZW5ndGgsIE1hdGgubWF4KDEsIE1hdGguZmxvb3IoKHdTZWMgLSAyICogYVBhZCkgLyAwLjAyKSkpOwogICAgICBjdHguc3Ryb2tlU3R5bGUgPSBoZXgycmdiYSgnI2Y1YTYyMycsIDAuOTUgKiBhbCk7CiAgICAgIGN0eC5saW5lV2lkdGggPSAxLjggLyBaOwogICAgICBmb3IgKGxldCBvaSA9IDA7IG9pIDwgblQ7IG9pKyspIHsKICAgICAgICBjb25zdCBvYSA9IEwuYTAgKyBhUGFkICsgKG9pICsgMC41KSAqIDAuMDE5OwogICAgICAgIGN0eC5iZWdpblBhdGgoKTsKICAgICAgICBjdHgubW92ZVRvKE1hdGguY29zKG9hKSAqIChnLlIgKyA4KSwgTWF0aC5zaW4ob2EpICogKGcuUiArIDgpKTsKICAgICAgICBjdHgubGluZVRvKE1hdGguY29zKG9hKSAqIChnLlIgKyAxMyksIE1hdGguc2luKG9hKSAqIChnLlIgKyAxMykpOwogICAgICAgIGN0eC5zdHJva2UoKTsKICAgICAgfQogICAgICBjdHgubGluZVdpZHRoID0gMSAvIFo7CiAgICB9CiAgICAvKiBibG9ja2VkIHB1bHNlIG9uIHJpbSAqLwogICAgaWYgKHAuc3QgPT09IDIpIHsKICAgICAgY29uc3QgcHVsc2UgPSBSRURVQ0VEID8gMC41IDogMC4zNSArIDAuMyAqIE1hdGguc2luKHRpbWUgKiA0KTsKICAgICAgY3R4LnN0cm9rZVN0eWxlID0gaGV4MnJnYmEoJyNlZjQ0NDQnLCBwdWxzZSAqIGFsKTsKICAgICAgY3R4LmJlZ2luUGF0aCgpOyBjdHguYXJjKDAsIDAsIGcuUiArIDgsIEwuYTAgKyAwLjAxLCBMLmExIC0gMC4wMSk7IGN0eC5zdHJva2UoKTsKICAgIH0KICAgIC8qICh0b2tlbiB1c2FnZSBjaGFydCBtb3ZlZCBpbnRvIHRoZSBkZXRhaWwgcGFuZSDigJQgcmltIHN0YXlzIGNsZWFuKSAqLwogICAgLyogbGFiZWwgaWYgd2lkZSBlbm91Z2ggb24gc2NyZWVuIOKAlCBvciBob3ZlcmVkIChjZW5zdXMgbW9kZSBuYW1lcyBvbiBob3ZlcikgKi8KICAgIGNvbnN0IGlzSG92U2VjID0gcCA9PT0gaG92ZXJTZWM7CiAgICBpZiAoKHdTZWMgKiBnLlIgKiBaID4gNDYgfHwgaXNIb3ZTZWMpICYmIHNvbG8gIT09IHApIHsgIC8qIHNvbG8gbmFtZXMgaXRzZWxmIGF0IHRoZSBzZWFtICovCiAgICAgIGNvbnN0IG1pZEEgPSAoTC5hMCArIEwuYTEpIC8gMiwgbHIgPSBnLlIgKyAxNDsKICAgICAgY3R4LnNhdmUoKTsKICAgICAgY3R4LnRyYW5zbGF0ZShNYXRoLmNvcyhtaWRBKSAqIGxyLCBNYXRoLnNpbihtaWRBKSAqIGxyKTsKICAgICAgY3R4LnJvdGF0ZShtaWRBICsgKE1hdGguY29zKG1pZEEgKyByb3QpIDwgMCA/IE1hdGguUEkgOiAwKSk7CiAgICAgIGN0eC5maWxsU3R5bGUgPSBpc0hvdlNlYyA/ICdyZ2JhKDIzOCwyNDAsMjQ2LDEpJyA6ICdyZ2JhKDIwMCwyMDYsMjE5LCcgKyAwLjk1ICogYWwgKyAnKSc7CiAgICAgIGN0eC5mb250ID0gJzcwMCAnICsgKDEyIC8gWikgKyAncHggJyArIE1PTk87CiAgICAgIGN0eC50ZXh0QWxpZ24gPSBNYXRoLmNvcyhtaWRBICsgcm90KSA8IDAgPyAncmlnaHQnIDogJ2xlZnQnOwogICAgICBjdHgudGV4dEJhc2VsaW5lID0gJ21pZGRsZSc7CiAgICAgIGNvbnN0IGxibCA9IGlzSG92U2VjID8gKHAuc2hvcnQubGVuZ3RoID4gMzQgPyBwLnNob3J0LnNsaWNlKDAsIDMzKSArICfigKYnIDogcC5zaG9ydCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgOiAocC5zaG9ydC5sZW5ndGggPiAxNiA/IHAuc2hvcnQuc2xpY2UoMCwgMTUpICsgJ+KApicgOiBwLnNob3J0KTsKICAgICAgY3R4LmZpbGxUZXh0KGxibCArICcgJyArIHAuZG9uZSArICcvJyArIHAudG90YWwsIDAsIDApOwogICAgICBjdHgucmVzdG9yZSgpOwogICAgfQogICAgLyogYmFycyArIGRvdHMgKG9sZGVyIGJhcnMgcGFpbnRlZCBsYXN0ID0gb24gdG9wKSAqLwogICAgZm9yIChjb25zdCBjIG9mIHAuY2VsbHMpIHsKICAgICAgaWYgKGMuZGF5ID4gVCB8fCBjLmRheSA8IFMgfHwgYy5kYXkgPiBFKSBjb250aW51ZTsKICAgICAgaWYgKCFwYXNzRmlsdGVyKGMpKSB7IGMuX3ggPSB1bmRlZmluZWQ7IGNvbnRpbnVlOyB9CiAgICAgIGNvbnN0IHBvcyA9IGNlbGxQb3MoZywgYyk7CiAgICAgIGlmICghcG9zKSBjb250aW51ZTsKICAgICAgY29uc3QgY2h1ZSA9IGNvbG9yQnlTdGF0ZSA/IHN0YXRlSHVlKGMucCkgOiAoS0lORF9IVUVbYy5raW5kXSB8fCAnIzhiOTZmMicpOwogICAgICBjb25zdCBpc1NlbCA9IChob3ZlciA9PT0gYyB8fCBwaW5uZWQgPT09IGMpOwogICAgICBjb25zdCBhZ2UgPSBUIC0gYy5kYXk7CiAgICAgIGNvbnN0IHBvcCA9IFJFRFVDRUQgPyAxIDogTWF0aC5taW4oMSwgYWdlIC8gMC44KTsgICAgICAgICAgIC8qIGJpcnRoIHBvcCAqLwogICAgICBjb25zdCByciA9IGRvdFIoYykgKiAoaXNTZWwgPyAxLjcgOiAxKSAqICgwLjQgKyAwLjYgKiBwb3ApOwogICAgICBpZiAobW9kZSA9PT0gJ2JhcnMnKSB7CiAgICAgICAgY3R4LnN0cm9rZVN0eWxlID0gaGV4MnJnYmEoY2h1ZSwgKDAuMzQgKyAoYy5yZWFsID8gMC4zIDogMCkpICogYWwgKiBwb3ApOwogICAgICAgIGN0eC5saW5lV2lkdGggPSAoaXNTZWwgPyAzLjYgOiAyLjYpIC8gTWF0aC5zcXJ0KFopOwogICAgICAgIGN0eC5iZWdpblBhdGgoKTsKICAgICAgICBjdHgubW92ZVRvKE1hdGguY29zKHBvcy5hKSAqIGcucjAsIE1hdGguc2luKHBvcy5hKSAqIGcucjApOwogICAgICAgIGN0eC5saW5lVG8ocG9zLngsIHBvcy55KTsKICAgICAgICBjdHguc3Ryb2tlKCk7CiAgICAgIH0KICAgICAgY3R4LmZpbGxTdHlsZSA9IGhleDJyZ2JhKGNodWUsIChjLnJlYWwgPyAwLjkyIDogMC41NSkgKiBhbCAqIHBvcCk7CiAgICAgIGlmIChjLmtpbmQgPT09ICdnYXRlJyAmJiBjLnJlYWwpIHsKICAgICAgICBjdHguYmVnaW5QYXRoKCk7CiAgICAgICAgY3R4Lm1vdmVUbyhwb3MueCwgcG9zLnkgLSByciAtIDEpOyBjdHgubGluZVRvKHBvcy54ICsgcnIsIHBvcy55KTsgY3R4LmxpbmVUbyhwb3MueCwgcG9zLnkgKyByciArIDEpOyBjdHgubGluZVRvKHBvcy54IC0gcnIsIHBvcy55KTsKICAgICAgICBjdHguY2xvc2VQYXRoKCk7IGN0eC5maWxsKCk7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgY3R4LmJlZ2luUGF0aCgpOyBjdHguYXJjKHBvcy54LCBwb3MueSwgcnIsIDAsIDcpOyBjdHguZmlsbCgpOwogICAgICB9CiAgICAgIGlmIChjLnZlcnNpb24gPiAxKSB7CiAgICAgICAgY3R4LnN0cm9rZVN0eWxlID0gaGV4MnJnYmEoY2h1ZSwgMC44ICogYWwpOwogICAgICAgIGN0eC5saW5lV2lkdGggPSAxIC8gWjsKICAgICAgICBjdHguYmVnaW5QYXRoKCk7IGN0eC5hcmMocG9zLngsIHBvcy55LCByciArIDIuNSAvIFosIDAsIDcpOyBjdHguc3Ryb2tlKCk7CiAgICAgIH0KICAgICAgaWYgKCFSRURVQ0VEICYmIGFnZSA8IDAuOCkgeyAgICAgICAgICAgICAgICAgLyogYmlydGggaGFsbyAqLwogICAgICAgIGN0eC5zdHJva2VTdHlsZSA9IGhleDJyZ2JhKGNodWUsICgxIC0gYWdlIC8gMC44KSAqIDAuOCk7CiAgICAgICAgY3R4LmxpbmVXaWR0aCA9IDEuNSAvIFo7CiAgICAgICAgY3R4LmJlZ2luUGF0aCgpOyBjdHguYXJjKHBvcy54LCBwb3MueSwgcnIgKyAoYWdlIC8gMC44KSAqIDE0LCAwLCA3KTsgY3R4LnN0cm9rZSgpOwogICAgICB9CiAgICAgIGlmIChpc1NlbCkgewogICAgICAgIGN0eC5zdHJva2VTdHlsZSA9IGhleDJyZ2JhKGNodWUsIDAuOTUpOwogICAgICAgIGN0eC5saW5lV2lkdGggPSAxLjUgLyBaOwogICAgICAgIGN0eC5iZWdpblBhdGgoKTsgY3R4LmFyYyhwb3MueCwgcG9zLnksIHJyICsgNCAvIFosIDAsIDcpOyBjdHguc3Ryb2tlKCk7CiAgICAgIH0KICAgICAgYy5feCA9IHBvcy54OyBjLl95ID0gcG9zLnk7IGMuX2EgPSBwb3MuYTsgYy5fciA9IHBvcy5yOyBjLl9kciA9IHJyOwogICAgfQogIH0KCiAgLyog4pSA4pSAIGxpbmVhZ2UgY2hvcmRzOiBhIGRlcGVuZHNfb24gYiwgZHJhd24gcmltIOKGkiByaW0gdGhyb3VnaCB0aGUgZGlzYy4KICAgICBBbGwgZmFpbnQgd2hlbiB0aGUgbGluZWFnZSB0b2dnbGUgaXMgb247IGEgaG92ZXJlZCBzZWN0b3IncyBvd24gZWRnZXMKICAgICBhbHdheXMgbGlnaHQuIERvdCBtYXJrcyB0aGUgZGVwZW5kZW5jeSAodGhlIHBsYW4gYmVpbmcgc3Rvb2Qgb24pLiDilIDilIAgKi8KICBpZiAoIXNvbG8pIHsKICAgIGZvciAoY29uc3QgZWQgb2YgREVQX0VER0VTKSB7CiAgICAgIGNvbnN0IGxpdCA9IGhvdmVyU2VjID09PSBlZC5hIHx8IGhvdmVyU2VjID09PSBlZC5iOwogICAgICBpZiAoIXNob3dMaW5lYWdlICYmICFsaXQpIGNvbnRpbnVlOwogICAgICBpZiAoIWVkLmEubGF5IHx8ICFlZC5iLmxheSB8fCBlZC5hLmxheS5hbHBoYSA8IDAuMyB8fCBlZC5iLmxheS5hbHBoYSA8IDAuMykgY29udGludWU7CiAgICAgIGNvbnN0IGFtID0gKGVkLmEubGF5LmEwICsgZWQuYS5sYXkuYTEpIC8gMiwgYm0gPSAoZWQuYi5sYXkuYTAgKyBlZC5iLmxheS5hMSkgLyAyOwogICAgICBjb25zdCByMSA9IGcuUiAqIDAuOTc7CiAgICAgIGNvbnN0IGF4ID0gTWF0aC5jb3MoYW0pICogcjEsIGF5ID0gTWF0aC5zaW4oYW0pICogcjE7CiAgICAgIGNvbnN0IGJ4ID0gTWF0aC5jb3MoYm0pICogcjEsIGJ5ID0gTWF0aC5zaW4oYm0pICogcjE7CiAgICAgIGNvbnN0IGFscGhhMiA9IGxpdCA/IDAuNjUgOiAwLjEwOwogICAgICBjdHguc3Ryb2tlU3R5bGUgPSBoZXgycmdiYSgnIzhiOTZmMicsIGFscGhhMik7CiAgICAgIGN0eC5saW5lV2lkdGggPSAobGl0ID8gMS42IDogMS4xKSAvIFo7CiAgICAgIGN0eC5iZWdpblBhdGgoKTsKICAgICAgY3R4Lm1vdmVUbyhheCwgYXkpOwogICAgICBjdHgucXVhZHJhdGljQ3VydmVUbygoYXggKyBieCkgLyAyICogMC4yLCAoYXkgKyBieSkgLyAyICogMC4yLCBieCwgYnkpOwogICAgICBjdHguc3Ryb2tlKCk7CiAgICAgIGN0eC5maWxsU3R5bGUgPSBoZXgycmdiYSgnIzhiOTZmMicsIE1hdGgubWluKDEsIGFscGhhMiAqIDEuNikpOwogICAgICBjdHguYmVnaW5QYXRoKCk7IGN0eC5hcmMoYngsIGJ5LCAobGl0ID8gMyA6IDIuMikgLyBaLCAwLCA3KTsgY3R4LmZpbGwoKTsKICAgIH0KICAgIGN0eC5saW5lV2lkdGggPSAxIC8gWjsKICB9CgogIC8qIOKUgOKUgCBzb2xvIGV2ZW50IGxlZGdlcjogb25lIHJpbmcgcGVyIGV2ZW50IChlYXJsaWVzdCBvdXRlcm1vc3QpLiBFYWNoCiAgICAgZXZlbnQncyByaW5nIHRyYWNrcyBhcm91bmQgdG8gOSBvJ2Nsb2NrLCB0aGVuIHN0YW5kcyBzdHJhaWdodCB1cCBhcyBhCiAgICAgdmVydGljYWwgc3RhY2tlZCBiYXIg4oCUIHRva2VucyAoaW5kaWdvKSArIGZhY3Qga2luZCArIHZlcnNpb24gY2FwLgogICAgIFNhbWUtZGF5IGV2ZW50cyBrZWVwIHRoZWlyIGV4YWN0IHRpbWUgb3JkZXI6IGFkamFjZW50IHJpbmdzLiDilIDilIAgKi8KICBpZiAoc29sbyAmJiBzb2xvLmxheSAmJiBzb2xvLmxheS5hbHBoYSA+IDAuNSkgewogICAgc29sb0xhYmVscyA9IFtdOwogICAgY29uc3QgdW5pdCA9IGcuUiAtIGcucjA7CiAgICBjb25zdCBMID0gc29sby5sYXk7CiAgICBjb25zdCBldnMgPSBbLi4uc29sby5jZWxsc10uc29ydCgoYSwgYikgPT4gYS5kYXkgLSBiLmRheSkKICAgICAgLmZpbHRlcihjID0+IGMuZGF5IDw9IFQgJiYgYy5kYXkgPj0gUyAmJiBjLmRheSA8PSBFICYmIHBhc3NGaWx0ZXIoYykpOwogICAgLyogOSBvJ2Nsb2NrIGJhc2VsaW5lIHRoZSBiYXJzIHN0YW5kIG9uICovCiAgICBjdHguc3Ryb2tlU3R5bGUgPSAncmdiYSgyNTUsMjU1LDI1NSwuMTYpJzsKICAgIGN0eC5saW5lV2lkdGggPSAxIC8gWjsKICAgIGN0eC5iZWdpblBhdGgoKTsgY3R4Lm1vdmVUbygtKGcuUiArIDEwKSwgMCk7IGN0eC5saW5lVG8oLWcucjAgKiAwLjcyLCAwKTsgY3R4LnN0cm9rZSgpOwogICAgZm9yIChjb25zdCBjIG9mIGV2cykgewogICAgICBjb25zdCByID0gc29sb1JpbmdSKGcsIGMpOwogICAgICBjb25zdCBmcmFjID0gYy5uID4gMSA/IChjLnJhbmsgKyAwLjUpIC8gYy5uIDogMC41OwogICAgICBjb25zdCBhTm9kZSA9IEwuYTAgKyAoTC5hMSAtIEwuYTApICogKDAuMDYgKyAwLjg4ICogZnJhYyk7CiAgICAgIGNvbnN0IGNodWUgPSBLSU5EX0hVRVtjLmtpbmRdIHx8ICcjOGI5NmYyJzsKICAgICAgY29uc3QgaXNTZWxCYXIgPSBwaW5uZWQgPT09IGM7CiAgICAgIC8qIGZhaW50IGZ1bGwgcmluZyBhY3Jvc3MgdGhlIHNlY3RvciwgYnJpZ2h0ZXIgdHJhY2sgbm9kZSDihpIgOSBvJ2Nsb2NrICovCiAgICAgIGN0eC5zdHJva2VTdHlsZSA9IGhleDJyZ2JhKGNodWUsIDAuMDcpOwogICAgICBjdHgubGluZVdpZHRoID0gMSAvIFo7CiAgICAgIGN0eC5iZWdpblBhdGgoKTsgY3R4LmFyYygwLCAwLCByLCBMLmEwLCBhTm9kZSk7IGN0eC5zdHJva2UoKTsKICAgICAgY3R4LnN0cm9rZVN0eWxlID0gaGV4MnJnYmEoY2h1ZSwgaXNTZWxCYXIgPyAwLjc1IDogMC4zMCk7CiAgICAgIGN0eC5saW5lV2lkdGggPSAoaXNTZWxCYXIgPyAyIDogMS4zKSAvIFo7CiAgICAgIGN0eC5iZWdpblBhdGgoKTsgY3R4LmFyYygwLCAwLCByLCBhTm9kZSwgTWF0aC5QSSk7IGN0eC5zdHJva2UoKTsKICAgICAgLyogZWxib3cgYXQgKOKIknIsIDApOiB0aGUgYmFyIGdvZXMgc3RyYWlnaHQgdXAgKi8KICAgICAgbGV0IHkxID0gMDsKICAgICAgY29uc3Qgc2VncyA9IFsKICAgICAgICB7IGg6IHVuaXQgKiAoMC4wNiArIE1hdGgubWluKDAuMzAsICgoYy50b2tlbnMgfHwgMTYwKSAvIDU1MCkgKiAwLjM0KSksIGNvbDogaGV4MnJnYmEoJyM4Yjk2ZjInLCAwLjU1KSB9LAogICAgICAgIHsgaDogdW5pdCAqIDAuMDU1LCBjb2w6IGhleDJyZ2JhKGNodWUsIDAuOTUpIH0sCiAgICAgIF07CiAgICAgIGlmIChjLnZlcnNpb24gPiAxKSBzZWdzLnB1c2goeyBoOiB1bml0ICogMC4wMjIsIGNvbDogJ3JnYmEoMjM4LDI0MCwyNDYsLjg1KScgfSk7CiAgICAgIGZvciAoY29uc3Qgc2cgb2Ygc2VncykgewogICAgICAgIGN0eC5zdHJva2VTdHlsZSA9IHNnLmNvbDsKICAgICAgICBjdHgubGluZVdpZHRoID0gKDUgLyBaKSAqIChpc1NlbEJhciA/IDEuNSA6IDEpOwogICAgICAgIGN0eC5iZWdpblBhdGgoKTsKICAgICAgICBjdHgubW92ZVRvKC1yLCAteTEpOwogICAgICAgIHkxICs9IHNnLmg7CiAgICAgICAgY3R4LmxpbmVUbygtciwgLXkxKTsKICAgICAgICBjdHguc3Ryb2tlKCk7CiAgICAgIH0KICAgICAgYy5fYnggPSAtcjsgYy5fYmggPSB5MTsKICAgIH0KICAgIGN0eC5saW5lV2lkdGggPSAxIC8gWjsKICAgIC8qIGRhdGUgbGFiZWxzIHVuZGVyIHRoZSBheGlzOiBmaXJzdCAvIG1pZCAvIGxhc3QgdmlzaWJsZSBldmVudCAqLwogICAgY29uc3QgcGlja3MgPSBldnMubGVuZ3RoID8gW2V2c1swXSwgZXZzW01hdGguZmxvb3IoKGV2cy5sZW5ndGggLSAxKSAvIDIpXSwgZXZzW2V2cy5sZW5ndGggLSAxXV0gOiBbXTsKICAgIGNvbnN0IHNlZW4gPSBuZXcgU2V0KCk7CiAgICBmb3IgKGNvbnN0IGMgb2YgcGlja3MpIHsKICAgICAgaWYgKHNlZW4uaGFzKGMucmFuaykpIGNvbnRpbnVlOwogICAgICBzZWVuLmFkZChjLnJhbmspOwogICAgICBzb2xvTGFiZWxzLnB1c2goeyB4OiAtc29sb1JpbmdSKGcsIGMpLCB5OiAxNiwgdDogZGF5RGF0ZShjLmRheSkgfSk7CiAgICB9CiAgICBzb2xvTGFiZWxzLnB1c2goeyB4OiAtKGcucjAgKyB1bml0ICogMC41NSksIHk6IC0odW5pdCAqIDAuNjIpLCB0OiAnZXZlbnQgbGVkZ2VyIMK3IG91dGVyIHJpbmcgPSBmaXJzdCBldmVudCcsIGNhcDogdHJ1ZSB9KTsKICB9CgogIH0gIC8qIGVuZCB3b3JrLWxlbnMgaW4tZnJhbWUgKi8KCiAgLyogbGl2ZSBlZGdlOiBvdXR3YXJkIG1vZGUgc3dlZXBzIHdpdGggVDsgaW53YXJkIG1vZGUgSVMgdGhlIHJpbSAqLwogIHsKICAgIGNvbnN0IGVyID0gZGlyID09PSAnaW4nID8gZy5yMCArIChnLlIgLSBnLnIwKSAqIDAuOTYgOiBkYXlSKGcsIFQpOwogICAgaWYgKGRpciA9PT0gJ2luJyB8fCBUIDwgRSAtIDAuMDEpIHsKICAgICAgY29uc3QgZ3JvdyA9IFJFRFVDRUQgPyAwLjg2IDogKDAuNTUgKyAwLjQ1ICogKCh0aW1lICogMC4wNikgJSAxKSk7CiAgICAgIGN0eC5zdHJva2VTdHlsZSA9ICdyZ2JhKDEzOSwxNTAsMjQyLC43KSc7CiAgICAgIGN0eC5saW5lV2lkdGggPSAxLjYgLyBaOwogICAgICBjdHguc2V0TGluZURhc2goWzUgLyBaLCA3IC8gWl0pOwogICAgICBjdHguYmVnaW5QYXRoKCk7IGN0eC5hcmMoMCwgMCwgZXIsIC1NYXRoLlBJIC8gMiwgLU1hdGguUEkgLyAyICsgVEFVICogZ3Jvdyk7IGN0eC5zdHJva2UoKTsKICAgICAgY3R4LnNldExpbmVEYXNoKFtdKTsKICAgIH0KICB9CgogIC8qIGVudGVyL2V4aXQgZmxhc2hlcyAqLwogIGZvciAobGV0IGkgPSBmbGFzaGVzLmxlbmd0aCAtIDE7IGkgPj0gMDsgaS0tKSB7CiAgICBjb25zdCBmID0gZmxhc2hlc1tpXTsKICAgIGNvbnN0IGsgPSAodGltZSAtIGYudDApIC8gMS4xOwogICAgaWYgKGsgPiAxKSB7IGZsYXNoZXMuc3BsaWNlKGksIDEpOyBjb250aW51ZTsgfQogICAgaWYgKFJFRFVDRUQpIGNvbnRpbnVlOwogICAgY29uc3QgcnIgPSBmLmtpbmQgPT09ICdleGl0JyA/IGcuUiAqICgxICsgayAqIDAuMTQpIDogZy5SICogKDEuMTQgLSBrICogMC4xNCk7CiAgICBjdHguc3Ryb2tlU3R5bGUgPSBoZXgycmdiYShmLmh1ZSwgKDEgLSBrKSAqIDAuOSk7CiAgICBjdHgubGluZVdpZHRoID0gKDIuNSAqICgxIC0gaykgKyAwLjUpIC8gWjsKICAgIGN0eC5iZWdpblBhdGgoKTsgY3R4LmFyYygwLCAwLCByciwgZi5hbmcgLSAwLjMgKiAoMSAtIGsgKiAwLjUpLCBmLmFuZyArIDAuMyAqICgxIC0gayAqIDAuNSkpOyBjdHguc3Ryb2tlKCk7CiAgfQogIGN0eC5saW5lV2lkdGggPSAxOwoKICAvKiBoZWFydHdvb2QgKi8KICBjb25zdCBnbG93ID0gY3R4LmNyZWF0ZVJhZGlhbEdyYWRpZW50KDAsIDAsIDAsIDAsIDAsIGcucjAgKiAxLjUpOwogIGdsb3cuYWRkQ29sb3JTdG9wKDAsICdyZ2JhKDEzOSwxNTAsMjQyLC41KScpOwogIGdsb3cuYWRkQ29sb3JTdG9wKDEsICd0cmFuc3BhcmVudCcpOwogIGN0eC5maWxsU3R5bGUgPSBnbG93OwogIGN0eC5iZWdpblBhdGgoKTsgY3R4LmFyYygwLCAwLCBnLnIwICogMS41LCAwLCA3KTsgY3R4LmZpbGwoKTsKICBjdHguZmlsbFN0eWxlID0gJyMxMjE1MWQnOwogIGN0eC5iZWdpblBhdGgoKTsgY3R4LmFyYygwLCAwLCBnLnIwICogMC43LCAwLCA3KTsgY3R4LmZpbGwoKTsKICBjdHguc3Ryb2tlU3R5bGUgPSAncmdiYSgxMzksMTUwLDI0MiwuODUpJzsKICBjdHgubGluZVdpZHRoID0gMSAvIFo7CiAgY3R4LmJlZ2luUGF0aCgpOyBjdHguYXJjKDAsIDAsIGcucjAgKiAwLjcsIDAsIDcpOyBjdHguc3Ryb2tlKCk7CiAgY3R4LnJlc3RvcmUoKTsKCiAgLyog4pWQ4pWQIHNjcmVlbiBzcGFjZSDilZDilZAgKi8KICBjb25zdCBuQWN0ID0gYWN0aXZlUGxhbnMoVCkubGVuZ3RoOwogIGN0eC5maWxsU3R5bGUgPSAncmdiYSgyMzgsMjQwLDI0NiwuOTUpJzsKICBjdHguZm9udCA9ICc2MDAgMTAuNXB4ICcgKyBNT05POwogIGN0eC50ZXh0QWxpZ24gPSAnY2VudGVyJzsgY3R4LnRleHRCYXNlbGluZSA9ICdtaWRkbGUnOwogIGNvbnN0IGNvcmUgPSB0b1NjcmVlbihnLCAwLCAwKTsKICBjdHguZmlsbFRleHQoJ2NydXgnLCBjb3JlLngsIGNvcmUueSAtIDYpOwogIGN0eC5maWxsU3R5bGUgPSAncmdiYSgxMjYsMTMzLDE0OSwuOSknOwogIGN0eC5mb250ID0gJzguNXB4ICcgKyBNT05POwogIGN0eC5maWxsVGV4dChsZW5zID09PSAnd29yaycgPyBuQWN0ICsgKHNob3dBbGwgPyAnIHBsYW5zJyA6ICcgbGl2ZScpIDogbGVucywgY29yZS54LCBjb3JlLnkgKyA3KTsKICBjdHgudGV4dEFsaWduID0gJ2xlZnQnOyBjdHgudGV4dEJhc2VsaW5lID0gJ2FscGhhYmV0aWMnOwoKICAvKiBjb3JuZXIgc3RhdHVzICovCiAgY3R4LmZpbGxTdHlsZSA9ICdyZ2JhKDEyNiwxMzMsMTQ5LC44KSc7CiAgY3R4LmZvbnQgPSAnOS41cHggJyArIE1PTk87CiAgY3R4LmZpbGxUZXh0KGRheURhdGUoUykgKyAnIOKGkiAnICsgZGF5RGF0ZShFKSArICcgwrcgVCA9ICcgKyBkYXlEYXRlKFQpICsgJyDCtyAnICsgbkFjdCArICcgbGl2ZSDCtyB6b29tICcgKyBaLnRvRml4ZWQoMSkgKyAnw5cnCiAgICArIChSQURfTE8gPiBTICsgMC41ID8gJyDCtyByaW5ncyBmcm9tICcgKyBkYXlEYXRlKFJBRF9MTykgOiAnJyksIDE4LCAyNCk7CgogIC8qIHNvbG86IGxlZGdlciBsYWJlbHMgKyB0aGUgc2VhbSdzIG1pbuKGkm1heCByYW5nZSBmb3IgVEhJUyBwbGFuICovCiAgaWYgKHNvbG9MYWJlbHMpIHsKICAgIGN0eC5mb250ID0gJzlweCAnICsgTU9OTzsKICAgIGN0eC50ZXh0QWxpZ24gPSAnY2VudGVyJzsKICAgIGZvciAoY29uc3QgTDIgb2Ygc29sb0xhYmVscykgewogICAgICBjb25zdCBzcCA9IHRvU2NyZWVuKGcsIEwyLngsIEwyLnkpOwogICAgICBjdHguZmlsbFN0eWxlID0gTDIuY2FwID8gJ3JnYmEoMTgyLDE4OCwyMDEsLjkpJyA6ICdyZ2JhKDEyNiwxMzMsMTQ5LC44NSknOwogICAgICBjdHguZmlsbFRleHQoTDIudCwgc3AueCwgc3AueSk7CiAgICB9CiAgICBjb25zdCB0aXAyID0gdG9TY3JlZW4oZywgMCwgLShnLlIgKyAyNCkpOwogICAgY3R4LmZpbGxTdHlsZSA9ICdyZ2JhKDIzOCwyNDAsMjQ2LC45MiknOwogICAgY3R4LmZvbnQgPSAnNzAwIDEwcHggJyArIE1PTk87CiAgICBjdHguZmlsbFRleHQoZGF5RGF0ZShzb2xvLmIpICsgJyDihpIgJyArIGRheURhdGUoc29sby5lKSwgdGlwMi54LCB0aXAyLnkpOwogICAgY3R4LnRleHRBbGlnbiA9ICdsZWZ0JzsKICB9CgogIC8qIGxlbnMgY2FwdGlvbnMgKHNjcmVlbiBzcGFjZSkgKi8KICBpZiAobGVuc0xhYmVscy5sZW5ndGgpIHsKICAgIGN0eC5mb250ID0gJzkuNXB4ICcgKyBNT05POwogICAgY3R4LnRleHRBbGlnbiA9ICdjZW50ZXInOwogICAgZm9yIChjb25zdCBMMiBvZiBsZW5zTGFiZWxzKSB7CiAgICAgIGNvbnN0IHNwID0gdG9TY3JlZW4oZywgTDIueCwgTDIueSk7CiAgICAgIGN0eC5zYXZlKCk7CiAgICAgIGlmIChMMi5yb3QgIT09IHVuZGVmaW5lZCkgeyBjdHgudHJhbnNsYXRlKHNwLngsIHNwLnkpOyBjdHgucm90YXRlKEwyLnJvdCArIHJvdCk7IGN0eC50cmFuc2xhdGUoLXNwLngsIC1zcC55KTsgfQogICAgICBjdHguZmlsbFN0eWxlID0gTDIuY2FwID8gJ3JnYmEoMTgyLDE4OCwyMDEsLjkpJyA6ICdyZ2JhKDIwMCwyMDYsMjE5LC45NSknOwogICAgICBpZiAoIUwyLmNhcCkgY3R4LmZvbnQgPSAnNzAwIDExcHggJyArIE1PTk87CiAgICAgIGN0eC5maWxsVGV4dChMMi50LCBzcC54LCBzcC55KTsKICAgICAgY3R4LnJlc3RvcmUoKTsKICAgICAgY3R4LmZvbnQgPSAnOS41cHggJyArIE1PTk87CiAgICB9CiAgICBjdHgudGV4dEFsaWduID0gJ2xlZnQnOwogIH0KCiAgLyogY29tcGxldGVkIGxlZGdlciDigJQgcGxhbnMgcmV0aXJlIG9mZiB0aGUgY2xvY2sgaW50byB0aGUgbGVmdCBlZGdlLgogICAgIFJvd3MgYXJlIGNsaWNrYWJsZTogZmlsdGVyIHRoZSByaW5nIGRvd24gdG8gdGhhdCBvbmUgcGxhbi4KICAgICBIaWRkZW4gYnkgZGVmYXVsdDsg4omhIHRvZ2dsZXMsIHBsYXliYWNrIGF1dG8tc2hvd3MsIGxlbnMgc3dhcCBoaWRlcy4gKi8KICBsZWRnZXJSb3dzID0gW107CiAgaWYgKGxlbnMgPT09ICd3b3JrJyAmJiBzaG93TGVkZ2VyKSB7CiAgICBjb25zdCBkb25lTGlzdCA9IFBMQU5TCiAgICAgIC5maWx0ZXIocCA9PiBwLnN0ID09PSAwICYmIHAuZXhpdCA8PSBUICYmIHAuYiA8PSBFICYmIHAuZSA+PSBTIC0gMC4wMDEpCiAgICAgIC5zb3J0KChhLCBiKSA9PiBiLmV4aXQgLSBhLmV4aXQpOwogICAgY3R4LmZvbnQgPSAnNzAwIDExcHggJyArIE1PTk87CiAgICBjdHguZmlsbFN0eWxlID0gJ3JnYmEoNDUsMjEyLDE5MSwuOSknOwogICAgY3R4LmZpbGxUZXh0KCdjb21wbGV0ZWQgwrcgJyArIGRvbmVMaXN0Lmxlbmd0aCArIChzb2xvID8gJyAgKGZpbHRlcmluZyDigJQgY2xpY2sgcm93IGFnYWluIG9yIGJhY2tncm91bmQgdG8gY2xlYXIpJyA6ICcnKSwgMTgsIDUyKTsKICAgIGN0eC5mb250ID0gJzkuNXB4ICcgKyBNT05POwogICAgY29uc3QgbWF4Um93cyA9IE1hdGguZmxvb3IoKEggLSAxNDApIC8gMTYpOwogICAgZG9uZUxpc3Quc2xpY2UoMCwgbWF4Um93cykuZm9yRWFjaCgocCwgaykgPT4gewogICAgICBjb25zdCBmcmVzaCA9IFQgLSBwLmV4aXQgPCAyLjA7CiAgICAgIGNvbnN0IGlzU29sbyA9IHNvbG8gPT09IHA7CiAgICAgIGNvbnN0IHkgPSA3MCArIGsgKiAxNjsKICAgICAgaWYgKGlzU29sbykgewogICAgICAgIGN0eC5maWxsU3R5bGUgPSAncmdiYSgxMzksMTUwLDI0MiwuMTYpJzsKICAgICAgICBjdHguZmlsbFJlY3QoMTIsIHkgLSAxMSwgMjE4LCAxNSk7CiAgICAgIH0KICAgICAgY3R4LmZpbGxTdHlsZSA9IGZyZXNoIHx8IGlzU29sbyA/ICdyZ2JhKDQ1LDIxMiwxOTEsLjk1KScgOiAncmdiYSgxMjYsMTMzLDE0OSwuNzUpJzsKICAgICAgY3R4LmZpbGxUZXh0KCfinJMnLCAxOCwgeSk7CiAgICAgIGN0eC5maWxsU3R5bGUgPSBpc1NvbG8gPyAncmdiYSgyMzgsMjQwLDI0NiwxKScgOiBmcmVzaCA/ICdyZ2JhKDIzOCwyNDAsMjQ2LC45NSknIDogJ3JnYmEoMTI2LDEzMywxNDksLjgpJzsKICAgICAgY29uc3QgbGJsID0gcC5zaG9ydC5sZW5ndGggPiAyNiA/IHAuc2hvcnQuc2xpY2UoMCwgMjUpICsgJ+KApicgOiBwLnNob3J0OwogICAgICBjdHguZmlsbFRleHQobGJsLCAzMiwgeSk7CiAgICAgIGN0eC5maWxsU3R5bGUgPSAncmdiYSgxMjYsMTMzLDE0OSwuNTUpJzsKICAgICAgY3R4LmZpbGxUZXh0KGRheURhdGUocC5leGl0KS5zbGljZSg1KSwgMzIgKyAyNyAqIDYuMCwgeSk7CiAgICAgIGxlZGdlclJvd3MucHVzaCh7IHg6IDEyLCB5OiB5IC0gMTEsIHc6IDIxOCwgaDogMTUsIHAgfSk7CiAgICB9KTsKICAgIGlmIChkb25lTGlzdC5sZW5ndGggPiBtYXhSb3dzKSB7CiAgICAgIGN0eC5maWxsU3R5bGUgPSAncmdiYSgxMjYsMTMzLDE0OSwuNiknOwogICAgICBjdHguZmlsbFRleHQoJ+KApiArJyArIChkb25lTGlzdC5sZW5ndGggLSBtYXhSb3dzKSArICcgbW9yZScsIDE4LCA3MCArIG1heFJvd3MgKiAxNik7CiAgICB9CiAgfQoKICByYWZJZCA9IG51bGw7CiAgaWYgKHZpc2libGUgJiYgIWRvY3VtZW50LmhpZGRlbikgcmFmSWQgPSByZXF1ZXN0QW5pbWF0aW9uRnJhbWUoZHJhdyk7Cn0KCi8qIOKUgOKUgCBkYXRhIGdyYXBoIGxlbnM6IDY2IHJlYWwgZmFjdHMgcHVsbGVkIGxpdmUgZnJvbSB0aGUgZGFlbW9uLgogICBBbmdsZSA9IHNvdXJjZSBkYXRlIG9uIHRoZSBjbG9jayDCtyByYWRpdXMgPSBlZmZlY3RpdmUgY29uZmlkZW5jZQogICAoaGlnaCBuZWFyIHRoZSBoZWFydHdvb2QsIGRlY2F5ZWQvbG93IGZ1cnRoZXIgb3V0KSDCtyBlZGdlcyA9IGZhY3RzCiAgIHNoYXJpbmcgYW4gZW50aXR5LCBpbiB0aW1lIG9yZGVyIMK3IGNsaWNrID0gMi1ob3AgbmVpZ2hib3VyaG9vZC4g4pSA4pSAICovCmNvbnN0IEdSQVBIX1JBVyA9IFt7ImUiOiJleGVjcGxhbjpjcm9zcy1zaXRlLWF1dGgtc3NvLWN1ZWNydXgtMjAyNi0wNy0xMyIsImsiOiJnYXRlOk0xLVItY29kZSIsImQiOjc1LjU5Njk2NzU5MjU5MTY4LCJhIjoiY2xhdWRlLXdvcmsiLCJoIjoibWVkaXVtIiwiYyI6MS4wLCJ0IjoxMjd9LHsiZSI6ImV4ZWNwbGFuOnZlcmlmaWFibGUtcmVjb3JkLXByb2R1Y3RzLTIwMjYtMDctMTciLCJrIjoiZ2F0ZTpNMy1jb3JlLXBvaW50ZXItcHJvZHVjZXItY29kZS0yMDI2LTA3LTIyIiwiZCI6NzYuNzU4NjU3NDA3NDA4NDYsImEiOiJjbGF1ZGUtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjE1OH0seyJlIjoiZXhlY3BsYW46Y3J1eC1kYWVtb24tYnV5ZXItZml0LWJ1aWxkb3V0LTIwMjYtMDctMTMiLCJrIjoiZ2F0ZTpNMyIsImQiOjY4Ljk1MDcyOTE2NjY2Njg2LCJhIjoiY29kZXgtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjMxNn0seyJlIjoiaW5jaWRlbnQ6MjAyNi0wNy0yMiIsImsiOiJncHUxLWNhcmdvLWRlcGxveS1oZWxwLXNpZGUtZWZmZWN0IiwiZCI6NzYuNDMwMjg5MzUxODUwNjYsImEiOiJjbGF1ZGUtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjI5MX0seyJlIjoiZXhlY3BsYW46Y3Jvc3Mtc2l0ZS1hdXRoLXNzby1jdWVjcnV4LTIwMjYtMDctMTMiLCJrIjoiZGVjaXNpb246dmF1bHQtdGFyZ2V0LXJlZ3Jlc3Npb24tcmVwYWlyIiwiZCI6NzUuNTk2OTY3NTkyNTkxNjgsImEiOiJjbGF1ZGUtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjE1NX0seyJlIjoiZXhlY3BsYW46Y3J1eC1kYWVtb24tYnV5ZXItZml0LWJ1aWxkb3V0LTIwMjYtMDctMTMiLCJrIjoicHJvZ3Jlc3M6TTMiLCJkIjo2OC45MDk3MTA2NDgxNDk0OCwiYSI6ImNvZGV4LXdvcmsiLCJoIjoidm9sYXRpbGUiLCJjIjoxLjAsInQiOjI3NH0seyJlIjoiZXhlY3BsYW46cHJvZHVjdGlvbi1ldGhvcy1hdWRpdC1oYXJuZXNzLTIwMjYtMDctMTciLCJrIjoiZ2F0ZTpNNSIsImQiOjc0LjYwNTg5MTIwMzcwNDIzLCJhIjoiY29kZXgtd29yayIsImgiOiJ2b2xhdGlsZSIsImMiOjEuMCwidCI6MzIzfSx7ImUiOiJleGVjcGxhbjpjcm9zcy1zaXRlLWF1dGgtc3NvLWN1ZWNydXgtMjAyNi0wNy0xMyIsImsiOiJnYXRlOk0xIiwiZCI6NjguMzgxNTc0MDc0MDc1NjIsImEiOiJjb2RleC13b3JrIiwiaCI6Im1lZGl1bSIsImMiOjEuMCwidCI6Mjk2fSx7ImUiOiJleGVjcGxhbjp3aWtpY3J1eC1wdWJsaWMtcmVhZGluZXNzLWhhcmRlbmluZy0yMDI2LTA3LTIxIiwiayI6ImdhdGU6TTNiLWJsb2NrZWQiLCJkIjo3NS44Mjc3MzE0ODE0ODA0NCwiYSI6ImRyaXZldy1ob3N0IiwiaCI6InN0YWJsZSIsImMiOjEuMCwidCI6MjIxfSx7ImUiOiJleGVjcGxhbjpjcnV4LWRhZW1vbi1idXllci1maXQtYnVpbGRvdXQtMjAyNi0wNy0xMyIsImsiOiJkZWNpc2lvbjptNWItaW5zdGFsbGVyLXRyYW5zYWN0aW9uIiwiZCI6NzYuMzY3ODkzNTE4NTE5ODUsImEiOiJjbGF1ZGUtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjIzMn0seyJlIjoiaW5jaWRlbnQ6MjAyNi0wNy0yMiIsImsiOiJjcmMtdjEtcmVzaWRlbnQtb3JkaW5hbC1oYW5kbGUtYWxpYXMiLCJkIjo3Ni40Nzk2MDY0ODE0OCwiYSI6ImNsYXVkZS13b3JrIiwiaCI6InN0YWJsZSIsImMiOjEuMCwidCI6MTg1fSx7ImUiOiJleGVjcGxhbjp2ZXJpZmlhYmxlLXJlY29yZC1wcm9kdWN0cy0yMDI2LTA3LTE3IiwiayI6ImdhdGU6TTktZXZpZGVuY2UtcHVibGljYXRpb24iLCJkIjo3Ni42NzExNTc0MDc0MDcwMSwiYSI6ImNsYXVkZS13b3JrIiwiaCI6InN0YWJsZSIsImMiOjEuMCwidCI6MTI1fSx7ImUiOiJleGVjcGxhbjpjcm9zcy1zaXRlLWF1dGgtc3NvLWN1ZWNydXgtMjAyNi0wNy0xMyIsImsiOiJicmllZiIsImQiOjY3LjkyMDY4Mjg3MDM3MTgyLCJhIjoiY29kZXgtd29yayIsImgiOiJtZWRpdW0iLCJjIjoxLjAsInQiOjIwNX0seyJlIjoiZXhlY3BsYW46d2lraWNydXgtbTUtcHJpY2luZy1lbmZvcmNlbWVudC0yMDI2LTA3LTE3IiwiayI6ImRlY2lzaW9uOm0zYi1yZWZ1bmQtY29udHJhY3QtcGFyaXR5IiwiZCI6NzYuMDI1MzQ3MjIyMjIxMTcsImEiOiJjbGF1ZGUtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjE1M30seyJlIjoiZXhlY3BsYW46dmVyaWZpYWJsZS1yZWNvcmQtcHJvZHVjdHMtMjAyNi0wNy0xNyIsImsiOiJnYXRlOk0zLWVuZ2luZS1jb25zdW1lci1kZXBsb3ktMjAyNi0wNy0yMiIsImQiOjc2LjczOTU3MTc1OTI1ODk4LCJhIjoiY2xhdWRlLXdvcmsiLCJoIjoic3RhYmxlIiwiYyI6MS4wLCJ0IjoyMjN9LHsiZSI6ImV4ZWNwbGFuOmNyb3NzLXNpdGUtYXV0aC1zc28tY3VlY3J1eC0yMDI2LTA3LTEzIiwiayI6ImdhdGU6TTAiLCJkIjo2Ny45MzU4NjgwNTU1NTYwNiwiYSI6ImNvZGV4LXdvcmsiLCJoIjoibWVkaXVtIiwiYyI6MS4wLCJ0IjoyMDV9LHsiZSI6ImV4ZWNwbGFuOmNydXgtbWFjYXJvb24tdG9rZW4tYXR0ZW51YXRpb24tMjAyNi0wNy0xNiIsImsiOiJkZXNpZ246c3luYy1kZWxlZ2F0aW9uLWNvbnZlbnRpb24iLCJkIjo3Ni40OTc5NzQ1MzcwMzY1LCJhIjoiY29kZXgtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjQwOH0seyJlIjoiZXhlY3BsYW46Y3J1eC1tYWNhcm9vbi10b2tlbi1hdHRlbnVhdGlvbi0yMDI2LTA3LTE2IiwiayI6ImdhdGU6TTJwcmltZS1ob3RmaXgtcmV2aWV3ZWQtYW5kLXJlY29uY2lsaWF0aW9uLXBsYW4iLCJkIjo3Ni40MTgxMzY1NzQwNzMyOSwiYSI6ImNvZGV4LXdvcmsiLCJoIjoic3RhYmxlIiwiYyI6MS4wLCJ0Ijo3NDN9LHsiZSI6ImV4ZWNwbGFuOndpa2ljcnV4LW1hcmtldC13ZWRnZS1vZmZlcnMtMjAyNi0wNy0xNiIsImsiOiJkZWNpc2lvbjpjYW5vbmljYWwtcHJpY2luZyIsImQiOjc1LjgyMjI1Njk0NDQ0NDIzLCJhIjoiY2xhdWRlLXdvcmsiLCJoIjoic3RhYmxlIiwiYyI6MS4wLCJ0IjoxNDZ9LHsiZSI6ImV4ZWNwbGFuOndpa2ljcnV4LW01LXByaWNpbmctZW5mb3JjZW1lbnQtMjAyNi0wNy0xNyIsImsiOiJnYXRlOk0zYiIsImQiOjc2LjAyNTM0NzIyMjIyMTE3LCJhIjoiY2xhdWRlLXdvcmsiLCJoIjoic3RhYmxlIiwiYyI6MS4wLCJ0IjoyMjN9LHsiZSI6ImV4ZWNwbGFuOnZlcmlmaWFibGUtcmVjb3JkLXByb2R1Y3RzLTIwMjYtMDctMTciLCJrIjoiZ2F0ZTpNMyIsImQiOjc2Ljc0Njg1MTg1MTg1MDgsImEiOiJjbGF1ZGUtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjE1MH0seyJlIjoiZXhlY3BsYW46Y3VlY3J1eC1zZWxmc2VydmUtbGF1bmNoLXJlYWRpbmVzcy0yMDI2LTA3LTE2IiwiayI6ImdhdGU6TTgtZWRnZS1yZXBhaXIiLCJkIjo3Ni41NDgwMDkyNTkyNTg4MywiYSI6ImNsYXVkZS13b3JrIiwiaCI6Im5vbmUiLCJjIjoxLjAsInQiOjI1NH0seyJlIjoiYmVuY2g6cHJvdmVuYW5jZS1ieW9rLWxvY2FsLTIwMjYwNzIxVDE3NDc1MVotOGU3MTExNTAiLCJrIjoicmVzdWx0IiwiZCI6NzUuNzQzNjkyMTI5NjI4NDcsImEiOiJjbGF1ZGUtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjE0NX0seyJlIjoiZXhlY3BsYW46Y3Jvc3Mtc2l0ZS1hdXRoLXNzby1jdWVjcnV4LTIwMjYtMDctMTMiLCJrIjoiZ2F0ZTpNMy1NNCIsImQiOjY4LjgyOTc0NTM3MDM3MDgsImEiOiJjb2RleC13b3JrIiwiaCI6Im1lZGl1bSIsImMiOjEuMCwidCI6MzI4fSx7ImUiOiJleGVjcGxhbjpjcm9zcy1zaXRlLWF1dGgtc3NvLWN1ZWNydXgtMjAyNi0wNy0xMyIsImsiOiJjb25zb2xlLXYxLXJlbW92ZWQtZm9sbG93dXAtZG9uZSIsImQiOjY5Ljg5MTU5NzIyMjIyMzk0LCJhIjoiY29kZXgtd29yayIsImgiOiJtZWRpdW0iLCJjIjoxLjAsInQiOjMyOX0seyJlIjoiZXhlY3BsYW46Y3Jvc3Mtc2l0ZS1hdXRoLXNzby1jdWVjcnV4LTIwMjYtMDctMTMiLCJrIjoiZ2F0ZTpNMiIsImQiOjY4LjY0ODgxOTQ0NDQ0Mjc4LCJhIjoiY29kZXgtd29yayIsImgiOiJtZWRpdW0iLCJjIjoxLjAsInQiOjIzNn0seyJlIjoiZXhlY3BsYW46Y3J1eC1tYWNhcm9vbi10b2tlbi1hdHRlbnVhdGlvbi0yMDI2LTA3LTE2IiwiayI6ImRlc2lnbjpNM3ByaW1lLXN5bmMtZW5mb3JjZW1lbnQtb24tdjExIiwiZCI6NzYuNDM1Mjc3Nzc3Nzc4NTQsImEiOiJjb2RleC13b3JrIiwiaCI6InN0YWJsZSIsImMiOjEuMCwidCI6ODcwfSx7ImUiOiJpbmNpZGVudDoyMDI2LTA3LTIyIiwiayI6InJlbGVhc2UtdjAuNS40OC1tYWNvcy1zb2NrZXQtZml4dHVyZSIsImQiOjc2LjU2NjEyMjY4NTE4NDM4LCJhIjoiY2xhdWRlLXdvcmsiLCJoIjoic3RhYmxlIiwiYyI6MS4wLCJ0IjoxNDd9LHsiZSI6ImV4ZWNwbGFuOndpa2ljcnV4LXB1YmxpYy1yZWFkaW5lc3MtaGFyZGVuaW5nLTIwMjYtMDctMjEiLCJrIjoiZ2F0ZTpNM2IiLCJkIjo3NS44NDI2MDQxNjY2NjgwMiwiYSI6ImRyaXZldy1ob3N0IiwiaCI6InN0YWJsZSIsImMiOjEuMCwidCI6Mjg3fSx7ImUiOiJleGVjcGxhbjp3aWtpY3J1eC1tYXJrZXQtd2VkZ2Utb2ZmZXJzLTIwMjYtMDctMTYiLCJrIjoiZ2F0ZTpNMCIsImQiOjc1LjgyMjI1Njk0NDQ0NDIzLCJhIjoiY2xhdWRlLXdvcmsiLCJoIjoic3RhYmxlIiwiYyI6MS4wLCJ0Ijo3NH0seyJlIjoiZXhlY3BsYW46Y29yZWNydXgtb2JqZWN0LXN0b3JhZ2UtdGllci0yMDI2LTA3LTA3IiwiayI6ImdhdGU6RzMtY29kZS1tZXJnZSIsImQiOjc2LjYzMTAwNjk0NDQ0NDM4LCJhIjoiY2xhdWRlLXdvcmsiLCJoIjoic3RhYmxlIiwiYyI6MS4wLCJ0IjoxMjV9LHsiZSI6ImV4ZWNwbGFuOmNydXgtZGFlbW9uLWJ1eWVyLWZpdC1idWlsZG91dC0yMDI2LTA3LTEzIiwiayI6ImdhdGU6TTEiLCJkIjo2OC42Njk4OTU4MzMzMzI3LCJhIjoiY29kZXgtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjUzNn0seyJlIjoiZXhlY3BsYW46d2lraWNydXgtbTUtcHJpY2luZy1lbmZvcmNlbWVudC0yMDI2LTA3LTE3IiwiayI6ImdhdGU6TTVhIiwiZCI6NzUuNzk1MTA0MTY2NjY3NDQsImEiOiJjbGF1ZGUtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjIzMH0seyJlIjoiZXhlY3BsYW46Y3Jvc3Mtc2l0ZS1hdXRoLXNzby1jdWVjcnV4LTIwMjYtMDctMTMiLCJrIjoiZGVjaXNpb246dG9wb2xvZ3ktY29ycmVjdGVkLWNydXhlbmdpbmUtMTQzNDMiLCJkIjo2Ny45NDgwNzg3MDM3MDI3OCwiYSI6ImNvZGV4LXdvcmsiLCJoIjoibWVkaXVtIiwiYyI6MS4wLCJ0IjoyMDd9LHsiZSI6ImluY2lkZW50OjIwMjYtMDctMjIiLCJrIjoicGFzc3BvcnQtbWludC1wcmUtbTItYXBwcm92YWwtbGl2ZSIsImQiOjc2Ljc1MDY0ODE0ODE0Njg3LCJhIjoiY2xhdWRlLXdvcmsiLCJoIjoic3RhYmxlIiwiYyI6MS4wLCJ0IjoyMDN9LHsiZSI6ImluY2lkZW50OjIwMjYtMDctMjIiLCJrIjoiY29yZS1zaWRlY2FyLXNuYXBzaG90LXBhdGgiLCJkIjo3Ni44MTAwNjk0NDQ0NDM4LCJhIjoiY2xhdWRlLXdvcmsiLCJoIjoic3RhYmxlIiwiYyI6MS4wLCJ0IjoxNzJ9LHsiZSI6ImV4ZWNwbGFuOmNydXgtZGFlbW9uLWJ1eWVyLWZpdC1idWlsZG91dC0yMDI2LTA3LTEzIiwiayI6ImdhdGU6TTViIiwiZCI6NzYuMzY3ODkzNTE4NTE5ODUsImEiOiJjbGF1ZGUtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjE4NH0seyJlIjoiZXhlY3BsYW46Y3J1eC1kYWVtb24tYnV5ZXItZml0LWJ1aWxkb3V0LTIwMjYtMDctMTMiLCJrIjoiaGFuZG9mZjoyMDI2LTA3LTE0IiwiZCI6NjguODgyMTc1OTI1OTI2MjgsImEiOiJjb2RleC13b3JrIiwiaCI6InN0YWJsZSIsImMiOjEuMCwidCI6NDA5fSx7ImUiOiJleGVjcGxhbjpjcm9zcy1zaXRlLWF1dGgtc3NvLWN1ZWNydXgtMjAyNi0wNy0xMyIsImsiOiJtaWxlc3RvbmU6TTEtcGFydGlhbCIsImQiOjY3Ljk5MDcyOTE2NjY2NzczLCJhIjoiY29kZXgtd29yayIsImgiOiJtZWRpdW0iLCJjIjoxLjAsInQiOjI3NX0seyJlIjoiZXhlY3BsYW46Y3J1eC1tYWNhcm9vbi10b2tlbi1hdHRlbnVhdGlvbi0yMDI2LTA3LTE2IiwiayI6ImdhdGU6TTItcnVzdGRvYy1maXgtYW5kLU0zLWdyb3VuZGluZyIsImQiOjc1LjgyOTg4NDI1OTI1OTQyLCJhIjoiY29kZXgtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjczMn0seyJlIjoiZXhlY3BsYW46c2RrY3J1eC1kZXBlbmRlbmN5LXZ1bG4tcmVtZWRpYXRpb24tMjAyNi0wNy0yMCIsImsiOiJhdWRpdC1zbmFwc2hvdCIsImQiOjc0LjU2MTkzMjg3MDM2ODc2LCJhIjoiY29kZXgtd29yayIsImgiOiJ2b2xhdGlsZSIsImMiOjEuMCwidCI6NDE1fSx7ImUiOiJleGVjcGxhbjpjcnV4LWRhZW1vbi1idXllci1maXQtYnVpbGRvdXQtMjAyNi0wNy0xMyIsImsiOiJnYXRlOk0wIiwiZCI6NjguMzU2NTc0MDc0MDc0MTYsImEiOiJjb2RleC13b3JrIiwiaCI6InN0YWJsZSIsImMiOjEuMCwidCI6NDEyfSx7ImUiOiJleGVjcGxhbjpjcnV4LXBhc3Nwb3J0LW1pbnQtcmVxdWVzdC1nYXRlLTIwMjYtMDctMTciLCJrIjoiZ2F0ZTpNMi4xLWludGVncmF0aW9uIiwiZCI6NzYuNjUwMzI0MDc0MDc0ODksImEiOiJjbGF1ZGUtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjIwN30seyJlIjoiZXhlY3BsYW46Y3VlY3J1eC1zZWxmc2VydmUtbGF1bmNoLXJlYWRpbmVzcy0yMDI2LTA3LTE2IiwiayI6ImRlY2lzaW9uOmVkZ2UtY3V0b3Zlci1nYXRlIiwiZCI6NzYuNTQzNDk1MzcwMzY5NzgsImEiOiJjbGF1ZGUtd29yayIsImgiOiJub25lIiwiYyI6MS4wLCJ0IjoxNjd9LHsiZSI6ImluY2lkZW50OjIwMjYtMDctMjAiLCJrIjoic2RrY3J1eC1jaS1ydW5uZXItbW92ZS1hbmQtc3RhY2tlZC1mYWlsdXJlcyIsImQiOjc0LjU0NzY3MzYxMTExMjI2LCJhIjoiY29kZXgtd29yayIsImgiOiJ2b2xhdGlsZSIsImMiOjEuMCwidCI6NTY0fSx7ImUiOiJleGVjcGxhbjpwcm9kdWN0aW9uLWV0aG9zLWF1ZGl0LWhhcm5lc3MtMjAyNi0wNy0xNyIsImsiOiJnYXRlOk03IiwiZCI6NzUuNjEyNjE1NzQwNzQxNiwiYSI6ImNsYXVkZS13b3JrIiwiaCI6InN0YWJsZSIsImMiOjEuMCwidCI6MTE2fSx7ImUiOiJleGVjcGxhbjpjcnV4LWRhZW1vbi1idXllci1maXQtYnVpbGRvdXQtMjAyNi0wNy0xMyIsImsiOiJnYXRlOk0yIiwiZCI6NjguODQ2NzU5MjU5MjYwNTgsImEiOiJjb2RleC13b3JrIiwiaCI6InN0YWJsZSIsImMiOjEuMCwidCI6NDYzfSx7ImUiOiJleGVjcGxhbjpjcnV4LWJhbm5lci1yZWRlc2lnbi0yMDI2LTA3LTIxIiwiayI6ImdhdGU6ZGVwbG95LXYwLjUuNDciLCJkIjo3Ni4zOTUxMDQxNjY2NjU5OSwiYSI6ImNvZGV4LXdvcmsiLCJoIjoidm9sYXRpbGUiLCJjIjoxLjAsInQiOjIxNn0seyJlIjoiZXhlY3BsYW46d2lraWNydXgtbWFya2V0LXdlZGdlLW9mZmVycy0yMDI2LTA3LTE2IiwiayI6ImdhdGU6TTEiLCJkIjo3NS44MjIyNTY5NDQ0NDQyMywiYSI6ImNsYXVkZS13b3JrIiwiaCI6Im1lZGl1bSIsImMiOjEuMCwidCI6MTYyfSx7ImUiOiJleGVjcGxhbjp2ZXJpZmlhYmxlLXJlY29yZC1wcm9kdWN0cy0yMDI2LTA3LTE3IiwiayI6ImdhdGU6TTMtZGVwbG95LWF1dG9tYXRpb24tMjAyNi0wNy0yMiIsImQiOjc2Ljc1Njk1NjAxODUxODQsImEiOiJjbGF1ZGUtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjE3NX0seyJlIjoiZXhlY3BsYW46Y3J1eC1tYWNhcm9vbi10b2tlbi1hdHRlbnVhdGlvbi0yMDI2LTA3LTE2IiwiayI6ImluY2lkZW50Ok0zLU00LWNvbGxpc2lvbi13aXRoLWNvbmN1cnJlbnQtc2VjdXJpdHktaG90Zml4IiwiZCI6NzUuOTI3NjM4ODg4ODkwMjEsImEiOiJjb2RleC13b3JrIiwiaCI6InN0YWJsZSIsImMiOjEuMCwidCI6ODIyfSx7ImUiOiJleGVjcGxhbjpjcnV4LW1hY2Fyb29uLXRva2VuLWF0dGVudWF0aW9uLTIwMjYtMDctMTYiLCJrIjoiZ2F0ZTpNM3ByaW1lLXN5bmMtZGVsZWdhdGlvbiIsImQiOjc2LjYxNTgzMzMzMzMzMzI4LCJhIjoiY29kZXgtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjYzOH0seyJlIjoiX193b3JrX2NvbW1lbnRfXzo6d181MTc1MjY0N2NhNmU0YmRiYmU0YzNiNDVkMzAyNDFjOTo6Y185YTcyODVjYmY2NjA0MTUyYmU5NjRlODFkN2RlMDM2NyIsImsiOiJyZWNvcmQiLCJkIjo3Ni43MzkyMDEzODg4ODkzNCwiYSI6bnVsbCwiaCI6Im5vbmUiLCJjIjoxLjAsInQiOjE3M30seyJlIjoiZXhlY3BsYW46Y3J1eC1wYXNzcG9ydC1taW50LXJlcXVlc3QtZ2F0ZS0yMDI2LTA3LTE3IiwiayI6ImdhdGU6TTItbGl2ZS1jb250YWlubWVudC0yMDI2LTA3LTIyIiwiZCI6NzYuNzUwNjQ4MTQ4MTQ2ODcsImEiOiJjbGF1ZGUtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjE1OX0seyJlIjoiZXhlY3BsYW46c2RrY3J1eC1kZXBlbmRlbmN5LXZ1bG4tcmVtZWRpYXRpb24tMjAyNi0wNy0yMCIsImsiOiJnYXRlOk00IiwiZCI6NzQuNTgzMTgyODcwMzcwMzYsImEiOiJjb2RleC13b3JrIiwiaCI6InZvbGF0aWxlIiwiYyI6MS4wLCJ0IjoyMjB9LHsiZSI6ImV4ZWNwbGFuOmNvcmVjcnV4LW9iamVjdC1zdG9yYWdlLXRpZXItMjAyNi0wNy0wNyIsImsiOiJnYXRlOkczLXByb2Qtc2FmZXR5LXJlY2hlY2siLCJkIjo3Ni42NTgzOTEyMDM3MDIyLCJhIjoiY2xhdWRlLXdvcmsiLCJoIjoidm9sYXRpbGUiLCJjIjoxLjAsInQiOjEzMX0seyJlIjoiZXhlY3BsYW46d2lraWNydXgtbTUtcHJpY2luZy1lbmZvcmNlbWVudC0yMDI2LTA3LTE3IiwiayI6ImdhdGU6TTNhLWhhcm5lc3MiLCJkIjo3NS45MTY1NjI0OTk5OTg2OSwiYSI6ImNsYXVkZS13b3JrIiwiaCI6InN0YWJsZSIsImMiOjEuMCwidCI6MjQ0fSx7ImUiOiJleGVjcGxhbjpwcm9kdWN0aW9uLWV0aG9zLWF1ZGl0LWhhcm5lc3MtMjAyNi0wNy0xNyIsImsiOiJnYXRlOk00IiwiZCI6NzQuNTc4MTI1LCJhIjoiY29kZXgtd29yayIsImgiOiJ2b2xhdGlsZSIsImMiOjEuMCwidCI6MzQ0fSx7ImUiOiJleGVjcGxhbjpjcnV4LWRhZW1vbi1idXllci1maXQtYnVpbGRvdXQtMjAyNi0wNy0xMyIsImsiOiJnYXRlOk00IiwiZCI6NjguODU4ODE5NDQ0NDQ1NTQsImEiOiJjb2RleC13b3JrIiwiaCI6InN0YWJsZSIsImMiOjEuMCwidCI6NDA5fSx7ImUiOiJleGVjcGxhbjpjcnV4LXBhc3Nwb3J0LW1pbnQtcmVxdWVzdC1nYXRlLTIwMjYtMDctMTciLCJrIjoiZ2F0ZTpNMi4xLWludGVncmF0aW9uIiwiZCI6NzYuNjQ3ODM1NjQ4MTQ5MzQsImEiOiJjbGF1ZGUtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjE4NX0seyJlIjoiZXhlY3BsYW46d2lraWNydXgtcHVibGljLXJlYWRpbmVzcy1oYXJkZW5pbmctMjAyNi0wNy0yMSIsImsiOiJnYXRlOk0zYiIsImQiOjc1LjkxMzYxMTExMTExMTEsImEiOiJkcml2ZXctaG9zdCIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjI5M30seyJlIjoiZXhlY3BsYW46Y3Jvc3Mtc2l0ZS1hdXRoLXNzby1jdWVjcnV4LTIwMjYtMDctMTMiLCJrIjoiY29uc29sZS12MS1yZW1vdmVkIiwiZCI6NjguODkxODYzNDI1OTI0MzgsImEiOiJjb2RleC13b3JrIiwiaCI6Im1lZGl1bSIsImMiOjEuMCwidCI6Mjg4fSx7ImUiOiJpbmNpZGVudDoyMDI2LTA3LTIyIiwiayI6InZhdWx0Y3J1eC1wdWJsaWMtZWRnZS1sb29wYmFjay1yZWdyZXNzaW9uIiwiZCI6NzYuNTQ4MDA5MjU5MjU4ODMsImEiOiJjbGF1ZGUtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjE1N30seyJlIjoiaW5jaWRlbnQ6MjAyNi0wNy0yMiIsImsiOiJsZWdhbC1ob2xkLWNhbmFyeS1tY3AtYXV0aC1taXNtYXRjaCIsImQiOjc2LjQzOTM1MTg1MTg1MTgyLCJhIjoiY29kZXgtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjIxNH0seyJlIjoiZXhlY3BsYW46Y3J1eC1kYWVtb24tYnV5ZXItZml0LWJ1aWxkb3V0LTIwMjYtMDctMTMiLCJrIjoiZ2F0ZTpNMyIsImQiOjY5LjAzMjExODA1NTU1NDc1LCJhIjoiY29kZXgtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjIxNX0seyJlIjoiaW5jaWRlbnQ6MjAyNi0wNy0yMiIsImsiOiJsZWdhbC1ob2xkLWNhbmFyeS1tY3AtYXV0aC1taXNtYXRjaCIsImQiOjc2LjQzODkzNTE4NTE4NTk4LCJhIjoiY29kZXgtd29yayIsImgiOiJzdGFibGUiLCJjIjoxLjAsInQiOjIxNH1dOwpjb25zdCBHTk9ERVMgPSBHUkFQSF9SQVcubWFwKChuLCBpKSA9PiAoeyAuLi5uLCBpIH0pKTsKY29uc3QgR0VER0VTID0gW107CihmdW5jdGlvbiBidWlsZEdyYXBoKCkgewogIGNvbnN0IGJ5RSA9IHt9OwogIGZvciAoY29uc3QgbiBvZiBHTk9ERVMpIChieUVbbi5lXSA9IGJ5RVtuLmVdIHx8IFtdKS5wdXNoKG4pOwogIGZvciAoY29uc3QgZSBpbiBieUUpIHsKICAgIGNvbnN0IGFyciA9IGJ5RVtlXS5zb3J0KChhLCBiKSA9PiBhLmQgLSBiLmQpOwogICAgZm9yIChsZXQgaSA9IDE7IGkgPCBhcnIubGVuZ3RoOyBpKyspIEdFREdFUy5wdXNoKHsgYTogYXJyW2kgLSAxXSwgYjogYXJyW2ldIH0pOwogIH0KfSkoKTsKY29uc3QgR0FESiA9IHt9Owpmb3IgKGNvbnN0IGVkIG9mIEdFREdFUykgewogIChHQURKW2VkLmEuaV0gPSBHQURKW2VkLmEuaV0gfHwgW10pLnB1c2goZWQuYi5pKTsKICAoR0FESltlZC5iLmldID0gR0FESltlZC5iLmldIHx8IFtdKS5wdXNoKGVkLmEuaSk7Cn0KbGV0IGdTZWwgPSBudWxsOyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLyogc2VsZWN0ZWQgbm9kZSBpbmRleCDihpIgMi1ob3AgaGlnaGxpZ2h0ICovCmZ1bmN0aW9uIGdIb3BzKGkwKSB7CiAgY29uc3QgbDEgPSBuZXcgU2V0KEdBREpbaTBdIHx8IFtdKTsKICBjb25zdCBsMiA9IG5ldyBTZXQoKTsKICBmb3IgKGNvbnN0IGogb2YgbDEpIGZvciAoY29uc3QgazIgb2YgKEdBREpbal0gfHwgW10pKSBpZiAoazIgIT09IGkwICYmICFsMS5oYXMoazIpKSBsMi5hZGQoazIpOwogIHJldHVybiB7IGwxLCBsMiB9Owp9CmNvbnN0IEdfRkFNX0hVRSA9IGUgPT4KICBlLnN0YXJ0c1dpdGgoJ2V4ZWNwbGFuOicpID8gJyNhNzhiZmEnIDoKICBlLnN0YXJ0c1dpdGgoJ2JlbmNoOicpID8gJyNmNWE2MjMnIDoKICBlLnN0YXJ0c1dpdGgoJ2luY2lkZW50OicpID8gJyNlZjQ0NDQnIDoKICBlLnN0YXJ0c1dpdGgoJ2Rlc2lnbjonKSA/ICcjMjJkM2VlJyA6CiAgZS5zdGFydHNXaXRoKCdfX3dvcmtfY29tbWVudF9fJykgPyAnIzM0ZDM5OScgOiAnIzdlODU5NSc7CmNvbnN0IEdfVEhSID0geyB2b2xhdGlsZTogMSwgbWVkaXVtOiAzNSwgc3RhYmxlOiAzNjUsIG5vbmU6IEluZmluaXR5IH07CmZ1bmN0aW9uIGdFZmZDb25mKG4pIHsKICBjb25zdCBhZ2UgPSBNYXRoLm1heCgwLCBUIC0gbi5kKTsKICBjb25zdCB0aHIgPSBHX1RIUltuLmhdIHx8IEluZmluaXR5OwogIGlmICh0aHIgPT09IEluZmluaXR5KSByZXR1cm4gbi5jOwogIHJldHVybiBhZ2UgPiB0aHIgPyBuLmMgKiAwLjUgOiBuLmMgKiAoMSAtIDAuMzUgKiAoYWdlIC8gdGhyKSk7Cn0KZnVuY3Rpb24gZHJhd0RhdGFMZW5zKGN0eDIsIGcpIHsKICBmb3IgKGNvbnN0IG4gb2YgR05PREVTKSB7IG4uX3ggPSB1bmRlZmluZWQ7IG4uX29uID0gZmFsc2U7IH0KICBjb25zdCBzcGFuID0gTWF0aC5tYXgoMC41LCBFIC0gUyk7CiAgY29uc3QgckluID0gZy5yMCAqIDEuMjUsIHJPdXQgPSBnLlIgKiAwLjk2OwogIC8qIHJhZGl1cyA9IGNvbmZpZGVuY2UgUkFOSyB3aXRoaW4gdGhlIHZpc2libGUgc2V0IChyZWFsIGNvbmZpZGVuY2VzIGFyZQogICAgIHVuaWZvcm1seSB+MS4wIHRvZGF5OyBub3JtYWxpc2luZyBrZWVwcyAiaGlnaGVyID0gbmVhcmVyIHRoZSBjZW50cmUiCiAgICAgbWVhbmluZ2Z1bCBpbnN0ZWFkIG9mIGNsdW1waW5nIGV2ZXJ5dGhpbmcgYXQgdGhlIGhlYXJ0d29vZCkgKi8KICBjb25zdCB2aXMgPSBHTk9ERVMuZmlsdGVyKG4gPT4gbi5kIDw9IFQgJiYgbi5kID49IFMgJiYgbi5kIDw9IEUpOwogIGxldCBjTWluID0gMSwgY01heCA9IDA7CiAgZm9yIChjb25zdCBuIG9mIHZpcykgeyBjb25zdCBlYyA9IGdFZmZDb25mKG4pOyBpZiAoZWMgPCBjTWluKSBjTWluID0gZWM7IGlmIChlYyA+IGNNYXgpIGNNYXggPSBlYzsgfQogIGNvbnN0IGNTcGFuID0gTWF0aC5tYXgoMC4wMiwgY01heCAtIGNNaW4pOwogIGNvbnN0IHBvc09mID0gbiA9PiB7CiAgICBjb25zdCBhID0gQkFTRSArIChUQVUgLSBTRUFNKSAqIE1hdGgubWF4KDAsIE1hdGgubWluKDEsIChuLmQgLSBTKSAvIHNwYW4pKTsKICAgIGNvbnN0IG5vcm0gPSAoZ0VmZkNvbmYobikgLSBjTWluKSAvIGNTcGFuOwogICAgY29uc3QgciA9IHJJbiArIChyT3V0IC0gckluKSAqICgxIC0gKDAuMDggKyAwLjg0ICogbm9ybSkpOwogICAgcmV0dXJuIHsgYSwgeDogTWF0aC5jb3MoYSkgKiByLCB5OiBNYXRoLnNpbihhKSAqIHIgfTsKICB9OwogIGNvbnN0IGhvcHMgPSBnU2VsICE9PSBudWxsID8gZ0hvcHMoZ1NlbCkgOiBudWxsOwogIGNvbnN0IGluRm9jdXMgPSBpMiA9PiBnU2VsID09PSBudWxsID8gbnVsbCA6IChpMiA9PT0gZ1NlbCA/IDAgOiBob3BzLmwxLmhhcyhpMikgPyAxIDogaG9wcy5sMi5oYXMoaTIpID8gMiA6IC0xKTsKICAvKiBjb25maWRlbmNlIGd1aWRlIHJpbmdzICovCiAgZm9yIChjb25zdCBjZiBvZiBbMC4yNSwgMC41LCAwLjc1XSkgewogICAgY3R4Mi5zdHJva2VTdHlsZSA9ICdyZ2JhKDI1NSwyNTUsMjU1LC4wNCknOwogICAgY3R4Mi5saW5lV2lkdGggPSAxIC8gWjsKICAgIGN0eDIuYmVnaW5QYXRoKCk7IGN0eDIuYXJjKDAsIDAsIHJJbiArIChyT3V0IC0gckluKSAqIGNmLCAwLCA3KTsgY3R4Mi5zdHJva2UoKTsKICB9CiAgbGVuc0xhYmVscy5wdXNoKHsgeDogMCwgeTogLShySW4gKyAock91dCAtIHJJbikgKiAwLjAyKSArIDEwLCB0OiAnJyB9KTsKICAvKiBlZGdlcyAqLwogIGZvciAoY29uc3QgZWQgb2YgR0VER0VTKSB7CiAgICBpZiAoZWQuYS5kID4gVCB8fCBlZC5iLmQgPiBUIHx8IGVkLmEuZCA8IFMgfHwgZWQuYi5kIDwgUykgY29udGludWU7CiAgICBjb25zdCBwYTIgPSBwb3NPZihlZC5hKSwgcGIyID0gcG9zT2YoZWQuYik7CiAgICBsZXQgYWxwaGEgPSAwLjE2OwogICAgaWYgKGhvcHMpIHsKICAgICAgY29uc3QgZmEgPSBpbkZvY3VzKGVkLmEuaSksIGZiID0gaW5Gb2N1cyhlZC5iLmkpOwogICAgICBhbHBoYSA9IChmYSA+PSAwICYmIGZiID49IDApID8gMC42IDogMC4wMzsKICAgIH0KICAgIGN0eDIuc3Ryb2tlU3R5bGUgPSBoZXgycmdiYShHX0ZBTV9IVUUoZWQuYS5lKSwgYWxwaGEpOwogICAgY3R4Mi5saW5lV2lkdGggPSAxLjEgLyBaOwogICAgY3R4Mi5iZWdpblBhdGgoKTsKICAgIGN0eDIubW92ZVRvKHBhMi54LCBwYTIueSk7CiAgICBjdHgyLnF1YWRyYXRpY0N1cnZlVG8oKHBhMi54ICsgcGIyLngpIC8gMiAqIDAuNTUsIChwYTIueSArIHBiMi55KSAvIDIgKiAwLjU1LCBwYjIueCwgcGIyLnkpOwogICAgY3R4Mi5zdHJva2UoKTsKICB9CiAgLyogbm9kZXMgKi8KICBmb3IgKGNvbnN0IG4gb2YgR05PREVTKSB7CiAgICBpZiAobi5kID4gVCB8fCBuLmQgPCBTIHx8IG4uZCA+IEUpIGNvbnRpbnVlOwogICAgY29uc3QgcDIgPSBwb3NPZihuKTsKICAgIGNvbnN0IGh1ZTIgPSBHX0ZBTV9IVUUobi5lKTsKICAgIGNvbnN0IGYyID0gaW5Gb2N1cyhuLmkpOwogICAgY29uc3QgaXNIID0gaG92ZXIgPT09IG47CiAgICBsZXQgYWxwaGEgPSAwLjg1OwogICAgaWYgKGYyICE9PSBudWxsKSBhbHBoYSA9IGYyID09PSAtMSA/IDAuMTAgOiBmMiA9PT0gMCA/IDEgOiBmMiA9PT0gMSA/IDAuOTUgOiAwLjY7CiAgICBjb25zdCByciA9ICgyLjIgKyBNYXRoLm1pbigzLCAobi50IHx8IDE1MCkgLyAxODApKSAqIChpc0ggfHwgZjIgPT09IDAgPyAxLjcgOiAxKTsKICAgIGN0eDIuZmlsbFN0eWxlID0gaGV4MnJnYmEoaHVlMiwgYWxwaGEpOwogICAgY3R4Mi5iZWdpblBhdGgoKTsgY3R4Mi5hcmMocDIueCwgcDIueSwgcnIsIDAsIDcpOyBjdHgyLmZpbGwoKTsKICAgIGlmIChmMiA9PT0gMCkgewogICAgICBjdHgyLnN0cm9rZVN0eWxlID0gaGV4MnJnYmEoaHVlMiwgMC45NSk7CiAgICAgIGN0eDIubGluZVdpZHRoID0gMS41IC8gWjsKICAgICAgY3R4Mi5iZWdpblBhdGgoKTsgY3R4Mi5hcmMocDIueCwgcDIueSwgcnIgKyA1IC8gWiwgMCwgNyk7IGN0eDIuc3Ryb2tlKCk7CiAgICB9CiAgICBpZiAoaXNIKSB7IGN0eDIuc3Ryb2tlU3R5bGUgPSBoZXgycmdiYShodWUyLCAwLjkpOyBjdHgyLmJlZ2luUGF0aCgpOyBjdHgyLmFyYyhwMi54LCBwMi55LCByciArIDQgLyBaLCAwLCA3KTsgY3R4Mi5zdHJva2UoKTsgfQogICAgbi5feCA9IHAyLng7IG4uX3kgPSBwMi55OyBuLl9kciA9IHJyOyBuLl9vbiA9IHRydWU7CiAgfQogIGxlbnNMYWJlbHMucHVzaCh7IHg6IDAsIHk6IGcuUiArIDQyLCBjYXA6IHRydWUsCiAgICAgICAgICAgICAgICAgICAgdDogJ2RhdGEgZ3JhcGggwrcgNjYgbGl2ZSBmYWN0cyDCtyBhbmdsZSA9IHNvdXJjZSBkYXRlIMK3IGNlbnRyZSA9IGhpZ2hlciBjb25maWRlbmNlIChkZWNheS1hZGp1c3RlZCwgcmFuay1zY2FsZWQgJyArIGNNaW4udG9GaXhlZCgyKSArICfigJMnICsgY01heC50b0ZpeGVkKDIpICsgJykgwrcgZWRnZSA9IHNoYXJlZCBlbnRpdHkgwrcgY2xpY2sgPSAyLWhvcCcgfSk7Cn0KCi8qIOKUgOKUgCB0b2tlbnMgbGVuczogd29ya3NwYWNlLXRvdGFsIHNwZW5kICsgZXN0aW1hdGVkIHNhdmluZ3Mgb3ZlciB0aW1lLgogICBTcGVuZDogZWFjaCBwbGFuJ3MgcmVhbCBvdXRwdXQtdG9rZW4gdG90YWwgZGlzdHJpYnV0ZWQgYWNyb3NzIGl0cyBvd24KICAgZXZlbnQgZGF5cy4gU2F2aW5nczogdGhlIGRhZW1vbidzIHB1Ymxpc2hlZCBwYXR0ZXJuIG1hdGgg4oCUIGEgcmVjYWxsZWQKICAgZmFjdCDiiYggMTIgdG9rZW5zIHZzIH4zayByZXBsYXlpbmcgdGhlIGNvbnZlcnNhdGlvbiBpdCBjYW1lIGZyb20g4oCUIGFwcGxpZWQKICAgdG8gdGhlIGZhY3RzIHdyaXR0ZW4gZWFjaCBkYXkuIEJhcnM6IHNwZW50IGdyb3dzIE9VVFdBUkQgKHB1cnBsZSksIHNhdmVkCiAgIGdyb3dzIElOV0FSRCB0b3dhcmQgdGhlIGhlYXJ0d29vZCAoZ3JlZW4pLiDilqUgdG9nZ2xlcyBjdW11bGF0aXZlL2RhaWx5LiDilIDilIAgKi8KY29uc3QgVE9LID0gKGZ1bmN0aW9uIGJ1aWxkVG9rKCkgewogIGNvbnN0IHNwZW50ID0ge30sIHNhdmVkID0ge307CiAgZm9yIChjb25zdCBwIG9mIFBMQU5TKSB7CiAgICBpZiAoIXAuY2VsbHMubGVuZ3RoIHx8ICFwLm8pIGNvbnRpbnVlOwogICAgY29uc3QgcGVyID0gKHAubyAvIDEwKSAvIHAuY2VsbHMubGVuZ3RoOyAgICAgICAvKiBNIHRva2VucyBwZXIgZXZlbnQgKi8KICAgIGZvciAoY29uc3QgYyBvZiBwLmNlbGxzKSB7CiAgICAgIGNvbnN0IGQyID0gTWF0aC5mbG9vcihjLmRheSk7CiAgICAgIHNwZW50W2QyXSA9IChzcGVudFtkMl0gfHwgMCkgKyBwZXI7CiAgICB9CiAgfQogIGZvciAoY29uc3QgYyBvZiBjZWxscykgewogICAgY29uc3QgZDIgPSBNYXRoLmZsb29yKGMuZGF5KTsKICAgIHNhdmVkW2QyXSA9IChzYXZlZFtkMl0gfHwgMCkgKyAwLjAwMzsgICAgICAgICAgLyog4omIM2sgdG9rZW5zIHJlcGxheSBhdm9pZGVkIHBlciBmYWN0ICovCiAgfQogIGxldCB0b3RTID0gMCwgdG90ViA9IDA7CiAgZm9yIChjb25zdCBkMiBpbiBzcGVudCkgdG90UyArPSBzcGVudFtkMl07CiAgZm9yIChjb25zdCBkMiBpbiBzYXZlZCkgdG90ViArPSBzYXZlZFtkMl07CiAgcmV0dXJuIHsgc3BlbnQsIHNhdmVkLCB0b3RTLCB0b3RWIH07Cn0pKCk7CmRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0aWxlLXRvaycpLnRleHRDb250ZW50ID0gTWF0aC5yb3VuZChUT0sudG90UykgKyAnTSc7CmxldCB0b2tCaW5zID0gW107ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8qIHBlci1mcmFtZSBiaW4gZ2VvbWV0cnkgZm9yIGhvdmVyICovCmxldCB0b2tWaWV3ID0gJ2N1bSc7ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8qIGN1bSB8IGRheSDigJQgZXhwbGljaXQgc3ViLXZpZXcgKi8KbGV0IHRva1NlbCA9IG51bGw7ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLyogc2VsZWN0ZWQgZGF5IOKGkiBwYW5lIGxpc3RzIGFjdGl2ZSBwbGFucyAqLwpmdW5jdGlvbiBkcmF3VG9rZW5zTGVucyhjdHgyLCBnKSB7CiAgdG9rQmlucyA9IFtdOwogIGNvbnN0IGN1bSA9IHRva1ZpZXcgPT09ICdjdW0nOwogIGNvbnN0IHJCID0gZy5yMCAqIDEuNzsKICBjb25zdCBzcGFuT3V0ID0gZy5SICogMC45NCAtIHJCLCBzcGFuSW4gPSByQiAtIGcucjAgKiAwLjg7CiAgY29uc3QgZDAgPSBNYXRoLmNlaWwoUyksIGQxID0gTWF0aC5mbG9vcihNYXRoLm1pbihULCBFKSk7CiAgLyogc2VyaWVzICsgbm9ybWFsaXNhdGlvbiAqLwogIGxldCBjcyA9IDAsIGN2ID0gMCwgbWF4UyA9IDAuMDAxLCBtYXhWID0gMC4wMDE7CiAgY29uc3Qgcm93cyA9IFtdOwogIGZvciAobGV0IGQyID0gZDA7IGQyIDw9IGQxOyBkMisrKSB7CiAgICBjb25zdCBzcCA9IFRPSy5zcGVudFtkMl0gfHwgMCwgc3YgPSBUT0suc2F2ZWRbZDJdIHx8IDA7CiAgICBjcyArPSBzcDsgY3YgKz0gc3Y7CiAgICByb3dzLnB1c2goeyBkOiBkMiwgc3AsIHN2LCBjcywgY3YgfSk7CiAgfQogIGZvciAoY29uc3QgcjIgb2Ygcm93cykgeyBtYXhTID0gTWF0aC5tYXgobWF4UywgY3VtID8gcjIuY3MgOiByMi5zcCk7IG1heFYgPSBNYXRoLm1heChtYXhWLCBjdW0gPyByMi5jdiA6IHIyLnN2KTsgfQogIGNvbnN0IHdBID0gKFRBVSAtIFNFQU0pIC8gTWF0aC5tYXgoMSwgKE1hdGguZmxvb3IoRSkgLSBNYXRoLmNlaWwoUykgKyAxKSk7CiAgY3R4Mi5zdHJva2VTdHlsZSA9ICdyZ2JhKDI1NSwyNTUsMjU1LC4xMiknOwogIGN0eDIubGluZVdpZHRoID0gMSAvIFo7CiAgY3R4Mi5iZWdpblBhdGgoKTsgY3R4Mi5hcmMoMCwgMCwgckIsIEJBU0UsIEJBU0UgKyBUQVUgLSBTRUFNKTsgY3R4Mi5zdHJva2UoKTsKICBmb3IgKGNvbnN0IHIyIG9mIHJvd3MpIHsKICAgIGNvbnN0IGEgPSBCQVNFICsgKFRBVSAtIFNFQU0pICogKChyMi5kICsgMC41IC0gUykgLyBNYXRoLm1heCgwLjUsIEUgLSBTKSk7CiAgICBjb25zdCBoUyA9ICgoY3VtID8gcjIuY3MgOiByMi5zcCkgLyBtYXhTKSAqIHNwYW5PdXQ7CiAgICBjb25zdCB3QmFyID0gTWF0aC5tYXgoMS41LCB3QSAqIHJCICogMC41NSkgLyBNYXRoLm1heCgxLCBNYXRoLnNxcnQoWikpOwogICAgY29uc3QgaXNTZWxEYXkgPSB0b2tTZWwgPT09IHIyLmQ7CiAgICBpZiAoY3VtKSB7CiAgICAgIGNvbnN0IGhWID0gKChyMi5jdikgLyBtYXhWKSAqIHNwYW5JbjsKICAgICAgY3R4Mi5saW5lV2lkdGggPSB3QmFyOwogICAgICBjdHgyLnN0cm9rZVN0eWxlID0gaGV4MnJnYmEoJyNhNzhiZmEnLCAwLjU1KTsgIC8qIHNwZW50IOKGkiBvdXR3YXJkICovCiAgICAgIGN0eDIuYmVnaW5QYXRoKCk7CiAgICAgIGN0eDIubW92ZVRvKE1hdGguY29zKGEpICogckIsIE1hdGguc2luKGEpICogckIpOwogICAgICBjdHgyLmxpbmVUbyhNYXRoLmNvcyhhKSAqIChyQiArIGhTKSwgTWF0aC5zaW4oYSkgKiAockIgKyBoUykpOwogICAgICBjdHgyLnN0cm9rZSgpOwogICAgICBjdHgyLnN0cm9rZVN0eWxlID0gaGV4MnJnYmEoJyMzNGQzOTknLCAwLjYpOyAgIC8qIHNhdmVkIOKGkiBpbndhcmQgKi8KICAgICAgY3R4Mi5iZWdpblBhdGgoKTsKICAgICAgY3R4Mi5tb3ZlVG8oTWF0aC5jb3MoYSkgKiByQiwgTWF0aC5zaW4oYSkgKiByQik7CiAgICAgIGN0eDIubGluZVRvKE1hdGguY29zKGEpICogKHJCIC0gaFYpLCBNYXRoLnNpbihhKSAqIChyQiAtIGhWKSk7CiAgICAgIGN0eDIuc3Ryb2tlKCk7CiAgICB9IGVsc2UgewogICAgICAvKiBwZXIgZGF5OiBPTkUgam9pbmVkIGJhciDigJQgcHVycGxlIHNwZW5kIHdpdGggYSBncmVlbiBzYXZpbmdzIGNvcmUKICAgICAgICAgb3ZlcmxhaWQgb24gdGhlIHNhbWUgc3Bva2UgKGVhY2ggc2VyaWVzIGtlZXBzIGl0cyBvd24gc2NhbGUpICovCiAgICAgIGNvbnN0IGhWID0gKChyMi5zdikgLyBtYXhWKSAqIHNwYW5PdXQgKiAwLjg1OwogICAgICBjdHgyLmxpbmVXaWR0aCA9IHdCYXI7CiAgICAgIGN0eDIuc3Ryb2tlU3R5bGUgPSBoZXgycmdiYSgnI2E3OGJmYScsIGlzU2VsRGF5ID8gMC45IDogMC41KTsKICAgICAgY3R4Mi5iZWdpblBhdGgoKTsKICAgICAgY3R4Mi5tb3ZlVG8oTWF0aC5jb3MoYSkgKiByQiwgTWF0aC5zaW4oYSkgKiByQik7CiAgICAgIGN0eDIubGluZVRvKE1hdGguY29zKGEpICogKHJCICsgaFMpLCBNYXRoLnNpbihhKSAqIChyQiArIGhTKSk7CiAgICAgIGN0eDIuc3Ryb2tlKCk7CiAgICAgIGN0eDIubGluZVdpZHRoID0gTWF0aC5tYXgoMS4yLCB3QmFyICogMC4zOCk7CiAgICAgIGN0eDIuc3Ryb2tlU3R5bGUgPSBoZXgycmdiYSgnIzM0ZDM5OScsIGlzU2VsRGF5ID8gMSA6IDAuOCk7CiAgICAgIGN0eDIuYmVnaW5QYXRoKCk7CiAgICAgIGN0eDIubW92ZVRvKE1hdGguY29zKGEpICogckIsIE1hdGguc2luKGEpICogckIpOwogICAgICBjdHgyLmxpbmVUbyhNYXRoLmNvcyhhKSAqIChyQiArIGhWKSwgTWF0aC5zaW4oYSkgKiAockIgKyBoVikpOwogICAgICBjdHgyLnN0cm9rZSgpOwogICAgICBjdHgyLmxpbmVXaWR0aCA9IDEgLyBaOwogICAgICBjdHgyLmZpbGxTdHlsZSA9IGhleDJyZ2JhKCcjYTc4YmZhJywgaXNTZWxEYXkgPyAxIDogMC44NSk7CiAgICAgIGN0eDIuYmVnaW5QYXRoKCk7IGN0eDIuYXJjKE1hdGguY29zKGEpICogKHJCICsgaFMpLCBNYXRoLnNpbihhKSAqIChyQiArIGhTKSwgKGlzU2VsRGF5ID8gMy40IDogMi40KSAvIE1hdGguc3FydChaKSwgMCwgNyk7IGN0eDIuZmlsbCgpOwogICAgICBjdHgyLmZpbGxTdHlsZSA9IGhleDJyZ2JhKCcjMzRkMzk5JywgaXNTZWxEYXkgPyAxIDogMC44NSk7CiAgICAgIGN0eDIuYmVnaW5QYXRoKCk7IGN0eDIuYXJjKE1hdGguY29zKGEpICogKHJCICsgaFYpLCBNYXRoLnNpbihhKSAqIChyQiArIGhWKSwgKGlzU2VsRGF5ID8gMi44IDogMikgLyBNYXRoLnNxcnQoWiksIDAsIDcpOyBjdHgyLmZpbGwoKTsKICAgICAgaWYgKGlzU2VsRGF5KSB7CiAgICAgICAgY3R4Mi5zdHJva2VTdHlsZSA9ICdyZ2JhKDIzOCwyNDAsMjQ2LC41KSc7CiAgICAgICAgY3R4Mi5iZWdpblBhdGgoKTsgY3R4Mi5hcmMoMCwgMCwgckIsIGEgLSAwLjAyLCBhICsgMC4wMik7IGN0eDIuc3Ryb2tlKCk7CiAgICAgIH0KICAgIH0KICAgIHRva0JpbnMucHVzaCh7IC4uLnIyLCBhLCByVGlwOiByQiArIGhTIH0pOwogIH0KICBjdHgyLmxpbmVXaWR0aCA9IDEgLyBaOwogIGNvbnN0IHBjdCA9IFRPSy50b3RTID4gMCA/IE1hdGgucm91bmQoMTAwICogVE9LLnRvdFYgLyBUT0sudG90UykgOiAwOwogIGNvbnN0IG5EYXlzID0gTWF0aC5tYXgoMSwgcm93cy5sZW5ndGgpOwogIGxlbnNMYWJlbHMucHVzaCh7IHg6IDAsIHk6IGcuUiArIDQyLCBjYXA6IHRydWUsCiAgICB0OiBjdW0KICAgICAgPyAndG9rZW5zIMK3IGN1bXVsYXRpdmUgwrcgb3V0d2FyZCA9IHNwZW50ICcgKyBNYXRoLnJvdW5kKFRPSy50b3RTKSArICdNIMK3IGlud2FyZCA9IGVzdC4gc2F2ZWQgJyArIFRPSy50b3RWLnRvRml4ZWQoMSkgKyAnTSAoficgKyBwY3QgKyAnJSwgZnJvbSAxMi10b2tlbiBmYWN0IHJlY2FsbHMgdnMgfjNrIHJlcGxheXMpJwogICAgICA6ICd0b2tlbnMgwrcgcGVyIGRheSDCtyBhdmcgJyArIChjcyAvIG5EYXlzKS50b0ZpeGVkKDEpICsgJ00vZGF5IHNwZW50IMK3IHBlYWsgJyArIG1heFMudG9GaXhlZCgxKSArICdNIMK3IGVzdC4gc2F2ZWQgYXZnICcgKyAoY3YgLyBuRGF5cyAqIDEwMDApLnRvRml4ZWQoMCkgKyAnay9kYXknIH0pOwp9CgovKiDilIDilIAgYWx0ZXJuYXRpdmUgbGVuc2VzOiBzYW1lIGRpc2MsIGRpZmZlcmVudCBzdWJzdHJhdGUgY3V0IOKUgOKUgCAqLwpmdW5jdGlvbiBkcmF3TGVuc0luRnJhbWUoY3R4MiwgZywgdGltZSkgewogIGZvciAoY29uc3QgYyBvZiBjZWxscykgeyBjLl94ID0gdW5kZWZpbmVkOyBjLl9vbiA9IGZhbHNlOyBjLl9ieCA9IHVuZGVmaW5lZDsgfQogIGlmIChsZW5zID09PSAnZGF0YScpIHsgZHJhd0RhdGFMZW5zKGN0eDIsIGcpOyByZXR1cm47IH0KICBpZiAobGVucyA9PT0gJ3Rva2VucycpIHsgZHJhd1Rva2Vuc0xlbnMoY3R4MiwgZyk7IHJldHVybjsgfQogIGlmIChsZW5zID09PSAncmVjZWlwdHMnKSB7IGRyYXdSZWNlaXB0c0xlbnMoY3R4MiwgZywgdGltZSk7IHJldHVybjsgfQogIGNvbnN0IGdyb3VwcyA9IGxlbnMgPT09ICdtZW1vcnknCiAgICA/IFtbJ2dhdGUnLCAnIzJkZDRiZiddLCBbJ2RlY2lzaW9uJywgJyNhNzhiZmEnXSwgWydtZW1vcnknLCAnIzhiOTZmMiddLCBbJ2hhbmRvZmYnLCAnI2Y1YTYyMyddLCBbJ2luY2lkZW50JywgJyNlZjQ0NDQnXV0KICAgIDogW1snY2xhdWRlLXdvcmsnLCAnIzhiOTZmMiddLCBbJ2NvZGV4LXdvcmsnLCAnIzIyZDNlZSddLCBbJ3VudHJhY2VkJywgJyM3ZTg1OTUnXV07CiAgY29uc3Qga2V5T2YgPSBjID0+IGxlbnMgPT09ICdtZW1vcnknID8gYy5raW5kIDogKGMuYWN0b3IgfHwgJ3VudHJhY2VkJyk7CiAgY29uc3QgTjIgPSBncm91cHMubGVuZ3RoOwogIGdyb3Vwcy5mb3JFYWNoKChncnAsIGdpKSA9PiB7CiAgICBjb25zdCBrMiA9IGdycFswXSwgaHVlMiA9IGdycFsxXTsKICAgIGNvbnN0IGEwID0gQkFTRSArIChnaSAvIE4yKSAqIChUQVUgLSBTRUFNKSwgYTEgPSBCQVNFICsgKChnaSArIDEpIC8gTjIpICogKFRBVSAtIFNFQU0pOwogICAgLyogZGl2aWRlciArIHJpbSBhcmMgKi8KICAgIGN0eDIuc3Ryb2tlU3R5bGUgPSAncmdiYSgyNTUsMjU1LDI1NSwuMDYpJzsKICAgIGN0eDIubGluZVdpZHRoID0gMSAvIFo7CiAgICBjdHgyLmJlZ2luUGF0aCgpOwogICAgY3R4Mi5tb3ZlVG8oTWF0aC5jb3MoYTApICogZy5yMCwgTWF0aC5zaW4oYTApICogZy5yMCk7CiAgICBjdHgyLmxpbmVUbyhNYXRoLmNvcyhhMCkgKiBnLlIsIE1hdGguc2luKGEwKSAqIGcuUik7CiAgICBjdHgyLnN0cm9rZSgpOwogICAgY29uc3QgbWVtYmVycyA9IGNlbGxzLmZpbHRlcihjID0+IGtleU9mKGMpID09PSBrMiAmJiBjLmRheSA8PSBUICYmIGMuZGF5ID49IFMgJiYgYy5kYXkgPD0gRSAmJiBwYXNzRmlsdGVyKGMpKTsKICAgIGN0eDIuc3Ryb2tlU3R5bGUgPSBoZXgycmdiYShodWUyLCAwLjUpOwogICAgY3R4Mi5saW5lV2lkdGggPSAzIC8gWjsKICAgIGN0eDIuYmVnaW5QYXRoKCk7IGN0eDIuYXJjKDAsIDAsIGcuUiArIDMsIGEwICsgMC4wMiwgYTEgLSAwLjAyKTsgY3R4Mi5zdHJva2UoKTsKICAgIGN0eDIubGluZVdpZHRoID0gMSAvIFo7CiAgICAvKiBsYWJlbCAqLwogICAgY29uc3QgbWlkID0gKGEwICsgYTEpIC8gMjsKICAgIGxlbnNMYWJlbHMucHVzaCh7IHg6IE1hdGguY29zKG1pZCkgKiAoZy5SICsgMjApLCB5OiBNYXRoLnNpbihtaWQpICogKGcuUiArIDIwKSwKICAgICAgICAgICAgICAgICAgICAgIHQ6IGsyICsgJyDCtyAnICsgbWVtYmVycy5sZW5ndGggfSk7CiAgICAvKiBjZWxsczogcmluZyA9IGRheSBlcG9jaCwgZmFkZSA9IGFnZSAobWVtb3J5IGxlbnMpICovCiAgICBmb3IgKGNvbnN0IGMgb2YgbWVtYmVycykgewogICAgICBjb25zdCBhID0gYTAgKyAoYTEgLSBhMCkgKiAoMC4wOCArIGMuamEgKiAwLjg0KTsKICAgICAgY29uc3QgciA9IGRheVIoZywgYy5kYXkpICogKDAuOTk1ICsgYy5qciAqIDAuMDEpOwogICAgICBjb25zdCB4ID0gTWF0aC5jb3MoYSkgKiByLCB5ID0gTWF0aC5zaW4oYSkgKiByOwogICAgICBjb25zdCBpc0ggPSBob3ZlciA9PT0gYzsKICAgICAgbGV0IGFscGhhID0gYy5yZWFsID8gMC45IDogMC40NTsKICAgICAgaWYgKGxlbnMgPT09ICdtZW1vcnknKSB7CiAgICAgICAgY29uc3QgYWdlRnJhYyA9IE1hdGgubWF4KDAsIE1hdGgubWluKDEsIChUIC0gYy5kYXkpIC8gTWF0aC5tYXgoMC41LCBFIC0gUykpKTsKICAgICAgICBhbHBoYSAqPSAxIC0gMC41ICogYWdlRnJhYzsgICAgICAgICAgICAgICAgIC8qIG9sZGVyIG1lbW9yeSBkaW1zIOKAlCBkZWNheSwgaWxsdXN0cmF0aXZlbHkgKi8KICAgICAgfQogICAgICBjb25zdCByciA9IChjLnJlYWwgPyAzLjIgOiAyLjQpICogKGlzSCA/IDEuOCA6IDEpOwogICAgICBjdHgyLmZpbGxTdHlsZSA9IGhleDJyZ2JhKGh1ZTIsIGFscGhhICogKGhvdmVyICYmICFpc0ggPyAwLjUgOiAxKSk7CiAgICAgIGlmIChjLmtpbmQgPT09ICdnYXRlJyAmJiBjLnJlYWwpIHsKICAgICAgICBjdHgyLmJlZ2luUGF0aCgpOwogICAgICAgIGN0eDIubW92ZVRvKHgsIHkgLSByciAtIDEpOyBjdHgyLmxpbmVUbyh4ICsgcnIsIHkpOyBjdHgyLmxpbmVUbyh4LCB5ICsgcnIgKyAxKTsgY3R4Mi5saW5lVG8oeCAtIHJyLCB5KTsKICAgICAgICBjdHgyLmNsb3NlUGF0aCgpOyBjdHgyLmZpbGwoKTsKICAgICAgfSBlbHNlIHsKICAgICAgICBjdHgyLmJlZ2luUGF0aCgpOyBjdHgyLmFyYyh4LCB5LCByciwgMCwgNyk7IGN0eDIuZmlsbCgpOwogICAgICB9CiAgICAgIGlmIChpc0gpIHsgY3R4Mi5zdHJva2VTdHlsZSA9IGhleDJyZ2JhKGh1ZTIsIDAuOTUpOyBjdHgyLmJlZ2luUGF0aCgpOyBjdHgyLmFyYyh4LCB5LCByciArIDQgLyBaLCAwLCA3KTsgY3R4Mi5zdHJva2UoKTsgfQogICAgICBjLl94ID0geDsgYy5feSA9IHk7IGMuX2RyID0gcnI7IGMuX29uID0gdHJ1ZTsKICAgIH0KICB9KTsKICBsZW5zTGFiZWxzLnB1c2goeyB4OiAwLCB5OiBnLlIgKyA0MiwgY2FwOiB0cnVlLAogICAgICAgICAgICAgICAgICAgIHQ6IGxlbnMgPT09ICdtZW1vcnknCiAgICAgICAgICAgICAgICAgICAgICA/ICdtZW1vcnkgbGVucyDCtyBzZWN0b3IgPSBmYWN0IGtpbmQgwrcgcmluZyA9IGRheSDCtyBmYWRlID0gYWdlIChkZWNheSBpbGx1c3RyYXRpdmUpJwogICAgICAgICAgICAgICAgICAgICAgOiAnc2Vzc2lvbnMgbGVucyDCtyBzZWN0b3IgPSBhZ2VudCBwYXNzcG9ydCDCtyByaW5nID0gZGF5IMK3IHVudHJhY2VkIHBsYW5zIGhhdmUgbm8gYWN0b3InIH0pOwp9CmZ1bmN0aW9uIGRyYXdSZWNlaXB0c0xlbnMoY3R4MiwgZywgdGltZSkgewogIGNvbnN0IHRlZXRoID0gMTIwOwogIGNvbnN0IHNlYWxlZEZyYWMgPSBNYXRoLm1heCgwLCBNYXRoLm1pbigxLCAoVCAtIFMpIC8gTWF0aC5tYXgoMC41LCBFIC0gUykpKTsKICBmb3IgKGxldCBpID0gMDsgaSA8IHRlZXRoOyBpKyspIHsKICAgIGNvbnN0IGEgPSBCQVNFICsgKGkgLyB0ZWV0aCkgKiAoVEFVIC0gU0VBTSk7CiAgICBjb25zdCBzZWFsZWQgPSBpIC8gdGVldGggPD0gc2VhbGVkRnJhYzsKICAgIGN0eDIuc3Ryb2tlU3R5bGUgPSBzZWFsZWQgPyAncmdiYSg1MiwyMTEsMTUzLC44KScgOiAncmdiYSgyNTUsMjU1LDI1NSwuMTApJzsKICAgIGN0eDIubGluZVdpZHRoID0gKHNlYWxlZCA/IDEuOCA6IDEpIC8gWjsKICAgIGN0eDIuYmVnaW5QYXRoKCk7CiAgICBjdHgyLm1vdmVUbyhNYXRoLmNvcyhhKSAqIGcuUiwgTWF0aC5zaW4oYSkgKiBnLlIpOwogICAgY3R4Mi5saW5lVG8oTWF0aC5jb3MoYSkgKiAoZy5SICsgKHNlYWxlZCA/IDkgOiA2KSksIE1hdGguc2luKGEpICogKGcuUiArIChzZWFsZWQgPyA5IDogNikpKTsKICAgIGN0eDIuc3Ryb2tlKCk7CiAgfQogIGN0eDIubGluZVdpZHRoID0gMSAvIFo7CiAgLyogcml2ZXQgc3BpcmFsOiByZWNlaXB0cyBhY2N1bXVsYXRpbmcgaW53YXJkLW91dCAoZ29sZGVuIGFuZ2xlKSAqLwogIGNvbnN0IG4gPSBNYXRoLmZsb29yKDkwICogc2VhbGVkRnJhYykgKyA4OwogIGZvciAobGV0IGkgPSAwOyBpIDwgbjsgaSsrKSB7CiAgICBjb25zdCBhID0gaSAqIDIuMzk5OTYzOwogICAgY29uc3QgciA9IGcucjAgKyAoZy5SIC0gZy5yMCkgKiAoMC4xMiArIChpIC8gOTgpICogMC43OCk7CiAgICBjdHgyLmZpbGxTdHlsZSA9IGhleDJyZ2JhKCcjMzRkMzk5JywgMC4yNSArIChpIC8gbikgKiAwLjUpOwogICAgY3R4Mi5iZWdpblBhdGgoKTsgY3R4Mi5hcmMoTWF0aC5jb3MoYSkgKiByLCBNYXRoLnNpbihhKSAqIHIsIDEuOCwgMCwgNyk7IGN0eDIuZmlsbCgpOwogIH0KICBsZW5zTGFiZWxzLnB1c2goeyB4OiAwLCB5OiBnLlIgKyA0MiwgY2FwOiB0cnVlLAogICAgICAgICAgICAgICAgICAgIHQ6ICdyZWNlaXB0cyBsZW5zIMK3IGNoYWluIHRpY2tzIGZvcndhcmQgb25seSDCtyBpbGx1c3RyYXRpdmUgdW50aWwgL3YxL3JlY2VpcHRzL2V4cG9ydCBpcyB3aXJlZCcgfSk7Cn0KCi8qIGtpY2sgKi8KZnVuY3Rpb24ga2ljaygpIHsgaWYgKHJhZklkID09PSBudWxsKSByYWZJZCA9IHJlcXVlc3RBbmltYXRpb25GcmFtZShkcmF3KTsgfQpkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCd2aXNpYmlsaXR5Y2hhbmdlJywga2ljayk7CmtpY2soKTsKCi8qIOKUgOKUgCBjb250cm9scyDilIDilIAgKi8KZnVuY3Rpb24gc2V0UGxheWluZyh2KSB7CiAgcGxheWluZyA9IHY7CiAgYlBsYXkudGV4dENvbnRlbnQgPSB2ID8gJ+KPuCcgOiAn4pa2JzsKICBiUGxheS5zZXRBdHRyaWJ1dGUoJ2FyaWEtcHJlc3NlZCcsIFN0cmluZyh2KSk7CiAgaWYgKHYgJiYgIXNob3dDb21wbGV0ZWQpIHNldENvbXBsZXRlZCh0cnVlKTsgICAgIC8qIHBsYXliYWNrIG5lZWRzIHRoZSBhZGQvcmVtb3ZlIHN0b3J5ICovCiAgaWYgKHYgJiYgIXNob3dMZWRnZXIpIHNldExlZGdlcih0cnVlKTsgICAgICAgICAgIC8qIOKApmFuZCB0aGUgcmV0aXJlIGxpc3QgYWxvbmdzaWRlIGl0ICovCn0KZnVuY3Rpb24gc2V0TGVkZ2VyKHYpIHsKICBzaG93TGVkZ2VyID0gdjsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYi1sZWRnZXInKS5zZXRBdHRyaWJ1dGUoJ2FyaWEtcHJlc3NlZCcsIFN0cmluZyh2KSk7Cn0KZnVuY3Rpb24gc2V0Q29tcGxldGVkKHYpIHsKICBzaG93Q29tcGxldGVkID0gdjsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYi1kb25lJykuc2V0QXR0cmlidXRlKCdhcmlhLXByZXNzZWQnLCBTdHJpbmcodikpOwp9CmJQbGF5LmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogIGlmICghcGxheWluZyAmJiBUID49IEUgLSAwLjAxKSBUID0gUzsgICAgICAgICAgICAvKiByZXBsYXkgZnJvbSB3aW5kb3cgc3RhcnQgKi8KICBzZXRQbGF5aW5nKCFwbGF5aW5nKTsKfSk7CmJTcGluLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogIHNwaW5uaW5nID0gIXNwaW5uaW5nOwogIGJTcGluLnNldEF0dHJpYnV0ZSgnYXJpYS1wcmVzc2VkJywgU3RyaW5nKHNwaW5uaW5nKSk7Cn0pOwpkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYi1kb25lJykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiBzZXRDb21wbGV0ZWQoIXNob3dDb21wbGV0ZWQpKTsKZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2ItbGVkZ2VyJykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiBzZXRMZWRnZXIoIXNob3dMZWRnZXIpKTsKYkNsb2NrLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogIHJlc2V0VHdlZW4gPSB0cnVlOwogIHNwaW5uaW5nID0gZmFsc2U7ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvKiByZXNldCBhbHNvIHN0b3BzIHRoZSBzcGluICovCiAgYlNwaW4uc2V0QXR0cmlidXRlKCdhcmlhLXByZXNzZWQnLCAnZmFsc2UnKTsKfSk7CmJNb2RlLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogIG1vZGUgPSBtb2RlID09PSAnZG90cycgPyAnYmFycycgOiAnZG90cyc7CiAgYk1vZGUuc2V0QXR0cmlidXRlKCdhcmlhLXByZXNzZWQnLCBTdHJpbmcobW9kZSA9PT0gJ2JhcnMnKSk7Cn0pOwpjb25zdCBiRGlyID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2ItZGlyJyk7CmJEaXIuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB7CiAgZGlyID0gZGlyID09PSAnb3V0JyA/ICdpbicgOiAnb3V0JzsKICBiRGlyLnRleHRDb250ZW50ID0gZGlyID09PSAnb3V0JyA/ICdlZGdlOiBvdXR3YXJkJyA6ICdlZGdlOiBpbndhcmQnOwogIGJEaXIuc2V0QXR0cmlidXRlKCdhcmlhLXByZXNzZWQnLCBTdHJpbmcoZGlyID09PSAnaW4nKSk7Cn0pOwpjb25zdCBiQWxsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2ItYWxsJyk7CmJBbGwuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB7CiAgc2hvd0FsbCA9ICFzaG93QWxsOwogIGJBbGwuc2V0QXR0cmlidXRlKCdhcmlhLXByZXNzZWQnLCBTdHJpbmcoc2hvd0FsbCkpOwp9KTsKY29uc3QgYlN0YXRlID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2Itc3RhdGUnKTsKYlN0YXRlLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogIGNvbG9yQnlTdGF0ZSA9ICFjb2xvckJ5U3RhdGU7CiAgYlN0YXRlLnNldEF0dHJpYnV0ZSgnYXJpYS1wcmVzc2VkJywgU3RyaW5nKGNvbG9yQnlTdGF0ZSkpOwp9KTsKY29uc3QgYkxpbiA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdiLWxpbicpOwpiTGluLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogIHNob3dMaW5lYWdlID0gIXNob3dMaW5lYWdlOwogIGJMaW4uc2V0QXR0cmlidXRlKCdhcmlhLXByZXNzZWQnLCBTdHJpbmcoc2hvd0xpbmVhZ2UpKTsKfSk7CmRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzLWtpbmQnKS5hZGRFdmVudExpc3RlbmVyKCdjaGFuZ2UnLCBlID0+IHsgZktpbmQgPSBlLnRhcmdldC52YWx1ZTsgfSk7CmRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzLWFnZW50JykuYWRkRXZlbnRMaXN0ZW5lcignY2hhbmdlJywgZSA9PiB7IGZBZ2VudCA9IGUudGFyZ2V0LnZhbHVlOyB9KTsKY29uc3QgZFN0YXJ0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2Qtc3RhcnQnKTsKY29uc3QgZEVuZCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdkLWVuZCcpOwpmdW5jdGlvbiBzeW5jV2luZG93KCkgewogIGNvbnN0IHMgPSBNYXRoLm1pbihyU3RhcnQudmFsdWUgLyAxMDAwLCByRW5kLnZhbHVlIC8gMTAwMCAtIDAuMDMpOwogIGNvbnN0IGUgPSBNYXRoLm1heChyRW5kLnZhbHVlIC8gMTAwMCwgclN0YXJ0LnZhbHVlIC8gMTAwMCArIDAuMDMpOwogIFMgPSAxMSArIHMgKiAoTk9XIC0gMTEpOwogIEUgPSAxMSArIGUgKiAoTk9XIC0gMTEpOwogIFQgPSBNYXRoLm1heChTLCBNYXRoLm1pbihFLCBUKSk7CiAgclRpbWUudmFsdWUgPSBNYXRoLnJvdW5kKChUIC0gUykgLyBNYXRoLm1heCgwLjUsIEUgLSBTKSAqIDEwMDApOwogIGNEYXRlLnRleHRDb250ZW50ID0gZGF5RGF0ZShUKTsKICBkU3RhcnQudmFsdWUgPSBkYXlEYXRlKFMpOwogIGRFbmQudmFsdWUgPSBkYXlEYXRlKEUpOwp9CnJTdGFydC5hZGRFdmVudExpc3RlbmVyKCdpbnB1dCcsIHN5bmNXaW5kb3cpOwpyRW5kLmFkZEV2ZW50TGlzdGVuZXIoJ2lucHV0Jywgc3luY1dpbmRvdyk7Ci8qIGRhdGUgcGlja2VycyBkcml2ZSB0aGUgc2FtZSB3aW5kb3cgKi8KZnVuY3Rpb24gZGF0ZVRvRGF5KHYpIHsgcmV0dXJuIERhdGUucGFyc2UodiArICdUMDA6MDA6MDBaJykgLyA4NjQwMDAwMCAtIDIwNTgwOyB9CmRTdGFydC5hZGRFdmVudExpc3RlbmVyKCdjaGFuZ2UnLCAoKSA9PiB7CiAgY29uc3QgZCA9IE1hdGgubWF4KDExLCBNYXRoLm1pbihOT1cgLSAxLCBkYXRlVG9EYXkoZFN0YXJ0LnZhbHVlKSkpOwogIHJTdGFydC52YWx1ZSA9IE1hdGgucm91bmQoKGQgLSAxMSkgLyAoTk9XIC0gMTEpICogMTAwMCk7CiAgc3luY1dpbmRvdygpOwp9KTsKZEVuZC5hZGRFdmVudExpc3RlbmVyKCdjaGFuZ2UnLCAoKSA9PiB7CiAgY29uc3QgZCA9IE1hdGgubWF4KDEyLCBNYXRoLm1pbihOT1csIGRhdGVUb0RheShkRW5kLnZhbHVlKSkpOwogIHJFbmQudmFsdWUgPSBNYXRoLnJvdW5kKChkIC0gMTEpIC8gKE5PVyAtIDExKSAqIDEwMDApOwogIHN5bmNXaW5kb3coKTsKfSk7CnJUaW1lLmFkZEV2ZW50TGlzdGVuZXIoJ2lucHV0JywgKCkgPT4gewogIFQgPSBTICsgKHJUaW1lLnZhbHVlIC8gMTAwMCkgKiAoRSAtIFMpOwogIHNldFBsYXlpbmcoZmFsc2UpOwogIGNEYXRlLnRleHRDb250ZW50ID0gZGF5RGF0ZShUKTsKfSk7CgovKiB6b29tICsgcGFuICovCmZ1bmN0aW9uIHpvb21BdChzeCwgc3ksIGZhY3RvcikgewogIGNvbnN0IGcgPSBnZW9tKCk7CiAgY29uc3QgYmVmb3JlID0gdG9EaXNjKGcsIHN4LCBzeSk7CiAgWiA9IE1hdGgubWF4KDAuNiwgTWF0aC5taW4oNywgWiAqIGZhY3RvcikpOwogIGNvbnN0IGFmdGVyID0gdG9TY3JlZW4oZywgYmVmb3JlLngsIGJlZm9yZS55KTsKICBwYW5YICs9IHN4IC0gYWZ0ZXIueDsgcGFuWSArPSBzeSAtIGFmdGVyLnk7Cn0KY3YuYWRkRXZlbnRMaXN0ZW5lcignd2hlZWwnLCBlID0+IHsKICBlLnByZXZlbnREZWZhdWx0KCk7CiAgY29uc3QgciA9IGN2LmdldEJvdW5kaW5nQ2xpZW50UmVjdCgpOwogIHpvb21BdChlLmNsaWVudFggLSByLmxlZnQsIGUuY2xpZW50WSAtIHIudG9wLCBlLmRlbHRhWSA8IDAgPyAxLjE1IDogMSAvIDEuMTUpOwp9LCB7IHBhc3NpdmU6IGZhbHNlIH0pOwpkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYi16aW4nKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHpvb21BdChXIC8gMiwgSCAvIDIsIDEuMzUpKTsKZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2Item91dCcpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gem9vbUF0KFcgLyAyLCBIIC8gMiwgMSAvIDEuMzUpKTsKZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2ItemZpdCcpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4geyBaID0gMTsgcGFuWCA9IHBhblkgPSAwOyB9KTsKCmN2LmFkZEV2ZW50TGlzdGVuZXIoJ3BvaW50ZXJkb3duJywgZSA9PiB7CiAgZHJhZ2dpbmcgPSB0cnVlOyBkcmFnTW92ZWQgPSAwOwogIGxhc3RQWCA9IGUuY2xpZW50WDsgbGFzdFBZID0gZS5jbGllbnRZOwogIGN2LnNldFBvaW50ZXJDYXB0dXJlKGUucG9pbnRlcklkKTsKfSk7CmN2LmFkZEV2ZW50TGlzdGVuZXIoJ3BvaW50ZXJ1cCcsIGUgPT4gewogIGRyYWdnaW5nID0gZmFsc2U7CiAgaWYgKGRyYWdNb3ZlZCA8IDUpIGhhbmRsZUNsaWNrKGUpOwp9KTsKY3YuYWRkRXZlbnRMaXN0ZW5lcigncG9pbnRlcm1vdmUnLCBlID0+IHsKICBteEFicyA9IGUuY2xpZW50WDsgbXlBYnMgPSBlLmNsaWVudFk7CiAgaWYgKGRyYWdnaW5nKSB7CiAgICBjb25zdCBkeCA9IGUuY2xpZW50WCAtIGxhc3RQWCwgZHkgPSBlLmNsaWVudFkgLSBsYXN0UFk7CiAgICBkcmFnTW92ZWQgKz0gTWF0aC5hYnMoZHgpICsgTWF0aC5hYnMoZHkpOwogICAgaWYgKGRyYWdNb3ZlZCA+IDUpIHsgcGFuWCArPSBkeDsgcGFuWSArPSBkeTsgfQogICAgbGFzdFBYID0gZS5jbGllbnRYOyBsYXN0UFkgPSBlLmNsaWVudFk7CiAgICByZXR1cm47CiAgfQogIGlmIChsZW5zID09PSAndG9rZW5zJykgewogICAgY29uc3QgZzIgPSBnZW9tKCk7CiAgICBjb25zdCBwZCA9IHRvRGlzYyhnMiwgZS5jbGllbnRYIC0gY3YuZ2V0Qm91bmRpbmdDbGllbnRSZWN0KCkubGVmdCwgZS5jbGllbnRZIC0gY3YuZ2V0Qm91bmRpbmdDbGllbnRSZWN0KCkudG9wKTsKICAgIGNvbnN0IHByMiA9IE1hdGguaHlwb3QocGQueCwgcGQueSk7CiAgICBsZXQgcGEyID0gTWF0aC5hdGFuMihwZC55LCBwZC54KTsKICAgIHdoaWxlIChwYTIgPCBCQVNFKSBwYTIgKz0gVEFVOwogICAgbGV0IGJpbiA9IG51bGwsIGJkMiA9IDAuMDU7CiAgICBmb3IgKGNvbnN0IGIyIG9mIHRva0JpbnMpIHsKICAgICAgbGV0IGJhID0gYjIuYTsgd2hpbGUgKGJhIDwgQkFTRSkgYmEgKz0gVEFVOwogICAgICBjb25zdCBkYTIgPSBNYXRoLmFicyhwYTIgLSBiYSk7CiAgICAgIGlmIChkYTIgPCBiZDIgJiYgcHIyID4gZzIucjAgKiAwLjcgJiYgcHIyIDwgZzIuUikgeyBiZDIgPSBkYTI7IGJpbiA9IGIyOyB9CiAgICB9CiAgICBpZiAoYmluKSB7CiAgICAgIHNob3dUaXAoZS5jbGllbnRYLCBlLmNsaWVudFksCiAgICAgICAgJzxiPicgKyBkYXlEYXRlKGJpbi5kKSArICc8L2I+PGJyPicgKwogICAgICAgICc8c3BhbiBjbGFzcz0iayI+c3BlbnQ8L3NwYW4+ICcgKyBiaW4uc3AudG9GaXhlZCgxKSArICdNIDxzcGFuIGNsYXNzPSJrIj5kYXk8L3NwYW4+IMK3ICcgKyBiaW4uY3MudG9GaXhlZCgxKSArICdNIDxzcGFuIGNsYXNzPSJrIj5jdW08L3NwYW4+PGJyPicgKwogICAgICAgICc8c3BhbiBjbGFzcz0iayI+c2F2ZWQ8L3NwYW4+ICcgKyBiaW4uc3YudG9GaXhlZCgyKSArICdNIDxzcGFuIGNsYXNzPSJrIj5kYXk8L3NwYW4+IMK3ICcgKyBiaW4uY3YudG9GaXhlZCgyKSArICdNIDxzcGFuIGNsYXNzPSJrIj5jdW0gKGVzdC4pPC9zcGFuPicpOwogICAgfSBlbHNlIGhpZGVUaXAoKTsKICAgIGhvdmVyID0gbnVsbDsgaG92ZXJTZWMgPSBudWxsOwogICAgcmV0dXJuOwogIH0KICBob3ZlciA9IGhpdFRlc3QoZSk7CiAgaG92ZXJTZWMgPSBob3ZlciAmJiBob3Zlci5wID8gaG92ZXIucCA6IHNlY3RvckF0KGUpOwogIGlmIChob3ZlciAmJiBsZW5zID09PSAnZGF0YScpIHsKICAgIGNvbnN0IG4gPSBob3ZlcjsKICAgIHNob3dUaXAobXhBYnMsIG15QWJzLAogICAgICAnPGI+JyArIG4uayArICc8L2I+PGJyPicgKwogICAgICAnPHNwYW4gY2xhc3M9ImsiPmVudGl0eTwvc3Bhbj4gJyArIChuLmUubGVuZ3RoID4gNDAgPyBuLmUuc2xpY2UoMCwgMzkpICsgJ+KApicgOiBuLmUpICsgJzxicj4nICsKICAgICAgJzxzcGFuIGNsYXNzPSJrIj5zb3VyY2U8L3NwYW4+ICcgKyBkYXlEYXRlKG4uZCkgKyAobi5hID8gJyA8c3BhbiBjbGFzcz0iayI+Ynk8L3NwYW4+ICcgKyBuLmEgOiAnJykgKyAnPGJyPicgKwogICAgICAnPHNwYW4gY2xhc3M9ImsiPmNvbmZpZGVuY2U8L3NwYW4+ICcgKyBnRWZmQ29uZihuKS50b0ZpeGVkKDIpICsgJyA8c3BhbiBjbGFzcz0iayI+KCcgKyAobi5oIHx8ICdub25lJykgKyAnKTwvc3Bhbj4nICsKICAgICAgJyDCtyA8c3BhbiBjbGFzcz0iayI+bGlua3M8L3NwYW4+ICcgKyAoKEdBREpbbi5pXSB8fCBbXSkubGVuZ3RoKSk7CiAgICByZXR1cm47CiAgfQogIGlmIChob3ZlcikgewogICAgY29uc3QgYyA9IGhvdmVyOwogICAgc2hvd1RpcChteEFicywgbXlBYnMsIGMucmVhbAogICAgICA/ICc8Yj4nICsgYy5rZXkgKyAnPC9iPicgKyAoYy52ZXJzaW9uID4gMSA/ICcgPHNwYW4gY2xhc3M9ImsiPnYnICsgYy52ZXJzaW9uICsgJzwvc3Bhbj4nIDogJycpICsgJzxicj4nICsKICAgICAgICAnPHNwYW4gY2xhc3M9ImsiPnBsYW48L3NwYW4+ICcgKyBjLnAuc2hvcnQgKyAnPGJyPicgKwogICAgICAgICc8c3BhbiBjbGFzcz0iayI+c3RvcmVkPC9zcGFuPiAnICsgZGF5RGF0ZShjLmRheSkgKyAnIDxzcGFuIGNsYXNzPSJrIj5ieTwvc3Bhbj4gJyArIGMuYWN0b3IgKyAnPGJyPicgKwogICAgICAgICc8c3BhbiBjbGFzcz0iayI+a2luZDwvc3Bhbj4gJyArIGMua2luZCArICcgwrcgPHNwYW4gY2xhc3M9ImsiPmhvcml6b248L3NwYW4+ICcgKyBjLmhvcml6b24KICAgICAgOiAnPGI+JyArIGMucC5zaG9ydCArICc8L2I+PGJyPicgKwogICAgICAgICc8c3BhbiBjbGFzcz0iayI+JyArIFNUQVRFW2MucC5zdF0gKyAnIMK3ICcgKyBjLnAuZG9uZSArICcvJyArIGMucC50b3RhbCArICcgwrcgYm9ybiAnICsgZGF5RGF0ZShjLnAuYikgKyAnPC9zcGFuPjxicj4nICsKICAgICAgICAnPHNwYW4gY2xhc3M9ImsiPicgKyAoYy5raW5kID09PSAnZ2F0ZScgPyBjLmtleSA6ICd1bnRyYWNlZCBkZW5zaXR5IOKAlCBvbmUgcXVlcnlfZmFjdHMgY2FsbCBhd2F5JykgKyAnPC9zcGFuPicpOwogIH0gZWxzZSBpZiAoaG92ZXJTZWMpIHsKICAgIGNvbnN0IHAgPSBob3ZlclNlYzsKICAgIGNvbnN0IG5EZXBJbiA9IERFUF9FREdFUy5maWx0ZXIoZWQgPT4gZWQuYiA9PT0gcCkubGVuZ3RoOwogICAgc2hvd1RpcChteEFicywgbXlBYnMsCiAgICAgICc8Yj4nICsgcC5zaG9ydCArICc8L2I+PGJyPicgKwogICAgICAnPHNwYW4gY2xhc3M9ImsiPicgKyBTVEFURVtwLnN0XSArICcgwrcgJyArIHAuZG9uZSArICcvJyArIHAudG90YWwgKyAnPC9zcGFuPjxicj4nICsKICAgICAgJzxzcGFuIGNsYXNzPSJrIj5ib3JuPC9zcGFuPiAnICsgZGF5RGF0ZShwLmIpICsgJyA8c3BhbiBjbGFzcz0iayI+wrcgbGFzdDwvc3Bhbj4gJyArIGRheURhdGUocC5lKSArCiAgICAgIChwLm8gPyAnPGJyPjxzcGFuIGNsYXNzPSJrIj5vdXRwdXQ8L3NwYW4+ICcgKyAocC5vIC8gMTApLnRvRml4ZWQoMSkgKyAnTSB0b2snIDogJycpICsKICAgICAgKHAub2QubGVuZ3RoID8gJzxicj48c3BhbiBjbGFzcz0iayI+b3BlbiBkZWNpc2lvbnM8L3NwYW4+ICcgKyBwLm9kLmpvaW4oJyAnKSA6ICcnKSArCiAgICAgIChwLmRlcC5sZW5ndGggfHwgbkRlcEluCiAgICAgICAgPyAnPGJyPjxzcGFuIGNsYXNzPSJrIj5saW5lYWdlPC9zcGFuPiBkZXBlbmRzIG9uICcgKyBwLmRlcC5sZW5ndGggKyAnIMK3IGRlcGVuZGVkIG9uIGJ5ICcgKyBuRGVwSW4KICAgICAgICA6ICcnKSk7CiAgfSBlbHNlIGhpZGVUaXAoKTsKfSk7Ci8qIHdoaWNoIHBsYW4ncyBzZWN0b3IgaXMgdW5kZXIgdGhlIHBvaW50ZXIgKGFubnVsdXMgb25seSkgKi8KZnVuY3Rpb24gc2VjdG9yQXQoZSkgewogIGlmIChsZW5zICE9PSAnd29yaycpIHJldHVybiBudWxsOwogIGNvbnN0IHIgPSBjdi5nZXRCb3VuZGluZ0NsaWVudFJlY3QoKTsKICBjb25zdCBnID0gZ2VvbSgpOwogIGNvbnN0IHAgPSB0b0Rpc2MoZywgZS5jbGllbnRYIC0gci5sZWZ0LCBlLmNsaWVudFkgLSByLnRvcCk7CiAgY29uc3QgcHIgPSBNYXRoLmh5cG90KHAueCwgcC55KTsKICBpZiAocHIgPCBnLnIwICogMC44NSB8fCBwciA+IGcuUiArIDMwKSByZXR1cm4gbnVsbDsKICBjb25zdCBwYSA9IE1hdGguYXRhbjIocC55LCBwLngpOwogIGZvciAoY29uc3QgcGwgb2YgUExBTlMpIHsKICAgIGlmICghcGwubGF5IHx8IHBsLmxheS5hbHBoYSA8IDAuNCkgY29udGludWU7CiAgICBsZXQgZGEgPSBwYSAtIHBsLmxheS5hMDsKICAgIHdoaWxlIChkYSA8IDApIGRhICs9IFRBVTsKICAgIHdoaWxlIChkYSA+PSBUQVUpIGRhIC09IFRBVTsKICAgIGlmIChkYSA8PSBwbC5sYXkuYTEgLSBwbC5sYXkuYTApIHJldHVybiBwbDsKICB9CiAgcmV0dXJuIG51bGw7Cn0KY3YuYWRkRXZlbnRMaXN0ZW5lcigncG9pbnRlcmxlYXZlJywgKCkgPT4geyBob3ZlciA9IG51bGw7IGhvdmVyU2VjID0gbnVsbDsgaGlkZVRpcCgpOyB9KTsKCmZ1bmN0aW9uIGhpdFRlc3QoZSkgewogIGNvbnN0IHIgPSBjdi5nZXRCb3VuZGluZ0NsaWVudFJlY3QoKTsKICBjb25zdCBnID0gZ2VvbSgpOwogIGNvbnN0IHAgPSB0b0Rpc2MoZywgZS5jbGllbnRYIC0gci5sZWZ0LCBlLmNsaWVudFkgLSByLnRvcCk7CiAgY29uc3QgcHIgPSBNYXRoLmh5cG90KHAueCwgcC55KTsKICBjb25zdCBwYSA9IE1hdGguYXRhbjIocC55LCBwLngpOwogIC8qIGRhdGEgbGVuczogZ3JhcGggbm9kZXMgKi8KICBpZiAobGVucyA9PT0gJ2RhdGEnKSB7CiAgICBsZXQgYmVzdDIgPSBudWxsLCBiZDIgPSA5IC8gWjsKICAgIGZvciAoY29uc3QgbiBvZiBHTk9ERVMpIHsKICAgICAgaWYgKCFuLl9vbiB8fCBuLl94ID09PSB1bmRlZmluZWQpIGNvbnRpbnVlOwogICAgICBjb25zdCBkMiA9IE1hdGguaHlwb3Qobi5feCAtIHAueCwgbi5feSAtIHAueSk7CiAgICAgIGlmIChkMiA8IGJkMiArIG4uX2RyKSB7IGJkMiA9IGQyOyBiZXN0MiA9IG47IH0KICAgIH0KICAgIHJldHVybiBiZXN0MjsKICB9CiAgLyogc29sbzogZXZlbnQtbGVkZ2VyIHZlcnRpY2FsIGJhcnMgdGFrZSBwcmlvcml0eSAqLwogIGlmIChzb2xvKSB7CiAgICBmb3IgKGNvbnN0IGMgb2Ygc29sby5jZWxscykgewogICAgICBpZiAoYy5fYnggPT09IHVuZGVmaW5lZCB8fCBjLmRheSA+IFQpIGNvbnRpbnVlOwogICAgICBpZiAoTWF0aC5hYnMocC54IC0gYy5fYngpIDwgNiAvIFogJiYgcC55IDwgNSAvIFogJiYgcC55ID4gLShjLl9iaCArIDkgLyBaKSkgcmV0dXJuIGM7CiAgICB9CiAgfQogIGxldCBiZXN0ID0gbnVsbCwgYmQgPSAxMCAvIFo7CiAgZm9yIChjb25zdCBjIG9mIGNlbGxzKSB7CiAgICBpZiAoYy5feCA9PT0gdW5kZWZpbmVkIHx8IGMuZGF5ID4gVCB8fCAhYy5wLmxheSB8fCBjLnAubGF5LmFscGhhIDwgMC4zIHx8ICFwYXNzRmlsdGVyKGMpKSBjb250aW51ZTsKICAgIGNvbnN0IGQgPSBNYXRoLmh5cG90KGMuX3ggLSBwLngsIGMuX3kgLSBwLnkpOwogICAgaWYgKGQgPCBiZCArIGMuX2RyKSB7IGJkID0gZDsgYmVzdCA9IGM7IH0KICAgIGlmIChtb2RlID09PSAnYmFycycgJiYgIWJlc3QpIHsKICAgICAgLyogcmFkaWFsIGJhciBoaXQ6IHNhbWUgYW5nbGUgKHdpdGhpbiB+M3B4IGFyYyksIHJhZGl1cyB3aXRoaW4gW3IwLCBjZWxsUl0gKi8KICAgICAgbGV0IGRhID0gcGEgLSBjLl9hOwogICAgICB3aGlsZSAoZGEgPiBNYXRoLlBJKSBkYSAtPSBUQVU7CiAgICAgIHdoaWxlIChkYSA8IC1NYXRoLlBJKSBkYSArPSBUQVU7CiAgICAgIGlmIChNYXRoLmFicyhkYSkgKiBwciA8IDQgLyBaICYmIHByID4gZy5yMCAtIDIgJiYgcHIgPCBjLl9yICsgYy5fZHIpIGJlc3QgPSBjOwogICAgfQogIH0KICByZXR1cm4gYmVzdDsKfQpmdW5jdGlvbiBoYW5kbGVDbGljayhlKSB7CiAgaWYgKGxlbnMgPT09ICdkYXRhJykgeyAgICAgICAgICAgICAgICAgICAgICAgICAgIC8qIGdyYXBoOiB0b2dnbGUgMi1ob3AgbmVpZ2hib3VyaG9vZCAqLwogICAgY29uc3QgaGl0ID0gaGl0VGVzdChlKTsKICAgIGdTZWwgPSAoaGl0ICYmIGhpdC5pICE9PSB1bmRlZmluZWQpID8gKGdTZWwgPT09IGhpdC5pID8gbnVsbCA6IGhpdC5pKSA6IG51bGw7CiAgICByZXR1cm47CiAgfQogIGlmIChsZW5zID09PSAndG9rZW5zJykgeyAgICAgICAgICAgICAgICAgICAgICAgICAvKiBkYXkgYmFyIOKGkiB3aGljaCBwbGFucyB3ZXJlIGFjdGl2ZSAqLwogICAgY29uc3QgcjIgPSBjdi5nZXRCb3VuZGluZ0NsaWVudFJlY3QoKTsKICAgIGNvbnN0IGcyID0gZ2VvbSgpOwogICAgY29uc3QgcGQgPSB0b0Rpc2MoZzIsIGUuY2xpZW50WCAtIHIyLmxlZnQsIGUuY2xpZW50WSAtIHIyLnRvcCk7CiAgICBjb25zdCBwcjIgPSBNYXRoLmh5cG90KHBkLngsIHBkLnkpOwogICAgbGV0IHBhMiA9IE1hdGguYXRhbjIocGQueSwgcGQueCk7CiAgICB3aGlsZSAocGEyIDwgQkFTRSkgcGEyICs9IFRBVTsKICAgIGxldCBiaW4gPSBudWxsLCBiZDIgPSAwLjA1OwogICAgZm9yIChjb25zdCBiMiBvZiB0b2tCaW5zKSB7CiAgICAgIGxldCBiYSA9IGIyLmE7IHdoaWxlIChiYSA8IEJBU0UpIGJhICs9IFRBVTsKICAgICAgY29uc3QgZGEyID0gTWF0aC5hYnMocGEyIC0gYmEpOwogICAgICBpZiAoZGEyIDwgYmQyICYmIHByMiA+IGcyLnIwICogMC43ICYmIHByMiA8IGcyLlIgKyAxNCkgeyBiZDIgPSBkYTI7IGJpbiA9IGIyOyB9CiAgICB9CiAgICBpZiAoYmluICYmIHRva1NlbCAhPT0gYmluLmQpIHsgdG9rU2VsID0gYmluLmQ7IHJlbmRlclRva2VuRGF5UGFuZShiaW4pOyB9CiAgICBlbHNlIHsgdG9rU2VsID0gbnVsbDsgcGFuZS5jbGFzc0xpc3QucmVtb3ZlKCdvcGVuJyk7IH0KICAgIHJldHVybjsKICB9CiAgaWYgKGxlbnMgIT09ICd3b3JrJykgcmV0dXJuOyAgICAgICAgICAgICAgICAgICAgIC8qIG90aGVyIGxlbnMgdmlld3M6IGhvdmVyIG9ubHkgaW4gdGhpcyBtb2NrICovCiAgY29uc3QgciA9IGN2LmdldEJvdW5kaW5nQ2xpZW50UmVjdCgpOwogIGNvbnN0IGN4cCA9IGUuY2xpZW50WCAtIHIubGVmdCwgY3lwID0gZS5jbGllbnRZIC0gci50b3A7CiAgLyogMSDigJQgbGVkZ2VyIHJvd3M6IGZpbHRlciB0aGUgcmluZyB0byB0aGF0IHBsYW4gKi8KICBmb3IgKGNvbnN0IHJvdyBvZiBsZWRnZXJSb3dzKSB7CiAgICBpZiAoY3hwID49IHJvdy54ICYmIGN4cCA8PSByb3cueCArIHJvdy53ICYmIGN5cCA+PSByb3cueSAmJiBjeXAgPD0gcm93LnkgKyByb3cuaCkgewogICAgICBpZiAoc29sbyA9PT0gcm93LnApIHsgc2V0U2VsKG51bGwpOyBzb2xvID0gbnVsbDsgfQogICAgICBlbHNlIHsgc29sbyA9IHJvdy5wOyBzZXRTZWwoeyB0eXBlOiAncGxhbicsIHA6IHJvdy5wIH0pOyB9CiAgICAgIHJldHVybjsKICAgIH0KICB9CiAgLyogMiDigJQgbm9kZSAqLwogIGNvbnN0IGhpdCA9IGhpdFRlc3QoZSk7CiAgaWYgKGhpdCkgeyBzZXRTZWwoc2VsICYmIHNlbC5jID09PSBoaXQgPyBudWxsIDogeyB0eXBlOiAnY2VsbCcsIGM6IGhpdCB9KTsgcmV0dXJuOyB9CiAgLyogMyDigJQgc2VjdG9yOiBmb2N1cyB0aGUgcGxhbiBvbiBpdHMgb3duICgxMuKGkjkgKyBldmVudCBsZWRnZXIpICovCiAgY29uc3Qgc2VjID0gc2VjdG9yQXQoZSk7CiAgaWYgKHNlYykgewogICAgaWYgKHNvbG8gPT09IHNlYykgeyBzZXRTZWwobnVsbCk7IHNvbG8gPSBudWxsOyB9CiAgICBlbHNlIHsgc29sbyA9IHNlYzsgc2V0U2VsKHsgdHlwZTogJ3BsYW4nLCBwOiBzZWMgfSk7IH0KICAgIHJldHVybjsKICB9CiAgLyogMy41IOKAlCBjbGlja3MgaW5zaWRlIHRoZSBzb2xvIGV2ZW50LWxlZGdlciBxdWFkcmFudCBhcmUgbm90ICJiYWNrZ3JvdW5kIiAqLwogIGlmIChzb2xvKSB7CiAgICBjb25zdCBnMiA9IGdlb20oKTsKICAgIGNvbnN0IHBkID0gdG9EaXNjKGcyLCBjeHAsIGN5cCk7CiAgICBjb25zdCBwcjIgPSBNYXRoLmh5cG90KHBkLngsIHBkLnkpOwogICAgbGV0IHBhMiA9IE1hdGguYXRhbjIocGQueSwgcGQueCk7CiAgICBpZiAocGEyIDwgMCkgcGEyICs9IFRBVTsKICAgIGlmIChwcjIgPiBnMi5yMCAmJiBwcjIgPCBnMi5SICsgMTIgJiYgcGEyID4gTWF0aC5QSSAmJiBwYTIgPCBNYXRoLlBJICogMS41KSByZXR1cm47CiAgfQogIC8qIDQg4oCUIGJhY2tncm91bmQ6IGhpZGUgcGFuZSwgY2xlYXIgZmlsdGVyICovCiAgc2V0U2VsKG51bGwpOwogIHNvbG8gPSBudWxsOwp9CmZ1bmN0aW9uIHNldFNlbChzKSB7CiAgc2VsID0gczsKICBwaW5uZWQgPSBzICYmIHMudHlwZSA9PT0gJ2NlbGwnID8gcy5jIDogbnVsbDsKICByZW5kZXJQYW5lKCk7Cn0KY29uc3QgcGFuZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdwYW5lJyk7CmZ1bmN0aW9uIHJlbmRlclBhbmUoKSB7CiAgaWYgKCFzZWwpIHsgcGFuZS5jbGFzc0xpc3QucmVtb3ZlKCdvcGVuJyk7IHJldHVybjsgfQogIGNvbnN0IGVzYyA9IHQgPT4gU3RyaW5nKHQpLnJlcGxhY2UoLyYvZywgJyZhbXA7JykucmVwbGFjZSgvPC9nLCAnJmx0OycpOwogIC8qIHRva2VuIHVzYWdlIGFzIGEgaG9yaXpvbnRhbCBncmFkaWVudCBhcmVhIGNoYXJ0OiBjdW11bGF0aXZlIGV2ZW50IHdlaWdodAogICAgIG92ZXIgdGhlIHBsYW4ncyBsaWZlLCBldmVudCBkb3RzIGNvbG91cmVkIGJ5IGtpbmQgKi8KICBjb25zdCB0b2tDaGFydCA9IHAgPT4gewogICAgY29uc3QgZXZzID0gWy4uLnAuY2VsbHNdLnNvcnQoKGEsIGIpID0+IGEuZGF5IC0gYi5kYXkpOwogICAgaWYgKCFldnMubGVuZ3RoKSByZXR1cm4gJyc7CiAgICBjb25zdCBXMiA9IDI4OCwgSDIgPSA5MiwgcGFkVCA9IDEwLCBwYWRCID0gMjAsIHBhZFggPSAyOwogICAgY29uc3QgYiA9IHAuYiwgZSA9IE1hdGgubWF4KHAuZSwgYiArIDAuNSk7CiAgICBjb25zdCB0b3QgPSBldnMucmVkdWNlKChhLCBjKSA9PiBhICsgYy50b2tXLCAwKSB8fCAxOwogICAgY29uc3QgaHVlID0gc3RhdGVIdWUocCk7CiAgICBjb25zdCBYMiA9IGQgPT4gcGFkWCArIE1hdGgubWF4KDAsIE1hdGgubWluKDEsIChkIC0gYikgLyAoZSAtIGIpKSkgKiAoVzIgLSAyICogcGFkWCk7CiAgICBjb25zdCBZMiA9IGYgPT4gKEgyIC0gcGFkQikgLSBmICogKEgyIC0gcGFkQiAtIHBhZFQpOwogICAgbGV0IGN1bSA9IDA7CiAgICBjb25zdCBwdHMgPSBldnMubWFwKGMgPT4geyBjdW0gKz0gYy50b2tXOyByZXR1cm4geyB4OiBYMihjLmRheSksIHk6IFkyKGN1bSAvIHRvdCksIGMgfTsgfSk7CiAgICBjb25zdCBsaW5lID0gJ00nICsgcGFkWCArICcsJyArIFkyKDApICsgcHRzLm1hcChwdCA9PiAnTCcgKyBwdC54LnRvRml4ZWQoMSkgKyAnLCcgKyBwdC55LnRvRml4ZWQoMSkpLmpvaW4oJycpICsKICAgICAgICAgICAgICAgICAnTCcgKyAoVzIgLSBwYWRYKSArICcsJyArIHB0c1twdHMubGVuZ3RoIC0gMV0ueS50b0ZpeGVkKDEpOwogICAgY29uc3QgYXJlYSA9IGxpbmUgKyAnTCcgKyAoVzIgLSBwYWRYKSArICcsJyArIFkyKDApICsgJ1onOwogICAgY29uc3QgZ2lkID0gJ3RnJyArIHAuaTsKICAgIGNvbnN0IGRvdHMgPSBwdHMubWFwKHB0ID0+CiAgICAgICc8Y2lyY2xlIGN4PSInICsgcHQueC50b0ZpeGVkKDEpICsgJyIgY3k9IicgKyBwdC55LnRvRml4ZWQoMSkgKyAnIiByPSInICsgKHB0LmMua2luZCA9PT0gJ2dhdGUnID8gMyA6IDIuMikgKyAnIiBmaWxsPSInICsgKEtJTkRfSFVFW3B0LmMua2luZF0gfHwgJyM4Yjk2ZjInKSArICciLz4nKS5qb2luKCcnKTsKICAgIHJldHVybiAnPGRpdiBjbGFzcz0ic2VjdCI+VE9LRU4gVVNBR0UnICsgKHAubyA/ICcgwrcgJyArIChwLm8gLyAxMCkudG9GaXhlZCgxKSArICdNIG91dCcgOiAnJykgKyAnPC9kaXY+JyArCiAgICAgICc8c3ZnIHdpZHRoPSIxMDAlIiB2aWV3Qm94PSIwIDAgJyArIFcyICsgJyAnICsgSDIgKyAnIiBzdHlsZT0iZGlzcGxheTpibG9jazttYXJnaW4tdG9wOjZweCIgcm9sZT0iaW1nIiBhcmlhLWxhYmVsPSJDdW11bGF0aXZlIHRva2VuIHVzYWdlIG92ZXIgdGhlIHBsYW7igJlzIGxpZmUiPicgKwogICAgICAnPGRlZnM+PGxpbmVhckdyYWRpZW50IGlkPSInICsgZ2lkICsgJyIgeDE9IjAiIHkxPSIwIiB4Mj0iMCIgeTI9IjEiPicgKwogICAgICAnPHN0b3Agb2Zmc2V0PSIwIiBzdG9wLWNvbG9yPSInICsgaHVlICsgJyIgc3RvcC1vcGFjaXR5PSIuMzgiLz4nICsKICAgICAgJzxzdG9wIG9mZnNldD0iMSIgc3RvcC1jb2xvcj0iJyArIGh1ZSArICciIHN0b3Atb3BhY2l0eT0iMCIvPjwvbGluZWFyR3JhZGllbnQ+PC9kZWZzPicgKwogICAgICAnPHBhdGggZD0iJyArIGFyZWEgKyAnIiBmaWxsPSJ1cmwoIycgKyBnaWQgKyAnKSIvPicgKwogICAgICAnPHBhdGggZD0iJyArIGxpbmUgKyAnIiBmaWxsPSJub25lIiBzdHJva2U9IicgKyBodWUgKyAnIiBzdHJva2Utb3BhY2l0eT0iLjg1IiBzdHJva2Utd2lkdGg9IjEuNCIvPicgKwogICAgICBkb3RzICsKICAgICAgJzx0ZXh0IHg9IicgKyBwYWRYICsgJyIgeT0iJyArIChIMiAtIDUpICsgJyIgZmlsbD0icmdiYSgxMjYsMTMzLDE0OSwuOCkiIGZvbnQtc2l6ZT0iOSIgZm9udC1mYW1pbHk9IicgKyBNT05PLnJlcGxhY2UoLyIvZywgIiciKSArICciPicgKyBkYXlEYXRlKGIpICsgJzwvdGV4dD4nICsKICAgICAgJzx0ZXh0IHg9IicgKyAoVzIgLSBwYWRYKSArICciIHk9IicgKyAoSDIgLSA1KSArICciIHRleHQtYW5jaG9yPSJlbmQiIGZpbGw9InJnYmEoMTI2LDEzMywxNDksLjgpIiBmb250LXNpemU9IjkiIGZvbnQtZmFtaWx5PSInICsgTU9OTy5yZXBsYWNlKC8iL2csICInIikgKyAnIj4nICsgZGF5RGF0ZShwLmUpICsgJzwvdGV4dD4nICsKICAgICAgJzwvc3ZnPic7CiAgfTsKICBjb25zdCBwbGFuQmxvY2sgPSBwID0+IHsKICAgIGNvbnN0IGh1ZSA9IHN0YXRlSHVlKHApOwogICAgY29uc3QgbkNlbGxzID0gcC5jZWxscy5sZW5ndGg7CiAgICBjb25zdCBnYXRlcyA9IHAuY2VsbHMuZmlsdGVyKGMgPT4gYy5raW5kID09PSAnZ2F0ZScpLmxlbmd0aDsKICAgIHJldHVybiAnPGRpdiBjbGFzcz0ic2VjdCI+RVhFQ1BMQU48L2Rpdj4nICsKICAgICAgJzxoND4nICsgZXNjKHAuc2x1ZykgKyAnPC9oND4nICsKICAgICAgJzxkaXYgY2xhc3M9ImJhciI+PGkgc3R5bGU9IndpZHRoOicgKyBNYXRoLnJvdW5kKDEwMCAqIHAuZG9uZSAvIHAudG90YWwpICsgJyU7YmFja2dyb3VuZDonICsgaHVlICsgJyI+PC9pPjwvZGl2PicgKwogICAgICAnPGRpdiBjbGFzcz0icm93Ij48c3Bhbj5zdGF0ZTwvc3Bhbj48c3Bhbj4nICsgU1RBVEVbcC5zdF0gKyAnIMK3ICcgKyBwLmRvbmUgKyAnLycgKyBwLnRvdGFsICsgJzwvc3Bhbj48L2Rpdj4nICsKICAgICAgJzxkaXYgY2xhc3M9InJvdyI+PHNwYW4+Ym9ybjwvc3Bhbj48c3Bhbj4nICsgZGF5RGF0ZShwLmIpICsgJzwvc3Bhbj48L2Rpdj4nICsKICAgICAgJzxkaXYgY2xhc3M9InJvdyI+PHNwYW4+bGFzdCBhY3Rpdml0eTwvc3Bhbj48c3Bhbj4nICsgZGF5RGF0ZShwLmUpICsgJzwvc3Bhbj48L2Rpdj4nICsKICAgICAgKHAubyA/ICc8ZGl2IGNsYXNzPSJyb3ciPjxzcGFuPm91dHB1dCB0b2tlbnM8L3NwYW4+PHNwYW4+JyArIChwLm8gLyAxMCkudG9GaXhlZCgxKSArICdNPC9zcGFuPjwvZGl2PicgOiAnJykgKwogICAgICAnPGRpdiBjbGFzcz0icm93Ij48c3Bhbj5ub2Rlczwvc3Bhbj48c3Bhbj4nICsgbkNlbGxzICsgJyAoJyArIGdhdGVzICsgJyBnYXRlcyk8L3NwYW4+PC9kaXY+JyArCiAgICAgIChwLm9kLmxlbmd0aCA/ICc8ZGl2IGNsYXNzPSJyb3ciPjxzcGFuPm9wZW4gZGVjaXNpb25zPC9zcGFuPjxzcGFuPicgKyBwLm9kLm1hcChlc2MpLmpvaW4oJyDCtyAnKSArICc8L3NwYW4+PC9kaXY+JyA6ICcnKSArCiAgICAgIChwLmRlcC5sZW5ndGggPyAnPGRpdiBjbGFzcz0icm93Ij48c3Bhbj5kZXBlbmRzIG9uPC9zcGFuPjxzcGFuPicgKyBwLmRlcC5tYXAoZCA9PiBlc2MoZC5yZXBsYWNlKC8tMjAyNi1cZFxkLVxkXGQkLywgJycpKSkuam9pbignPGJyPicpICsgJzwvc3Bhbj48L2Rpdj4nIDogJycpICsKICAgICAgKHAuZXh0Lmxlbmd0aCA/ICc8ZGl2IGNsYXNzPSJyb3ciPjxzcGFuPmV4dGVuZGVkIGJ5PC9zcGFuPjxzcGFuPicgKyBwLmV4dC5tYXAoZCA9PiBlc2MoZC5yZXBsYWNlKC8tMjAyNi1cZFxkLVxkXGQkLywgJycpKSkuam9pbignPGJyPicpICsgJzwvc3Bhbj48L2Rpdj4nIDogJycpICsKICAgICAgdG9rQ2hhcnQocCkgKwogICAgICAocC50cmFjZWQKICAgICAgICA/ICc8ZGl2IGNsYXNzPSJzZWN0Ij5GQUNUUyAocmVhbCk8L2Rpdj48dWwgY2xhc3M9ImZhY3RzIj4nICsKICAgICAgICAgIFsuLi5wLmNlbGxzXS5zb3J0KChhLCBiKSA9PiBhLmRheSAtIGIuZGF5KS5tYXAoYyA9PgogICAgICAgICAgICAnPGxpJyArIChzZWwuYyA9PT0gYyA/ICcgY2xhc3M9InNlbCInIDogJycpICsgJz48Yj4nICsgZXNjKGMua2V5KSArICc8L2I+IMK3ICcgKyBkYXlEYXRlKGMuZGF5KSArCiAgICAgICAgICAgIChjLmFjdG9yID8gJyDCtyAnICsgZXNjKGMuYWN0b3IpIDogJycpICsgJzwvbGk+Jykuam9pbignJykgKyAnPC91bD4nCiAgICAgICAgOiAnPHAgY2xhc3M9Im5vdGUiPlVudHJhY2VkIHBsYW4g4oCUIG5vZGUgZGVuc2l0eSBpcyBtaWxlc3RvbmUtZGVyaXZlZC4gT25lIGNhbGwgbWFrZXMgaXQgcmVhbDo8YnI+PGNvZGU+cXVlcnlfZmFjdHMoZW50aXR5PSJleGVjcGxhbjonICsgZXNjKHAuc2x1ZykgKyAnIiwgdG9rZW5fYnVkZ2V0PTQwMDApPC9jb2RlPjwvcD4nKTsKICB9OwogIGlmIChzZWwudHlwZSA9PT0gJ2NlbGwnKSB7CiAgICBjb25zdCBjID0gc2VsLmMsIGh1ZSA9IEtJTkRfSFVFW2Mua2luZF0gfHwgJyM4Yjk2ZjInOwogICAgcGFuZS5pbm5lckhUTUwgPQogICAgICAnPGg0PicgKyBlc2MoYy5rZXkpICsgKGMudmVyc2lvbiA+IDEgPyAnIDxzcGFuIHN0eWxlPSJjb2xvcjp2YXIoLS1pbmszKSI+dicgKyBjLnZlcnNpb24gKyAnPC9zcGFuPicgOiAnJykgKyAnPC9oND4nICsKICAgICAgJzxzcGFuIGNsYXNzPSJraW5kY2hpcCI+PGkgc3R5bGU9ImJhY2tncm91bmQ6JyArIGh1ZSArICciPjwvaT4nICsgYy5raW5kICsgKGMucmVhbCA/ICcgwrcgcmVhbCBmYWN0JyA6ICcgwrcgaWxsdXN0cmF0aXZlJykgKyAnPC9zcGFuPicgKwogICAgICAoYy5yZWFsCiAgICAgICAgPyAnPGRpdiBjbGFzcz0icm93Ij48c3Bhbj5zdG9yZWQ8L3NwYW4+PHNwYW4+JyArIGRheURhdGUoYy5kYXkpICsgJzwvc3Bhbj48L2Rpdj4nICsKICAgICAgICAgICc8ZGl2IGNsYXNzPSJyb3ciPjxzcGFuPmFjdG9yPC9zcGFuPjxzcGFuPicgKyBlc2MoYy5hY3RvcikgKyAnPC9zcGFuPjwvZGl2PicgKwogICAgICAgICAgJzxkaXYgY2xhc3M9InJvdyI+PHNwYW4+aG9yaXpvbjwvc3Bhbj48c3Bhbj4nICsgYy5ob3Jpem9uICsgJzwvc3Bhbj48L2Rpdj4nICsKICAgICAgICAgICc8ZGl2IGNsYXNzPSJyb3ciPjxzcGFuPnRva2Vuczwvc3Bhbj48c3Bhbj4nICsgYy50b2tlbnMgKyAnPC9zcGFuPjwvZGl2PicgKwogICAgICAgICAgKGMudmVyc2lvbiA+IDEgPyAnPGRpdiBjbGFzcz0icm93Ij48c3Bhbj5zdXBlcnNlZGVzPC9zcGFuPjxzcGFuPnYnICsgKGMudmVyc2lvbiAtIDEpICsgJyBvZiBzYW1lIGtleTwvc3Bhbj48L2Rpdj4nIDogJycpCiAgICAgICAgOiAnPGRpdiBjbGFzcz0icm93Ij48c3Bhbj5kYXk8L3NwYW4+PHNwYW4+JyArIGRheURhdGUoYy5kYXkpICsgJzwvc3Bhbj48L2Rpdj4nKSArCiAgICAgIHBsYW5CbG9jayhjLnApOwogIH0gZWxzZSB7CiAgICBwYW5lLmlubmVySFRNTCA9IHBsYW5CbG9jayhzZWwucCkgKwogICAgICAoc29sbyA9PT0gc2VsLnAgPyAnPHAgY2xhc3M9Im5vdGUiPlJpbmcgZmlsdGVyZWQgdG8gdGhpcyBwbGFuIOKAlCBjbGljayB0aGUgYmFja2dyb3VuZCB0byBjbGVhci48L3A+JyA6ICcnKTsKICB9CiAgcGFuZS5jbGFzc0xpc3QuYWRkKCdvcGVuJyk7Cn0KYWRkRXZlbnRMaXN0ZW5lcigna2V5ZG93bicsIGUgPT4geyBpZiAoZS5rZXkgPT09ICdFc2NhcGUnKSB7IHNldFNlbChudWxsKTsgc29sbyA9IG51bGw7IHRva1NlbCA9IG51bGw7IH0gfSk7CgovKiB0aWxlczogcHJlc3MgdG8gc3dpdGNoIHRoZSBsZW5zICovCmRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJyN0aWxlcyAudGlsZScpLmZvckVhY2godDIgPT4gewogIHQyLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogICAgbGVucyA9IHQyLmRhdGFzZXQubGVuczsKICAgIGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJyN0aWxlcyAudGlsZScpLmZvckVhY2goeCA9PiB4LnNldEF0dHJpYnV0ZSgnYXJpYS1wcmVzc2VkJywgU3RyaW5nKHggPT09IHQyKSkpOwogICAgc2V0U2VsKG51bGwpOyBzb2xvID0gbnVsbDsgaG92ZXIgPSBudWxsOyBob3ZlclNlYyA9IG51bGw7IGdTZWwgPSBudWxsOyB0b2tTZWwgPSBudWxsOyBoaWRlVGlwKCk7CiAgICBzZXRMZWRnZXIoZmFsc2UpOyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8qIGxlbnMgc3dhcCBoaWRlcyB0aGUgY29tcGxldGVkIGxpc3QgKi8KICAgIGlmIChsZW5zID09PSAnZGF0YScpIHsKICAgICAgLyogYXV0by1maXQgdGhlIHdpbmRvdyB0byB0aGUgZGF0YSBleHRlbnQgc28gc291cmNlIGRhdGVzIHNwcmVhZCB0aGUgY2xvY2sgKi8KICAgICAgY29uc3QgbWluRCA9IE1hdGgubWluKC4uLkdOT0RFUy5tYXAobiA9PiBuLmQpKSAtIDAuNTsKICAgICAgaWYgKFMgPCBtaW5EIC0gMSkgeyByU3RhcnQudmFsdWUgPSBNYXRoLnJvdW5kKChtaW5EIC0gMTEpIC8gKE5PVyAtIDExKSAqIDEwMDApOyBzeW5jV2luZG93KCk7IH0KICAgIH0KICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0b2stdmlld3MnKS5zdHlsZS5kaXNwbGF5ID0gbGVucyA9PT0gJ3Rva2VucycgPyAnZmxleCcgOiAnbm9uZSc7CiAgfSk7Cn0pOwoKLyogdG9rZW5zOiBncmFkaWVudCBsaW5lIGNoYXJ0IG9mIHRoZSB3aG9sZSB3aW5kb3csIHNlbGVjdGVkIGRheSBtYXJrZWQgKi8KZnVuY3Rpb24gdG9rUGFuZUNoYXJ0KHNlbERheSkgewogIGNvbnN0IFcyID0gMjg4LCBIMiA9IDkyLCBwYWRUID0gMTAsIHBhZEIgPSAyMCwgcGFkWCA9IDI7CiAgY29uc3QgZDAgPSBNYXRoLmNlaWwoUyksIGQxID0gTWF0aC5mbG9vcihFKTsKICBjb25zdCBkYXlzID0gW107CiAgbGV0IG1TID0gMC4wMDEsIG1WID0gMC4wMDE7CiAgZm9yIChsZXQgZDMgPSBkMDsgZDMgPD0gZDE7IGQzKyspIHsKICAgIGNvbnN0IHNwID0gVE9LLnNwZW50W2QzXSB8fCAwLCBzdiA9IFRPSy5zYXZlZFtkM10gfHwgMDsKICAgIGRheXMucHVzaCh7IGQ6IGQzLCBzcCwgc3YgfSk7CiAgICBtUyA9IE1hdGgubWF4KG1TLCBzcCk7IG1WID0gTWF0aC5tYXgobVYsIHN2KTsKICB9CiAgaWYgKCFkYXlzLmxlbmd0aCkgcmV0dXJuICcnOwogIGNvbnN0IFgyID0gZDMgPT4gcGFkWCArICgoZDMgLSBkMCkgLyBNYXRoLm1heCgxLCBkMSAtIGQwKSkgKiAoVzIgLSAyICogcGFkWCk7CiAgY29uc3QgWVMgPSB2ID0+IChIMiAtIHBhZEIpIC0gKHYgLyBtUykgKiAoSDIgLSBwYWRCIC0gcGFkVCk7CiAgY29uc3QgWVYgPSB2ID0+IChIMiAtIHBhZEIpIC0gKHYgLyBtVikgKiAoSDIgLSBwYWRCIC0gcGFkVCk7CiAgY29uc3QgbGluZVMgPSBkYXlzLm1hcCgocjIsIGkyKSA9PiAoaTIgPyAnTCcgOiAnTScpICsgWDIocjIuZCkudG9GaXhlZCgxKSArICcsJyArIFlTKHIyLnNwKS50b0ZpeGVkKDEpKS5qb2luKCcnKTsKICBjb25zdCBhcmVhUyA9IGxpbmVTICsgJ0wnICsgWDIoZDEpLnRvRml4ZWQoMSkgKyAnLCcgKyAoSDIgLSBwYWRCKSArICdMJyArIFgyKGQwKS50b0ZpeGVkKDEpICsgJywnICsgKEgyIC0gcGFkQikgKyAnWic7CiAgY29uc3QgbGluZVYgPSBkYXlzLm1hcCgocjIsIGkyKSA9PiAoaTIgPyAnTCcgOiAnTScpICsgWDIocjIuZCkudG9GaXhlZCgxKSArICcsJyArIFlWKHIyLnN2KS50b0ZpeGVkKDEpKS5qb2luKCcnKTsKICBjb25zdCBzZWxYID0gWDIoc2VsRGF5KS50b0ZpeGVkKDEpOwogIGNvbnN0IHNlbFJvdyA9IGRheXMuZmluZChyMiA9PiByMi5kID09PSBzZWxEYXkpOwogIHJldHVybiAnPHN2ZyB3aWR0aD0iMTAwJSIgdmlld0JveD0iMCAwICcgKyBXMiArICcgJyArIEgyICsgJyIgc3R5bGU9ImRpc3BsYXk6YmxvY2s7bWFyZ2luOjEwcHggMCAycHgiIHJvbGU9ImltZyIgYXJpYS1sYWJlbD0iRGFpbHkgdG9rZW4gc3BlbmQgd2l0aCB0aGUgc2VsZWN0ZWQgZGF5IG1hcmtlZCI+JyArCiAgICAnPGRlZnM+PGxpbmVhckdyYWRpZW50IGlkPSJ0cCIgeDE9IjAiIHkxPSIwIiB4Mj0iMCIgeTI9IjEiPicgKwogICAgJzxzdG9wIG9mZnNldD0iMCIgc3RvcC1jb2xvcj0iI2E3OGJmYSIgc3RvcC1vcGFjaXR5PSIuNCIvPjxzdG9wIG9mZnNldD0iMSIgc3RvcC1jb2xvcj0iI2E3OGJmYSIgc3RvcC1vcGFjaXR5PSIwIi8+PC9saW5lYXJHcmFkaWVudD48L2RlZnM+JyArCiAgICAnPHBhdGggZD0iJyArIGFyZWFTICsgJyIgZmlsbD0idXJsKCN0cCkiLz4nICsKICAgICc8cGF0aCBkPSInICsgbGluZVMgKyAnIiBmaWxsPSJub25lIiBzdHJva2U9IiNhNzhiZmEiIHN0cm9rZS1vcGFjaXR5PSIuOSIgc3Ryb2tlLXdpZHRoPSIxLjQiLz4nICsKICAgICc8cGF0aCBkPSInICsgbGluZVYgKyAnIiBmaWxsPSJub25lIiBzdHJva2U9IiMzNGQzOTkiIHN0cm9rZS1vcGFjaXR5PSIuOCIgc3Ryb2tlLXdpZHRoPSIxLjEiLz4nICsKICAgICc8bGluZSB4MT0iJyArIHNlbFggKyAnIiB5MT0iJyArIHBhZFQgKyAnIiB4Mj0iJyArIHNlbFggKyAnIiB5Mj0iJyArIChIMiAtIHBhZEIpICsgJyIgc3Ryb2tlPSJyZ2JhKDIzOCwyNDAsMjQ2LC41KSIgc3Ryb2tlLWRhc2hhcnJheT0iMiAzIi8+JyArCiAgICAoc2VsUm93ID8gJzxjaXJjbGUgY3g9IicgKyBzZWxYICsgJyIgY3k9IicgKyBZUyhzZWxSb3cuc3ApLnRvRml4ZWQoMSkgKyAnIiByPSIzLjIiIGZpbGw9IiNhNzhiZmEiLz4nICsKICAgICAgICAgICAgICAnPGNpcmNsZSBjeD0iJyArIHNlbFggKyAnIiBjeT0iJyArIFlWKHNlbFJvdy5zdikudG9GaXhlZCgxKSArICciIHI9IjIuNCIgZmlsbD0iIzM0ZDM5OSIvPicgOiAnJykgKwogICAgJzx0ZXh0IHg9IicgKyBwYWRYICsgJyIgeT0iJyArIChIMiAtIDUpICsgJyIgZmlsbD0icmdiYSgxMjYsMTMzLDE0OSwuOCkiIGZvbnQtc2l6ZT0iOSIgZm9udC1mYW1pbHk9Im1vbm9zcGFjZSI+JyArIGRheURhdGUoZDApICsgJzwvdGV4dD4nICsKICAgICc8dGV4dCB4PSInICsgKFcyIC0gcGFkWCkgKyAnIiB5PSInICsgKEgyIC0gNSkgKyAnIiB0ZXh0LWFuY2hvcj0iZW5kIiBmaWxsPSJyZ2JhKDEyNiwxMzMsMTQ5LC44KSIgZm9udC1zaXplPSI5IiBmb250LWZhbWlseT0ibW9ub3NwYWNlIj4nICsgZGF5RGF0ZShkMSkgKyAnPC90ZXh0PicgKwogICAgJzwvc3ZnPicgKwogICAgJzxwIGNsYXNzPSJub3RlIiBzdHlsZT0ibWFyZ2luLXRvcDowIj5wdXJwbGUgPSBzcGVudC9kYXkgKG1heCAnICsgbVMudG9GaXhlZCgxKSArICdNKSDCtyBncmVlbiA9IGVzdC4gc2F2ZWQvZGF5IChvd24gc2NhbGUsIG1heCAnICsgKG1WICogMTAwMCkudG9GaXhlZCgwKSArICdrKTwvcD4nOwp9CgovKiB0b2tlbnM6IGRheSBwYW5lIOKAlCB3aGljaCBleGVjcGxhbnMgd2VyZSBhY3RpdmUgb24gdGhlIGNsaWNrZWQgZGF5ICovCmZ1bmN0aW9uIHJlbmRlclRva2VuRGF5UGFuZShiaW4pIHsKICBjb25zdCBlc2MgPSB0MiA9PiBTdHJpbmcodDIpLnJlcGxhY2UoLyYvZywgJyZhbXA7JykucmVwbGFjZSgvPC9nLCAnJmx0OycpOwogIGNvbnN0IGQyID0gYmluLmQ7CiAgY29uc3QgYWN0ID0gUExBTlMKICAgIC5maWx0ZXIocCA9PiBwLmIgPD0gZDIgJiYgZDIgPD0gcC5lKQogICAgLm1hcChwID0+IHsKICAgICAgY29uc3QgZGF5Q2VsbHMgPSBwLmNlbGxzLmZpbHRlcihjID0+IE1hdGguZmxvb3IoYy5kYXkpID09PSBkMikubGVuZ3RoOwogICAgICBjb25zdCBzcCA9IChwLm8gJiYgcC5jZWxscy5sZW5ndGgpID8gKHAubyAvIDEwKSAvIHAuY2VsbHMubGVuZ3RoICogZGF5Q2VsbHMgOiAwOwogICAgICByZXR1cm4geyBwLCBkYXlDZWxscywgc3AgfTsKICAgIH0pCiAgICAuc29ydCgoeCwgeSkgPT4geS5zcCAtIHguc3AgfHwgeS5kYXlDZWxscyAtIHguZGF5Q2VsbHMpOwogIHBhbmUuaW5uZXJIVE1MID0KICAgICc8aDQ+JyArIGRheURhdGUoZDIpICsgJzwvaDQ+JyArCiAgICAnPHNwYW4gY2xhc3M9ImtpbmRjaGlwIj48aSBzdHlsZT0iYmFja2dyb3VuZDojZjVhNjIzIj48L2k+dG9rZW4gZGF5PC9zcGFuPicgKwogICAgJzxkaXYgY2xhc3M9InJvdyI+PHNwYW4+c3BlbnQ8L3NwYW4+PHNwYW4+JyArIGJpbi5zcC50b0ZpeGVkKDEpICsgJ00gZGF5IMK3ICcgKyBiaW4uY3MudG9GaXhlZCgxKSArICdNIGN1bTwvc3Bhbj48L2Rpdj4nICsKICAgICc8ZGl2IGNsYXNzPSJyb3ciPjxzcGFuPnNhdmVkIChlc3QuKTwvc3Bhbj48c3Bhbj4nICsgKGJpbi5zdiAqIDEwMDApLnRvRml4ZWQoMCkgKyAnayBkYXkgwrcgJyArIGJpbi5jdi50b0ZpeGVkKDIpICsgJ00gY3VtPC9zcGFuPjwvZGl2PicgKwogICAgdG9rUGFuZUNoYXJ0KGQyKSArCiAgICAnPGRpdiBjbGFzcz0ic2VjdCI+QUNUSVZFIEVYRUNQTEFOUyDCtyAnICsgYWN0Lmxlbmd0aCArICc8L2Rpdj4nICsKICAgIChhY3QubGVuZ3RoCiAgICAgID8gJzx1bCBjbGFzcz0iZmFjdHMiPicgKyBhY3Quc2xpY2UoMCwgMjIpLm1hcCh4MiA9PgogICAgICAgICAgJzxsaT48YiBzdHlsZT0iY29sb3I6JyArIHN0YXRlSHVlKHgyLnApICsgJyI+4pePPC9iPiA8Yj4nICsgZXNjKHgyLnAuc2hvcnQuc2xpY2UoMCwgMzApKSArICc8L2I+IMK3ICcgKwogICAgICAgICAgU1RBVEVbeDIucC5zdF0gKyAnICcgKyB4Mi5wLmRvbmUgKyAnLycgKyB4Mi5wLnRvdGFsICsKICAgICAgICAgICh4Mi5zcCA/ICcgwrcgficgKyB4Mi5zcC50b0ZpeGVkKDEpICsgJ00nIDogJycpICsKICAgICAgICAgICh4Mi5kYXlDZWxscyA/ICcgwrcgJyArIHgyLmRheUNlbGxzICsgJyBldmVudHMnIDogJycpICsgJzwvbGk+Jykuam9pbignJykgKwogICAgICAgIChhY3QubGVuZ3RoID4gMjIgPyAnPGxpPuKApiArJyArIChhY3QubGVuZ3RoIC0gMjIpICsgJyBtb3JlPC9saT4nIDogJycpICsgJzwvdWw+JwogICAgICA6ICc8cCBjbGFzcz0ibm90ZSI+bm8gcGxhbnMgd2l0aCBhY3Rpdml0eSBzcGFucyBjb3ZlcmluZyB0aGlzIGRheTwvcD4nKSArCiAgICAnPHAgY2xhc3M9Im5vdGUiPnNwZW5kIGF0dHJpYnV0aW9uOiBwbGFuIG91dHB1dC10b2tlbiB0b3RhbHMgZGlzdHJpYnV0ZWQgYWNyb3NzIHRoZWlyIGV2ZW50IGRheXMgKGVzdGltYXRlIHVudGlsIHBlci1kYXkgdG9rZW5fYnVybiBpcyB3aXJlZCk8L3A+JzsKICBwYW5lLmNsYXNzTGlzdC5hZGQoJ29wZW4nKTsKfQoKLyogdG9rZW5zIHN1Yi12aWV3cyAqLwpmdW5jdGlvbiBzZXRUb2tWaWV3KHYpIHsKICB0b2tWaWV3ID0gdjsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYi10b2stY3VtJykuc2V0QXR0cmlidXRlKCdhcmlhLXByZXNzZWQnLCBTdHJpbmcodiA9PT0gJ2N1bScpKTsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYi10b2stZGF5Jykuc2V0QXR0cmlidXRlKCdhcmlhLXByZXNzZWQnLCBTdHJpbmcodiA9PT0gJ2RheScpKTsKfQpkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYi10b2stY3VtJykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiBzZXRUb2tWaWV3KCdjdW0nKSk7CmRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdiLXRvay1kYXknKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHNldFRva1ZpZXcoJ2RheScpKTsKCi8qIGluaXQgKi8Kc3luY1dpbmRvdygpOwp9KSgpOwo8L3NjcmlwdD4K';

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
