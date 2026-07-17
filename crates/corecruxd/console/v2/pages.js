// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.
//
// Unified Shell Console v2 — page registry (ExecPlan unified-shell-console-2026-07-03, M1).
// A no-build, dependency-free module (UMD: window.CruxPages in the browser,
// module.exports under node for the static-analysis smoke). It carries all 26
// legacy CX pages ported into the v2 IA — each page keeps the legacy control DSL
// (t:'search'|'input'|'textarea'|'select'|'toggle'|'btn'|'info'|'exp'|'rpcout'|
// 'bar'|'theme'). Rendering lives in render.js; this file is pure data + pure
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

  // AX / Agent — the agent-side cockpit. MCP tools load live (/v1/mcp/tools,
  // allowlisted); activity / memory / snapshots already have v2 homes; graph
  // opens on the Pro 3D substrate; bulk / handoff / storybook / story / dossiers
  // have no daemon read endpoint (deferred, honest notes).
  function buildAgent(res) {
    var tools;
    if (!res.ok || !res.data) {
      tools = { h: 'MCP tools', sub: 'the agent tool surface · /v1/mcp/tools', wide: true, controls: [{ t: 'search', ph: 'Filter tools…' }].concat(degraded(res.status, 'MCP tools unavailable — GET /v1/mcp/tools')) };
    } else {
      var list = arr(res.data.tools || res.data.items || res.data);
      tools = { h: 'MCP tools', sub: list.length + ' tool' + (list.length === 1 ? '' : 's') + ' loaded at session bind · /v1/mcp/tools', wide: true,
        controls: [{ t: 'search', ph: 'Filter tools…' }].concat(list.length ? list.map(function (tl) {
          var name = tl.name || tl.tool || tl.id || 'tool';
          return { t: 'exp', label: name, sub: clip(tl.description || tl.summary || '', 90) || 'mcp tool', badge: tl.scope || 'tool',
            meta: (arr(tl.scopes).length ? arr(tl.scopes).join(' · ') : str(tl.scope)),
            controls: [info('description', clip(tl.description || tl.summary || '—', 200))] };
        }) : [info('none', 'no MCP tools reported')]) };
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
    return [tools, cockpit, deferred];
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
    'ax-agent': page('ax-agent', 'overwatch', 'Agent', 'agent-side cockpit — MCP tools, graph, and where each surface lives', { pro: true, load: { endpoint: '/v1/mcp/tools', build: buildAgent } })
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
    { id: 'sitemap', label: 'Site map', icon: 'map', key: '7', sub: "the 26-item rail, rearranged into 5 destinations + System" }
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

  return {
    PAGES: PAGES,
    DESTS: DESTS,
    LEGACY_IDS: LEGACY_IDS,
    PRO_PORTED_IDS: PRO_PORTED_IDS,
    LEGACY_PORT: LEGACY_PORT,
    MUTATING_ACTIONS: MUTATING_ACTIONS,
    CONTROL_DIFF: CONTROL_DIFF,
    JSX_PORT: JSX_PORT,
    CruxDemo: CruxDemo,
    // Exposed for tests / render composition.
    _helpers: { workStageOf: workStageOf, laneWeightControls: laneWeightControls, amrLaneToggles: amrLaneToggles }
  };
});
