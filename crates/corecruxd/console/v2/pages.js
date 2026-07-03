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
  else { root.CruxPages = api; }
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
    var version = get(s, ['daemon', 'build', 'version']);
    return [
      { h: 'Daemon at a glance', sub: 'live from /v1/console/summary', wide: true,
        tiles: [
          ['Node', str(get(s, ['daemon', 'node_id']))],
          ['Build', str(version)],
          ['Facts', fmtNum(get(s, ['stores', 'facts']))],
          ['Sessions', fmtNum(get(s, ['stores', 'sessions']))],
          ['Shards', fmtNum(get(s, ['routing', 'shard_count'])), 'map v' + str(get(s, ['routing', 'shard_map_version']))],
          ['Storage free', fmtPct(get(s, ['capacity', 'free_ratio'])), 'of ' + fmtBytes(get(s, ['capacity', 'total_bytes']))],
          ['MCP agents', fmtNum(get(s, ['daemon', 'mcp_agent_count'])), get(s, ['daemon', 'mcp_enabled']) ? 'enabled' : 'off'],
          ['Integrations', fmtNum(get(s, ['integrations', 'builtin_pack_count'])), get(s, ['integrations', 'enabled']) ? 'enabled' : 'off'],
          ['Auth mode', str(get(s, ['daemon', 'auth_mode']))],
          ['Dataplane', get(s, ['daemon', 'dataplane_enabled']) ? 'on' : 'off']
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
    var head = { h: 'AMR defaults — all tenants',
      sub: 'Adaptive Manifest Routing picks lanes per query; set the default policy once — tenants inherit unless pinned', wide: true,
      controls: [info('subscription', 'inactive — CoreCrux lanes activate with a subscription · lexical + verbatim stay free/local')]
        .concat(amrLaneToggles('amr_'))
        .concat([mbtn('Apply defaults to all tenants', { hint: 'resets per-tenant pins back to inherit' })]) };
    if (!res.ok || !res.data) {
      return [head, { h: 'Tenants', wide: true, controls: [{ t: 'search', ph: 'Filter tenants…' }].concat(degraded(res.status, 'Tenants unavailable — GET /v1/console/tenants')) }];
    }
    var ts = arr(res.data.tenants);
    var rows = [{ t: 'search', ph: 'Filter tenants…' },
      { t: 'toggle', k: 'hidesys', label: 'hide system tenants', v: true, desc: 'System tenants carry daemon internals — hidden by default.' }];
    ts.forEach(function (t) {
      var id = t.tenant_id || t.id; var sys = (t.category === 'system') || /^__/.test(String(id));
      rows.push(tenantExpRow(id, [t.category, t.source].filter(Boolean).join(' · ') || 'tenant', sys));
    });
    if (!ts.length) { rows.push(info('none', 'no tenants registered')); }
    return [head, { h: 'Tenants', sub: ts.length + ' tenant' + (ts.length === 1 ? '' : 's') + ' · click to expand lane policy', wide: true, controls: rows }];
  }

  function buildPassports(res) {
    var form = { h: 'New passport', sub: 'mint a passport and attach who owns it (POST /v1/passports)', wide: true,
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
    if (!res.ok || !res.data) { return [form, { h: 'Passports', wide: true, controls: [{ t: 'search', ph: 'Filter passports…' }].concat(degraded(res.status, 'Passports unavailable — GET /v1/passports')) }]; }
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
    return [form, { h: 'Passports', sub: ps.length + ' passport' + (ps.length === 1 ? '' : 's') + ' · loaded from /v1/passports', wide: true, controls: rows }];
  }

  function buildSessions(res) {
    if (!res.ok || !res.data) { return [{ h: 'Sessions', wide: true, controls: [{ t: 'search', ph: 'Filter sessions…' }].concat(degraded(res.status, 'Sessions unavailable — GET /v1/console/sessions')) }]; }
    var list = arr(res.data.sessions || res.data.items || res.data);
    var live = list.filter(function (s) { return !s.archived; });
    var arch = list.filter(function (s) { return s.archived; });
    var row = function (s) {
      return { t: 'exp', label: s.session_id || s.id || s.label || 'session', sub: [s.execplan_slug, s.passport_id, s.last_active || s.updated_at].filter(Boolean).join(' · '), badge: s.archived ? 'archived' : (s.status || 'session'),
        controls: [['passport', s.passport_id], ['execplan', s.execplan_slug], ['tenant', s.tenant_id], ['turns', s.turn_count], ['updated', s.updated_at]]
          .filter(function (kv) { return kv[1] != null && kv[1] !== ''; }).map(function (kv) { return info(kv[0], String(kv[1])); }) };
    };
    return [
      { h: 'Active & idle', sub: live.length + ' session' + (live.length === 1 ? '' : 's') + ' · /v1/console/sessions', wide: true,
        controls: [{ t: 'search', ph: 'Filter sessions…' }].concat(live.length ? live.map(row) : [info('none', 'no live sessions')]) },
      { h: 'Archived', sub: arch.length + ' archived', wide: true, controls: arch.length ? arch.map(row) : [info('—', 'no archived sessions')] }
    ];
  }

  function buildWork(res) {
    var head = { h: 'ExecPlans', sub: 'list view — same data as the kanban · /v1/work?source=all', wide: true, controls: [{ t: 'search', ph: 'Filter plans…' }] };
    if (!res.ok || !res.data) { return [head, { h: 'Work', wide: true, controls: degraded(res.status, 'Work board unavailable — GET /v1/work?source=all') }]; }
    var items = arr(res.data.work || res.data.items);
    var mk = function (w) {
      return { t: 'exp', label: w.title || w.id, sub: (w.milestones_total ? ('M ' + (w.milestones_done || 0) + '/' + w.milestones_total) : '') || w.current_milestone || w.plan_path || '', badge: workStageOf(w).replace('_', ' '),
        controls: [['state', w.state], ['risk', w.risk_class], ['plan', w.plan_path], ['milestone', w.current_milestone], ['owner', w.assignee_passport], ['pr', w.linked_pr]]
          .filter(function (kv) { return kv[1] != null && kv[1] !== ''; }).map(function (kv) { return info(kv[0], String(kv[1])); })
          .concat([rbtn('Open in kanban')]) };
    };
    return [head].concat(WORK_STAGES.map(function (st) {
      var rows = items.filter(function (w) { return workStageOf(w) === st[0]; }).map(mk);
      return { h: st[1], wide: true, controls: rows.length ? rows : [info('—', 'none')] };
    }));
  }

  function buildGates(res) {
    if (!res.ok || !res.data) { return [{ h: 'Awaiting approval', wide: true, controls: [{ t: 'search', ph: 'Filter pending gates…' }].concat(degraded(res.status, 'Gates unavailable — GET /v1/work/gate/pending')) }]; }
    var pend = arr(res.data.pending).filter(function (p) { return (p.status || 'pending') === 'pending'; });
    var rows = [{ t: 'search', ph: 'Filter pending gates…' }].concat(pend.slice(0, 20).map(function (p) {
      return { t: 'exp', label: p.work_id, sub: (p.requested_action || 'update_state') + (p.target_state ? ' → ' + p.target_state : '') + ' · requested by ' + (p.requested_by_passport || '?'), badge: (p.risk_class || 'gated').toUpperCase(),
        desc: 'Approval is passport-attributed (Art. 14); one approval never extends to other actions.',
        controls: [info('action id', p.action_id), info('requested', p.requested_at || '—'),
          mbtn('Approve ' + p.action_id, { hint: 'records approving passport + timestamp' }),
          mbtn('Reject ' + p.action_id)] };
    }));
    if (!pend.length) { rows.push(info('none pending', 'gated transitions appear here when an agent requests a high-risk state change')); }
    rows.push(mbtn('Withhold all', { hint: 'keeps gates pending' }));
    return [{ h: 'Awaiting approval', sub: '/v1/work/gate/pending · ' + pend.length + ' pending', wide: true, controls: rows }];
  }

  function buildReview(res) {
    var head = [{ t: 'search', ph: 'Filter candidates…' }];
    var candSec;
    if (!res.ok || !res.data) {
      candSec = { h: 'Contradictions', wide: true, controls: head.concat(degraded(res.status, 'Contradictions unavailable — GET /v1/console/review/contradictions')) };
    } else {
      var cands = arr(res.data.candidates);
      var rows = head.concat([info('candidates', String(res.data.count || cands.length))]).concat(cands.length
        ? cands.map(function (c, i) {
          return { t: 'exp', label: (c.entity || 'entity') + ' · ' + (c.key || 'key'), sub: (c.reason || 'candidate') + ' · ' + (c.polarity_a || '?') + ' vs ' + (c.polarity_b || '?'), badge: 'candidate ' + (i + 1),
            controls: [info('fact ids', arr(c.fact_ids).join(', ') || '—'), info('values', arr(c.values).map(function (v) { return clip(v, 80); }).join(' | ') || '—')] };
        })
        : [info('none', 'no active opposite-polarity fact pairs')]);
      candSec = { h: 'Contradictions', sub: 'read-only candidates · ' + (res.data.count || 0) + ' found', wide: true, controls: rows };
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
    return [candSec, consSec];
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
    return [
      { h: 'Access posture', sub: 'who may call :14800',
        controls: [
          { t: 'select', k: 'auth_mode', label: 'auth mode', options: arr(a.supported_modes).length ? a.supported_modes.slice() : ['local_only', 'open', 'token', 'jwt_hs256'], v: a.chosen_mode || a.running_mode || 'local_only', mut: true },
          { t: 'toggle', k: 'require_bind', label: 'require passport binding', v: true, mut: true },
          info('node id', str(get(s, ['node_id']) || get(s, ['daemon', 'node_id'])))
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

  function buildCost(res) {
    var sel = { h: 'Session', sub: 'measured from the transcript message.usage (not an estimate)', wide: true, controls: [{ t: 'select', k: 'sess', label: 'session', options: ['latest'], v: 'latest' }] };
    if (!res.ok || !res.data) {
      sel.controls.push(info('status', 'cost lens off or unreachable — set CORECRUXD_FEATURE_COST_LENS=1'));
      return [sel, { h: 'Headline', wide: true, controls: [info('no data', 'run:  corecruxctl session cost --post')] }];
    }
    var d = res.data;
    if (!d.has_report) {
      sel.controls.push(info('status', arr(d.sessions).length ? 'pick a session above' : 'no reports posted yet'));
      return [sel, { h: 'Headline', wide: true, controls: [info('get started', 'run:  corecruxctl session cost --post   (then refresh)')] }];
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
    return [sel, head, where, levers];
  }

  // =======================================================================
  //  Static pages — sections ported directly from the legacy PAGES DSL.
  // =======================================================================

  var STATIC = {
    'cx-activity': [
      { h: 'Live activity', sub: 'the rolling activity log lives on a dedicated, streaming surface', wide: true,
        controls: [
          info('stream', 'GET /v1/events/stream?types=activity.appended'),
          info('note', 'the full receipt-cross-walked activity log is a dedicated page'),
          link('Open the activity log', '/console/activity', { hint: 'streams both lanes with ✓verify badges' })
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
    'cx-workbench': [
      { h: 'Workbench', sub: 'operator tooling over /v1/workbench/* — the full deep-machinery surface stays on the Pro console', wide: true,
        controls: [
          info('scope', 'brief · context-pack · impact-preflight · policy-simulation · route-probe · query lanes · entities'),
          info('note', 'the workbench is operator deep machinery; it opens on the Pro console'),
          link('Open the Pro console', '/console/legacy', { hint: 'opens the full legacy workbench' })
        ] },
      { h: '3D substrate', sub: 'the graph/topology view renders on the Pro 3D canvas', wide: true,
        controls: [
          info('view', 'entity graph · shard topology · lane overlay'),
          link('Open the 3D substrate', '/console-3d/index.html?embed=1', { hint: 'opens the Pro 3D substrate view' })
        ] }
    ],
    'cx-projects': [
      { h: 'Projects', sub: 'a project pairs repos to track + search, a planning repo for ExecPlans, passports and working tenants', wide: true,
        controls: [
          { t: 'search', ph: 'Filter projects…' },
          { t: 'exp', label: 'CueCrux', sub: 'workspace · 12 repos · 3 sessions', badge: 'active',
            controls: [
              { t: 'select', k: 'pr_planrepo', label: 'planning repo', options: ['PlanCrux', 'Crux', 'AuditCrux', 'CruxEngine', '(daemon-native)'], v: 'PlanCrux', mut: true },
              { t: 'toggle', k: 'pr_track_crux', label: 'Crux · tracked', v: true, mut: true },
              { t: 'input', k: 'pr_tenants', label: 'working tenants', v: 'default, lme-s', mono: true, mut: true },
              mbtn('Save cuecrux', { hint: 'PATCH /v1/projects/cuecrux — kept locally until the daemon grows an update route' })
            ] }
        ] },
      { h: 'Add repos · GitHub', sub: 'activates when the GitHub integration is connected', wide: true,
        controls: [
          info('github', 'not connected — connect under Integrations to add repos'),
          { t: 'select', k: 'gh_addrepo', label: 'repo', options: ['— connect GitHub first —'], v: '— connect GitHub first —', mut: true },
          mbtn('Add repo', { hint: 'POST /v1/integrations/github/repos/{owner}/{repo}/select' }),
          mbtn('Set as planning repo', { hint: 'designates where ExecPlans live' })
        ] },
      { h: 'New project', wide: true,
        controls: [
          { t: 'input', k: 'proj_name', label: 'name', ph: 'My project', mut: true },
          { t: 'input', k: 'proj_id', label: 'id', ph: 'proj-slug', mono: true, mut: true },
          { t: 'select', k: 'proj_storage', label: 'execplan storage', options: ['planning repo (recommended)', 'daemon-native', 'hybrid — repo files + daemon kanban'], v: 'planning repo (recommended)', mut: true },
          mbtn('Create project')
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
    'cx-overview': page('cx-overview', 'overwatch', 'Overview', 'daemon posture, readiness, and capacity at a glance', { load: { endpoint: '/v1/console/summary', build: buildOverview } }),
    'cx-activity': page('cx-activity', 'overwatch', 'Activity', 'all sessions · live rolling log'),
    'cx-coord': page('cx-coord', 'overwatch', 'Live board', 'who is working right now · /v1/coord/active', { load: { endpoint: '/v1/coord/active', build: buildCoord } }),
    'cx-orchestrators': page('cx-orchestrators', 'overwatch', 'Orchestrators', 'group plans for a session · /v1/orchestrators', { load: { endpoint: '/v1/orchestrators', build: buildOrchestrators } }),
    'cx-punchcards': page('cx-punchcards', 'overwatch', 'Punchcards', 'advisory path leases grouped by session · /v1/punchcards', { load: { endpoint: '/v1/punchcards', build: buildPunchcards } }),
    // ---- Work ------------------------------------------------------------
    'cx-work': page('cx-work', 'work', 'ExecPlans', 'read-time projection over .agent/execplans/*.md · /v1/work', { load: { endpoint: '/v1/work?source=all', build: buildWork } }),
    'cx-projects': page('cx-projects', 'work', 'Projects', 'repos to track + search, a planning repo, passports and working tenants'),
    'cx-sessions': page('cx-sessions', 'work', 'Sessions', 'saved session snapshots for resume + audit · /v1/console/sessions', { load: { endpoint: '/v1/console/sessions', build: buildSessions } }),
    // ---- Memory ----------------------------------------------------------
    'cx-facts': page('cx-facts', 'memory', 'Facts', 'the durable record — grouped by entity prefix', { load: { endpoint: '/v1/console/facts?top_k=100', build: buildFacts } }),
    'cx-memory': page('cx-memory', 'memory', 'Memory', 'recent facts per tenant — system tenants hidden by default', { load: { endpoint: '/v1/console/facts?top_k=50', build: buildMemory } }),
    'cx-tenants': page('cx-tenants', 'memory', 'Tenants', 'memory stores · AMR lane routing', { load: { endpoint: '/v1/console/tenants', build: buildTenants } }),
    'cx-documents': page('cx-documents', 'memory', 'Documents', 'what the daemon has read, per tenant — and how to feed it more'),
    'cx-review': page('cx-review', 'memory', 'Review', 'contradiction candidates · guarded fact consolidation', { load: { endpoint: '/v1/console/review/contradictions?limit=50', build: buildReview } }),
    'cx-lane-weights': page('cx-lane-weights', 'memory', 'Lane weights', 'CoreCrux RRF overlay · same-origin console proxy', { operatorOnly: true, load: { endpoint: '/v1/console/corecrux/lane-weights', build: buildLaneWeights } }),
    // ---- Trust -----------------------------------------------------------
    'cx-receipts': page('cx-receipts', 'trust', 'Receipts', 'CROWN · verify Ed25519 proofs offline with the key'),
    'cx-gates': page('cx-gates', 'trust', 'Gates', 'human approvals — destructive / high-risk transitions wait here (Art. 14)', { load: { endpoint: '/v1/work/gate/pending', build: buildGates } }),
    'cx-passport': page('cx-passport', 'trust', 'Passport', 'agent + people identities · create and view passports', { load: { endpoint: '/v1/passports', build: buildPassports } }),
    'cx-identity': page('cx-identity', 'trust', 'Identity', 'candidate links — inference proposes, consent disposes', { load: { endpoint: '/v1/identity/candidates', build: buildIdentity } }),
    'cx-mediation': page('cx-mediation', 'trust', 'Mediation', 'the gateway plane — identity, capability ladder, foresight'),
    // ---- Meters ----------------------------------------------------------
    'cx-cost': page('cx-cost', 'meters', 'Token burn', 'ground-truth cost lens — what each session cost + how to cut it', { load: { endpoint: '/v1/cost/report?tenant_id=default&token_budget=4000', build: buildCost } }),
    'cx-usage': page('cx-usage', 'meters', 'Token usage', 'aggregate call volume and spend · /v1/observations/aggregate'),
    // ---- System ----------------------------------------------------------
    'cx-settings': page('cx-settings', 'system', 'Settings', 'daemon configuration and console preferences', { load: { endpoint: '/v1/console/settings', build: buildSettings } }),
    'cx-integrations': page('cx-integrations', 'system', 'Integrations', 'installed packs and their grants', { load: { endpoint: '/v1/console/integrations', build: buildIntegrations } }),
    'cx-extensions': page('cx-extensions', 'system', 'Extensions', 'signed third-party manifests · per-passport grants', { load: { endpoint: '/v1/extensions', build: buildExtensions } }),
    'cx-workbench': page('cx-workbench', 'system', 'Workbench', 'operator tooling — opens the Pro console'),
    'cx-raw': page('cx-raw', 'system', 'Raw · JSON-RPC', '/mcp on :14801 · scopes header attaches automatically', { operatorOnly: true })
  };

  // ---- Destinations (rail order + pill grouping) ------------------------
  var DESTS = [
    { id: 'overwatch', label: 'Overwatch', icon: 'overwatch', key: '1', sub: 'Needs-you queue, fleet, and live activity.' },
    { id: 'work', label: 'Work', icon: 'work', key: '2', sub: 'ExecPlans, projects, and sessions.' },
    { id: 'memory', label: 'Memory', icon: 'memory', key: '3', sub: 'Facts, tenants, documents, and retrieval tuning.' },
    { id: 'trust', label: 'Trust', icon: 'trust', key: '4', sub: 'Receipts, gates, identity, and posture.' },
    { id: 'meters', label: 'Meters', icon: 'meters', key: '5', sub: 'Cost and usage.' },
    { id: 'system', label: 'System', icon: 'settings', key: '6', sub: 'Settings, integrations, and developer tools.' }
  ];

  // ---- Legacy id inventory (the 26 CX pages this plan must keep reachable)
  var LEGACY_IDS = [
    'cx-overview', 'cx-activity', 'cx-cost', 'cx-projects', 'cx-work', 'cx-usage', 'cx-documents', 'cx-gates',
    'cx-review', 'cx-coord', 'cx-sessions', 'cx-orchestrators', 'cx-punchcards', 'cx-passport', 'cx-identity',
    'cx-receipts', 'cx-mediation', 'cx-workbench', 'cx-integrations', 'cx-extensions', 'cx-facts', 'cx-memory',
    'cx-tenants', 'cx-lane-weights', 'cx-settings', 'cx-raw'
  ];

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
    'Create project',                  // cx-projects
    'Save cuecrux',                    // cx-projects
    'Add repo',                        // cx-projects
    'Set as planning repo'             // cx-projects
  ];

  return {
    PAGES: PAGES,
    DESTS: DESTS,
    LEGACY_IDS: LEGACY_IDS,
    MUTATING_ACTIONS: MUTATING_ACTIONS,
    // Exposed for tests / render composition.
    _helpers: { workStageOf: workStageOf, laneWeightControls: laneWeightControls, amrLaneToggles: amrLaneToggles }
  };
});
