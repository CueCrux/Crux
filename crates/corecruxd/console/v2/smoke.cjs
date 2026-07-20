// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.
//
// Unified Shell Console v2 — static-analysis smoke (ExecPlan
// unified-shell-console-2026-07-03, M1). Zero dependencies; node only. Run:
//   node crates/corecruxd/console/v2/smoke.cjs
//
// Checks (all must pass; exit non-zero on any failure):
//   1. pages.js carries all 26 legacy CX ids, each with a valid destination.
//      A page tagged pill:false (e.g. cx-overview) is folded out of its
//      destination's pill row but stays reachable — its content is rendered by
//      the destination's landing (render.js references its id), so it still
//      counts toward the 26/26 reachability.
//   2. every control type used in pages.js has a renderer branch in render.js.
//   3. the three theme CSS blocks in shell.html clear the WCAG contrast floor
//      (ink/ink2 >= 4.5:1, ink3 >= 4.0:1, over bg AND over surface).
//   4. every MUTATING_ACTIONS entry maps to a control tagged mut:true, and
//      render.js routes mutating controls through the operator posture gate.
//   5. no v2 file loads an external http(s) dependency.
//   6. reads go only through the generated client (no direct fetch in
//      pages/render/shell; api.js is the sole network layer).
//   7. (M3) CruxApiGated is EXACTLY the curated (method,path) mutation set and
//      is referenced only inside render.js operatorGatedCall (isOperator-guarded).
//   8. (M3) derivePosture() is a pure function with the documented truth table.
//   9. (M4) no shipped file addresses the Engine directly; engine GETs allowlisted.
//  10. (M5) manifest.webmanifest parses as JSON with the installability fields.
//  11. (M5) sw.js precache == the exact app-shell set; /v1/* never cached; SW_REV
//      matches shell.html (bump-together).
//  12. (M5) phone tier: bottom tab bar (4 tabs) + safe-area-inset + ≥44px targets.
//  13. (round 2) demo mode: CruxDemo fixtures are reachable ONLY behind the demo
//      flag (render.js reads them solely via the demoOn()-guarded demoData());
//      the DEMO DATA chip + ?demo activation live in the shell.
//  14. (round 2) exactly two button families console-wide (.btn-primary +
//      .btn-quiet); the retired ow-btn/ctl-btn classes are gone.
//  15. (round 2) collapsible rail: railToggle + <html data-rail> + persisted
//      crux.console.rail + aria-expanded, desktop-guarded (min-width:721px).
//  16. (round 2) status pill drops the node id; topbar chips carry auth /
//      dataplane / build; the node origin+id+build move to System › Node.
//  17. (round 2) charts: an areaChart helper + a Day/Week/Month range switch
//      (aria-pressed, no legend), used on cx-cost + cx-usage.
//  18. (round 2) pro-board strips: work rows + gate cards share a 3px
//      state-keyed left strip.
//  23. (M8) presentation mode system (Standard | Professional + reserved
//      Documents): registry, persisted, pre-paint, segmented control (aria-
//      pressed, left of chips), and STATIC posture-independence (no posture fn
//      branches on mode; applyMode touches no posture).
//  24. (M8) legacy port-checklist integrity: the LEGACY_PORT manifest covers the
//      EXACT known legacy inventory (5 scopes + 4 renderDash cards) with a valid
//      disposition each (home:/ported-pro:/deferred:) — nothing dropped.
//  34. (M13a) safe control parity: the 17 enumerated write controls + the 5
//      audit-flagged controls (all grounded as still-side-effecting) stay
//      operator-gated + disabled; 0 live writes added; grounding documented.
//  35. (M13a) native workbench port + CONTROL_DIFF coverage: the manifest covers
//      every legacy CX page; cx-workbench loads /v1/workbench/contract and renders
//      its GET read tools via a GET-only self-loader; every wired op is a GET.
//  41. (desktop mission control M2) every mapped control names a declared runtime
//      capability and route; unavailable controls render disabled with an
//      accessible, machine-readable reason without bypassing the write choke.

'use strict';

const fs = require('fs');
const path = require('path');

const DIR = __dirname;
const pages = require('./pages.js');
const render = require('./render.js');
const shellHtml = fs.readFileSync(path.join(DIR, 'shell.html'), 'utf8');
const pagesSrc = fs.readFileSync(path.join(DIR, 'pages.js'), 'utf8');
const renderSrc = fs.readFileSync(path.join(DIR, 'render.js'), 'utf8');

const failures = [];
const notes = [];
// Promises for checks that must drive an async renderer (M4a renderPlanTree);
// the report awaits these so their assertions land before the exit code.
const asyncChecks = [];
function check(ok, msg) { if (!ok) { failures.push(msg); } }

// Shared jsdom-free mock DOM for the renderer-driving checks (plan tree, session
// detail, plan-hash chip). `collect(node, out)` returns element descendants; seed
// with `[node]` to include the root. `classesOf`/`findByClass` are thin wrappers.
function newMockDom() {
  function mkNode(tag) {
    const node = {
      tagName: String(tag || 'div').toUpperCase(), nodeType: 1, childNodes: [], _attrs: {}, className: '',
      setAttribute: function (k, v) { this._attrs[k] = String(v); if (k === 'class') { this.className = String(v); } },
      getAttribute: function (k) { return Object.prototype.hasOwnProperty.call(this._attrs, k) ? this._attrs[k] : null; },
      appendChild: function (c) { this.childNodes.push(c); c.parentNode = this; return c; },
      addEventListener: function () {}
    };
    Object.defineProperty(node, 'textContent', {
      get: function () { let t = this._text || ''; (this.childNodes || []).forEach(function (c) { t += (c.textContent || ''); }); return t; },
      set: function (v) { this._text = String(v); this.childNodes.length = 0; }
    });
    return node;
  }
  const doc = { createElement: mkNode, createTextNode: function (v) { return { nodeType: 3, textContent: String(v), childNodes: [] }; } };
  function collect(node, out) {
    out = out || [];
    (node.childNodes || []).forEach(function (c) { if (c && c.nodeType === 1) { out.push(c); collect(c, out); } });
    return out;
  }
  function classesOf(node) { return collect(node, [node]).map(function (n) { return n.className || ''; }); }
  function findByClass(node, cls) { return collect(node, [node]).filter(function (n) { return new RegExp('\\b' + cls + '\\b').test(n.className || ''); }); }
  return { mkNode: mkNode, doc: doc, collect: collect, classesOf: classesOf, findByClass: findByClass };
}

// Extract a brace-matched `function <name>(...) { ... }` span from `src`.
// (operatorGatedCall contains no string-literal braces, so a plain depth
// counter is sufficient for the containment audit in check 7.)
function funcBody(src, name) {
  const at = src.indexOf('function ' + name);
  if (at < 0) { return null; }
  const open = src.indexOf('{', at);
  if (open < 0) { return null; }
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    const ch = src[i];
    if (ch === '{') { depth++; }
    else if (ch === '}') { depth--; if (depth === 0) { return src.slice(at, i + 1); } }
  }
  return null;
}

// Extract an object-method body such as `queryGraphExpand(body) { ... }` from
// the generated no-build client. Used only by the route-conformance audit.
function objectMethodBody(src, name) {
  const at = src.indexOf('\n  ' + name + '(');
  if (at < 0) { return null; }
  const open = src.indexOf('{', at);
  if (open < 0) { return null; }
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    const ch = src[i];
    if (ch === '{') { depth++; }
    else if (ch === '}') { depth--; if (depth === 0) { return src.slice(at, i + 1); } }
  }
  return null;
}

// The 26 legacy CX pages (scope table, index.html:764).
const LEGACY_26 = [
  'cx-overview', 'cx-activity', 'cx-cost', 'cx-projects', 'cx-work', 'cx-usage', 'cx-documents', 'cx-gates',
  'cx-review', 'cx-coord', 'cx-sessions', 'cx-orchestrators', 'cx-punchcards', 'cx-passport', 'cx-identity',
  'cx-receipts', 'cx-mediation', 'cx-workbench', 'cx-integrations', 'cx-extensions', 'cx-facts', 'cx-memory',
  'cx-tenants', 'cx-lane-weights', 'cx-settings', 'cx-raw'
];

// ---- Walk helper: every control across a page (static + live build) ------
function walkControls(controls, fn) {
  (controls || []).forEach(function (c) {
    if (!c || typeof c !== 'object') { return; }
    fn(c);
    if (c.controls) { walkControls(c.controls, fn); }
  });
}
function walkPage(page, fn) {
  (page.sections || []).forEach(function (s) { walkControls(s.controls, fn); walkControls(s.headControls, fn); });
  if (page.load && typeof page.load.build === 'function') {
    // Exercise all branches so degraded + empty + populated control types are
    // seen — the populated res carries a representative row so per-item controls
    // (e.g. a project's per-project ＋Add-repos disclose) materialise for the walk.
    [
      { ok: true, status: 200, data: {} },
      { ok: false, status: 0, data: null },
      { ok: true, status: 200, data: { projects: [{ id: 'demo-proj', name: 'Demo project', is_default: true, planning_target: 'PlanCrux' }] } }
    ].forEach(function (res) {
      let sections;
      try { sections = page.load.build(res); } catch (e) { sections = []; }
      (sections || []).forEach(function (s) { walkControls(s.controls, fn); walkControls(s.headControls, fn); });
    });
  }
}

// =========================================================================
//  Check 1 — 26 legacy ids present, each with a valid dest.
// =========================================================================
(function checkIds() {
  const destIds = new Set(pages.DESTS.map(function (d) { return d.id; }));
  check(pages.LEGACY_IDS && pages.LEGACY_IDS.length === 26, 'pages.LEGACY_IDS must list exactly 26 ids (got ' + (pages.LEGACY_IDS || []).length + ')');
  LEGACY_26.forEach(function (id) {
    const p = pages.PAGES[id];
    check(!!p, '[ids] missing legacy page: ' + id);
    if (p) {
      check(p.legacyId === id, '[ids] ' + id + ' legacyId mismatch: ' + p.legacyId);
      check(destIds.has(p.dest), '[ids] ' + id + ' has invalid dest: ' + String(p.dest));
    }
  });
  // No stray pages outside the 26 — EXCEPT the M8 Pro-ported pages, each of
  // which must be declared in PRO_PORTED_IDS and be pro:true (hidden in Standard
  // mode). This extends the guarantee (documents the only allowed extras) without
  // weakening it: any page id neither in the 26 nor in PRO_PORTED_IDS still fails.
  const proPorted = new Set(pages.PRO_PORTED_IDS || []);
  // Declared native v2 pages beyond the legacy 26 (not pro-gated). cx-activity-log
  // is the Work › Activity log — folded into this console (the standalone
  // /console/activity page was removed), custom-rendered.
  const nativeExtra = new Set(['cx-activity-log']);
  Object.keys(pages.PAGES).forEach(function (id) {
    if (LEGACY_26.indexOf(id) >= 0) { return; }
    if (nativeExtra.has(id)) {
      const np = pages.PAGES[id];
      check(np && destIds.has(np.dest), '[ids] native page ' + id + ' has invalid dest: ' + String(np && np.dest));
      return;
    }
    check(proPorted.has(id), '[ids] unexpected page id not in the legacy 26, PRO_PORTED_IDS, nor a declared native page: ' + id);
    const pp = pages.PAGES[id];
    check(pp && pp.pro === true, '[ids] PRO_PORTED page ' + id + ' must be pro:true (Pro-mode only)');
    check(pp && destIds.has(pp.dest), '[ids] PRO_PORTED page ' + id + ' has invalid dest: ' + String(pp && pp.dest));
  });
  check((pages.PRO_PORTED_IDS || []).length === 4,
    '[ids] expected exactly 4 Pro-ported legacy pages (dx-docs, gx-global, ax-agent, ix-infra); got ' + (pages.PRO_PORTED_IDS || []).length);
  // Item 0: a pill:false page is folded out of its destination's pill row but
  // must still be reachable — its content is rendered inline by the
  // destination's landing (render.js references its id). cx-overview is the one.
  let pillFalse = 0;
  Object.keys(pages.PAGES).forEach(function (id) {
    const p = pages.PAGES[id];
    if (p && p.pill === false) {
      pillFalse++;
      check(renderSrc.indexOf("'" + id + "'") >= 0,
        '[ids] pill:false page ' + id + ' must be rendered by its destination landing (render.js must reference ' + id + ')');
    }
  });
  check(pages.PAGES['cx-overview'] && pages.PAGES['cx-overview'].pill === false,
    '[ids] cx-overview must be pill:false — folded out of the Overwatch pills, reachable via the landing tiles');
  notes.push('26/26 legacy CX ids mapped across ' + destIds.size + ' destinations (' + pillFalse + ' pill:false, landing-rendered).');
})();

// =========================================================================
//  Check 2 — every control type used in pages.js has a renderer branch.
// =========================================================================
(function checkControlTypes() {
  const used = new Set();
  Object.keys(pages.PAGES).forEach(function (id) {
    walkPage(pages.PAGES[id], function (c) { if (c.t) { used.add(c.t); } });
  });
  const supported = new Set(render.CONTROL_TYPES || []);
  used.forEach(function (t) {
    check(supported.has(t), '[controls] control type "' + t + '" used in pages.js has no entry in render.CONTROL_TYPES');
    check(new RegExp("case '" + t + "'").test(renderSrc), '[controls] render.js has no `case \'' + t + '\'` branch for control type "' + t + '"');
  });
  notes.push('control types used: ' + Array.from(used).sort().join(', '));
})();

// =========================================================================
//  Check 3 — theme contrast (WCAG 2.1 relative luminance).
// =========================================================================
function parseColor(raw) {
  const s = String(raw).trim();
  let m = s.match(/^#([0-9a-f]{3})$/i);
  if (m) { return { r: parseInt(m[1][0] + m[1][0], 16), g: parseInt(m[1][1] + m[1][1], 16), b: parseInt(m[1][2] + m[1][2], 16), a: 1 }; }
  m = s.match(/^#([0-9a-f]{6})$/i);
  if (m) { return { r: parseInt(m[1].slice(0, 2), 16), g: parseInt(m[1].slice(2, 4), 16), b: parseInt(m[1].slice(4, 6), 16), a: 1 }; }
  m = s.match(/^rgba?\(([^)]+)\)$/i);
  if (m) {
    const parts = m[1].split(',').map(function (x) { return x.trim(); });
    return { r: +parts[0], g: +parts[1], b: +parts[2], a: parts[3] != null ? +parts[3] : 1 };
  }
  return null;
}
function compositeOver(top, bottom) {
  if (!top) { return bottom; }
  if (top.a >= 1) { return { r: top.r, g: top.g, b: top.b, a: 1 }; }
  const a = top.a;
  return {
    r: Math.round(a * top.r + (1 - a) * bottom.r),
    g: Math.round(a * top.g + (1 - a) * bottom.g),
    b: Math.round(a * top.b + (1 - a) * bottom.b),
    a: 1
  };
}
function luminance(c) {
  const chan = [c.r, c.g, c.b].map(function (v) {
    const x = v / 255;
    return x <= 0.03928 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4);
  });
  return 0.2126 * chan[0] + 0.7152 * chan[1] + 0.0722 * chan[2];
}
function contrast(a, b) {
  const l1 = luminance(a), l2 = luminance(b);
  const hi = Math.max(l1, l2), lo = Math.min(l1, l2);
  return (hi + 0.05) / (lo + 0.05);
}
function extractThemeVars(theme) {
  // Grab the CSS block :root[data-theme="X"] { ... } and pull the --vars.
  const re = new RegExp(':root\\[data-theme="' + theme + '"\\]\\s*\\{([^}]*)\\}');
  const m = shellHtml.match(re);
  if (!m) { return null; }
  const body = m[1];
  function v(name) {
    const mm = body.match(new RegExp('--' + name + '\\s*:\\s*([^;]+);'));
    return mm ? parseColor(mm[1]) : null;
  }
  return {
    bg: v('bg'), surface: v('surface'), ink: v('ink'), ink2: v('ink2'), ink3: v('ink3'),
    approveInk: v('approve-ink'), approveB: v('approve-b')
  };
}
(function checkContrast() {
  ['glass', 'dark', 'light'].forEach(function (theme) {
    const t = extractThemeVars(theme);
    if (!t || !t.bg || !t.surface) { check(false, '[contrast] could not parse theme block: ' + theme); return; }
    const overSurface = compositeOver(t.surface, t.bg);
    [['ink', 4.5], ['ink2', 4.5], ['ink3', 4.0]].forEach(function (pair) {
      const name = pair[0], floor = pair[1], col = t[name];
      if (!col) { check(false, '[contrast] ' + theme + ' missing --' + name); return; }
      const cBg = contrast(col, t.bg), cSurf = contrast(col, overSurface);
      check(cBg >= floor, '[contrast] ' + theme + ' --' + name + ' over --bg = ' + cBg.toFixed(2) + ':1 (need >= ' + floor + ')');
      check(cSurf >= floor, '[contrast] ' + theme + ' --' + name + ' over --surface = ' + cSurf.toFixed(2) + ':1 (need >= ' + floor + ')');
      notes.push('contrast ' + theme + '/' + name + ': bg ' + cBg.toFixed(2) + ':1 · surface ' + cSurf.toFixed(2) + ':1');
    });
    // Approve button (Overwatch gate action): the label ink must clear 4.5:1
    // over the button's solid base --approve-b on every theme.
    if (!t.approveInk || !t.approveB) {
      check(false, '[contrast] ' + theme + ' missing --approve-ink / --approve-b token');
    } else {
      const cApprove = contrast(t.approveInk, t.approveB);
      check(cApprove >= 4.5, '[contrast] ' + theme + ' --approve-ink over --approve-b = ' + cApprove.toFixed(2) + ':1 (need >= 4.5)');
      notes.push('contrast ' + theme + '/approve-ink over approve-b: ' + cApprove.toFixed(2) + ':1');
    }
  });
})();

// =========================================================================
//  Check 4 — MUTATING_ACTIONS are gated (data + renderer logic).
// =========================================================================
(function checkMutationGate() {
  const mutLabels = new Set();
  Object.keys(pages.PAGES).forEach(function (id) {
    walkPage(pages.PAGES[id], function (c) { if (c.mut === true && c.label) { mutLabels.add(String(c.label)); } });
  });
  (pages.MUTATING_ACTIONS || []).forEach(function (label) {
    check(mutLabels.has(label), '[posture] MUTATING_ACTIONS entry "' + label + '" has no control tagged mut:true in pages.js');
  });
  check((pages.MUTATING_ACTIONS || []).length > 0, '[posture] MUTATING_ACTIONS must not be empty');
  // Renderer must route mutating controls through the operator gate.
  check(/function applyMutationGate/.test(renderSrc), '[posture] render.js missing applyMutationGate()');
  check(/control\.mut/.test(renderSrc), '[posture] render.js gate must branch on control.mut');
  check(/data-requires['"]?\s*,\s*['"]operator/.test(renderSrc) || /setAttribute\('data-requires', 'operator'\)/.test(renderSrc), '[posture] render.js gate must stamp data-requires="operator"');
  check(/wired in M3\+/.test(renderSrc), '[posture] render.js gate must disable with title "wired in M3+"');
  notes.push((pages.MUTATING_ACTIONS || []).length + ' mutating actions, all gated operator-only + disabled (wired in M3+).');
})();

// =========================================================================
//  Check 5 — no external http(s) runtime deps in any v2 file.
// =========================================================================
(function checkNoExternalDeps() {
  // Flag remote LOADERS and CDN hosts. Bare http(s) literals (e.g. the
  // embedding-endpoint placeholder `http://localhost:…`) are display text, not
  // dependencies, and are not flagged — matching the legacy console's posture.
  const loaderPatterns = [
    /<script[^>]+src\s*=\s*['"]https?:/i,
    /<link[^>]+href\s*=\s*['"]https?:/i,
    /<iframe[^>]+src\s*=\s*['"]https?:/i,
    /\bfrom\s+['"]https?:/i,
    /\bimport\s*\(\s*['"]https?:/i,
    /@import\s+(?:url\()?['"]?https?:/i,
    /\bfetch\s*\(\s*['"]https?:\/\/(?!localhost|127\.0\.0\.1)/i
  ];
  const cdnHosts = ['unpkg.com', 'jsdelivr.net', 'cdnjs.cloudflare', 'cdn.jsdelivr', 'fonts.googleapis', 'fonts.gstatic'];
  // Scan shipped browser files only (smoke.cjs itself contains regex source).
  const files = fs.readdirSync(DIR).filter(function (f) {
    return (/\.(js|html|css)$/.test(f)) && f !== 'smoke.cjs';
  });
  files.forEach(function (f) {
    const src = fs.readFileSync(path.join(DIR, f), 'utf8');
    loaderPatterns.forEach(function (re) {
      if (re.test(src)) { check(false, '[external] ' + f + ' loads a remote dependency matching ' + re); }
    });
    cdnHosts.forEach(function (host) {
      if (src.indexOf(host) >= 0) { check(false, '[external] ' + f + ' references CDN host: ' + host); }
    });
  });
  notes.push('scanned ' + files.length + ' shipped v2 file(s) for external deps: ' + files.join(', '));
})();

// =========================================================================
//  Check 6 — M2 contract gate: reads only through the generated client.
//  The ONLY shipped v2 file allowed to call fetch() is the generated api.js;
//  pages/render/shell route every read through window.CruxApi.get (allowlist-
//  guarded). api.js must load before pages.js/render.js in the shell.
// =========================================================================
(function checkThroughClientFetches() {
  ['pages.js', 'render.js', 'shell.html'].forEach(function (f) {
    const src = fs.readFileSync(path.join(DIR, f), 'utf8');
    const hits = (src.match(/\bfetch\s*\(/g) || []).length;
    check(hits === 0, '[through-client] ' + f + ' calls fetch() directly (' + hits + '×) — route reads via CruxApi.get');
  });
  const shellSrc = fs.readFileSync(path.join(DIR, 'shell.html'), 'utf8');
  const apiAt = shellSrc.indexOf('/console-v2/api.js');
  const pagesAt = shellSrc.indexOf('/console-v2/pages.js');
  check(apiAt >= 0 && pagesAt > apiAt, '[through-client] shell.html must load api.js before pages.js');
  const apiSrc = fs.readFileSync(path.join(DIR, 'api.js'), 'utf8');
  check(/LITERAL_GET_PATHS/.test(apiSrc) && /window\.CruxApi\s*=\s*CruxApi/.test(apiSrc),
    '[through-client] api.js must expose the allowlist-guarded window.CruxApi global');
  check(!/^\s*export\s+(const|default|function|let|var|class)\b/m.test(apiSrc),
    '[through-client] api.js must be a classic script (no export statements) for the no-build shell');
  notes.push('through-client rule: pages/render/shell contain zero direct fetch() calls; api.js is the sole network layer.');
})();

// =========================================================================
//  Check 7 — M3 gated-mutations audit. CruxApiGated in api.js contains EXACTLY
//  the curated (method, path) set (asserted against the machine-readable
//  GATED_MUTATIONS twin), and the gated client is referenced ONLY inside
//  render.js operatorGatedCall (which guards on isOperator) — never in
//  pages.js / shell.html.
// =========================================================================
(function checkGatedMutations() {
  const apiSrc = fs.readFileSync(path.join(DIR, 'api.js'), 'utf8');
  check(/const CruxApiGated = Object\.freeze\(/.test(apiSrc), '[gated] api.js must define CruxApiGated');
  check(/window\.CruxApiGated\s*=\s*CruxApiGated/.test(apiSrc), '[gated] api.js must expose window.CruxApiGated');

  // The curated set — the ONLY writes the console may do (M3 + M13b live-wiring).
  const EXPECTED = [
    ['POST', '/v1/work/gate/{actionId}/approve'],
    ['POST', '/v1/work/gate/{actionId}/reject'],
    ['POST', '/v1/work/{id}/comments'],
    ['POST', '/v1/actions/enrich'],
    // M13b live-wired write controls (each behind the WIRED_WRITES harness):
    ['POST', '/v1/projects'],
    ['POST', '/v1/passports'],
    ['POST', '/v1/console/review/consolidations'],
    ['POST', '/v1/identity/candidates/{candidateId}/confirm'],
    ['PUT', '/v1/console/corecrux/lane-weights'],
    ['DELETE', '/v1/console/corecrux/lane-weights'],
    ['POST', '/v1/admin/restart'],
    ['POST', '/v1/console/onboarding/restart'],
    ['POST', '/v1/console/embedding/probe'],
    ['POST', '/v1/integrations/github/connect'],
    ['POST', '/v1/integrations/openai/chat'],
    ['POST', '/v1/extensions/keys'],
    ['POST', '/v1/workspace/scan'],
    ['POST', '/v1/workbench/context-pack'],
    ['POST', '/v1/workbench/impact-preflight'],
    ['POST', '/v1/workbench/policy-simulation'],
    ['POST', '/v1/workbench/route-probe'],
    ['POST', '/v1/features/capabilities/{id}/audit']
  ];
  // Parse the machine-readable GATED_MUTATIONS array and assert set-equality.
  const arrM = apiSrc.match(/const GATED_MUTATIONS = Object\.freeze\(\[([\s\S]*?)\]\);/);
  check(!!arrM, '[gated] api.js must declare the GATED_MUTATIONS array');
  const declared = [];
  if (arrM) {
    const re = /\[\s*'([A-Z]+)'\s*,\s*'([^']+)'\s*\]/g;
    let m;
    while ((m = re.exec(arrM[1])) !== null) { declared.push([m[1], m[2]]); }
  }
  const norm = function (pairs) { return pairs.map(function (p) { return p[0] + ' ' + p[1]; }).sort(); };
  check(JSON.stringify(norm(declared)) === JSON.stringify(norm(EXPECTED)),
    '[gated] GATED_MUTATIONS must be EXACTLY the curated set; got ' + JSON.stringify(norm(declared)));

  // Each declared mutation has a matching CruxApiGated fetch (verb + path stem).
  declared.forEach(function (pair) {
    const method = pair[0];
    const stem = pair[1].split('{')[0].replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const hasFetch = new RegExp('fetch\\(`' + stem + "[^`]*`,\\s*\\{\\s*method:\\s*'" + method + "'").test(apiSrc);
    check(hasFetch, '[gated] CruxApiGated missing a ' + method + ' fetch for ' + pair[1]);
  });
  // No non-GET verbs beyond the two curated sets anywhere in api.js: the gated
  // MUTATIONS (writes) + the curated READ POSTs (retrieval). READ_POST_ROUTES all
  // use POST, so the total method-verb count is gated + read.
  const READ_POST_EXPECTED = [
    ['POST', '/v1/query/text-search'],
    ['POST', '/v1/query/text-search/expand'],
    ['POST', '/v1/query/graph-expand'],
    ['POST', '/v1/query/time-range'],
    ['POST', '/v1/console/engine/search']
  ];
  // CruxSession (hosted BFF /api/auth/*) carries exactly ONE non-GET call —
  // the logout POST. It is a platform-session call, not a daemon mutation, so
  // it sits outside the gated-write and read-POST allowlists; assert it
  // explicitly so the daemon-mutation count below stays exact.
  const SESSION_POSTS = 1;
  check(/window\.CruxSession\s*=\s*CruxSession/.test(apiSrc) && /'\/api\/auth\/logout'/.test(apiSrc),
    '[gated] api.js must expose CruxSession with the /api/auth/logout call (hosted logout)');
  const verbCount = (apiSrc.match(/method:\s*'(POST|PUT|PATCH|DELETE)'/g) || []).length;
  const verbExpected = EXPECTED.length + READ_POST_EXPECTED.length + SESSION_POSTS;
  check(verbCount === verbExpected, '[gated] api.js has ' + verbCount + ' non-GET fetch(es); expected ' + verbExpected + ' (' + EXPECTED.length + ' gated writes + ' + READ_POST_EXPECTED.length + ' curated read POSTs + ' + SESSION_POSTS + ' session logout)');

  // Static containment: pages.js + shell.html never touch CruxApiGated; render.js
  // touches it ONLY inside operatorGatedCall (which guards on isOperator()).
  ['pages.js', 'shell.html'].forEach(function (f) {
    const src = fs.readFileSync(path.join(DIR, f), 'utf8');
    check(!/CruxApiGated/.test(src), '[gated] ' + f + ' must not reference CruxApiGated (use CruxRender operator helpers)');
  });
  const gc = funcBody(renderSrc, 'operatorGatedCall');
  check(!!gc, '[gated] render.js must define operatorGatedCall');
  check(gc && /isOperator\(\)/.test(gc), '[gated] operatorGatedCall must guard on isOperator()');
  if (gc) {
    const outside = renderSrc.split(gc).join('');
    check(!/CruxApiGated/.test(outside), '[gated] render.js references CruxApiGated outside operatorGatedCall');
  }
  notes.push('gated mutations: ' + declared.length + ' curated; client invoked only inside operator-guarded operatorGatedCall.');
})();

// =========================================================================
//  Check 8 — posture derivation is a pure function with the documented truth
//  table (operator for auth-off, operator for probe-200, customer else).
// =========================================================================
(function checkPostureDerivation() {
  const derive = render.derivePosture;
  check(typeof derive === 'function', '[posture] render.js must export derivePosture()');
  if (typeof derive === 'function') {
    check(derive({ authMode: 'off' }) === 'operator', '[posture] derivePosture(off) must be operator');
    check(derive({ authMode: 'local_only' }) === 'customer', '[posture] local_only is NOT a real auth mode (config enum: off|dev_scopes|jwt_hs256|jwt_jwks) — must not grant operator');
    check(derive({ adminProbeStatus: 200 }) === 'operator', '[posture] derivePosture(probe 200) must be operator');
    check(derive({ authMode: 'token', adminProbeStatus: 401 }) === 'customer', '[posture] derivePosture(token/401) must be customer');
    check(derive({ authMode: 'token', adminProbeStatus: 403 }) === 'customer', '[posture] derivePosture(token/403) must be customer');
    check(derive({ adminProbeStatus: 0 }) === 'customer', '[posture] derivePosture(network fail) must be customer');
    check(derive({}) === 'customer', '[posture] derivePosture(empty) must be customer');
    notes.push('posture derivation truth table verified (auth-off→operator, probe200→operator, else→customer; local_only rejected).');
  }
})();

// =========================================================================
//  Check 9 — M4 engine mediation. (a) No shipped v2 file addresses the Engine
//  directly (ports :14343 / :14344 must never appear — reads go through the
//  daemon proxy). (b) The three /v1/console/engine/* GET paths, and every
//  /v1/console/engine/ path pages.js references, are in api.js's allowlist.
// =========================================================================
(function checkEngineMediation() {
  const shipped = fs.readdirSync(DIR).filter(function (f) {
    return (/\.(js|html|css)$/.test(f)) && f !== 'smoke.cjs';
  });
  ['14343', '14344'].forEach(function (port) {
    shipped.forEach(function (f) {
      const src = fs.readFileSync(path.join(DIR, f), 'utf8');
      check(src.indexOf(':' + port) < 0, '[engine] ' + f + ' addresses the Engine directly (:' + port + ') — reads must go through the daemon proxy');
    });
  });

  const apiSrc = fs.readFileSync(path.join(DIR, 'api.js'), 'utf8');
  const allowM = apiSrc.match(/const LITERAL_GET_PATHS = Object\.freeze\(\{([\s\S]*?)\}\);/);
  check(!!allowM, '[engine] api.js must declare LITERAL_GET_PATHS');
  const allow = new Set();
  if (allowM) {
    const re = /'([^']+)'\s*:\s*true/g;
    let m;
    while ((m = re.exec(allowM[1])) !== null) { allow.add(m[1]); }
  }
  const ENGINE_GETS = ['/v1/console/engine/summary', '/v1/console/engine/bench', '/v1/console/engine/spend'];
  ENGINE_GETS.forEach(function (p) {
    check(allow.has(p), '[engine] api.js allowlist (LITERAL_GET_PATHS) missing engine GET: ' + p);
  });
  // Every /v1/console/engine/ path referenced in pages.js must be allowlisted.
  const refs = new Set((pagesSrc.match(/\/v1\/console\/engine\/[a-z]+/g) || []));
  refs.forEach(function (p) {
    check(allow.has(p), '[engine] pages.js references ' + p + ' but it is not in the api.js allowlist');
  });
  notes.push('engine mediation: no direct :14343/:14344 addressing; ' + ENGINE_GETS.length + ' engine GETs allowlisted; ' + refs.size + ' referenced in pages.js.');
})();

// =========================================================================
//  Check 10 — M5 PWA manifest. Parses as JSON and carries the installability
//  fields (name, start_url "/console", display "standalone", ≥1 icon).
// =========================================================================
(function checkManifest() {
  const raw = fs.readFileSync(path.join(DIR, 'manifest.webmanifest'), 'utf8');
  let manifest = null;
  try { manifest = JSON.parse(raw); }
  catch (e) { check(false, '[manifest] manifest.webmanifest is not valid JSON: ' + e.message); return; }
  check(typeof manifest.name === 'string' && manifest.name.length > 0, '[manifest] missing "name"');
  check(manifest.start_url === '/console', '[manifest] start_url must be "/console" (got ' + JSON.stringify(manifest.start_url) + ')');
  check(manifest.scope === '/console', '[manifest] scope should be "/console" (got ' + JSON.stringify(manifest.scope) + ')');
  check(manifest.display === 'standalone', '[manifest] display must be "standalone" (got ' + JSON.stringify(manifest.display) + ')');
  check(Array.isArray(manifest.icons) && manifest.icons.length >= 1, '[manifest] must declare ≥1 icon');
  const hasSvg = (manifest.icons || []).some(function (i) { return i && i.src === '/console-v2/icon.svg'; });
  check(hasSvg, '[manifest] icons must include /console-v2/icon.svg');
  notes.push('manifest: name "' + manifest.name + '", start_url ' + manifest.start_url + ', display ' + manifest.display + ', ' + (manifest.icons || []).length + ' icon(s).');
})();

// =========================================================================
//  Check 11 — M5 service worker. (a) APP_SHELL precache list == the EXACT
//  app-shell set. (b) /v1/* is network-only (bypass present) and NO cache write
//  (addAll/put) targets /v1/. (c) SW_REV matches shell.html's (bump-together).
// =========================================================================
(function checkServiceWorker() {
  const swSrc = fs.readFileSync(path.join(DIR, 'sw.js'), 'utf8');
  const EXPECTED_SHELL = [
    '/console',
    '/console-v2/api.js',
    '/console-v2/pages.js',
    '/console-v2/render.js',
    '/console-v2/icon.svg',
    '/console-v2/manifest.webmanifest'
  ].slice().sort();

  const arrM = swSrc.match(/const APP_SHELL = \[([\s\S]*?)\];/);
  check(!!arrM, '[sw] sw.js must declare the APP_SHELL precache array');
  const declared = [];
  if (arrM) {
    const re = /'([^']+)'/g;
    let m;
    while ((m = re.exec(arrM[1])) !== null) { declared.push(m[1]); }
  }
  check(JSON.stringify(declared.slice().sort()) === JSON.stringify(EXPECTED_SHELL),
    '[sw] APP_SHELL must be EXACTLY the app-shell set; got ' + JSON.stringify(declared.slice().sort()));

  // /v1/ network-only bypass present.
  check(/url\.pathname\.startsWith\(['"]\/v1\/['"]\)/.test(swSrc),
    '[sw] fetch handler must bypass /v1/ (network-only) — url.pathname.startsWith("/v1/")');
  // No cache write (addAll / .put) targets a /v1/ path. Comments may mention it.
  swSrc.split('\n').forEach(function (line) {
    const t = line.replace(/^\s+/, '');
    if (t.indexOf('//') === 0) { return; }   // skip comment lines
    if ((/(?:addAll|\.put)\(/.test(t)) && t.indexOf('/v1/') >= 0) {
      check(false, '[sw] cache write must never target /v1/: ' + line.trim());
    }
  });

  // SW_REV bump-together with shell.html.
  function rev(src) { const m = src.match(/SW_REV\s*=\s*'([^']+)'/); return m ? m[1] : null; }
  const swRev = rev(swSrc), shellRev = rev(shellHtml);
  check(!!swRev, '[sw] sw.js must declare SW_REV');
  check(!!shellRev, '[sw] shell.html must declare SW_REV');
  check(swRev && shellRev && swRev === shellRev,
    '[sw] SW_REV must match between sw.js (' + swRev + ') and shell.html (' + shellRev + ')');
  notes.push('service worker: ' + declared.length + '-asset app shell, /v1/ network-only, SW_REV=' + swRev + ' (matches shell).');
})();

// =========================================================================
//  Check 12 — M5 phone tier. shell.html carries the fixed bottom tab bar with
//  the four tabs (Overwatch · Work · Trust · More), respects safe-area-inset,
//  and the tab CSS uses ≥44px touch targets.
// =========================================================================
(function checkPhoneTier() {
  check(shellHtml.indexOf('id="tabbar"') >= 0, '[phone] shell.html must carry the bottom tab bar (id="tabbar")');
  check(shellHtml.indexOf('id="moreSheet"') >= 0, '[phone] shell.html must carry the "More" sheet (id="moreSheet")');
  // The four tabs: three direct destination ids + the "More" tab.
  const tabM = shellHtml.match(/TAB_DEST_IDS\s*=\s*\[([^\]]*)\]/);
  check(!!tabM, '[phone] shell.html must declare TAB_DEST_IDS (the three direct tabs)');
  const tabIds = tabM ? (tabM[1].match(/'([^']+)'/g) || []).map(function (s) { return s.replace(/'/g, ''); }) : [];
  ['overwatch', 'work', 'trust'].forEach(function (id) {
    check(tabIds.indexOf(id) >= 0, '[phone] TAB_DEST_IDS must include the "' + id + '" tab');
  });
  check(/label:\s*'More'/.test(shellHtml), '[phone] the 4th tab must be "More"');
  check((tabIds.length + 1) === 4, '[phone] tab bar must have exactly 4 tabs (3 direct + More); got ' + (tabIds.length + 1));
  // Safe-area inset respected (fixed bar + content padding).
  check(shellHtml.indexOf('safe-area-inset') >= 0, '[phone] phone tier must respect env(safe-area-inset-*)');
  // ≥44px touch target in the .tab CSS rule.
  check(/\.tab\s*\{[^}]*min-height:\s*44px/.test(shellHtml), '[phone] .tab CSS must set min-height: 44px (touch target)');
  notes.push('phone tier: 4-tab bottom bar (' + tabIds.join('/') + '/More), safe-area-inset respected, .tab ≥44px.');
})();

// =========================================================================
//  Check 13 — demo mode is labelled + gated. CruxDemo fixtures are reachable
//  ONLY behind the demo flag: render.js reads them solely through demoData(),
//  which guards on demoOn() (window.CRUX_DEMO). The DEMO DATA chip + the ?demo
//  activation live in the shell. This mirrors the gated-mutation containment
//  audit (check 7) — a static proof that fixtures can never render un-flagged.
// =========================================================================
(function checkDemoMode() {
  check(/var CruxDemo = /.test(pagesSrc), '[demo] pages.js must define the CruxDemo fixtures module');
  check(/root\.CruxDemo\s*=\s*api\.CruxDemo/.test(pagesSrc), '[demo] pages.js must expose window.CruxDemo for render.js');
  check(pages.CruxDemo && typeof pages.CruxDemo === 'object', '[demo] CruxDemo must be exported from pages.js');
  ['needsYou', 'fleet', 'activity', 'engine', 'costSeries', 'usageSeries'].forEach(function (k) {
    check(pages.CruxDemo && pages.CruxDemo[k] != null, '[demo] CruxDemo missing representative fixture: ' + k);
  });
  // Representative shapes: one fleet overlap, one gate with consequences, 12 ticks.
  check(Array.isArray(pages.CruxDemo.fleet) && pages.CruxDemo.fleet.some(function (s) { return (s.overlaps || []).length; }),
    '[demo] CruxDemo.fleet must include a ⚠ overlap session');
  check(Array.isArray(pages.CruxDemo.needsYou) && pages.CruxDemo.needsYou.some(function (g) { return (g.consequences || []).length; }),
    '[demo] CruxDemo.needsYou must include a gate with consequences');
  check(Array.isArray(pages.CruxDemo.activity) && pages.CruxDemo.activity.length === 12 && pages.CruxDemo.activity.every(function (r) { return (r.receipt_ids || []).length; }),
    '[demo] CruxDemo.activity must be 12 rows, each with a receipt id');
  // Containment: CruxDemo is named in render.js ONLY inside demoData(), which
  // guards on demoOn() (window.CRUX_DEMO). Nothing else touches the fixtures.
  const dd = funcBody(renderSrc, 'demoData');
  check(!!dd, '[demo] render.js must define demoData()');
  check(dd && /demoOn\(\)/.test(dd), '[demo] demoData() must guard on demoOn() (the demo flag)');
  check(/window\.CRUX_DEMO/.test(renderSrc), '[demo] demoOn() must read window.CRUX_DEMO');
  if (dd) {
    const outside = renderSrc.split(dd).join('');
    check(!/window\.CruxDemo/.test(outside), '[demo] render.js reads window.CruxDemo outside the demoData() choke point');
  }
  // The DEMO DATA chip + ?demo activation live in the shell (flag-driven).
  check(/DEMO DATA/.test(shellHtml), '[demo] shell.html must render the fixed DEMO DATA chip when demo mode is on');
  check(/crux\.console\.demo/.test(shellHtml), '[demo] shell.html must persist the demo flag (crux.console.demo)');
  check(/window\.CRUX_DEMO\s*=/.test(shellHtml), '[demo] shell.html must set window.CRUX_DEMO');
  check(/demo=1/.test(shellHtml) && /demo=0/.test(shellHtml), '[demo] shell.html must honour ?demo=1 / ?demo=0');
  notes.push('demo mode: fixtures reachable only via demoOn()-guarded demoData(); DEMO DATA chip + ?demo activation present.');
})();

// =========================================================================
//  Check 14 — exactly two button families console-wide (.btn-primary +
//  .btn-quiet); the retired ow-btn / ow-approve / ow-ghost / ctl-btn / ctl-link
//  classes are gone from every shipped browser file.
// =========================================================================
(function checkUnifiedButtons() {
  check(/\.btn-primary\b/.test(shellHtml) && /\.btn-quiet\b/.test(shellHtml), '[buttons] shell.html must define both .btn-primary and .btn-quiet');
  check(/btn-quiet/.test(renderSrc), '[buttons] render.js must render page/DSL buttons with the .btn-quiet family');
  check(/btn-primary/.test(renderSrc), '[buttons] render.js must render the gate approve as .btn-primary');
  ['ow-approve', 'ow-ghost', 'ow-btn', 'ctl-btn', 'ctl-link'].forEach(function (cls) {
    check(shellHtml.indexOf(cls) < 0, '[buttons] shell.html still references the retired button class: ' + cls);
    check(renderSrc.indexOf(cls) < 0, '[buttons] render.js still references the retired button class: ' + cls);
  });
  notes.push('unified buttons: two families (.btn-primary/.btn-quiet); retired ow-btn/ctl-btn classes removed.');
})();

// =========================================================================
//  Check 15 — collapsible rail (persisted, desktop-guarded).
// =========================================================================
(function checkCollapsibleRail() {
  check(/id="railToggle"/.test(shellHtml), '[rail] shell.html must carry the rail toggle (id="railToggle")');
  check(/crux\.console\.rail/.test(shellHtml), '[rail] shell.html must persist the rail state (crux.console.rail)');
  check(/data-rail/.test(shellHtml), '[rail] shell.html must toggle <html data-rail>');
  check(/aria-expanded/.test(shellHtml), '[rail] the rail toggle must set aria-expanded');
  check(shellHtml.indexOf('Collapse navigation') >= 0, '[rail] the rail toggle must carry the "Collapse navigation" aria-label');
  // Collapsed rules are guarded to the desktop tier so they never fight the
  // phone media query (which hides the rail entirely).
  check(/@media \(min-width: 721px\)[\s\S]*data-rail="collapsed"/.test(shellHtml), '[rail] collapsed rail CSS must be guarded to @media (min-width: 721px)');
  notes.push('collapsible rail: railToggle + data-rail + crux.console.rail, desktop-guarded (min-width:721px).');
})();

// =========================================================================
//  Check 16 — status pill (no node id) + topbar chips + System Node section.
// =========================================================================
(function checkStatusAndChips() {
  ['Connected · Local', 'Connected · Platform', 'Offline', 'read-only'].forEach(function (t) {
    check(shellHtml.indexOf(t) >= 0, '[status] status pill missing state text: "' + t + '"');
  });
  check(shellHtml.indexOf("'Connected · ' + node") < 0, '[status] status pill must NOT embed the node id in its text');
  check(/id="topchips"/.test(shellHtml), '[chips] shell.html must carry the topbar chip cluster (id="topchips")');
  check(/function setTopChips/.test(shellHtml), '[chips] shell.html must build the topbar chips');
  check(shellHtml.indexOf("'auth: '") >= 0 && shellHtml.indexOf("'dataplane: '") >= 0, '[chips] topbar chips must include auth + dataplane');
  // Node origin + id + build move to System › Settings › Node.
  check(/h:\s*'Node'/.test(pagesSrc), '[status] Settings must gain a "Node" section for origin + node id + build');
  check(/window\.location\.origin/.test(pagesSrc), '[status] the Node section origin must read window.location.origin');
  notes.push('status pill (state-only, +read-only) · topbar chips (auth/dataplane/build) · System Node section.');
})();

// =========================================================================
//  Check 17 — charts (single-series area, Day/Week/Month range, no legend),
//  used on cx-cost + cx-usage.
// =========================================================================
(function checkCharts() {
  check((render.CONTROL_TYPES || []).indexOf('chart') >= 0, '[charts] render.CONTROL_TYPES must include "chart"');
  check(new RegExp("case 'chart'").test(renderSrc), '[charts] render.js must have a `case \'chart\'` branch');
  check(/function areaChart/.test(renderSrc), '[charts] render.js must define the areaChart helper');
  check(/chart-line/.test(renderSrc) && /chart-line/.test(shellHtml), '[charts] the area-chart line class must be defined + used');
  check(/var\(--acc\)/.test(shellHtml) && /\.chart-line\s*\{[^}]*var\(--acc\)/.test(shellHtml), '[charts] the chart line must stroke with var(--acc)');
  ["'Day'", "'Week'", "'Month'"].forEach(function (t) {
    check(renderSrc.indexOf(t) >= 0, '[charts] range switcher missing label ' + t);
  });
  check(/aria-pressed/.test(renderSrc), '[charts] chart range buttons must set aria-pressed');
  check(/chart-title/.test(renderSrc), '[charts] the chart must render a title (no legend)');
  let chartUsed = 0;
  ['cx-cost', 'cx-usage'].forEach(function (id) {
    walkPage(pages.PAGES[id], function (c) { if (c.t === 'chart') { chartUsed++; } });
  });
  check(chartUsed > 0, '[charts] cx-cost + cx-usage must carry a chart control');
  // A single-scalar series is never fabricated — the tile-sparkline series comes
  // from bucketed /v1/activity, else a demo fixture.
  check(/function bucketActivityByDay/.test(renderSrc), '[charts] tile sparklines must bucket /v1/activity (never fabricate from a scalar)');
  notes.push('charts: areaChart + Day/Week/Month range (aria-pressed, no legend); used on cost + usage; sparklines from real /v1/activity or demo.');
})();

// =========================================================================
//  Check 18 — pro-board strips: work rows + gate cards share the 3px
//  state-keyed left strip.
// =========================================================================
(function checkBoardStrips() {
  check(/exp-strip/.test(renderSrc), '[strips] render.js must add the exp-strip class for state-keyed rows');
  check(/strip:\s*stage/.test(pagesSrc), '[strips] buildWork rows must carry a state strip (strip: stage)');
  check(/\.exp-strip\[data-strip="in_progress"\]/.test(shellHtml), '[strips] shell.html must key the work strip colour by state');
  // Gate cards already stripe (::before); the two strips share the 3px geometry.
  check(/\.ow-gate::before[\s\S]{0,160}width:\s*3px/.test(shellHtml), '[strips] the gate strip must be 3px');
  check(/\.exp-strip::before[\s\S]{0,160}width:\s*3px/.test(shellHtml), '[strips] the work strip must be 3px (one consistent system)');
  notes.push('pro-board strips: work rows + gate cards share the 3px state-keyed left strip.');
})();

// =========================================================================
//  Check 19 — (round 3 → round 4) nav-family consolidation, with the left rail
//  restored to borderless-at-rest. .nav-item, .btn-quiet, and .pill still share
//  ONE look ruleset (one source of truth — shape/size/transition/hover/current),
//  and the sub-nav pill still has the squarer (not rounded solid-accent) look.
//  NEW: the LEFT RAIL items rest borderless (transparent border) — the shared
//  resting outline is for body buttons + sub-nav pills only; the rail's border
//  returns on hover / aria-current. .btn-primary stays the single accent variant.
// =========================================================================
(function checkNavFamily() {
  // The three selectors are grouped in one shared look ruleset.
  check(/\.nav-item,\s*\.btn-quiet,\s*\.pill\s*\{/.test(shellHtml),
    '[navfamily] shell.html must consolidate .nav-item, .btn-quiet, .pill into one shared look ruleset');
  // Body buttons + pills keep their resting outline: the shared family ruleset
  // still declares the 1px var(--edge) resting border (only the rail drops it).
  check(/\.nav-item,\s*\.btn-quiet,\s*\.pill\s*\{[^}]*border:\s*1px solid var\(--edge\)/.test(shellHtml),
    '[navfamily] the shared family ruleset must keep the resting outline (border: 1px solid var(--edge)) for body buttons + sub-nav pills');
  // Their current/pressed states also share one ruleset (not three near-identical blocks).
  check(/\.nav-item\[aria-current="page"\],\s*\.pill\[aria-current="page"\],\s*\.btn-quiet\[aria-pressed="true"\]\s*\{/.test(shellHtml),
    '[navfamily] current/pressed states for nav-item/pill/btn-quiet must share one ruleset');
  // NEW (round 4): the left rail rests borderless — a .rail .nav-item at-rest
  // override sets border-color: transparent (restored pre-round-3 look).
  check(/\.rail \.nav-item\s*\{[^}]*border-color:\s*transparent/.test(shellHtml),
    '[navfamily] the left rail .nav-item must rest borderless (.rail .nav-item { border-color: transparent }) — body buttons + pills keep their resting outline');
  // ...and the rail's border returns on hover / aria-current (rail-scoped rule).
  check(/\.rail \.nav-item:hover,\s*\.rail \.nav-item\[aria-current="page"\]\s*\{[^}]*border-color:\s*var\(--edge-strong\)/.test(shellHtml),
    '[navfamily] the rail border must return on hover / aria-current (rail-scoped edge-strong rule)');
  // The pill no longer solid-fills with --acc (it now uses the squarer nav look).
  check(!/\.pill\[aria-current="page"\]\s*\{\s*background:\s*var\(--acc\)/.test(shellHtml),
    '[navfamily] .pill must NOT solid-fill with var(--acc) — it adopts the nav-family current look (edge-strong + accent icon)');
  // The pill is no longer independently rounded (999px) — it inherits radius-sm.
  check(!/\.pill\s*\{[^}]*border-radius:\s*999px/.test(shellHtml),
    '[navfamily] .pill must drop the rounded 999px corners for the squarer var(--radius-sm) family');
  // .btn-primary remains the single accent (gradient) variant.
  check(/\.btn-primary\s*\{[^}]*linear-gradient/.test(shellHtml),
    '[navfamily] .btn-primary must remain the single accent (approve gradient) variant');
  notes.push('nav-family: shared look ruleset (shape/hover/current) + rail-at-rest-borderless; body buttons + pills keep the resting outline; pill squarer; .btn-primary sole accent.');
})();

// =========================================================================
//  Check 20 — (round 3) cx-projects progressive disclosure + repo grid.
//  "＋ New project" / "＋ Add repos" are operator-tagged disclose controls;
//  projects load from the REAL /v1/projects list as expandable cards; repos
//  render via a repogrid control that fetches per-project + demo-fills only when
//  the real list is empty.
// =========================================================================
(function checkProjectsDisclosure() {
  // "＋ New project" is a top-right card action (headAction "+") that reveals a
  // hidden #newProjectForm section (mirrors the Passports pattern); its "Create
  // project" write stays mut-gated (verified by the MUTATING_ACTIONS checks).
  // "＋ Add repos" is a per-project operator-tagged disclose inside each project
  // card, so its repo writes target that specific project.
  const found = { newpAction: false, newpForm: false, addr: false };
  const projSections = pages.PAGES['cx-projects'].load.build({ ok: true, status: 200, data: { projects: [{ id: 'demo-proj', name: 'Demo project', is_default: true }] } }) || [];
  projSections.forEach(function (s) {
    const act = s.headAction;
    if (act && act.variant === 'plus' && act.target === 'newProjectForm' && /New project/.test(act.title || '')) { found.newpAction = true; }
    if (s.id === 'newProjectForm' && s.hidden) { found.newpForm = true; }
  });
  walkPage(pages.PAGES['cx-projects'], function (c) {
    if (c.t === 'disclose' && c.requires === 'operator' && /Add repos/.test(c.label || '')) { found.addr = true; }
  });
  check(found.newpAction, '[projects] "＋ New project" must be a top-right headAction "+" targeting the newProjectForm');
  check(found.newpForm, '[projects] the "+" must reveal a hidden #newProjectForm section (its Create project write stays mut-gated)');
  check(found.addr, '[projects] "＋ Add repos" must be a per-project operator-tagged (requires:operator) disclose control');
  // render.js knows the disclose control + stamps data-requires="operator".
  check((render.CONTROL_TYPES || []).indexOf('disclose') >= 0, '[projects] render.CONTROL_TYPES must include "disclose"');
  check(new RegExp("case 'disclose'").test(renderSrc), '[projects] render.js must have a `case \'disclose\'` branch');
  check(/setAttribute\('data-requires', 'operator'\)/.test(renderSrc), '[projects] the disclose branch must stamp data-requires="operator"');
  // cx-projects builds from the real /v1/projects list (not a hardcoded card).
  check(/build:\s*buildProjects/.test(pagesSrc) && /endpoint:\s*'\/v1\/projects'/.test(pagesSrc),
    '[projects] cx-projects must load the real /v1/projects list via buildProjects');
  check(/strip:\s*strip/.test(pagesSrc), '[projects] project cards must carry the pro-board left strip (strip: strip)');
  // Repo grid: a repogrid control fetched via the named CruxApi method, demo-
  // filled ONLY when the real list is empty (via demoData, demoOn()-guarded).
  check((render.CONTROL_TYPES || []).indexOf('repogrid') >= 0, '[projects] render.CONTROL_TYPES must include "repogrid"');
  check(new RegExp("case 'repogrid'").test(renderSrc), '[projects] render.js must have a `case \'repogrid\'` branch');
  check(/projectsByIdRepos/.test(renderSrc), '[projects] the repo grid must fetch via CruxApi.projectsByIdRepos (named method, not raw fetch)');
  check(/demoData\('projectRepos'\)/.test(renderSrc), '[projects] repo cards must demo-fill via demoData(\'projectRepos\') (demoOn()-guarded)');
  check(pages.CruxDemo && Array.isArray(pages.CruxDemo.projectRepos) && pages.CruxDemo.projectRepos.length > 0,
    '[projects] CruxDemo must carry a representative projectRepos fixture');
  notes.push('projects: real /v1/projects expandable cards + operator-tagged ＋New/＋Add-repos disclosures + per-project repo grid (named method, demo-filled when empty).');
})();

// =========================================================================
//  Check 21 — (round 3) topbar chip height. Every topbar chip AND the status
//  pill share one height/padding/font ruleset (32px min-height) so they baseline
//  -align in the .topbar-right cluster.
// =========================================================================
(function checkTopbarChipHeight() {
  check(/\.topchip,\s*\.health\s*\{/.test(shellHtml),
    '[topbar] .topchip + .health (status pill) must share ONE height/padding/font ruleset');
  check(/\.topchip,\s*\.health\s*\{[^}]*min-height:\s*32px/.test(shellHtml),
    '[topbar] the shared topbar chip ruleset must set min-height: 32px (one height for every chip + the status pill)');
  notes.push('topbar chips: .topchip + the status pill (.health) share one 32px-height ruleset (baseline-aligned).');
})();

// =========================================================================
//  Check 22 — (round 4) legacy list/toggle language ported. (a) The v2 `toggle`
//  control renders the legacy LED toggle (.active-toggle, index.html:388-392):
//  a squarer chip with an 8px .led that glows (box-shadow) when on, on-state via
//  the .on class from control.v. (b) The topbar chips + status pill carry the
//  squarer family radius (var(--radius-sm), no longer a rounded 999px pill),
//  keeping their round-3 32px height.
// =========================================================================
(function checkLegacyListAndToggle() {
  // (a) LED toggle markers — the .led dot, its glow, and the squarer chip shape.
  check(/case 'toggle'/.test(renderSrc), '[legacy-ui] render.js must keep the `toggle` control branch');
  check(/'class':\s*'led'/.test(renderSrc) || /class="led"/.test(renderSrc),
    '[legacy-ui] the toggle branch must render an 8px LED dot (a .led span)');
  check(/'ctl-toggle'\s*\+\s*\(control\.v\s*\?\s*' on'/.test(renderSrc),
    '[legacy-ui] the toggle on-state must come from the .on class set from control.v (legacy .active-toggle.on)');
  check(/\.ctl-toggle\s+\.led\s*\{[^}]*width:\s*8px/.test(shellHtml),
    '[legacy-ui] shell.html must style the 8px LED dot (.ctl-toggle .led)');
  check(/\.ctl-toggle\.on\s+\.led\s*\{[^}]*box-shadow:\s*0 0 7px/.test(shellHtml),
    '[legacy-ui] the on-state LED must glow with box-shadow: 0 0 7px (ported from index.html:392)');
  check(/\.ctl-toggle\.on\s+\.led\s*\{[^}]*background:\s*var\(--ok\)/.test(shellHtml),
    '[legacy-ui] the on-state LED must light with var(--ok) (the operator-chosen glow colour)');
  check(/\.ctl-toggle\s*\{[^}]*border-radius:\s*var\(--radius-sm\)/.test(shellHtml),
    '[legacy-ui] the LED toggle must carry the squarer family shape (var(--radius-sm), not a rounded 999px pill)');
  check(!/\.ctl-track\b/.test(shellHtml) && !/ctl-track/.test(renderSrc),
    '[legacy-ui] the retired sliding .ctl-track toggle must be gone from shell.html + render.js');
  // (b) Squarer radius on the topbar chips + status pill (item 2).
  check(/\.topchip,\s*\.health\s*\{[^}]*border-radius:\s*var\(--radius-sm\)/.test(shellHtml),
    '[legacy-ui] .topchip + .health (status pill) must use the squarer family radius var(--radius-sm) (not 999px)');
  check(!/\.topchip,\s*\.health\s*\{[^}]*border-radius:\s*999px/.test(shellHtml),
    '[legacy-ui] the topbar chip ruleset must NOT keep the rounded 999px pill radius');
  // (c) The list rows adopt the legacy row language: hover treatment + mono sub.
  check(/\.exp-sum:hover\s*\{[^}]*background/.test(shellHtml),
    '[legacy-ui] .exp-sum must gain the legacy row hover treatment (background lift on hover)');
  check(/\.exp-sub\s*\{[^}]*var\(--font-mono\)/.test(shellHtml),
    '[legacy-ui] the list-row metadata column (.exp-sub) must be mono (legacy .sp-expname small)');
  notes.push('legacy list/toggle language: LED toggle (.led + glowing --ok on-state, squarer shape) + squarer topbar chips/pill + list-row hover + mono metadata.');
})();

// =========================================================================
//  Check 23 — (M8) presentation mode system (Standard | Professional +
//  reserved Documents). Registry + persisted + pre-paint + segmented control
//  (aria-pressed, sat left of the chips). POSTURE INDEPENDENCE is asserted
//  statically: mode is presentation only — no posture function branches on
//  mode, and applyMode touches no posture. Customer posture behaves identically
//  in every mode because the gate keys on posture, never on data-mode.
// =========================================================================
(function checkModeSystem() {
  // The visible top-level toggle is the SURFACES registry (Command | Explore).
  // Command's density (Standard | Professional) is a Settings preference; Explore
  // is the documents reader. The three underlying presentation modes remain.
  check(/var SURFACES = \[/.test(shellHtml), '[mode] shell.html must declare a SURFACES registry (Command | Explore)');
  ['command', 'explore'].forEach(function (s) {
    check(new RegExp("id:\\s*'" + s + "'").test(shellHtml), '[mode] SURFACES must include the "' + s + '" slot');
  });
  check(/DEFAULT_MODE = 'standard'/.test(shellHtml) && /'professional'/.test(shellHtml) && /'documents'/.test(shellHtml),
    '[mode] the standard | professional | documents presentation modes must remain (density + Explore)');
  // M10: the reserved third slot is ACTIVATED — all three modes are selectable
  // (Documents is the console-as-reader). No soon:true / disabled reserved slot
  // remains; buildModeSeg wires every mode to applyMode. (This supersedes the M8
  // "documents reserved / arrives in M10" assertion — the mode-system guarantees
  // below are unchanged; check 27 owns the documents-mode surface.)
  check(!/soon:\s*true/.test(shellHtml), '[mode] Documents is activated (M10) — the soon:true reserved marker must be gone');
  const modeSegBody = funcBody(shellHtml, 'buildModeSeg');
  check(modeSegBody && !/\.disabled\s*=\s*true/.test(modeSegBody), '[mode] buildModeSeg must not disable any mode (all three selectable in M10)');
  // Persisted + pre-paint applied as html[data-mode].
  check(/crux\.console\.mode/.test(shellHtml), '[mode] mode must persist at localStorage crux.console.mode');
  check(/setAttribute\('data-mode'/.test(shellHtml), '[mode] mode must be applied as html[data-mode] (pre-paint + applyMode)');
  const head = shellHtml.slice(0, shellHtml.indexOf('</head>'));
  check(/setAttribute\('data-mode'/.test(head), '[mode] data-mode must be applied pre-paint (in <head>) to avoid a Pro-density flash');
  // Segmented control: id, buildModeSeg, aria-pressed, sat LEFT of the chips.
  check(/id="modeSeg"/.test(shellHtml), '[mode] topbar must carry the segmented control (id="modeSeg")');
  check(/function buildModeSeg/.test(shellHtml), '[mode] shell.html must build the segmented control (buildModeSeg)');
  check(/modeseg-btn/.test(shellHtml) && /aria-pressed/.test(shellHtml), '[mode] segmented control buttons must set aria-pressed');
  check(shellHtml.indexOf('id="modeSeg"') >= 0 && shellHtml.indexOf('id="topchips"') >= 0 &&
    shellHtml.indexOf('id="modeSeg"') < shellHtml.indexOf('id="topchips"'),
    '[mode] the segmented control must sit LEFT of the chips cluster (modeSeg before topchips)');
  // applyMode re-renders + persists + sets the window flag, and NEVER touches posture.
  const am = funcBody(shellHtml, 'applyMode');
  check(!!am, '[mode] shell.html must define applyMode');
  check(am && /route\(\)/.test(am), '[mode] applyMode must re-render (route()) so the Pro surface appears/disappears');
  // M10: applyMode delegates the window-flag write to the shared setModeSilently
  // (also used by route()'s deep-link-out auto-switch); that helper sets
  // window.CRUX_MODE for render.js proMode(). The guarantee is unchanged.
  check(am && /setModeSilently\(/.test(am), '[mode] applyMode must set the mode via setModeSilently (shared with the route auto-switch)');
  const setModeBody = funcBody(shellHtml, 'setModeSilently');
  check(setModeBody && /window\.CRUX_MODE\s*=/.test(setModeBody), '[mode] setModeSilently must set window.CRUX_MODE for render.js proMode()');
  check(am && !/setPosture|isOperator|CRUX_POSTURE|derivePosture/.test(am),
    '[mode] applyMode must NOT touch posture — mode is presentation, posture is the security boundary');
  // render.js honours the mode: proMode() reads window.CRUX_MODE; renderSections
  // drops pro:true sections in Standard; the Overwatch dashboard strip is Pro-only.
  check(typeof render.proMode === 'function', '[mode] render.js must export proMode()');
  check(/window\.CRUX_MODE/.test(renderSrc), '[mode] render.js proMode() must read window.CRUX_MODE');
  check(/sections\[i\]\.pro/.test(renderSrc), '[mode] renderSections must drop pro:true sections outside Professional mode');
  check(/renderDashStrip/.test(renderSrc) && /proMode\(\)/.test(renderSrc), '[mode] the Overwatch dashboard strip must be Pro-only (proMode()-guarded)');
  // POSTURE INDEPENDENCE (statically): no posture function branches on mode.
  // Extended in M10 to include the 'documents' token (Documents mode is
  // presentation only — posture must be blind to it too).
  const modeTokens = /CRUX_MODE|data-mode|crux\.console\.mode|proMode|professional|documents/;
  ['setPosture', 'applyPosture', 'derivePostureFromServer', 'applyDerivedPosture'].forEach(function (fn) {
    const b = funcBody(shellHtml, fn);
    check(!!b, '[mode] shell.html must define the posture fn ' + fn);
    check(b && !modeTokens.test(b), '[mode] posture fn ' + fn + '() must not branch on mode (presentation ≠ security)');
  });
  ['derivePosture', 'applyMutationGate', 'operatorGatedCall'].forEach(function (fn) {
    const b = funcBody(renderSrc, fn);
    check(!!b, '[mode] render.js must define ' + fn);
    check(b && !modeTokens.test(b), '[mode] render.js ' + fn + '() must not branch on mode (posture is mode-independent)');
  });
  notes.push('mode system: Standard|Professional (+reserved Documents) — persisted, pre-paint, segmented control (aria-pressed, left of chips); posture statically mode-independent.');
})();

// =========================================================================
//  Check 24 — (M8) legacy port-checklist integrity. The LEGACY_PORT manifest in
//  pages.js maps EVERY legacy console section (the 5 scopes at index.html:763 +
//  the 4 renderDash landing cards) to a disposition: home:<page> | ported-pro:
//  <target> | deferred:<reason>. The known legacy inventory is embedded here, so
//  a silently-dropped section fails the build. Nothing may be missing, unlabeled,
//  or stray; every target must resolve.
// =========================================================================
(function checkLegacyPort() {
  const LP = pages.LEGACY_PORT;
  check(LP && typeof LP === 'object', '[port] pages.js must export the LEGACY_PORT manifest');
  // M10: LEGACY_PORT carries a top-level `retired_at` metadata key (NOT a legacy
  // section). It is excluded from the section-inventory checks below; check 28
  // owns the retirement asserts. The section-integrity guarantee is unchanged for
  // the real section keys.
  const META_KEYS = new Set(['retired_at']);
  const sectionKeys = Object.keys(LP || {}).filter(function (k) { return !META_KEYS.has(k); });
  const CX = ['cx-overview', 'cx-activity', 'cx-cost', 'cx-projects', 'cx-work', 'cx-usage', 'cx-documents', 'cx-gates', 'cx-review', 'cx-coord', 'cx-sessions', 'cx-orchestrators', 'cx-punchcards', 'cx-passport', 'cx-identity', 'cx-receipts', 'cx-mediation', 'cx-workbench', 'cx-integrations', 'cx-extensions', 'cx-facts', 'cx-memory', 'cx-tenants', 'cx-lane-weights', 'cx-settings', 'cx-raw'];
  const DX = ['dx-articles', 'dx-readme', 'dx-sites'];
  const GX = ['gx-engrams', 'gx-bench', 'gx-sites', 'gx-factstore'];
  const AX = ['ax-overview', 'ax-activity', 'ax-memory', 'ax-bulk', 'ax-snapshots', 'ax-tools', 'ax-handoff', 'ax-graph', 'ax-storybook', 'ax-dossiers', 'ax-story'];
  const IX = ['ix-index', 'ix-machines', 'ix-rails', 'ix-config', 'ix-sync'];
  const DASH = ['dash-daemon', 'dash-execplans', 'dash-usage', 'dash-mcp'];   // renderDash top cards
  const EXPECTED = [].concat(CX, DX, GX, AX, IX, DASH);
  EXPECTED.forEach(function (id) {
    const s = LP && LP[id];
    check(typeof s === 'string' && s.length > 0, '[port] LEGACY_PORT missing/unlabeled legacy section: ' + id);
    check(typeof s === 'string' && /^(home:|ported-pro:|deferred:)/.test(s), '[port] LEGACY_PORT ' + id + ' has an invalid status label: ' + s);
  });
  const expectedSet = new Set(EXPECTED);
  sectionKeys.forEach(function (id) {
    check(expectedSet.has(id), '[port] LEGACY_PORT has a stray key not in the known legacy inventory: ' + id);
  });
  check(sectionKeys.length === EXPECTED.length,
    '[port] LEGACY_PORT must cover EXACTLY the ' + EXPECTED.length + '-section legacy inventory; got ' + sectionKeys.length);
  // Disposition targets resolve.
  const proPorted = new Set(pages.PRO_PORTED_IDS || []);
  sectionKeys.forEach(function (id) {
    const s = LP[id];
    if (s.indexOf('home:') === 0) {
      const pid = s.slice('home:'.length);
      check(!!pages.PAGES[pid], '[port] ' + id + ' home target is not a real page: ' + pid);
    } else if (s.indexOf('ported-pro:') === 0) {
      const target = s.slice('ported-pro:'.length);
      if (target === 'overwatch-dashboard-strip') {
        check(/renderDashStrip/.test(renderSrc), '[port] ' + id + ' → overwatch-dashboard-strip but render.js has no renderDashStrip');
      } else {
        check(pages.PAGES[target] && pages.PAGES[target].pro === true, '[port] ' + id + ' ported-pro target must be a pro:true page: ' + target);
        check(proPorted.has(target), '[port] ' + id + ' ported-pro target must be listed in PRO_PORTED_IDS: ' + target);
      }
    } else {
      check(s.slice('deferred:'.length).trim().length > 0, '[port] ' + id + ' deferred status must carry a reason');
    }
  });
  proPorted.forEach(function (pid) { check(!!pages.PAGES[pid], '[port] PRO_PORTED page not registered in PAGES: ' + pid); });
  const tally = { home: 0, 'ported-pro': 0, deferred: 0 };
  sectionKeys.forEach(function (id) { tally[LP[id].split(':')[0]]++; });
  notes.push('legacy port: ' + EXPECTED.length + ' sections — ' + tally.home + ' home, ' + tally['ported-pro'] + ' ported-pro, ' + tally.deferred + ' deferred; nothing dropped.');
})();

// =========================================================================
//  Check 25 — (M9) Canvas board. (a) canvasTier is a PURE exported fn with the
//  documented width truth table (500/1200/2000/3000/4000 → xs/s/m/l/xl).
//  (b) the widget registry integrity: every widget carries id/span/minTier/build
//  with unique ids, and the per-tier cumulative counts honour the size-adaptive
//  contract (xs 4 · s ≥6 · m ≥10 · l ≥14 · xl ≥16 — the 4K+ full board).
// =========================================================================
(function checkCanvasBoard() {
  const tier = render.canvasTier;
  check(typeof tier === 'function', '[canvas] render.js must export the pure canvasTier(width,height) fn');
  if (typeof tier === 'function') {
    [[500, 'xs'], [1200, 's'], [2000, 'm'], [3000, 'l'], [4000, 'xl']].forEach(function (row) {
      check(tier(row[0]) === row[1], '[canvas] canvasTier(' + row[0] + ') must be "' + row[1] + '" (got ' + tier(row[0]) + ')');
    });
  }
  const widgets = render.CANVAS_WIDGETS;
  const ORDER = ['xs', 's', 'm', 'l', 'xl'];
  check(Array.isArray(widgets) && widgets.length >= 16, '[canvas] render.CANVAS_WIDGETS must be an array of ≥16 widgets (the 4K+ board); got ' + (widgets ? widgets.length : 'none'));
  const seen = {};
  (widgets || []).forEach(function (w, i) {
    check(w && typeof w.id === 'string' && w.id, '[canvas] widget ' + i + ' missing id');
    check(w && typeof w.span === 'number' && w.span >= 1, '[canvas] widget ' + (w && w.id) + ' must carry a numeric span ≥1');
    check(w && ORDER.indexOf(w.minTier) >= 0, '[canvas] widget ' + (w && w.id) + ' minTier must be one of xs/s/m/l/xl');
    check(w && typeof w.build === 'function', '[canvas] widget ' + (w && w.id) + ' must carry a build() fn');
    if (w && w.id) { check(!seen[w.id], '[canvas] duplicate widget id: ' + w.id); seen[w.id] = true; }
  });
  function upTo(t) { const max = ORDER.indexOf(t); return (widgets || []).filter(function (w) { return ORDER.indexOf(w.minTier) <= max; }).length; }
  check(upTo('xs') === 4, '[canvas] xs tier must expose exactly 4 widgets (single column); got ' + upTo('xs'));
  check(upTo('s') >= 6, '[canvas] s tier must expose ≥6 widgets; got ' + upTo('s'));
  check(upTo('m') >= 10, '[canvas] m tier must expose ≥10 widgets; got ' + upTo('m'));
  check(upTo('l') >= 14, '[canvas] l tier must expose ≥14 widgets; got ' + upTo('l'));
  check(upTo('xl') >= 16, '[canvas] xl (4K+) tier must expose ≥16 widgets; got ' + upTo('xl'));
  // Canvas is a destination with no sub-pills: a nav-family Board|Graph view
  // switch (deep-linkable) IS the page. The shell routes it to render.renderCanvas.
  check((pages.DESTS || []).some(function (d) { return d.id === 'canvas'; }), '[canvas] pages.DESTS must carry the "canvas" destination');
  check(typeof render.renderCanvas === 'function', '[canvas] render.js must export renderCanvas');
  check(/window\.CruxRender\.renderCanvas/.test(shellHtml) && /destId === 'canvas'/.test(shellHtml), '[canvas] shell.html must route the canvas destination to render.renderCanvas');
  check(/data-view/.test(renderSrc) && /\['board', 'Board'\]/.test(renderSrc) && /\['graph', 'Graph'\]/.test(renderSrc) && renderSrc.indexOf("'#/canvas/' + vid") >= 0,
    '[canvas] Canvas must carry a Board|Graph view switch (deep-linkable #/canvas/<view>)');
  check(/setTimeout\(paint, 200\)/.test(renderSrc), '[canvas] the board must recompose on a debounced resize');
  notes.push('canvas board: canvasTier xs/s/m/l/xl truth table + ' + (widgets ? widgets.length : 0) + '-widget registry (xs' + upTo('xs') + '·s' + upTo('s') + '·m' + upTo('m') + '·l' + upTo('l') + '·xl' + upTo('xl') + '); Board|Graph deep-linkable.');
})();

// =========================================================================
//  Check 26 — (M9) Canvas graph honesty + wiring. (a) Deterministic layout —
//  NO Math.random anywhere in render.js. (b) buildGraphModel edges reference
//  ONLY the real endpoint field names (grounded in api.js/handlers) and drop any
//  dangling edge (real edges only). (c) parseFocus (pure, exported) handles
//  work:/session:/project:/passport: and composite ids. (d) launch-point markers
//  present on the fleet (render) + work/project/gate (pages) renderers.
// =========================================================================
(function checkCanvasGraph() {
  check(!/Math\.random/.test(renderSrc), '[graph] canvas/graph layout must be deterministic — no Math.random in render.js');
  const gm = funcBody(renderSrc, 'buildGraphModel');
  check(!!gm, '[graph] render.js must define buildGraphModel');
  const GROUNDED = ['projects', 'project_id', 'work', 'items', 'title', 'created_by_passport', 'assignee_passport',
    'pending', 'action_id', 'work_id', 'requested_by_passport', 'target_state', 'passports', 'reputation_tier',
    'active_sessions', 'session_id_hex', 'passport_id', 'intent', 'execplan_slug', 'links', 'owner', 'repo', 'role', 'plane_id'];
  GROUNDED.forEach(function (f) {
    check(gm && gm.indexOf(f) >= 0, '[graph] buildGraphModel must reference the real endpoint field "' + f + '" (edges grounded in real handlers)');
  });
  check(gm && /index\[e\.from\]\s*&&\s*index\[e\.to\]/.test(gm), '[graph] buildGraphModel must keep ONLY real edges (both endpoints resolved) — no invented relations');
  check(/coord\/active/.test(renderSrc), '[graph] the graph must read live sessions from /v1/coord/active (404-tolerant)');
  // Deterministic layered layout by node type.
  check(/function layoutGraph/.test(renderSrc), '[graph] render.js must define the deterministic layoutGraph');
  // Focus deep-link parser — pure, exported, first-colon split.
  const pf = render.parseFocus;
  check(typeof pf === 'function', '[graph] render.js must export the pure parseFocus() deep-link parser');
  if (typeof pf === 'function') {
    ['work', 'session', 'project', 'passport'].forEach(function (ty) {
      const r = pf(ty + ':abc123');
      check(r && r.type === ty && r.id === 'abc123', '[graph] parseFocus must handle ' + ty + ':<id>');
    });
    const c = pf('work:execplan:unified-shell-console');
    check(c && c.type === 'work' && c.id === 'execplan:unified-shell-console', '[graph] parseFocus must split on the FIRST colon (composite ids preserved)');
    check(pf('') === null && pf('nocolon') === null && pf(null) === null, '[graph] parseFocus must reject malformed focus params');
  }
  // Focus centres + highlights the node neighbourhood (dims the rest).
  const dg = funcBody(renderSrc, 'drawGraph');
  check(dg && /focus/.test(dg) && /is-dim/.test(renderSrc), '[graph] a focus deep-link must centre + highlight the node neighbourhood (dim the rest via .is-dim)');
  // Launch-point markers: fleet (render) + work/project/gate (pages).
  const fr = funcBody(renderSrc, 'fleetRow');
  check(fr && /cx-graphlink/.test(fr) && fr.indexOf('#/canvas/graph?focus=session:') >= 0, '[graph] the fleet row must carry a "View graph" launch point (focus=session:…)');
  check(/function graphLink/.test(pagesSrc) && pagesSrc.indexOf('#/canvas/graph?focus=') >= 0, '[graph] pages.js must define graphLink() (the cross-feature launch control)');
  ['buildWork', 'buildProjects', 'buildGates'].forEach(function (fn) {
    const b = funcBody(pagesSrc, fn);
    check(b && /graphLink\(/.test(b), '[graph] ' + fn + ' must carry a "View graph" launch point (graphLink)');
  });
  // Card nodes colour by type from theme tokens (project=acc, passport=trust, session=ok, gate=warn).
  check(/\.cv-card\[data-type="project"\]\s*\{[^}]*var\(--acc\)/.test(shellHtml) && /\.cv-card\[data-type="passport"\]\s*\{[^}]*var\(--trust\)/.test(shellHtml) &&
    /\.cv-card\[data-type="session"\]\s*\{[^}]*var\(--ok\)/.test(shellHtml) && /\.cv-card\[data-type="gate"\]\s*\{[^}]*var\(--warn\)/.test(shellHtml),
    '[graph] node cards must colour by type from theme tokens (project=acc · passport=trust · session=ok · gate=warn)');
  // Pan (drag on the stage) + zoom (wheel).
  check(/canvas-graph-stage/.test(shellHtml) && /addEventListener\('wheel'/.test(renderSrc) && /addEventListener\('mousedown'/.test(renderSrc),
    '[graph] the graph must support pan (mousedown drag) + zoom (wheel)');
  notes.push('canvas graph: real-edge-only model (grounded fields, dangling edges dropped), deterministic layered layout, pan+zoom, focus parser (work/session/project/passport), launch points on fleet/work/project/gate.');
})();

// =========================================================================
//  Check 27 — (M10) Documents mode: the console-as-reader. (a) three-mode
//  registry all ENABLED (no reserved/disabled slot); pre-paint honours
//  documents. (b) the reader entry point + 3-zone layout + ~72ch reading
//  measure + evidence-panel material (EvidenceCards / Receipt rows / coverage).
//  (c) real sources (tenants + per-tenant chunks named method + facts) with the
//  demo Proof fixture behind demoData('docsReader'). (d) deep-link-out auto-
//  switch (a real destination hash while in documents mode flips back to
//  standard). (e) posture-independence still statically clean (extends check 23).
// =========================================================================
(function checkDocumentsMode() {
  // (a) The three presentation modes remain, all enabled — density (standard |
  // professional) + documents (the Explore reader). The visible toggle is SURFACES.
  check(/DEFAULT_MODE = 'standard'/.test(shellHtml) && /'professional'/.test(shellHtml) && /id === 'documents'/.test(shellHtml),
    '[documents] standard | professional | documents modes must remain selectable');
  check(!/soon:\s*true/.test(shellHtml), '[documents] Documents must be activated (no soon:true reserved marker)');
  check(/isSelectableMode/.test(shellHtml) && /id === 'documents'/.test(shellHtml),
    '[documents] applyMode must treat documents as a selectable, paintable mode');
  const head = shellHtml.slice(0, shellHtml.indexOf('</head>'));
  check(/'documents'/.test(head) && /data-mode/.test(head),
    '[documents] pre-paint (<head>) must apply data-mode=documents to avoid a reader-layout flash');
  // (b) Reader entry point + 3-zone layout + ~72ch measure + evidence markers.
  check(typeof render.renderDocuments === 'function', '[documents] render.js must export renderDocuments (the reader entry point)');
  check(/renderDocuments/.test(shellHtml), '[documents] shell.html must route documents mode to render.renderDocuments');
  check(/\.doc-reader\b/.test(shellHtml) && /\.doc-evidence\b/.test(shellHtml),
    '[documents] shell.html must style the 3-zone reader (.doc-reader + .doc-evidence panel)');
  check(/\.doc-main\s*\{[^}]*max-width:\s*72ch/.test(shellHtml),
    '[documents] the reading surface must carry the ~72ch measure rule (.doc-main { max-width: 72ch })');
  check(/function renderDocEvidence/.test(renderSrc), '[documents] render.js must build the evidence panel (renderDocEvidence)');
  check(/doc-evcard/.test(renderSrc) && /doc-receipt/.test(renderSrc),
    '[documents] the evidence panel must carry EvidenceCards + Receipt rows (ported Proof material)');
  // (c) Real sources grounded + demo Proof fixture behind the demo choke point.
  check(/consoleTenantsByTenantIdChunks/.test(renderSrc),
    '[documents] per-tenant document chunks must load via the named CruxApi method (no raw fetch)');
  check(renderSrc.indexOf('/v1/console/tenants') >= 0 && renderSrc.indexOf('/v1/console/facts') >= 0,
    '[documents] the reader must ground on real /v1/console/tenants + /v1/console/facts');
  check(/demoData\('docsReader'\)/.test(renderSrc),
    '[documents] the demo Proof reader must come from demoData(\'docsReader\') (demoOn()-guarded choke point)');
  check(pages.CruxDemo && pages.CruxDemo.docsReader && Array.isArray(pages.CruxDemo.docsReader.sections) && pages.CruxDemo.docsReader.sections.length > 0,
    '[documents] CruxDemo.docsReader fixture (ported Proof narrative) must be present');
  check(Array.isArray(pages.CruxDemo.docsReader.evidence) && pages.CruxDemo.docsReader.evidence.length > 0 &&
        Array.isArray(pages.CruxDemo.docsReader.receipts) && pages.CruxDemo.docsReader.receipts.length > 0,
    '[documents] the docsReader fixture must carry evidence + receipts (the full reader composition)');
  // (d) Deep-link-out auto-switch + reader routing.
  const rt = funcBody(shellHtml, 'route');
  check(rt && /CRUX_MODE === 'documents'/.test(rt) && /setModeSilently\('standard'\)/.test(rt),
    '[documents] route() must auto-switch documents→standard on a deep link to a real destination');
  check(rt && /renderDocumentsRoute/.test(rt),
    '[documents] route() must render the reader for #/documents (renderDocumentsRoute)');
  // (e) Posture independence (statically): documents is presentation-only.
  const modeTokens = /CRUX_MODE|data-mode|crux\.console\.mode|proMode|professional|documents/;
  ['setPosture', 'applyPosture', 'derivePostureFromServer', 'applyDerivedPosture'].forEach(function (fn) {
    const b = funcBody(shellHtml, fn);
    check(b && !modeTokens.test(b), '[documents] posture fn ' + fn + '() must not branch on mode (incl. documents)');
  });
  const rd = funcBody(renderSrc, 'renderDocuments');
  check(rd && !/setPosture|derivePosture|applyMutationGate|CRUX_POSTURE|isOperator/.test(rd),
    '[documents] renderDocuments must not touch posture (presentation ≠ the security boundary)');
  notes.push('documents mode (M10): three-mode registry all enabled · ~72ch reader + evidence panel (EvidenceCards/Receipts/coverage) · real tenants+facts sources + demoOn() Proof fixture · deep-link-out auto-switch · posture statically mode-independent.');
})();

// =========================================================================
//  Check 28 — (M10→M12) legacy retirement + removal. (a) LEGACY_PORT.retired_at
//  marker survives (the formal retirement date is recorded history, not live
//  state). (b) the v2 shell no longer carries the old "(legacy — retired, kept
//  as fallback)" copy nor a live link() to /console/legacy — it now states the
//  legacy console has been REMOVED and this v2 console is its full replacement.
//  (c) console.rs no longer defines serve_console_legacy: the route was deleted,
//  so /console/legacy now 404s (verified structurally — the handler symbol is
//  absent from the served-console source).
// =========================================================================
(function checkRetirement() {
  check(pages.LEGACY_PORT && pages.LEGACY_PORT.retired_at === '2026-07-03',
    '[retire] LEGACY_PORT.retired_at must be "2026-07-03" (the formal legacy-console retirement date)');
  // The old "kept as fallback" copy must be GONE — the legacy console is removed,
  // not retained as a reachable fallback.
  check(!/\(legacy — retired, kept as fallback\)/.test(pagesSrc),
    '[retire] the old "(legacy — retired, kept as fallback)" copy must be gone (legacy console is fully removed, not a fallback)');
  // …replaced by explicit removal copy.
  check(/\(legacy — removed, fully replaced by this console\)/.test(pagesSrc),
    '[retire] the v2 shell must carry the "(legacy — removed, fully replaced by this console)" removal copy');
  // No LIVE link() to the now-404 /console/legacy route may survive.
  check(!/link\([^)]*['"]\/console\/legacy['"]/.test(pagesSrc),
    '[retire] the v2 shell must not render a live link() to the removed /console/legacy route');
  const consoleRsPath = path.join(DIR, '..', '..', 'src', 'console.rs');
  let consoleRs = '';
  try { consoleRs = fs.readFileSync(consoleRsPath, 'utf8'); }
  catch (e) { check(false, '[retire] could not read console.rs at ' + consoleRsPath + ': ' + e.message); }
  // The legacy handler must be GONE — the route was removed, so /console/legacy 404s.
  check(consoleRs.indexOf('fn serve_console_legacy') < 0,
    '[retire] console.rs must no longer define serve_console_legacy (legacy route removed → /console/legacy 404s)');
  notes.push('retirement (M10→M12): LEGACY_PORT.retired_at=2026-07-03 · v2 removal copy (no "kept as fallback", no live /console/legacy link) · console.rs serve_console_legacy handler removed (route 404s).');
})();

// =========================================================================
//  Check 29 — (M11) CruxApiRead curated read-POST client. Searches are POST
//  reads; the GET-only CruxApi cannot express them, so api.js carries a THIRD
//  frozen client, CruxApiRead, from EXACTLY the curated READ_POST_ROUTES set
//  (retrieval, not mutation). render.js is the only shipped file that calls it
//  (pages.js/shell.html never do); the through-client rule now allows it
//  alongside CruxApi (GET reads) + CruxApiGated (operator writes).
// =========================================================================
(function checkReadPostClient() {
  const apiSrc = fs.readFileSync(path.join(DIR, 'api.js'), 'utf8');
  check(/const CruxApiRead = Object\.freeze\(/.test(apiSrc), '[read-post] api.js must define CruxApiRead');
  check(/window\.CruxApiRead\s*=\s*CruxApiRead/.test(apiSrc), '[read-post] api.js must expose window.CruxApiRead');
  check(/window\.CRUX_READ_POST_ROUTES\s*=\s*READ_POST_ROUTES/.test(apiSrc), '[read-post] api.js must expose window.CRUX_READ_POST_ROUTES');

  // The curated read-POST set the M11 plan authorises — the ONLY read POSTs.
  const EXPECTED = [
    ['POST', '/v1/query/text-search'],
    ['POST', '/v1/query/text-search/expand'],
    ['POST', '/v1/query/graph-expand'],
    ['POST', '/v1/query/time-range'],
    ['POST', '/v1/console/engine/search']
  ];
  const arrM = apiSrc.match(/const READ_POST_ROUTES = Object\.freeze\(\[([\s\S]*?)\]\);/);
  check(!!arrM, '[read-post] api.js must declare the READ_POST_ROUTES array');
  const declared = [];
  if (arrM) {
    const re = /\[\s*'([A-Z]+)'\s*,\s*'([^']+)'\s*\]/g;
    let m;
    while ((m = re.exec(arrM[1])) !== null) { declared.push([m[1], m[2]]); }
  }
  const norm = function (pairs) { return pairs.map(function (p) { return p[0] + ' ' + p[1]; }).sort(); };
  check(JSON.stringify(norm(declared)) === JSON.stringify(norm(EXPECTED)),
    '[read-post] READ_POST_ROUTES must be EXACTLY the curated set; got ' + JSON.stringify(norm(declared)));

  // Each declared read-POST has a matching CruxApiRead fetch (verb + path stem).
  declared.forEach(function (pair) {
    const stem = pair[1].split('{')[0].replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const hasFetch = new RegExp('fetch\\(`' + stem + "[^`]*`,\\s*\\{\\s*method:\\s*'" + pair[0] + "'").test(apiSrc);
    check(hasFetch, '[read-post] CruxApiRead missing a ' + pair[0] + ' fetch for ' + pair[1]);
  });

  // Static containment: search goes ONLY through render.js's CruxApiRead — the
  // shell + page registry never touch the read-POST client directly.
  ['pages.js', 'shell.html'].forEach(function (f) {
    const src = fs.readFileSync(path.join(DIR, f), 'utf8');
    check(!/CruxApiRead/.test(src), '[read-post] ' + f + ' must not reference CruxApiRead (search lives in render.js renderExplorer)');
  });
  check(/window\.CruxApiRead/.test(renderSrc), '[read-post] render.js must reach searches through window.CruxApiRead');
  notes.push('read-post client (M11): CruxApiRead = ' + declared.length + ' curated retrieval POSTs (through-client rule extended; render.js is the sole caller).');
})();

// =========================================================================
//  Check 30 — (M11) Documents reader renders. renderDocuments must paint a
//  main pane (.doc-main) + a document tree SYNCHRONOUSLY — even before (or
//  without) the /v1/console/tenants fetch resolving. The earlier bug deferred
//  ALL painting behind that fetch, so a slow/hung/unreachable daemon left the
//  reader blank (no .doc-main, empty tree). Exercised with a minimal hand-rolled
//  DOM (jsdom-independent) using the SAME {railHost} ctx shape the shell passes,
//  and a never-resolving CruxApi.get (the daemon-hang case).
// =========================================================================
(function checkDocumentsReaderPaints() {
  function mkEl(tag) {
    const node = {
      tagName: String(tag || 'div').toUpperCase(), nodeType: 1,
      childNodes: [], _attrs: {}, className: '', style: {},
      setAttribute: function (k, v) { this._attrs[k] = String(v); if (k === 'class') { this.className = String(v); } },
      getAttribute: function (k) { return (k in this._attrs) ? this._attrs[k] : null; },
      appendChild: function (c) { this.childNodes.push(c); c.parentNode = this; return c; },
      addEventListener: function () {},
      querySelectorAll: function (sel) { const out = []; collect(this, sel, out); return out; }
    };
    Object.defineProperty(node, 'textContent', { get: function () { return this._text || ''; }, set: function (v) { this._text = String(v); this.childNodes.length = 0; } });
    Object.defineProperty(node, 'innerHTML', { get: function () { return this._html || ''; }, set: function (v) { this._html = String(v); } });
    Object.defineProperty(node, 'firstChild', { get: function () { return this.childNodes[0] || null; } });
    Object.defineProperty(node, 'children', { get: function () { return this.childNodes.filter(function (n) { return n.nodeType === 1; }); } });
    return node;
  }
  function collect(node, sel, out) {
    const cls = sel.charAt(0) === '.' ? sel.slice(1) : sel;
    (node.childNodes || []).forEach(function (c) {
      if (c && c.nodeType === 1) {
        if (String(c.className).split(/\s+/).indexOf(cls) >= 0) { out.push(c); }
        collect(c, sel, out);
      }
    });
  }
  const savedDoc = global.document, savedWin = global.window;
  global.document = { createElement: mkEl, createElementNS: function (ns, tag) { return mkEl(tag); }, createTextNode: function (t) { return { nodeType: 3, textContent: String(t), childNodes: [] }; } };
  global.window = { CruxApi: { get: function () { return new Promise(function () { /* daemon hang — never resolves */ }); } } };
  try {
    // (M14) #/documents with no docId lands on the corpus tile canvas — its
    // zero-network base set (reference docs + Explorer) must paint before any
    // fetch resolves, preserving the daemon-hang guarantee for the landing.
    const host = mkEl('div');
    const rail = mkEl('nav');
    render.renderDocuments(host, { summary: null, docId: null, railHost: rail });
    check(host.querySelectorAll('.doc-reader').length === 1, '[documents] renderDocuments must paint the reader shell synchronously');
    check(host.querySelectorAll('.cvx-surface').length === 1, '[documents] the #/documents landing must paint the corpus tile canvas synchronously (M14)');
    check(host.querySelectorAll('.cvx-node').length >= 4, '[documents] the corpus canvas must paint its zero-network tiles synchronously (reference docs + Explorer)');
    check(rail.querySelectorAll('.nav-item').length >= 3, '[documents] renderDocuments must populate the Explore rail synchronously (Canvas + Explorer + surface pages, >=3 nav-items)');
    // The 3-zone reader stays intact for explicit reader docs (M11 guarantee).
    const host2 = mkEl('div');
    const rail2 = mkEl('nav');
    render.renderDocuments(host2, { summary: null, docId: 'proof', railHost: rail2 });
    check(host2.querySelectorAll('.doc-main').length === 1, '[documents] renderDocuments must still paint a .doc-main synchronously for reader docs (daemon-hang case)');
    check(host2.querySelectorAll('.doc-reader').length === 1, '[documents] renderDocuments must paint the reader synchronously for reader docs');
    notes.push('documents (M11+M14): #/documents lands on the corpus tile canvas (zero-network tiles paint synchronously); reader docs still paint .doc-main + a >=3-item Explore rail under a never-resolving daemon. Docs/corpora reached via tiles + Explorer results.');
  } catch (e) {
    check(false, '[documents] renderDocuments threw on the synchronous paint: ' + e.message);
  } finally {
    if (savedDoc === undefined) { delete global.document; } else { global.document = savedDoc; }
    if (savedWin === undefined) { delete global.window; } else { global.window = savedWin; }
  }
})();

// =========================================================================
//  Check 31 — (M11) Explorer destination. A new nav destination (search icon,
//  key '8') with a renderExplorer entry point; the shell special-cases it (like
//  Canvas) and provides the 'search' icon. Reads only → posture-independent.
// =========================================================================
(function checkExplorerDestination() {
  const explorer = (pages.DESTS || []).filter(function (d) { return d.id === 'explorer'; })[0];
  check(!!explorer, '[explorer] pages.DESTS must register the explorer destination');
  if (explorer) {
    check(explorer.railHidden === true, '[explorer] explorer destination must be railHidden — reached via the top-right search field + the top of the Explore menu, not the Command rail');
    check(explorer.icon === 'search', '[explorer] explorer destination must use the search icon');
  }
  check(/search:\s*'<svg/.test(shellHtml), '[explorer] shell.html must define the "search" icon glyph');
  check(/destId === 'explorer'/.test(shellHtml) && /renderExplorer/.test(shellHtml),
    '[explorer] shell.html must route the explorer destination to render.renderExplorer');
  check(typeof render.renderExplorer === 'function', '[explorer] render.js must export renderExplorer (the search surface entry point)');
  notes.push('explorer destination (M11): search icon + key 8, shell special-cases like Canvas, render.renderExplorer surfaces Local | WikiCrux cards (real fields), reads-only → shows in every posture.');
})();

// =========================================================================
//  Check 32 — (M12) JSX surface port. All 11 WebCrux Proof surfaces
//  (webcrux-surfaces-demo-v3.jsx NAV, line 3028) are the Documents-mode surface
//  list: render.DOC_SURFACES carries the 11 ids; each has a render function
//  (Proof reuses renderDocuments; the other ten are renderDocSurface_<id>);
//  pages.JSX_PORT covers all 11 with a source_line + status + component; the
//  rail nav is built from DOC_SURFACES and each surface is a #/documents/<id>
//  route reachable through renderDocuments.
// =========================================================================
(function checkSurfacePort() {
  const NAV_IDS = ['proof', 'watch', 'ask', 'living', 'deps', 'signals', 'diff', 'sourcing', 'lanes', 'domains', 'reverse'];
  // render.DOC_SURFACES — the ported NAV.
  const surfaces = render.DOC_SURFACES || [];
  check(surfaces.length === 11, '[surfaces] render.DOC_SURFACES must list exactly 11 surfaces (got ' + surfaces.length + ')');
  const surfaceIds = surfaces.map(function (s) { return s.id; });
  NAV_IDS.forEach(function (id) {
    check(surfaceIds.indexOf(id) >= 0, '[surfaces] render.DOC_SURFACES missing the "' + id + '" surface');
    check(surfaces.some(function (s) { return s.id === id && s.label && s.icon; }), '[surfaces] surface "' + id + '" must carry a label + icon (the ported NAV entry)');
  });
  // render.renderDocSurface dispatch + a render fn per non-Proof surface.
  check(typeof render.renderDocSurface === 'function', '[surfaces] render.js must export renderDocSurface (the surface dispatch)');
  check(/var DOC_SURFACE_RENDER = \{/.test(renderSrc), '[surfaces] render.js must declare the DOC_SURFACE_RENDER dispatch table');
  NAV_IDS.forEach(function (id) {
    if (id === 'proof') { check(typeof render.renderDocuments === 'function', '[surfaces] Proof must reuse renderDocuments (the M11 reader)'); return; }
    check(new RegExp('function renderDocSurface_' + id + '\\b').test(renderSrc), '[surfaces] render.js must define renderDocSurface_' + id);
  });
  // pages.JSX_PORT — every surface mapped with source_line + status + component.
  const port = pages.JSX_PORT || {};
  check(Object.keys(port).length === 11, '[surfaces] pages.JSX_PORT must cover exactly 11 surfaces (got ' + Object.keys(port).length + ')');
  NAV_IDS.forEach(function (id) {
    const e = port[id];
    check(!!e, '[surfaces] JSX_PORT missing surface: ' + id);
    if (e) {
      check(typeof e.source_line === 'number' && e.source_line > 0, '[surfaces] JSX_PORT.' + id + ' must carry a numeric source_line');
      check(/^real:/.test(e.status) || e.status === 'demo-surface', '[surfaces] JSX_PORT.' + id + ' status must be real:<endpoint> or demo-surface (got ' + e.status + ')');
      check(typeof e.component === 'string' && renderSrc.indexOf(e.component) >= 0, '[surfaces] JSX_PORT.' + id + ' component "' + e.component + '" must exist in render.js');
    }
  });
  // Rail nav + route reachability: the rail tree is built from DOC_SURFACES, each
  // surface navigates to #/documents/<id>, and renderDocuments dispatches surfaces.
  check(/DOC_SURFACES\.forEach/.test(renderSrc), '[surfaces] buildDocTree must render the 11-surface nav from DOC_SURFACES');
  check(/isDocSurface/.test(renderSrc) && /renderDocSurface\(/.test(renderSrc), '[surfaces] renderDocuments must dispatch non-Proof surfaces via isDocSurface + renderDocSurface');
  check(renderSrc.indexOf("'#/documents/' + s.id") >= 0, '[surfaces] surface nav items must deep-link to #/documents/<id>');
  notes.push('surface port (M12): 11/11 WebCrux surfaces in DOC_SURFACES + JSX_PORT; Proof→reader, 10× renderDocSurface_<id>; rail nav from DOC_SURFACES; #/documents/<id> routes.');
})();

// =========================================================================
//  Check 33 — (M12) real-vs-demo honesty. A JSX_PORT 'real:<endpoint>' surface
//  reads through the api.js client (fetchJSON → window.CruxApi.get); a
//  'demo-surface' renders its fixture ONLY behind the demoOn()-guarded choke
//  point (surfaceDemo → demoData) and carries an honest empty state. Nothing is
//  fabricated as if real, and every colour in the new surface CSS is a var(--…).
// =========================================================================
(function checkSurfaceHonesty() {
  const port = pages.JSX_PORT || {};
  // surfaceDemo is the fixture choke point — it must read via demoData().
  const sd = funcBody(renderSrc, 'surfaceDemo');
  check(!!sd && /demoData\(/.test(sd), '[honesty] surfaceDemo must read fixtures via the demoData() choke point');
  Object.keys(port).forEach(function (id) {
    if (id === 'proof') { return; }   // the reader's honesty is covered by check 27
    const body = funcBody(renderSrc, port[id].component);
    check(!!body, '[honesty] could not extract ' + port[id].component + ' body');
    if (!body) { return; }
    if (/^real:/.test(port[id].status)) {
      // Real surfaces read through the api.js client — the literal-GET helper
      // (fetchJSON), a named parameterised-read helper (activityRows / fetchVia →
      // CruxApi.<method>), or a curated read-POST (readPost → CruxApiRead). All
      // route through window.Crux* — never a raw fetch.
      check(/(?:fetchJSON|activityRows|fetchVia|projCall|readPost)\(/.test(body),
        '[honesty] real surface ' + id + ' must read via the api.js client (fetchJSON / named CruxApi method / readPost)');
    } else {
      check(/surfaceDemo\(/.test(body), '[honesty] demo-surface ' + id + ' must read its fixture only via the surfaceDemo() choke point');
      check(/docSurfaceEmpty\(/.test(body), '[honesty] demo-surface ' + id + ' must show an honest empty state when demo is off (docSurfaceEmpty)');
    }
  });
  // The four real surfaces (+ Proof reader) are named in JSX_PORT with an endpoint.
  const realCount = Object.keys(port).filter(function (id) { return /^real:/.test(port[id].status); }).length;
  check(realCount >= 4, '[honesty] at least 4 surfaces must be wired to real endpoints (watch/diff/lanes/domains + Proof reader); got ' + realCount);
  // Every colour in the new surface CSS block is a theme token (no hex/rgb).
  const cssM = shellHtml.match(/M12-SURFACE-CSS-START([\s\S]*?)M12-SURFACE-CSS-END/);
  check(!!cssM, '[honesty] shell.html must delimit the M12 surface CSS block (colour audit region)');
  if (cssM) {
    const block = cssM[1];
    check(!/#[0-9a-fA-F]{3,8}\b/.test(block), '[honesty] the M12 surface CSS must use only var(--…) tokens — a hex literal was found');
    check(!/\brgba?\(/.test(block), '[honesty] the M12 surface CSS must use only var(--…) tokens — an rgb()/rgba() literal was found');
  }
  notes.push('surface honesty (M12): real surfaces read via fetchJSON (CruxApi); demo surfaces render fixtures only behind surfaceDemo()/demoData() + carry honest empty states; new surface CSS is 100% var(--…) tokens.');
})();

// =========================================================================
//  Check 34 — (M13a) SAFE control parity: the genuine destructive/write
//  controls STAY operator-gated + disabled. M13a introduces ZERO new live
//  writes: the 17 enumerated write controls + the 5 controls the audit flagged
//  as possibly-mislabeled "mutations" (all GROUNDED as still-side-effecting →
//  conservatively kept gated) all remain in MUTATING_ACTIONS, each mapping to a
//  mut:true control that render.js disables. The set of ops M13a wired live is
//  the NON-mutating workbench GET reads (asserted in check 35) — never any of
//  these. This is the hard-safety assertion for the milestone.
// =========================================================================
(function checkSafeControlParity() {
  const WIRED = (render && render.WIRED_WRITES) || {};
  // The write controls that STAY operator-gated + disabled after the M13b flip.
  // Each is ungroundable in this UI (no groundable route/body) or would break the
  // curated no-arbitrary-mutation invariant — and must NOT be in WIRED_WRITES.
  const STILL_GATED = [
    'Add repo', 'Set as planning repo', 'Queue ingest', 'Install',
    'Apply defaults to all tenants', 'Run sweep now', 'Export audit bundle', 'Send'
  ];

  const mut = new Set(pages.MUTATING_ACTIONS || []);
  STILL_GATED.forEach(function (label) {
    check(mut.has(label), '[m13b] still-gated write control missing from MUTATING_ACTIONS: ' + label);
    check(!WIRED[label], '[m13b] still-gated control "' + label + '" must NOT be in WIRED_WRITES (it stays disabled)');
  });

  // Every MUTATING_ACTIONS entry still maps to a mut:true control (belt-and-braces
  // over the static sections + both build() branches; same walk as check 4).
  const mutLabels = new Set();
  Object.keys(pages.PAGES).forEach(function (id) {
    walkPage(pages.PAGES[id], function (c) { if (c.mut === true && c.label) { mutLabels.add(String(c.label)); } });
  });
  (pages.MUTATING_ACTIONS || []).forEach(function (label) {
    check(mutLabels.has(label), '[m13b] MUTATING_ACTIONS "' + label + '" has no mut:true control');
  });

  // Partition invariant: every MUTATING_ACTIONS entry is EITHER live-wired
  // (WIRED_WRITES) OR still-gated — never both, never neither.
  (pages.MUTATING_ACTIONS || []).forEach(function (label) {
    const wired = !!WIRED[label], gated = STILL_GATED.indexOf(label) >= 0;
    check(wired !== gated, '[m13b] MUTATING_ACTIONS "' + label + '" must be exactly one of live-wired / still-gated (wired=' + wired + ', gated=' + gated + ')');
  });

  // render.js STILL keeps the gated path: applyMutationGate DISABLES a still-gated
  // control (not just hides it) — the disabled half keeps it inert for operators.
  check(/target && 'disabled' in target/.test(renderSrc) && /target\.disabled = true/.test(renderSrc),
    '[m13b] applyMutationGate must still disable a still-gated input/button');
  check(/wired in M3\+/.test(renderSrc), '[m13b] render.js must still tag a still-gated write with "wired in M3+"');

  // Each still-gated control is documented in CONTROL_DIFF._grounding with a reason.
  const grounding = (pages.CONTROL_DIFF || {})._grounding || {};
  STILL_GATED.forEach(function (label) {
    check(typeof grounding[label] === 'string' && grounding[label].length > 0,
      '[m13b] CONTROL_DIFF._grounding must record why "' + label + '" stays gated');
  });
  notes.push('m13b partition: ' + Object.keys(WIRED).length + ' write controls live-wired (guard harness) + ' + STILL_GATED.length + ' stay operator-gated + disabled (ungroundable/invariant-breaking, documented in _grounding).');
})();

// =========================================================================
//  Check 35 — (M13a) native workbench port + CONTROL_DIFF coverage. The
//  CONTROL_DIFF manifest covers every legacy CX page; cx-workbench is a native
//  page that loads the /v1/workbench/contract GET and renders its GET read
//  tools; and every op the workbench newly wires live is NON-mutating (a GET on
//  the allowlisted read client — never a mutation route, never the gated write
//  client).
// =========================================================================
(function checkWorkbenchAndControlDiff() {
  const CD = pages.CONTROL_DIFF;
  check(CD && typeof CD === 'object', '[m13a] pages.js must export the CONTROL_DIFF manifest');
  // Coverage: every legacy CX page (the 26) has a diff entry with the required shape.
  LEGACY_26.forEach(function (id) {
    const e = CD && CD[id];
    check(!!e, '[m13a] CONTROL_DIFF missing legacy CX page: ' + id);
    if (e) {
      check(e.legacy && typeof e.legacy === 'object', '[m13a] CONTROL_DIFF.' + id + ' must carry a grounded `legacy` inventory');
      check(Array.isArray(e.v2_present), '[m13a] CONTROL_DIFF.' + id + ' must carry v2_present[]');
      check(Array.isArray(e.v2_missing_read), '[m13a] CONTROL_DIFF.' + id + ' must carry v2_missing_read[] (the M13a-eligible worklist)');
      check(Array.isArray(e.v2_gated_write), '[m13a] CONTROL_DIFF.' + id + ' must carry v2_gated_write[] (the M13b worklist)');
    }
  });
  // Every v2_gated_write label across the manifest is actually gated in MUTATING_ACTIONS.
  const mut = new Set(pages.MUTATING_ACTIONS || []);
  LEGACY_26.forEach(function (id) {
    const e = CD && CD[id];
    (e && e.v2_gated_write || []).forEach(function (label) {
      check(mut.has(label), '[m13a] CONTROL_DIFF.' + id + ' lists gated write "' + label + '" not in MUTATING_ACTIONS');
    });
  });

  // Native workbench: loads the contract GET + has a build (no link-only fallback).
  const wb = pages.PAGES['cx-workbench'];
  check(wb && wb.load && wb.load.endpoint === '/v1/workbench/contract', '[m13a] cx-workbench must load GET /v1/workbench/contract');
  check(wb && wb.load && typeof wb.load.build === 'function', '[m13a] cx-workbench must have a live build (buildWorkbench)');

  // buildWorkbench wires the workbench GET read tools through the api.js GET client.
  const WB_GET_METHODS = ['workbenchApiDrift', 'workbenchCommandLedger', 'workbenchReasoningTimeline', 'workbenchAuditTriage', 'workbenchBrief'];
  WB_GET_METHODS.forEach(function (m) {
    check(pagesSrc.indexOf(m) >= 0, '[m13a] buildWorkbench must wire the GET read tool ' + m);
  });

  // The workbench read self-loader is GET-ONLY: it reads through CruxApi and never
  // POSTs / never touches the gated write client. (A newly-wired op is a read.)
  const fw = funcBody(renderSrc, 'fetchWorkbench');
  check(!!fw, '[m13a] render.js must define fetchWorkbench (the workbench GET self-loader)');
  if (fw) {
    check(/window\.CruxApi\b/.test(fw), '[m13a] fetchWorkbench must read through window.CruxApi');
    check(!/CruxApiGated/.test(fw), '[m13a] fetchWorkbench must never touch the gated write client');
    check(!/method:\s*'(POST|PUT|PATCH|DELETE)'/.test(fw), '[m13a] fetchWorkbench must be GET-only (no write verb)');
  }
  check(typeof render === 'object', '[m13a] render.js module must load');
  const lw = funcBody(renderSrc, 'loadWorkbenchRead');
  check(!!lw && /fetchWorkbench\(/.test(lw), '[m13a] loadWorkbenchRead must paint via the GET-only fetchWorkbench');

  // Every workbench route the port wires live is an allowlisted GET in api.js
  // (LITERAL_GET_PATHS) — proof no wired op is a mutation route.
  const apiSrc = fs.readFileSync(path.join(DIR, 'api.js'), 'utf8');
  ['/v1/workbench/contract', '/v1/workbench/api-drift', '/v1/workbench/command-ledger',
    '/v1/workbench/reasoning-timeline', '/v1/workbench/audit-triage', '/v1/workbench/brief'].forEach(function (p) {
    check(new RegExp("'" + p.replace(/[-/]/g, '\\$&') + "': true").test(apiSrc),
      '[m13a] wired workbench read ' + p + ' must be an allowlisted GET in api.js (never a mutation route)');
  });
  notes.push('m13a workbench + control-diff: CONTROL_DIFF covers all 26 legacy CX pages; cx-workbench is native (loads /v1/workbench/contract + 5 live GET read tools via a GET-only self-loader); every newly-wired op is an allowlisted GET.');
})();

// =========================================================================
//  Check 36 — (M13b) every live-wired write dispatches through the single
//  operatorGatedCall→CruxApiGated choke point. No wired run calls a raw route,
//  fetch(), or a client (CruxApi/CruxApiRead/CruxApiGated) directly — the write
//  fires ONLY through operatorGatedCall (which guards on isOperator).
// =========================================================================
(function checkWiredThroughGate() {
  const WIRED = (render && render.WIRED_WRITES) || {};
  const labels = Object.keys(WIRED);
  check(labels.length === 19, '[m13b] expected 19 live-wired write controls; got ' + labels.length);
  labels.forEach(function (label) {
    const spec = WIRED[label];
    check(spec && typeof spec.run === 'function', '[m13b] WIRED_WRITES.' + label + ' must expose a run() fn');
    const src = spec && typeof spec.run === 'function' ? spec.run.toString() : '';
    check(/operatorGatedCall/.test(src), '[m13b] WIRED_WRITES "' + label + '" run must dispatch through operatorGatedCall');
    check(!/\bfetch\s*\(/.test(src), '[m13b] WIRED_WRITES "' + label + '" run must not call fetch() directly');
    check(!/CruxApiGated|CruxApiRead|window\.CruxApi\b|CruxApi\./.test(src), '[m13b] WIRED_WRITES "' + label + '" run must not touch a client directly (only operatorGatedCall)');
  });
  // Every wired label is still a mutation (in MUTATING_ACTIONS).
  const mut = new Set(pages.MUTATING_ACTIONS || []);
  labels.forEach(function (label) { check(mut.has(label), '[m13b] wired write "' + label + '" must be in MUTATING_ACTIONS'); });
  // The btn renderer looks up WIRED_WRITES and hands off to attachWiredWrite,
  // which invokes spec.run — never a bespoke fetch.
  check(/WIRED_WRITES\[control\.label\]/.test(renderSrc), '[m13b] btn renderer must look up WIRED_WRITES[control.label]');
  const aw = funcBody(renderSrc, 'attachWiredWrite');
  check(!!aw, '[m13b] render.js must define attachWiredWrite');
  check(aw && /spec\.run\(/.test(aw), '[m13b] attachWiredWrite must invoke spec.run()');
  notes.push('m13b gate routing: all ' + labels.length + ' live-wired writes dispatch through operatorGatedCall→CruxApiGated (no raw route / no direct client), each still a MUTATING_ACTIONS entry.');
})();

// =========================================================================
//  Check 37 — (M13b) the destructive/spend subset each carries a two-step
//  confirm dialog BEFORE the gated call fires; additive creates do not.
// =========================================================================
(function checkDestructiveConfirm() {
  const WIRED = (render && render.WIRED_WRITES) || {};
  const MUST_CONFIRM = [
    'Restart daemon', 'Re-run onboarding', 'Apply lane weights', 'Reset lane weights',
    'Consolidate facts', 'Withhold all', 'Confirm candidate', 'Test call'
  ];
  MUST_CONFIRM.forEach(function (label) {
    const spec = WIRED[label];
    check(!!spec, '[m13b] destructive/spend control "' + label + '" must be live-wired');
    check(spec && !!spec.confirm, '[m13b] destructive/spend control "' + label + '" must require a confirm dialog (spec.confirm)');
  });
  // Additive creates fire directly — no needless confirm friction.
  ['Create passport', 'Create project', 'Add key', 'Probe endpoint', 'Scan path', 'Verify connection'].forEach(function (label) {
    const spec = WIRED[label];
    check(spec && !spec.confirm, '[m13b] additive create "' + label + '" should not carry a confirm dialog');
  });
  // The handler branches on spec.confirm and shows the dialog before firing.
  const aw = funcBody(renderSrc, 'attachWiredWrite');
  check(aw && /spec\.confirm/.test(aw), '[m13b] attachWiredWrite must branch on spec.confirm');
  check(aw && /showConfirm\(/.test(aw), '[m13b] attachWiredWrite must call showConfirm for the destructive subset');
  // showConfirm is a genuine two-step: onConfirm runs only from the Confirm click.
  const sc = funcBody(renderSrc, 'showConfirm');
  check(!!sc && /onConfirm\(\)/.test(sc), '[m13b] showConfirm must invoke onConfirm only from the Confirm button');
  check(sc && /wired-confirm/.test(sc), '[m13b] showConfirm must render a wired-confirm dialog naming the consequence');
  // The highest-risk control names its consequence explicitly.
  check(/RESTARTS THE DAEMON PROCESS/.test(renderSrc), '[m13b] Restart daemon confirm must explicitly state it restarts the daemon process');
  notes.push('m13b confirm guard: ' + MUST_CONFIRM.length + ' destructive/spend controls each require a two-step confirm (consequence + scope) before the gated call; additive creates fire directly.');
})();

// =========================================================================
//  Check 38 — (M13b) customer posture hides AND refuses every write. The
//  security boundary is posture/mode-independent: writes are hidden
//  (data-requires="operator") AND refused (operatorGatedCall + attachWiredWrite
//  re-check isOperator + require a bound passport for Art.14 attribution).
// =========================================================================
(function checkCustomerPostureRefusesWrites() {
  // operatorGatedCall refuses (rejects) unless operator — the server-independent
  // client-side boundary every wired write funnels through.
  const gc = funcBody(renderSrc, 'operatorGatedCall');
  check(gc && /isOperator\(\)/.test(gc) && /reject/i.test(gc), '[m13b] operatorGatedCall must refuse (reject) unless isOperator()');
  // attachWiredWrite double-checks posture AND requires a bound passport (Art.14).
  const aw = funcBody(renderSrc, 'attachWiredWrite');
  check(aw && /isOperator\(\)/.test(aw), '[m13b] attachWiredWrite must re-check isOperator() (customer refusal)');
  check(aw && /boundPassport\(\)/.test(aw), '[m13b] attachWiredWrite must require boundPassport() (Art.14 attribution)');
  check(aw && /ART14_MSG/.test(aw), '[m13b] attachWiredWrite must refuse with the Art.14 message when unbound');
  // The wired button is stamped operator-only so the shell hides it from customers.
  check(/wired-write/.test(renderSrc) && /stampOperatorOnly\(node\)/.test(renderSrc), '[m13b] a wired write button must be stampOperatorOnly (data-requires="operator")');
  const so = funcBody(renderSrc, 'stampOperatorOnly');
  check(so && /data-requires/.test(so) && /operator/.test(so), '[m13b] stampOperatorOnly must set data-requires="operator"');
  check(so && /hidden = !isOperator\(\)/.test(so), '[m13b] stampOperatorOnly must hide the control for non-operators');
  // shell.applyPosture hides every data-requires="operator" node in customer view.
  check(/\[data-requires="operator"\]/.test(shellHtml) && /POSTURE !== 'operator'/.test(shellHtml),
    '[m13b] shell.applyPosture must hide data-requires="operator" nodes unless operator');
  notes.push('m13b customer safety: writes are hidden (data-requires="operator") AND refused (operatorGatedCall + attachWiredWrite re-check isOperator + Art.14 bound passport) in customer posture — the boundary is posture/mode-independent.');
})();

// =========================================================================
//  Check 39 — Overwatch landing layout rework. The landing drops the Pro
//  dashboard strip (ow-dashstrip) and the Activity ticker (ow-ticker); expands
//  Daemon-at-a-glance with ExecPlans + Token-usage tiles + the moved Engine
//  tile; puts Fleet directly under Needs-you (LEFT column) and the destination
//  page nav in the RIGHT column (the top sub-nav pill row is suppressed for
//  overwatch only). Honesty: tile charts are a REAL series OR demoOn()-guarded
//  demo / an honest meter — never a fabricated real line. Exercised both
//  statically (source) and with a hand-rolled DOM (jsdom-independent).
// =========================================================================
(function checkOverwatchLandingLayout() {
  // ---- Static source assertions on the landing + tile decoration ----------
  const landing = funcBody(renderSrc, 'renderOverwatchLanding');
  check(!!landing, '[overwatch] render.js must define renderOverwatchLanding');
  if (landing) {
    check(!/renderDashStrip/.test(landing), '[overwatch] landing must NOT render the Pro dashboard strip (renderDashStrip removed)');
    check(!/ow-dashstrip/.test(landing), '[overwatch] landing must NOT build an ow-dashstrip');
    check(!/fillActivity/.test(landing), '[overwatch] landing must NOT render the Activity ticker panel (fillActivity removed — duplicates the Activity page)');
    check(!/activityTicker/.test(landing), '[overwatch] landing must NOT build an activity ticker');
    check(!/fillEngine\b/.test(landing), '[overwatch] landing must NOT render the standalone Engine panel (folded into the tiles)');
    check(/fillNeedsYou/.test(landing) && /fillFleet/.test(landing), '[overwatch] landing must still fill Needs-you + Fleet');
    check(/left\.appendChild\(needs\)/.test(landing) && /left\.appendChild\(fleet\)/.test(landing),
      '[overwatch] the Activity tab must stack Needs-you then Fleet in the LEFT column');
    check(/right\.appendChild\(actHost\)/.test(landing) && /renderPage\(page, actHost\)/.test(landing),
      '[overwatch] the Activity tab must render the Activity page (cx-activity) in the RIGHT column (50%)');
    check(/ow-tabs/.test(landing) && /renderTab/.test(landing) && /ow-tabcontent/.test(landing),
      '[overwatch] the landing must render the view tab bar (ow-tabs) + swappable ow-tabcontent (renderTab)');
  }
  // owPageNav reuses the page list from pages.js (dest==='overwatch'), never hardcoded.
  const nav = funcBody(renderSrc, 'owPageNav');
  check(!!nav, '[overwatch] render.js must define owPageNav');
  if (nav) {
    check(/window\.CruxPages/.test(nav) && /'overwatch'/.test(nav), '[overwatch] owPageNav must reuse CruxPages.PAGES filtered to the overwatch destination (not hardcoded)');
    check(/'#\/overwatch\/'/.test(nav), '[overwatch] owPageNav pills must deep-link to #/overwatch/<id>');
    check(/proMode\(\)/.test(nav), '[overwatch] owPageNav must gate Pro pages behind proMode() (mirror the pill row)');
  }
  // Tile decoration: the two new tiles + the honest-chart contract.
  const dt = funcBody(renderSrc, 'decorateTiles');
  check(!!dt, '[overwatch] render.js must define decorateTiles (the tile expansion)');
  if (dt) {
    check(/'ExecPlans'/.test(dt) && /\/v1\/work/.test(dt), '[overwatch] decorateTiles must add an ExecPlans tile grounded in /v1/work');
    check(/'Token usage'/.test(dt) && /\/v1\/cost\/report/.test(dt), '[overwatch] decorateTiles must add a Token-usage tile grounded in /v1/cost/report');
    check(/markStatLarge\(card, 'Facts'\)/.test(dt) && /markStatLarge\(card, 'Sessions'\)/.test(dt) && /'ExecPlans'\)\s*;\s*[\s\S]*stat-lg|stat-lg/.test(dt),
      '[overwatch] Facts + Sessions + ExecPlans must render with the legacy stat-lg number size');
    check(/attachMeter\(/.test(dt), '[overwatch] Storage free must render an honest meter (attachMeter), not a fabricated series');
    check(/attachDemoSpark\(card, 'Token usage'/.test(dt) && /attachDemoSpark\(card, 'MCP agents'/.test(dt) && /attachDemoSpark\(card, 'Integrations'/.test(dt),
      '[overwatch] Token-usage / MCP-agents / Integrations charts must be demoOn()-guarded (attachDemoSpark)');
    check(/fillEngineTile\(/.test(dt), '[overwatch] the Engine tile must be filled by fillEngineTile (moved into the tiles)');
  }
  // Honesty of the chart helpers: demo sparks go through the demoData() choke
  // point; the meter is a real ratio; the engine series is a real probe buffer.
  const ads = funcBody(renderSrc, 'attachDemoSpark');
  check(ads && /demoData\(/.test(ads), '[overwatch] attachDemoSpark must read fixtures only via the demoData() choke point (demoOn()-guarded)');
  const meter = funcBody(renderSrc, 'attachMeter');
  check(meter && /tile-meter-fill/.test(meter) && !/demoData\(/.test(meter), '[overwatch] attachMeter must render a REAL ratio meter (no demo fabrication)');
  const eng = funcBody(renderSrc, 'fillEngineTile');
  check(eng && /\/v1\/console\/engine\/summary/.test(eng) && /engine_reachable/.test(eng),
    '[overwatch] fillEngineTile must build a REAL latency series by probing /v1/console/engine/summary');
  check(eng && /engineLatencySeries/.test(eng), '[overwatch] fillEngineTile must fall back to a demoOn()-guarded demo series when the engine is off');
  // Demo fixtures exist (demo-only tile series).
  const demo = pages.CruxDemo || {};
  ['mcpSeries', 'integrationsSeries', 'engineLatencySeries'].forEach(function (k) {
    check(Array.isArray(demo[k]) && demo[k].length >= 2, '[overwatch] CruxDemo.' + k + ' must be a demo-only series (length >= 2)');
  });
  // Shell suppresses the sub-nav pill row for overwatch ONLY.
  check(/if \(destId !== 'overwatch'\) \{ content\.appendChild\(buildSubnav/.test(shellHtml),
    '[overwatch] shell.html must suppress the sub-nav pill row for the overwatch destination only');
  // CSS: the new tokens exist (all colours are var(--…) — checked below).
  check(/\.stat\.stat-lg \.v/.test(shellHtml), '[overwatch] shell.html must style the legacy stat-lg number size');
  check(/\.ow-pagenav/.test(shellHtml), '[overwatch] shell.html must style the .ow-pagenav right-column nav');
  check(/\.ow-tiles \.tile-meter/.test(shellHtml), '[overwatch] shell.html must style the honest .tile-meter gauge');

  // ---- DOM render assertions (jsdom-independent, like check 30) ------------
  function mkEl(tag) {
    const node = {
      tagName: String(tag || 'div').toUpperCase(), nodeType: 1,
      childNodes: [], _attrs: {}, className: '', style: {},
      setAttribute: function (k, v) { this._attrs[k] = String(v); if (k === 'class') { this.className = String(v); } },
      getAttribute: function (k) { return (k in this._attrs) ? this._attrs[k] : null; },
      appendChild: function (c) { if (c.parentNode) { const i = c.parentNode.childNodes.indexOf(c); if (i >= 0) { c.parentNode.childNodes.splice(i, 1); } } this.childNodes.push(c); c.parentNode = this; return c; },
      insertBefore: function (c, ref) { if (c.parentNode) { const j = c.parentNode.childNodes.indexOf(c); if (j >= 0) { c.parentNode.childNodes.splice(j, 1); } } const i = this.childNodes.indexOf(ref); if (i < 0) { this.childNodes.push(c); } else { this.childNodes.splice(i, 0, c); } c.parentNode = this; return c; },
      removeChild: function (c) { const i = this.childNodes.indexOf(c); if (i >= 0) { this.childNodes.splice(i, 1); } return c; },
      addEventListener: function () {},
      querySelector: function (sel) { const out = []; collect(this, sel, out); return out[0] || null; },
      querySelectorAll: function (sel) { const out = []; collect(this, sel, out); return out; }
    };
    node.classList = {
      add: function (c) { const s = node.className.split(/\s+/).filter(Boolean); if (s.indexOf(c) < 0) { s.push(c); } node.className = s.join(' '); node._attrs['class'] = node.className; },
      contains: function (c) { return node.className.split(/\s+/).indexOf(c) >= 0; }
    };
    Object.defineProperty(node, 'textContent', { get: function () { return this._text || ''; }, set: function (v) { this._text = String(v); this.childNodes.length = 0; } });
    Object.defineProperty(node, 'innerHTML', { get: function () { return this._html || ''; }, set: function (v) { this._html = String(v); } });
    Object.defineProperty(node, 'firstChild', { get: function () { return this.childNodes[0] || null; } });
    Object.defineProperty(node, 'nextSibling', { get: function () { const p = this.parentNode; if (!p) { return null; } const i = p.childNodes.indexOf(this); return p.childNodes[i + 1] || null; } });
    Object.defineProperty(node, 'children', { get: function () { return this.childNodes.filter(function (n) { return n.nodeType === 1; }); } });
    return node;
  }
  function collect(node, sel, out) {
    const cls = sel.charAt(0) === '.' ? sel.slice(1) : sel;
    (node.childNodes || []).forEach(function (c) {
      if (c && c.nodeType === 1) {
        if (String(c.className).split(/\s+/).indexOf(cls) >= 0) { out.push(c); }
        collect(c, sel, out);
      }
    });
  }
  function panelTitle(p) { try { return p.childNodes[0].childNodes[0].textContent; } catch (e) { return null; } }
  const savedDoc = global.document, savedWin = global.window, savedLoc = global.location;
  global.document = { createElement: mkEl, createElementNS: function (ns, tag) { return mkEl(tag); }, createTextNode: function (t) { return { nodeType: 3, textContent: String(t), childNodes: [] }; } };
  global.window = { CruxApi: { get: function () { return new Promise(function () { /* daemon hang */ }); } }, CruxPages: pages, CRUX_MODE: 'professional' };
  global.location = { hash: '#/overwatch/cx-activity' };
  try {
    const region = mkEl('div');
    render.renderOverwatchLanding(region, { summary: { capacity: { free_ratio: 0.5 } } });
    // Strip + ticker are gone from the landing.
    check(region.querySelectorAll('.ow-dashstrip').length === 0, '[overwatch] rendered landing must have NO ow-dashstrip');
    check(region.querySelectorAll('.ow-ticker').length === 0, '[overwatch] rendered landing must have NO ow-ticker');
    // The page nav is in the RIGHT column (one only), never the left.
    const cols = region.querySelectorAll('.ow-cols')[0];
    check(!!cols, '[overwatch] rendered landing must have an .ow-cols region');
    if (cols) {
      const left = cols.children[0], right = cols.children[1];
      check(left.querySelectorAll('.ow-panel').length === 2, '[overwatch] Activity LEFT column must stack Needs-you + Fleet (2 panels)');
      check(right.querySelectorAll('.page-host').length === 1, '[overwatch] Activity RIGHT column must host the Activity page (.page-host)');
      check(panelTitle(left.querySelectorAll('.ow-panel')[0]) === 'Needs you', '[overwatch] Activity LEFT panel 1 must be Needs-you (got ' + panelTitle(left.querySelectorAll('.ow-panel')[0]) + ')');
      check(panelTitle(left.querySelectorAll('.ow-panel')[1]) === 'Fleet', '[overwatch] Activity LEFT panel 2 must be Fleet (got ' + panelTitle(left.querySelectorAll('.ow-panel')[1]) + ')');
    }
    // The view tab bar lists the overwatch pages; Activity is the default tab.
    const tabbar = region.querySelectorAll('.ow-tabs')[0];
    check(tabbar && tabbar.querySelectorAll('.ow-tab').length >= 5, '[overwatch] the view tab bar must list the overwatch pages (>=5 tabs)');
    if (tabbar) {
      const tabButtons = tabbar.querySelectorAll('.ow-tab');
      const tabIds = tabButtons.map(function (b) { return b.getAttribute('data-tab'); });
      check(tabIds.indexOf('cx-activity') >= 0, '[overwatch] the tab bar must include Activity (cx-activity)');
      const act = tabButtons.filter(function (b) { return b.getAttribute('data-tab') === 'cx-activity'; })[0];
      check(act && act.getAttribute('aria-selected') === 'true', '[overwatch] Activity must be the default selected tab');
    }
    notes.push('overwatch layout (tabs): Daemon-at-a-glance tiles → a view tab bar (Activity · Live board · Orchestrators · Punchcards · Agent) that swaps the content below; Activity default = Needs-you then Fleet (left 50%) | Activity page (right 50%); other tabs render their page full-width. The bottom-of-page dup is gone (shell no longer re-renders the resolved overwatch page). Sub-nav pills stay suppressed for overwatch.');
  } catch (e) {
    check(false, '[overwatch] renderOverwatchLanding threw on the synchronous paint: ' + (e && e.stack || e));
  } finally {
    if (savedDoc === undefined) { delete global.document; } else { global.document = savedDoc; }
    if (savedWin === undefined) { delete global.window; } else { global.window = savedWin; }
    if (savedLoc === undefined) { delete global.location; } else { global.location = savedLoc; }
  }
})();

// =========================================================================
//  Check 40 — (M14) WebCrux tile canvas port. The canvas tile pattern from
//  WebCrux-aurora (useCanvasState/CanvasView/CanvasNode; grammar per
//  Unified-Web-Direction §07 + Aurora-Spec-2026-07-07) is the Canvas board and
//  the Documents landing. (a) The pure grid/state engine is exported: tileSnap
//  rounds to the 20px grid; TILE_SIZE_MAP carries the four shapes × four sizes
//  (hero-lg 600×320); tileAutoLayout is deterministic, never overlaps tiles,
//  and preserves manual positions verbatim. (b) The measured interaction
//  grammar ships in shell.html CSS: cubic-bezier(.16,1,.3,1) easing, entry
//  scale(.92)+8px rise over .4s, exit .25s (.cvx-leave), hover −3px lift,
//  sibling dim blur(18px) saturate(.2) opacity .15, 20px snap-grid dots, a
//  reduced-motion fallback that drops the dim blur. (c) Pan mechanics: shared
//  4px deadzone, auto-pan target {20,20}, layer transition off while panning.
//  (d) Wiring: renderCanvasBoard renders the widget registry as tiles;
//  renderDocCanvas is the documents corpus canvas; the form/stack view kicks
//  in under 640px.
// =========================================================================
(function checkTileCanvas() {
  // (a) Pure engine exports.
  check(typeof render.tileSnap === 'function', '[tiles] render.js must export the pure tileSnap(v)');
  if (typeof render.tileSnap === 'function') {
    check(render.tileSnap(23) === 20 && render.tileSnap(31) === 40 && render.tileSnap(0) === 0 && render.tileSnap(-9) === 0,
      '[tiles] tileSnap must round to the 20px grid');
  }
  const sm = render.TILE_SIZE_MAP;
  check(!!sm && !!sm.square && !!sm.wide && !!sm.tall && !!sm.hero, '[tiles] TILE_SIZE_MAP must carry square/wide/tall/hero');
  check(!!sm && ['sm', 'md', 'lg', 'xl'].every(function (s) { return sm.hero[s] && sm.hero[s].w > 0; }),
    '[tiles] each TILE_SIZE_MAP shape must carry sm/md/lg/xl');
  check(!!sm && sm.hero.lg.w === 600 && sm.hero.lg.h === 320, '[tiles] TILE_SIZE_MAP hero.lg must be 600×320 (the WebCrux anchor)');
  check(typeof render.tileAutoLayout === 'function', '[tiles] render.js must export the pure tileAutoLayout');
  if (typeof render.tileAutoLayout === 'function') {
    const sample = [
      { id: 'a', shape: 'hero', size: 'lg' }, { id: 'b', shape: 'wide', size: 'md' },
      { id: 'c', shape: 'square', size: 'md' }, { id: 'd', shape: 'tall', size: 'md' },
      { id: 'e', shape: 'square', size: 'sm' }
    ];
    const p1 = render.tileAutoLayout(sample, undefined);
    const p2 = render.tileAutoLayout(sample, undefined);
    check(JSON.stringify(p1) === JSON.stringify(p2), '[tiles] tileAutoLayout must be deterministic (same input → same layout)');
    const ids = Object.keys(p1);
    check(ids.length === sample.length, '[tiles] tileAutoLayout must place every card');
    let overlap = false;
    for (let i = 0; i < ids.length; i++) {
      for (let j = i + 1; j < ids.length; j++) {
        const a = p1[ids[i]], b = p1[ids[j]];
        if (a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h) { overlap = true; }
      }
    }
    check(!overlap, '[tiles] tileAutoLayout must never overlap tiles');
    const p3 = render.tileAutoLayout(sample, { c: { x: 400, y: 220, manual: true } });
    check(p3.c && p3.c.x === 400 && p3.c.y === 220 && p3.c.manual === true,
      '[tiles] manual positions must be preserved verbatim (auto tiles re-flow around them)');
  }
  // (b) The measured grammar in shell.html CSS.
  check(/cubic-bezier\(\.16,\s*1,\s*\.3,\s*1\)/.test(shellHtml), '[tiles] shell.html must ease the canvas on cubic-bezier(.16,1,.3,1)');
  check(/scale\(\.92\) translateY\(8px\)/.test(shellHtml), '[tiles] tile entry must rise from scale(.92)+8px');
  check(/cvx-enter \.4s/.test(shellHtml), '[tiles] tile entry must run .4s');
  check(/cvx-leave\b/.test(shellHtml) && /opacity \.25s ease, transform \.25s ease/.test(shellHtml),
    '[tiles] tile exit must run .25s (.cvx-leave)');
  check(/blur\(18px\) saturate\(\.2\)/.test(shellHtml) && /\.cvx-node\.cvx-dim\s*\{[^}]*opacity:\s*\.15/.test(shellHtml),
    '[tiles] sibling dim must be blur(18px) saturate(.2) opacity .15 (the measured grammar)');
  check(/translateY\(-3px\)/.test(shellHtml), '[tiles] tile hover lift must be −3px (shared with Aurora cards)');
  check(/\.cvx-grid\s*\{[^}]*background-size:\s*20px 20px/.test(shellHtml), '[tiles] the snap-grid dots must be 20px cells');
  check(/prefers-reduced-motion[^}]*\}[\s\S]*\.cvx-node\.cvx-dim\s*\{\s*filter:\s*none/.test(shellHtml) || /\.cvx-node\.cvx-dim\s*\{\s*filter:\s*none;\s*opacity:\s*\.3/.test(shellHtml),
    '[tiles] reduced motion must drop the dim blur (context stays readable)');
  // (c) Pan mechanics in render.js.
  check(/TILE_PAN_DEAD_ZONE = 4/.test(renderSrc), '[tiles] the pan/drag deadzone must be 4px');
  check(/TILE_PAN_TARGET = \{ x: 20, y: 20 \}/.test(renderSrc), '[tiles] the expand auto-pan target must be {20,20}');
  check(/\.cvx-surface\.cvx-panning \.cvx-layer\s*\{\s*transition:\s*none/.test(shellHtml),
    '[tiles] the layer transition must switch off while actively panning');
  check(/Math\.min\(0, pan\.px \+ dx\)/.test(renderSrc), '[tiles] manual pan must clamp the translate ≤ 0 (pan right/down only)');
  // (d) Wiring: board + documents + the form stack.
  const boardBody = funcBody(renderSrc, 'renderCanvasBoard') || '';
  check(/renderTileCanvas\(/.test(boardBody), '[tiles] renderCanvasBoard must render the widget registry on the tile canvas');
  check(/function renderDocCanvas/.test(renderSrc), '[tiles] render.js must define renderDocCanvas (the documents corpus canvas)');
  check(/TILE_FORM_BREAK = 640/.test(renderSrc) && /function renderTileStack/.test(renderSrc),
    '[tiles] the form/stack view must kick in under 640px (renderTileStack)');
  check(/grid-template-columns:\s*repeat\(12, 1fr\)/.test(shellHtml), '[tiles] the form view must be a 12-col grid (PageView port)');
  notes.push('tile canvas (M14): WebCrux grammar ported — 20px snap grid + SIZE_MAP + deterministic onion-layer auto-layout (pure, unit-tested), 4px-deadzone pan + {20,20} auto-pan, sibling dim blur(18px)/saturate(.2)/opacity(.15), entry .4s / exit .25s on cubic-bezier(.16,1,.3,1), hover −3px, form stack <640px; board = widget registry as tiles, documents landing = corpus canvas.');
})();

// =========================================================================
//  Check 41 — (desktop mission control M2) capability-mapped controls. The
//  central data map must reference fields declared by the daemon's versioned
//  descriptor and list every route each control reaches. The renderer fails
//  closed and paints an accessible reason; this DOM layer never dispatches a
//  mutation and never enables a control disabled by another safety gate.
// =========================================================================
(function checkCapabilityMappedControls() {
  const map = pages.CONTROL_CAPABILITY_MAP || {};
  const expected = [
    'documents.living.load', 'documents.dependencies.expand'
  ];
  check(Object.isFrozen(map), '[capabilities] CONTROL_CAPABILITY_MAP must be exported as frozen central data');
  check(JSON.stringify(Object.keys(map).sort()) === JSON.stringify(expected.slice().sort()),
    '[capabilities] CONTROL_CAPABILITY_MAP must contain the two stable consumer control ids');
  check(/applyCapabilityGate\(bar, 'documents\.living\.load'\)/.test(renderSrc),
    '[capabilities] Living Objects custom control bar must use the generic capability gate');
  check(/applyCapabilityGate\(bar, 'documents\.dependencies\.expand'\)/.test(renderSrc),
    '[capabilities] Dependencies custom control bar must use the generic capability gate');
  check(/return applyCapabilityGate\(node, control && control\.k\)/.test(renderSrc),
    '[capabilities] keyed DSL controls must pass once through the generic capability gate at renderControl return');

  const productSrc = fs.readFileSync(path.join(DIR, '..', '..', 'src', 'product.rs'), 'utf8');
  const openapiSrc = fs.readFileSync(path.join(DIR, '..', '..', 'src', 'http', 'openapi.rs'), 'utf8');
  const apiSrc = fs.readFileSync(path.join(DIR, 'api.js'), 'utf8');
  const structMatch = productSrc.match(/pub struct RuntimeCapabilities\s*\{([\s\S]*?)\n\}/);
  check(!!structMatch, '[capabilities] product.rs must declare RuntimeCapabilities for route conformance');
  const descriptorFields = new Set();
  if (structMatch) {
    let fieldMatch;
    const fieldRe = /pub\s+([a-z][a-z0-9_]*):/g;
    while ((fieldMatch = fieldRe.exec(structMatch[1])) !== null) { descriptorFields.add(fieldMatch[1]); }
  }
  Object.keys(map).forEach(function (controlId) {
    const spec = map[controlId];
    check(spec && descriptorFields.has(spec.capability),
      '[capabilities] mapped control ' + controlId + ' names undeclared descriptor capability: ' + String(spec && spec.capability));
    check(spec && Array.isArray(spec.routes) && spec.routes.length > 0,
      '[capabilities] mapped control ' + controlId + ' must declare at least one route');
    (spec && spec.routes || []).forEach(function (route) {
      check(Array.isArray(route) && route.length === 2 && /^(GET|POST|PUT|PATCH|DELETE)$/.test(route[0]) && /^\/v1\//.test(route[1]),
        '[capabilities] mapped control ' + controlId + ' has an invalid [method, /v1/path] route');
    });
  });

  const daemonRoutes = new Set();
  const routeEntryRe = /RouteEntry\s*\{\s*path:\s*"([^"]+)",\s*methods:\s*&\[([^\]]*)\]/g;
  let routeEntry;
  while ((routeEntry = routeEntryRe.exec(openapiSrc)) !== null) {
    let method;
    const methodRe = /"([A-Z]+)"/g;
    while ((method = methodRe.exec(routeEntry[2])) !== null) {
      daemonRoutes.add(method[1] + ' ' + routeEntry[1]);
    }
  }
  Object.keys(map).forEach(function (controlId) {
    map[controlId].routes.forEach(function (route) {
      check(daemonRoutes.has(route[0] + ' ' + route[1]),
        '[capabilities] mapped route is absent from the daemon route catalog: ' + route[0] + ' ' + route[1]);
    });
  });

  function clientRoute(methodName) {
    const body = objectMethodBody(apiSrc, methodName) || '';
    const template = body.match(/`(\/v1\/[^`]*)`/);
    const verb = body.match(/method:\s*'([A-Z]+)'/);
    if (!template) { return null; }
    return [verb ? verb[1] : 'GET', template[1].replace(/\$\{encodeURIComponent\(([^)]+)\)\}/g, '{$1}')];
  }
  function sortedRoutes(routes) {
    return routes.filter(Boolean).map(function (route) { return route[0] + ' ' + route[1]; }).sort();
  }
  const livingBody = funcBody(renderSrc, 'renderDocSurface_living') || '';
  const livingMethods = [];
  let call;
  const livingCallRe = /projCall\('([^']+)'/g;
  while ((call = livingCallRe.exec(livingBody)) !== null) { livingMethods.push(call[1]); }
  const dependencyBody = funcBody(renderSrc, 'renderDocSurface_deps') || '';
  const dependencyCall = dependencyBody.match(/readPost\('([^']+)'/);
  check(JSON.stringify(sortedRoutes(livingMethods.map(clientRoute))) === JSON.stringify(sortedRoutes(map['documents.living.load'].routes)),
    '[capabilities] Living Objects map routes must exactly match its generated-client dispatches');
  check(dependencyCall && JSON.stringify(sortedRoutes([clientRoute(dependencyCall[1])])) === JSON.stringify(sortedRoutes(map['documents.dependencies.expand'].routes)),
    '[capabilities] Dependencies map routes must exactly match its generated-client dispatch');

  const fullDescriptor = { schema_version: 1, capabilities: {} };
  descriptorFields.forEach(function (name) {
    fullDescriptor.capabilities[name] = {
      availability: 'available', reason_code: 'available', reason: 'Available.',
      compiled: true, configured: true, initialized: true, entitled: true, degraded: false
    };
  });
  fullDescriptor.capabilities.rerank_gpu = {
    availability: 'unavailable', reason_code: 'rerank_not_compiled',
    reason: 'This daemon was built without the hosted GPU rerank bridge.',
    compiled: false, configured: true, initialized: false, entitled: true, degraded: false
  };
  const dataplaneOffDescriptor = JSON.parse(JSON.stringify(fullDescriptor));
  const descriptor = dataplaneOffDescriptor;
  descriptor.capabilities.projection_queries = {
    availability: 'unavailable', reason_code: 'http_dataplane_disabled',
    reason: 'The HTTP dataplane is not initialised, so projection queries are unavailable.',
    compiled: true, configured: false, initialized: false, entitled: true, degraded: false
  };
  descriptor.capabilities.graph_expand = {
    availability: 'unavailable', reason_code: 'http_dataplane_disabled',
    reason: 'The HTTP dataplane is not initialised, so graph expansion is unavailable.',
    compiled: true, configured: true, initialized: false, entitled: true, degraded: false
  };
  descriptor.capabilities.append = {
    availability: 'unavailable', reason_code: 'http_dataplane_disabled',
    reason: 'The HTTP dataplane is not initialised, so event append is unavailable.',
    compiled: true, configured: false, initialized: false, entitled: true, degraded: false
  };
  const noLocalEmbedderDescriptor = JSON.parse(JSON.stringify(fullDescriptor));
  noLocalEmbedderDescriptor.capabilities.local_embedders = {
    availability: 'unavailable', reason_code: 'local_embedder_unavailable',
    reason: "No in-process embedder is initialised in this daemon's local fact store.",
    compiled: true, configured: false, initialized: false, entitled: true, degraded: false
  };

  [
    ['full', fullDescriptor, false],
    ['dataplane-off', dataplaneOffDescriptor, true],
    ['no-local-embedder', noLocalEmbedderDescriptor, false]
  ].forEach(function (profile) {
    Object.keys(map).forEach(function (controlId) {
      const state = render.capabilityStateForControl(controlId, profile[1], map);
      check(state && state.disabled === profile[2],
        '[capabilities] ' + profile[0] + ' profile has the wrong gate for ' + controlId);
    });
  });

  const missing = render.capabilityStateForControl('documents.living.load', null, map);
  check(missing && missing.disabled && missing.reasonCode === 'descriptor_unavailable',
    '[capabilities] a missing descriptor must fail closed with descriptor_unavailable');
  const unknownSchema = render.capabilityStateForControl('documents.living.load', { schema_version: 2, capabilities: {} }, map);
  check(unknownSchema && unknownSchema.disabled && unknownSchema.reasonCode === 'descriptor_unavailable',
    '[capabilities] an unknown descriptor schema must fail closed');
  const incomplete = render.capabilityStateForControl('documents.living.load', {
    schema_version: 1, capabilities: { projection_queries: { availability: 'available' } }
  }, map);
  check(incomplete && incomplete.disabled && incomplete.reasonCode === 'capability_descriptor_invalid',
    '[capabilities] an incomplete schema-v1 capability must fail closed');
  const manualDescriptor = JSON.parse(JSON.stringify(descriptor));
  manualDescriptor.capabilities.projection_queries = {
    availability: 'available', reason_code: 'available_manual', reason: 'Manual operation is available.',
    compiled: true, configured: true, initialized: false, entitled: true, degraded: false
  };
  const manual = render.capabilityStateForControl('documents.living.load', manualDescriptor, map);
  check(manual && !manual.disabled,
    '[capabilities] independently reported stages must not override an explicit available state');

  const statusSection = render.runtimeCapabilitySection(descriptor);
  const noLocalStatusSection = render.runtimeCapabilitySection(noLocalEmbedderDescriptor);
  const statusControls = statusSection.controls || [];
  check(JSON.stringify(statusControls.map(function (control) { return control.capability; }).sort()) === JSON.stringify(Array.from(descriptorFields).sort()),
    '[capabilities] Settings status must render every descriptor-declared capability exactly once');
  const appendStatus = statusControls.find(function (control) { return control.capability === 'append'; });
  const embedderStatus = (noLocalStatusSection.controls || []).find(function (control) { return control.capability === 'local_embedders'; });
  check(appendStatus && appendStatus.reasonCode === 'http_dataplane_disabled' && /event append is unavailable/.test(appendStatus.v),
    '[capabilities] Settings must expose append availability and its daemon reason');
  check(embedderStatus && embedderStatus.reasonCode === 'local_embedder_unavailable' && /local fact store/.test(embedderStatus.v),
    '[capabilities] Settings must expose local-embedder availability and its daemon reason');

  function matches(node, selector) {
    return selector.split(',').some(function (part) {
      const token = part.trim();
      if (token.charAt(0) === '.') { return String(node.className || '').split(/\s+/).indexOf(token.slice(1)) >= 0; }
      return node.tagName === token.toUpperCase();
    });
  }
  function collect(node, selector, out) {
    (node.childNodes || []).forEach(function (child) {
      if (!child || child.nodeType !== 1) { return; }
      if (matches(child, selector)) { out.push(child); }
      collect(child, selector, out);
    });
  }
  function mkEl(tag) {
    const node = {
      tagName: String(tag || 'div').toUpperCase(), nodeType: 1, childNodes: [],
      _attrs: {}, className: '', disabled: false,
      setAttribute: function (key, value) { this._attrs[key] = String(value); if (key === 'class') { this.className = String(value); } },
      getAttribute: function (key) { return Object.prototype.hasOwnProperty.call(this._attrs, key) ? this._attrs[key] : null; },
      appendChild: function (child) { this.childNodes.push(child); child.parentNode = this; return child; },
      querySelector: function (selector) { const out = []; collect(this, selector, out); return out[0] || null; },
      querySelectorAll: function (selector) { const out = []; collect(this, selector, out); return out; }
    };
    node.classList = {
      add: function (name) { const names = node.className.split(/\s+/).filter(Boolean); if (names.indexOf(name) < 0) { names.push(name); } node.className = names.join(' '); node._attrs.class = node.className; },
      contains: function (name) { return node.className.split(/\s+/).indexOf(name) >= 0; }
    };
    Object.defineProperty(node, 'textContent', {
      get: function () { return this._text || ''; },
      set: function (value) { this._text = String(value); this.childNodes.length = 0; }
    });
    return node;
  }

  const savedDoc = global.document;
  const savedWindow = global.window;
  global.document = {
    createElement: mkEl,
    createTextNode: function (value) { return { nodeType: 3, textContent: String(value), childNodes: [] }; }
  };
  global.window = { CRUX_RUNTIME_CAPABILITIES: descriptor, CruxPages: pages };
  try {
    const row = mkEl('div');
    const input = mkEl('input');
    row.appendChild(input);
    render.applyCapabilityGate(row, 'documents.living.load', descriptor, map);
    const reason = row.querySelector('.capability-reason');
    check(input.disabled === true, '[capabilities] an unavailable mapped control must render disabled');
    check(row.getAttribute('data-capability') === 'projection_queries',
      '[capabilities] disabled control must expose data-capability');
    check(row.getAttribute('data-capability-reason') === 'http_dataplane_disabled',
      '[capabilities] disabled control must expose the machine-readable reason code');
    check(!!reason && reason.textContent.indexOf('projection queries are unavailable') >= 0,
      '[capabilities] disabled control must render the daemon reason inline');
    check(input.getAttribute('aria-describedby') === (reason && reason.getAttribute('id')),
      '[capabilities] disabled control must associate its inline reason with aria-describedby');

    const graphRow = mkEl('div');
    const graphButton = mkEl('button');
    graphRow.appendChild(graphButton);
    render.applyCapabilityGate(graphRow, 'documents.dependencies.expand', descriptor, map);
    check(graphButton.disabled === true && graphRow.getAttribute('data-capability-reason') === 'http_dataplane_disabled',
      '[capabilities] dataplane-off must disable graph expansion with the daemon reason');

    const degradedDescriptor = JSON.parse(JSON.stringify(descriptor));
    degradedDescriptor.capabilities.projection_queries = {
      availability: 'degraded', reason_code: 'projection_degraded', reason: 'Projection reads are degraded.',
      compiled: true, configured: true, initialized: true, entitled: true, degraded: true
    };
    const degradedRow = mkEl('div');
    const degradedInput = mkEl('input');
    degradedRow.appendChild(degradedInput);
    render.applyCapabilityGate(degradedRow, 'documents.living.load', degradedDescriptor, map);
    check(degradedInput.disabled === true && degradedRow.getAttribute('data-capability-availability') === 'degraded',
      '[capabilities] a degraded mapped control must remain disabled and retain its availability state');
    check(/^Degraded — /.test((degradedRow.querySelector('.capability-reason') || {}).textContent || ''),
      '[capabilities] a degraded mapped control must render a distinct degraded reason');

    const alreadyDisabled = mkEl('div');
    const button = mkEl('button');
    button.disabled = true;
    alreadyDisabled.appendChild(button);
    render.applyCapabilityGate(alreadyDisabled, 'documents.dependencies.expand', fullDescriptor, map);
    check(button.disabled === true, '[capabilities] the capability layer must never enable a control disabled by another gate');
    check(alreadyDisabled.querySelector('.capability-reason') === null,
      '[capabilities] an available capability must not paint an unavailable reason');

    const settings = mkEl('main');
    render.renderPage({
      id: 'cx-settings', title: 'Settings',
      sections: [{ h: 'Settings', controls: [{ t: 'info', label: 'status', v: 'ready' }] }]
    }, settings);
    check(settings.querySelectorAll('.runtime-capability-status').length === descriptorFields.size,
      '[capabilities] cx-settings must render the all-capability status section');
  } catch (e) {
    check(false, '[capabilities] disabled-with-reason DOM render threw: ' + (e && e.stack || e));
  } finally {
    if (savedDoc === undefined) { delete global.document; } else { global.document = savedDoc; }
    if (savedWindow === undefined) { delete global.window; } else { global.window = savedWindow; }
  }

  const gateBody = funcBody(renderSrc, 'applyCapabilityGate') || '';
  check(!/CruxApiGated|operatorGatedCall|\bfetch\s*\(/.test(gateBody),
    '[capabilities] the capability renderer must not dispatch or bypass the gated mutation choke point');
  const publish = "window.CRUX_RUNTIME_CAPABILITIES = get(BOOT.version, ['product', 'runtime_capabilities']) || null;";
  const publishAt = shellHtml.indexOf(publish);
  check(publishAt >= 0 && shellHtml.indexOf('route();', publishAt) > publishAt,
    '[capabilities] shell boot must publish product.runtime_capabilities in memory before routing');
  notes.push('runtime capabilities (M2): Settings reports all 6 descriptor capabilities; full/dataplane-off/no-local-embedder profiles gate 2 mapped consumers; map entries match descriptor fields, daemon routes, and generated-client dispatches; unavailable/missing/incomplete status fails closed with data-capability-reason and an aria-associated inline reason; available status never re-enables another gate.');
})();

// =========================================================================
//  Check 42 — (desktop mission control M4a) plan-rooted tree join. The pure
//  buildPlanTree() joins Project → ExecPlan → Milestone → live session from the
//  real /v1/work?source=all + /v1/coord/active fields. The join must NOT
//  fabricate edges: a session whose announced execplan_slug resolves to no work
//  item lands under an explicit "unattached" root — never guessed onto a plan —
//  and milestone nodes come only from ids the data names (current/next-ready/
//  announced), never synthesised from milestones_total. Session nodes carry their
//  announced focus + held leases. The view is wired into Canvas as a Tree switch,
//  reachable via #/canvas/tree, and reads only through the generated client.
// =========================================================================
(function checkPlanTree() {
  check(typeof render.buildPlanTree === 'function', '[plan-tree] render.js must export buildPlanTree()');
  check(typeof render.renderPlanTree === 'function', '[plan-tree] render.js must export renderPlanTree()');
  if (typeof render.buildPlanTree !== 'function') { return; }

  // Empty input fabricates nothing.
  const empty = render.buildPlanTree({});
  check(empty && Array.isArray(empty.roots) && empty.roots.length === 0,
    '[plan-tree] empty input must yield zero roots (no fabricated nodes)');

  const fixture = {
    projects: { projects: [
      { id: 'execplans', name: 'ExecPlans' },
      { id: 'proj-real', name: 'Real Project' }
    ] },
    work: { work: [
      { id: 'execplan:alpha', project_id: 'execplans', title: 'Alpha plan', state: 'in_progress',
        current_milestone: 'M2', next_ready_milestone: 'M3', milestones_done: 1, milestones_total: 5 },
      { id: 'kanban-1', project_id: 'proj-real', title: 'Kanban task', state: 'planned' }
    ] },
    sessions: { active_sessions: [
      // resolves to alpha + announces M2 → under the M2 milestone node; carries focus + a lease.
      { session_id_hex: 'aaaa1111beef', passport_id: 'pp_a',
        intent: { execplan_slug: 'alpha', milestone: 'M2', paths: ['crates/x'], deploy_target: 'deploy:crux' },
        leases: [{ resource: 'tree://crates/x', punchcard_id: 'pc1', mode: 'modify', holder_passport: 'pp_a', expires_at_unix_ms: 9e15 }] },
      // announces a slug that resolves to NO work item → must land under "unattached", not on a plan.
      { session_id_hex: 'bbbb2222cafe', passport_id: 'pp_b',
        intent: { execplan_slug: 'ghost-plan', milestone: 'M9' } },
      // resolves to alpha but announces NO milestone → directly under the plan, not a milestone node.
      { session_id_hex: 'cccc3333face', passport_id: 'pp_c',
        intent: { execplan_slug: 'alpha' } },
      // resolves to a KANBAN item (even with a milestone string) → must hang
      // DIRECTLY off the kanban work node, never grow a milestone/ExecPlan shape.
      { session_id_hex: 'dddd4444feed', passport_id: 'pp_d',
        intent: { execplan_slug: 'kanban-1', milestone: 'M7' } }
    ] }
  };
  const tree = render.buildPlanTree(fixture);
  const roots = (tree && tree.roots) || [];
  function byId(nodes, type, id) { return (nodes || []).find(function (n) { return n.type === type && n.id === id; }) || null; }
  function walk(node, visit) { visit(node); (node.children || []).forEach(function (c) { walk(c, visit); }); }

  const execRoot = byId(roots, 'project', 'execplans');
  const realRoot = byId(roots, 'project', 'proj-real');
  const unattachedRoot = byId(roots, 'unattached', 'unattached');
  check(!!execRoot, '[plan-tree] the "execplans" virtual project must be a root');
  check(!!realRoot, '[plan-tree] a real kanban project must be a root');
  check(!!unattachedRoot, '[plan-tree] an explicit "unattached" root must exist when a session resolves to no plan');

  const alpha = execRoot && byId(execRoot.children, 'execplan', 'execplan:alpha');
  check(!!alpha, '[plan-tree] execplan:alpha must nest under its "execplans" project');
  const alphaMilestones = alpha ? (alpha.children || []).filter(function (n) { return n.type === 'milestone'; }).map(function (n) { return n.id; }).sort() : [];
  // Only current (M2) + next-ready (M3) — NOT M1/M4/M5 synthesised from total=5,
  // and NOT M9 (announced only by the unattached ghost session).
  check(JSON.stringify(alphaMilestones) === JSON.stringify(['M2', 'M3']),
    '[plan-tree] milestone nodes must be exactly the ids the data names (current+next-ready), got ' + JSON.stringify(alphaMilestones));

  const m2 = alpha && byId(alpha.children, 'milestone', 'M2');
  const sessAAtM2 = m2 && byId(m2.children, 'session', 'aaaa1111beef');
  check(!!sessAAtM2, '[plan-tree] a session announcing (alpha, M2) must attach under the M2 milestone node');
  // Announced focus + leases travel WITH the node (M4a gate).
  check(sessAAtM2 && sessAAtM2.focus && sessAAtM2.focus.milestone === 'M2' &&
    JSON.stringify(sessAAtM2.focus.paths) === JSON.stringify(['crates/x']) && sessAAtM2.focus.deploy_target === 'deploy:crux',
    '[plan-tree] session node must carry its announced focus (milestone, paths, deploy target)');
  check(sessAAtM2 && Array.isArray(sessAAtM2.leases) && sessAAtM2.leases.length === 1 && sessAAtM2.leases[0].resource === 'tree://crates/x',
    '[plan-tree] session node must carry its held leases');

  // A session that announced the plan but no milestone hangs directly off the plan.
  const sessCdirect = alpha && byId(alpha.children, 'session', 'cccc3333face');
  check(!!sessCdirect, '[plan-tree] a session announcing a plan but no milestone must hang directly off the ExecPlan node');

  // ---- Kanban vs ExecPlan (blocker #1): a kanban item is a plain "work" node
  // with NO milestone synthesis; a session announcing its id (even with a
  // milestone string) hangs directly off it — never a fabricated ExecPlan shape.
  const kanban = realRoot && byId(realRoot.children, 'work', 'kanban-1');
  check(!!kanban, '[plan-tree] a kanban item must render as a plain "work" node under its real project');
  check(!execRoot || !byId(execRoot.children, 'execplan', 'kanban-1'),
    '[plan-tree] a kanban item must NOT be rendered as an ExecPlan node');
  check(kanban && !(kanban.children || []).some(function (n) { return n.type === 'milestone'; }),
    '[plan-tree] a kanban item must NOT grow a milestone layer');
  const kSess = kanban && byId(kanban.children, 'session', 'dddd4444feed');
  check(!!kSess, '[plan-tree] a session announcing a kanban id must hang directly off the kanban work node (no milestone level)');
  let kanbanSessCount = 0;
  roots.forEach(function (root) { walk(root, function (n) { if (n.type === 'session' && n.id === 'dddd4444feed') { kanbanSessCount++; } }); });
  check(kanbanSessCount === 1, '[plan-tree] a kanban session must appear exactly once (not duplicated onto a fabricated ExecPlan/milestone)');

  // ---- No fabricated edges: the ghost session appears ONLY under "unattached".
  const ghostUnderProjects = [];
  const allMilestoneIds = {};
  roots.forEach(function (root) {
    if (root.type === 'unattached') { return; }
    walk(root, function (n) {
      if (n.type === 'session' && n.id === 'bbbb2222cafe') { ghostUnderProjects.push(n.id); }
      if (n.type === 'milestone') { allMilestoneIds[n.id] = true; }
    });
  });
  check(ghostUnderProjects.length === 0,
    '[plan-tree] a session resolving to no work item must NOT appear under any project subtree (no fabricated edge)');
  const ghostInUnattached = unattachedRoot && byId(unattachedRoot.children, 'session', 'bbbb2222cafe');
  check(!!ghostInUnattached, '[plan-tree] the unresolved session must be present under the "unattached" root');
  check(!allMilestoneIds['M9'],
    '[plan-tree] no milestone node may be fabricated from an unresolved session\'s announced milestone (M9)');
  check(!allMilestoneIds['M7'],
    '[plan-tree] no milestone node may be fabricated from a kanban session\'s announced milestone (M7)');

  // ---- Through-client + wiring: the Tree view reads via the generated client
  // (the parameterised work?source=all through the named CruxApi.work({source})
  // method — the query-string fetchJSON path rejects), and Canvas exposes it.
  const renderPlanTreeBody = funcBody(renderSrc, 'renderPlanTree') || '';
  check(/api\.work\(\s*\{\s*source:\s*'all'\s*\}\s*\)/.test(renderPlanTreeBody),
    '[plan-tree] renderPlanTree must read /v1/work?source=all through the named CruxApi.work({source:"all"}) method');
  check(/fetchJSON\('\/v1\/coord\/active'\)/.test(renderPlanTreeBody),
    '[plan-tree] renderPlanTree must read /v1/coord/active for announced focus + leases');
  check(!/\bfetch\s*\(/.test(renderPlanTreeBody),
    '[plan-tree] renderPlanTree must not raw-fetch — api.js is the sole network layer');
  check(/\['tree', 'Tree'\]/.test(renderSrc) && /renderPlanTree\(body, ctx\)/.test(renderSrc),
    '[plan-tree] Canvas must carry a Tree view switch dispatching to renderPlanTree');
  check(/parts\[1\] === 'tree'/.test(shellHtml),
    '[plan-tree] shell.html parseCanvasHash must route #/canvas/tree to the Tree view');

  // ---- The model paints + the live renderer fails honest. The shared mock DOM
  // (newMockDom) lets the smoke both (a) paint the model directly and (b) drive
  // renderPlanTree end to end with a mocked generated client where one feed FAILS.
  const mock = newMockDom();
  const mkNode = mock.mkNode, mockDoc = mock.doc, collectNodes = mock.collect, classesOf = mock.classesOf;

  if (typeof render.planTreeNode === 'function') {
    const savedDoc = global.document;
    global.document = mockDoc;
    try {
      const classes = classesOf(render.planTreeNode(execRoot, 0));
      check(classes.some(function (c) { return /\bplan-tree-focus\b/.test(c); }), '[plan-tree] rendered DOM must paint the announced-focus chip');
      check(classes.some(function (c) { return /\bplan-tree-lease\b/.test(c); }), '[plan-tree] rendered DOM must paint the held-lease chip');
      check(classesOf(render.planTreeNode(unattachedRoot, 0)).some(function (c) { return /\bplan-tree-unattached\b/.test(c); }),
        '[plan-tree] rendered DOM must paint the explicit unattached node');
      // #5 — an unattached session paints the slug that failed to resolve.
      check(classesOf(render.planTreeNode(unattachedRoot, 0)).some(function (c) { return /\bplan-tree-unresolved\b/.test(c); }),
        '[plan-tree] an unattached session must paint its unresolved execplan_slug');
    } catch (e) {
      check(false, '[plan-tree] planTreeNode DOM render threw: ' + (e && e.stack || e));
    } finally {
      if (savedDoc === undefined) { delete global.document; } else { global.document = savedDoc; }
    }
  }

  // ---- (fix #4b) Drive renderPlanTree end to end through a mocked generated
  // client where COORD fails (503) while work + projects are healthy. The tree
  // must still paint AND a per-feed degraded notice for coord must appear — the
  // fail-honest hole the review caught (coord-off must not look like "no sessions").
  if (typeof render.renderPlanTree === 'function') {
    function fakeRes(ok, status, data) { return Promise.resolve({ ok: ok, status: status, json: function () { return Promise.resolve(data); } }); }
    const mockApi = {
      get: function (path) {
        if (path === '/v1/projects') { return fakeRes(true, 200, fixture.projects); }
        if (path === '/v1/coord/active') { return fakeRes(false, 503, null); }   // FAILED feed
        return fakeRes(false, 404, null);
      },
      work: function () { return fakeRes(true, 200, fixture.work); }
    };
    const savedDoc = global.document, savedWin = global.window;
    global.document = mockDoc;
    global.window = { CruxApi: mockApi };
    const host = mkNode('div');
    asyncChecks.push(Promise.resolve(render.renderPlanTree(host, {})).then(function () {
      const all = collectNodes(host, []);
      const degraded = all.filter(function (n) { return /\bplan-tree-degraded\b/.test(n.className || ''); });
      check(all.some(function (n) { return /\bplan-tree-row\b/.test(n.className || ''); }),
        '[plan-tree] renderPlanTree must still paint the healthy tree when only one feed failed');
      check(degraded.some(function (n) { return n.getAttribute('data-feed') === 'coord'; }),
        '[plan-tree] renderPlanTree must render a per-feed degraded notice for the failed coord feed (fail honest, not silent "no sessions")');
    }).catch(function (e) {
      check(false, '[plan-tree] renderPlanTree drive threw: ' + (e && e.stack || e));
    }).then(function () {
      if (savedDoc === undefined) { delete global.document; } else { global.document = savedDoc; }
      if (savedWin === undefined) { delete global.window; } else { global.window = savedWin; }
    }));
  }

  notes.push('plan tree (M4a): buildPlanTree joins Project→ExecPlan→Milestone→live session from /v1/work?source=all + /v1/coord/active; kanban items render as plain work nodes (no milestone synthesis) and a kanban-announcing session hangs directly off them; unresolved sessions land under an explicit unattached root painting the failed slug (no fabricated edges); milestone nodes only from named ids (current/next-ready/announced), never from milestones_total; session nodes carry announced focus + held leases (model + mock-DOM paint); renderPlanTree fails honest per feed (coord-503 notice alongside a healthy tree); null-proto lookups; wired as Canvas #/canvas/tree through the generated client.');
})();

// =========================================================================
//  Check 43 — (ISOLATED root-cause fix, NOT M4a) fetchJSON heals query-bearing
//  reads at the single choke point: it splits "path?query" into (base, query) and
//  calls CruxApi.get(base, query), whose allowlist matches the BASE path and
//  re-applies the query. Before this, the whole query string was passed as the
//  path → allowlist miss → reject → status 0 → the surface false-empties to demo.
//  Functionally drives the REAL fetchJSON against the REAL generated client.
// =========================================================================
(function checkQueryStringSplit() {
  const body = funcBody(renderSrc, 'fetchJSON') || '';
  check(/URLSearchParams/.test(body) && /api\.get\(base, query\)/.test(body),
    '[query-split] fetchJSON must split path?query and call CruxApi.get(base, query)');
  check(typeof render.fetchJSON === 'function', '[query-split] render.js must export fetchJSON');

  if (typeof render.fetchJSON === 'function') {
    // Drive fetchJSON against the REAL client (require api.js onto a fresh window)
    // with a stubbed fetch. fetchJSON reads window.CruxApi + global.fetch
    // SYNCHRONOUSLY, so fire every probe then restore globals immediately — the
    // promises resolve off already-captured refs (no async global juggling).
    const savedWin = global.window, savedFetch = global.fetch;
    const fetched = [];
    global.window = {};
    require('./api.js');   // populates global.window.CruxApi with the real client
    global.fetch = function (u) { fetched.push(String(u)); return Promise.resolve({ ok: true, status: 200, json: function () { return Promise.resolve({ work: [] }); } }); };
    // The five query-bearing surfaces the fix heals (work + the four cx-* loaders).
    const urls = [
      '/v1/work?source=all',
      '/v1/console/facts?top_k=100',
      '/v1/console/facts?top_k=50',
      '/v1/console/review/queue?limit=50',
      '/v1/cost/report?tenant_id=default&token_budget=4000'
    ];
    const probes = urls.map(function (u) { return render.fetchJSON(u); });
    global.window = savedWin; global.fetch = savedFetch;
    asyncChecks.push(Promise.all(probes).then(function (rs) {
      check(rs.every(function (r) { return r.ok === true && r.status === 200; }),
        '[query-split] every query-bearing read must resolve through the client (not false-empty status 0)');
      check(urls.every(function (u) { return fetched.indexOf(u) >= 0; }),
        '[query-split] the split must rebuild each exact query URL and reach the client');
    }));
  }
  notes.push('query-string fix (isolated from M4a): fetchJSON splits path?query → CruxApi.get(base, query) at the single choke point, healing every query-bearing read (work?source=all + cx-facts/cost/review/memory) — verified by driving the real fetchJSON against the real generated client; the per-endpoint fetchWorkAll/fetchPageFeed wrappers are removed as redundant.');
})();

// =========================================================================
//  Check 44 — (desktop mission control M4b) session-detail / evidence contract.
//  Clicking a session opens an authorized/redacted evidence view over EXISTING
//  daemon GET routes only: receipts (← /v1/sessions/{id}/observations, each record
//  a signed CROWN receipt), fact provenance (← /v1/facts/entity/execplan:<slug>),
//  and announced focus (← coord, already on the node). Decisions enforced here:
//   · transcript = REFERENCE-ONLY — an inert text chip, never fetched/rendered;
//     the smoke asserts NO transcript-content request path exists;
//   · no arbitrary local-path read — API-supplied paths render as text, not links;
//   · absence honesty — missing evidence renders an explicit absent-state (M2
//     disabled-with-reason idiom); a feed error renders a degraded notice (M4a).
//  All reads go through the generated client.
// =========================================================================
(function checkSessionDetail() {
  check(typeof render.buildSessionDetail === 'function', '[session-detail] render.js must export buildSessionDetail()');
  check(typeof render.paintSessionDetail === 'function', '[session-detail] render.js must export paintSessionDetail()');
  check(typeof render.renderSessionDetail === 'function', '[session-detail] render.js must export renderSessionDetail()');
  if (typeof render.buildSessionDetail !== 'function') { return; }

  const sessionNode = {
    key: 'session:aaaa', type: 'session', id: 'aaaa1111beef', label: 'aaaa1111',
    execplanEntity: 'execplan:alpha',   // stamped by buildPlanTree only for ExecPlan-resolved sessions
    // transcript_ref rides on the coord announcement (already-loaded node data) — never fetched.
    focus: { execplan_slug: 'alpha', milestone: 'M2', paths: ['crates/x'], deploy_target: 'deploy:crux', transcript_ref: 'transcripts/aaaa1111.jsonl' },
    leases: [{ resource: 'tree://crates/x', punchcard_id: 'pc1', mode: 'modify' }],
    unresolvedSlug: null, children: []
  };
  const obsFixture = { observations: [
    { observation_id: 'obs-1', provider: 'anthropic', kind: 'assistant', ts: '2026-07-20T10:00:00Z', seq: 0,
      receipt: { alg: 'ed25519', signed_by: 'crux', body_hash: 'blake3:deadbeefcafe0000', signature: 'sig' } }
  ], chain: { status: 'ok', chained_len: 1 } };
  const factsFixture = { facts: [
    { fact_id: 'f1', entity: 'execplan:alpha', key: 'gate:M2', value: '{...}', stored_at: '2026-07-20T09:00:00Z',
      source_receipt: 'blake3:aaaabbbbcccc', actor: 'claude-opus-4-8', version: 2, private: false },
    // canonical [REDACTED:…] marker (redact_writer.rs) → the redaction marker renders.
    { fact_id: 'f2', entity: 'execplan:alpha', key: 'decision:x', value: '[REDACTED:fld.secret#abcd]', stored_at: '2026-07-20T09:30:00Z',
      source_receipt: null, actor: null, version: 3 },
    // genuinely EMPTY value → honest empty, NOT a redaction claim.
    { fact_id: 'f3', entity: 'execplan:alpha', key: 'note:y', value: '', stored_at: '2026-07-20T09:45:00Z', version: 1 }
  ] };
  const okS = { ok: true, status: 200 };

  // ---- Pure contract: focus + receipts + provenance + transcript all present.
  const model = render.buildSessionDetail({ session: sessionNode, entity: 'execplan:alpha',
    observations: obsFixture, obsStatus: okS, facts: factsFixture, factsStatus: okS });
  check(model.focus && model.focus.milestone === 'M2' && model.focus.deploy_target === 'deploy:crux' &&
    JSON.stringify(model.focus.paths) === JSON.stringify(['crates/x']) && (model.focus.leases || []).length === 1,
    '[session-detail] model carries the announced focus (milestone, deploy target, paths, leases) from the node — not re-fetched');
  check(model.receipts && model.receipts.present === true && model.receipts.items.length === 1 &&
    model.receipts.items[0].body_hash === 'blake3:deadbeefcafe0000' && model.receipts.chain && model.receipts.chain.status === 'ok',
    '[session-detail] receipts come from the observations feed (receipt envelope + daemon chain status)');
  check(model.provenance && model.provenance.present === true && model.provenance.entity === 'execplan:alpha' &&
    model.provenance.items.length === 3 && model.provenance.items[0].source_receipt === 'blake3:aaaabbbbcccc',
    '[session-detail] fact provenance comes from /v1/facts/entity/<resolved-entity>');
  // Redaction honesty: ONLY the canonical [REDACTED:…] value is a redaction; the
  // empty value is honest-empty (no false redaction claim).
  check(model.provenance.items[1].redacted === true && model.provenance.items[0].redacted === false && model.provenance.items[2].redacted === false,
    '[session-detail] only a canonical [REDACTED:…] value renders the redaction marker; an empty value is honest-empty');
  check(model.transcript && model.transcript.present === true && model.transcript.ref === 'transcripts/aaaa1111.jsonl',
    '[session-detail] transcript reference comes from already-loaded node data (coord announcement) — no session-state fetch');

  // ---- Fix 6: a session that did NOT resolve to an ExecPlan (no execplanEntity;
  // it merely ANNOUNCED a slug that pointed at a kanban item) → no_plan absent.
  // Provenance must NOT be keyed off the announced slug (would fetch unrelated facts).
  const kanbanSess = { id: 'k1', focus: { execplan_slug: 'kanban-1' }, leases: [] };
  const noPlan = render.buildSessionDetail({ session: kanbanSess, entity: null,
    observations: obsFixture, obsStatus: okS, facts: factsFixture, factsStatus: okS });
  check(noPlan.provenance.present === false && noPlan.provenance.absent && noPlan.provenance.absent.code === 'no_plan' && !noPlan.provenance.absent.degraded,
    '[session-detail] a session that did not resolve to an ExecPlan renders no_plan absent (never guesses execplan:<announced-slug>)');
  check(noPlan.transcript.present === false, '[session-detail] no transcript reference on the node → transcript absent-state');

  // ---- Fix 4: any non-ok feed → degraded; reachable-but-empty (200+[]) → absent.
  const emptyObs = render.buildSessionDetail({ session: sessionNode, entity: 'execplan:alpha', observations: { observations: [] }, obsStatus: okS,
    facts: factsFixture, factsStatus: okS });
  check(emptyObs.receipts.present === false && emptyObs.receipts.absent.code === 'empty' && emptyObs.receipts.absent.degraded === false,
    '[session-detail] reachable-but-empty receipts render an absent-state (not degraded)');
  [{ ok: false, status: 503 }, { ok: false, status: 404 }, { ok: false, status: 0 }].forEach(function (st) {
    const errObs = render.buildSessionDetail({ session: sessionNode, entity: 'execplan:alpha', obsStatus: st, facts: factsFixture, factsStatus: okS });
    check(errObs.receipts.present === false && errObs.receipts.absent.degraded === true,
      '[session-detail] a non-ok receipts feed (status ' + st.status + ') → degraded notice, never an absent-state');
  });

  // ---- Source-level: renders through the generated client only; NO state fetch, NO transcript route.
  const rsdBody = funcBody(renderSrc, 'renderSessionDetail') || '';
  check(!/\bfetch\s*\(/.test(rsdBody), '[session-detail] renderSessionDetail must not raw-fetch — api.js is the sole network layer');
  check(/api\.sessionsBySessionIdObservations\b/.test(rsdBody) && /api\.factsEntityByEntity\b/.test(rsdBody),
    '[session-detail] receipts + provenance reads must go through the named generated-client methods');
  check(!/sessionsBySessionIdState/.test(rsdBody),
    '[session-detail] renderSessionDetail must NOT fetch session state (that blob can embed transcript content — content must never transit to page JS)');
  // No transcript-content client method exists anywhere in the generated client —
  // the strongest proof no transcript-content request path exists.
  const apiSrc44 = fs.readFileSync(path.join(DIR, 'api.js'), 'utf8');
  check(!/transcript/i.test(apiSrc44), '[session-detail] the generated client must expose NO transcript-content method (reference-only decision)');

  // ---- Mock-DOM paint: honest badges, inert transcript, redacted/degraded/absent.
  const mock = newMockDom();
  const savedDoc = global.document;
  global.document = mock.doc;
  try {
    const painted = render.paintSessionDetail(model);
    const tref = mock.findByClass(painted, 'session-detail-transcript-ref');
    check(tref.length === 1 && tref[0].tagName !== 'A' && tref[0].getAttribute('href') == null && tref[0].getAttribute('data-inert') === 'reference-only',
      '[session-detail] the transcript chip is inert text — never an <a>/href, marked data-inert (reference-only, no fetch/open)');
    // Honest badges: a neutral "receipt envelope" chip, NEVER a green "signed"/"valid" claim.
    const paintedText = painted.textContent || '';
    check(/receipt envelope/.test(paintedText) && !/\bsigned\b/.test(paintedText),
      '[session-detail] receipts render a neutral "receipt envelope" chip, never a "signed" claim the browser did not verify');
    check(/chain: ok/.test(paintedText) && !/intact/.test(paintedText),
      '[session-detail] chain status renders VERBATIM from the daemon ("chain: ok"), never a client-computed "intact" verdict');
    check(mock.findByClass(painted, 'session-detail-item').length >= 4,
      '[session-detail] painted DOM renders receipt + provenance evidence items');
    check(mock.findByClass(painted, 'session-detail-redacted').length === 1,
      '[session-detail] exactly one redaction marker renders (the canonical [REDACTED:…] fact) — the empty fact is honest-empty');
    const pathChips = mock.findByClass(painted, 'plan-tree-path');
    check(pathChips.length === 1 && pathChips[0].tagName !== 'A' && pathChips[0].getAttribute('href') == null,
      '[session-detail] an API-supplied path renders as inert text, never a link that fetches or opens');

    const degradedModel = render.buildSessionDetail({ session: sessionNode, entity: 'execplan:alpha', observations: obsFixture, obsStatus: okS,
      factsStatus: { ok: false, status: 500 } });
    check(mock.findByClass(render.paintSessionDetail(degradedModel), 'session-detail-degraded').length >= 1,
      '[session-detail] a provenance feed error paints a degraded notice');
    const absentNodes = mock.findByClass(render.paintSessionDetail(emptyObs), 'session-detail-absent')
      .filter(function (n) { return n.getAttribute('data-capability-reason') != null; });
    check(absentNodes.length >= 1, '[session-detail] a reachable-but-empty section paints an absent-state carrying data-capability-reason (M2 idiom)');
  } catch (e) {
    check(false, '[session-detail] paintSessionDetail DOM render threw: ' + (e && e.stack || e));
  } finally {
    if (savedDoc === undefined) { delete global.document; } else { global.document = savedDoc; }
  }

  // ---- Drive renderSessionDetail through a MOCK client. Fix 7: assert the EXACT
  // call multiset (count + names), not membership. Fix 6: a non-ExecPlan session
  // fetches observations only. Fix 5: a stale in-flight paint is dropped.
  if (typeof render.renderSessionDetail === 'function') {
    function fakeRes(ok, status, data) { return Promise.resolve({ ok: ok, status: status, json: function () { return Promise.resolve(data); } }); }
    function fakeResLater(ok, status, data) { return new Promise(function (res) { setTimeout(function () { res({ ok: ok, status: status, json: function () { return Promise.resolve(data); } }); }, 8); }); }
    const savedDoc2 = global.document, savedWin = global.window;
    global.document = mock.doc; global.window = {};

    // Drive A — ExecPlan session, provenance feed FAILS.
    const callsA = [];
    const apiA = {
      sessionsBySessionIdObservations: function (id) { callsA.push('observations:' + id); return fakeRes(true, 200, obsFixture); },
      factsEntityByEntity: function (entity) { callsA.push('facts:' + entity); return fakeRes(false, 500, null); },
      sessionsBySessionIdState: function (id) { callsA.push('state:' + id); return fakeRes(true, 200, {}); }
    };
    const hostA = mock.mkNode('div');
    asyncChecks.push(Promise.resolve(render.renderSessionDetail(hostA, sessionNode, apiA)).then(function () {
      check(JSON.stringify(callsA.slice().sort()) === JSON.stringify(['facts:execplan:alpha', 'observations:aaaa1111beef']),
        '[session-detail] an ExecPlan session drives EXACTLY {observations, facts/entity} — no state fetch, no transcript (got ' + JSON.stringify(callsA.slice().sort()) + ')');
      const painted = mock.collect(hostA, []);
      check(painted.some(function (n) { return /\bsession-detail-transcript-ref\b/.test(n.className || ''); }),
        '[session-detail] the inert transcript reference paints from node data (not a state fetch)');
      check(painted.some(function (n) { return /\bsession-detail-degraded\b/.test(n.className || ''); }),
        '[session-detail] a failed provenance feed paints a degraded notice (fail honest)');
    }).catch(function (e) { check(false, '[session-detail] drive A threw: ' + (e && e.stack || e)); }));

    // Drive B (fix 6) — kanban session (no execplanEntity): observations ONLY.
    const callsB = [];
    const apiB = {
      sessionsBySessionIdObservations: function (id) { callsB.push('observations:' + id); return fakeRes(true, 200, obsFixture); },
      factsEntityByEntity: function (entity) { callsB.push('facts:' + entity); return fakeRes(true, 200, factsFixture); }
    };
    const hostB = mock.mkNode('div');
    asyncChecks.push(Promise.resolve(render.renderSessionDetail(hostB, { id: 'k1', focus: { execplan_slug: 'kanban-1' }, leases: [] }, apiB)).then(function () {
      check(JSON.stringify(callsB) === JSON.stringify(['observations:k1']),
        '[session-detail] a non-ExecPlan session fetches observations ONLY — never facts for execplan:<announced-slug> (got ' + JSON.stringify(callsB) + ')');
    }).catch(function (e) { check(false, '[session-detail] drive B threw: ' + (e && e.stack || e)); }));

    // Drive C (fix 5) — race: slow A then fast B into the SAME host; only B paints.
    const nodeSlow = { id: 'slowA', label: 'SLOWA', execplanEntity: 'execplan:slowa', focus: { execplan_slug: 'slowa' }, leases: [] };
    const nodeFast = { id: 'fastB', label: 'FASTB', execplanEntity: 'execplan:fastb', focus: { execplan_slug: 'fastb' }, leases: [] };
    const apiRace = {
      sessionsBySessionIdObservations: function (id) { return id === 'slowA' ? fakeResLater(true, 200, obsFixture) : fakeRes(true, 200, obsFixture); },
      factsEntityByEntity: function () { return fakeRes(true, 200, factsFixture); }
    };
    const hostRace = mock.mkNode('div');
    const pSlow = render.renderSessionDetail(hostRace, nodeSlow, apiRace);   // in-flight (slow)
    const pFast = render.renderSessionDetail(hostRace, nodeFast, apiRace);   // supersedes
    asyncChecks.push(Promise.all([pSlow, pFast]).then(function () {
      const txt = hostRace.textContent || '';
      check(/FASTB/.test(txt) && !/SLOWA/.test(txt),
        '[session-detail] a stale in-flight paint (slow A) is dropped — only the latest selection (fast B) paints (got: ' + txt.slice(0, 60) + ')');
    }).catch(function (e) { check(false, '[session-detail] race drive threw: ' + (e && e.stack || e)); }).then(function () {
      if (savedDoc2 === undefined) { delete global.document; } else { global.document = savedDoc2; }
      if (savedWin === undefined) { delete global.window; } else { global.window = savedWin; }
    }));
  }

  notes.push('session-detail (M4b): buildSessionDetail joins receipts (observations feed — a neutral "receipt envelope" chip + the daemon-reported chain status VERBATIM, never a client-side "signed"/"intact" verification claim) + fact provenance (/v1/facts/entity/<RESOLVED ExecPlan entity> — only for sessions that resolved to an ExecPlan; kanban/unattached → no_plan absent, never guessing execplan:<announced-slug>) + announced focus (from the node — no re-fetch) over EXISTING GET routes only. Transcript is reference-only: rendered from an id/path ALREADY on the node (coord announcement), NEVER by fetching session state (that blob can embed content — no state read is issued). Only a canonical [REDACTED:…] value renders the redaction marker; empty is honest-empty. Any non-ok feed → degraded; reachable-empty → absent. renderSessionDetail drives EXACTLY {observations[, facts]} (asserted as an exact multiset), guards a per-host selection token so a stale slow paint cannot overwrite a newer selection, and adds no transcript route/method.');
})();

// =========================================================================
//  Check 45 — (desktop mission control M4c, console half) stale-plan mismatch
//  badge. PR #457 adds `plan_content_hash` (lowercase BLAKE3 hex) to ExecPlan
//  /v1/work items. planHashBadge(daemon_hash, local_hash|null) is a pure function:
//  the browser cannot read local files, so with no local hash it renders a
//  provenance chip (daemon short-form); the desktop shell (M5a) supplies a local
//  hash, and both-present-and-differing renders a visible mismatch badge (T.2
//  guard). buildPlanTree wires it onto ExecPlan nodes; the row paints the chip.
// =========================================================================
(function checkPlanHashBadge() {
  check(typeof render.planHashBadge === 'function', '[plan-hash] render.js must export planHashBadge()');
  if (typeof render.planHashBadge !== 'function') { return; }

  // Pure function — the four honest states.
  check(render.planHashBadge(null, null) === null && render.planHashBadge('', 'x') === null,
    '[plan-hash] no daemon hash → no badge (nothing projected to attest)');
  const prov = render.planHashBadge('abcdef0123456789', null);
  check(prov && prov.kind === 'provenance' && prov.code === 'daemon_only' && prov.short === 'abcdef012345',
    '[plan-hash] local_hash null → provenance chip carrying the daemon hash short-form (browser cannot read local files)');
  const sync = render.planHashBadge('ABCDEF', 'abcdef');
  check(sync && sync.kind === 'insync' && sync.code === 'in_sync',
    '[plan-hash] equal hashes (case-insensitive) → in-sync chip');
  const drift = render.planHashBadge('aaaa1111', 'bbbb2222');
  check(drift && drift.kind === 'mismatch' && drift.code === 'stale_plan' && drift.short === 'aaaa1111' && drift.localShort === 'bbbb2222',
    '[plan-hash] differing hashes → mismatch badge (T.2 guard) carrying both short-forms');

  // buildPlanTree wiring: daemon hash defensive; local hash from data.localPlanHashes
  // (by id then bare slug). No hash on the item → no badge.
  const fixture = {
    work: { work: [
      { id: 'execplan:alpha', project_id: 'execplans', title: 'Alpha', plan_content_hash: 'aaaaaaaaaaaa1111' },   // local matches
      { id: 'execplan:beta', project_id: 'execplans', title: 'Beta', plan_content_hash: 'bbbbbbbbbbbb2222' },     // local differs
      { id: 'execplan:gamma', project_id: 'execplans', title: 'Gamma', plan_content_hash: 'cccccccccccc3333' },   // no local entry
      { id: 'execplan:delta', project_id: 'execplans', title: 'Delta' }                                            // no daemon hash
    ] },
    localPlanHashes: { 'alpha': 'aaaaaaaaaaaa1111', 'execplan:beta': 'ffffffffffff9999' }
  };
  const roots = (render.buildPlanTree(fixture).roots) || [];
  const exec = roots.find(function (n) { return n.type === 'project' && n.id === 'execplans'; });
  function planById(id) { return exec ? (exec.children || []).find(function (n) { return n.id === id; }) : null; }
  const alpha = planById('execplan:alpha'), beta = planById('execplan:beta'), gamma = planById('execplan:gamma'), delta = planById('execplan:delta');
  check(alpha && alpha.planBadge && alpha.planBadge.kind === 'insync', '[plan-hash] a plan whose local hash (resolved by bare slug) matches → in-sync badge');
  check(beta && beta.planBadge && beta.planBadge.kind === 'mismatch', '[plan-hash] a plan whose local hash (resolved by full id) differs → mismatch badge');
  check(gamma && gamma.planBadge && gamma.planBadge.kind === 'provenance', '[plan-hash] a plan with a daemon hash but no local entry → provenance chip');
  check(delta && delta.planBadge == null, '[plan-hash] a plan with no daemon hash carries no badge (forward-compatible before PR #457 ships)');

  // Row paints the chip with its state class AND a data-hash-state attribute.
  const mock = newMockDom();
  const savedDoc = global.document;
  global.document = mock.doc;
  try {
    function hashChip(node, code) { return mock.collect(render.planTreeNode(node, 0), []).find(function (n) { return n.getAttribute('data-hash-state') === code; }) || null; }
    const mmChip = hashChip(beta, 'stale_plan');
    check(mmChip && /\bplan-tree-hash-mismatch\b/.test(mmChip.className || ''),
      '[plan-hash] a mismatched ExecPlan row paints a chip with data-hash-state="stale_plan" + the mismatch class (T.2 guard)');
    const provChip = hashChip(gamma, 'daemon_only');
    check(provChip && /\bplan-tree-hash-prov\b/.test(provChip.className || ''),
      '[plan-hash] a provenance-only ExecPlan row paints a chip with data-hash-state="daemon_only" + the provenance class');
    check(mock.collect(render.planTreeNode(delta, 0), []).every(function (n) { return n.getAttribute('data-hash-state') == null; }),
      '[plan-hash] a plan with no daemon hash paints no hash chip at all');
  } catch (e) {
    check(false, '[plan-hash] planTreeNode hash-chip render threw: ' + (e && e.stack || e));
  } finally {
    if (savedDoc === undefined) { delete global.document; } else { global.document = savedDoc; }
  }

  notes.push('plan-hash badge (M4c console half): planHashBadge(daemon_hash, local_hash|null) is pure — no daemon hash → no badge; no local hash → provenance chip (daemon short-form, since the browser cannot read local files); equal → in-sync; differing → mismatch badge (T.2 guard); buildPlanTree wires it onto ExecPlan nodes (daemon hash read defensively so it is forward-compatible before PR #457 ships; local hash from data.localPlanHashes by id then slug) and the row paints the state-classed chip carrying data-hash-state.');
})();

// ---- Report (awaits async renderer-driven checks) -----------------------
Promise.all(asyncChecks).then(function () {
  console.log('unified-shell-console v2 — M14 + desktop mission control M2 smoke');
  notes.forEach(function (n) { console.log('  · ' + n); });
  if (failures.length) {
    console.error('\nFAIL (' + failures.length + '):');
    failures.forEach(function (f) { console.error('  ✗ ' + f); });
    process.exit(1);
  }
  console.log('\nPASS — all gates green (incl. M4a plan-rooted tree join: kanban/ExecPlan discrimination, no-fabricated-edges, named-ids-only milestones, focus+leases on nodes, fail-honest-per-feed).');
  process.exit(0);
});
