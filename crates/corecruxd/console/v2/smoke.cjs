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
function check(ok, msg) { if (!ok) { failures.push(msg); } }

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
  (page.sections || []).forEach(function (s) { walkControls(s.controls, fn); });
  if (page.load && typeof page.load.build === 'function') {
    // Exercise both branches so degraded + populated control types are seen.
    [{ ok: true, status: 200, data: {} }, { ok: false, status: 0, data: null }].forEach(function (res) {
      let sections;
      try { sections = page.load.build(res); } catch (e) { sections = []; }
      (sections || []).forEach(function (s) { walkControls(s.controls, fn); });
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
  Object.keys(pages.PAGES).forEach(function (id) {
    if (LEGACY_26.indexOf(id) >= 0) { return; }
    check(proPorted.has(id), '[ids] unexpected page id not in the legacy 26 nor PRO_PORTED_IDS: ' + id);
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
  const verbCount = (apiSrc.match(/method:\s*'(POST|PUT|PATCH|DELETE)'/g) || []).length;
  const verbExpected = EXPECTED.length + READ_POST_EXPECTED.length;
  check(verbCount === verbExpected, '[gated] api.js has ' + verbCount + ' non-GET fetch(es); expected ' + verbExpected + ' (' + EXPECTED.length + ' gated writes + ' + READ_POST_EXPECTED.length + ' curated read POSTs)');

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
  const found = { newp: false, addr: false };
  walkPage(pages.PAGES['cx-projects'], function (c) {
    if (c.t === 'disclose' && c.requires === 'operator') {
      if (/New project/.test(c.label || '')) { found.newp = true; }
      if (/Add repos/.test(c.label || '')) { found.addr = true; }
    }
  });
  check(found.newp, '[projects] "＋ New project" must be an operator-tagged (requires:operator) disclose control');
  check(found.addr, '[projects] "＋ Add repos" must be an operator-tagged (requires:operator) disclose control');
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
//  Check 28 — (M10) legacy retirement. (a) LEGACY_PORT.retired_at marker.
//  (b) the v2 shell carries the "(legacy — retired, kept as fallback)" copy on
//  the /console/legacy link (retained as a fallback, not dropped). (c) the
//  console.rs serve_console_legacy handler carries a DEPRECATED doc-comment
//  referencing the ExecPlan slug (read via a relative path — comment-only, the
//  flag-off byte-parity test proves the served body is unchanged).
// =========================================================================
(function checkRetirement() {
  check(pages.LEGACY_PORT && pages.LEGACY_PORT.retired_at === '2026-07-03',
    '[retire] LEGACY_PORT.retired_at must be "2026-07-03" (the formal legacy-console retirement date)');
  check(/\(legacy — retired, kept as fallback\)/.test(pagesSrc),
    '[retire] the v2 /console/legacy link must carry the "(legacy — retired, kept as fallback)" copy');
  check(pagesSrc.indexOf('/console/legacy') >= 0,
    '[retire] the v2 shell must keep /console/legacy reachable as a fallback (not removed)');
  const consoleRsPath = path.join(DIR, '..', '..', 'src', 'console.rs');
  let consoleRs = '';
  try { consoleRs = fs.readFileSync(consoleRsPath, 'utf8'); }
  catch (e) { check(false, '[retire] could not read console.rs at ' + consoleRsPath + ': ' + e.message); }
  const legAt = consoleRs.indexOf('fn serve_console_legacy');
  check(legAt >= 0, '[retire] console.rs must define serve_console_legacy');
  const preamble = legAt >= 0 ? consoleRs.slice(Math.max(0, legAt - 1200), legAt) : '';
  check(/DEPRECATED/.test(preamble) && /unified-shell-console-2026-07-03/.test(preamble),
    '[retire] serve_console_legacy must carry a DEPRECATED doc-comment referencing the ExecPlan slug');
  check(/fallback/.test(preamble),
    '[retire] the deprecation comment must note the legacy console is retained only as a fallback');
  notes.push('retirement (M10): LEGACY_PORT.retired_at=2026-07-03 · v2 legacy-fallback copy · console.rs serve_console_legacy DEPRECATED doc-comment (ExecPlan-referenced, comment-only).');
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
    const host = mkEl('div');
    const rail = mkEl('nav');
    render.renderDocuments(host, { summary: null, docId: null, railHost: rail });
    // SYNCHRONOUS assertions — the reader must exist before any fetch resolves.
    check(host.querySelectorAll('.doc-main').length === 1, '[documents] renderDocuments must paint a .doc-main synchronously (daemon-hang case)');
    check(host.querySelectorAll('.doc-reader').length === 1, '[documents] renderDocuments must paint the reader synchronously');
    check(rail.querySelectorAll('.nav-item').length >= 3, '[documents] renderDocuments must populate the Explore rail synchronously (Explorer + surface pages, >=3 nav-items)');
    notes.push('documents reader (M11): renderDocuments paints .doc-main + a >=3-item Explore rail (Explorer + surface Pages, Command .nav-item style) synchronously under a never-resolving daemon. Docs/corpora reached via Explorer results, not the menu.');
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
      check(/fetchJSON\(/.test(body), '[honesty] real surface ' + id + ' must read via the api.js client (fetchJSON)');
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
      '[overwatch] Fleet must sit UNDER Needs-you in the LEFT column');
    check(/right\.appendChild\(owPageNav\(\)\)/.test(landing), '[overwatch] the RIGHT column must carry the destination page nav (owPageNav)');
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
      check(left.querySelectorAll('.ow-panel').length === 2, '[overwatch] LEFT column must hold exactly 2 panels (Needs-you + Fleet)');
      check(left.querySelectorAll('.ow-pagenav').length === 0, '[overwatch] the page nav must NOT be in the LEFT column');
      check(right.querySelectorAll('.ow-pagenav').length === 1, '[overwatch] the page nav must be in the RIGHT column');
      const lp = left.querySelectorAll('.ow-panel');
      check(panelTitle(lp[0]) === 'Needs you', '[overwatch] LEFT column panel 1 must be Needs-you (got ' + panelTitle(lp[0]) + ')');
      check(panelTitle(lp[1]) === 'Fleet', '[overwatch] LEFT column panel 2 must be Fleet — directly under Needs-you (got ' + panelTitle(lp[1]) + ')');
    }
    // The page nav lists the overwatch destination pages, deep-linked.
    const pn = region.querySelectorAll('.ow-pagenav')[0];
    check(pn && pn.querySelectorAll('.pill').length >= 5, '[overwatch] the page nav must list the overwatch destination pages (>=5 pills)');
    if (pn) {
      const hrefs = pn.querySelectorAll('.pill').map(function (a) { return a.getAttribute('href'); });
      check(hrefs.indexOf('#/overwatch/cx-activity') >= 0, '[overwatch] the page nav must deep-link Activity (#/overwatch/cx-activity)');
      check(hrefs.every(function (h) { return /^#\/overwatch\//.test(h); }), '[overwatch] every page-nav pill must deep-link into #/overwatch/<id>');
    }
    notes.push('overwatch layout (rework): no ow-dashstrip + no ow-ticker; Daemon-at-a-glance adds ExecPlans (/v1/work) + Token usage (/v1/cost/report) + a moved Engine tile; Facts/Sessions/ExecPlans at legacy stat-lg size; charts are real-series-or-demoOn()-guarded-or-honest-meter; Fleet under Needs-you (left); page nav in the right column (sub-nav pills suppressed for overwatch).');
  } catch (e) {
    check(false, '[overwatch] renderOverwatchLanding threw on the synchronous paint: ' + (e && e.stack || e));
  } finally {
    if (savedDoc === undefined) { delete global.document; } else { global.document = savedDoc; }
    if (savedWin === undefined) { delete global.window; } else { global.window = savedWin; }
    if (savedLoc === undefined) { delete global.location; } else { global.location = savedLoc; }
  }
})();

// ---- Report -------------------------------------------------------------
console.log('unified-shell-console v2 — M13b (live mutation wiring) smoke');
notes.forEach(function (n) { console.log('  · ' + n); });
if (failures.length) {
  console.error('\nFAIL (' + failures.length + '):');
  failures.forEach(function (f) { console.error('  ✗ ' + f); });
  process.exit(1);
}
console.log('\nPASS — all gates green (26/26 ids incl. pill:false landing-render + 4 Pro-ported legacy pages, control coverage, theme contrast, posture gate, no external deps, through-client fetches, gated-mutations audit, posture derivation, engine mediation, PWA manifest, service worker, phone tier, demo-mode gating, unified buttons, collapsible rail, status pill + chips, charts, board strips, nav-family consolidation + rail-at-rest-borderless, projects disclosure + repo grid, topbar chip height, legacy LED toggle + squarer topbar chips + list-row language, M8 mode system + posture-independence, M8 legacy port-checklist integrity, M9 canvas board (canvasTier + widget registry), M9 canvas graph (real-edge-only model + focus parser + launch points), M10 documents mode (3-mode reader + ~72ch measure + evidence panel + real sources + demo Proof fixture + deep-link-out auto-switch), M10 legacy retirement (retired_at + fallback copy + console.rs DEPRECATED comment), M12 11-surface JSX port (DOC_SURFACES + JSX_PORT + rail nav + #/documents/<id> routes + real-vs-demo honesty), M13a safe control parity + native workbench port (CONTROL_DIFF covers all 26 CX pages; cx-workbench loads /v1/workbench/contract + 5 GET read tools via a GET-only self-loader), M13b live mutation wiring (19 write controls live behind the guard harness — operatorGatedCall→CruxApiGated + bound-passport Art.14 refusal + confirm dialog on the destructive/spend subset + real receipt; 22 curated GATED_MUTATIONS; 8 controls stay operator-gated + disabled for documented ungroundable/invariant reasons; customer posture hides AND refuses every write)).');
process.exit(0);
