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

  // The curated set the M3 plan authorises — the ONLY writes the console may do.
  const EXPECTED = [
    ['POST', '/v1/work/gate/{actionId}/approve'],
    ['POST', '/v1/work/gate/{actionId}/reject'],
    ['POST', '/v1/work/{id}/comments'],
    ['POST', '/v1/actions/enrich']
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
  // No mutating verbs beyond the curated count anywhere in api.js.
  const verbCount = (apiSrc.match(/method:\s*'(POST|PUT|PATCH|DELETE)'/g) || []).length;
  check(verbCount === EXPECTED.length, '[gated] api.js has ' + verbCount + ' mutating fetch(es); expected ' + EXPECTED.length);

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
  // Registry with the three slots (documents reserved / not selectable).
  check(/var MODES = \[/.test(shellHtml), '[mode] shell.html must declare a MODES registry');
  ['standard', 'professional', 'documents'].forEach(function (m) {
    check(new RegExp("id:\\s*'" + m + "'").test(shellHtml), '[mode] MODES must include the "' + m + '" slot');
  });
  check(/soon:\s*true/.test(shellHtml), '[mode] the reserved third slot (documents) must be marked soon:true (visible but not selectable)');
  check(/arrives in M10/.test(shellHtml), '[mode] the reserved documents slot must be labelled "arrives in M10"');
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
  check(am && /window\.CRUX_MODE\s*=/.test(am), '[mode] applyMode must set window.CRUX_MODE for render.js proMode()');
  check(am && !/setPosture|isOperator|CRUX_POSTURE|derivePosture/.test(am),
    '[mode] applyMode must NOT touch posture — mode is presentation, posture is the security boundary');
  // render.js honours the mode: proMode() reads window.CRUX_MODE; renderSections
  // drops pro:true sections in Standard; the Overwatch dashboard strip is Pro-only.
  check(typeof render.proMode === 'function', '[mode] render.js must export proMode()');
  check(/window\.CRUX_MODE/.test(renderSrc), '[mode] render.js proMode() must read window.CRUX_MODE');
  check(/sections\[i\]\.pro/.test(renderSrc), '[mode] renderSections must drop pro:true sections outside Professional mode');
  check(/renderDashStrip/.test(renderSrc) && /proMode\(\)/.test(renderSrc), '[mode] the Overwatch dashboard strip must be Pro-only (proMode()-guarded)');
  // POSTURE INDEPENDENCE (statically): no posture function branches on mode.
  const modeTokens = /CRUX_MODE|data-mode|crux\.console\.mode|proMode|professional/;
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
  Object.keys(LP || {}).forEach(function (id) {
    check(expectedSet.has(id), '[port] LEGACY_PORT has a stray key not in the known legacy inventory: ' + id);
  });
  check(Object.keys(LP || {}).length === EXPECTED.length,
    '[port] LEGACY_PORT must cover EXACTLY the ' + EXPECTED.length + '-section legacy inventory; got ' + Object.keys(LP || {}).length);
  // Disposition targets resolve.
  const proPorted = new Set(pages.PRO_PORTED_IDS || []);
  Object.keys(LP || {}).forEach(function (id) {
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
  Object.keys(LP || {}).forEach(function (id) { tally[LP[id].split(':')[0]]++; });
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
  // Node styling by type uses theme tokens (project=acc, passport=trust, session=ok, gate=warn).
  check(/\.g-project\s*\{[^}]*var\(--acc\)/.test(shellHtml) && /\.g-passport\s*\{[^}]*var\(--trust\)/.test(shellHtml) &&
    /\.g-session\s*\{[^}]*var\(--ok\)/.test(shellHtml) && /\.g-gate\s*\{[^}]*var\(--warn\)/.test(shellHtml),
    '[graph] node fills must come from theme tokens (project=acc · passport=trust · session=ok · gate=warn)');
  // Pan (drag) + zoom (wheel).
  check(/canvas-graph-svg/.test(shellHtml) && /addEventListener\('wheel'/.test(renderSrc) && /addEventListener\('mousedown'/.test(renderSrc),
    '[graph] the graph must support pan (mousedown drag) + zoom (wheel)');
  notes.push('canvas graph: real-edge-only model (grounded fields, dangling edges dropped), deterministic layered layout, pan+zoom, focus parser (work/session/project/passport), launch points on fleet/work/project/gate.');
})();

// ---- Report -------------------------------------------------------------
console.log('unified-shell-console v2 — M9 (canvas) smoke');
notes.forEach(function (n) { console.log('  · ' + n); });
if (failures.length) {
  console.error('\nFAIL (' + failures.length + '):');
  failures.forEach(function (f) { console.error('  ✗ ' + f); });
  process.exit(1);
}
console.log('\nPASS — all gates green (26/26 ids incl. pill:false landing-render + 4 Pro-ported legacy pages, control coverage, theme contrast, posture gate, no external deps, through-client fetches, gated-mutations audit, posture derivation, engine mediation, PWA manifest, service worker, phone tier, demo-mode gating, unified buttons, collapsible rail, status pill + chips, charts, board strips, nav-family consolidation + rail-at-rest-borderless, projects disclosure + repo grid, topbar chip height, legacy LED toggle + squarer topbar chips + list-row language, M8 mode system + posture-independence, M8 legacy port-checklist integrity, M9 canvas board (canvasTier + widget registry), M9 canvas graph (real-edge-only model + focus parser + launch points)).');
process.exit(0);
