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
//   2. every control type used in pages.js has a renderer branch in render.js.
//   3. the three theme CSS blocks in shell.html clear the WCAG contrast floor
//      (ink/ink2 >= 4.5:1, ink3 >= 4.0:1, over bg AND over surface).
//   4. every MUTATING_ACTIONS entry maps to a control tagged mut:true, and
//      render.js routes mutating controls through the operator posture gate.
//   5. no v2 file loads an external http(s) dependency.

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
  // No stray pages outside the 26.
  Object.keys(pages.PAGES).forEach(function (id) {
    check(LEGACY_26.indexOf(id) >= 0, '[ids] unexpected page id not in the legacy 26: ' + id);
  });
  notes.push('26/26 legacy CX ids mapped across ' + destIds.size + ' destinations.');
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
  return { bg: v('bg'), surface: v('surface'), ink: v('ink'), ink2: v('ink2'), ink3: v('ink3') };
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

// ---- Report -------------------------------------------------------------
console.log('unified-shell-console v2 — M1 smoke');
notes.forEach(function (n) { console.log('  · ' + n); });
if (failures.length) {
  console.error('\nFAIL (' + failures.length + '):');
  failures.forEach(function (f) { console.error('  ✗ ' + f); });
  process.exit(1);
}
console.log('\nPASS — all M1 gates green (26/26 ids, control-type coverage, theme contrast, posture gate, no external deps).');
process.exit(0);
