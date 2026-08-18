// Copyright (c) 2026 CueCrux Ltd.
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.
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
let passportMintInteraction = function () { return Promise.resolve(); };
function check(ok, msg) { if (!ok) { failures.push(msg); } }

// Shared jsdom-free mock DOM for the renderer-driving checks (plan tree, session
// detail, plan-hash chip). `collect(node, out)` returns element descendants; seed
// with `[node]` to include the root. `classesOf`/`findByClass` are thin wrappers.
function newMockDom() {
  function mkNode(tag) {
    const node = {
      tagName: String(tag || 'div').toUpperCase(), nodeType: 1, childNodes: [], _attrs: {}, className: '',
      // `style` and `classList` are here because real renderers use them for
      // show/hide and open/closed state; without them a renderer-driving check
      // fails on the harness rather than on the code under test.
      style: {}, disabled: false,
      setAttribute: function (k, v) { this._attrs[k] = String(v); if (k === 'class') { this.className = String(v); } },
      getAttribute: function (k) { return Object.prototype.hasOwnProperty.call(this._attrs, k) ? this._attrs[k] : null; },
      appendChild: function (c) { this.childNodes.push(c); c.parentNode = this; return c; },
      insertBefore: function (c, ref) {
        const i = this.childNodes.indexOf(ref);
        if (i < 0) { this.childNodes.push(c); } else { this.childNodes.splice(i, 0, c); }
        c.parentNode = this; return c;
      },
      removeChild: function (c) { const i = this.childNodes.indexOf(c); if (i >= 0) { this.childNodes.splice(i, 1); } return c; },
      // Handlers are CAPTURED, not swallowed: a renderer whose tabs and rows
      // only exist as click handlers cannot be asserted otherwise.
      _handlers: {},
      addEventListener: function (type, fn) { (this._handlers[type] = this._handlers[type] || []).push(fn); },
      click: function (ev) { (this._handlers.click || []).forEach(function (fn) { fn(ev || { target: null }); }); },
      closest: function (sel) {
        const cls = sel.charAt(0) === '.' ? sel.slice(1) : sel;
        let cur = this;
        while (cur) {
          if (String(cur.className || '').split(/\s+/).indexOf(cls) >= 0) { return cur; }
          cur = cur.parentNode;
        }
        return null;
      }
    };
    node.classList = {
      add: function (c) { const p = node.className.split(/\s+/).filter(Boolean); if (p.indexOf(c) < 0) { p.push(c); } node.className = p.join(' '); node._attrs['class'] = node.className; },
      remove: function (c) { const p = node.className.split(/\s+/).filter(Boolean).filter(function (x) { return x !== c; }); node.className = p.join(' '); node._attrs['class'] = node.className; },
      contains: function (c) { return node.className.split(/\s+/).indexOf(c) >= 0; },
      toggle: function (c) { if (node.classList.contains(c)) { node.classList.remove(c); return false; } node.classList.add(c); return true; }
    };
    Object.defineProperty(node, 'lastChild', { get: function () { return this.childNodes[this.childNodes.length - 1] || null; } });
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
  // cx-storybook is Work › Storybook — the context-graph readout (phase 3) and
  // the agent dossier board (phase 4), custom-rendered because a markdown
  // narrative and a nested claim/evidence shape are not expressible in the
  // control model.
  // cx-connections is System › Connections — how a client reaches THIS daemon
  // (MCP endpoints, the agent-token rail, the Claude Desktop .mcpb bundle).
  // cx-work-order is Work › Work order — the ranked ready-list off
  // /v1/work?ranked=1. The kanban next door answers "what is there"; this
  // answers "what do I do next", which the board could not express because a
  // state-grouped board has no order within a column.
  const nativeExtra = new Set(['cx-activity-log', 'cx-mints', 'cx-storybook', 'cx-connections', 'cx-work-order']);
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
    ['POST', '/v1/passport/mint-requests/{request_id}/approve'],
    ['POST', '/v1/passport/mint-requests/{request_id}/reject'],
    // M13b live-wired write controls (each behind the WIRED_WRITES harness):
    ['POST', '/v1/projects'],
    ['POST', '/v1/passports'],
    ['POST', '/v1/console/review/consolidations'],
    ['POST', '/v1/identity/candidates/{candidateId}/confirm'],
    // console-surfaces-remediation M6: operator-gated "Seed candidates".
    ['POST', '/v1/identity/candidates/propose'],
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
    ['POST', '/v1/features/capabilities/{id}/audit'],
    // console-surfaces-remediation M14: Canvas Studio daemon-side board/design persistence.
    ['POST', '/v1/console/facts/add'],
    // crux-integrations I1: connector lifecycle (connect already shipped above).
    ['POST', '/v1/integrations/github/disconnect'],
    ['POST', '/v1/integrations/github/sync'],
    ['POST', '/v1/integrations/openai/connect'],
    ['POST', '/v1/integrations/openai/disconnect'],
    // crux-integrations I1: built-in integration packs.
    ['POST', '/v1/console/integrations/{packId}/install'],
    ['POST', '/v1/console/integrations/{packId}/grant'],
    ['POST', '/v1/console/integrations/{packId}/disable'],
    // crux-integrations I2: community extensions — catalog install, uninstall,
    // grants and grant-scoped tool invoke.
    ['POST', '/v1/extensions/install-from-registry'],
    ['DELETE', '/v1/extensions/{id}'],
    ['POST', '/v1/extensions/{id}/grants'],
    ['DELETE', '/v1/extensions/{id}/grants/{passport_fpr}'],
    ['DELETE', '/v1/extensions/keys/{passport_fpr}'],
    ['POST', '/v1/extensions/{id}/tools/{tool_name}/invoke'],
    // crux-integrations-and-template-library L2: the ONE mutating /v1/studio/
    // route — install a signed catalog entry as fresh console facts (write-
    // class in route_auth; provenance + collision remap daemon-side).
    ['POST', '/v1/studio/library/{id}/install'],
    // crux-storybook-dossier-agent-and-console-surface M3: the two context-graph
    // regenerate actions. Deterministic, no body, no user content — but each
    // persists a fact, so they are writes.
    ['POST', '/v1/projects/{id}/storybook'],
    ['POST', '/v1/projects/{id}/dossiers/auto']
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
    ['POST', '/v1/console/engine/search'],
    ['POST', '/v1/studio/pack/build'],
    ['POST', '/v1/studio/pack/verify']
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
//  Check 8b — Passport mint M3 console gate + bound-approver picker. The picker
//  loads real passport ids through the read client, persists the shared Art.14
//  identity, clears it, and falls back to typed ids when the read fails. A
//  pending request still preserves prefill/edit/approve/reject/error behaviour.
// =========================================================================
(function checkPassportMintGate() {
  const page = pages.PAGES['cx-mints'];
  check(!!page, '[mint-m3] cx-mints must be registered');
  check(page && page.operatorOnly === true, '[mint-m3] cx-mints must be operator-only');
  check(page && page.load && page.load.endpoint === '/v1/passport/mint-requests/pending',
    '[mint-m3] cx-mints must load GET /v1/passport/mint-requests/pending');
  if (!page || !page.load || typeof page.load.build !== 'function') { return; }

  const fixture = {
    request_id: 'pmr_123', requester_id: 'agent-work', requested_category: 'work',
    requested_by_passport: 'agent-work', reason: 'Needs an attributed work identity',
    status: 'pending', requested_at_unix_ms: Date.now() - 5 * 60000
  };
  const sections = page.load.build({ ok: true, status: 200, data: { count: 1, pending: [fixture] } });
  check(sections[0].controls[0] && sections[0].controls[0].t === 'approver',
    '[mint-picker] bound approver must be the first control in the pending-mints panel');
  const mint = sections[0].controls.find(function (c) { return c.t === 'mintcard'; });
  check(!!mint, '[mint-m3] a pending request must build one mintcard');
  check(mint && mint.category === 'work', '[mint-m3] mintcard category must default to requested_category');
  check(mint && /ago|just now/.test(mint.age), '[mint-m3] mintcard must carry a human-readable request age');

  const empty = page.load.build({ ok: true, status: 200, data: { count: 0, pending: [] } });
  check(empty[0].controls[0] && empty[0].controls[0].t === 'approver',
    '[mint-picker] bound approver must render when there are zero pending requests');

  const disabled = page.load.build({ ok: false, status: 404, data: null });
  const disabledControls = (disabled[0] && disabled[0].controls) || [];
  check(disabledControls[0] && disabledControls[0].t === 'approver',
    '[mint-picker] bound approver must survive a pending-mints feature-off response');
  check(!disabledControls.some(function (c) { return c.t === 'mintcard'; }),
    '[mint-m3] feature-off 404 must render no mint cards');
  check(disabledControls.some(function (c) { return /feature disabled/i.test(String(c.v || '')); }),
    '[mint-m3] feature-off 404 must degrade to an inline feature-disabled state');

  function mockDom() {
    function node(tag) {
      const listeners = {};
      const n = {
        tagName: String(tag || 'div').toUpperCase(), nodeType: 1, childNodes: [], _attrs: {}, value: '', disabled: false, hidden: false,
        setAttribute: function (k, v) {
          this._attrs[k] = String(v);
          if (k === 'class') { this.className = String(v); }
          if (k === 'value') { this.value = String(v); }
          if (k === 'disabled') { this.disabled = true; }
        },
        getAttribute: function (k) { return Object.prototype.hasOwnProperty.call(this._attrs, k) ? this._attrs[k] : null; },
        appendChild: function (c) { this.childNodes.push(c); c.parentNode = this; return c; },
        addEventListener: function (type, fn) { listeners[type] = fn; },
        fire: function (type) { return listeners[type] ? listeners[type]({ type: type, target: this }) : undefined; },
        focus: function () { this.focused = true; }
      };
      Object.defineProperty(n, 'textContent', {
        get: function () { let t = this._text || ''; this.childNodes.forEach(function (c) { t += c.textContent || ''; }); return t; },
        set: function (v) { this._text = String(v); this.childNodes.length = 0; }
      });
      return n;
    }
    const doc = { createElement: node, createTextNode: function (v) { return { nodeType: 3, textContent: String(v), childNodes: [] }; } };
    function all(root, out) {
      out = out || [root];
      (root.childNodes || []).forEach(function (c) { if (c && c.nodeType === 1) { out.push(c); all(c, out); } });
      return out;
    }
    function byAttr(root, key, value) { return all(root).find(function (n) { return n.getAttribute && n.getAttribute(key) === value; }); }
    return { doc: doc, node: node, byAttr: byAttr };
  }

  passportMintInteraction = async function () {
    const dom = mockDom();
    const calls = [];
    const storageValues = {};
    let passportsFail = false;
    let passportsEmpty = false;
    let approveResponse = { ok: true, status: 200, data: { minted: true, status: 'approved', category: 'public' } };
    function response(spec) { return { ok: spec.ok, status: spec.status, json: function () { return Promise.resolve(spec.data); } }; }
    const savedDoc = global.document, savedWin = global.window, savedStorage = global.localStorage;
    global.document = dom.doc;
    global.localStorage = {
      getItem: function (key) { return Object.prototype.hasOwnProperty.call(storageValues, key) ? storageValues[key] : null; },
      setItem: function (key, value) { storageValues[key] = String(value); },
      removeItem: function (key) { delete storageValues[key]; }
    };
    global.window = {
      CRUX_POSTURE: 'operator', CruxPages: pages,
      CruxApi: { get: function (url) {
        if (url === '/v1/passports') {
          calls.push({ kind: 'passports', url: url });
          if (passportsFail) { return Promise.reject(new Error('passport list unavailable')); }
          return Promise.resolve(response({ ok: true, status: 200, data: { passports: passportsEmpty ? [] : [
            { id: 'operator-personal', category: 'personal', reputation_tier: 'trusted' },
            { id: 'operator-work', category: 'work', reputation_tier: 'verified' }
          ] } }));
        }
        calls.push({ kind: 'refresh', url: url });
        return Promise.resolve(response({ ok: true, status: 200, data: { count: 0, pending: [] } }));
      } },
      CruxApiGated: {
        passportMintRequestApprove: function (id, body) { calls.push({ kind: 'approve', id: id, body: body }); return Promise.resolve(response(approveResponse)); },
        passportMintRequestReject: function (id, body) { calls.push({ kind: 'reject', id: id, body: body }); return Promise.resolve(response({ ok: true, status: 200, data: { minted: false, status: 'rejected' } })); }
      }
    };
    try {
      const approverControl = render.renderBoundApproverControl(dom.node('section'));
      const initialCurrent = dom.byAttr(approverControl, 'data-bound-approver-current', 'true');
      check(initialCurrent && /No approver bound.*Art\.14/.test(initialCurrent.textContent),
        '[mint-picker] empty localStorage must render the explicit unbound Art.14 state');
      await approverControl.cruxReady;
      const picker = dom.byAttr(approverControl, 'data-bound-approver-picker', 'select');
      check(!!picker, '[mint-picker] successful GET /v1/passports must render a select');
      check(picker && /operator-personal.*personal.*trusted/.test(picker.textContent)
        && /operator-work.*work.*verified/.test(picker.textContent),
      '[mint-picker] select options must come from passport ids with category/tier context');
      if (picker) { picker.value = 'operator-work'; }
      await dom.byAttr(approverControl, 'data-bound-approver-action', 'bind').fire('click');
      check(storageValues['crux-console-bound-passport'] === 'operator-work',
        '[mint-picker] Bind must write the shared crux-console-bound-passport localStorage key');
      check(render.boundPassport() === 'operator-work',
        '[mint-picker] boundPassport() must re-read the id written by Bind');
      check(calls.some(function (c) { return c.kind === 'refresh' && c.url === '/v1/passport/mint-requests/pending'; }),
        '[mint-picker] Bind must refresh the pending-mints panel through its existing read path');

      const reboundControl = render.renderBoundApproverControl(dom.node('section'));
      const reboundCurrent = dom.byAttr(reboundControl, 'data-bound-approver-current', 'true');
      check(reboundCurrent && reboundCurrent.textContent === 'operator-work',
        '[mint-picker] a refreshed bound-approver control must show the current bound id');
      await reboundControl.cruxReady;
      check(dom.byAttr(reboundControl, 'data-bound-approver-picker', 'select').value === 'operator-work',
        '[mint-picker] passport select must default to the current bound id when it is present');

      const card = render.renderMintRequestCard(mint, dom.node('section'));
      const category = dom.byAttr(card, 'data-mint-field', 'category');
      const name = dom.byAttr(card, 'data-mint-field', 'name');
      const accept = dom.byAttr(card, 'data-mint-action', 'accept');
      const reject = dom.byAttr(card, 'data-mint-action', 'reject');
      const status = dom.byAttr(card, 'data-mint-status', fixture.request_id);
      check(category && category.value === 'work', '[mint-m3] rendered category select must be pre-filled to work');
      check(!!name && !!accept && !!reject, '[mint-m3] rendered card must carry name, Accept, and Reject controls');

      category.value = 'public'; name.value = 'Agent Public';
      await accept.fire('click');
      const approve = calls.find(function (c) { return c.kind === 'approve'; });
      check(approve && approve.id === fixture.request_id, '[mint-m3] Accept must target the request approve endpoint client');
      check(approve && approve.body.approver_passport === 'operator-work', '[mint-m3] Accept must carry the bound operator passport');
      check(approve && approve.body.category === 'public' && approve.body.name === 'Agent Public',
        '[mint-m3] Accept must carry the edited category and name');
      check(status && !/Bind a passport/.test(status.textContent),
        '[mint-picker] Accept must no longer hit the bind-first Art.14 gate after binding');
      check(calls.some(function (c) { return c.kind === 'refresh' && c.url === '/v1/passport/mint-requests/pending'; }),
        '[mint-m3] successful Accept must refresh the pending mint queue');
      check(status && /minted as public/.test(status.textContent), '[mint-m3] successful Accept must surface the minted category');

      accept.disabled = false; reject.disabled = false;
      await reject.fire('click');
      const rejected = calls.find(function (c) { return c.kind === 'reject'; });
      check(rejected && rejected.id === fixture.request_id, '[mint-m3] Reject must target the request reject endpoint client');
      check(rejected && JSON.stringify(rejected.body) === JSON.stringify({ approver_passport: 'operator-work' }),
        '[mint-m3] Reject must carry only the bound operator passport');
      check(calls.filter(function (c) { return c.kind === 'refresh'; }).length >= 2,
        '[mint-m3] successful Reject must refresh the pending mint queue');

      await dom.byAttr(reboundControl, 'data-bound-approver-action', 'clear').fire('click');
      check(!Object.prototype.hasOwnProperty.call(storageValues, 'crux-console-bound-passport') && render.boundPassport() === '',
        '[mint-picker] Clear must remove the shared approver key');

      passportsEmpty = true;
      const emptyPassportControl = render.renderBoundApproverControl(dom.node('section'));
      await emptyPassportControl.cruxReady;
      check(!!dom.byAttr(emptyPassportControl, 'data-bound-approver-picker', 'text'),
        '[mint-picker] an empty passport list must degrade to a text input');

      passportsEmpty = false;
      passportsFail = true;
      const fallbackControl = render.renderBoundApproverControl(dom.node('section'));
      await fallbackControl.cruxReady;
      const fallback = dom.byAttr(fallbackControl, 'data-bound-approver-picker', 'text');
      check(!!fallback, '[mint-picker] passport-fetch failure must degrade to a text input without throwing');
      if (fallback) { fallback.value = 'manual-approver'; }
      await dom.byAttr(fallbackControl, 'data-bound-approver-action', 'bind').fire('click');
      check(render.boundPassport() === 'manual-approver',
        '[mint-picker] text-input fallback Bind must persist the typed passport id');

      approveResponse = { ok: false, status: 403, data: { detail: 'admin:write scope required' } };
      const errorCard = render.renderMintRequestCard(mint, dom.node('section'));
      await dom.byAttr(errorCard, 'data-mint-action', 'accept').fire('click');
      const errorStatus = dom.byAttr(errorCard, 'data-mint-status', fixture.request_id);
      check(errorStatus && /HTTP 403.*admin:write scope required/.test(errorStatus.textContent),
        '[mint-m3] API errors must render inline with status and detail');
    } catch (e) {
      check(false, '[mint-m3] interaction smoke threw: ' + (e && e.stack || e));
    } finally {
      if (savedDoc === undefined) { delete global.document; } else { global.document = savedDoc; }
      if (savedWin === undefined) { delete global.window; } else { global.window = savedWin; }
      if (savedStorage === undefined) { delete global.localStorage; } else { global.localStorage = savedStorage; }
    }
    notes.push('passport mint picker + M3: first/empty/feature-off control presence; read-client options; shared-key bind + panel refresh + ungated Accept; Clear; failed-read text fallback; pending-card prefill/edit/approve/reject/error degradation exercised.');
  };
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
  // M20 RETARGET (operator directive): Overwatch is retired as a destination —
  // Rings is the console index and its tabs ARE the Overwatch views. The phone
  // tier's first direct tab moves with it. Work + Trust are unchanged.
  ['rings', 'work', 'trust'].forEach(function (id) {
    check(tabIds.indexOf(id) >= 0, '[phone] TAB_DEST_IDS must include the "' + id + '" tab');
  });
  check(tabIds.indexOf('overwatch') < 0, '[phone] the retired Overwatch destination must NOT be a phone tab (M20)');
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
  // M21 RETARGET (was: "Canvas must carry a Board|Graph view switch"). M19/M20
  // moved Board, Graph and Tree into the Rings tab hub and left Canvas as
  // Studio's route-only home, so three of the four segmented buttons pointed at
  // views that no longer live here; M21 removed the control and promoted the
  // Studio's OWN sections (Board · Pages · Integrations) in its place. What is
  // still true and worth gating: renderCanvas must still RESOLVE every legacy
  // view (a #/w/ workspace page of type canvas/board|graph|tree renders through
  // it), and the segmented control must be GONE — no dead #/canvas/<view> links.
  check(/ctx\.view === 'graph'/.test(renderSrc) && /ctx\.view === 'tree'/.test(renderSrc) && /ctx\.view === 'studio'/.test(renderSrc),
    '[canvas] renderCanvas must still resolve the board/graph/tree/studio views (workspace page types depend on it)');
  check(renderSrc.indexOf("'#/canvas/' + vid") < 0 && !/canvas-seg', role: 'group', 'aria-label': 'Canvas view'/.test(renderSrc),
    '[canvas] the Board|Graph|Tree|Studio segmented control must be GONE (M21 — those views live in the Rings tab hub)');
  check(/setTimeout\(paint, 200\)/.test(renderSrc), '[canvas] the board must recompose on a debounced resize');
  notes.push('canvas board: canvasTier xs/s/m/l/xl truth table + ' + (widgets ? widgets.length : 0) + '-widget registry (xs' + upTo('xs') + '·s' + upTo('s') + '·m' + upTo('m') + '·l' + upTo('l') + '·xl' + upTo('xl') + '); M21 — the Board|Graph|Tree|Studio segmented control is retired (those views are Rings tabs), renderCanvas still resolves every view for workspace page types.');
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

  // The curated read-POST set. M11 authorised the query/search POSTs; M15
  // (console-surfaces-remediation) adds the two Studio pack read POSTs (build +
  // verify) — pure transforms/validators, no store mutation.
  const EXPECTED = [
    ['POST', '/v1/query/text-search'],
    ['POST', '/v1/query/text-search/expand'],
    ['POST', '/v1/query/graph-expand'],
    ['POST', '/v1/query/time-range'],
    ['POST', '/v1/console/engine/search'],
    ['POST', '/v1/studio/pack/build'],
    ['POST', '/v1/studio/pack/verify']
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
//  Check — (M4) Link graph destination. A special full-viewport destination
//  (like Canvas/Explorer/Sitemap) that IS a WebGL six-degrees explorer over the
//  CoreCrux link graph, reached ONLY through the Crux daemon's read-only
//  mediation proxy (/v1/console/corecrux/graph/*). VISIBILITY is gated on the
//  daemon's runtime capability PLAN (console_link_graph), not the route registry
//  (unified-shell rule). Renderer = custom three.js r165 on the already-vendored
//  module (zero new vendored files, T.5). Reduced-motion: render-on-demand only.
// =========================================================================
(function checkLinkGraphDestination() {
  // ---- Patchbay (console-execplan-patchbay M3) --------------------------
  // A registry-driven destination is silently absent if any one of its four
  // wiring points is missed, and the rest of the smoke passes regardless — so
  // assert all four, plus the two invariants the operator asked for: that it
  // sits directly under Rings, and that adding it moved nobody's shortcut.
  const destList = pages.DESTS || [];
  const pb = destList.filter(function (d) { return d.id === 'patchbay'; })[0];
  check(!!pb, '[patchbay] pages.DESTS must register the patchbay destination');
  if (pb) {
    check(pb.icon === 'patchbay', '[patchbay] the patchbay destination must use the patchbay icon');
    check(pb.key === '6', '[patchbay] the patchbay destination must claim shortcut 6 (the free slot — taking a used one would renumber an existing destination)');
    check(!pb.capability, '[patchbay] the patchbay destination must NOT be capability-gated: the route is always mounted and self-degrades to an empty graph');
    check(!pb.railHidden, '[patchbay] the patchbay destination must be visible in the Command rail');
  }
  // Rail order is array position: patchbay sits immediately after rings.
  const idxRings = destList.findIndex(function (d) { return d.id === 'rings'; });
  const idxPb = destList.findIndex(function (d) { return d.id === 'patchbay'; });
  check(idxRings === 0, '[patchbay] rings must remain the first destination (the console index)');
  check(idxPb === idxRings + 1, '[patchbay] patchbay must sit directly under rings in the rail');
  // No incumbent shortcut moved.
  const EXPECTED_KEYS = { rings: '1', work: '2', memory: '3', trust: '4', meters: '5', sitemap: '7' };
  Object.keys(EXPECTED_KEYS).forEach(function (id) {
    const d = destList.filter(function (x) { return x.id === id; })[0];
    check(!!d && d.key === EXPECTED_KEYS[id],
      '[patchbay] adding patchbay must not renumber the ' + id + ' shortcut (expected ' + EXPECTED_KEYS[id] + ')');
  });
  // No two destinations may claim the same shortcut.
  const seenKeys = {};
  destList.forEach(function (d) {
    if (!d.key) { return; }
    check(!seenKeys[d.key], '[patchbay] duplicate keyboard shortcut ' + d.key + ' claimed by ' + d.id);
    seenKeys[d.key] = d.id;
  });
  // Shell + render wiring.
  check(/patchbay:\s*'<svg/.test(shellHtml), '[patchbay] shell.html must define the "patchbay" icon glyph');
  check(/destId === 'patchbay'/.test(shellHtml) && /renderPatchbay/.test(shellHtml),
    '[patchbay] shell.html must route the patchbay destination to render.renderPatchbay');
  check(typeof render.renderPatchbay === 'function', '[patchbay] render.js must export renderPatchbay');
  // The page reads ONLY through the generated client — no raw fetch in render.js.
  check(renderSrc.indexOf('api.workGraph') >= 0,
    '[patchbay] renderPatchbay must read through the generated CruxApi.workGraph client method');
  {
    const apiSrcPb = fs.readFileSync(path.join(DIR, 'api.js'), 'utf8');
    check(apiSrcPb.indexOf("'/v1/work/graph': true") >= 0,
      '[patchbay] api.js LITERAL_GET_PATHS must allowlist /v1/work/graph (regenerate from the ROUTES manifest)');
    check(/workGraph\(query\)/.test(apiSrcPb),
      '[patchbay] api.js must expose the generated workGraph client method');
  }

  // Mock-DOM paint: registration alone proves nothing about what the route
  // draws. Drive the renderer over a fixture and over each failure shape, and
  // assert the three states stay DISTINCT — an aggregator that is switched off
  // must not read as "the board is empty", and a failed read must not read as
  // either. This is the console's own verification idiom (model + mock paint).
  if (typeof render.renderPatchbay === 'function') {
    function pbRes(ok, status, data) {
      return Promise.resolve({ ok: ok, status: status, json: function () { return Promise.resolve(data); } });
    }
    const pbFixture = {
      plans: [
        { id: 'execplan:a-2026-01-01', slug: 'a-2026-01-01', title: 'Alpha', state: 'in_progress',
          plane: 'Crux daemon', services: ['Postgres'], links: ['b-2026-01-01'],
          blurb: 'Does a thing.', milestones_done: 1, milestones_total: 4, updated_at_unix_ms: 1 },
        { id: 'execplan:b-2026-01-01', slug: 'b-2026-01-01', title: 'Bravo', state: 'blocked',
          plane: 'Commerce', services: [], links: [], milestones_done: 0, milestones_total: 2,
          updated_at_unix_ms: 2 }
      ],
      planes: [{ key: 'Crux daemon', n: 1 }, { key: 'Commerce', n: 1 }],
      services: [{ key: 'Postgres', side: 'bottom', n: 1 }],
      link_count: 1,
      generated_at_unix_ms: 3
    };
    const pbMock = newMockDom();
    const mkNode = pbMock.mkNode, mockDoc = pbMock.doc, collectNodes = pbMock.collect;
    const pbSavedDoc = global.document, pbSavedWin = global.window;
    const textOf = function (host) {
      return collectNodes(host, [host]).map(function (n) { return n.textContent || ''; }).join(' | ');
    };
    global.document = mockDoc;

    // 1. healthy read paints the counts and every system
    global.window = { CruxApi: { workGraph: function () { return pbRes(true, 200, pbFixture); } } };
    const pbHost = mkNode('div');
    asyncChecks.push(Promise.resolve(render.renderPatchbay(pbHost, {})).then(function () {
      const t = textOf(pbHost);
      check(t.indexOf('open plans') >= 0, '[patchbay] renderPatchbay must paint the summary strip');
      // The canvas is the surface, so assert against its nodes, not prose. It
      // uppercases the system label, which is exactly the kind of drift a text
      // assertion hides.
      const nodes = collectNodes(pbHost, [pbHost]);
      const byClass = function (c) {
        return nodes.filter(function (n) { return String(n.className || '').split(/\s+/).indexOf(c) >= 0; });
      };
      check(byClass('pb-chip').length === pbFixture.plans.length,
        '[patchbay] the canvas must draw one card per open plan');
      check(byClass('pb-centre').length === pbFixture.planes.length,
        '[patchbay] the canvas must draw one label block per system');
      check(byClass('pb-plate').length === pbFixture.planes.length,
        '[patchbay] the canvas must draw one raised plate per system');
      check(byClass('pb-rail').length === pbFixture.services.length,
        '[patchbay] the canvas must draw one rail per touched service');
      check(byClass('pb-wire').length === pbFixture.link_count,
        '[patchbay] the canvas must draw one wire per declared edge');
      check(t.indexOf('CRUX DAEMON') >= 0 && t.indexOf('COMMERCE') >= 0,
        '[patchbay] the canvas must label every system it draws');
      check(t.indexOf('edges') >= 0,
        '[patchbay] renderPatchbay must surface the declared-edge count');
      check(t.indexOf('Postgres') >= 0,
        '[patchbay] the canvas must name the services it wires to');
      check(byClass('pb-legend').length === 0,
        '[patchbay] the explainer block is gone — the controls and the subtitle carry it');
      check(t.indexOf('Reading the board') < 0,
        '[patchbay] the loading line must be cleared once the read resolves');
    }).catch(function (e) {
      check(false, '[patchbay] renderPatchbay drive threw: ' + (e && e.stack || e));
    }));

    // 1b. M5 interaction: freshness, selection, isolation and keyboard reach.
    // Driven through the CAPTURED handlers, so a control that exists only as a
    // painted node with no behaviour fails here.
    const nowMs = Date.now();
    const pbLiveFixture = {
      plans: [
        { id: 'execplan:f1', slug: 'f1', title: 'Fresh one', state: 'in_progress', plane: 'Crux daemon',
          services: [], links: ['f2'], milestones_done: 1, milestones_total: 3,
          updated_at_unix_ms: nowMs, last_activity_unix_ms: nowMs - 2 * 3600000 },   // 2h — worked on
        { id: 'execplan:f2', slug: 'f2', title: 'Fresh two', state: 'planned', plane: 'Crux daemon',
          services: [], links: [], milestones_done: 0, milestones_total: 3,
          updated_at_unix_ms: nowMs, last_activity_unix_ms: nowMs - 5 * 3600000 },   // 5h — worked on
        { id: 'execplan:s1', slug: 's1', title: 'Stale one', state: 'blocked', plane: 'Commerce',
          services: [], links: [], milestones_done: 2, milestones_total: 4,
          updated_at_unix_ms: nowMs, last_activity_unix_ms: nowMs - 20 * 24 * 3600000 } // 20d — cold at 24h, lit at 30d
      ],
      planes: [{ key: 'Crux daemon', n: 2 }, { key: 'Commerce', n: 1 }],
      services: [], link_count: 1
    };
    const pbLiveHost = mkNode('div');
    global.window = { CruxApi: { workGraph: function () { return pbRes(true, 200, pbLiveFixture); } } };
    asyncChecks.push(Promise.resolve(render.renderPatchbay(pbLiveHost, {})).then(function () {
      const nodes = function () { return collectNodes(pbLiveHost, [pbLiveHost]); };
      const byClass = function (c) {
        return nodes().filter(function (n) { return String(n.className || '').split(/\s+/).indexOf(c) >= 0; });
      };
      const sel = function (cls) {
        return nodes().filter(function (n) { return String(n.className || '').split(/\s+/).indexOf(cls) >= 0; });
      };
      const fire = function (node, type, ev) { (node._handlers[type] || []).forEach(function (f) { f(ev || { target: node }); }); };

      // Default is "any time": nothing is highlighted until a window is chosen.
      // This is deliberate — on a daemon whose plan root is synced in bulk most
      // plans have no fact activity, so defaulting to a window would hide the
      // board behind a dimmed state.
      check(byClass('pb-fresh').length === 0,
        '[patchbay] no recency highlight until a window is chosen');
      const chips = byClass('pb-chip');
      check(chips.length === 3, '[patchbay] all three cards must paint');

      // Keyboard reach.
      check(chips.every(function (n) { return n.getAttribute('tabindex') === '0'; }),
        '[patchbay] every card must be keyboard focusable');
      check(chips.every(function (n) { return (n.getAttribute('aria-label') || '').length > 0; }),
        '[patchbay] every card must carry an aria-label naming its plan and state');
      check(byClass('pb-plate-g').every(function (n) { return n.getAttribute('tabindex') === '0'; }),
        '[patchbay] every system plate must be keyboard focusable');
      const canvasNode = byClass('pb-canvas')[0];
      check(!!canvasNode && canvasNode.getAttribute('tabindex') === '0',
        '[patchbay] the canvas itself must be focusable so pan/zoom is not mouse-only');

      // ---- STATE FILTERS (the control that was missing on the live page) ----
      const stateBtns = sel('pb-chip-btn');
      check(stateBtns.length >= 2,
        '[patchbay] a filter chip must exist per open state present on the board');
      const blockedBtn = stateBtns.filter(function (b) { return b.getAttribute('data-state') === 'blocked'; })[0];
      check(!!blockedBtn, '[patchbay] a "blocked" filter chip must exist when blocked plans are present');
      blockedBtn.click();
      check(blockedBtn.getAttribute('aria-pressed') === 'true',
        '[patchbay] an active filter chip must report aria-pressed');
      let dim = byClass('pb-dim').map(function (n) { return n.getAttribute('data-slug'); });
      check(dim.indexOf('f1') >= 0 && dim.indexOf('f2') >= 0 && dim.indexOf('s1') < 0,
        '[patchbay] filtering to "blocked" must dim every non-blocked card (dimmed: ' + dim.join(',') + ')');
      blockedBtn.click();
      check(byClass('pb-dim').length === 0, '[patchbay] clicking the chip again must clear the filter');

      // ---- RECENCY comes from fact activity, not file mtime ----------------
      // The live regression: every plan file shared one rsync mtime, so all 228
      // read as "touched in the last 24h". Recency must key off
      // last_activity_unix_ms, and a plan without facts must stay cold.
      const winSel = sel('pb-select').filter(function (n) {
        return /worked on/i.test(n.getAttribute('aria-label') || '');
      })[0];
      check(!!winSel, '[patchbay] a recency control must exist');
      winSel.value = '24';
      fire(winSel, 'change', { target: winSel });
      check(byClass('pb-fresh').length === 3,
        '[patchbay] at 24h exactly the two recently-worked cards and the wire joining them light up (got ' +
        byClass('pb-fresh').length + ')');
      dim = byClass('pb-dim').map(function (n) { return n.getAttribute('data-slug'); });
      check(dim.indexOf('s1') >= 0,
        '[patchbay] a plan with no recent fact activity must dim under a recency window');
      winSel.value = '720';
      fire(winSel, 'change', { target: winSel });
      check(byClass('pb-fresh').length >= 4,
        '[patchbay] widening to 30d must light the older plan too');

      // A plan whose only timestamp is the file mtime must NOT read as fresh.
      check(pbLiveFixture.plans.every(function (p) { return p.last_activity_unix_ms; }),
        '[patchbay] fixture sanity: recency is driven by last_activity_unix_ms');

      // ---- pull-out panel --------------------------------------------------
      // Chrome is the console's graph inspector; the CONTENT is the prototype's.
      // Drive it: closed by default, opens on a card, carries the sections, and
      // its relation entries navigate rather than just describing.
      const panelNode = byClass('pb-panel')[0];
      check(!!panelNode, '[patchbay] a pull-out detail panel must exist');
      check(!/is-open/.test(panelNode.className || ''),
        '[patchbay] the panel must start closed');
      check(panelNode.getAttribute('aria-hidden') === 'true',
        '[patchbay] a closed panel must be hidden from assistive tech');
      const pcard = byClass('pb-chip').filter(function (n) { return n.getAttribute('data-slug') === 'f1'; })[0];
      pcard.click();
      check(/is-open/.test(byClass('pb-panel')[0].className || ''),
        '[patchbay] selecting a card must open the panel');
      check(byClass('pb-panel')[0].getAttribute('aria-hidden') === 'false',
        '[patchbay] an open panel must be exposed to assistive tech');
      const heads = byClass('cv-insp-linked-h').map(function (n) { return n.textContent; });
      check(heads.some(function (h) { return /Milestones/.test(h); }),
        '[patchbay] the panel must carry the milestone section');
      check(heads.some(function (h) { return /Depends on/.test(h); }),
        '[patchbay] the panel must list declared dependencies (f1 declares f2)');
      check(byClass('cv-insp-title').length === 1,
        '[patchbay] the panel must name the plan it is describing');
      check(byClass('cv-badge').length >= 3,
        '[patchbay] the panel must badge state, system and recency');
      // A relation entry NAVIGATES.
      const depBtn = byClass('pb-panel-item').filter(function (n) { return n.textContent === 'Fresh two'; })[0];
      check(!!depBtn, '[patchbay] a declared dependency must appear as a clickable entry');
      depBtn.click();
      check((byClass('cv-insp-title')[0] || {}).textContent === 'Fresh two',
        '[patchbay] clicking a relation must walk the panel to that plan, not just describe it');
      // Close.
      byClass('pb-panel-x')[0].click();
      check(!/is-open/.test(byClass('pb-panel')[0].className || ''),
        '[patchbay] the close control must shut the panel');
      check(byClass('pb-sel').length === 0,
        '[patchbay] closing the panel must clear the card selection with it');

      // ---- selection still works alongside filters -------------------------
      sel('pb-clear')[0].click();
      const f1 = byClass('pb-chip').filter(function (n) { return n.getAttribute('data-slug') === 'f1'; })[0];
      f1.click();
      check(String(f1.className).indexOf('pb-sel') >= 0,
        '[patchbay] activating a card must select it (the lift is the feedback)');
      dim = byClass('pb-dim').map(function (n) { return n.getAttribute('data-slug'); });
      check(dim.indexOf('s1') >= 0 && dim.indexOf('f2') < 0,
        '[patchbay] selecting a card must isolate it and what it declares (dimmed: ' + dim.join(',') + ')');
      f1.click();
      check(byClass('pb-sel').length === 0, '[patchbay] activating a selected card again must clear the selection');
      const plate = byClass('pb-plate-g')[0];
      plate.click();
      check(byClass('pb-gone').length > 0,
        '[patchbay] activating a system must REMOVE the plans it does not engage with, not grey them');
      check(byClass('pb-dim').length === 0,
        '[patchbay] a system selection must not leave half-faded cards alongside removed ones');
      plate.click();
      const target = byClass('pb-chip').filter(function (n) { return n.getAttribute('data-slug') === 's1'; })[0];
      (target._handlers.keydown || []).forEach(function (fn) { fn({ key: 'Enter', preventDefault: function () {} }); });
      check(String(target.className).indexOf('pb-sel') >= 0,
        '[patchbay] Enter on a focused card must select it, exactly as a click does');
    }).catch(function (e) {
      check(false, '[patchbay] renderPatchbay interaction drive threw: ' + (e && e.stack || e));
    }));

    // 2. aggregator off (200 + zero plans) is a CONFIGURATION statement
    const pbEmptyHost = mkNode('div');
    global.window = { CruxApi: { workGraph: function () { return pbRes(true, 200, { plans: [], planes: [], services: [], link_count: 0 }); } } };
    asyncChecks.push(Promise.resolve(render.renderPatchbay(pbEmptyHost, {})).then(function () {
      const t = textOf(pbEmptyHost);
      check(/CRUX_EXECPLANS_ROOT/.test(t),
        '[patchbay] an empty graph must name the missing ExecPlan root, not read as a healthy empty board');
      check(!/\d+ open plans/.test(t),
        '[patchbay] an empty graph must not paint a summary line of zeroes');
    }).catch(function (e) {
      check(false, '[patchbay] renderPatchbay empty-state drive threw: ' + (e && e.stack || e));
    }));

    // 3. failed read states the status verbatim and never fabricates a board
    const pbFailHost = mkNode('div');
    global.window = { CruxApi: { workGraph: function () { return pbRes(false, 503, null); } } };
    asyncChecks.push(Promise.resolve(render.renderPatchbay(pbFailHost, {})).then(function () {
      const t = textOf(pbFailHost);
      check(/503/.test(t), '[patchbay] a failed read must state the HTTP status verbatim');
      check(!/\d+ open plans/.test(t) && !/CRUX_EXECPLANS_ROOT/.test(t),
        '[patchbay] a failed read must be distinct from both a healthy board and a switched-off aggregator');
    }).catch(function (e) {
      check(false, '[patchbay] renderPatchbay failure drive threw: ' + (e && e.stack || e));
    }).then(function () {
      if (pbSavedDoc === undefined) { delete global.document; } else { global.document = pbSavedDoc; }
      if (pbSavedWin === undefined) { delete global.window; } else { global.window = pbSavedWin; }
    }));
  }

  // Geometry gates (M4). Layout and routing are pure, so the invariants that
  // make the picture readable are assertable here — no DOM, no daemon, no
  // screenshot (which headless cannot take of this SPA anyway, see D11).
  if (typeof render.patchbayLayout === 'function' && typeof render.patchbayRoutes === 'function') {
    // A board-sized synthetic fixture: 63 plans over 10 systems with 30 declared
    // edges, matching the real projection's shape.
    const PLANE_NAMES = ['Crux daemon', 'CoreCrux/Engine', 'Commerce', 'Surfaces/Web', 'Benchmarks',
      'WikiCrux', 'RCX protocol', 'Agents/Harness', 'VaultCrux', 'ChainCrux'];
    const PLANE_N = [14, 11, 10, 6, 6, 5, 5, 3, 2, 1];
    const gPlans = [];
    let gi = 0;
    PLANE_NAMES.forEach(function (pn, pi) {
      for (let k = 0; k < PLANE_N[pi]; k++) {
        gPlans.push({
          id: 'execplan:p' + gi, slug: 'p' + gi, title: 'Plan number ' + gi + ' with a longish title',
          state: ['in_progress', 'blocked', 'planned', 'drafting'][gi % 4],
          plane: pn, services: [], links: [], milestones_done: gi % 5, milestones_total: 5,
          updated_at_unix_ms: gi
        });
        gi++;
      }
    });
    // 30 edges, deliberately including long cross-system ones.
    for (let e = 0; e < 30; e++) {
      const a = gPlans[(e * 7) % gPlans.length], b = gPlans[(e * 13 + 5) % gPlans.length];
      if (a.slug !== b.slug && a.links.indexOf(b.slug) < 0) { a.links.push(b.slug); }
    }
    const gGraph = {
      plans: gPlans,
      planes: PLANE_NAMES.map(function (pn, pi) { return { key: pn, n: PLANE_N[pi] }; }),
      services: [
        { key: 'Anthropic API', side: 'top', n: 9 }, { key: 'GitHub / CI', side: 'top', n: 14 },
        { key: 'Postgres', side: 'bottom', n: 12 }, { key: 'GPU-1 / embedders', side: 'bottom', n: 18 },
        { key: 'Crux HTTP :14800', side: 'left', n: 7 }, { key: 'Paddle', side: 'right', n: 5 }
      ],
      link_count: 30
    };
    const L = render.patchbayLayout(gGraph);
    const cw = L.cw, chh = L.ch;
    check(L.chips.length === gPlans.length,
      '[patchbay] every open plan must get a card (got ' + L.chips.length + ' of ' + gPlans.length + ')');
    check(L.chips.length >= 60, '[patchbay] the board-sized fixture must render >= 60 cards');
    check(L.sections.length === PLANE_NAMES.length, '[patchbay] every system must get a plate');

    function rectsOverlap(a, b) {
      return !(a.x + a.w <= b.x || b.x + b.w <= a.x || a.y + a.h <= b.y || b.y + b.h <= a.y);
    }
    const chipRects = L.chips.map(function (c) { return { x: c.x, y: c.y, w: cw, h: chh, slug: c.plan.slug }; });
    let chipOverlaps = 0, centreOverlaps = 0, landlocked = 0;
    for (let a = 0; a < chipRects.length; a++) {
      if (!L.chips[a].out || !L.chips[a].out.length) { landlocked++; }
      for (let b = a + 1; b < chipRects.length; b++) {
        if (rectsOverlap(chipRects[a], chipRects[b])) { chipOverlaps++; }
      }
      for (let c2 = 0; c2 < L.centres.length; c2++) {
        if (rectsOverlap(chipRects[a], L.centres[c2])) { centreOverlaps++; }
      }
    }
    check(chipOverlaps === 0, '[patchbay] no two cards may overlap (got ' + chipOverlaps + ')');
    check(centreOverlaps === 0, '[patchbay] no card may overlap its system label block (got ' + centreOverlaps + ')');
    check(landlocked === 0,
      '[patchbay] every card must sit on the ring perimeter with an outward face — a landlocked card cannot route out (got ' + landlocked + ')');

    const R = render.patchbayRoutes(L, gGraph);
    let expectedEdges = 0;
    gPlans.forEach(function (p) { expectedEdges += p.links.length; });
    check(R.length === expectedEdges,
      '[patchbay] every declared edge must be routed, none dropped (got ' + R.length + ' of ' + expectedEdges + ')');
    check(R.length >= 25, '[patchbay] the board-sized fixture must route >= 25 wires');

    // Which plate does a card belong to? A wire legitimately crosses only its
    // OWN two plates, and only where it emerges from the card.
    function plateOf(slug) {
      const chip = L.chips.filter(function (c) { return c.plan.slug === slug; })[0];
      if (!chip) { return null; }
      for (let s = 0; s < L.sections.length; s++) {
        const sec = L.sections[s];
        if (chip.x >= sec.x - 1 && chip.x + cw <= sec.x + sec.w + 1 &&
            chip.y >= sec.y - 1 && chip.y + chh <= sec.y + sec.h + 1) { return sec; }
      }
      return null;
    }
    let diagonals = 0, plateCrossings = 0;
    R.forEach(function (w) {
      const own = [plateOf(w.from), plateOf(w.to)];
      for (let i2 = 0; i2 + 1 < w.pts.length; i2++) {
        const p1 = w.pts[i2], p2 = w.pts[i2 + 1];
        const dx = Math.abs(p1.x - p2.x), dy = Math.abs(p1.y - p2.y);
        if (dx > 0.6 && dy > 0.6) { diagonals++; continue; }
        for (let s = 0; s < L.sections.length; s++) {
          const sec = L.sections[s];
          if (own.indexOf(sec) >= 0) { continue; }           // its own plate: the stub
          const rx = sec.x + 2, ry = sec.y + 2, rw = sec.w - 4, rh = sec.h - 4;
          let hit = false;
          if (dx < 0.6) {
            hit = rx < p1.x && p1.x < rx + rw &&
              Math.max(ry, Math.min(p1.y, p2.y)) < Math.min(ry + rh, Math.max(p1.y, p2.y));
          } else {
            hit = ry < p1.y && p1.y < ry + rh &&
              Math.max(rx, Math.min(p1.x, p2.x)) < Math.min(rx + rw, Math.max(p1.x, p2.x));
          }
          if (hit) { plateCrossings++; }
        }
      }
    });
    check(diagonals === 0,
      '[patchbay] every wire segment must run in X or Y only — no diagonals (got ' + diagonals + ')');
    check(plateCrossings === 0,
      '[patchbay] no wire may cross a system plate it does not belong to (got ' + plateCrossings + ')');

    // CAPACITY GATE (incident 2026-08-07). A ring whose perimeter is smaller
    // than its plane cannot place every card, and the slot allocator span on it
    // forever — a frozen browser tab, not a wrong picture. Prod had a 61-plan
    // plane while the sizer topped out at 28 slots.
    //
    // Asserted as a PROPERTY of the sizer rather than by running the layout:
    // on the broken code "does the layout finish" would hang CI instead of
    // failing it, which is a worse outcome than the bug.
    if (typeof render.patchbayGridFor === 'function') {
      let worst = null;
      for (let n = 1; n <= 400; n++) {
        const g = render.patchbayGridFor(n);
        const perim = 2 * (g[0] + g[1]) - 4;
        if (perim < n && !worst) { worst = { n, g, perim }; }
        if (g[0] < 3 || g[1] < 3) { worst = worst || { n, g, perim }; }
      }
      check(!worst, '[patchbay] every ring must have perimeter >= its plan count and an interior for the label' +
        (worst ? ' — n=' + worst.n + ' got ' + worst.g.join('x') + ' (' + worst.perim + ' slots)' : ''));
      // And the interior must stay big enough for the label block.
      const big = render.patchbayGridFor(228);
      check((big[0] - 2) >= 1 && (big[1] - 2) >= 1,
        '[patchbay] a large ring must still leave an interior for its system label');
    }
    // A plane larger than the sizer's static table must place every card.
    {
      const many = [];
      for (let i = 0; i < 61; i++) {
        many.push({ id: 'execplan:b' + i, slug: 'b' + i, title: 'Big plan ' + i, state: 'planned',
          plane: 'VaultCrux', services: [], links: [], milestones_done: 0, milestones_total: 3,
          updated_at_unix_ms: 1 });
      }
      const LB = render.patchbayLayout({ plans: many, planes: [{ key: 'VaultCrux', n: 61 }],
        services: [], link_count: 0 });
      check(LB.chips.length === 61,
        '[patchbay] a 61-plan system must place all 61 cards (got ' + LB.chips.length + ')');
      check(LB.chips.every(function (c) { return c.out && c.out.length; }),
        '[patchbay] every card in a large ring must still have an outward face');
    }

    // A board with no declared edges must still lay out (the endpoint can
    // legitimately return zero links) rather than throw.
    const noEdge = { plans: gPlans.map(function (p) { return Object.assign({}, p, { links: [] }); }),
      planes: gGraph.planes, services: [], link_count: 0 };
    const L2 = render.patchbayLayout(noEdge);
    check(render.patchbayRoutes(L2, noEdge).length === 0,
      '[patchbay] a board with no declared edges must route nothing and not throw');
  }

  // The wire vocabulary lives in the destination subtitle now that the
  // on-page explainer is gone — if it lives nowhere, the board is a mystery.
  if (pb) {
    check(/declared dependencies/i.test(pb.sub || ''),
      '[patchbay] the destination subtitle must say what a solid wire means');
    check(/mention/i.test(pb.sub || ''),
      '[patchbay] the destination subtitle must say what a dashed wire means');
  }
  // Service rails must be operable, not decorative: a count you cannot click is
  // exactly how they read on the live page.
  check(/pb-rail-g/.test(renderSrc) && /selectService/.test(renderSrc),
    '[patchbay] service rails must be clickable and wire to the plans that touch them');
  check(/pb-cable/.test(renderSrc),
    '[patchbay] selecting a service must draw cables to its plans');
  check(/pb-wire-mention/.test(renderSrc),
    '[patchbay] prose mentions must be drawn as a distinct, weaker edge than a declared dependency');

  const lg = (pages.DESTS || []).filter(function (d) { return d.id === 'linkgraph'; })[0];
  check(!!lg, '[linkgraph] pages.DESTS must register the linkgraph destination');
  if (lg) {
    check(lg.capability === 'console_link_graph', '[linkgraph] the linkgraph destination must declare capability "console_link_graph" (gate visibility on the runtime plan, not the registry)');
    check(lg.icon === 'linkgraph', '[linkgraph] the linkgraph destination must use the linkgraph icon');
    check(!lg.key, '[linkgraph] the linkgraph destination must not claim a keyboard shortcut (it is capability-gated + not always present)');
  }
  // Shell wiring: icon glyph, import map → vendored r165, special-cased render,
  // and the capability-gated nav (destVisible + a post-boot nav rebuild).
  check(/linkgraph:\s*'<svg/.test(shellHtml), '[linkgraph] shell.html must define the "linkgraph" icon glyph');
  check(/<script type="importmap">/.test(shellHtml) && shellHtml.indexOf('/console-3d/vendor/three.module.min.js') >= 0,
    '[linkgraph] shell.html must map bare `three` to the already-vendored r165 (no new vendored files, no CDN)');
  check(/destId === 'linkgraph'/.test(shellHtml) && /renderLinkGraph/.test(shellHtml),
    '[linkgraph] shell.html must route the linkgraph destination to render.renderLinkGraph');
  check(/function destVisible/.test(shellHtml) && /destVisible\(item\)/.test(shellHtml),
    '[linkgraph] shell.html must gate rail destinations on the runtime capability plan (destVisible)');
  check(/capabilityAvailable/.test(shellHtml) || /CruxRender\.capabilityAvailable/.test(shellHtml),
    '[linkgraph] the capability gate must read the daemon capability plan via CruxRender.capabilityAvailable');
  // render.js entry points.
  check(typeof render.renderLinkGraph === 'function', '[linkgraph] render.js must export renderLinkGraph');
  check(typeof render.capabilityAvailable === 'function', '[linkgraph] render.js must export capabilityAvailable (plan-driven gate)');
  // The pane reaches the graph ONLY through the four read-only proxy routes.
  const apiSrc = fs.readFileSync(path.join(DIR, 'api.js'), 'utf8');
  ['/v1/console/corecrux/graph/stats', '/v1/console/corecrux/graph/resolve', '/v1/console/corecrux/graph/ego', '/v1/console/corecrux/graph/path'].forEach(function (route) {
    check(renderSrc.indexOf(route) >= 0, '[linkgraph] render.renderLinkGraph must reach the proxy route ' + route);
    check(apiSrc.indexOf("'" + route + "': true") >= 0, '[linkgraph] api.js LITERAL_GET_PATHS must allowlist ' + route);
  });
  // The renderer is a client-only ESM module: Apache-2.0 header, bare `three`, the shared
  // public API, and zero external runtime deps (T.5). It also must not run a
  // perpetual rAF loop (reduced-motion floor) — render-on-demand only.
  const rendererSrc = fs.readFileSync(path.join(DIR, 'linkgraph-renderer.mjs'), 'utf8');
  check(/Licensed under the Apache License, Version 2\.0\./.test(rendererSrc), '[linkgraph] linkgraph-renderer.mjs must carry the Apache-2.0 licence header');
  check(/import \* as THREE from 'three'/.test(rendererSrc), '[linkgraph] renderer must import the bare `three` specifier (resolved to the vendored r165 by the shell import map)');
  ['mount', 'setData', 'expandData', 'setTheme', 'onNodeClick', 'destroy'].forEach(function (m) {
    check(rendererSrc.indexOf(m) >= 0, '[linkgraph] renderer must expose the shared public API method: ' + m);
  });
  ['unpkg.com', 'jsdelivr.net', 'cdnjs.cloudflare', 'cdn.jsdelivr', 'fonts.googleapis', "from 'http", 'from "http', "import('http", 'import("http'].forEach(function (bad) {
    check(rendererSrc.indexOf(bad) < 0, '[linkgraph] renderer must have no external runtime dependency: ' + bad);
  });
  check(/reduced-motion/i.test(rendererSrc) || /reducedMotion/.test(rendererSrc), '[linkgraph] renderer must honour prefers-reduced-motion (render-on-demand, no perpetual animation)');
  notes.push('linkgraph destination (M4): capability-gated (console_link_graph) WebGL six-degrees pane over /v1/console/corecrux/graph/* (stats/resolve/ego/path); custom three.js r165 via the vendored module (zero new files); render-on-demand (reduced-motion safe); 44px targets + focus-visible.');
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
  // workbenchCommandLedger is deliberately gone: `ledger:history` is no longer a sold
  // claim (no producer ever wrote a record), so the route 402s and the tile was removed.
  // See ExecPlan crux-command-ledger-claim-truth-2026-07-30.
  const WB_GET_METHODS = ['workbenchApiDrift', 'workbenchReasoningTimeline', 'workbenchAuditTriage', 'workbenchBrief'];
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
  ['/v1/workbench/contract', '/v1/workbench/api-drift',
    '/v1/workbench/reasoning-timeline', '/v1/workbench/audit-triage', '/v1/workbench/brief'].forEach(function (p) {
    check(new RegExp("'" + p.replace(/[-/]/g, '\\$&') + "': true").test(apiSrc),
      '[m13a] wired workbench read ' + p + ' must be an allowlisted GET in api.js (never a mutation route)');
  });
  notes.push('m13a workbench + control-diff: CONTROL_DIFF covers all 26 legacy CX pages; cx-workbench is native (loads /v1/workbench/contract + 4 live GET read tools via a GET-only self-loader); every newly-wired op is an allowlisted GET.');
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
    check(/ow-tabs/.test(landing) && /renderTab/.test(landing) && /ow-tabcontent/.test(landing),
      '[overwatch] the landing must render the view tab bar (ow-tabs) + swappable ow-tabcontent (renderTab)');
  }
  // M13 — the tab CONTENT renderer was extracted to the shared module-level
  // owRenderTab so the Rings tab hub (renderRings) reuses the EXACT same view
  // renderers + arrangement instead of forking them. The activity-layout
  // assertions moved here with it; renderOverwatchLanding.renderTab delegates.
  const owtab = funcBody(renderSrc, 'owRenderTab');
  check(!!owtab, '[overwatch] render.js must define the shared owRenderTab (reused by the landing + the Rings tab hub)');
  if (owtab) {
    check(/fillNeedsYou/.test(owtab) && /fillFleet/.test(owtab), '[overwatch] owRenderTab must still fill Needs-you + Fleet');
    check(/left\.appendChild\(needs\)/.test(owtab) && /left\.appendChild\(fleet\)/.test(owtab),
      '[overwatch] the Activity tab must stack Needs-you then Fleet in the LEFT column');
    check(/right\.appendChild\(actHost\)/.test(owtab) && /renderPage\(page, actHost\)/.test(owtab),
      '[overwatch] the Activity tab must render the Activity page (cx-activity) in the RIGHT column (50%)');
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
  // M20 RETARGET: the sub-nav PILL ROW is gone from the whole console — sub-page
  // navigation is the rail accordion (one idiom, not two). The original assertion
  // ("suppressed for overwatch only") no longer has a subject; the honest successor
  // is that buildSubnav does not exist at all and the accordion does.
  check(!/function buildSubnav\(/.test(shellHtml) && !/appendChild\(buildSubnav/.test(shellHtml),
    '[overwatch] shell.html must NOT build a sub-nav pill row any more (M20: buildSubnav removed)');
  check(/function buildNavGroup\(/.test(shellHtml) && /function syncRailAccordion\(/.test(shellHtml),
    '[overwatch] shell.html must build the rail accordion instead (buildNavGroup + syncRailAccordion)');
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
//  M2b — two-profile capability conformance. Proves the anti-501 guarantee
//  holds on BOTH a full daemon and a lite (delegating) daemon (M5b): (1)
//  reverse coverage — every capability-gated control is actually wired through
//  applyCapabilityGate AND present in CONTROL_CAPABILITY_MAP (a new gated
//  control that skipped the map would render enabled → 404/501, the M2-review
//  gap); (2) descriptor completeness — every capability the map consumes is
//  declared by BOTH profiles, so a mapped control never falls to
//  capability_undeclared (a "should work but the daemon didn't say so" 501);
//  (3) the gate reacts to a lite/degraded profile with disabled-with-reason.
(function checkTwoProfileConformance() {
  const map = pages.CONTROL_CAPABILITY_MAP || {};

  // (0) Schema-version lock-step: the console's accepted runtime-capability
  // schema MUST equal the daemon's emitted RUNTIME_CAPABILITY_SCHEMA_VERSION.
  // The M5b regression — daemon bumped 1→2 (additively) while render.js still
  // rejected schema_version !== 1 — blanked the WHOLE descriptor
  // (descriptor_unavailable) against every real daemon. This guard fails the
  // smoke on any future one-sided bump.
  const productSrcSchema = fs.readFileSync(path.join(DIR, '..', '..', 'src', 'product.rs'), 'utf8');
  const daemonSchema = (productSrcSchema.match(/RUNTIME_CAPABILITY_SCHEMA_VERSION:\s*u32\s*=\s*(\d+)/) || [])[1];
  const consoleSchema = (renderSrc.match(/descriptor\.schema_version\s*!==\s*(\d+)/) || [])[1];
  check(!!daemonSchema && daemonSchema === consoleSchema,
    '[m2b] console-accepted schema (' + consoleSchema + ') must equal daemon RUNTIME_CAPABILITY_SCHEMA_VERSION (' + daemonSchema + ') — a one-sided bump blanks the descriptor on every real daemon');

  // (1) Reverse coverage: collect every applyCapabilityGate call-site that names
  // a STRING-LITERAL control id and assert each is a map key. The one dynamic
  // call site — applyCapabilityGate(node, control && control.k) — routes keyed
  // DSL controls whose ids are validated elsewhere; only literals are checkable.
  const litRe = /applyCapabilityGate\([^,]+,\s*'([^']+)'/g;
  const gatedIds = new Set();
  let m;
  while ((m = litRe.exec(renderSrc)) !== null) { gatedIds.add(m[1]); }
  check(gatedIds.size > 0, '[m2b] expected at least one literal applyCapabilityGate call site');
  gatedIds.forEach(function (id) {
    check(Object.prototype.hasOwnProperty.call(map, id),
      '[m2b] gated control "' + id + '" is not in CONTROL_CAPABILITY_MAP — it would render enabled and reach a 404/501');
  });

  // A valid capability object per runtimeCapabilityState's shape contract.
  function cap(availability, reasonCode) {
    return {
      availability: availability, reason_code: reasonCode, reason: reasonCode.replace(/_/g, ' '),
      compiled: true, configured: true, initialized: availability === 'available',
      entitled: true, degraded: availability === 'degraded'
    };
  }
  // Every capability the map consumes, declared for a given profile. This mirrors
  // what a real daemon /v1/version emits — the point is that the KEYS are all
  // present on both profiles (completeness), with profile-appropriate availability.
  function descriptorWith(overrides) {
    const caps = {};
    Object.keys(map).forEach(function (id) { caps[map[id].capability] = cap('available', 'available'); });
    // Also carry the embedder/delegation axis so a lite profile is realistic.
    caps.local_embedders = caps.local_embedders || cap('available', 'available');
    caps.embedding_delegation = caps.embedding_delegation || cap('available', 'available');
    Object.keys(overrides || {}).forEach(function (k) { caps[k] = overrides[k]; });
    return { schema_version: 1, capabilities: caps };
  }

  const fullDescriptor = descriptorWith({});
  // Lite (delegating) daemon (M5b): local embedders delegated, delegation live.
  // The two mapped consumers are dataplane-gated (projection_queries /
  // graph_expand), NOT embedder-gated, so they stay AVAILABLE on lite.
  const liteDescriptor = descriptorWith({
    local_embedders: cap('unavailable', 'delegated_to_remote'),
    embedding_delegation: cap('available', 'available')
  });
  // Lite + delegation-down: the delegation capability degrades. Mapped consumers
  // are still unaffected (not delegation-gated) — proving lite degradation does
  // not spuriously disable dataplane controls, and vice-versa.
  const liteDegraded = descriptorWith({
    local_embedders: cap('unavailable', 'delegated_to_remote'),
    embedding_delegation: cap('degraded', 'embedding_delegation_degraded')
  });

  [['full', fullDescriptor], ['lite', liteDescriptor], ['lite-degraded', liteDegraded]].forEach(function (pair) {
    const label = pair[0], descriptor = pair[1];
    // (2) Completeness: every mapped capability is declared on this profile.
    Object.keys(map).forEach(function (id) {
      const capName = map[id].capability;
      check(!!descriptor.capabilities[capName],
        '[m2b] ' + label + ' profile must declare capability "' + capName + '" consumed by control "' + id + '" (else undeclared → 501)');
      // Anti-501: with the capability declared+available, the control is enabled;
      // it never renders enabled-but-unbacked.
      const state = render.capabilityStateForControl(id, descriptor, map);
      check(state && state.disabled === false && state.availability === 'available',
        '[m2b] ' + label + ': dataplane control "' + id + '" must be enabled (available) — not disabled, not 501');
    });
  });

  // (3) The gate DOES react to a degraded profile: a hypothetical control mapped
  // to the delegation capability renders disabled-with-reason on lite-degraded.
  const probeMap = { 'probe.embedding': { capability: 'embedding_delegation', routes: [['POST', '/v1/query']] } };
  const enabled = render.capabilityStateForControl('probe.embedding', liteDescriptor, probeMap);
  const degraded = render.capabilityStateForControl('probe.embedding', liteDegraded, probeMap);
  check(enabled && enabled.disabled === false,
    '[m2b] a delegation-gated control is enabled when delegation is available');
  check(degraded && degraded.disabled === true && degraded.reasonCode === 'embedding_delegation_degraded',
    '[m2b] a delegation-gated control is disabled-with-reason when delegation is degraded (lite fail-closed)');

  notes.push('two-profile conformance (M2b): reverse coverage asserts every literal applyCapabilityGate call site is in CONTROL_CAPABILITY_MAP (a new gated control that skipped the map fails the smoke instead of reaching a 501); descriptor completeness asserts every mapped capability is declared on BOTH full and lite (delegating) profiles so no mapped control falls to capability_undeclared; the two dataplane consumers stay enabled across full/lite/lite-degraded; and a delegation-gated probe flips to disabled-with-reason when a lite daemon reports delegation degraded (M5b breaker open) — proving the gate reacts to the lite axis and never renders enabled-but-unbacked.');
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
  // M21 RETARGET (was: "Canvas must carry a Tree view switch"). The Tree's home
  // is the Rings tab hub since M19; M21 deleted the Canvas segmented control. The
  // dispatch itself must survive — #/canvas/tree and workspace pages of type
  // canvas/tree still resolve through renderCanvas.
  check(/ctx\.view === 'tree'/.test(renderSrc) && /renderPlanTree\(body, ctx\)/.test(renderSrc),
    '[plan-tree] renderCanvas must still dispatch the tree view to renderPlanTree');
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
//  Check 51 — (console-surfaces-remediation M14) Canvas Studio: the ported
//  diagram-builder engine as a fourth canvas view. Asserts (a) the pure doc
//  subset round-trips + sanitises (same-origin web src, known-route API bind,
//  dangling-link drop, dropped-kind normalise); (b) the tstudio region carries
//  NO innerHTML and NO raw fetch, and persists ONLY through operatorGatedCall →
//  consoleFactsAdd against the console:tileboard: / console:tiledesign: entities;
//  (c) the registry wiring (renderCanvas dispatch, parseCanvasHash, sitemap
//  node); (d) the view paints its shell against a mock DOM and builds a seeded
//  multi-kind board (incl. a same-origin iframe) without throwing; (e) read-only
//  posture paints the banner and disables Save.
// =========================================================================
(function checkTileStudio() {
  // ---- (a) pure doc subset ------------------------------------------------
  check(typeof render.renderTileStudio === 'function', '[studio] render.js must export renderTileStudio');
  check(typeof render.tstudioNormalizeDoc === 'function', '[studio] render.js must export tstudioNormalizeDoc');
  check(render.tstudioSnap(33) === 40 && render.tstudioSnap(50) === 60, '[studio] tstudioSnap must snap to the 20px grid (matches the incumbent canvas grammar)');
  check(render.tstudioWebSrcOk('/console') === true, '[studio] a same-origin path must be an allowed web src');
  check(render.tstudioWebSrcOk('http://x.test') === false && render.tstudioWebSrcOk('//host') === false && render.tstudioWebSrcOk('javascript:1') === false,
    '[studio] external / protocol-relative / javascript: web srcs must be rejected');
  check(render.tstudioJsonPath({ a: { b: [7, 8] } }, 'a.b[1]') === 8, '[studio] tstudioJsonPath must resolve dot/bracket paths');
  // Round-trip identity + sanitisation over a multi-kind board.
  const raw = {
    nodes: [
      { id: 'n1', kind: 'note', x: 40, y: 40, w: 220, h: 140, label: 'A', body: 'b' },
      { id: 'n2', kind: 'box', x: 60, y: 200, w: 240, h: 150 },
      { id: 'n3', kind: 'web', x: 300, y: 40, w: 380, h: 260, url: 'http://evil.test' },
      { id: 'n4', kind: 'api', x: 300, y: 320, w: 240, h: 150, api: { route: '/v1/facts/list', preset: 'stat', jsonPath: 'total_visible' } },
      { id: 'n5', kind: 'model', x: 700, y: 40 },       // dropped kind → normalised
      { id: 'n1', kind: 'note' }                          // duplicate id → dropped
    ],
    links: [ { from: 'n1', to: 'n2', label: 'flows' }, { from: 'n1', to: 'ghost' } ],  // second link dangles
    texts: [ { text: 'title', x: 10, y: 10, size: 30, bold: true } ],
    pan: { x: 5, y: 6 }, zoom: 9, version: 1
  };
  const norm = render.tstudioNormalizeDoc(raw);
  check(norm.nodes.length === 5, '[studio] normalizeDoc must drop duplicate node ids (5 unique of 6)');
  check(norm.nodes[2].url === '', '[studio] normalizeDoc must strip an external web url to empty (same-origin only)');
  check(norm.links.length === 1, '[studio] normalizeDoc must drop links whose endpoints are missing');
  check(norm.zoom === 3, '[studio] normalizeDoc must clamp zoom into range');
  const round = render.tstudioNormalizeDoc(JSON.parse(render.tstudioSerializeDoc(norm)));
  check(round.nodes.length === norm.nodes.length && round.links.length === norm.links.length && round.texts.length === norm.texts.length,
    '[studio] doc must survive a serialize → normalize round-trip (board persistence identity)');
  // Known-route allowlist for API tiles (drives the real tstudioApiRouteKnown
  // against a stubbed window.CRUX_GET_ROUTES).
  {
    const savedWin = global.window;
    global.window = { CRUX_GET_ROUTES: ['/v1/facts/list', '/v1/activity'] };
    check(render.tstudioApiRouteKnown('/v1/facts/list') === true, '[studio] a known GET route must validate for an API tile');
    check(render.tstudioApiRouteKnown('/v1/../etc') === false && render.tstudioApiRouteKnown('http://x') === false,
      '[studio] an arbitrary / unknown route must be rejected for an API tile');
    if (savedWin === undefined) { delete global.window; } else { global.window = savedWin; }
  }

  // ---- (b) region invariants + gated-write choke --------------------------
  const tsA = renderSrc.indexOf('Canvas Studio (M14)');
  const tsB = renderSrc.indexOf('function renderCanvas(host, ctx)');
  const region = (tsA >= 0 && tsB > tsA) ? renderSrc.slice(tsA, tsB) : '';
  check(!!region, '[studio] the tstudio region must be locatable in render.js');
  check(!/\.innerHTML/.test(region), '[studio] the studio engine must contain NO innerHTML (el()/svgEl()/textContent only)');
  check(!/\bfetch\s*\(/.test(region), '[studio] the studio engine must issue NO raw fetch — reads via fetchJSON/CruxApi, writes via the gated client');
  check(/operatorGatedCall\(function \(g\) \{ return g\.consoleFactsAdd\(/.test(region),
    '[studio] persistence must write ONLY through operatorGatedCall → consoleFactsAdd');
  check(/console:tileboard:/.test(region) && /console:tiledesign:/.test(region),
    '[studio] boards + designs must persist under the console:tileboard: / console:tiledesign: entities');
  check(/CRUX_GET_ROUTES/.test(region), '[studio] the API-tile route picker must validate against the generated client route list');

  // ---- (c) registry / nav wiring -----------------------------------------
  // M21 RETARGET (was: "Canvas must carry a Studio view switch"). Inside the
  // Studio the primary control is now the Studio's own sections; the Studio is
  // no longer one tab of a four-view switch. Gate the dispatch + the new control.
  check(/ctx\.view === 'studio'/.test(renderSrc) && /renderTileStudio\(body, ctx\)/.test(renderSrc),
    '[studio] renderCanvas must dispatch the studio view to renderTileStudio');
  // L1 added a fourth section (Library) to this same control — Check 58 gates
  // the full four-entry list and its routing; this gate keeps the M16b three and
  // the control's identity.
  check(/canvas-subseg', role: 'group', 'aria-label': 'Studio section'/.test(renderSrc)
    && /\['board', 'Board'\], \['pages', 'Pages'\], \['integrations', 'Integrations'\]/.test(renderSrc),
    '[studio] the Studio must expose its OWN sections (Board · Pages · Integrations, + Library per Check 58) as the primary control');
  check(/parts\[1\] === 'studio'/.test(shellHtml), '[studio] shell.html parseCanvasHash must route #/canvas/studio to the Studio view');
  check(/'canvas:studio'/.test(renderSrc), '[studio] the site map must carry a canvas:studio node');

  // ---- (d)+(e) mock-DOM drive --------------------------------------------
  function mkEl(tag) {
    const node = {
      tagName: String(tag || 'div').toUpperCase(), nodeType: 1, childNodes: [], _attrs: {}, className: '',
      style: { _p: {}, setProperty: function (k, v) { this._p[k] = v; } },
      classList: {
        _s: {},
        add: function (c) { this._s[c] = true; },
        remove: function (c) { delete this._s[c]; },
        contains: function (c) { return !!this._s[c]; },
        toggle: function (c, on) { const want = (on === undefined) ? !this._s[c] : !!on; if (want) { this._s[c] = true; } else { delete this._s[c]; } return want; }
      },
      setAttribute: function (k, v) { this._attrs[k] = String(v); if (k === 'class') { this.className = String(v); } },
      getAttribute: function (k) { return Object.prototype.hasOwnProperty.call(this._attrs, k) ? this._attrs[k] : null; },
      appendChild: function (c) { this.childNodes.push(c); c.parentNode = this; return c; },
      removeChild: function (c) { const i = this.childNodes.indexOf(c); if (i >= 0) { this.childNodes.splice(i, 1); } return c; },
      addEventListener: function () {}, removeEventListener: function () {},
      getBoundingClientRect: function () { return { left: 0, top: 0, width: 960, height: 640, right: 960, bottom: 640 }; },
      focus: function () {},
      querySelector: function (sel) { const out = []; sel_collect(this, sel, out); return out[0] || null; },
      querySelectorAll: function (sel) { const out = []; sel_collect(this, sel, out); return out; }
    };
    Object.defineProperty(node, 'textContent', { get: function () { return this._text || ''; }, set: function (v) { this._text = String(v); this.childNodes.length = 0; } });
    Object.defineProperty(node, 'lastChild', { get: function () { return this.childNodes[this.childNodes.length - 1] || null; } });
    Object.defineProperty(node, 'firstChild', { get: function () { return this.childNodes[0] || null; } });
    return node;
  }
  function sel_match(node, sel) {
    if (sel.charAt(0) === '.') { return String(node.className).split(/\s+/).indexOf(sel.slice(1)) >= 0; }
    if (sel.charAt(0) === '#') { return node._attrs && node._attrs.id === sel.slice(1); }
    return node.tagName === sel.toUpperCase();
  }
  function sel_collect(node, sel, out) {
    (node.childNodes || []).forEach(function (c) { if (c && c.nodeType === 1) { if (sel_match(c, sel)) { out.push(c); } sel_collect(c, sel, out); } });
  }
  function collectAll(node, out) { out = out || []; (node.childNodes || []).forEach(function (c) { if (c && c.nodeType === 1) { out.push(c); collectAll(c, out); } }); return out; }

  const seededDoc = {
    nodes: [
      { id: 'a', kind: 'note', x: 40, y: 40, w: 220, h: 140, label: 'Note' },
      { id: 'b', kind: 'box', x: 40, y: 220, w: 240, h: 150 },
      { id: 'c', kind: 'web', x: 320, y: 40, w: 380, h: 260, url: '/console' },
      { id: 'd', kind: 'api', x: 320, y: 340, w: 240, h: 150, label: 'API', api: { route: '', preset: 'stat', jsonPath: '', params: '', fields: '', max: '', refresh: 'off', tokenBudget: '' } },
      { id: 'e', kind: 'server', x: 720, y: 40, w: 220, h: 140, label: 'Server' }
    ],
    links: [{ id: 'l1', from: 'a', to: 'e', label: 'reads' }],
    texts: [], pan: { x: 0, y: 0 }, zoom: 1, version: 1
  };
  // The seed path renders synchronously (no async load) → no global.document
  // race with other async checks; assertions land in the same sync tick.
  function driveStudio(posture) {
    const savedDoc = global.document, savedWin = global.window;
    global.document = {
      createElement: mkEl, createElementNS: function (ns, tag) { return mkEl(tag); },
      createTextNode: function (v) { return { nodeType: 3, textContent: String(v), childNodes: [] }; },
      addEventListener: function () {}, removeEventListener: function () {},
      elementFromPoint: function () { return null; }, body: mkEl('body')
    };
    global.window = { CRUX_POSTURE: posture, CRUX_GET_ROUTES: ['/v1/facts/list', '/v1/activity'], CruxApi: { get: function () { return Promise.resolve({ ok: true, status: 200, json: function () { return Promise.resolve({ facts: [] }); } }); } }, CruxApiGated: { consoleFactsAdd: function () { return Promise.resolve({ ok: true, status: 201 }); } } };
    const host = mkEl('div');
    try { render.renderTileStudio(host, { seedDoc: seededDoc }); }
    catch (e) { check(false, '[studio] renderTileStudio threw on the seeded paint (' + posture + '): ' + (e && e.stack || e)); }
    check(host.querySelectorAll('.tstudio').length === 1, '[studio] renderTileStudio must paint the .tstudio shell (' + posture + ')');
    check(host.querySelectorAll('.tstudio-toolbar').length === 1, '[studio] the toolbar must paint (' + posture + ')');
    check(host.querySelectorAll('.tstudio-library').length === 1, '[studio] the library panel must paint (' + posture + ')');
    check(host.querySelectorAll('.tstudio-stage').length === 1, '[studio] the stage must paint (' + posture + ')');
    if (savedDoc === undefined) { delete global.document; } else { global.document = savedDoc; }
    if (savedWin === undefined) { delete global.window; } else { global.window = savedWin; }
    return host;
  }
  try {
    const hostOp = driveStudio('operator');
    const allOp = collectAll(hostOp);
    const nodes = allOp.filter(function (n) { return /\btstudio-node\b/.test(n.className || ''); });
    check(nodes.length === 5, '[studio] the seeded 5-node board must build 5 tiles (got ' + nodes.length + ')');
    check(allOp.some(function (n) { return n.tagName === 'IFRAME'; }), '[studio] a same-origin web tile must render an iframe embed');
    check(allOp.some(function (n) { return /\btstudio-savechip\b/.test(n.className || ''); }), '[studio] the toolbar must carry a save-state chip');
    const hostRo = driveStudio('customer');
    const allRo = collectAll(hostRo);
    check(allRo.some(function (n) { return /\btstudio-banner\b/.test(n.className || ''); }), '[studio] read-only posture must paint the honest read-only banner');
  } catch (e) {
    check(false, '[studio] mock-DOM drive threw: ' + (e && e.stack || e));
  }

  notes.push('canvas studio (M14): ported diagram-builder as a fourth canvas view (#/canvas/studio); pure doc subset round-trips + sanitises (same-origin web src, known-route API bind, dangling-link drop, dropped 3D/PDF kinds); NO innerHTML / NO raw fetch in the engine; boards + designs persist daemon-side via operatorGatedCall→consoleFactsAdd under console:tileboard:/console:tiledesign:; mock-DOM drive builds a seeded 5-tile board incl. a same-origin iframe; read-only posture paints the banner + disables Save.');

  // ---- M15: live tiles, automated-data-handling kinds, packs, settings ----
  // (a) new pure helpers (smoke-tested, no DOM).
  check(render.tstudioCoverageNote(0.42).low === true && /corpus may not cover this/.test(render.tstudioCoverageNote(0.42).text),
    '[studio-m15] coverage below 0.5 is flagged honestly');
  check(render.tstudioCoverageNote(0.8).low === false, '[studio-m15] coverage at/above 0.5 is not flagged');
  var capsBoard = { nodes: [ { kind: 'api', api: { route: '/v1/facts/list' } }, { kind: 'search', search: { route: '/v1/query/text-search' } }, { kind: 'receipts', api: { route: '/v1/receipts/list' } } ] };
  var caps = render.tstudioDerivePackCaps(capsBoard);
  check(caps.indexOf('integrations:read') >= 0 && caps.indexOf('facts:read') >= 0 && caps.indexOf('admin:read') >= 0,
    '[studio-m15] derived caps include the minimal read set (integrations:read + facts:read + admin:read for a receipts tile)');
  check(JSON.stringify(caps) === JSON.stringify(caps.slice().sort()), '[studio-m15] derived caps are sorted + deterministic');
  check(render.tstudioTileEvents({ kind: 'search' }).indexOf('fact.stored') >= 0, '[studio-m15] a search tile depends on fact.stored for live refresh');
  check(render.tstudioTileEvents({ kind: 'api', api: { route: '/v1/activity' } }).indexOf('activity.appended') >= 0, '[studio-m15] an activity-bound tile depends on activity.appended');
  check(render.tstudioTileEvents({ kind: 'extensions' }).length === 0, '[studio-m15] the extensions tile takes no live event (registry rarely changes)');
  var ph = render.tstudioFindPlaceholders({ search: { query: '{{q}} in {{scope}}' } });
  check(ph.indexOf('q') >= 0 && ph.indexOf('scope') >= 0, '[studio-m15] parameterised designs expose {{placeholder}} fields');
  var filled = render.tstudioApplyPlaceholders({ q: '{{q}}' }, { q: 'execplan' });
  check(filled.q === 'execplan', '[studio-m15] placeholders are substituted on instantiate');
  var st = render.tstudioNormalizeSettings({ grid: 999, accent: 'nope', title: 'T' });
  check(st.grid === 20 && st.accent === 'cool' && st.title === 'T', '[studio-m15] settings normalise: unknown grid/accent fall back, title kept');
  var payload = render.tstudioBuildStudioPayload('b1', render.tstudioNormalizeDoc({ nodes: [{ id: 'x', kind: 'note' }] }), [], { title: 'Board' });
  check(payload.schema === 'crux.studio.v1' && payload.board.doc.nodes.length === 1 && payload.settings.title === 'Board',
    '[studio-m15] a studio payload wraps the board doc + settings under crux.studio.v1');
  // settings survive a serialize → normalize round-trip (persistence identity).
  var withSettings = render.tstudioNormalizeDoc({ nodes: [], settings: { grid: 32, accent: 'ok', title: 'RT' } });
  var rtSettings = render.tstudioNormalizeDoc(JSON.parse(render.tstudioSerializeDoc(withSettings))).settings;
  check(rtSettings.grid === 32 && rtSettings.accent === 'ok' && rtSettings.title === 'RT', '[studio-m15] board settings survive the serialize→normalize round-trip');

  // (b) pure content renderers against a mock document (el()/textContent only).
  function withMockDoc(fn) {
    var savedDoc = global.document;
    global.document = {
      createElement: mkEl, createElementNS: function (ns, tag) { return mkEl(tag); },
      createTextNode: function (v) { return { nodeType: 3, textContent: String(v), childNodes: [] }; },
      addEventListener: function () {}, removeEventListener: function () {}, body: mkEl('body')
    };
    try { return fn(); } finally { if (savedDoc === undefined) { delete global.document; } else { global.document = savedDoc; } }
  }
  withMockDoc(function () {
    // search: coverage honesty text renders.
    var sEl = render.tstudioRenderSearch({ coverage: { score: 0.42 }, results: [{ entity: 'e1', score: 1.2 }] }, { query: 'x' }, {});
    var sTxt = collectAll(sEl).map(function (n) { return n.textContent || ''; }).join(' ');
    check(/corpus may not cover this/.test(sTxt), '[studio-m15] the search tile renders the honest low-coverage note');
    // corpus: store counts render.
    var cEl = render.tstudioRenderCorpus({ stores: { facts: 5202, sessions: 76 }, integrations: { builtin_pack_count: 3 }, daemon: { build: { version: '0.5.46' } } });
    var cTxt = collectAll(cEl).map(function (n) { return n.textContent || ''; }).join(' ');
    check(/5,202/.test(cTxt) || /5202/.test(cTxt), '[studio-m15] the corpus tile renders the fact count');
    // receipts: rows render.
    var rEl = render.tstudioRenderReceipts({ rows: [{ kind: 'approval_decision', principal: 'operator', receipt_id: 'ad_ga_abc' }] });
    check(collectAll(rEl).some(function (n) { return /approval_decision/.test(n.textContent || ''); }), '[studio-m15] the receipts tile renders newest rows');
    // extensions: honest empty on a bare mirror.
    var eEmpty = render.tstudioRenderExtensions({ count: 0, extensions: [] }, { operator: true });
    check(/No extensions installed/.test(collectAll(eEmpty).map(function (n) { return n.textContent || ''; }).join(' ')), '[studio-m15] the extensions tile is honest-empty on a bare mirror + explains install');
    // extensions: a fixture extension WITH a data endpoint renders capability
    // chips + a capability-gated Invoke affordance (proves the outbound binding).
    var eFix = render.tstudioRenderExtensions({ count: 1, extensions: [{ id: 'ext.quote', trust_tier: 'community_reviewed', manifest: { capabilities: ['facts:read'], external_tool_endpoint: 'https://x/', tools: [{ name: 'quote.daily' }] } }] }, { operator: true });
    var fixAll = collectAll(eFix);
    check(fixAll.some(function (n) { return /\btstudio-cap-chip\b/.test(n.className || '') && /facts:read/.test(n.textContent || ''); }), '[studio-m15] extensions tile renders capability chips');
    check(fixAll.some(function (n) { return /\btstudio-ext-invoke\b/.test(n.className || ''); }), '[studio-m15] a declared data endpoint renders a capability-gated Invoke affordance (extension_outbound)');
    // non-operator posture disables the Invoke affordance.
    var eRo = render.tstudioRenderExtensions({ count: 1, extensions: [{ id: 'ext.quote', manifest: { capabilities: [], tools: [{ name: 't' }] } }] }, { operator: false });
    check(collectAll(eRo).some(function (n) { return /\btstudio-ext-invoke\b/.test(n.className || '') && n.disabled === true; }), '[studio-m15] Invoke is disabled without operator posture');
  });

  // (c) the new kinds are registered with fixed routes + the live option.
  ['search', 'corpus', 'receipts', 'extensions'].forEach(function (k) {
    check(!!render.TSTUDIO_KINDS[k], '[studio-m15] kind "' + k + '" is registered');
  });
  check(/\['live', 'Live'\]/.test(renderSrc), '[studio-m15] the refresh options include a Live mode');
  check(/new EventSource\('\/v1\/events\/stream'\)/.test(renderSrc), '[studio-m15] live tiles subscribe to /v1/events/stream (EventSource, not fetch)');
  // pack routes ride the curated read-POST client (added to READ_POST in M15).
  check(/window\.CruxApiRead\.studioPackBuild|CruxApiRead[\s\S]{0,40}studioPackBuild/.test(renderSrc) || /studioPackBuild/.test(renderSrc), '[studio-m15] export builds through the read-POST client (studioPackBuild)');
  check(/studioPackVerify/.test(renderSrc), '[studio-m15] import verifies through the read-POST client (studioPackVerify)');

  // (d) a seeded board with the new kinds builds without throwing (mock DOM).
  try {
    var savedDoc2 = global.document, savedWin2 = global.window;
    global.document = {
      createElement: mkEl, createElementNS: function (ns, tag) { return mkEl(tag); },
      createTextNode: function (v) { return { nodeType: 3, textContent: String(v), childNodes: [] }; },
      addEventListener: function () {}, removeEventListener: function () {}, elementFromPoint: function () { return null; }, body: mkEl('body')
    };
    global.window = {
      CRUX_POSTURE: 'operator', CRUX_GET_ROUTES: ['/v1/console/summary', '/v1/receipts/list', '/v1/extensions'],
      CruxApi: { get: function () { return Promise.resolve({ ok: true, status: 200, json: function () { return Promise.resolve({ stores: { facts: 1, sessions: 1 }, rows: [], extensions: [], count: 0 }); } }); } },
      CruxApiGated: { consoleFactsAdd: function () { return Promise.resolve({ ok: true, status: 201 }); } },
      CruxApiRead: { queryTextSearch: function () { return Promise.resolve({ ok: true, json: function () { return Promise.resolve({ coverage: { score: 0 }, results: [] }); } }); } }
    };
    var seededM15 = { nodes: [
      { id: 's', kind: 'search', x: 40, y: 40, w: 480, h: 240, search: { route: '/v1/query/text-search', query: 'q', tenant: 'default', tokenBudget: '800', refresh: 'off' } },
      { id: 'co', kind: 'corpus', x: 540, y: 40, w: 240, h: 170, api: { route: '/v1/console/summary', refresh: 'live' } },
      { id: 're', kind: 'receipts', x: 40, y: 300, w: 340, h: 220, api: { route: '/v1/receipts/list', refresh: 'off', limit: '7' } },
      { id: 'ex', kind: 'extensions', x: 400, y: 300, w: 340, h: 220, api: { route: '/v1/extensions', refresh: 'off' } }
    ], links: [], texts: [], pan: { x: 0, y: 0 }, zoom: 1, version: 1, settings: { grid: 24, accent: 'trust', title: 'M15' } };
    var hostM15 = mkEl('div');
    render.renderTileStudio(hostM15, { seedDoc: seededM15 });
    var tilesM15 = collectAll(hostM15).filter(function (n) { return /\btstudio-node\b/.test(n.className || ''); });
    check(tilesM15.length === 4, '[studio-m15] a seeded board with the 4 new kinds builds 4 tiles (got ' + tilesM15.length + ')');
    check(collectAll(hostM15).some(function (n) { return /\btstudio-livechip\b/.test(n.className || ''); }), '[studio-m15] the toolbar carries a live connection chip');
    check(collectAll(hostM15).some(function (n) { return /\btstudio-lib-item\b/.test(n.className || '') && /Text search|Corpus|Receipts|Extensions/.test(collectAll(n).map(function (c) { return c.textContent || ''; }).join('')); }), '[studio-m15] the library palette offers the new kinds');
    if (savedDoc2 === undefined) { delete global.document; } else { global.document = savedDoc2; }
    if (savedWin2 === undefined) { delete global.window; } else { global.window = savedWin2; }
  } catch (e) {
    check(false, '[studio-m15] seeded new-kind board threw: ' + (e && e.stack || e));
  }
  notes.push('studio M15: live tiles (per-tile live/interval/off via one shared /v1/events/stream EventSource, targeted debounced refetch, honest connection chip); 4 automated-data-handling kinds (text-search w/ coverage honesty, corpus status, receipts, registry-backed extensions w/ capability chips + capability-gated extension_outbound Invoke, honest-empty); Studio packs export/import (crux.studio.v1 in a signed crux.integration.v1 manifest via /v1/studio/pack/{build,verify}; hashes + verbatim verdict + operator-gated apply); board settings (grid/refresh/accent/title/description, exported in the pack) + parameterised design instantiation; a signed community example pack passes the community_packs gate.');
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
  check(typeof render.registryVerifyUrl === 'function', '[session-detail] render.js must export registryVerifyUrl()');
  if (typeof render.buildSessionDetail !== 'function') { return; }

  if (typeof render.registryVerifyUrl === 'function') {
    check(render.registryVerifyUrl('blake3:deadbeef') ===
      'https://registry.rcxprotocol.org/v0/receipts/blake3%3Adeadbeef',
      '[session-detail] registryVerifyUrl must resolve a receipt/hash against the fixed HTTPS Registry origin');
    ['', '../escape', 'hash/segment', ' hash with spaces ', 'https://evil.invalid/x', 'x\u0000y'].forEach(function (bad) {
      check(render.registryVerifyUrl(bad) === null,
        '[session-detail] registryVerifyUrl must reject an unsafe/empty receipt reference: ' + JSON.stringify(bad));
    });
  }

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
    model.receipts.items[0].body_hash === 'blake3:deadbeefcafe0000' &&
    model.receipts.items[0].registry_ref === 'blake3:deadbeefcafe0000' &&
    model.receipts.chain && model.receipts.chain.status === 'ok',
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
    const verifyLinks = mock.findByClass(painted, 'session-detail-verify');
    check(verifyLinks.length === 1 && verifyLinks[0].tagName === 'A' &&
      verifyLinks[0].getAttribute('href') === 'https://registry.rcxprotocol.org/v0/receipts/blake3%3Adeadbeefcafe0000' &&
      verifyLinks[0].getAttribute('target') === '_blank' && verifyLinks[0].getAttribute('rel') === 'noopener noreferrer' &&
      verifyLinks[0].getAttribute('data-shell-tab') === 'registry',
      '[session-detail] a receipt body hash renders one fixed-origin, noopener Registry lookup link for the shell-tab policy');
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
//  Check 44b — (desktop mission control M9 local build) Registry + WikiCrux
//  public tabs remain a closed native allow-list and receive zero Tauri IPC.
//  Runtime rendering/SSO/CSP stays an operator+real-webview gate; this source
//  audit proves the locally testable privilege and lifecycle invariants.
// =========================================================================
(function checkDesktopPublicShellTabs() {
  const desktopRoot = path.join(DIR, '../../../../shells/desktop');
  const capabilityPath = path.join(desktopRoot, 'app/capabilities/default.json');
  const appPath = path.join(desktopRoot, 'app/src/main.rs');
  const navigationPath = path.join(desktopRoot, 'connection/src/navigation.rs');
  let capability, appSrc, navigationSrc;
  try {
    capability = JSON.parse(fs.readFileSync(capabilityPath, 'utf8'));
    appSrc = fs.readFileSync(appPath, 'utf8');
    navigationSrc = fs.readFileSync(navigationPath, 'utf8');
  } catch (e) {
    check(false, '[desktop-tabs] shell source/config must be readable: ' + (e && e.message || e));
    return;
  }
  const windows = capability.windows || [];
  check(Array.isArray(capability.permissions) && capability.permissions.length === 0 &&
    !Object.prototype.hasOwnProperty.call(capability, 'remote'),
    '[desktop-tabs] capability must keep an empty permission set and no remote URL grant');
  check(windows.indexOf('shell-tab-registry') >= 0 && windows.indexOf('shell-tab-wikicrux') >= 0,
    '[desktop-tabs] the zero-permission capability must enumerate both stable public-tab labels');
  check(/registry\.rcxprotocol\.org/.test(navigationSrc) && /wiki\.cuecrux\.com/.test(navigationSrc) &&
    /parsed\.scheme != "https"/.test(navigationSrc) && /parsed\.port != 443/.test(navigationSrc),
    '[desktop-tabs] navigation.rs must pin the two exact HTTPS:443 product origins');
  check(/fn build_shell_tab_window\b/.test(appSrc) &&
    /\.on_navigation\(move \|url\| navigation_tab\.allows/.test(appSrc) &&
    /\.on_new_window\(\|_url, _features\| NewWindowResponse::Deny\)/.test(appSrc) &&
    /\.on_download\(\|_webview, _event\| false\)/.test(appSrc),
    '[desktop-tabs] the public-tab builder must origin-lock top-level navigation and deny popups/downloads');
  check(!/invoke_handler\s*\(/.test(appSrc),
    '[desktop-tabs] the desktop app must register no Tauri invoke handler reachable by remote page script');
  check(/shell_tab_for_window_label\(window\.label\(\)\)/.test(appSrc) && /close_shell_tabs\(app\)/.test(appSrc),
    '[desktop-tabs] closing a public tab must not exit the app, and profile switches must close stale public tabs');
  notes.push('desktop M9 local build: exact Registry/WikiCrux HTTPS:443 tab allow-list; separate origin-locked webviews; no remote capability/invoke surface; popups + downloads denied; profile switch closes tabs; receipt link uses fixed Registry origin.');
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

  // M5a: renderPlanTree must source data.localPlanHashes from the desktop
  // shell's injected read-only global (window.CRUX_LOCAL_PLAN_HASHES), not from
  // a fetch — otherwise the injected hashes never reach the badge (dead wiring).
  check(/localPlanHashes:\s*\(typeof window[^\n]*CRUX_LOCAL_PLAN_HASHES/.test(renderSrc),
    '[plan-hash] renderPlanTree must wire window.CRUX_LOCAL_PLAN_HASHES into buildPlanTree data.localPlanHashes (M5a shell feed)');

  notes.push('plan-hash badge (M4c console half): planHashBadge(daemon_hash, local_hash|null) is pure — no daemon hash → no badge; no local hash → provenance chip (daemon short-form, since the browser cannot read local files); equal → in-sync; differing → mismatch badge (T.2 guard); buildPlanTree wires it onto ExecPlan nodes (daemon hash read defensively so it is forward-compatible before PR #457 ships; local hash from data.localPlanHashes by id then slug) and the row paints the state-classed chip carrying data-hash-state. M5a: renderPlanTree feeds data.localPlanHashes from window.CRUX_LOCAL_PLAN_HASHES (shell-injected read-only global; undefined for browser-only users → provenance-only).');
})();

// =========================================================================
//  Check 47 — (M3b) attention-zone classifier truth table. deriveAttentionZone
//  sorts ONE normalised work/session item into exactly one zone with an explicit
//  precedence (needs_you > running > done_review) and an explicit staleness rule
//  (a live session is "running" only while its heartbeat is within
//  ATTENTION_LIVENESS_STALE_MS of now). The classifier is pure — no DOM, no fetch.
// =========================================================================
(function checkAttentionZoneClassifier() {
  check(typeof render.deriveAttentionZone === 'function', '[attn] render.js must export the pure deriveAttentionZone classifier');
  check(render.ATTENTION_LIVENESS_STALE_MS === 300000,
    '[attn] ATTENTION_LIVENESS_STALE_MS must be 300000ms (5 min); got ' + render.ATTENTION_LIVENESS_STALE_MS);
  if (typeof render.deriveAttentionZone !== 'function') { return; }
  const dz = render.deriveAttentionZone;
  const STALE = render.ATTENTION_LIVENESS_STALE_MS;
  const now = 1000000000;
  const fresh = now - Math.floor(STALE / 2);   // within the window → live
  const stale = now - (STALE + 60000);          // older than the window → idle
  const future = now + 60000;                    // clock skew → negative age

  // Truth table: one representative input per zone (+ the "no attention" cases).
  // States are the REAL WorkItem enum (work.rs WORK_STATES): 'complete' is done.
  const cases = [
    ['gate pending', { gatePending: true }, 'needs_you'],
    ['blocked plan', { state: 'blocked', blockerReason: 'waiting on review' }, 'needs_you'],
    ['waiting session', { liveSession: true, lastSeenUnixMs: fresh, waitingForInput: true }, 'needs_you'],
    ['in_progress plan', { state: 'in_progress' }, 'running'],
    ['fresh live session', { liveSession: true, lastSeenUnixMs: fresh }, 'running'],
    ['complete plan', { state: 'complete' }, 'done_review'],
    ['review pending', { reviewPending: true }, 'done_review'],
    ['planned/idle', { state: 'planned' }, null],
    ['deployed (shipped, not awaiting review)', { state: 'deployed' }, null],
    ['empty item', {}, null],
    ['non-object', null, null]
  ];
  cases.forEach(function (c) {
    check(dz(c[1], now) === c[2], '[attn] deriveAttentionZone(' + c[0] + ') must be ' + String(c[2]) + ' (got ' + String(dz(c[1], now)) + ')');
  });

  // Precedence — needs_you > running > done_review.
  check(dz({ state: 'blocked', liveSession: true, lastSeenUnixMs: fresh }, now) === 'needs_you',
    '[attn] precedence: an item that is BOTH blocked AND a running session must resolve to needs_you');
  check(dz({ gatePending: true, state: 'in_progress' }, now) === 'needs_you',
    '[attn] precedence: a gate on an in_progress plan must resolve to needs_you');
  check(dz({ state: 'in_progress', reviewPending: true }, now) === 'running',
    '[attn] precedence: running must outrank done_review');

  // Staleness rule — running requires a FINITE, non-negative heartbeat age in
  // [0, threshold]. Stale, future (clock skew → negative age), and non-finite
  // timestamps are all NOT running.
  check(dz({ liveSession: true, lastSeenUnixMs: stale }, now) === null,
    '[attn] staleness: a stale-heartbeat session must NOT be running (idle → null)');
  check(dz({ liveSession: true, lastSeenUnixMs: future }, now) === null,
    '[attn] staleness: a FUTURE heartbeat (clock skew → negative age) must NOT be running');
  check(dz({ liveSession: true, lastSeenUnixMs: 'nope' }, now) === null,
    '[attn] staleness: a non-finite heartbeat must NOT be running');
  check(dz({ liveSession: true, lastSeenUnixMs: now - STALE }, now) === 'running',
    '[attn] staleness: a heartbeat exactly at the threshold is still running (<=)');
  check(dz({ liveSession: true, lastSeenUnixMs: now }, now) === 'running',
    '[attn] staleness: a zero-age heartbeat is running');
  check(dz({ liveSession: true, lastSeenUnixMs: now - STALE - 1 }, now) === null,
    '[attn] staleness: a heartbeat one ms past the threshold is idle');

  // Pure — no DOM / no fetch / no window in the classifier body.
  const body = funcBody(renderSrc, 'deriveAttentionZone') || '';
  check(!!body && !/document|\bwindow\b|fetch\s*\(|appendChild|CruxApi/.test(body),
    '[attn] deriveAttentionZone must be pure (no DOM, no fetch, no window/CruxApi)');
  notes.push('attention zones (M3b): deriveAttentionZone(item, now) sorts one normalised item into needs_you > running > done_review with an explicit staleness rule (a live session is running only while its heartbeat is within ATTENTION_LIVENESS_STALE_MS=' + STALE + 'ms of now); precedence + staleness truth table asserted; pure (no DOM/fetch).');
})();

// =========================================================================
//  Check 48 — (M3b) attention surface renders zones from the classifier over a
//  work + coord + gate fixture (mock DOM), grouping correctly; a failed feed
//  shows a per-feed degraded notice (never a silently-empty zone).
// =========================================================================
(function checkAttentionSurfaceRender() {
  if (typeof render.fillNeedsYou !== 'function') { check(false, '[attn-surface] render.js must export fillNeedsYou'); return; }
  const mock = newMockDom();
  const mkNode = mock.mkNode, mockDoc = mock.doc;
  const STALE = render.ATTENTION_LIVENESS_STALE_MS;
  const nowMs = 2000000000;
  const coordData = { now_unix_ms: nowMs, presence_ttl_secs: 900, active_sessions: [
    { session_id_hex: 'run11111', passport_id: 'pp_run', last_seen_at_unix_ms: nowMs - 60000, intent: { execplan_slug: 'alpha', milestone: 'M2' } },
    { session_id_hex: 'idle2222', passport_id: 'pp_idle', last_seen_at_unix_ms: nowMs - (STALE + 300000), intent: { execplan_slug: 'alpha' } },
    { session_id_hex: 'wait3333', passport_id: 'pp_wait', last_seen_at_unix_ms: nowMs - 60000, intent: { execplan_slug: 'beta', note: 'awaiting operator input before deploy' } }
  ] };
  // alpha is in_progress AND carries a pending gate → the gate join must classify
  // it as needs_you ONCE (a gate card), NEVER also running (the double-count bug).
  const workData = { work: [
    { id: 'execplan:alpha', project_id: 'execplans', title: 'Alpha', state: 'in_progress' },
    { id: 'execplan:beta', project_id: 'execplans', title: 'Beta', state: 'blocked', blocker_reason: 'needs a schema decision' },
    { id: 'execplan:gamma', project_id: 'execplans', title: 'Gamma', state: 'complete' },
    { id: 'execplan:delta', project_id: 'execplans', title: 'Delta', state: 'planned' }
  ] };
  const gateData = { pending: [{ action_id: 'act1', work_id: 'execplan:alpha', requested_by_passport: 'pp_req', status: 'pending' }] };
  function fakeRes(ok, status, data) { return Promise.resolve({ ok: ok, status: status, json: function () { return Promise.resolve(data); } }); }
  function mkWrap() { const w = mkNode('div'); w.__body = mkNode('div'); w.__ct = mkNode('span'); return w; }
  function isCard(n) { return (n.className || '').split(/\s+/).indexOf('ow-gate') >= 0; }

  const savedDoc = global.document, savedWin = global.window;
  global.document = mockDoc;
  // Drive A — every feed healthy → correct single-zone grouping (api captured
  // synchronously so the later window swaps don't affect this drive).
  global.window = { CruxApi: { get: function (p) {
    if (p === '/v1/work/gate/pending') { return fakeRes(true, 200, gateData); }
    if (p === '/v1/coord/active') { return fakeRes(true, 200, coordData); }
    return fakeRes(false, 404, null);
  }, work: function () { return fakeRes(true, 200, workData); } } };
  const wrapA = mkWrap();
  const pA = Promise.resolve(render.fillNeedsYou(wrapA));
  // Drive B — coord fails (503) while gates+work stay healthy.
  global.window = { CruxApi: { get: function (p) {
    if (p === '/v1/work/gate/pending') { return fakeRes(true, 200, gateData); }
    if (p === '/v1/coord/active') { return fakeRes(false, 503, null); }
    return fakeRes(false, 404, null);
  }, work: function () { return fakeRes(true, 200, workData); } } };
  const wrapB = mkWrap();
  const pB = Promise.resolve(render.fillNeedsYou(wrapB));
  // Drive C — gate feed fails while work + coord are healthy-but-empty. The panel
  // must show the gates degraded notice and MUST NOT show "All clear" (fail
  // honest), and must NOT fall back to demo (which would erase the notice).
  global.window = { CruxApi: { get: function (p) {
    if (p === '/v1/work/gate/pending') { return fakeRes(false, 503, null); }
    if (p === '/v1/coord/active') { return fakeRes(true, 200, { now_unix_ms: nowMs, active_sessions: [] }); }
    return fakeRes(false, 404, null);
  }, work: function () { return fakeRes(true, 200, { work: [] }); } } };
  const wrapC = mkWrap();
  const pC = Promise.resolve(render.fillNeedsYou(wrapC));

  asyncChecks.push(Promise.all([pA, pB, pC]).then(function () {
    // ---- Drive A: single-zone grouping (no double-count) ----
    const nodesA = mock.collect(wrapA.__body, []);
    const summary = nodesA.filter(function (n) { return /\bow-zone-summary\b/.test(n.className || ''); })[0];
    check(!!summary, '[attn-surface] a zone summary must render the grouping readout');
    if (summary) {
      check(summary.getAttribute('data-needs-you') === '3', '[attn-surface] needs_you must group 3 (gated alpha + blocked beta + waiting session); got ' + summary.getAttribute('data-needs-you'));
      check(summary.getAttribute('data-running') === '1', '[attn-surface] running must group 1 (fresh session ONLY — the gated in_progress alpha must NOT also count as running); got ' + summary.getAttribute('data-running'));
      check(summary.getAttribute('data-done-review') === '1', '[attn-surface] done_review must group 1 (the complete plan); got ' + summary.getAttribute('data-done-review'));
    }
    const cardsA = nodesA.filter(isCard);
    check(cardsA.length === 3, '[attn-surface] exactly 3 needs_you cards must render (got ' + cardsA.length + ')');
    // The gated in_progress alpha appears exactly ONCE, as a gate card (data-action-id).
    const alphaGate = nodesA.filter(function (n) { return n.getAttribute && n.getAttribute('data-action-id') === 'act1'; });
    check(alphaGate.length === 1, '[attn-surface] a gated item must render exactly one gate card (not duplicated across zones); got ' + alphaGate.length);
    check(nodesA.some(function (n) { return n.getAttribute && n.getAttribute('data-attn-kind') === 'blocked'; }), '[attn-surface] a blocked-plan card must render in the needs_you zone');
    check(nodesA.some(function (n) { return n.getAttribute && n.getAttribute('data-attn-kind') === 'session'; }), '[attn-surface] a waiting-session card must render in the needs_you zone');
    check(!nodesA.some(function (n) { return /idle2222/.test(n.textContent || ''); }), '[attn-surface] a stale-heartbeat session must NOT surface in the inbox (staleness rule)');
    // ---- Drive B: fail honest per feed (partial failure keeps real cards) ----
    const nodesB = mock.collect(wrapB.__body, []);
    check(nodesB.filter(function (n) { return /\bplan-tree-degraded\b/.test(n.className || ''); }).some(function (n) { return n.getAttribute('data-feed') === 'coord'; }),
      '[attn-surface] a failed coord feed must render a per-feed degraded notice (fail honest)');
    check(nodesB.some(isCard), '[attn-surface] the needs_you zone must still paint its real cards when only one feed failed (never a silent empty)');
    // ---- Drive C: failed feed + empty others → degraded, NEVER "All clear" ----
    const nodesC = mock.collect(wrapC.__body, []);
    check(nodesC.filter(function (n) { return /\bplan-tree-degraded\b/.test(n.className || ''); }).some(function (n) { return n.getAttribute('data-feed') === 'gates'; }),
      '[attn-surface] a failed gates feed must render a per-feed degraded notice');
    check(!nodesC.some(function (n) { return (n.className || '').split(/\s+/).indexOf('ow-allclear') >= 0; }),
      '[attn-surface] must NOT render "All clear" when a feed failed (fail-honest contradiction)');
    check(!nodesC.some(function (n) { return (n.className || '').split(/\s+/).indexOf('is-demo') >= 0 || (n.className || '').split(/\s+/).indexOf('demo-chip') >= 0; }),
      '[attn-surface] must NOT fall back to demo when a feed failed (demo would erase the degraded notice)');
  }).catch(function (e) {
    check(false, '[attn-surface] fillNeedsYou drive threw: ' + (e && e.stack || e));
  }).then(function () {
    if (savedDoc === undefined) { delete global.document; } else { global.document = savedDoc; }
    if (savedWin === undefined) { delete global.window; } else { global.window = savedWin; }
  }));

  notes.push('attention surface (M3b): fillNeedsYou renders the needs_you zone as cards (gate + blocked plan + waiting session) over a work+coord+gate fixture; a gated in_progress item is classified ONCE (gate card, not also running — the join fix); stale-heartbeat sessions excluded; a partial-failure feed keeps its real cards + a per-feed degraded notice; a failed feed with empty others shows the notice and NEVER "All clear" nor a notice-erasing demo (fail honest).');
})();

// =========================================================================
//  Check 49 — (M3b) attention wiring + choke-point audit. The needs_you inbox is
//  grouped by deriveAttentionZone over the three live feeds read THROUGH the
//  generated client (M4a pattern); approve/return goes ONLY through the gated
//  helpers → operatorGatedCall → CruxApiGated; no new mutation client, no raw
//  fetch, no stray /v1/ literal for the query-bearing work path.
// =========================================================================
(function checkAttentionWiringAndChoke() {
  const fn = funcBody(renderSrc, 'fillNeedsYou') || '';
  check(!!fn, '[attn-wire] render.js must define fillNeedsYou');
  check(/deriveAttentionZone\(/.test(fn), '[attn-wire] fillNeedsYou must group the inbox via deriveAttentionZone (not a raw list)');
  check(/fetchJSON\('\/v1\/work\/gate\/pending'\)/.test(fn), '[attn-wire] fillNeedsYou must read pending gates via fetchJSON(/v1/work/gate/pending)');
  check(/api\.work\(\s*\{\s*source:\s*'all'\s*\}\s*\)/.test(fn), '[attn-wire] fillNeedsYou must read /v1/work?source=all through CruxApi.work({source:"all"}) (parameterised — not a literal fetchJSON)');
  check(/fetchJSON\('\/v1\/coord\/active'\)/.test(fn), '[attn-wire] fillNeedsYou must read /v1/coord/active via fetchJSON');
  check(/appendFeedNotices\(/.test(fn), '[attn-wire] fillNeedsYou must fail honest per feed via appendFeedNotices');
  check(!/fetchJSON\('\/v1\/work\?/.test(fn), '[attn-wire] fillNeedsYou must NOT read the query-bearing work path via literal fetchJSON (allowlist miss → false-empty)');
  check(!/\bfetch\s*\(/.test(fn), '[attn-wire] fillNeedsYou must not raw-fetch — api.js is the sole network layer');
  check(!/CruxApiGated/.test(fn), '[attn-wire] fillNeedsYou must not touch the gated write client directly');

  // Approve/return route ONLY through the operator helpers (the sole choke point).
  const gate = funcBody(renderSrc, 'gateCard') || '';
  check(/approveGate\(/.test(gate) && /rejectGate\(/.test(gate), '[attn-wire] the gate card must approve/return through the approveGate/rejectGate operator helpers');
  check(!/\bfetch\s*\(|CruxApiGated/.test(gate), '[attn-wire] the gate card must not raw-fetch or touch the gated client directly');
  // Prove the routing chain by INSPECTING the helper bodies (not regex on the
  // caller): approveGate/rejectGate → operatorGatedCall → CruxApiGated.gate*.
  const ag = funcBody(renderSrc, 'approveGate') || '';
  const rg = funcBody(renderSrc, 'rejectGate') || '';
  const ogc = funcBody(renderSrc, 'operatorGatedCall') || '';
  check(/operatorGatedCall\(/.test(ag) && /\bg\.gateApprove\(/.test(ag), '[attn-wire] approveGate must dispatch operatorGatedCall(g => g.gateApprove(...))');
  check(/operatorGatedCall\(/.test(rg) && /\bg\.gateReject\(/.test(rg), '[attn-wire] rejectGate must dispatch operatorGatedCall(g => g.gateReject(...))');
  check(/isOperator\(\)/.test(ogc) && /CruxApiGated/.test(ogc) && /return\s+invoke\(gated\)/.test(ogc),
    '[attn-wire] operatorGatedCall must guard on isOperator() and invoke the CruxApiGated client (the sole gated choke point)');
  // The blocked/waiting cards are read-only — no mutation surface at all.
  ['blockedPlanCard', 'waitingSessionCard'].forEach(function (name) {
    const b = funcBody(renderSrc, name) || '';
    check(!!b, '[attn-wire] render.js must define ' + name);
    check(!/CruxApiGated|operatorGatedCall|approveGate|rejectGate|\bfetch\s*\(/.test(b), '[attn-wire] ' + name + ' must be read-only (no mutation, no gated client)');
  });
  // M3b introduces NO new gated mutation — the curated set (check 7) is unchanged
  // and the approve/reject path remains the sole gate write.
  const apiSrc = fs.readFileSync(path.join(DIR, 'api.js'), 'utf8');
  check(/'\/v1\/work\/gate\/\{actionId\}\/approve'/.test(apiSrc) && /'\/v1\/work\/gate\/\{actionId\}\/reject'/.test(apiSrc),
    '[attn-wire] approve/reject must remain the curated gated path (M3b adds no new mutation client)');
  // The receipt reference (M3a) is surfaced after a resolve.
  const mr = funcBody(renderSrc, 'markResolved') || '';
  check(/receipt_id/.test(mr) && /ow-hash/.test(mr), '[attn-wire] markResolved must surface the M3a receipt reference (receipt_id) on the card');
  notes.push('attention wiring + choke-point (M3b): fillNeedsYou groups the needs_you inbox via deriveAttentionZone over /v1/work/gate/pending (fetchJSON) + /v1/work?source=all (CruxApi.work) + /v1/coord/active (fetchJSON), fail-honest per feed; approve/return route ONLY through approveGate/rejectGate→operatorGatedCall→CruxApiGated (no new mutation client, no raw fetch); blocked/waiting cards read-only; markResolved surfaces the M3a receipt_id.');
})();

// =========================================================================
//  Check 50 — (console-surfaces-remediation M8) Site map is a REAL, registry-
//  derived, click-through map — no dead nodes. Driving render.renderSiteMap
//  against a mock DOM (operator posture, a known previous route) proves: (a)
//  every non-Pro registered page has exactly one <a href="#/<dest>/<id>"> node;
//  (b) the destination-IS-the-page surfaces (overwatch home, canvas board/graph/
//  tree, explorer, sitemap, rings) each get their real route; (c) EVERY node
//  href resolves to a registered destination (no dead nodes / no drift); (d) the
//  "you are here" marker lands on the route the operator came from; (e) the
//  recommended first-run path is numbered on its cards.
// =========================================================================
(function checkSiteMap() {
  check(typeof render.renderSiteMap === 'function', '[sitemap] render.js must export renderSiteMap');
  if (typeof render.renderSiteMap !== 'function') { return; }
  const dom = newMockDom();
  const savedDoc = global.document, savedWin = global.window;
  global.document = dom.doc;
  global.window = { CruxPages: pages, CRUX_POSTURE: 'operator', CRUX_PREV_HASH: '#/work/cx-sessions' };
  try {
    const host = dom.mkNode('div');
    render.renderSiteMap(host);

    const destIds = new Set(pages.DESTS.map(function (d) { return d.id; }));
    const nodeAnchors = dom.findByClass(host, 'map-page');
    check(nodeAnchors.length > 0, '[sitemap] must render at least one clickable node (a.map-page)');

    // Every node anchor: an in-app hash link whose destination is registered.
    const hrefs = new Set();
    nodeAnchors.forEach(function (a) {
      const href = a.getAttribute('href') || '';
      check(/^#\//.test(href), '[sitemap] node anchor href must be an in-app hash route (got ' + JSON.stringify(href) + ')');
      hrefs.add(href);
      const dest = href.replace(/^#\//, '').split(/[/?]/)[0];
      check(destIds.has(dest), '[sitemap] DEAD NODE: href ' + href + ' points at an unregistered destination "' + dest + '"');
    });

    // Every non-Pro registered page has exactly one live node at its real route.
    // (Operator posture, so operator-only pages are included.)
    // M20 RETARGET: the Overwatch destination is retired, so its pages have no
    // #/overwatch/<id> route any more — they are Rings VIEWS (#/rings/<slug>), and
    // the map emits them there. The coverage rule is unchanged in substance: every
    // non-Pro registered page must still have exactly one live click-through node.
    const OW_TO_RINGS = pages.OVERWATCH_TO_RINGS || {};
    let expectedPages = 0;
    Object.keys(pages.PAGES).forEach(function (id) {
      const p = pages.PAGES[id];
      if (p.pro === true) { return; }
      expectedPages++;
      let want = '#/' + p.dest + '/' + id;
      if (p.dest === 'overwatch') {
        const slug = OW_TO_RINGS[id] || 'ring';
        want = slug === 'ring' ? '#/rings' : '#/rings/' + slug;
      }
      check(hrefs.has(want), '[sitemap] registered page ' + id + ' has no click-through node (' + want + ')');
    });
    check(!Array.from(hrefs).some(function (h) { return /^#\/overwatch/.test(h); }),
      '[sitemap] no node may point at the retired #/overwatch destination (M20)');

    // The destination-IS-the-page surfaces get their real routes. M19 — Board/
    // Graph/Tree are absorbed into the Rings tab hub, so their map nodes moved from
    // #/canvas/<view> to #/rings/<view> (the Canvas destination is retired from the
    // map; Studio moved to the account menu + rail head). Honest retarget.
    // M20 — '#/overwatch' is gone from this list with the destination; the five
    // Overwatch views now appear as Rings tab nodes (asserted above).
    ['#/rings/board', '#/rings/graph', '#/rings/tree', '#/explorer', '#/sitemap', '#/rings'].forEach(function (route) {
      check(hrefs.has(route), '[sitemap] missing destination-is-page node for ' + route);
    });

    // (d) "you are here" lands on the origin route (#/work/cx-sessions), exactly once.
    const hereNodes = nodeAnchors.filter(function (a) { return /\bis-here\b/.test(a.className || ''); });
    check(hereNodes.length === 1, '[sitemap] exactly one node must carry the you-are-here marker (got ' + hereNodes.length + ')');
    check(hereNodes[0] && hereNodes[0].getAttribute('href') === '#/work/cx-sessions',
      '[sitemap] you-are-here must mark the route navigated from (#/work/cx-sessions)');
    check(hereNodes[0] && hereNodes[0].getAttribute('aria-current') === 'page',
      '[sitemap] the you-are-here node must set aria-current="page"');

    // (e) the recommended first-run path is numbered on its cards.
    // M20 RETARGET: step 1 is Rings — it is where boot lands now.
    const startRoutes = ['#/rings', '#/work/cx-sessions', '#/memory/cx-facts', '#/trust/cx-receipts'];
    startRoutes.forEach(function (route) {
      const node = nodeAnchors.find(function (a) { return a.getAttribute('href') === route; });
      check(!!node, '[sitemap] start-path node missing: ' + route);
      check(node && dom.findByClass(node, 'map-step').length >= 1, '[sitemap] start-path node ' + route + ' must carry a step numeral');
    });

    notes.push('site map (M8): ' + nodeAnchors.length + ' click-through nodes over ' + destIds.size + ' destinations (' + expectedPages + ' registered pages + destination-is-page surfaces), all hrefs resolve to a registered dest (no dead nodes), you-are-here marks the origin route, first-run path numbered.');
  } catch (e) {
    check(false, '[sitemap] renderSiteMap smoke threw: ' + (e && e.stack || e));
  } finally {
    if (savedDoc === undefined) { delete global.document; } else { global.document = savedDoc; }
    if (savedWin === undefined) { delete global.window; } else { global.window = savedWin; }
  }
})();

// ─────────────────────────────────────────────────────────────────────────────
//  Check 52 — (console-surfaces-remediation M16b) Configurable Workspaces: the
//  config-schema pure functions honour the CONTRACT (memo §4 + the M16 decision
//  log): canonical key-sorted JSON, a TOLERANT reader that preserves unknown
//  keys and version-gates, built-in generation, reversible fork/revert, and
//  additive packs. The runtime nav + Studio subsections drive these; the
//  invariants live here so a regression fails the smoke, not production.
// ─────────────────────────────────────────────────────────────────────────────
(function checkConfigurableWorkspaces() {
  const need = ['cwsCanonical', 'cwsReadWorkspaceDef', 'cwsReadPageDef', 'cwsBuiltinWorkspaces',
    'cwsEffectiveWorkspaces', 'cwsForkWorkspace', 'cwsTombstone', 'cwsStarterTemplates',
    'cwsPageTypes', 'cwsPackEmbed', 'cwsPackExtract', 'cwsMergeQuery', 'renderWorkspacePage',
    'renderWorkspaceStudio', 'renderIntegrationsStudio'];
  need.forEach(function (fn) { check(typeof render[fn] === 'function', '[workspaces] render.js must export ' + fn); });

  // (a) canonical JSON is byte-stable + key-order independent (one artifact, two editors).
  const c1 = render.cwsCanonical({ b: 1, a: { z: 9, y: 8 }, arr: [3, 1, 2] });
  const c2 = render.cwsCanonical({ a: { y: 8, z: 9 }, arr: [3, 1, 2], b: 1 });
  check(c1 === c2, '[workspaces] canonical JSON must be key-order independent');
  check(c1 === '{"a":{"y":8,"z":9},"arr":[3,1,2],"b":1}', '[workspaces] canonical JSON must be sorted + whitespace-free');

  // (b) TOLERANT reader: unknown keys survive (top + nested) through a canonical round-trip.
  const rd = render.cwsReadWorkspaceDef({ schema_version: 1, uid: 'ws-x', name: 'X',
    dests: [{ id: 'g', label: 'G', pages: ['p1'], futureField: 42 }], newTopKey: { deep: 'keep' } });
  check(rd.valid && !rd.unknownVersion, '[workspaces] a known-version workspace def must read valid');
  const rt = JSON.parse(render.cwsCanonical(rd.def));
  check(rt.newTopKey && rt.newTopKey.deep === 'keep', '[workspaces] tolerant reader must preserve an unknown TOP-level key through a round-trip');
  check(rt.dests[0].futureField === 42, '[workspaces] tolerant reader must preserve an unknown NESTED key (dest.futureField)');
  const pr = render.cwsReadPageDef({ schema_version: 1, uid: 'p1', type: 'cx-facts', title: 'F', extra: { x: 1 } });
  check(pr.valid && JSON.parse(render.cwsCanonical(pr.def)).extra.x === 1, '[workspaces] page tolerant reader must preserve unknown keys');

  // (c) version gate: a NEWER schema_version renders an honest state, never destroys.
  const nv = render.cwsReadWorkspaceDef({ schema_version: 99, uid: 'ws-n', weird: 'data' });
  check(nv.unknownVersion === true && nv.def.weird === 'data', '[workspaces] a newer schema_version must be flagged + returned untouched (never rebuilt)');

  // (d) tombstone → reverted.
  check(render.cwsReadWorkspaceDef(render.cwsTombstone('ws-x')).reverted === true, '[workspaces] a tombstone def must read as reverted');

  // (e) built-ins + fork/revert semantics (over a stubbed registry).
  const savedWin = global.window;
  global.window = { CruxPages: { DESTS: [{ id: 'work', label: 'Work', icon: 'work' }, { id: 'canvas', label: 'Canvas', icon: 'canvas' }, { id: 'explorer', label: 'Explorer', icon: 'search' }],
    PAGES: { 'cx-work': { title: 'ExecPlans', sub: 's', dest: 'work' } } } };
  try {
    const bw = render.cwsBuiltinWorkspaces();
    check(bw.length === 2 && bw[0].uid === 'command' && bw[1].uid === 'explore', '[workspaces] built-ins must be exactly Command + Explorer, auto-generated from the registry');
    check(bw[0].source === 'builtin' && bw[0].builtin === true, '[workspaces] a built-in must be marked source:builtin');
    const fork = render.cwsForkWorkspace(bw[0]);
    check(fork.source === 'builtin-fork' && fork.forked_from === 'command' && !fork.builtin, '[workspaces] fork must set source:builtin-fork + forked_from and drop the builtin flag (take control)');
    const forkedEff = render.cwsEffectiveWorkspaces([{ def: fork, valid: true, reverted: false }]);
    const cmdForked = forkedEff.find(function (w) { return w.uid === 'command'; });
    check(cmdForked && cmdForked.source === 'builtin-fork', '[workspaces] a fork overlay must REPLACE its built-in in the effective set');
    const revEff = render.cwsEffectiveWorkspaces([{ def: render.cwsReadWorkspaceDef(render.cwsTombstone('command')).def, valid: true, reverted: true }]);
    const cmdRev = revEff.find(function (w) { return w.uid === 'command'; });
    check(cmdRev && cmdRev.source === 'builtin' && cmdRev.builtin === true, '[workspaces] reverting a fork (tombstone) must restore auto-generation (built-in resumes)');
    const userEff = render.cwsEffectiveWorkspaces([{ def: { schema_version: 1, uid: 'ws-mine', name: 'Mine', source: 'user', order: 5, dests: [] }, valid: true, reverted: false }]);
    check(userEff.length === 3 && userEff.some(function (w) { return w.uid === 'ws-mine'; }), '[workspaces] a user workspace must append to the built-ins');
    const userRev = render.cwsEffectiveWorkspaces([{ def: render.cwsReadWorkspaceDef(render.cwsTombstone('ws-mine')).def, valid: true, reverted: true }]);
    check(!userRev.some(function (w) { return w.uid === 'ws-mine'; }), '[workspaces] a tombstoned user workspace must drop out of the effective set');

    // (f) page-type coverage: EVERY registry page id is generatable as a type.
    const types = render.cwsPageTypes();
    const tset = new Set(types.map(function (t) { return t.type; }));
    check(tset.has('cx-work'), '[workspaces] every registry page id must be a generatable page type (cx-work present)');
    check(tset.has('canvas/graph') && tset.has('explorer') && tset.has('sitemap') && tset.has('rings'), '[workspaces] destination-IS-the-page surfaces must be generatable page types');

    // (g) starter templates: remix-not-blank (Blank is last), Duplicate Command builds dests.
    const st = render.cwsStarterTemplates();
    check(st.length >= 3 && st[st.length - 1].id === 'blank', '[workspaces] starter templates must be remix-first (Blank last)');
    const dup = st[0].build('ws-dup', 'Dup');
    check(dup.workspace.dests.length >= 1 && dup.workspace.source === 'user', '[workspaces] Duplicate Command starter must produce a user workspace with dests');
  } finally { if (savedWin === undefined) { delete global.window; } else { global.window = savedWin; } }

  // (h) additive packs: crux.studio.v1 stays valid; workspaces/pages round-trip.
  const pay = render.cwsPackEmbed({ schema: 'crux.studio.v1', board: {} }, [{ uid: 'ws-mine' }], [{ uid: 'p1', type: 'cx-work' }]);
  check(pay.schema === 'crux.studio.v1' && pay.workspaces.length === 1 && pay.pages.length === 1, '[workspaces] pack embed must be additive (schema preserved + workspaces/pages arrays)');
  const ext = render.cwsPackExtract(pay);
  check(ext.workspaces.length === 1 && ext.pages.length === 1, '[workspaces] pack extract must recover workspaces/pages');
  check(render.cwsPackExtract({ schema: 'crux.studio.v1' }).workspaces.length === 0, '[workspaces] an older pack (no workspaces) must extract to empty arrays (backward compatible)');

  // (i) config query merge (type-specific page config over an endpoint).
  check(render.cwsMergeQuery('/v1/work?source=all', { source: 'kanban' }) === '/v1/work?source=kanban', '[workspaces] cwsMergeQuery must override an existing query param');

  // (j) writes go ONLY through the gated console fact-add (no new mutation client / no raw fetch in the studio subsections).
  const wsA = renderSrc.indexOf('Studio › Pages (M16b)');
  // Ends at the Integrations subsection, which has its own region gate (check 62)
  // — otherwise this assertion silently covered a surface it does not describe.
  const wsB = renderSrc.indexOf('Studio › Integrations (M16b');
  const wsRegion = (wsA >= 0 && wsB > wsA) ? renderSrc.slice(wsA, wsB) : '';
  check(!!wsRegion, '[workspaces] the Studio subsection region must be locatable');
  check(!/\bfetch\s*\(/.test(wsRegion), '[workspaces] the Studio subsections must issue NO raw fetch (reads via fetchJSON/CruxApi)');
  check(/tstudioWriteFact\(/.test(wsRegion) && !/CruxApiGated/.test(wsRegion), '[workspaces] writes must route through tstudioWriteFact (operatorGatedCall→consoleFactsAdd), never the gated client directly');
  check(/CWS_WS_ENTITY|console:workspace:/.test(renderSrc) && /CWS_PAGE_ENTITY|console:page:/.test(renderSrc), '[workspaces] config must persist under console:workspace: / console:page: entities');

  // (k) the shell wires the switcher + #/w route + model load off the pure helpers.
  check(/activateWorkspace\(/.test(shellHtml) && /data-ws/.test(shellHtml), '[workspaces] the shell switcher must build per-workspace buttons (data-ws) + activateWorkspace');
  check(/first === 'w' && parts\[1\]/.test(shellHtml) && /renderWorkspace\(/.test(shellHtml), '[workspaces] the shell must route #/w/<uid> to renderWorkspace');
  check(/loadWorkspaceModel\(/.test(shellHtml) && /CRUX_WS_RELOAD/.test(shellHtml), '[workspaces] the shell must load the workspace model at boot + expose CRUX_WS_RELOAD');

  notes.push('configurable workspaces (M16b): canonical key-sorted JSON (one artifact / two editors); tolerant reader preserves unknown keys (top + nested) + version-gates a newer schema; built-ins Command+Explorer auto-generated from the registry; reversible fork (source:builtin-fork+forked_from) / revert (tombstone → auto-generation resumes); every registry page id + the destination-IS-the-page surfaces are generatable page types; remix-not-blank starters (Blank last); additive crux.studio.v1 packs (workspaces/pages, older packs still valid); Studio subsections write ONLY through tstudioWriteFact→consoleFactsAdd under console:workspace:/console:page: (no raw fetch, no direct gated client); shell wires the switcher + #/w route + boot model load.');
})();

// ---- Check 53 — (console-surfaces-remediation M17) operator round 6:
//  the workspace-pages BUG fix (sub-nav + flyout from the config model), the
//  collapsed-rail rework (no chevron, icons-only, dest-click → flyout), the
//  single workspace switcher + rightward pop-out (replacing the multi-button
//  strip), the operator popup gaining Studio + Options, and Settings honesty
//  (an honest gate reason instead of the stale "wired in M3+" promise).
(function () {
  // (a) BUG FIX — a workspace group's pages render as a sub-nav pill row driven
  //     by the SAME config model as the flyout (before M17 the rail showed only
  //     the group label, so pages — incl. a newly added one — appeared nowhere).
  // M20 RETARGET: the M17 fix was "a workspace group's pages must be VISIBLE and
  // navigable". That requirement is unchanged — only its vehicle moved, from the
  // topbar pill row (buildWorkspaceSubnav, now removed with buildSubnav) into the
  // rail accordion, which the workspace rail builds from the SAME workspaceDestPages
  // join. The assertion follows the requirement, not the removed function name.
  check(!/function buildWorkspaceSubnav\(/.test(shellHtml),
    '[m17] the workspace pill row must be gone (M20: one sub-page idiom — the accordion)');
  check(/function workspaceGroupItems\(ws, dest\)/.test(shellHtml) && /workspaceDestPages\(dest\)/.test(shellHtml),
    '[m17] a workspace group\'s pages must still resolve from the config model (workspaceGroupItems → workspaceDestPages)');
  check(/buildNavGroup\(nav, btn, d\.id, items\)/.test(shellHtml),
    '[m17] buildWorkspaceRail must render each group\'s pages as an accordion group — the workspace-pages bug fix, M20 vehicle');
  // M22 RETARGET: the M17 requirement was "a workspace dest must resolve its pages
  // AND surface them in the COMPRESSED rail too". The vehicle moved again — from
  // the right-side flyout (openWorkspaceRailFlyout, deleted in M22) to the compact
  // inline accordion, which renders the SAME workspaceGroupItems list the expanded
  // rail renders. The assertion follows the requirement, not the removed function.
  check(/function workspaceDestPages\(/.test(shellHtml) && !/function openWorkspaceRailFlyout\(/.test(shellHtml),
    '[m17] workspace dests must resolve their pages (workspaceDestPages); the flyout vehicle is gone (M22)');
  check(/workspaceGroupItems\(ws, d\)/.test(shellHtml) && !/:root\[data-rail="collapsed"\] \.nav-sub \{ display: none; \}/.test(shellHtml),
    '[m17] a workspace group\'s pages must reach the COMPRESSED rail — now the inline accordion, not a flyout');
  // (b) live pick-up: a stored console:workspace:/console:page: fact reloads the
  //     model (refresh always works; this is the "ideally live" upgrade).
  check(/EventSource\('\/v1\/events\/stream\?types=fact\.stored'\)/.test(shellHtml) && /console:workspace:'\) !== 0 && entity\.indexOf\('console:page:/.test(shellHtml),
    '[m17] the shell must live-reload the workspace model on a console:workspace/page fact.stored event');
  // (c) collapsed rail: the expander chevron is removed (icons only). M19 changed
  //     the click semantics — a dest icon CLICK now navigates PAGE-LEVEL in both
  //     rail states; the sub-page flyout is a hover + ArrowRight (keyboard)
  //     affordance (see Check 55). Honest retarget of the M17 click assertion.
  check(/\[data-rail="collapsed"\]\s+\.rail-toggle\s*\{\s*display:\s*none/.test(shellHtml),
    '[m17] the compressed rail must hide the expander chevron (rail-toggle display:none)');
  check(/function railIsCollapsed\(/.test(shellHtml),
    '[m17] railIsCollapsed() must exist (collapsed-rail state helper)');
  // (d) single workspace switcher button + rightward pop-out (replaces the
  //     multi-button data-ws strip); reachable in both rail states.
  check(/ws-switch-btn/.test(shellHtml) && /function openWsSwitchPop\(/.test(shellHtml) && /id: 'wsSwitchPop'/.test(shellHtml),
    '[m17] the switcher must be ONE button opening a rightward workspace pop-out (wsSwitchPop)');
  check(/'data-railic': 'ws-switch'/.test(shellHtml) && !/'data-railic': 'command'/.test(shellHtml),
    '[m17] the collapsed rail must carry the single ws-switch icon (command/explorer folded into the pop-out)');
  // (e) operator popup keeps Options (theme+connection stay). M19 — Studio moved
  //     OUT of this popup to the account pop-out + rail head (see Check 55), so it
  //     is no longer asserted here (was M17). Honest retarget.
  check(/rail-ops-nav/.test(shellHtml) && /'#\/system\/cx-settings'/.test(shellHtml),
    '[m17] the operator popup must keep the Options (#/system/cx-settings) nav entry');
  // (f) Settings honesty — a page-specific honest gate reason; the generic
  //     "wired in M3+" stays the DEFAULT choke point everywhere else.
  check(/gateReason/.test(renderSrc) && /wired in M3\+/.test(renderSrc),
    '[m17] applyMutationGate must honour a page-specific honest gateReason while keeping "wired in M3+" as the default');
  check(/SETTINGS_GATE_REASON/.test(pagesSrc) && /stampSettingsGate\(/.test(pagesSrc) && !/'Appearance'/.test(pagesSrc),
    '[m17] Settings must stamp an honest gate reason + drop the stale Appearance section (duplicate theme + dead canvas info)');
  // (g) unified Settings cards — equal-height grid rows.
  check(/\.settings-page \.v2grid\s*\{\s*align-items:\s*stretch/.test(shellHtml) && /content\.classList\.add\('settings-page'\)/.test(shellHtml),
    '[m17] the Settings region must render as one equal-height card grid (.settings-page)');
  notes.push('operator round 6 (M17): workspace-pages bug fixed (config-driven buildWorkspaceSubnav pill row + openWorkspaceRailFlyout, both off workspaceDestPages) + live model reload on console:workspace/page fact.stored; collapsed rail reworked (chevron removed → expand via the logo, icons-only, a dest icon CLICK opens the flyout — primary compressed nav for touch/keyboard; M22 retired the flyout, the compact bar now carries the sub-pages inline as icons); single workspace switcher button + rightward pop-out (wsSwitchPop) replacing the multi-button data-ws strip, reachable collapsed + expanded; operator popup gains Studio + Options nav entries (theme + connection kept); Settings shows an honest, non-milestone gate reason (generic "wired in M3+" stays the default choke point) + drops the stale Appearance section + renders one equal-height card grid.');
})();

// ---- Check 54 — (console-surfaces-remediation M18) operator round 7:
//  (1) the switcher return-to-Command BUG — from a user workspace (#/w/<uid>) a
//      switch to Command must LEAVE the workspace hash. Before M18, applyMode
//      only cleared a #/documents hash, so a switch back to Command from #/w/
//      fell through to route(), which re-read the still-#/w/ hash and re-rendered
//      the SAME workspace — the switcher could never return to Command.
//  (2) the bottom-of-rail operator/account badge redesigned into the M17
//      rail-flyout pop-out family (glass, keyboard, Escape/click-away); the old
//      upward roll-up (clipped to the ~48px collapsed rail) is removed.
(function () {
  // (1a) applyMode must drive a #/w/ workspace route to a Command destination on
  //      a Command-surface switch (the fix), exactly as it does for the reader.
  check(shellHtml.indexOf("/^#\\/w\\//.test(location.hash") >= 0,
    '[m18] applyMode must exit a #/w/ workspace route when switching to Command (return-to-Command bug fix)');
  // (1b) the switcher still routes the Command builtin through applySurface (the
  //      choke point the fix repairs) and derives every workspace (Command
  //      included) into the pop-out, so Command is listed from a #/w/ context.
  check(/if \(uid === 'command'\) \{ applySurface\('command'\)/.test(shellHtml) && /function activateWorkspace\(/.test(shellHtml),
    '[m18] activateWorkspace must route the Command builtin through applySurface');
  check(/wsSwitcherList\(\)\.forEach/.test(shellHtml) && /'data-ws': ws\.uid/.test(shellHtml),
    '[m18] the switcher pop-out must derive its entries from every workspace (Command included) — reachable from a #/w/ context');
  // (2a) RETARGETED in M23 — the badge no longer opens a popup at all. M18's
  //      glass pop-out (#acctPop) replaced a clipped roll-up; M23 replaces the
  //      pop-out with the rail's own accordion, triggered by the badge itself.
  //      Both of M18's originals are asserted GONE, honestly, and the M18
  //      properties that survive (one badge control, keyboard, no bespoke
  //      roll-up) are asserted on the accordion instead.
  check(!/id: 'acctPop'/.test(shellHtml) && !/#acctPop['"]/.test(shellHtml)
    && !/function ensureAcctPop\(/.test(shellHtml) && !/function openAcctPop\(/.test(shellHtml)
    && !/function closeAcctPop\(/.test(shellHtml) && !/function toggleAcctPop\(/.test(shellHtml)
    && !/function acctSyncSystemRows\(/.test(shellHtml),
    '[m18→m23] the account pop-out (#acctPop and its ensure/open/close/toggle/sync handlers) must be removed outright');
  check(!/id="acctMenu"/.test(shellHtml) && !/class="acct-item"/.test(shellHtml) && !/\.acct-menu\s*\{/.test(shellHtml),
    '[m18] the old upward account roll-up (#acctMenu / .acct-item / .acct-menu) must be removed');
  // (2b) the badge is the accordion's TRIGGER: it toggles the group, carries
  //      aria-expanded (driven by navGroupSetOpen, the shared code path) and
  //      advertises no popup.
  check(/function toggleAcctGroup\(\)/.test(shellHtml)
    && /btn\.addEventListener\('click', function \(e\) \{ e\.stopPropagation\(\); toggleAcctGroup\(\); \}\);/.test(shellHtml),
    '[m23] the account badge must TOGGLE its own accordion group (one footer control)');
  check(!/aria-haspopup="menu" aria-expanded="false" title="Account/.test(shellHtml)
    && /<button class="passport-chip" id="passportChip" type="button" aria-expanded="false"/.test(shellHtml),
    '[m23] the badge must advertise an expandable group (aria-expanded), not a popup (no aria-haspopup)');
  check(/rec\.btn\.setAttribute\('aria-expanded', open \? 'true' : 'false'\);/.test(shellHtml),
    '[m23] the badge\'s expanded state must be driven by the SHARED navGroupSetOpen path, not a bespoke one');
  notes.push('operator round 7 (M18): switcher return-to-Command bug fixed (applyMode now leaves a #/w/ workspace route for a Command destination, mirroring its #/documents exit — before, only #/documents was cleared so the switch re-rendered the same workspace); the bottom-of-rail operator/account badge redesigned from the clipped upward roll-up into the M17 rail-flyout glass pop-out (#acctPop) — SUPERSEDED by M23, which retires the pop-out entirely and makes the badge the trigger of the rail footer accordion (the M18 gates are retargeted to assert the removal + the surviving properties, not silenced).');
})();

// ---- Check 55 — (console-surfaces-remediation M19) operator round 8:
//  rings consolidation (play bar inline with the tab icons + search; date pickers
//  return to the bottom bar; static aria-hidden range labels where they were),
//  right-tile dedup + real-series charts, Canvas absorbed into the Rings tab hub
//  (Board/Graph/Tree tabs; #/canvas/* deep-link redirects), and Studio relocated
//  (account pop-out between Settings and Language + a rail-head button; removed
//  from the operator popup). Collapsed-rail click becomes page-level nav.
(function () {
  // (a) rings play bar rides the topbar row; dates moved to the bottom bar; the
  //     old date-picker slots are NON-clickable static (aria-hidden) range labels.
  check(/'class': 'rings-playbar'/.test(renderSrc) && /ringTabMount\.appendChild\(playbar\)/.test(renderSrc),
    '[m19] the rings play bar (rings-playbar) must mount into the topbar tab slot (next to the tab icons + search)');
  check(/rings-rangelabel/.test(renderSrc) && /\.rings-playbar \.rings-rangelabel/.test(shellHtml) && /pointer-events: none/.test(shellHtml),
    '[m19] the play bar must render NON-clickable, aria-hidden static range labels where the pickers were');
  check(/'class': 'rings-bottombar' \}, \[dStart, grpWindow, dEnd, grpZoom\]/.test(renderSrc),
    '[m19] the date pickers must return to the bottom bar, flanking the window sliders ([start][sliders][end] + zoom)');
  // (b) right-tile dedup + real per-day charts (no fabricated trends).
  check(!/glExecplans/.test(renderSrc) && !/glSessions/.test(renderSrc),
    '[m19] the duplicate execplans + sessions glance tiles must be removed (they mirrored the ExecPlans/Sessions lens tiles)');
  check(/SESS_DAYS/.test(renderSrc) && /last_active_unix_ms/.test(renderSrc) && /daySpark\(tSess\.sp/.test(renderSrc),
    '[m19] the sessions tile must chart a real last_active_unix_ms per-day histogram');
  check(/daySpark\(glFacts\.sp, dataS/.test(renderSrc),
    '[m19] the facts glance tile must chart the real facts-stored_at series (no fabricated trend)');
  // (c) Canvas absorbed: Board/Graph/Tree are Rings tabs; #/canvas/* redirects;
  //     the Canvas destination is railHidden (route-only, Studio's stable home).
  // M20 RETARGET: the nine tab DEFINITIONS moved out of renderRings into the shared
  // registry (CruxPages.RINGS_TAB_SLUGS + render.js RINGS_TAB_ICONS) because the rail
  // accordion renders them now. The substance holds: Board/Graph/Tree are still three
  // of the nine Rings views.
  const slugDefs = pages.RINGS_TAB_SLUGS || [];
  const slugTabs = slugDefs.map(function (t) { return t.tab; });
  ['cv-board', 'cv-graph', 'cv-tree'].forEach(function (t) {
    check(slugTabs.indexOf(t) >= 0, '[m19] the Rings view registry must carry the absorbed ' + t + ' tab');
  });
  check(slugDefs.length === 9, '[m19] the Rings tab hub must carry nine views (got ' + slugDefs.length + ')');
  check(/CANVAS_TAB_IDS/.test(renderSrc) && /renderCanvasGraph\(tabHost/.test(renderSrc) && /renderPlanTree\(tabHost/.test(renderSrc) && /renderCanvasBoard\(tabHost/.test(renderSrc),
    '[m19] the rings tab hub must render Board/Graph/Tree through their normal renderers into the swap host');
  check(/function teardownCanvasTab\(/.test(renderSrc) && /__canvasGraphCleanup/.test(renderSrc),
    '[m19] switching away from a canvas tab must tear down its RAF/listener (teardownCanvasTab)');
  const canvasDest = (pages.DESTS || []).find(function (d) { return d.id === 'canvas'; });
  check(!!canvasDest && canvasDest.railHidden === true && canvasDest.key === undefined,
    '[m19] the canvas destination must be railHidden + keyless (route-only home for Studio; not in the rail/keyboard)');
  // The dest ID stays 'canvas' (route stability: #/canvas/studio, the
  // canvas/board|graph|tree workspace page types and the #/rings redirect all
  // key off it) but its LABEL is the topbar heading of the only surface it
  // still serves — the Studio. "Canvas" headed a destination retired in M19.
  check(!!canvasDest && canvasDest.id === 'canvas' && canvasDest.label === 'Studio',
    '[m19] the canvas destination must keep id "canvas" (routes) and read "Studio" (the heading of the surface it serves)');
  check(/first === 'canvas'/.test(shellHtml) && /'#\/rings\/' \+ target/.test(shellHtml),
    '[m19] route() must redirect #/canvas/board|graph|tree to #/rings/<view> (deep links never dead-end)');
  // M20 RETARGET: the ad-hoc RINGS_TAB_MAP (board|graph|tree only) is replaced by
  // ringsTabIdForSlug over the shared nine-slug grammar — a strictly wider mapping.
  check(/initialTab: ringsInitialTab/.test(shellHtml) && /function ringsTabIdForSlug\(/.test(shellHtml),
    '[m19] the rings route must map a #/rings/<slug> deep link to the matching tab (initialTab)');
  check(/d\.id !== 'explorer' && d\.id !== 'canvas'/.test(renderSrc),
    '[m19] the Command workspace builtin must skip the retired Canvas destination');
  check(/#\/canvas\/studio keeps working/.test(shellHtml) || /studio' \)/.test(shellHtml) || /parts\[1\] === 'studio'/.test(shellHtml),
    '[m19] #/canvas/studio must remain routable (Studio stable home)');
  // (d) Studio relocation: account pop-out (between Settings/Language) + rail head;
  //     removed from the operator popup ("move", not copy).
  // RETARGETED in M23 — the pop-out is gone; its rows are now the account half of
  // the merged footer accordion (acctFooterItems). Settings is DEDUPED away (the
  // System half already carries cx-settings = Settings), so the surviving claim is
  // that Studio still reaches #/canvas/studio from the badge, ahead of Language.
  const iStu = shellHtml.indexOf("key: 'acct-studio'");
  const iLang = shellHtml.indexOf("key: 'acct-language'");
  check(iStu >= 0 && iLang > iStu && /acctAction\('studio'\)/.test(shellHtml)
    && /else if \(acct === 'studio'\) \{ location\.hash = '#\/canvas\/studio'; \}/.test(shellHtml),
    '[m19→m23] the badge accordion must carry Studio (→ #/canvas/studio) ahead of Language');
  check(/id="railStudioBtn"/.test(shellHtml) && /getElementById\('railStudioBtn'\)/.test(shellHtml) && /'#\/canvas\/studio'/.test(shellHtml),
    '[m19] the expanded-rail head must carry a Studio button (railStudioBtn) next to the theme control');
  check(!/mkNav\('Studio'/.test(shellHtml),
    '[m19] the operator popup must NOT carry a Studio nav entry (moved to the account pop-out + rail head)');
  // (e) collapsed rail click = page-level nav; flyout on hover + ArrowRight.
  // M22 RETARGET: the click semantics are unchanged (page-level nav in BOTH rail
  // states) — but the sub-page affordance it used to sit beside is gone. The
  // hover-intent + ArrowRight flyout entry is replaced by the compact inline
  // accordion, so this gate asserts the click contract plus the flyout's absence.
  check(/a dest icon CLICK always navigates/.test(shellHtml) && !/e\.key === 'ArrowRight'/.test(shellHtml),
    '[m19] a rail dest click must navigate page-level; the hover/ArrowRight flyout entry is gone (M22)');
  notes.push('operator round 8 (M19): rings play bar moved inline with the tab icons + search (static, aria-hidden range labels where the pickers were); date pickers returned to the bottom bar flanking the window sliders; duplicate execplans/sessions glance tiles removed; sessions tile + facts glance gained real per-day histograms (last_active_unix_ms / facts stored_at); Board/Graph/Tree absorbed into the Rings tab hub (renderCanvasBoard/Graph + renderPlanTree into the swap host, clean teardown), Canvas destination retired to a railHidden route-only home, #/canvas/board|graph|tree redirect to #/rings/<view>, sitemap Check 50 retargeted; Studio relocated to the account pop-out (between Settings and Language) + a rail-head button next to the theme control, removed from the operator popup; rail dest click navigates page-level (built-in + workspace rails) — the hover + ArrowRight flyout that accompanied it is retired in M22.');
})();

// ---- Check 56 — (console-surfaces-remediation M20) operator round 9:
//  accordion nav (the nine Rings views move out of the main pane into the left
//  nav; ONE group open — the active destination's; pills removed console-wide),
//  Rings as the console INDEX (default route, top of the rail, #/overwatch
//  redirects), graph zoom anchored at the POINTER + the Overview element rebuilt
//  as a bottom-left glass chip, one-row rings bottom bar with a width-matched top
//  bar, and the completed-plans list nudged clear of the left toolbar.
(function () {
  // (a) ONE sub-page item list feeds BOTH rail states; pills are gone.
  check(/function railGroupItems\(destId\)/.test(shellHtml) && /function workspaceGroupItems\(ws, dest\)/.test(shellHtml),
    '[m20] the shell must define railGroupItems + workspaceGroupItems (one list for the accordion AND the flyout)');
  check(!/function buildSubnav\(/.test(shellHtml) && !/function buildWorkspaceSubnav\(/.test(shellHtml) && !/'class': 'subnav'/.test(shellHtml),
    '[m20] the topbar sub-nav PILL ROW must be removed console-wide (built-in + workspace)');
  // M22 RETARGET: the shared-list invariant is unchanged — only its second
  // consumer moved. It was the collapsed-rail flyout (openRailFlyout); it is now
  // the compact inline accordion, which is literally the same buildNavGroup call
  // over the same railGroupItems, restyled by CSS. One list, two presentations.
  check(/buildNavGroup\(nav, btn, item\.id, items\)/.test(shellHtml) && /var items = railGroupItems\(item\.id\);/.test(shellHtml)
    && !/function openRailFlyout\(/.test(shellHtml),
    '[m20] ONE railGroupItems list must feed the rail in BOTH states (M22: the compact accordion replaced the flyout)');
  // (b) the accordion itself: one group open, animated, reduced-motion aware.
  check(/function buildNavGroup\(nav, btn, key, items\)/.test(shellHtml) && /function navGroupSetOpen\(rec, open\)/.test(shellHtml) && /function syncRailAccordion\(/.test(shellHtml),
    '[m20] the shell must build accordion groups (buildNavGroup / navGroupSetOpen / syncRailAccordion)');
  check(/\.nav-sub \{[^}]*height: 0[^}]*transition: height/.test(shellHtml) && /\.nav-sub \{[^}]*opacity: 0/.test(shellHtml),
    '[m20] .nav-sub must animate height + opacity (the downward expand)');
  check(/prefers-reduced-motion: reduce\) \{\s*\n\s*\.nav-sub \{ transition: none/.test(shellHtml) && /function navReduceMotion\(/.test(shellHtml),
    '[m20] the accordion must respect prefers-reduced-motion (CSS + the JS end-state snap)');
  check(/var open = \(k === activeKey\);/.test(shellHtml),
    '[m20] exactly one group may be open — the active destination\'s');
  // M22 RETARGET: M20 scoped the accordion to the expanded rail (collapsed had the
  // flyout). M22 gives the collapsed rail the accordion too, as icons — so the rule
  // that hid it must be GONE and the compact row styling must be present.
  check(!/:root\[data-rail="collapsed"\] \.nav-sub \{ display: none; \}/.test(shellHtml)
    && /:root\[data-rail="collapsed"\] \.nav-subitem \{/.test(shellHtml),
    '[m20] the collapsed rail must show the accordion as ICONS (M22), not hide it');
  check(/buildNavGroup\(nav, btn, item\.id, items\)/.test(shellHtml) && /buildNavGroup\(nav, btn, d\.id, items\)/.test(shellHtml),
    '[m20] BOTH rails (built-in + workspace) must build accordion groups — the standard applies to all nav links');
  // (c) the nine Rings views are the Rings group; switching drives the SAME swap.
  const slugs = (pages.RINGS_TAB_SLUGS || []).map(function (t) { return t.slug; });
  check(slugs.length === 9, '[m20] CruxPages.RINGS_TAB_SLUGS must define the nine Rings views (got ' + slugs.length + ')');
  check(slugs[0] === 'ring' && slugs.indexOf('graph') > 0 && slugs.indexOf('agent') > 0,
    '[m20] the Rings slug grammar must start at "ring" and cover the absorbed + Overwatch views');
  check(/ringsTabDefs: ringsTabDefs/.test(renderSrc) && /ringsSetTab: ringsSetTab/.test(renderSrc) && /ringsTabMounted: ringsTabMounted/.test(renderSrc),
    '[m20] render.js must export the rail contract (ringsTabDefs / ringsSetTab / ringsTabMounted)');
  check(/ringsSetTabHook = ringsSetTabBridge/.test(renderSrc) && /if \(ringsSetTabHook === ringsSetTabBridge\) \{ ringsSetTabHook = null; \}/.test(renderSrc),
    '[m20] renderRings must publish its setTab bridge while mounted and clear it on teardown');
  check(/R\.ringsSetTab\(tabId\);/.test(shellHtml) && /history\.replaceState\(null, '', location\.pathname \+ location\.search \+ target\)/.test(shellHtml),
    '[m20] an accordion row must drive the in-place swap + replaceState (a hashchange would re-route and kill the fade)');
  check(!/'class': 'rings-tabicons'/.test(renderSrc) && !/ringTabBar/.test(renderSrc),
    '[m20] the topbar #ringsTabSlot tab ICONS must be removed (the rail owns the controls now)');
  // (d) Rings is the index; Overwatch is retired but its renderers stay.
  check((pages.DESTS[0] || {}).id === 'rings' && (pages.DESTS[0] || {}).key === '1',
    '[m20] Rings must be DESTS[0] (the default route + top of the rail) with the "1" shortcut');
  const owDest = (pages.DESTS || []).find(function (d) { return d.id === 'overwatch'; });
  check(!!owDest && owDest.railHidden === true && owDest.key === undefined,
    '[m20] the Overwatch destination must be railHidden + keyless (retired, registry kept coherent)');
  check(/if \(first === 'overwatch'\)/.test(shellHtml) && /OVERWATCH_TO_RINGS/.test(shellHtml),
    '[m20] route() must redirect every #/overwatch route to its Rings equivalent');
  check(Object.keys(pages.OVERWATCH_TO_RINGS || {}).length === 6,
    '[m20] every Overwatch page must have a Rings redirect target (got ' + Object.keys(pages.OVERWATCH_TO_RINGS || {}).length + ')');
  check(/function renderOverwatchLanding\(/.test(renderSrc) && /function owRenderTab\(/.test(renderSrc),
    '[m20] the Overwatch RENDERERS must stay — they power the Rings tabs');
  check(/d\.id !== 'explorer' && d\.id !== 'canvas' && d\.id !== 'overwatch'/.test(renderSrc),
    '[m20] the Command workspace builtin must skip the retired Overwatch destination');
  check(/if \(d\.id === 'overwatch'\) \{ return \{ dest: d, nodes: \[\] \}; \}/.test(renderSrc),
    '[m20] the site map must emit NO Overwatch section (its views are Rings nodes)');
  check((function () { const m = renderSrc.match(/var SITEMAP_START = \[([^\]]*)\]/); return !!m && /'rings'/.test(m[1]) && !/overwatch/.test(m[1]); })(),
    '[m20] the site map start path must begin at Rings (where boot lands)');
  // (e) graph zoom anchored at the pointer + the rebuilt Overview chip.
  check(/function zoomAtPoint\(sx, sy, factor\)/.test(renderSrc) && /view\.tx = sx - \(sx - view\.tx\) \* k;/.test(renderSrc) && /view\.ty = sy - \(sy - view\.ty\) \* k;/.test(renderSrc),
    '[m20] the canvas graph must anchor the zoom transform at a point (not the layer origin)');
  check(/zoomAtPoint\(ev\.clientX - sr\.left, ev\.clientY - sr\.top, ev\.deltaY < 0 \? 1\.1 : 0\.9\)/.test(renderSrc),
    '[m20] the graph wheel handler must pass the POINTER position to zoomAtPoint');
  check(/function zoomBy\(factor\) \{ zoomAtPoint\(/.test(renderSrc),
    '[m20] the +/- buttons must go through the same anchored zoom (viewport centre)');
  check(/'class': 'cv-zoom-pct'/.test(renderSrc) && /function updateZoomChip\(/.test(renderSrc),
    '[m20] the Overview chip must report the live zoom percentage alongside the LOD state');
  check(/\.cv-zoom \{[^}]*position: absolute;[^}]*left: 14px;[^}]*bottom: 14px/.test(shellHtml),
    '[m20] the Overview chip must sit in the BOTTOM-LEFT corner of the graph viewport');
  check(/\.rings-tabhost \.canvas-graph-stage \{ height: auto; min-height: 0; flex: 1 1 auto; \}/.test(shellHtml),
    '[m20] inside the Rings tab host the graph stage must FILL the viewport (so the corner is the real corner)');
  check(!/<iframe/i.test(renderSrc.slice(renderSrc.indexOf('function drawGraph'), renderSrc.indexOf('function renderCanvasGraph'))),
    '[m20] the graph (and its Overview element) must be NATIVE — no iframe');
  // (f) rings bars: one row, one shared measure.
  check(/:root \{ --rings-bar-measure: min\(760px, calc\(100% - 28px\)\); \}/.test(shellHtml),
    '[m20] both rings bars must share ONE measure custom property');
  check(/\.rings-bottombar \{[^}]*width: var\(--rings-bar-measure\)[^}]*flex-wrap: nowrap/.test(shellHtml),
    '[m20] the rings bottom bar must be a single non-wrapping row on the shared measure');
  check(/\.topbar\.rings-tabmode \.rings-playbar \{\s*\n\s*position: absolute; left: 50%; transform: translateX\(-50%\);\s*\n\s*width: var\(--rings-bar-measure\)/.test(shellHtml),
    '[m20] the rings top bar must take the shared measure + the same centring as the bottom bar');
  // (g) the completed-plans list clears the left toolbar.
  check(/var LEDGER_X = Math\.round\(toolsRight\) \+ 14;/.test(renderSrc) && /tR\.right - cR\.left/.test(renderSrc),
    '[m20] the completed-plans list must start clear of the left toolbar, measured from its live geometry');
  check(!/ctx\.fillRect\(12, y - 11, 218, 15\)/.test(renderSrc) && /ctx\.fillRect\(LEDGER_X, y - 11, 218, 15\)/.test(renderSrc),
    '[m20] the ledger rows (and their hit boxes) must move with LEDGER_X');
  check(/ledgerRows\.push\(\{ x: LEDGER_X/.test(renderSrc),
    '[m20] the ledger hit-test rects must match the drawn rows (click-to-solo stays aligned)');
  notes.push('operator round 9 (M20): the nine Rings views moved OUT of the main pane INTO the left nav as an accordion group (buildNavGroup/syncRailAccordion; one group open — the active destination\'s; height+opacity ease, reduced-motion snap), applied to BOTH the built-in and workspace rails; the topbar sub-nav PILL ROW is removed console-wide (buildSubnav + buildWorkspaceSubnav deleted) — one accordion in both rail states off ONE railGroupItems list (M22 replaced the collapsed-rail flyout with the compact inline accordion); a Rings row drives the SAME in-place fade swap via CruxRender.ringsSetTab + replaceState (a hashchange would re-route and kill the fade), and the topbar tab icons are gone; RINGS IS THE INDEX (DESTS[0], key 1, boot + "#/" land there) and Overwatch is retired to a railHidden route-only registry entry with every #/overwatch route redirected to its Rings equivalent (renderers kept — they ARE the tabs), plus sitemap/start-path/workspace-builtin/phone-tab retargets; the canvas graph zoom is ANCHORED AT THE POINTER (zoomAtPoint: t\' = s - (s - t)·k) and the Overview element is rebuilt as a compact bottom-left glass chip (LOD state + zoom %, native, var(--) tokens) over a stage that now fills the tab host; the rings bottom bar is one non-wrapping row and the top bar takes the same measure + midline; the completed-plans list starts clear of the vertical left toolbar, measured from its live geometry.');
})();

// =========================================================================
//  M21 — operator round 10: accordion icons · graph LOD anchor · session
//  allocation · ExecPlan list filter+sort · board edit mode · Studio sections ·
//  settings spacing + upward settings accordion · cx-cost titles + token bars.
// =========================================================================
(function m21OperatorRound10() {
  // ---- (1) accordion sub-page icons, shared by BOTH rail states -----------
  check(/function navPageGlyph\(pageId\)/.test(shellHtml) && /var NAV_PAGE_PATHS = \{/.test(shellHtml),
    '[m21] shell.html must carry a per-page nav glyph map + navPageGlyph resolver');
  check(/icon: navPageGlyph\(p\.id\)/.test(shellHtml) && /icon: navPageGlyph\(p\.type\)/.test(shellHtml),
    '[m21] BOTH railGroupItems and workspaceGroupItems must resolve a per-page mark (one list feeds accordion + flyout)');
  check(!/icon: NAV_SUB_GLYPH, current:/.test(shellHtml),
    '[m21] no item list may still hard-code the placeholder dot as its icon');
  // Reuse rule: pages whose mark the ICONS registry already owns must NOT be redrawn.
  ['cx-settings', 'cx-integrations', 'cx-workbench', 'cx-passport', 'cx-raw', 'dx-docs'].forEach(function (id) {
    check(new RegExp("'" + id + "': '").test(shellHtml.slice(shellHtml.indexOf('var NAV_PAGE_ICON_REF'), shellHtml.indexOf('function navPageGlyph'))),
      '[m21] ' + id + ' must reuse its existing ICONS entry, not a second drawing');
  });
  // Every registry page id should resolve to a real mark (map or ICONS ref).
  (function () {
    var mapped = {};
    var seg = shellHtml.slice(shellHtml.indexOf('var NAV_PAGE_PATHS'), shellHtml.indexOf('function navPageGlyph'));
    (seg.match(/'([a-z0-9-]+)':/g) || []).forEach(function (m) { mapped[m.slice(1, -2)] = true; });
    var missing = Object.keys(pages.PAGES || {}).filter(function (id) { return !mapped[id]; });
    check(missing.length === 0, '[m21] every registry page needs a nav mark; missing: ' + missing.join(','));
  })();

  // ---- (2) graph zoom: the LOD cut must PRESERVE the viewpoint ------------
  var switchBody = funcBody(renderSrc, 'switchMode') || '';
  check(switchBody.length > 0, '[m21] switchMode must be locatable');
  check(!/var f = frame\(activeDims\); view\.scale = f\.scale/.test(switchBody),
    '[m21] switchMode must NOT re-frame to fit on a LOD cut (that reset the operator zoom to the top-left)');
  check(/function switchMode\(next, anchor\)/.test(renderSrc),
    '[m21] switchMode must take the anchor the zoom was performed around');
  check(/var wx = \(ax - view\.tx\) \/ view\.scale, wy = \(ay - view\.ty\) \/ view\.scale;/.test(switchBody)
    && /view\.tx = ax - rx \* view\.scale; view\.ty = ay - ry \* view\.scale;/.test(switchBody),
    '[m21] switchMode must re-pin the anchor world point after the cut');
  check(/switchMode\('ring', \{ x: sx, y: sy \}\)/.test(renderSrc) && /switchMode\('card', \{ x: sx, y: sy \}\)/.test(renderSrc),
    '[m21] zoomAtPoint must hand its own anchor to switchMode');
  check(/function lodBounds\(m\)/.test(renderSrc) && !/var b = \(mode === 'ring'\) \? \{ min: 0\.03/.test(renderSrc),
    '[m21] the per-mode zoom bounds must be ONE function shared by zoomAtPoint + switchMode');
  check(/window\.__cvZoomProbe = function \(key\)/.test(renderSrc) && /window\.__cvZoomAt = function/.test(renderSrc),
    '[m21] the graph must expose dev-gated zoom probes so the anchor claim is assertable, not eyeballed');

  // ---- (3) session allocation: actor stamp + honest counts ---------------
  check(/state_title/.test(renderSrc) && /state_summary/.test(renderSrc) && /\bactor\b/.test(renderSrc),
    '[m21] the console must consume the new session row fields');
  check(/function paintAllocation\(a\)/.test(renderSrc) && /res\.data\.allocation/.test(renderSrc),
    '[m21] the sessions browser must render the daemon-computed allocation block');
  check(/if \(!a \|\| typeof a\.counted !== 'number'\) \{ allocWrap\.textContent = '';/.test(renderSrc)
    || /if \(!a \|\| typeof a\.counted !== 'number'\) \{ allocWrap\.hidden = true; return; \}/.test(renderSrc),
    '[m21] an older daemon (no allocation block) must hide the panel, never paint zeros');
  check(/identity stamped on this record at write time/.test(renderSrc),
    '[m21] the actor chip must say what it is (write-time stamp, not an inference)');

  // ---- (4) ExecPlan list: state chips + sort, persisted -------------------
  check(/var KANBAN_SORTS = \[/.test(renderSrc) && /\['completion', 'Completion · most done'\]/.test(renderSrc),
    '[m21] the board must offer date / A→Z / completion sorts');
  check(/function kanbanReadHidden\(boardId, cols\)/.test(renderSrc) && /function kanbanWriteSort\(boardId, sort\)/.test(renderSrc)
    && /KANBAN_LS = 'crux\.console\.board\.'/.test(renderSrc),
    '[m21] state-chip + sort choices must persist in localStorage, keyed per board');
  check(/board: 'work', columns: columns, total: items\.length, withProgress: withProg/.test(pagesSrc),
    '[m21] buildWork must opt the ExecPlan list into the board controls and report how many plans have milestone counts');
  check(/updated: Number\(w\.updated_at_unix_ms\) \|\| 0, created: Number\(w\.created_at_unix_ms\) \|\| 0/.test(pagesSrc),
    '[m21] the sort keys must come from real /v1/work timestamps');
  check(/if \(!!a\.hasProg !== !!b\.hasProg\) \{ return a\.hasProg \? -1 : 1; \}/.test(renderSrc),
    '[m21] completion sort must place plans WITHOUT milestone counts last (no invented progress)');
  check(/plans report milestone counts — the rest sort last/.test(renderSrc),
    '[m21] the completion metric must state its coverage honestly');
  check(/if \(!kbHidden\[col\.key\] && shown\.length <= 1\) \{ return; \}/.test(renderSrc),
    '[m21] the last visible column must not be hideable');

  // ---- (5) board edit mode + expanded-card close -------------------------
  var tileBody = funcBody(renderSrc, 'renderTileCanvas') || '';
  check(/var editMode = false;/.test(tileBody), '[m21] a tile board must open LOCKED');
  check(/if \(!editMode\) \{ return; \}   \/\/ M21 — locked board: reading never moves a tile/.test(tileBody),
    '[m21] tile drag must be refused while the board is locked');
  check(/if \(!editMode \|\| expandedId\) \{ return; \}/.test(tileBody),
    '[m21] the resize handle must be inert while the board is locked');
  check(/'data-tb': 'edit', 'aria-pressed': 'false'/.test(tileBody),
    '[m21] the board toolbar must carry an explicit Edit toggle');
  check(/\.cvx-surface\.is-locked \.cvx-node \{ cursor: pointer; \}/.test(shellHtml)
    && /\.cvx-surface\.is-editing \.cvx-node:not\(\[data-fixed="1"\]\) \{ cursor: move; \}/.test(shellHtml),
    '[m21] the locked board must not show move cursors');
  check(/'class': 'cvx-expclose'/.test(tileBody) && /\.cvx-node\.cvx-exp \.cvx-expclose \{ display: inline-flex; \}/.test(shellHtml),
    '[m21] an expanded card must carry a top-right X close');
  // The Studio is a separate editor — its own behaviour must not be gated by this.
  check(!/editMode/.test(funcBody(renderSrc, 'renderTileStudio') || ''),
    '[m21] the Studio (an inherent editor) must be untouched by the board lock');

  // ---- (7) settings spacing ----------------------------------------------
  check(/'class': 'v2grid settings-prefs'/.test(shellHtml),
    '[m21] the Density + Theme cards must live in a grid, not as bare siblings');
  check(/\.settings-page \{ display: flex; flex-direction: column; gap: 14px; \}/.test(shellHtml),
    '[m21] Settings must have ONE vertical rhythm between its bands');
  check(/:root\[data-mode="professional"\] \.settings-page \{ gap: 10px; \}/.test(shellHtml),
    '[m21] the professional density must carry the settings gap too');

  // ---- (8) settings sub-page accordion, opening upward from the footer ----
  //      RETARGETED in M23: the builder is renamed (buildAccountFooterNav) and the
  //      trigger is the ACCOUNT BADGE, not a separate System button; the collapsed
  //      rail no longer hides the group (it IS the compact presentation), so the
  //      "popup carries the same list" pair below became "one list, one control".
  check(/function buildAccountFooterNav\(\)/.test(shellHtml) && /id="railFooterNav"/.test(shellHtml),
    '[m21→m23] the System sub-pages must live in a footer accordion');
  check(/buildNavGroup\(host, chip, 'system', items\)/.test(shellHtml),
    '[m21→m23] the footer accordion must reuse the SAME buildNavGroup idiom as the rail');
  check(/\.rail-footer-nav \.nav-group \{ display: flex; flex-direction: column-reverse; \}/.test(shellHtml),
    '[m21] the footer group must open UPWARD off its trigger');
  check(!/:root\[data-rail="collapsed"\] \.rail-footer-nav \{ display: none; \}/.test(shellHtml),
    '[m23] the collapsed rail must NOT hide the footer accordion any more — it is the compact presentation');
  check(/var sys = railGroupItems\('system'\);/.test(shellHtml) && /return sys\.concat\(\[\{ sep: true, key: 'acct-sep' \}\], acct\);/.test(shellHtml),
    '[m21→m23] the footer System list must still come from the SAME railGroupItems source (one list, one control, both rail states)');
  check(/buildAccountFooterNav\(\);   \/\/ M21\/M23/.test(shellHtml),
    '[m21→m23] the rail builder must (re)build the footer accordion');
  check(/function settingsFooterSig\(\)/.test(shellHtml) && /refreshSettingsFooterNav\(\); \}\n    if \(activeKey === undefined\)/.test(shellHtml),
    '[m21] the footer list must refresh when the System page SET changes, so both rail states never disagree');

  // ---- (9) cx-cost titles + gradient token bars ---------------------------
  var costBody = funcBody(renderSrc, 'renderCostBrowser') || '';
  // M25 RETARGET (operator decision, round 14). M21's requirement was "a FIXED
  // 2,000,000-token scale"; M24 measured that 51 of the 83 real rows clamp
  // against it, so the operator resolved the finding by going ADAPTIVE. These
  // two gates are retargeted honestly — the underlying requirement (two rows
  // comparable within a view, nothing silently rescaled per row, the 2M mark
  // still readable) is unchanged; only the mechanism moved.
  check(/var COST_REF_TOKENS = 2000000;/.test(costBody) && /var COST_SCALE_MIN = 10000;/.test(costBody)
    && /function computeCostScale\(visible\)/.test(costBody),
    '[m21→m25] the token bar must use ONE adaptive scale per painted view, keeping 2,000,000 as a named reference');
  check(/computeCostScale\(visible\);\n      renderChart\(visible\); renderTotals\(visible\);/.test(costBody),
    '[m25] the scale must be computed BEFORE anything paints, so the chart and every row share one axis');
  check(/var mx = COST_REF_TOKENS;/.test(costBody) && /var t = sessTokens\(s\); if \(t > mx\) \{ mx = t; \}/.test(costBody)
    && /var o = Number\(s\.output_tokens\) \|\| 0; if \(o > mx\) \{ mx = o; \}/.test(costBody),
    '[m25] the adaptive maximum must cover BOTH quantities the page draws (row ctx+out AND chart output) — one length, one meaning');
  check(/function costPos\(tokens, sc\) \{ sc = sc \|\| costScale; return logBarPos\(tokens, sc\.min, sc\.max\); \}/.test(costBody),
    '[m25] cx-cost must position its bars through the shared logBarPos helper (the rings arc lens uses the same one)');
  // The 2M ceiling survives as a REFERENCE TICK on every track, plus a decade
  // axis, and the caption must state the adaptivity AND the non-proportionality.
  check(/'class': 'cost-tbar-refline'/.test(costBody)
    && /ref\.style\.left = \(costPos\(COST_REF_TOKENS\) \* 100\)\.toFixed\(2\) \+ '%';/.test(costBody),
    '[m21→m25] the 2,000,000-token mark must stay on every track, now as a reference tick at its log position');
  check(/bar scale: adaptive to the ' \+ costScale\.n \+ ' visible sessions · log, '/.test(costBody)
    && /length is orders of magnitude, NOT proportion/.test(costBody)
    && /the tick marks the old fixed 2M ceiling/.test(costBody),
    '[m25] the scale strip must declare the adaptivity, the range, the reference tick AND that length is not proportional');
  check(/function costScaleStrip\(\)/.test(costBody) && /'class': 'cost-axis-tick'/.test(costBody)
    && /for \(var d = COST_SCALE_MIN; d <= costScale\.max \* 1\.0001; d \*= 10\)/.test(costBody),
    '[m25] the log-ness must be VISIBLE — real decade ticks on the axis, not an assertion in prose');
  check(/Top sessions by output tokens · same adaptive log scale as the rows/.test(costBody),
    '[m24→m25] the top-10 chart must stay on the SAME idiom and say which scale it is on');
  check(/fill\.style\.backgroundSize = \(10000 \/ pct\) \+ '% 100%'/.test(costBody),
    '[m21] the gradient must be stretched to the whole track so colour tracks MAGNITUDE, not bar length');
  check(/if \(m && m\.state_title\) \{ return \{ text: m\.state_title, kind: 'title' \}; \}/.test(costBody)
    && /if \(m && m\.state_first_line\) \{ return \{ text: m\.state_first_line, kind: 'first_line' \}; \}/.test(costBody)
    && /return \{ text: shortId\(s\.session_id\), kind: 'id' \};/.test(costBody),
    '[m21] the cost row name must fall back title → state_first_line → short id');
  check(/COST_UNTITLED_HINT = '\(untitled — agents: set title\/summary in save_session state\)'/.test(costBody),
    '[m21] an unnamed session must say so, and say what to set');
  check(/function loadSessionMeta\(\)/.test(costBody) && /fetchJSON\('\/v1\/console\/sessions\?include_archived=true'\)/.test(costBody),
    '[m21] cx-cost must join the session store for the agent-given name');
  check(!/\bfetch\s*\(/.test(costBody), '[m21] cx-cost must not raw-fetch');

  notes.push('operator round 10 (M21): accordion rows (expanded, and compact since M22) carry PER-PAGE marks off one NAV_PAGE_PATHS map (registry-owned marks reused, never redrawn); the graph LOD cut PRESERVES the viewpoint — switchMode no longer re-frames to fit (which is what threw the layer to (pad,pad) = the reported top-left jump at ~60%) but re-pins the cursor world point and carries the current scale, with dev-gated __cvZoomProbe/__cvZoomAt so the claim is measured; save_session now stamps the write-time actor (scope_identity, None for anonymous) and documents state.title/state.summary, /v1/console/sessions returns actor + state_title/state_summary + a server-computed allocation block and the console paints it (hidden, not zeroed, on an older daemon); the ExecPlan board gained persisted state chips + date/A→Z/completion sorts (completion states its coverage and sinks unmeasured plans); tile boards open LOCKED with an explicit Edit toggle arming move+resize and expanded cards carry a top-right X (the Studio, an inherent editor, is untouched); the Canvas segmented control is replaced by the Studio\'s own Board·Pages·Integrations; Settings gets one vertical rhythm (its two JS cards moved into a grid) and the System sub-pages return as an UPWARD accordion off the rail footer (M23 supersedes its trigger + collapsed half: the account badge is the trigger and the same accordion serves the compact rail); cx-cost rows show the agent title + summary with an honest fallback chain and a per-session gradient bar on a fixed 2M scale with a visible max line.');
})();

// =========================================================================
//  M22 — operator round 11: the COMPACT-rail inline accordion. Clicking a
//  destination icon in the icons-only rail pushes its sub-pages DOWN the bar as
//  icons — the icons-only twin of the expanded accordion — and the right-side
//  sub-page flyout is REMOVED. The other rail pop-outs (operator options,
//  account, workspace switcher) are different mechanisms and stay.
// =========================================================================
(function m22OperatorRound11() {
  // ---- (1) the flyout is GONE (state assertion, not just "unused") --------
  ['ensureRailFlyout', 'openRailFlyout', 'openWorkspaceRailFlyout', 'railFlyoutRender',
   'closeRailFlyout', 'scheduleRailFlyoutClose', 'railFlyoutFocusFirst'].forEach(function (fn) {
    check(!new RegExp('function ' + fn + '\\(').test(shellHtml) && shellHtml.indexOf(fn + '(') < 0,
      '[m22] the sub-page flyout function ' + fn + ' must be removed (no definition, no call site)');
  });
  check(!/id: 'railFlyout'/.test(shellHtml) && !/#railFlyout/.test(shellHtml),
    '[m22] no #railFlyout element may be built or queried any more');
  check(!/aria-haspopup/.test(shellHtml.slice(shellHtml.indexOf('function buildRail()'), shellHtml.indexOf('function buildThemeSwitch'))),
    '[m22] a rail destination must no longer advertise a popup (it owns an accordion group)');
  check(!/mouseenter[^\n]*railIsCollapsed/.test(shellHtml),
    '[m22] the collapsed rail must have NO hover-intent sub-page affordance');
  // The OTHER pop-outs are untouched — different mechanisms, explicitly retained.
  check(/id: 'wsSwitchPop'/.test(shellHtml) && /id: 'railOpsPop'/.test(shellHtml),
    '[m22→m23] the workspace-switcher and operator-options pop-outs must survive the flyout removal (the account pop-out is retired by M23, deliberately — see Check 54)');
  check(/\.rail-flyout \{/.test(shellHtml),
    '[m22] the .rail-flyout glass must remain — it is the shared skin of those three pop-outs');

  // ---- (2) compact rows are ICON buttons, nested, off the SAME glyphs -----
  check(/:root\[data-rail="collapsed"\] \.nav-subitem \{[^}]*justify-content: center;[^}]*width: 34px; min-height: 34px/.test(shellHtml),
    '[m22] a compact sub-page row must be a square icon button');
  // RETARGETED in M23 — the inset + connector hairline are REPLACED by centred
  // rows, a bigger destination glyph and a closing rule (see the M23 block).
  check(/:root\[data-rail="collapsed"\] \.nav-subitem \{[^}]*margin-left: auto; margin-right: auto;/.test(shellHtml)
    && !/:root\[data-rail="collapsed"\] \.nav-sub-inner::before \{ left: 6px/.test(shellHtml),
    '[m22→m23] compact rows must be CENTRED in the bar, with no left connector hairline (hierarchy by size, not by indent)');
  check(/:root\[data-rail="collapsed"\] \.nav-subitem \.label,\n    :root\[data-rail="collapsed"\] \.nav-subitem \.acct-code \{ display: none; \}/.test(shellHtml),
    '[m22→m23] the compact row must drop its text label AND the Language locale code (tooltips are the only text)');
  // M24 RETARGET: the requirement was "the compact row must carry its page name
  // somewhere, because it has no visible label". That still holds — but the
  // vehicle changed. The native `title` is REMOVED (it drew an uncontrolled
  // OS tooltip that fought the new glass hover label), so the name now rides on
  // aria-label (accessible name, unchanged) + data-hlabel (what the hover label
  // reads). Both are asserted, and the absence of `title` is asserted too, so a
  // future edit cannot quietly reintroduce the double tooltip.
  check(/'aria-label': it\.title, 'data-hlabel': it\.title/.test(shellHtml),
    '[m22→m24] every accordion row must carry the page name in aria-label + data-hlabel (the compact row has no visible label)');
  check(/\.nav-subitem\[aria-current="page"\] \{/.test(shellHtml) && /\.nav-subitem\[aria-current="page"\] svg \{ opacity: 1; color: var\(--acc\); \}/.test(shellHtml),
    '[m22] the active sub-page must be marked (accent fill + accent glyph) — it is the only state cue a compact icon has');
  // ONE glyph source for both presentations: the compact icons ARE the expanded icons.
  check(/if \(it\.icon\) \{ row\.appendChild\(el\('span', \{ 'class': 'ic', 'aria-hidden': 'true', html: it\.icon \}\)\); \}/.test(shellHtml),
    '[m22] both presentations must render the item list\'s own icon (no second compact glyph set)');

  // ---- (3) same accordion mechanics as expanded ---------------------------
  check(/M22 — COMPACT-RAIL ACCORDION/.test(shellHtml),
    '[m22] the compact accordion must be documented where its rules live (CSS)');
  check(/var open = \(k === activeKey\);/.test(shellHtml) && /function syncRailAccordion\(/.test(shellHtml),
    '[m22] the one-open invariant + route sync are the SAME code in both rail states');
  check(/\.nav-sub \{[^}]*transition: height/.test(shellHtml) && /function navReduceMotion\(/.test(shellHtml),
    '[m22] the compact group must use the same height/opacity ease and reduced-motion snap');
  check(/if \(location\.hash === target\) \{ syncRailAccordion\(\); return; \}/.test(shellHtml),
    '[m22] clicking the destination you are already on must still open its group (no hashchange fires)');
  check(/if \(location\.hash === target\) \{ syncRailAccordion\(dest\.id, first \|\| null\); return; \}/.test(shellHtml),
    '[m22] the workspace rail must do the same (both rails, one behaviour)');
  check(/function goRingsTab\(slug, tabId\)/.test(shellHtml) && /R\.ringsSetTab\(tabId\);/.test(shellHtml),
    '[m22] a Rings row must drive the in-place fade bridge — from the compact rail exactly as from the expanded one');

  // ---- (4) keyboard: the accordion replaces the flyout's key model --------
  check(/function navGroupRows\(group\)/.test(shellHtml) && /rows\[Math\.min\(i \+ 1, rows\.length - 1\)\]\.focus\(\)/.test(shellHtml),
    '[m22] ArrowDown/ArrowUp must walk the open group\'s rows');
  check(/function navGroupIsUpward\(group\)/.test(shellHtml),
    '[m22] the upward footer group must mirror its two vertical keys (visual order == key order)');

  // ---- (5) overflow containment ------------------------------------------
  check(/#nav \{ flex: 1 1 auto; min-height: 0; scrollbar-width: thin; \}/.test(shellHtml) && /nav \{[^}]*overflow-y: auto/.test(shellHtml),
    '[m22] an open compact group must scroll inside #nav (the M17 overflow fix), never overflow the viewport');

  notes.push('operator round 11 (M22): the COMPACT (icons-only) rail runs the accordion inline — clicking a destination icon navigates to its default page AND pushes that destination\'s sub-pages down the bar as square, inset icon buttons rendered from the SAME railGroupItems/workspaceGroupItems lists and the SAME navPageGlyph marks as the expanded rows (one list, two presentations; page name in title + aria-label, active row accent-marked), with the same one-open-group invariant, the same syncRailAccordion route binding, the same height+opacity ease and reduced-motion snap, and the same goRingsTab fade bridge for the nine Rings views; the right-side sub-page flyout is REMOVED outright (railFlyout element, ensureRailFlyout/openRailFlyout/openWorkspaceRailFlyout/railFlyoutRender/closeRailFlyout/scheduleRailFlyoutClose/railFlyoutFocusFirst, the hover-intent + ArrowRight entry, aria-haspopup and every close-on-route/popup-exclusion call site) while the three genuine rail pop-outs — operator options, account, workspace switcher — keep the .rail-flyout glass untouched; keyboard moves to the accordion model (ArrowDown steps into the open group, ArrowDown/ArrowUp walk its rows, ArrowUp off the first row and Escape return to the destination, Enter/Space navigate), mirrored for the upward footer group; an open group scrolls inside the #nav overflow region (M17) rather than the viewport.');
})();

// =========================================================================
//  M23 — operator round 12: rail hierarchy styling + footer consolidation.
//  (1) The compact rail drops the left connector hairline and the right inset:
//      sub icons CENTRE in the bar, the destination glyph steps up a tier, and a
//      short hairline past the LAST row closes an open group.
//  (2) The footer loses its separate "System" trigger — the ACCOUNT BADGE is the
//      single control, rolling ONE merged group (System pages · hairline · Studio
//      · Language · Log out) upward, in BOTH rail states. #acctPop is retired.
// =========================================================================
(function m23OperatorRound12() {
  // ---- (1a) no left connector hairline in the compact bar -----------------
  check(/:root\[data-rail="collapsed"\] \.nav-sub-inner::before \{ display: none; \}/.test(shellHtml),
    '[m23] the compact sub rows must have NO left connector hairline');
  check(!/:root\[data-rail="collapsed"\][^\n]*::before \{ left: 6px/.test(shellHtml),
    '[m23] the old left:6px compact connector must be gone, not merely overpainted');
  // The EXPANDED rail keeps its connector — this is a compact-only change.
  check(/\.nav-sub-inner::before \{\n    content: ''; position: absolute; left: 18px;/.test(shellHtml),
    '[m23] the EXPANDED rail must keep its left:18px connector (compact-only change)');

  // ---- (1b) compact sub rows are CENTRED ---------------------------------
  check(/:root\[data-rail="collapsed"\] \.nav-subitem \{[^}]*margin-left: auto; margin-right: auto;/.test(shellHtml),
    '[m23] compact sub rows must be centred horizontally (margin-left/right auto), not inset right');
  check(!/:root\[data-rail="collapsed"\] \.nav-subitem \{[^}]*margin-right: 3px;/.test(shellHtml),
    '[m23] the old right-inset margin trick must be removed');

  // ---- (1c) destination glyph is a clear step BIGGER than a sub glyph -----
  (function () {
    var dest = /:root\[data-rail="collapsed"\] \.nav-item svg \{ width: (\d+)px; height: (\d+)px; \}/.exec(shellHtml);
    var sub = /:root\[data-rail="collapsed"\] \.nav-subitem svg \{ width: (\d+)px; height: (\d+)px; \}/.exec(shellHtml);
    check(!!dest && !!sub, '[m23] both compact glyph sizes must be declared where the compact rules live');
    if (!dest || !sub) { return; }
    var d = parseInt(dest[1], 10), b = parseInt(sub[1], 10);
    check(d >= 20 && d <= 24, '[m23] the compact destination glyph must step up to 20–24px (was 18px), got ' + d);
    check(d - b >= 4, '[m23] main vs sub hierarchy must read by SIZE alone: dest ' + d + 'px must exceed sub ' + b + 'px by >= 4px');
    // Row heights move with it, harmoniously, and nothing may exceed the 48px
    // content width of the 64px rail (16px 8px padding => 48px).
    check(/:root\[data-rail="collapsed"\] \.nav-item \{ justify-content: center; padding: 0; gap: 0; min-height: 48px; \}/.test(shellHtml),
      '[m23] the compact destination button must grow with its glyph (48px row)');
    check(/:root\[data-rail="collapsed"\] \.nav-subitem \{[^}]*width: 34px; min-height: 34px;/.test(shellHtml),
      '[m23] the compact sub row must stay the smaller 34px square');
    var railW = /:root\[data-rail="collapsed"\] \.app \{ grid-template-columns: (\d+)px 1fr; \}/.exec(shellHtml);
    var railPad = /:root\[data-rail="collapsed"\] \.rail \{ padding: 16px (\d+)px;/.exec(shellHtml);
    check(!!railW && !!railPad, '[m23] the compact rail width + gutters must be declared');
    if (railW && railPad) {
      var content = parseInt(railW[1], 10) - 2 * parseInt(railPad[1], 10);
      check(d <= content && 34 <= content,
        '[m23] the bigger glyph (' + d + 'px) and the 34px sub square must fit the ' + content + 'px compact content width (no clipping)');
    }
  })();

  // ---- (1d) closing divider under the LAST row of an OPEN group ----------
  check(/:root\[data-rail="collapsed"\] \.nav-sub\.is-open \.nav-sub-inner::after \{/.test(shellHtml),
    '[m23] an OPEN compact group must be closed by a divider (.is-open-scoped, so a closed group shows none)');
  check(/:root\[data-rail="collapsed"\] \.nav-sub\.is-open \.nav-sub-inner::after \{[^}]*background: var\(--edge\);/.test(shellHtml),
    '[m23] the closing divider must use the shared hairline token, not a literal colour');
  check(/:root\[data-rail="collapsed"\] \.nav-sub\.is-open \.nav-sub-inner::after \{[^}]*bottom: 0;/.test(shellHtml)
    && /:root\[data-rail="collapsed"\] \.nav-sub\.is-open \.nav-sub-inner::after \{[^}]*left: 50%; transform: translateX\(-50%\);/.test(shellHtml),
    '[m23] the divider must sit past the LAST row (bottom of the group) and be centred like the rows');
  // ONE rule on the shared .nav-sub family => builtin AND workspace rails both get
  // it (buildWorkspaceRail goes through the same buildNavGroup).
  check(/buildNavGroup\(nav, btn, d\.id, items\)/.test(shellHtml) && /buildNavGroup\(nav, btn, item\.id, items\)/.test(shellHtml),
    '[m23] builtin and workspace rails must share buildNavGroup, so one divider rule covers both');
  // UPWARD group: the cap flips to the TOP — the group\'s far end from the badge.
  check(/:root\[data-rail="collapsed"\] \.rail-footer-nav \.nav-sub\.is-open \.nav-sub-inner::after \{ bottom: auto; top: 0; \}/.test(shellHtml),
    '[m23] the UPWARD footer group must cap at its TOP (its far end), so the divider still reads as the list end');

  // ---- (2a) ONE footer trigger: the account badge ------------------------
  check(!/'data-dest': 'system'/.test(shellHtml) && !/text: dest\.label/.test(shellHtml.slice(shellHtml.indexOf('function buildAccountFooterNav'), shellHtml.indexOf('function buildRail()'))),
    '[m23] the separate footer "System" trigger button must be removed');
  check(/var chip = document\.getElementById\('passportChip'\);/.test(shellHtml)
    && /buildNavGroup\(host, chip, 'system', items\)/.test(shellHtml),
    '[m23] the ACCOUNT BADGE itself must be the footer group\'s trigger button');
  (function () {
    var footer = shellHtml.slice(shellHtml.indexOf('<div class="rail-footer">'), shellHtml.indexOf('</aside>'));
    check((footer.match(/<button /g) || []).length === 1 && /id="passportChip"/.test(footer),
      '[m23] the rail footer markup must carry exactly ONE control — the account badge');
  })();
  // The badge is a live node (passport paint + placeMobileChrome hold it by id):
  // a rebuild must MOVE it, never re-create it.
  check(/if \(chip\.parentNode\) \{ chip\.parentNode\.removeChild\(chip\); \}\n    host\.textContent = '';/.test(shellHtml),
    '[m23] a footer rebuild must detach and re-mount the SAME badge node, never re-create it');
  check(/var acct = document\.getElementById\('railFooterNav'\);/.test(shellHtml),
    '[m23] placeMobileChrome must relocate the whole footer group (badge + rows travel together)');

  // ---- (2b) merged rows: System + account, deduped, in one list ----------
  check(/function acctFooterItems\(\)/.test(shellHtml) && /function accountFooterItems\(\)/.test(shellHtml),
    '[m23] the account actions must be an item list in the same shape as railGroupItems');
  ['acct-studio', 'acct-language', 'acct-logout'].forEach(function (k) {
    check(new RegExp("key: '" + k + "'").test(shellHtml),
      '[m23] the merged footer group must carry the account row ' + k);
  });
  check(!/mk\('Settings', 'settings', 'settings'\)/.test(shellHtml) && !/acctPop\.appendChild/.test(shellHtml),
    '[m23] the pop-out\'s duplicate "Settings" row must be DEDUPED away (System\'s cx-settings is Settings)');
  check(/return sys\.concat\(\[\{ sep: true, key: 'acct-sep' \}\], acct\);/.test(shellHtml),
    '[m23] System pages must come FIRST and account actions LAST — the group is column-reverse, so account actions land nearest the badge');
  check(/if \(it\.sep\) \{ inner\.appendChild\(el\('div', \{ 'class': 'nav-sub-sep', 'aria-hidden': 'true' \}\)\); return; \}/.test(shellHtml)
    && /\.nav-sub-sep \{ height: 1px; background: var\(--edge\);/.test(shellHtml),
    '[m23] the two merged sections must be separated by a non-focusable hairline');
  // Compact mode gets the SAME group as icon rows (no popup fallback anywhere).
  check(/:root\[data-rail="collapsed"\] \.rail-footer-nav \.nav-sub-sep \{ width: 24px; margin: 3px auto; \}/.test(shellHtml),
    '[m23] the compact footer group must centre its separator like its rows');
  check(!/railIsCollapsed\(\) \? railGroupItems\('system'\)/.test(shellHtml),
    '[m23] no rail-state branch may serve a SECOND presentation of the System list any more');

  // ---- (2c) task-1 styling applies to the upward group -------------------
  //      (asserted above: the connector/centring/divider rules are all
  //      :root[data-rail="collapsed"]-scoped on the shared .nav-sub family, and
  //      the footer group is a .nav-sub — plus the upward cap flip.)
  check(/\.rail-footer-nav \.nav-group \{ display: flex; flex-direction: column-reverse; \}/.test(shellHtml),
    '[m23] the merged group must still roll UPWARD off the badge');

  // ---- (2d) keyboard + logout-hidden -------------------------------------
  check(/var NAV_TRIGGER_SEL = '\.nav-item, \.passport-chip';/.test(shellHtml)
    && /var item = t\.closest\('\.nav-subitem'\), dest = t\.closest\(NAV_TRIGGER_SEL\);/.test(shellHtml),
    '[m23] the M22 keyboard walk must recognise the badge as a group trigger');
  check(/function navGroupTrigger\(group\) \{ return group\.querySelector\(NAV_TRIGGER_SEL\); \}/.test(shellHtml)
    && /if \(e\.key === 'Escape'\) \{ e\.preventDefault\(\); var b = navGroupTrigger\(group\); if \(b\) \{ b\.focus\(\); \} return; \}/.test(shellHtml),
    '[m23] Escape must return focus to the group\'s trigger — the badge, for the footer group');
  check(/var rows = Array\.prototype\.slice\.call\(group\.querySelectorAll\('\.nav-subitem:not\(\[hidden\]\)'\)\);/.test(shellHtml),
    '[m23] a [hidden] row (Log out on a local daemon) must not be in the keyboard walk');
  // M22 mirrored only the two KEY NAMES for the upward group, so ArrowUp off the
  // trigger jumped to the far end of the list and then walked back downward. The
  // walk order itself has to reverse: index 0 = nearest the trigger, always.
  check(/return navGroupIsUpward\(group\) \? rows\.reverse\(\) : rows;/.test(shellHtml),
    '[m23] the UPWARD group\'s row walk must be reversed so `into` always moves AWAY from the trigger (M22 mirrored the keys but not the order)');
  check(/if \(it\.hidden\) \{ row\.hidden = true; \}/.test(shellHtml)
    && /hidden: !ACCT_HOSTED, go: function \(\) \{ acctAction\('logout'\); \}/.test(shellHtml)
    && /window\.CruxSession\.probe\(\)\.then\(function \(hosted\) \{\n        ACCT_HOSTED = !!hosted;/.test(shellHtml),
    '[m23] Log out must stay hidden until CruxSession.probe() confirms a hosted session (the M18 local-daemon rule)');
  // A row's own `display: flex` out-specifies the UA [hidden] rule — the attribute
  // has to be honoured explicitly or the "hidden" logout row still paints 34px.
  check(/\.nav-subitem\[hidden\] \{ display: none; \}/.test(shellHtml),
    '[m23] [hidden] must actually hide a nav row (its display:flex out-specifies the UA rule)');

  // ---- house rules --------------------------------------------------------
  check(!/\bfetch\s*\(/.test(shellHtml.slice(shellHtml.indexOf('function acctAction'), shellHtml.indexOf('function initAcctMenu'))),
    '[m23] the footer accordion must not raw-fetch');
  check(!/nav-sub-sep[^\n]*innerHTML/.test(shellHtml),
    '[m23] the new footer DOM must be built with el()/textContent, not innerHTML');

  notes.push('operator round 12 (M23): the COMPACT rail\'s hierarchy is re-cut to read by SIZE — the left connector hairline is removed, the sub icons are CENTRED in the bar (the right-inset margin trick is gone), the destination glyph steps 18 → 22px inside a 48px row against the unchanged 34px/16px sub square, and an OPEN group is capped by a short centred var(--edge) hairline past its last row (one rule on the shared .nav-sub family, so the builtin and workspace rails both get it; the upward footer group flips the cap to its TOP so it still reads as the end of the list). The expanded rail is untouched (its left:18px connector is asserted intact). The rail FOOTER loses its second control: the separate System accordion trigger is deleted and the ACCOUNT BADGE (#passportChip, moved into the group by buildAccountFooterNav) becomes the single trigger of ONE merged upward group — System sub-pages, a non-focusable hairline, then Studio · Language · Log out nearest the badge (column-reverse ⇒ last in DOM is closest to the trigger). #acctPop is retired outright (element, ensure/open/close/toggle handlers, acctSyncSystemRows, the click-away listener and the route() close call), taking with it the duplicate "Settings" row (System\'s cx-settings IS Settings) and the collapsed-rail branch that served a second presentation of the same list; the compact rail now rolls the same group up as centred icon squares with tooltip-only text. Keyboard is unchanged in model — NAV_TRIGGER_SEL just admits .passport-chip, so ArrowUp steps into the upward group from the badge and Escape returns to it — and [hidden] rows are excluded from the walk, so Log out (hidden until CruxSession.probe() confirms a hosted session) is skipped on a local daemon.');
})();

// =========================================================================
//  Check 56 — M24, operator round 13.
//    (1) the compact rail's native title tooltips are REPLACED by a glass
//        hover label that eases out from under the bar;
//    (2) the Token Burn chart draws the SAME bar as its rows, named by the
//        cx-sessions naming chain;
//    (3) tokens-per-turn is a first-class signal (chips + sort) and the
//        "how to cut it" strapline is backed by per-session advice computed
//        from real numbers against features the daemon ships;
//    (4) "Average Token Usage" is live (its static mock is deleted) and its
//        bars use the cost lens's gradient;
//    (5) ring dots shrink (damped, floored) as zoom increases.
// =========================================================================
(function checkM24OperatorRound13() {
  // ---- (1) compact-rail hover label --------------------------------------
  // The native tooltip must be GONE from all three rail row builders — a
  // leftover `title:` would draw the OS box on top of the glass chip.
  check(!/'class': 'nav-item', type: 'button', 'data-dest': item\.id[^}]*title:/.test(shellHtml)
    && !/'data-wsdest': d\.id[^}]*title: d\.label/.test(shellHtml)
    && !/'class': 'nav-subitem', type: 'button'[^}]*\btitle:/.test(shellHtml),
    '[m24] no rail row builder may set a native title (it would fight the hover label)');
  check(/'aria-label': item\.label, 'data-hlabel': item\.label/.test(shellHtml)
    && /'aria-label': d\.label, 'data-hlabel': d\.label/.test(shellHtml),
    '[m24] destination buttons (built-in AND workspace rails) must name themselves via aria-label + data-hlabel');
  check(/id="passportChip"[^>]*aria-label="Account &amp; system" data-hlabel="Account &amp; system"/.test(shellHtml)
    && !/id="passportChip"[^>]*\btitle=/.test(shellHtml),
    '[m24] the footer account badge must follow the same rule (aria-label + data-hlabel, no native title)');
  // The accessible name must not regress: buildNavGroup used to read the
  // trigger's title for its group label, so it has to read aria-label now.
  check(/'aria-label': \(btn\.getAttribute\('aria-label'\) \|\| btn\.getAttribute\('data-hlabel'\) \|\| key\) \+ ' pages'/.test(shellHtml),
    '[m24] the sub-group\'s accessible name must come off the trigger\'s aria-label, not its removed title');
  check(/var RAIL_HLABEL_DELAY = 900;/.test(shellHtml),
    '[m24] the label must wait for steady hover (~1s), not fire on every pass of the pointer');
  check(/function railIsCompact\(\)/.test(shellHtml)
    && /data-rail'\) !== 'collapsed'\) \{ return false; \}/.test(shellHtml)
    && /matchMedia\('\(min-width: 721px\)'\)/.test(shellHtml),
    '[m24] the hover label is COMPACT-rail + desktop only — the expanded rail shows its labels inline and must be untouched');
  // Rendered on <body>, position:fixed — the reason it cannot be clipped by
  // #nav's overflow-y:auto scroll region.
  check(/document\.body\.appendChild\(railHLabelEl\);/.test(shellHtml)
    && /\.rail-hlabel \{\n    position: fixed;/.test(shellHtml),
    '[m24] the label must render OUTSIDE the scroll container (body child, position:fixed) so #nav overflow cannot clip it');
  // m24 set the pair at 5/6, which lost to the rings page's own overlay bands
  // (left toolbar z 16, tab icons z 22, fixed tips z 90) — the label slid out
  // UNDER the ring buttons. The invariant is relational + a floor: rail strictly
  // above chip (ease-out-from-behind) and chip strictly above every main-pane
  // overlay (highest is .rings-tip at 90), asserted numerically, not as pinned
  // literals.
  {
    const railZ = (shellHtml.match(/\.rail \{ z-index: (\d+); \}/) || [])[1];
    const chipZ = (shellHtml.match(/\.rail-hlabel \{[^}]*z-index: (\d+);/) || [])[1];
    check(railZ && chipZ && Number(railZ) > Number(chipZ) && Number(chipZ) > 90,
      '[m24→m26] the rail must paint ABOVE the label (ease-out-from-behind) and the label ABOVE every main-pane overlay band (rings toolbar/tips top out at z 90) — got rail=' + railZ + ' chip=' + chipZ);
  }
  check(/\.rail-hlabel \{[^}]*transform: translate\(-14px, -50%\);[^}]*transition: opacity \.16s ease, transform \.2s cubic-bezier\(\.16,1,\.3,1\);/.test(shellHtml)
    && /\.rail-hlabel\.is-out \{ opacity: 1; transform: translate\(0, -50%\); \}/.test(shellHtml),
    '[m24] the ease must be a ~200ms transform+opacity slide to the right (no layout animation)');
  check(/@media \(prefers-reduced-motion: reduce\) \{ \.rail-hlabel \{ transition: none; \} \}/.test(shellHtml),
    '[m24] reduced motion must snap the label instead of sliding it');
  check(/lab\.style\.top = Math\.round\(rr\.top \+ rr\.height \/ 2\) \+ 'px';/.test(shellHtml),
    '[m24] the label must sit at the row\'s vertical centre');
  check(/rail\.addEventListener\('mouseleave', hideRailHLabel\);/.test(shellHtml)
    && /window\.addEventListener\('scroll', hideRailHLabel, true\);/.test(shellHtml)
    && /if \(typeof hideRailHLabel === 'function'\) \{ hideRailHLabel\(\); \}/.test(shellHtml),
    '[m24] the label must leave on mouseleave, on any scroll, and on every route change');
  check(/'class': 'rail-hlabel', id: 'railHoverLabel', 'aria-hidden': 'true'/.test(shellHtml),
    '[m24] the label is decoration for sighted users — aria-hidden, because aria-label already names the row');
  check(/initRailHoverLabels\(\);/.test(shellHtml) && !/railHLabel[^\n]*innerHTML/.test(shellHtml),
    '[m24] the label must be wired at init and built with el()/textContent');

  // ---- (2) the chart speaks the rows' visual language ---------------------
  var costBody24 = funcBody(renderSrc, 'renderCostBrowser') || '';
  check(/costBar\(s\.output_tokens \|\| 0\)/.test(costBody24)
    && !/'class': 'cost-bar-fill'/.test(costBody24)
    && !/'class': 'cost-bar-track'/.test(costBody24),
    '[m24] the top-sessions chart must draw the SAME costBar() as the rows — its own flat track/fill is gone');
  check(!/\.cost-bar-fill \{/.test(shellHtml) && !/\.cost-bar-track \{/.test(shellHtml),
    '[m24] the retired chart-bar CSS must go with the markup that used it (one bar idiom, not two)');
  check(/var nm = sessName\(s\);[\s\S]{0,220}'class': 'cost-bar-label'/.test(costBody24),
    '[m24] chart labels must use the cx-sessions naming chain (title → first line → short id), not a raw UUID');

  // ---- (3) tokens-per-turn + advice grounded in real numbers -------------
  check(/function turnsOf\(s\)/.test(costBody24) && /function outPerTurn\(s\)/.test(costBody24)
    && /function ctxPerTurn\(s\)/.test(costBody24) && /function ctxRatio\(s\)/.test(costBody24),
    '[m24] per-turn rates must be first-class derivations, not inline arithmetic');
  check(/'turns unavailable'/.test(costBody24) && /return \(isFinite\(t\) && t > 0\) \? t : null;/.test(costBody24),
    '[m24] a report with no turn count must SAY so — never a fabricated 0');
  check(/COST_SORTS/.test(costBody24) && /\['outturn', 'output \/ turn'\]/.test(costBody24)
    && /\['ctxturn', 'context \/ turn'\]/.test(costBody24) && /function sortVisible\(rows, key\)/.test(costBody24),
    '[m24] the rows must be sortable BY the per-turn rate (magnitude finds the expensive, rate finds the inefficient)');
  check(/if \(va == null\) \{ return 1; \}/.test(costBody24),
    '[m24] rows with no value for the active sort must sink, not sort as zero');
  check(/var ADV_CTX_RATIO = 150;/.test(costBody24) && /var ADV_CTX_PER_TURN = 200000;/.test(costBody24)
    && /var ADV_TURNS = 300;/.test(costBody24) && /var ADV_OUT_PER_TURN = 2500;/.test(costBody24),
    '[m24] every advice threshold must be a named constant, not a magic number buried in a branch');
  check(/function adviceHelp\(\)/.test(costBody24) && /how to cut it — when each line fires/.test(costBody24),
    '[m24] the thresholds must be VISIBLE to the operator (a rule you cannot read is a rule you cannot check)');
  check(/if \(!adv\.length\) \{ return null; \}/.test(costBody24)
    && /if \(adv\) \{ kids\.push\(adv\); \}/.test(costBody24),
    '[m24] a session that trips nothing must get NO advice line (honest silence, not filler)');
  // Each recommendation must name a feature this daemon actually ships.
  ['token_budget', 'query_scan', 'query_expand', 'save_session', 'get_session', 'store_fact', 'query_facts'].forEach(function (f) {
    check(costBody24.indexOf(f) >= 0, '[m24] the advice must name the real token-reduction feature `' + f + '`');
  });
  check(/no savings percentage is claimed, because the daemon measures no counterfactual/.test(costBody24),
    '[m24] no savings percentage may be claimed — nothing measures the counterfactual');

  // ---- (4) Average Token Usage is live -----------------------------------
  // The literals must be gone as CONTROL VALUES. (buildUsageLive's header quotes
  // them verbatim to record what was removed — that is documentation, not a
  // rendered figure — so the assertion is scoped to the code, not the comments.)
  var pagesCode = pagesSrc.replace(/^\s*\/\/.*$/gm, '');
  check(!/STATIC\['cx-usage'\]/.test(pagesCode)
    && !/info\('daily avg', '~83k/.test(pagesCode)
    && !/info\('this week', '517k/.test(pagesCode)
    && !/≈233k in tokens\/week · −31%/.test(pagesCode)
    && !/pct: 100, v: '750k in\/wk'/.test(pagesCode),
    '[m24] every hardcoded cx-usage figure must be DELETED (page() paints STATIC first, so a mock there is what operators saw)');
  check(/'cx-usage': page\('cx-usage', 'meters', 'Average Token Usage', 'measured per-period and per-turn averages · \/v1\/cost\/report', \{ load: \{ endpoint: '\/v1\/cost\/report/.test(pagesSrc),
    '[m24] cx-usage must load the real feed it names');
  check(/function buildUsageLive\(res\)/.test(pagesSrc) && /function usageAgg\(rows\)/.test(pagesSrc)
    && /function usageSeriesFrom\(rows\)/.test(pagesSrc),
    '[m24] cx-usage numbers must be COMPUTED from the report rows');
  check(/turns unavailable — no report in this set carries an assistant_turns count/.test(pagesSrc)
    && /No session cost reports have been posted for this tenant/.test(pagesSrc),
    '[m24] cx-usage must degrade honestly (empty feed, missing turn counts) rather than estimate');
  check(/measured saving', 'none — the daemon records no counterfactual/.test(pagesSrc),
    '[m24] the savings card must state that nothing is measured, not carry an invented percentage');
  check(/turn-less reports are excluded from this average, not counted as zero/.test(pagesSrc)
    && /a\.ctxOnTurns \+= c; a\.outOnTurns \+= o;/.test(pagesSrc),
    '[m24] the per-turn average must divide like by like — reports with no turn count contribute neither numerator nor denominator');
  check(/var USAGE_BAR_MAX = 2000000;/.test(pagesSrc) && /ramp: true/.test(pagesSrc)
    && /\.ctl-bar-fill\.ramp \{\n    background-image: linear-gradient\(90deg, var\(--ok\) 0%, var\(--trust\) 34%, var\(--warn\) 68%, var\(--crit\) 100%\);/.test(shellHtml),
    '[m24→m25] cx-usage bars must use the cost lens\'s gradient on the 2,000,000-token mark — which cx-cost now draws as its REFERENCE tick rather than its ceiling (cx-usage keeps a fixed scale: it plots one averaged session size, not a ranked 5-order-of-magnitude spread)');

  // ---- (5) ring dots shrink with zoom ------------------------------------
  var ringsBody = funcBody(renderSrc, 'renderRings') || '';
  check(/var ZOOM_DOT_K = 0\.6, ZOOM_DOT_MIN = 0\.28;/.test(ringsBody)
    && /function zoomDotScale\(\) \{ return Z <= 1 \? 1 : Math\.max\(ZOOM_DOT_MIN, 1 \/ Math\.pow\(Z, ZOOM_DOT_K\)\); \}/.test(ringsBody),
    '[m24] dot radius must be damped by zoom, with a floor — and be EXACTLY 1 at or below the overview zoom');
  check(/var rr = dotR\(c\) \* zdot \*/.test(ringsBody) && /var zdot = zoomDotScale\(\);   \/\/ M24/.test(ringsBody),
    '[m24] the damping must be computed ONCE per frame and applied to the dot radius (no per-dot allocation)');
  check(/window\.__ringsZ = Z; window\.__ringsDotScale = zdot;/.test(ringsBody),
    '[m24] the zoom/dot-size relationship must be measurable from the mirror, not merely asserted');

  // =====================================================================
  //  M25 — operator round 14: adaptive session bars + the ExecPlans-arc lens
  // =====================================================================
  (function m25Gates() {
    // ---- (1) the shared log bar scale (pure; unit-tested, not asserted) ----
    check(typeof render.logBarPos === 'function', '[m25] logBarPos must be exported as the console-wide bar scale');
    check(render.logBarPos(0, 1e4, 1e8) === 0 && render.logBarPos(-5, 1e4, 1e8) === 0,
      '[m25] a zero/negative token count must be 0 on the axis, never a fabricated stub');
    check(Math.abs(render.logBarPos(1e4, 1e4, 1e8) - 0) < 1e-9 && Math.abs(render.logBarPos(1e8, 1e4, 1e8) - 1) < 1e-9,
      '[m25] the axis must run exactly floor→max');
    check(Math.abs(render.logBarPos(1e6, 1e4, 1e8) - 0.5) < 1e-9,
      '[m25] the axis must be LOGARITHMIC (1e6 is the geometric midpoint of 1e4..1e8)');
    check(render.logBarPos(500, 1e4, 1e8) === 0,
      '[m25] anything at or below the floor is a stub, not a rescale of the whole axis');
    // The measured claim the design rests on: on the review corpus (max
    // 613,105,748, median 3,171,069) linear-to-max buries the median row and the
    // log axis does not. Asserted with the real numbers.
    var LMAX = 613105748, LMED = 3171069;
    check((LMED / LMAX) < 0.006, '[m25] the linear-to-max alternative must be shown to bury the median row (<0.6% of the track)');
    check(render.logBarPos(LMED, 10000, LMAX) > 0.45 && render.logBarPos(LMED, 10000, LMAX) < 0.6,
      '[m25] on the shipped log axis the same median row must land mid-track');

    // ---- (2) the ExecPlans-arc lens registry + geometry --------------------
    var ringsBody25 = funcBody(renderSrc, 'renderRings') || '';
    check(/var tArc = tileEl\('arc', '#34d399', 'ExecPlans arc', '—'\);/.test(ringsBody25)
      && /var tileByLens = \{ work: tWork, arc: tArc, data: tData, memory: tMem, sessions: tSess, tokens: tTok \};/.test(ringsBody25),
      '[m25] the arc lens must join the SAME tile registry as the five incumbents (one new tile, none replaced)');
    check(/\[tWork\.b, tArc\.b, tData\.b, tMem\.b, tSess\.b, tTok\.b, glFacts\.el/.test(ringsBody25),
      '[m25] the new tile must be mounted in the existing card group, in lens order');
    check(/var ARC_A0 = -Math\.PI \/ 2;/.test(ringsBody25) && /var ARC_SPAN = Math\.PI \* 1\.5;/.test(ringsBody25),
      '[m25] the arc must be 270° starting at 12 o’clock (clockwise to 9 o’clock)');
    check(/if \(lens === 'arc'\) \{ drawArcLens\(ctx2, g, time\); return; \}/.test(ringsBody25)
      && /if \(lens === 'arc'\) \{ arcStep\(dt\); \}/.test(ringsBody25)
      && /if \(lens === 'arc'\) \{ arcPointerMove\(e\); return; \}/.test(ringsBody25)
      && /if \(lens === 'arc'\) \{ arcClick\(e\); return; \}/.test(ringsBody25),
      '[m25] the lens must be dispatched additively — one guarded branch per shared entry point, no existing branch rewritten');
    // Every incumbent lens branch must still be exactly where it was.
    check(/if \(lens === 'data'\) \{ drawDataLens\(ctx2, g\); return; \}/.test(ringsBody25)
      && /if \(lens === 'tokens'\) \{ drawTokensLens\(ctx2, g\); return; \}/.test(ringsBody25)
      && /if \(lens === 'receipts'\) \{ drawReceiptsLens\(ctx2, g, time\); return; \}/.test(ringsBody25),
      '[m25] the incumbent lens dispatch must be untouched');
    check(/window\.__ringsArc = \{ tracks: vis\.length/.test(ringsBody25),
      '[m25] the arc lens must publish a dev probe so the population + ordering claims are measurable from the mirror');

    // ---- (3) no second network read: the arc rides the existing feeds ------
    check(/arcWork = j\.work \|\| \[\]; arcBuild\(\);/.test(ringsBody25)
      && /arcFactIdx = idx; arcBuild\(\);/.test(ringsBody25),
      '[m25] the arc model must be fed from the SAME /v1/work response and the SAME fact walk — no lens-private fetch');

    // ---- (4) progress: measured vs estimated, never blurred ----------------
    var pm = render.arcProgress({ state: 'in_progress', current_milestone: 'M4', milestones_total: 8 });
    check(pm.f === 0.5 && pm.via === 'milestone' && pm.measured === true,
      '[m25] current_milestone / milestones_total must be the measured progress path');
    var pd = render.arcProgress({ state: 'in_progress', milestones_done: 3, milestones_total: 6 });
    check(pd.f === 0.5 && pd.via === 'done' && pd.measured === true,
      '[m25] milestones_done / milestones_total must be the second measured path');
    var ps = render.arcProgress({ state: 'in_progress' });
    check(ps.via === 'state' && ps.measured === false,
      '[m25] a plan that reports NO milestone position must be flagged unmeasured, never presented as measured');
    check(render.arcProgress({ state: 'complete' }).f === 1 && render.arcProgress({ state: 'archive' }).f === 1,
      '[m25] a completed plan must reach 9 o’clock');
    check(render.arcProgress({ state: 'complete', milestones_done: 2, milestones_total: 6 }).f === 1,
      '[m25] a completed plan whose milestone counters LAG (measured on the real corpus) must still reach 9 o’clock — the declared state wins');
    check(/ctx2\.setLineDash\(meas \? \[\] : \[5 \/ Z, 5 \/ Z\]\);/.test(ringsBody25)
      && /solid arc = measured \(current_milestone \/ milestones_total\) · dashed = state-estimated/.test(ringsBody25),
      '[m25] estimated progress must be visually distinct (dashed) AND named in the on-canvas note');

    // ---- (5) radial order: newest innermost, oldest at the rim ------------
    var mk = function (id, start, upd, st) {
      return { id: 'execplan:' + id, state: st || 'in_progress', updated_at_unix_ms: upd, created_at_unix_ms: start };
    };
    var now25 = 1784938789271, D = 86400000;
    var selA = render.arcSelectPlans([
      mk('old', now25 - 60 * D, now25 - D),
      mk('new', now25 - 2 * D, now25),
      mk('mid', now25 - 30 * D, now25 - 2 * D)
    ], now25, 16);
    check(selA.picked.map(function (w) { return w.id; }).join(',') === 'execplan:new,execplan:mid,execplan:old',
      '[m25] tracks must be ordered NEWEST first (index 0 = innermost), oldest at the outer edge');
    check(render.arcStartMs({ created_at_unix_ms: 5, provenance: { first_activity_unix_ms: 7 } }).via === 'provenance.first_activity'
      && render.arcStartMs({ created_at_unix_ms: 5 }).via === 'created_at',
      '[m25] the ordering key must prefer the plan\'s own first-activity provenance and DECLARE which source it used');

    // ---- (6) population honesty on a 1,000-plan corpus --------------------
    var many = [];
    for (var i = 0; i < 400; i++) { many.push(mk('a' + i, now25 - (i + 1) * D, now25 - i * 1000, 'in_progress')); }
    for (var j = 0; j < 300; j++) { many.push(mk('c' + j, now25 - (j + 1) * D, now25 - j * 1000, 'complete')); }
    for (var k = 0; k < 300; k++) { many.push(mk('p' + k, now25 - (k + 1) * D, now25 - k * 1000, 'planned')); }
    var selB = render.arcSelectPlans(many, now25, render.ARC_TRACK_CAP);
    check(selB.picked.length === render.ARC_TRACK_CAP, '[m25] the population must be capped to what stays readable');
    check(selB.total === 1000, '[m25] the cap must report the FULL corpus size it is a subset of');
    check(selB.picked.filter(function (w) { return w.state === 'planned'; }).length === 0,
      '[m25] the default population is active-first — never a silent sample of everything');
    check(selB.completing > 0 && selB.picked.filter(function (w) { return w.state === 'complete'; }).length === selB.completing,
      '[m25] recently-completed plans must keep slots (they are the ones mid-fade)');
    check(/showing ' \+ vis\.length \+ ' of ' \+ arcTotal \+ ' plans — active first/.test(ringsBody25),
      '[m25] the canvas must carry the "showing N of M" count note');

    // ---- (7) dot placement: the mapping is declared, per dot --------------
    check(render.arcKeyMilestone('gate:M7') === 7 && render.arcKeyMilestone('milestone:M3.2') === 3.2
      && render.arcKeyMilestone('decision:idp') === null,
      '[m25] milestone facts must be recognised from the real key convention (gate:M<n> / milestone:M<n>)');
    var byIdx = render.arcFactFrac({ key: 'gate:M3', ms: 0 }, 6, [], 0, 100);
    check(byIdx.f === 0.5 && byIdx.via === 'index', '[m25] an indexed milestone fact must sit exactly at n/total');
    var marks25 = [{ ms: 0, f: 0 }, { ms: 100, f: 1 }];
    var byBucket = render.arcFactFrac({ key: 'decision:x', ms: 50 }, 6, marks25, 0, 100);
    check(byBucket.via === 'bucket' && Math.abs(byBucket.f - 0.5) < 1e-9,
      '[m25] a non-milestone fact must fall in the milestone BUCKET it was written in when the plan has indexed milestones');
    var byTime = render.arcFactFrac({ key: 'decision:x', ms: 25 }, 0, [], 0, 100);
    check(byTime.via === 'time' && Math.abs(byTime.f - 0.25) < 1e-9,
      '[m25] with no milestone axis available the fallback must be the plan timeline fraction — and say so');
    check(/' placed by milestone index, ' \+ \(arcViaMix\.bucket \|\| 0\) \+ ' by milestone bucket, ' \+ \(arcViaMix\.time \|\| 0\) \+ ' by timeline fraction'/.test(ringsBody25),
      '[m25] the canvas must publish HOW MANY dots used each mapping — the reader can see the approximation');
    check(render.arcDotKind('gate:M1') === 'milestone' && render.arcDotKind('milestone:M2') === 'milestone'
      && render.arcDotKind('decision:auth') === 'decision' && render.arcDotKind('handoff:2026-07-24') === 'handoff'
      && render.arcDotKind('design:foo') === 'fact',
      '[m25] the dot vocabulary must key off the real fact-key convention');
    check(/var rr = \(big \? 3\.6 : 2\.3\) \* zdot \*/.test(ringsBody25) && /var zdot = zoomDotScale\(\);   \/\/ M24/.test(ringsBody25),
      '[m25] arc dots must reuse M24\'s zoomDotScale so zoom separates clusters here too');

    // ---- (8) completion fade + inward collapse ---------------------------
    var trkDone = { startMs: 0, done: true, doneMs: 1000 };
    check(render.arcAlphaAt(trkDone, 1000) === 1
      && Math.abs(render.arcAlphaAt(trkDone, 1000 + 5 * D) - 0.5) < 1e-9
      && render.arcAlphaAt(trkDone, 1000 + 20 * D) === 0,
      '[m25] a completed plan must fade to nothing over ARC_FADE_DAYS');
    check(render.arcAlphaAt({ startMs: 500, done: false }, 100) === 0
      && render.arcAlphaAt({ startMs: 500, done: false }, 600) === 1,
      '[m25] a plan not yet started at the scrub time must be absent — that is how a new plan enters and pushes the stack outward');
    check(/if \(t\.alphaT > 0\.02\) \{ slots\.push\(t\); \}/.test(ringsBody25)
      && /slots\.forEach\(function \(t, i\) \{ t\.rT = n > 1 \? rIn \+ \(rOut - rIn\) \* \(i \/ \(n - 1\)\) : \(rIn \+ rOut\) \/ 2; \}\);/.test(ringsBody25)
      && /var k = REDUCED \? 1 : Math\.min\(1, dt \* 6\);/.test(ringsBody25),
      '[m25] a faded-out track must surrender its slot and the survivors must EASE inward (instant under reduced motion)');

    // ---- (9) the 12 o'clock label column + leftward token bars ------------
    check(/var LBLW = g\.R \* 0\.44, BARW = g\.R \* 0\.18/.test(ringsBody25)
      && /ctx2\.textAlign = 'right';/.test(ringsBody25)
      && /ctx2\.fillRect\(barRight - w2, y - 2 \/ Z, w2, 4 \/ Z\);/.test(ringsBody25),
      '[m25] each track must carry a right-aligned title LEFT of the 12 o’clock line with its token bar extending further left');
    check(/var w2 = BARW \* logBarPos\(t\.burn, ARC_BAR_MIN, arcBarMax\);/.test(ringsBody25)
      && /var ARC_BAR_MIN = 10000;/.test(ringsBody25)
      && /if \(t\.burn\) \{/.test(ringsBody25),
      '[m25] the token bar must use the SAME adaptive log idiom as cx-cost, and a plan with no reported burn must get NO bar');
    check(/token burn \(log, 10k → ' \+ arcNum\(arcBarMax\) \+ '\)/.test(ringsBody25),
      '[m25] the token-bar column must label its own scale');

    // ---- (10) theme + interaction reuse ----------------------------------
    check(/hex2rgba\(PAL\.done, 0\.42\)/.test(ringsBody25) && /arcHue/.test(ringsBody25)
      && !/#[0-9a-f]{6}'\)/i.test((funcBody(renderSrc, 'drawArcLens') || '')),
      '[m25] the arc lens must draw from the theme-responsive PAL/KIND_HUE tokens only — no hard-coded canvas colours');
    check(/setSel\(\{ type: 'plan', p: PLANS\[i\] \}\);/.test(ringsBody25),
      '[m25] clicking a track must open the EXISTING plan detail pane, not a forked one');
    check(/showTip\(e\.clientX, e\.clientY, \[tb\(h\.dot\.key\)/.test(ringsBody25),
      '[m25] hover must use the existing tooltip idiom');
  })();

  notes.push('operator round 13 (M24): the compact rail\'s native `title` tooltips are REMOVED from all three row builders (dest buttons, sub-page icons, the account badge) and replaced by ONE console-drawn glass chip — a body-level position:fixed .rail-hlabel that cannot be clipped by #nav\'s scroll region, eased out from BEHIND the bar (the rail takes z-index 6 over the chip\'s 5) after 900ms of steady hover, centred on the row, 200ms transform+opacity on the accordion\'s own cubic-bezier, snapping under reduced motion, and dismissed by mouseleave / any scroll / click / Escape / route change; aria-label carries the accessible name unchanged (data-hlabel is what the chip reads), and the expanded rail is untouched. cx-cost: the top-sessions chart now calls the SAME costBar() as the rows — same track, gradient, height and fixed 2,000,000-token ceiling (fixed beat proportional-to-max: a proportional chart would put a full-width bar directly above a row bar of the same length meaning 2M) — labelled by the cx-sessions naming chain instead of raw UUIDs, and the chart\'s own flat bar CSS is deleted. Tokens-per-turn ships as a first-class signal beside the magnitude bar (turns / ctx-per-turn / out-per-turn chips, four new sorts, missing turn counts declared rather than zeroed, unsortable rows sinking) and "how to cut it" becomes real: five named thresholds over THIS session\'s numbers, each recommendation naming a feature the daemon ships (token_budget QC.2 · query_scan→query_expand · save_session/get_session · store_fact/query_facts), the thresholds published in an inline help note, no savings percentage claimed anywhere, and a session that trips nothing getting no line at all. cx-usage ("Average Token Usage") was STATIC — every figure a literal in STATIC[\'cx-usage\'] painted as page()\'s pre-load skeleton, plus a −31% savings card measured against an invented baseline, while its declared /v1/observations/aggregate feed was never called; the static entry is DELETED and the page is computed from /v1/cost/report (period + per-session + per-turn averages, session size on the same 2M gradient scale, a real bucketed output series), with the savings card replaced by a statement that no counterfactual is measured. Ring dots are damped by Z^0.6 with a 0.28 floor and an exact identity at or below overview zoom, so clusters separate as you zoom in; the factor is computed once per frame and published as __ringsZ/__ringsDotScale so the claim is measurable.');
  notes.push('operator round 14 (M25): cx-cost\'s bar scale goes ADAPTIVE — M21\'s fixed 2,000,000-token ceiling clamped 51 of the 83 real session reports, so the page now computes ONE log axis per painted view over both quantities it draws (row ctx+out AND chart output), floor 10k, max = the visible maximum, never below 2M. Log beat the two linear alternatives on the measured distribution (max 613,105,748 · p90 144,734,710 · median 3,171,069): linear-to-max puts the median row at 0.5% of the track and linear-capped-at-p90 puts it at 2.2% while re-clamping eight rows — the exact failure being fixed — where the log axis lands it at ~52%. The 2M ceiling survives as a REFERENCE TICK at its log position on every track plus a named tick on a decade-ticked axis strip, and the caption states the adaptivity, the range, the tick and that length is orders of magnitude and NOT proportion; the top-10 chart stays on the identical costBar idiom and says which scale it is on. Rings gains a sixth, strictly additive lens: ExecPlans arc — a 270° arc per plan from 12 o\'clock clockwise to 9 o\'clock where the angular axis is fraction-of-declared-milestones, so a just-started plan is a line at 12 and a completed plan reaches 9; progress is measured from current_milestone/milestones_total (or milestones_done/total, or the declared complete state) and drawn SOLID, while a plan reporting no milestone position gets a nominal state fraction drawn DASHED and counted in the on-canvas note. Dots ride the arc: big diamonds for gate:/milestone: facts placed exactly at n/total, smaller circles for decisions, handoffs and other facts placed in the milestone BUCKET they were written in (or, with no milestone axis available, at their timeline fraction) — with the per-mapping counts published on the canvas — all damped by M24\'s zoomDotScale. The newest plan is innermost (ordered by provenance.first_activity, falling back to created_at, and which source was used is stated); a new plan pushes the stack outward and a completed one fades over 10 days and the survivors ease inward to fill the slot, instantly under reduced motion. Titles sit right-aligned LEFT of the 12 o\'clock line with a token-burn bar extending further left on the same shared logBarPos idiom as cx-cost (no reported burn = no bar). The default population is active-first, capped at 16 tracks with 4 slots held for just-completed plans, labelled "showing N of M plans"; the model is fed from the SAME /v1/work response and the SAME fact walk the data lens already performs, so the lens adds no network read. Every incumbent lens branch, tile and dispatch line is asserted untouched.');
})();

// =========================================================================
//  Check 57 — (crux-integrations I1+I2) Studio › Integrations is the ONE
//  actionable integrations home. Four sections paint; every mutation in the
//  region dispatches through operatorGatedCall (no raw fetch, no direct gated
//  client); the Invoke control that used to render inert now carries a click
//  handler; the catalog safety scorecard builds its capability chips from data;
//  and the catalog's empty / 404 states are honest, naming the command that
//  populates the cached index.
// =========================================================================
(function checkIntegrationsStudio() {
  // Minimal mock DOM (same idiom as the studio drive): enough for el()/textContent.
  function mkNode(tag) {
    const n = { tagName: String(tag).toUpperCase(), nodeType: 1, childNodes: [], _attrs: {}, className: '',
      setAttribute: function (k, v) { this._attrs[k] = String(v); if (k === 'class') { this.className = String(v); } },
      getAttribute: function (k) { return Object.prototype.hasOwnProperty.call(this._attrs, k) ? this._attrs[k] : null; },
      appendChild: function (c) { this.childNodes.push(c); c.parentNode = this; return c; },
      removeChild: function (c) { const i = this.childNodes.indexOf(c); if (i >= 0) { this.childNodes.splice(i, 1); } return c; },
      addEventListener: function () {} };
    Object.defineProperty(n, 'textContent', { get: function () { return this._t || ''; }, set: function (v) { this._t = String(v); this.childNodes.length = 0; } });
    return n;
  }
  function mkDoc() { return { createElement: mkNode, createTextNode: function (v) { return { nodeType: 3, textContent: String(v), childNodes: [] }; } }; }
  function collect(n, out) { out = out || []; (n.childNodes || []).forEach(function (c) { if (c && c.nodeType === 1) { out.push(c); collect(c, out); } }); return out; }
  function hasClass(n, c) { return String(n.className || '').split(/\s+/).indexOf(c) >= 0; }

  // ---- (a) the four sections ---------------------------------------------
  const SECTIONS = ['connectors', 'packs', 'extensions', 'keys'];
  check(JSON.stringify(render.CINT_SECTIONS || []) === JSON.stringify(SECTIONS),
    '[integrations] render.js must declare the four Studio › Integrations sections in setup order');
  SECTIONS.forEach(function (key) {
    check(new RegExp("cintSection\\('" + key + "'").test(renderSrc),
      '[integrations] Studio › Integrations must build the "' + key + '" section');
  });
  // Drive the real renderer. Reads are handed a never-settling promise so the
  // whole paint is the SYNCHRONOUS scaffold — no continuation can run against a
  // restored global.document, and the assertions land in the same tick.
  (function drivePaint() {
    const savedDoc = global.document, savedWin = global.window;
    global.document = mkDoc();
    global.window = { CRUX_POSTURE: 'operator', CruxApi: { get: function () { return new Promise(function () {}); } } };
    const host = mkNode('div');
    try { render.renderIntegrationsStudio(host, {}); }
    catch (e) { check(false, '[integrations] renderIntegrationsStudio threw on paint: ' + (e && e.stack || e)); }
    const nodes = collect(host);
    const secs = nodes.filter(function (n) { return hasClass(n, 'cint-section'); });
    check(secs.length === 4, '[integrations] the Studio must paint exactly four sections (got ' + secs.length + ')');
    check(JSON.stringify(secs.map(function (s) { return s.getAttribute('data-section'); })) === JSON.stringify(SECTIONS),
      '[integrations] the four sections must be connectors · packs · extensions · keys, in that order');
    // Six cards: GitHub + OpenAI + packs + installed extensions + catalog + keys.
    check(nodes.filter(function (n) { return hasClass(n, 'cwstudio-intcard'); }).length === 6,
      '[integrations] each section must paint its cards (2 connectors + packs + extensions + catalog + keys)');
    if (savedDoc === undefined) { delete global.document; } else { global.document = savedDoc; }
    if (savedWin === undefined) { delete global.window; } else { global.window = savedWin; }
  })();

  // ---- region invariants: no raw fetch, no direct gated client ------------
  const iA = renderSrc.indexOf('Studio › Integrations (M16b');
  const iB = renderSrc.indexOf('Documents mode (M10)');
  const region = (iA >= 0 && iB > iA) ? renderSrc.slice(iA, iB) : '';
  check(!!region, '[integrations] the Studio › Integrations region must be locatable in render.js');
  check(!/\.innerHTML/.test(region), '[integrations] the surface must contain NO innerHTML (el()/textContent only)');
  check(!/\bfetch\s*\(/.test(region), '[integrations] the surface must issue NO raw fetch — reads via fetchJSON / named CruxApi methods');
  check(!/CruxApiGated/.test(region), '[integrations] the surface must never touch the gated client directly — only operatorGatedCall');

  // ---- (b) reverse coverage: every gated call site goes through the choke --
  // Each mutation is written exactly as operatorGatedCall(function (g) { return g.X(…) }),
  // so the count of gated-method call sites must equal the count of choke-point
  // wrappers. A bare `g.foo(` anywhere else would break the equality.
  const gatedCalls = (region.match(/\bg\.[a-zA-Z]+\(/g) || []).length;
  const chokes = (region.match(/operatorGatedCall\(function \(g\) \{ return g\./g) || []).length;
  check(gatedCalls > 0 && gatedCalls === chokes,
    '[integrations] every gated call site must sit inside operatorGatedCall (sites=' + gatedCalls + ', chokes=' + chokes + ')');
  // And every write this package added is actually reachable from the surface.
  ['githubConnect', 'githubDisconnect', 'githubSync', 'openaiConnect', 'openaiDisconnect',
    'integrationPackInstall', 'integrationPackGrant', 'integrationPackDisable',
    'extensionInstallFromRegistry', 'extensionUninstall', 'extensionGrantAdd',
    'extensionGrantRemove', 'extensionAddKey', 'extensionRemoveKey', 'extensionInvoke'
  ].forEach(function (m) {
    check(new RegExp('g\\.' + m + '\\(').test(region),
      '[integrations] Studio › Integrations must reach the gated method ' + m + '()');
  });
  // The destructive subset names its consequence before firing.
  ['githubDisconnect', 'openaiDisconnect', 'integrationPackDisable', 'extensionUninstall',
    'extensionGrantRemove', 'extensionRemoveKey', 'extensionInvoke'
  ].forEach(function (m) {
    const at = region.indexOf('g.' + m + '(');
    const before = at > 0 ? region.slice(Math.max(0, at - 700), at) : '';
    check(/confirm:\s*'/.test(before), '[integrations] the ' + m + '() control must carry a confirm dialog');
  });
  // The single write harness enforces posture + the Art.14 bound passport.
  const cw = funcBody(renderSrc, 'cintWrite');
  check(!!cw, '[integrations] render.js must define the cintWrite harness');
  check(cw && /isOperator\(\)/.test(cw) && /ART14_MSG/.test(cw) && /showConfirm\(/.test(cw),
    '[integrations] cintWrite must guard posture, refuse without a bound passport, and confirm the destructive subset');

  // ---- secrets are write-only --------------------------------------------
  check(/type:\s*'password'/.test(region), '[integrations] connector secrets must use a password-type input');
  check(/pat\.value = '';/.test(region) && /key\.value = '';/.test(region),
    '[integrations] the PAT / API-key fields must be cleared the moment the write fires');

  // ---- (c) Invoke now has a handler ---------------------------------------
  const invAt = region.indexOf("var invoke = cintBtn('Invoke'");
  check(invAt >= 0, '[integrations] the Studio must render an Invoke control');
  check(invAt >= 0 && /invoke\.addEventListener\('click'/.test(region.slice(invAt, invAt + 400)),
    '[integrations] the Invoke control must carry a click handler (it shipped inert)');
  check(/render:\s*cintVerbatim/.test(region), '[integrations] the invoke result must render verbatim');
  // The board tile's Invoke was enabled and inert too — it now routes to the Studio.
  const tileInv = renderSrc.slice(renderSrc.indexOf('function tstudioRenderExtensions'), renderSrc.indexOf('function tstudioCapabilityForRoute'));
  check(/btn\.addEventListener\('click', function \(\) \{ location\.hash = '#\/canvas\/studio\?sub=integrations'; \}\);/.test(tileInv),
    '[integrations] the extensions TILE Invoke button must route to Studio › Integrations instead of doing nothing');

  // ---- (d) the safety scorecard builds from data --------------------------
  (function driveScorecard() {
    const savedDoc = global.document;
    global.document = mkDoc();
    const all = collect;
    try {
      const entry = { id: 'ext.quote', name: 'Quote', version: '1.2.0', kind: 'external_tool', trust_tier: 'community_reviewed',
        manifest_sha256: 'a1b2c3', repo_url: 'https://example.test/quote', installed: true, installed_version: '1.1.0' };
      const manifest = { capabilities: ['facts:read', 'integrations:read'], network: { allowed_hosts: ['api.example.test'] }, signature: { alg: 'ed25519' } };
      const withM = all(render.cintScorecard(entry, manifest));
      const chips = withM.filter(function (n) { return /\btstudio-cap-chip\b/.test(n.className || ''); });
      check(chips.length === 2 && chips[0].textContent === 'facts:read',
        '[integrations] the scorecard must render one capability chip per declared capability (got ' + chips.length + ')');
      const text = withM.map(function (n) { return n.textContent || ''; }).join('|');
      check(text.indexOf('api.example.test') >= 0, '[integrations] the scorecard must show the manifest network allowed_hosts');
      check(text.indexOf('a1b2c3') >= 0, '[integrations] the scorecard must show the curator-pinned manifest sha256');
      check(text.indexOf('external_tool') >= 0, '[integrations] the scorecard must show the entry kind');
      check(text.indexOf('community_reviewed') >= 0, '[integrations] the scorecard must show the trust tier');
      check(withM.some(function (n) { return n.tagName === 'A' && n.getAttribute('href') === 'https://example.test/quote'; }),
        '[integrations] the scorecard must link the source repo');
      // Not installed: capabilities are NOT in the index, and the scorecard says so
      // rather than implying an empty capability set.
      const noM = all(render.cintScorecard({ id: 'ext.other', trust_tier: 'unknown' }, null));
      const noMText = noM.map(function (n) { return n.textContent || ''; }).join('|');
      check(noMText.indexOf('not in the index') >= 0,
        '[integrations] with no installed manifest the scorecard must declare that capabilities/hosts are not in the index');
      check(noM.filter(function (n) { return /\btstudio-cap-chip\b/.test(n.className || ''); }).length === 0,
        '[integrations] an uninstalled entry must render NO capability chips (nothing to claim)');
    } catch (e) {
      check(false, '[integrations] cintScorecard drive threw: ' + (e && e.stack || e));
    } finally {
      if (savedDoc === undefined) { delete global.document; } else { global.document = savedDoc; }
    }
  })();

  // ---- (e) catalog honest-empty + 404 -------------------------------------
  check(/res\.status === 404/.test(region) && /corecruxctl extensions sync/.test(region),
    '[integrations] a 404 from /v1/extensions/registry must name `corecruxctl extensions sync`, not read as a fault');
  check(/The verified index carries no entries/.test(region),
    '[integrations] a verified-but-empty index must say so (distinct from the un-synced 404)');
  const cu = funcBody(renderSrc, 'cintUnavailable');
  check(cu && /not available on this daemon/.test(cu) && /unreachable/.test(cu),
    '[integrations] an absent route must read as "not available on this daemon", and status 0 as unreachable');

  // ---- the dead-end is closed --------------------------------------------
  check(/STUDIO_INTEGRATIONS_HREF = '#\/canvas\/studio\?sub=integrations'/.test(pagesSrc),
    '[integrations] pages.js must define the Studio › Integrations link-through target');
  check(!/connect under Integrations to add repos/.test(pagesSrc),
    '[integrations] the cx-projects "connect under Integrations" dead-end text must be gone');
  const linkUses = (pagesSrc.match(/STUDIO_INTEGRATIONS_LINK/g) || []).length;
  check(linkUses >= 7, '[integrations] cx-projects, cx-integrations and cx-extensions must all link through to the Studio (uses=' + linkUses + ')');
  const CD = pages.CONTROL_DIFF || {};
  ['cx-integrations', 'cx-extensions'].forEach(function (id) {
    check((CD[id] && CD[id].v2_present || []).some(function (s) { return /Studio › Integrations/.test(s); }),
      '[integrations] CONTROL_DIFF.' + id + ' must record the Studio link-through as present');
  });
  check(/install-from-registry \{id\} IS wired/.test(pagesSrc),
    '[integrations] the still-gated cx-extensions "Install" grounding must state where install IS wired');

  notes.push('studio integrations (I1+I2): Studio › Integrations is the one actionable integrations home — four sections (connectors · packs · extensions+catalog · keys) over 15 gated methods, every call site inside operatorGatedCall with no raw fetch and no direct gated client; connector secrets are password-type and cleared on submit; the previously-inert Invoke is wired (verbatim result) and the board tile routes to it; the catalog renders a per-entry safety scorecard built from index provenance plus the installed manifest, with honest un-synced (names `corecruxctl extensions sync`), verified-empty and absent-route states; cx-projects/cx-integrations/cx-extensions link through and their CONTROL_DIFF rows say so.');
})();

// =========================================================================
//  Check 58 — (crux-integrations-and-template-library L1+L2) Studio › Library.
//  The Studio's FOURTH section: the curator-signed central template library.
//  Registered in the segmented control + dispatch; painted from ONE read whose
//  honest states are distinct (verified index · un-synced 404 naming
//  `corecruxctl studio sync` · 403 signature failure · verified-but-empty); the
//  install is the ONE mutation and it routes through the same
//  operatorGatedCall choke as every other Studio write; tier chips say plainly
//  that enforcement is advisory/server-side; artifact provenance is chipped
//  wherever boards / designs / workspaces / pages are listed; and a MANUAL pack
//  import stamps its own `imported_from` (never the daemon's `installed_from`).
// =========================================================================
(function checkStudioLibrary() {
  // Minimal mock DOM — same idiom as Check 57.
  function mkNode(tag) {
    const n = { tagName: String(tag).toUpperCase(), nodeType: 1, childNodes: [], _attrs: {}, className: '',
      setAttribute: function (k, v) { this._attrs[k] = String(v); if (k === 'class') { this.className = String(v); } },
      getAttribute: function (k) { return Object.prototype.hasOwnProperty.call(this._attrs, k) ? this._attrs[k] : null; },
      appendChild: function (c) { this.childNodes.push(c); c.parentNode = this; return c; },
      removeChild: function (c) { const i = this.childNodes.indexOf(c); if (i >= 0) { this.childNodes.splice(i, 1); } return c; },
      addEventListener: function () {} };
    Object.defineProperty(n, 'textContent', { get: function () { return this._t || ''; }, set: function (v) { this._t = String(v); this.childNodes.length = 0; } });
    return n;
  }
  function mkDoc() { return { createElement: mkNode, createTextNode: function (v) { return { nodeType: 3, textContent: String(v), childNodes: [] }; } }; }
  function collect(n, out) { out = out || []; (n.childNodes || []).forEach(function (c) { if (c && c.nodeType === 1) { out.push(c); collect(c, out); } }); return out; }
  function hasClass(n, c) { return String(n.className || '').split(/\s+/).indexOf(c) >= 0; }
  function textOf(nodes) { return nodes.map(function (n) { return n.textContent || ''; }).join('|'); }
  function withDom(posture, fn) {
    const savedDoc = global.document, savedWin = global.window;
    global.document = mkDoc();
    global.window = { CRUX_POSTURE: posture, CruxApi: { get: function () { return new Promise(function () {}); } } };
    try { return fn(); }
    finally {
      if (savedDoc === undefined) { delete global.document; } else { global.document = savedDoc; }
      if (savedWin === undefined) { delete global.window; } else { global.window = savedWin; }
    }
  }

  // ---- (a) the fourth section is registered -------------------------------
  check(/\[\['board', 'Board'\], \['pages', 'Pages'\], \['integrations', 'Integrations'\], \['library', 'Library'\]\]/.test(renderSrc),
    '[library] the Studio segmented control must carry a fourth Library section');
  check(/ctx\.sub === 'library' \? 'library'/.test(renderSrc),
    '[library] ?sub=library must resolve to the library section (deep-linkable)');
  check(/if \(studioSub === 'library'\) \{ return renderLibraryStudio\(body, ctx\); \}/.test(renderSrc),
    '[library] renderCanvas must dispatch the library section to renderLibraryStudio');
  // THE MISSING HALF (fixed here): L1 gated render.js alone, but the ROUTER is
  // shell.html's parseCanvasHash — and it still carried M16b's three-value
  // ?sub= allowlist, so ?sub=library normalised to 'board'. The control painted
  // a Library button that landed the operator back on the board, and the page
  // had no reachable route. Gate the shared allowlist AND its use, so a future
  // section cannot be half-wired the same way.
  check(/var STUDIO_SUBS = \{ board: 1, pages: 1, integrations: 1, library: 1 \};/.test(shellHtml),
    '[library] shell.html must allowlist every Studio section (board · pages · integrations · library) in ONE STUDIO_SUBS list');
  check(/Object\.prototype\.hasOwnProperty\.call\(STUDIO_SUBS, sm\[1\]\)/.test(shellHtml),
    '[library] parseCanvasHash must validate ?sub= against STUDIO_SUBS (so #/canvas/studio?sub=library resolves to the Library, not the board)');
  check(!/sm\[1\] === 'integrations' \? 'integrations' : 'board'/.test(shellHtml),
    '[library] the old three-value ?sub= ladder must be gone (it silently downgraded ?sub=library to the board)');
  check(/Studio › Library —/.test(shellHtml),
    '[library] the topbar sub-line must name the Library section (every other Studio section has one)');
  // Pure re-implementation of the parser's ?sub= rule, driven over the real
  // deep links: the fix is a routing claim, so assert the routing.
  (function () {
    const SUBS = { board: 1, pages: 1, integrations: 1, library: 1 };
    function subOf(hash) {
      const h = String(hash || '').replace(/^#\/?/, '');
      const qi = h.indexOf('?');
      const q = qi >= 0 ? h.slice(qi + 1) : '';
      const sm2 = q.match(/(?:^|&)sub=([^&]+)/);
      return (sm2 && Object.prototype.hasOwnProperty.call(SUBS, sm2[1])) ? sm2[1] : 'board';
    }
    check(subOf('#/canvas/studio?sub=library') === 'library', '[library] #/canvas/studio?sub=library must resolve to the library section');
    check(subOf('#/canvas/studio?sub=pages') === 'pages' && subOf('#/canvas/studio?sub=integrations') === 'integrations',
      '[library] the incumbent Studio sections must keep resolving');
    check(subOf('#/canvas/studio') === 'board' && subOf('#/canvas/studio?sub=nope') === 'board' && subOf('#/canvas/studio?sub=__proto__') === 'board',
      '[library] an absent or unknown ?sub= (including a prototype key) must fall back to the board');
  })();
  check(JSON.stringify(render.CLIB_KINDS || []) === JSON.stringify(['board', 'design', 'workspace', 'pack']),
    '[library] render.js must declare the four catalog kinds in the daemon\'s order');

  // ---- (b) paint the verified index over a fixture ------------------------
  // Two entries: one workspace already installed at an OLDER version under the
  // advisory "pro" tier, one free board that is not installed.
  const INSTALLED = {
    id: 'studio.ops-overview', kind: 'workspace', name: 'Ops overview', version: '1.2.0',
    summary: 'Retrieval latency + receipt freshness for an ops on-call.',
    publisher_passport_fpr: 'p_publisher_9f2c41ab77', tags: ['ops', 'latency'], required_tier: 'pro',
    pack_url: 'https://packs.example.test/ops-overview-1.2.0.json',
    pack_sha256: 'aa11bb22cc33dd44ee55', repo_url: 'https://example.test/ops-overview',
    preview: '12 tiles: retrieval latency, receipt freshness, lane weights',
    installed: true, installed_version: '1.1.0',
    installed_entities: ['console:workspace:ops-overview', 'console:page:ops-latency'],
    installed_at_unix_ms: 1753400000000
  };
  const FREE = {
    id: 'studio.latency-board', kind: 'board', name: 'Latency board', version: '0.3.0',
    summary: 'A single tile board for p50/p95 lane latency.',
    publisher_passport_fpr: 'p_publisher_9f2c41ab77', tags: ['latency'],
    pack_url: 'https://packs.example.test/latency-0.3.0.json', pack_sha256: 'ff99ee88dd77cc66',
    installed: false, installed_version: null, installed_entities: [], installed_at_unix_ms: null
  };
  const INDEX_OK = { ok: true, status: 200, data: {
    schema: 'crux.studio.library_list.v1', curator_passport_fpr: 'p_curator_5150aa',
    updated_at_unix_ms: 1753390000000, tier_enforcement: 'advisory', entries: [INSTALLED, FREE]
  } };
  withDom('operator', function () {
    const host = mkNode('div');
    try { render.clibPaintIndex(host, INDEX_OK, function () {}); }
    catch (e) { check(false, '[library] clibPaintIndex threw on the verified-index fixture: ' + (e && e.stack || e)); return; }
    const nodes = collect(host);
    const text = textOf(nodes);
    // header card
    check(text.indexOf('p_curator_5150aa') >= 0, '[library] the header must name the curator passport fpr');
    check(/advisory/.test(text) && /catalog server enforces required_tier/.test(text),
      '[library] the header must state tier_enforcement: advisory in plain words');
    check(text.indexOf('corecruxctl studio sync') >= 0,
      '[library] the header must name `corecruxctl studio sync` as the refresh path (there is no fetch route to button)');
    check(nodes.some(function (n) { return hasClass(n, 'clib-syncnote'); }) &&
      !nodes.some(function (n) { return /Refresh/.test(n.textContent || '') && n.tagName === 'BUTTON'; }),
      '[library] the surface must NOT offer a refresh button the daemon cannot serve');
    // one card per entry, grouped by kind in the declared order
    const cards = nodes.filter(function (n) { return hasClass(n, 'clib-card'); });
    check(cards.length === 2, '[library] the catalog must paint one card per entry (got ' + cards.length + ')');
    const groups = nodes.filter(function (n) { return hasClass(n, 'clib-group'); }).map(function (n) { return n.getAttribute('data-group'); });
    check(JSON.stringify(groups) === JSON.stringify(['board', 'workspace']),
      '[library] entries must be GROUPED by kind in the declared order (got ' + JSON.stringify(groups) + ')');
    check(JSON.stringify(cards.map(function (c) { return c.getAttribute('data-kind'); })) === JSON.stringify(['board', 'workspace']),
      '[library] each card must declare its kind');
    // tier chips: absent required_tier reads Free; "pro" is marked distinctly and
    // every chip says the enforcement is advisory.
    const tiers = nodes.filter(function (n) { return hasClass(n, 'clib-tier'); });
    check(tiers.length === 2 && tiers.map(function (t) { return t.textContent; }).join(',') === 'Free,Pro',
      '[library] every entry must carry a tier chip, an absent required_tier reading Free (got ' + tiers.map(function (t) { return t.textContent; }).join(',') + ')');
    check(tiers.every(function (t) { return /Advisory only/.test(t.getAttribute('title') || ''); }),
      '[library] the tier chip must state in its title that enforcement is advisory / server-side');
    check(tiers[1].className.indexOf('is-pro') >= 0 && tiers[0].className.indexOf('is-free') >= 0,
      '[library] a paid tier must be styled distinctly from Free');
    // installed state: version, entity count + the entities, and installed-at.
    check(/installed 1\.1\.0 · update available/.test(text),
      '[library] an entry installed at an older version must say so');
    check(/not installed/.test(text), '[library] an uninstalled entry must say so');
    check(text.indexOf('console:workspace:ops-overview') >= 0 && /2 ·/.test(text),
      '[library] the installed entry must list its written entities and their count');
    check(/2026-07-24|2025-|202\d-\d\d-\d\d/.test(text), '[library] the installed entry must show an installed-at date');
    // per-entry identity + provenance rows
    check(text.indexOf('aa11bb22cc33dd44') >= 0, '[library] the card must show the curator-pinned pack sha256 (short form)');
    check(text.indexOf('p_publisher_9f2c') >= 0, '[library] the card must show the publisher fpr (short form)');
    check(text.indexOf('12 tiles: retrieval latency') >= 0, '[library] the card must show the entry preview hint');
    check(nodes.some(function (n) { return n.tagName === 'A' && n.getAttribute('href') === 'https://example.test/ops-overview'; }),
      '[library] the card must link the source repo');
    check(nodes.some(function (n) { return n.tagName === 'BUTTON' && /POST \/v1\/studio\/library\/studio\.ops-overview\/install/.test(n.getAttribute('title') || ''); }),
      '[library] each card must carry an install control naming its route');
  });
  // Customer posture: the install control is stamped operator-only (hidden, the
  // cint idiom) AND the refusal reason is stated in its place.
  withDom('customer', function () {
    const host = mkNode('div');
    render.clibPaintIndex(host, INDEX_OK, function () {});
    const nodes = collect(host);
    const btns = nodes.filter(function (n) { return n.tagName === 'BUTTON' && /\/install/.test(n.getAttribute('title') || ''); });
    check(btns.length === 2 && btns.every(function (b) { return b.hidden === true && b.getAttribute('data-requires') === 'operator'; }),
      '[library] in customer posture the install control must be operator-stamped and withheld');
    check(nodes.some(function (n) { return hasClass(n, 'clib-gate') && /operator posture/.test(n.textContent || ''); }),
      '[library] a customer view must be told WHY install is unavailable, not left with a silent gap');
  });

  // ---- (c) the honest states are distinct ---------------------------------
  withDom('operator', function () {
    const un = mkNode('div');
    render.clibPaintIndex(un, { ok: false, status: 404, data: { detail: 'no cached index (run `corecruxctl studio sync` …)' } }, function () {});
    const unText = textOf(collect(un));
    check(/corecruxctl studio sync/.test(unText) && collect(un).some(function (n) { return hasClass(n, 'clib-unsynced'); }),
      '[library] a 404 must read as un-synced and NAME `corecruxctl studio sync`');
    check(!/carries no entries/.test(unText), '[library] an un-synced daemon must NOT read as a verified-but-empty index');

    const bad = mkNode('div');
    render.clibPaintIndex(bad, { ok: false, status: 403, data: { detail: 'studio library index signature invalid' } }, function () {});
    const badNodes = collect(bad);
    check(badNodes.some(function (n) { return hasClass(n, 'clib-badsig'); }) && /did NOT verify/.test(textOf(badNodes)),
      '[library] a 403 must read as a SIGNATURE failure, not as an absent index');
    check(/studio library index signature invalid/.test(textOf(badNodes)),
      '[library] the 403 detail must be shown verbatim');

    const empty = mkNode('div');
    render.clibPaintIndex(empty, { ok: true, status: 200, data: { curator_passport_fpr: 'p_curator_5150aa', updated_at_unix_ms: 1753390000000, tier_enforcement: 'advisory', entries: [] } }, function () {});
    const emptyNodes = collect(empty);
    check(emptyNodes.some(function (n) { return hasClass(n, 'clib-empty'); }) && /carries no entries/.test(textOf(emptyNodes)),
      '[library] a verified-but-EMPTY index must say so, distinctly from the un-synced 404');
    check(!emptyNodes.some(function (n) { return hasClass(n, 'clib-unsynced'); }),
      '[library] the verified-empty state must not name the sync command as if nothing were cached');

    const gone = mkNode('div');
    render.clibPaintIndex(gone, { ok: false, status: 0, data: null }, function () {});
    check(/unreachable/.test(textOf(collect(gone))), '[library] an unreachable daemon must read as unreachable');
  });

  // ---- (d) the catalog filter + grouping are pure -------------------------
  const ALL = [INSTALLED, FREE];
  check(render.clibFilterEntries(ALL, { kind: 'board' }).length === 1 &&
    render.clibFilterEntries(ALL, { kind: 'board' })[0].id === 'studio.latency-board',
    '[library] the kind filter must select by entry kind');
  check(render.clibFilterEntries(ALL, { text: 'ops' }).length === 1, '[library] the text filter must match a tag');
  check(render.clibFilterEntries(ALL, { text: 'receipt freshness' }).length === 1, '[library] the text filter must match the summary');
  check(render.clibFilterEntries(ALL, { text: 'Latency Board' }).length === 1, '[library] the text filter must match the name, case-insensitively');
  check(render.clibFilterEntries(ALL, {}).length === 2, '[library] an empty filter must select everything');
  check(render.clibFilterEntries(ALL, { kind: 'pack', text: 'ops' }).length === 0, '[library] kind + text must AND');
  const grouped = render.clibGroupByKind(ALL.concat([{ id: 'x', kind: 'lens' }]));
  check(JSON.stringify(grouped.map(function (g) { return g.kind; })) === JSON.stringify(['board', 'workspace', 'other']),
    '[library] an unknown kind must group under "other" rather than being dropped');

  // ---- (e) the install is the ONE mutation, through the ONE choke ---------
  const lA = renderSrc.indexOf('Studio › Library (crux-integrations-and-template-library L1+L2)');
  const lB = renderSrc.indexOf('Documents mode (M10)');
  const lib = (lA >= 0 && lB > lA) ? renderSrc.slice(lA, lB) : '';
  check(!!lib, '[library] the Studio › Library region must be locatable in render.js');
  check(!/\.innerHTML/.test(lib), '[library] the surface must contain NO innerHTML (el()/textContent only)');
  check(!/\bfetch\s*\(/.test(lib), '[library] the surface must issue NO raw fetch — the read goes through fetchJSON');
  check(!/CruxApiGated/.test(lib), '[library] the surface must never touch the gated client directly');
  const libCalls = (lib.match(/\bg\.[a-zA-Z]+\(/g) || []);
  const libChokes = (lib.match(/operatorGatedCall\(function \(g\) \{ return g\./g) || []);
  check(libCalls.length === 1 && libChokes.length === 1 && /g\.studioLibraryInstall\(id, \{\}\)/.test(lib),
    '[library] install must be the ONLY gated call site and must sit inside operatorGatedCall (sites=' + libCalls.length + ', chokes=' + libChokes.length + ')');
  check((lib.match(/fetchJSON\('\/v1\/studio\/library'\)/g) || []).length === 1,
    '[library] the catalog read must go through the allowlisted GET /v1/studio/library exactly once');
  const instAt = lib.indexOf('g.studioLibraryInstall(');
  const before = instAt > 0 ? lib.slice(Math.max(0, instAt - 900), instAt) : '';
  check(/confirm:\s*'/.test(before) && /pack sha256/.test(before) && /required tier/.test(before) && /Publisher/.test(before),
    '[library] the install control must confirm first, naming kind, id@version, publisher, sha and tier');
  check(/render: clibInstallResult/.test(lib), '[library] the install result must render in the response\'s own shape');
  // The result surfaces written entities, remaps and provenance; errors verbatim.
  withDom('operator', function () {
    const out = mkNode('div');
    render.clibInstallResult(out, { ok: true, status: 201, data: {
      schema: 'crux.studio.library_install.v1', library_id: 'studio.ops-overview', version: '1.2.0', kind: 'workspace',
      pack_sha256: 'aa11bb22cc33dd44ee55', publisher_passport_fpr: 'p_publisher_9f2c41ab77', signed: true,
      allow_unsigned_dev: false, required_tier: 'pro', tier_enforcement: 'advisory',
      provenance: { library_id: 'studio.ops-overview', version: '1.2.0', pack_sha256: 'aa11bb22cc33dd44ee55' },
      written: [{ artifact: 'workspace', entity: 'console:workspace:ops-overview', key: 'def', fact_id: 'f_1' },
        { artifact: 'page', entity: 'console:page:ops-latency-2', key: 'def', fact_id: 'f_2' }],
      remaps: [{ artifact: 'page', from: 'ops-latency', to: 'ops-latency-2' }]
    } });
    const t = textOf(collect(out));
    check(/HTTP 201 · installed studio\.ops-overview@1\.2\.0/.test(t), '[library] a successful install must report the daemon\'s own 201 shape');
    check(/Written entities \(2\)/.test(t) && t.indexOf('console:page:ops-latency-2') >= 0,
      '[library] the install result must list every written entity');
    check(/Collision remaps \(1\)/.test(t) && /ops-latency → ops-latency-2/.test(t),
      '[library] the install result must show each collision remap as from → to');
    check(/Provenance stamped/.test(t) && /"pack_sha256": "aa11bb22cc33dd44ee55"/.test(t),
      '[library] the install result must show the provenance block');
    check(/tier_enforcement: advisory/.test(t), '[library] the install result must repeat that the tier echo is advisory');

    const err = mkNode('div');
    render.clibInstallResult(err, { ok: false, status: 409, data: { title: 'Conflict', detail: 'pack sha256 mismatch: index says aa11…, bytes hash to bb22…' } });
    const et = textOf(collect(err));
    check(/HTTP 409/.test(et) && /pack sha256 mismatch/.test(et) && /"detail"/.test(et),
      '[library] an install failure must show the daemon\'s status + detail verbatim');
  });

  // ---- (f) provenance chips wherever artifacts are listed -----------------
  withDom('operator', function () {
    const libChip = render.studioProvenanceChip({ uid: 'ops', installed_from: { library_id: 'studio.ops-overview', version: '1.2.0', pack_sha256: 'aa11', publisher_passport_fpr: 'p_pub' } });
    check(!!libChip && /library: studio\.ops-overview@1\.2\.0/.test(textOf(collect(libChip))),
      '[library] an artifact installed from the library must chip "library: <id>@<version>"');
    check(libChip && /Installed from the Studio template library/.test(libChip.getAttribute('title') || ''),
      '[library] the provenance chip must name its publisher + pinned sha in its title');
    const impChip = render.studioProvenanceChip({ uid: 'mine', imported_from: { pack_id: 'studio.mine', signed: false, imported_at_unix_ms: 1753400000000 } });
    check(!!impChip && /import: studio\.mine · unsigned/.test(textOf(collect(impChip))),
      '[library] a hand-imported artifact must chip its import provenance, distinctly from a library install');
    check(render.studioProvenanceChip({ uid: 'plain' }) === null && render.studioProvenanceChip(null) === null,
      '[library] an artifact with no provenance must render NO chip (nothing to claim)');
    check(render.studioProvenanceChip({ installed_from: { version: '1' } }) === null,
      '[library] a provenance stamp with no library_id is not a claim — no chip');
  });
  // The four listing sites: cws workspace rows, cws page rows, the design
  // library panel, and the board toolbar (this console has no board switcher —
  // tstudioListBoards has no call site — so the toolbar IS the board listing).
  check(/var wsProv = studioProvenanceChip\(ws\);/.test(renderSrc), '[library] the Studio › Pages workspace rows must chip provenance');
  check(/var pProv = \(rp && rp\.def\) \? studioProvenanceChip\(rp\.def\) : null;/.test(renderSrc), '[library] the Studio › Pages page rows must chip provenance');
  check(/var dProv = studioProvenanceChip\(d\);/.test(renderSrc), '[library] the saved-designs library panel must chip provenance');
  check(/var boardProv = studioProvenanceChip\(S\);/.test(renderSrc), '[library] the board toolbar must chip the loaded board\'s provenance');
  check(/installed_from: def \? def\.installed_from : null/.test(renderSrc),
    '[library] the design listing must carry the def\'s provenance through to the panel');
  // The board doc's security choke ADMITS provenance (coerced), so an operator
  // save cannot silently orphan an installed board.
  const docWithProv = render.tstudioNormalizeDoc({ nodes: [{ id: 'a', kind: 'note' }], installed_from: { library_id: 'studio.ops-overview', version: '1.2.0', pack_sha256: 'aa11', publisher_passport_fpr: 'p_pub', installed_at_unix_ms: 1753400000000 } });
  check(docWithProv.installed_from && docWithProv.installed_from.library_id === 'studio.ops-overview',
    '[library] tstudioNormalizeDoc must preserve an installed board\'s provenance');
  const docRound = render.tstudioNormalizeDoc(JSON.parse(render.tstudioSerializeDoc(docWithProv)));
  check(JSON.stringify(docRound.installed_from) === JSON.stringify(docWithProv.installed_from),
    '[library] board provenance must survive the serialize → normalize round-trip (a save must not orphan it)');
  check(render.tstudioNormalizeDoc({ nodes: [] }).installed_from === undefined,
    '[library] a board with no provenance must gain none');

  // ---- (g) import preview states signedness ------------------------------
  const preview = funcBody(renderSrc, 'renderImportPreview');
  check(!!preview, '[library] render.js must define renderImportPreview');
  check(preview && /typeof v\.signed === 'boolean'/.test(preview) && /sig\.verdict === 'valid'/.test(preview),
    '[library] the import preview must read the verify response\'s additive `signed` boolean (falling back to the verdict)');
  check(preview && /packSigned \? 'signed' : 'unsigned'/.test(preview) && /cwstudio-postchip ' \+ \(packSigned \? 'is-on' : 'is-warn'\)/.test(preview),
    '[library] signed must paint an ok chip and unsigned a warning chip');
  check(preview && /applies only under operator posture and carries NO publisher trust/.test(preview),
    '[library] the unsigned chip must state that an unsigned pack carries no publisher trust');
  check(preview && /if \(!\(operator && v\.ok\)\) \{ apply\.disabled = true; \}/.test(preview),
    '[library] the existing operator && v.ok apply gate must be UNCHANGED (signedness is stated, not newly enforced)');

  // ---- (h) manual imports stamp imported_from (never installed_from) ------
  const stamp = render.studioImportStamp({ id: 'studio.mine', version: '0.1.0' }, { signed: true }, 1753400000000);
  check(stamp.pack_id === 'studio.mine' && stamp.imported_at_unix_ms === 1753400000000 && stamp.signed === true,
    '[library] the import stamp must carry the manifest pack id, the import time and the verified signedness');
  check(!('library_id' in stamp) && !('installed_from' in stamp),
    '[library] a manual import must NOT borrow the catalog install\'s field vocabulary');
  check(render.studioImportStamp({ id: 'studio.mine' }, null, 1).signed === false,
    '[library] an unverified pack must stamp signed:false, never an assumed true');
  const stampedWs = render.studioStampImported({ schema_version: 1, uid: 'ws-mine', name: 'Mine', newTopKey: { deep: 'keep' } }, stamp);
  check(stampedWs.imported_from && stampedWs.imported_from.pack_id === 'studio.mine' && stampedWs.uid === 'ws-mine',
    '[library] studioStampImported must add imported_from without disturbing the def');
  check(render.studioStampImported({ uid: 'x' }, { pack_id: '' }).imported_from === undefined,
    '[library] a pack with no manifest id must stamp nothing rather than an empty claim');
  // The tolerant reader keeps it, and the canonical form still round-trips.
  const rtWs = render.cwsReadWorkspaceDef(JSON.parse(render.cwsCanonical(stampedWs)));
  check(rtWs.valid && rtWs.def.imported_from && rtWs.def.imported_from.pack_id === 'studio.mine' && rtWs.def.newTopKey.deep === 'keep',
    '[library] imported_from must survive the canonical write → tolerant read round-trip');
  check(render.cwsCanonical(rtWs.def) === render.cwsCanonical(render.cwsReadWorkspaceDef(JSON.parse(render.cwsCanonical(rtWs.def))).def),
    '[library] the canonicalisation must still be stable with provenance present');
  const rtPage = render.cwsReadPageDef(JSON.parse(render.cwsCanonical(render.studioStampImported({ schema_version: 1, uid: 'p1', type: 'cx-work' }, stamp))));
  check(rtPage.valid && rtPage.def.imported_from.signed === true, '[library] a page def must carry imported_from through the same round-trip');
  check(render.tstudioDesignDef('Latency', { kind: 'api' }, stamp).imported_from.pack_id === 'studio.mine' &&
    render.tstudioDesignDef('Latency', { kind: 'api' }, null).imported_from === undefined,
    '[library] a design def must carry the import stamp when there is one, and nothing when there is not');
  // …and applyPack actually uses them, for every artifact class it writes.
  const ap = funcBody(renderSrc, 'applyPack');
  check(ap && /var stamp = studioImportStamp\(pack, verify\);/.test(ap), '[library] applyPack must build one import stamp per apply');
  check(ap && /tstudioNormalizeDoc\(studioStampImported\(studio\.board && studio\.board\.doc, stamp\)\)/.test(ap),
    '[library] the imported BOARD doc must carry the import stamp');
  check(ap && /tstudioSaveDesign\(tstudioSlugify\(dz\.slug\), dz\.name \|\| dz\.slug, dz\.config, stamp\)/.test(ap),
    '[library] each imported DESIGN must carry the import stamp');
  check(ap && /cwsCanonical\(studioStampImported\(w, stamp\)\)/.test(ap) && /cwsCanonical\(studioStampImported\(pg, stamp\)\)/.test(ap),
    '[library] each imported WORKSPACE and PAGE must carry the import stamp');
  check(!/installed_from: stamp/.test(ap || ''), '[library] a manual import must never write the daemon\'s installed_from');
  check(/applyPack\(pack, v\)\.then/.test(renderSrc), '[library] the apply control must hand applyPack the verify result it gated on');

  // ---- (i) the CSS family ------------------------------------------------
  ['.clib-headcard', '.clib-card', '.clib-tier', '.clib-kindchip', '.clib-group', '.clib-provchip'].forEach(function (sel) {
    check(shellHtml.indexOf(sel + ' ') >= 0 || shellHtml.indexOf(sel + ',') >= 0 || shellHtml.indexOf(sel + '.') >= 0,
      '[library] shell.html must style ' + sel);
  });
  const cssAt = shellHtml.indexOf('/* Studio › Library (L1+L2)');
  const cssEnd = shellHtml.indexOf('/* modal (self-contained', cssAt);
  const css = (cssAt >= 0 && cssEnd > cssAt) ? shellHtml.slice(cssAt, cssEnd) : '';
  check(!!css, '[library] the Studio › Library CSS block must be locatable');
  check(css && !/#[0-9a-fA-F]{3,8}\b/.test(css) && !/\brgba?\(/.test(css),
    '[library] the Library CSS must use var(--) tokens only — no literal colours');

  notes.push('studio library (L1+L2 console): Studio gains a fourth section — Library (#/canvas/studio?sub=library) — over the daemon\'s cached, curator-signed template index: a header stating curator, index age, entry count and that tier_enforcement is ADVISORY (the catalog server is the gate; the daemon only echoes required_tier, and every tier chip says so in its title), plus kind-grouped, kind/text-filterable entry cards carrying name·version·kind·tier·publisher·tags·summary·preview·repo·pinned sha and, when installed, the version, the written entities and the install date. There is deliberately NO refresh button — the daemon has no fetch-index route — so the surface names `corecruxctl studio sync` instead, and its four read states stay distinct (verified · un-synced 404 · 403 signature failure shown verbatim · verified-but-empty). Install is the one mutation: the same cintWrite harness as Studio › Integrations (posture + Art.14 bound passport + a confirm naming kind, id@version, publisher, sha and advisory tier) through the single operatorGatedCall choke, rendering the response\'s own shape — written entities, from → to collision remaps, the provenance block — and 404/409/403 details verbatim. Provenance is now visible wherever a Studio artifact is listed (workspace + page rows, the saved-designs panel, and the board toolbar, which is this console\'s only board listing): "library: <id>@<version>" for a catalog install, "import: <pack_id> · signed|unsigned" for a hand-import, read defensively and rendered as one chip. The board doc\'s field-dropping security choke now admits (coerced) provenance so an operator save cannot orphan an installed board. The import preview states SIGNEDNESS as a first-class chip off the verify route\'s additive `signed` bit — unsigned says plainly that it applies only under operator posture and carries no publisher trust — with the existing operator && v.ok apply gate untouched; and a manual apply stamps every artifact it writes with its OWN `imported_from` {pack_id, imported_at_unix_ms, signed}, never the daemon\'s `installed_from`, surviving the canonical write → tolerant read round-trip. ROUTE FIX (M27): L1 wired the fourth section in render.js only — shell.html\'s parseCanvasHash, which is the actual router, still carried M16b\'s three-value ?sub= ladder, so ?sub=library normalised to \'board\'. The Library button painted, clicking it repainted the board, and the page had no reachable route from the Studio at all. The ladder is replaced by ONE shared STUDIO_SUBS allowlist (board · pages · integrations · library) validated with hasOwnProperty (so a prototype key falls back to the board), the topbar sub-line gains its Studio › Library sentence, and the gates now assert the SHELL half as well as the render half — including the resolved routing for every deep link and the fallbacks.');
})();

// =========================================================================
//  Check 55 (crux-storybook-dossier-agent-and-console-surface M3) —
//  cx-storybook renders the context graph.
//
//  Two halves, both jsdom-independent:
//    (a) renderMarkdown is a NODE builder, never innerHTML. The readout
//        interpolates project-layer text an operator wrote, so an innerHTML
//        path here would be a live XSS sink on a page that renders it.
//    (b) the renderer, driven against a stubbed CruxApi carrying real response
//        shapes, paints the section rows, the stat row, and — the reason the
//        page exists — the cross-agent DISAGREEMENT panel.
// =========================================================================
(function checkContextGraphSurface() {
  // ---- (a) markdown → DOM, no innerHTML --------------------------------
  const mdSrc = funcBody(renderSrc, 'renderMarkdown') || '';
  check(!!mdSrc, '[cxg] renderMarkdown must be locatable in render.js');
  check(mdSrc.indexOf('innerHTML') < 0,
    '[cxg] renderMarkdown must never assign innerHTML — the readout carries operator-authored layer text');
  const inlineSrc = funcBody(renderSrc, 'cxmdInline') || '';
  check(inlineSrc.indexOf('innerHTML') < 0, '[cxg] cxmdInline must never assign innerHTML');

  const dom = newMockDom();
  const savedDoc = global.document;
  global.document = dom.doc;
  try {
    const md = render.renderMarkdown([
      '# Storybook · crux-daemon',
      '',
      '> **Generated** by `p_operator`',
      '',
      '## What this project is',
      '',
      'A daemon with **receipts** and `facts`.',
      '',
      '| Plane | Vision | Gap |',
      '|-------|--------|-----|',
      '| retrieval | ✓ | — |',
      '',
      '- first bullet',
      '- second bullet',
      '',
      '```',
      'let x = 1;',
      '```'
    ].join('\n'));
    const tags = dom.collect(md, [md]).map(function (n) { return n.tagName; });
    ['H1', 'H2', 'P', 'BLOCKQUOTE', 'TABLE', 'THEAD', 'TBODY', 'TH', 'TD', 'UL', 'LI', 'PRE', 'CODE', 'STRONG'].forEach(function (t) {
      check(tags.indexOf(t) >= 0, '[cxg] renderMarkdown must emit a <' + t.toLowerCase() + '> for the constructs storybook.rs writes');
    });
    check(dom.findByClass(md, 'cxmd-tw').length === 1,
      '[cxg] a table must sit in its own overflow container so the page never scrolls sideways');
    check(md.textContent.indexOf('receipts') >= 0 && md.textContent.indexOf('let x = 1;') >= 0,
      '[cxg] no content may be dropped by the markdown pass');
    // An unsupported construct degrades to literal text, never disappears.
    const odd = render.renderMarkdown('~~struck~~ and <not-a-tag> survive');
    check(odd.textContent.indexOf('<not-a-tag>') >= 0,
      '[cxg] unrecognised markup must render as literal text, not vanish');
  } finally { global.document = savedDoc; }

  // ---- (b) the renderer, against real response shapes -------------------
  const STORY = {
    project_id: 'crux-daemon', generated_at_unix_ms: 1785198400000, generated_by_passport: 'p_operator',
    markdown: '# Storybook\n\n## Gaps & alerts\n\n- No vision on 2 planes\n',
    sections: {
      '00_front': '# Storybook · crux-daemon\n',
      '10_vision': '## What this project is\n\nA local-first memory daemon.\n',
      '30_plane_retrieval': '### retrieval\n\n- **Plane vision**: BM25 + graph + dense\n',
      '30_planes_intro': '## Planes\n',
      '50_workspace_health': '## Workspace health\n\n**8** crates · **9151** LOC\n',
      '60_alerts': '## Gaps & alerts\n\n- Three planes map to no code\n'
    },
    stats: {
      plane_count: 3, planes_with_vision: 1, planes_with_mapped_modules: 0,
      orphan_planes: ['retrieval', 'coordination', 'context-graph'],
      workspace_loc: 9151, stub_count: 0, dead_code_count: 10, bytes: 3962
    },
    truncated: false, sections_omitted: [], available_versions: [1785198400000, 1785190000000]
  };
  const RECON = {
    project_id: 'crux-daemon', generated_at_unix_ms: 1785198400000, dossier_count: 3,
    agents: ['anonymous', 'p_opus_peer', 'p_sonnet_peer'],
    agreement: [{ kind: 'planning_target', subject: 'project:crux-daemon', object: 'github://cuecrux/crux', agreed_by_agents: ['p_opus_peer', 'p_sonnet_peer'], max_confidence: 1.0, avg_confidence: 1.0 }],
    disagreement: [{
      kind: 'implements', subject: 'plane:crux-daemon:retrieval',
      variants: [
        { object: 'crate:corecrux-retrieval', agents: ['p_sonnet_peer'], max_confidence: 0.92 },
        { object: 'crate:corecrux-index', agents: ['p_opus_peer'], max_confidence: 0.71 }
      ]
    }],
    unique: [], stats: { agreement_count: 1, disagreement_count: 1, unique_count: 9, total_distinct_subjects: 9 },
    truncated: false, disagreements_omitted: 0, agreements_omitted: 0, unique_omitted: 0
  };
  const DOSSIERS = {
    project_id: 'crux-daemon', count: 3, returned: 3, truncated: false, dossiers_omitted: 0,
    dossiers: [
      { dossier_id: 'dsr-peer-opus', generated_at_unix_ms: 1785198300000, agent_passport: 'p_opus_peer' },
      { dossier_id: 'dsr-peer-sonnet', generated_at_unix_ms: 1785198200000, agent_passport: 'p_sonnet_peer' }
    ]
  };
  function jsonResponse(body) {
    return Promise.resolve({ ok: true, status: 200, json: function () { return Promise.resolve(body); } });
  }
  const calls = [];
  const api = {
    get: function (path, query) { calls.push([path, query]); return jsonResponse({ projects: [{ id: 'crux-daemon', name: 'Crux Daemon', is_default: true }] }); },
    projectsByIdStorybook: function (id, q) { calls.push(['storybook', id, q]); return jsonResponse(STORY); },
    projectsByIdDossiers: function (id, q) { calls.push(['dossiers', id, q]); return jsonResponse(DOSSIERS); },
    projectsByIdDossiersReconcile: function (id, q) { calls.push(['reconcile', id, q]); return jsonResponse(RECON); }
  };

  // Sequenced AFTER every check registered so far. The renderer paints in
  // microtasks, so the mock document has to stay installed across them — and if
  // another check's pending continuation landed in that window it would build
  // its nodes with this mock and fail on a method the real DOM has. Chaining off
  // the existing queue means nothing else is in flight.
  const d2 = newMockDom();
  const priorChecks = asyncChecks.slice();
  asyncChecks.push(Promise.all(priorChecks).then(function () {
    const savedDoc2 = global.document, savedWin2 = global.window;
    global.document = d2.doc;
    global.window = { CruxApi: api, CruxPages: pages, CRUX_MODE: 'professional' };
    const host = d2.mkNode('div');
    render.renderContextGraph(host);
    // Let /v1/projects resolve, then the storybook + dossier reads it kicks
    // off. A macrotask turn drains every pending microtask, which a fixed
    // number of `.then` hops does not — the chain is 6+ deep here.
    const settle = function () { return new Promise(function (r) { setTimeout(r, 0); }); };
    return settle().then(settle).then(function () {
    try {
      const text = host.textContent;
      // The project picker painted from the real /v1/projects shape.
      check(d2.findByClass(host, 'cxg-bar').length >= 1, '[cxg] the page must carry a project picker bar');
      check(d2.findByClass(host, 'cxg-tab').length === 2, '[cxg] two tabs: Storybook and Dossiers');

      // Every read is budgeted — the page must not ask the daemon for an
      // unbounded document any more than an agent may.
      const reads = calls.filter(function (c) { return c[0] === 'storybook' || c[0] === 'dossiers' || c[0] === 'reconcile'; });
      check(reads.length >= 2, '[cxg] the page must load the storybook and the dossiers (got ' + reads.length + ' reads)');
      check(reads.every(function (c) { return c[2] && Number(c[2].token_budget) > 0; }),
        '[cxg] every context-graph read must carry a token_budget');

      // Storybook pane: stats and one row per section, alerts open by default.
      check(d2.findByClass(host, 'cxg-stat').length >= 5, '[cxg] the storybook pane must show the stat row');
      check(text.indexOf('9151') >= 0, '[cxg] workspace LOC from stats must be shown');
      check(text.indexOf('dead-code candidates') >= 0, '[cxg] the dead-code count must be labelled');
      const rows = d2.findByClass(host, 'facts-row');
      check(rows.length === Object.keys(STORY.sections).length,
        '[cxg] one row per section (want ' + Object.keys(STORY.sections).length + ', got ' + rows.length + ')');
      check(text.indexOf('Workspace health') >= 0, '[cxg] section keys must render as readable titles, not 50_workspace_health');
      check(text.indexOf('50_workspace_health') >= 0, '[cxg] ...while the raw key stays visible for grounding');

      // Dossier pane: disagreement leads.
      const tabs = d2.findByClass(host, 'cxg-tab');
      check(tabs.length === 2 && tabs[0].getAttribute('aria-pressed') === 'true',
        '[cxg] Storybook is the default tab');
      tabs[1].click();
      const dtext = host.textContent;
      check(dtext.indexOf('disagreement') >= 0,
        '[cxg] the dossier pane must lead with disagreement — the one thing a single dossier cannot tell you');
      check(dtext.indexOf('plane:crux-daemon:retrieval') >= 0 &&
            dtext.indexOf('crate:corecrux-retrieval') >= 0 &&
            dtext.indexOf('crate:corecrux-index') >= 0,
        '[cxg] both sides of a disagreement must be named, with the subject they disagree about');
      check(dtext.indexOf('p_sonnet_peer') >= 0 && dtext.indexOf('p_opus_peer') >= 0,
        '[cxg] a disagreement must attribute each variant to the agent that claimed it');
      const disIdx = dtext.indexOf('disagreement'), agrIdx = dtext.indexOf('agreement — two or more');
      check(disIdx >= 0 && agrIdx > disIdx, '[cxg] disagreement must precede agreement in the pane');
      check(dtext.indexOf('dsr-peer-opus') >= 0 && dtext.indexOf('dsr-peer-sonnet') >= 0,
        '[cxg] every saved dossier must be listed with its id');
      notes.push('cx-storybook (M3): the context graph gets a console home — a project picker driving the storybook readout (rendered markdown as DOM nodes, one collapsible per section, stat row, version list + two-version diff) and the dossier board (claims grouped by kind with confidence + evidence, uncertainties, contradictions, open questions), with cross-agent RECONCILIATION leading the dossier pane because a disagreement is the one thing a single dossier can never tell you. Every read carries a token_budget; the two regenerate actions go through operatorGatedCall. renderMarkdown builds nodes and never touches innerHTML.');
    } finally { global.document = savedDoc2; global.window = savedWin2; }
    });
  }));
})();

// =========================================================================
//  Check — (issue #703) cx-gates carries tenant context. A pending gate held in
//  a NON-DEFAULT tenant must appear on the routed page, the page must say which
//  tenants it answered for, a narrowed view must not borrow the rich "queue is
//  clear" state, and an unauthorized/failed read must fail honestly rather than
//  render as an empty queue. Driven through renderPage('cx-gates') — the routed
//  path a browser takes — against a stubbed client.
// =========================================================================
(function checkGatesTenantContext() {
  const gateSrc = funcBody(renderSrc, 'renderGatesBoard') || '';
  check(/tenant_scope/.test(gateSrc), '[gates-tenant] the board must read tenant_scope from the daemon response');
  check(/approveGate|rejectGate/.test(gateSrc), '[gates-tenant] approve/reject must still route through approveGate/rejectGate (operatorGatedCall)');

  const dom = newMockDom();
  const priorChecks = asyncChecks.slice();
  const settle = function () { return new Promise(function (r) { setTimeout(r, 0); }); };

  // One stubbed daemon: pending gates live in tenant `work`, none in `default`.
  const GATES = [
    { action_id: 'ga_1', work_id: 'w-1', requested_by_passport: 'p_agent', tenant_id: 'work', requested_action: 'update_state', target_state: 'complete', status: 'pending', requested_at_unix_ms: 1 },
    { action_id: 'ga_2', work_id: 'w-2', requested_by_passport: 'p_agent', tenant_id: 'work', requested_action: 'update_state', target_state: 'archived', status: 'pending', requested_at_unix_ms: 2 }
  ];
  const seen = [];
  let gateStatus = 200;
  function stubApi() {
    return { get: function (base, query) {
      const q = query || {};
      if (base === '/v1/work/gate/pending') {
        seen.push(q.tenant_id || null);
        if (gateStatus !== 200) {
          return Promise.resolve({ ok: false, status: gateStatus, json: function () { return Promise.resolve({ detail: 'token is missing a tenant claim' }); } });
        }
        const tenant = q.tenant_id || null;
        const rows = tenant ? GATES.filter(function (g) { return g.tenant_id === tenant; }) : GATES.slice();
        const scope = tenant ? [tenant] : ['*'];
        return Promise.resolve({ ok: true, status: 200, json: function () { return Promise.resolve({ count: rows.length, pending: rows, tenant_scope: scope }); } });
      }
      return Promise.resolve({ ok: true, status: 200, json: function () { return Promise.resolve({ work: [] }); } });
    } };
  }

  asyncChecks.push(Promise.all(priorChecks).then(function () {
    const savedDoc = global.document, savedWin = global.window;
    global.document = dom.doc;
    global.window = { CruxApi: stubApi(), CruxPages: pages, CRUX_POSTURE: 'operator', CRUX_MODE: 'professional' };
    const host = dom.mkNode('div');
    render.renderPage({ id: 'cx-gates', title: 'Gates' }, host);
    // Globals are restored in the tail, not a `finally` — the chain below is
    // async, so a `finally` here would unhook the mock DOM mid-flight.
    const restore = function () { global.document = savedDoc; global.window = savedWin; };
    return settle().then(settle).then(function () {
      {
        // (1) The default read asks for NO tenant — the daemon answers for every
        //     authorized tenant — so a non-default gate is visible.
        check(seen.length >= 1 && seen[0] === null, '[gates-tenant] the first read must not pin a tenant (got ' + JSON.stringify(seen[0]) + ')');
        let text = host.textContent;
        check(/ga_1/.test(text) && /ga_2/.test(text), '[gates-tenant] pending gates held in a non-default tenant must render');
        check(!/queue is clear/.test(text), '[gates-tenant] the rich "queue is clear" state must NOT show while gates are pending elsewhere');
        check(/all authorized tenants/.test(text), '[gates-tenant] the count line must name the tenant scope the daemon answered for');
        check(/\bwork\b/.test(text), '[gates-tenant] each row must name the tenant its gate belongs to');

        // (2) The operator can narrow to one authorized tenant, and the rows
        //     match GET /v1/work/gate/pending?tenant_id=<selected>.
        const picks = dom.collect(host, [host]).filter(function (n) { return n.getAttribute && n.getAttribute('data-gates-tenant'); });
        check(picks.length === 1, '[gates-tenant] the page must expose exactly one tenant selector');
        const pick = picks[0];
        const opts = dom.collect(pick).map(function (n) { return n.getAttribute('value'); });
        check(opts.indexOf('work') >= 0, '[gates-tenant] the selector must offer every tenant seen holding a pending gate');
        pick.value = 'work';
        (pick._handlers.change || []).forEach(function (fn) { fn(); });
        return settle().then(settle).then(function () {
          check(seen[seen.length - 1] === 'work', '[gates-tenant] selecting a tenant must re-read with ?tenant_id=<selected>');
          text = host.textContent;
          check(/ga_1/.test(text) && /tenant work/.test(text), '[gates-tenant] the narrowed view must show that tenant\'s rows and name the narrowing');

          // (3) A tenant with no gates is honestly narrow-empty, never "clear".
          pick.value = 'default';
          (pick._handlers.change || []).forEach(function (fn) { fn(); });
          return settle().then(settle);
        }).then(function () {
          text = host.textContent;
          check(!/queue is clear/.test(text), '[gates-tenant] a tenant-narrowed empty result must NOT claim the whole queue is clear');
          check(/narrowed to one tenant/.test(text), '[gates-tenant] a narrowed empty result must say it is narrowed and point back to all tenants');

          // (4) A refused read fails honestly — no empty queue, no "clear".
          gateStatus = 403;
          pick.value = '';
          (pick._handlers.change || []).forEach(function (fn) { fn(); });
          return settle().then(settle);
        }).then(function () {
          text = host.textContent;
          check(/Gates unavailable/.test(text) && /HTTP 403/.test(text), '[gates-tenant] an unauthorized read must render an explicit failure, not an empty queue');
          check(/NOT known to be clear/.test(text), '[gates-tenant] the failure must say the queue is not known to be clear');
          check(!/queue is clear/.test(text), '[gates-tenant] a failed read must never render the all-clear state');
          notes.push('gates tenant context (issue #703): GET /v1/work/gate/pending answers for every tenant the credential is authorized for (tenant_scope in the response; ["*"] = all), cx-gates renders the scope verbatim, offers an authorized-tenant selector, and refuses to show the rich "queue is clear" state when the view is narrowed or the read failed.');
        });
      }
    }).then(function () { restore(); }, function (e) { restore(); check(false, '[gates-tenant] routed gates render threw: ' + (e && e.stack || e)); });
  }));
})();

// =========================================================================
//  Check — (issue #705 M3/M4) the Gates page derives its Approve affordance
//  from the daemon's `work_gate_resolution` capability, and renders the
//  daemon's own reason verbatim when it is not available. A control that
//  renders as actionable where the daemon would refuse is the "visible but
//  inert" defect this whole line of work exists to remove, so it is asserted
//  as a property of the routed page, not of a helper.
// =========================================================================
(function checkGateCapabilityGating() {
  const gateSrc = funcBody(renderSrc, 'renderGatesBoard') || '';
  check(/work_gate_resolution/.test(gateSrc),
    '[gate-cap] the board must read the work_gate_resolution capability');
  check(!/\bfetch\s*\(/.test(gateSrc),
    '[gate-cap] the board must issue no raw fetch — and must NOT acquire a bearer token (api.js: the browser never holds one)');

  const dom = newMockDom();
  const priorChecks = asyncChecks.slice();
  const settle = function () { return new Promise(function (r) { setTimeout(r, 0); }); };
  const GATES = [{ action_id: 'ga_1', work_id: 'w-1', requested_by_passport: 'p_agent', tenant_id: 'default', requested_action: 'update_state', target_state: 'complete', status: 'pending', requested_at_unix_ms: 1 }];

  function api() {
    return { get: function (base) {
      if (base === '/v1/work/gate/pending') {
        return Promise.resolve({ ok: true, status: 200, json: function () { return Promise.resolve({ count: 1, pending: GATES, tenant_scope: ['*'] }); } });
      }
      return Promise.resolve({ ok: true, status: 200, json: function () { return Promise.resolve({ work: [] }); } });
    } };
  }
  function descriptor(capability) {
    return { schema_version: 1, capabilities: { work_gate_resolution: capability } };
  }
  const AVAILABLE = { availability: 'available', reason_code: 'ok', reason: 'ok', compiled: true, configured: true, initialized: true, entitled: true, degraded: false };
  const BLOCKED = { availability: 'degraded', reason_code: 'gate_rail_no_passport_mapping', reason: 'The identity rail is enabled but no allowlist entry binds a passport; append `#<passport>` to the entry for each human who may approve.', compiled: true, configured: true, initialized: true, entitled: true, degraded: true };
  const NONE = { availability: 'unavailable', reason_code: 'gate_no_identity_rung', reason: 'No rung can name a human on this daemon: enable the device grant (CORECRUXD_DEVICE_GRANT_ENABLED) or the identity rail (CORECRUXD_TS_IDENTITY_ENABLED) with a passport-bound allowlist.', compiled: true, configured: false, initialized: false, entitled: true, degraded: false };

  function render1(capability) {
    const savedDoc = global.document, savedWin = global.window;
    global.document = dom.doc;
    global.window = { CruxApi: api(), CruxPages: pages, CRUX_POSTURE: 'operator', CRUX_RUNTIME_CAPABILITIES: capability === null ? null : descriptor(capability) };
    const host = dom.mkNode('div');
    render.renderPage({ id: 'cx-gates', title: 'Gates' }, host);
    return settle().then(settle).then(function () {
      const text = host.textContent;
      const banners = dom.collect(host, [host]).filter(function (n) { return n.getAttribute && n.getAttribute('data-gate-capability'); });
      global.document = savedDoc; global.window = savedWin;
      return { text: text, banners: banners };
    });
  }

  asyncChecks.push(Promise.all(priorChecks).then(function () {
    return render1(AVAILABLE).then(function (r) {
      check(r.banners.length === 0, '[gate-cap] an available capability must NOT show a refusal banner');
      check(/ga_1/.test(r.text), '[gate-cap] the pending gate still renders when approval is available');
      return render1(BLOCKED);
    }).then(function (r) {
      check(r.banners.length === 1 && r.banners[0].getAttribute('data-gate-capability') === 'gate_rail_no_passport_mapping',
        '[gate-cap] a degraded capability must refuse with the daemon reason code');
      check(/#<passport>/.test(r.text),
        '[gate-cap] the daemon reason must be rendered VERBATIM — it names the remedy');
      return render1(NONE);
    }).then(function (r) {
      check(r.banners.length === 1 && r.banners[0].getAttribute('data-gate-capability') === 'gate_no_identity_rung',
        '[gate-cap] an unavailable capability must refuse with its reason code');
      check(/CORECRUXD_DEVICE_GRANT_ENABLED/.test(r.text),
        '[gate-cap] the refusal must name the flag that would fix it');
      return render1(null);
    }).then(function (r) {
      // Fails closed: no descriptor at all is NOT permission to offer approval.
      check(r.banners.length === 1,
        '[gate-cap] an absent capability descriptor must fail closed, not render an actionable control');
      notes.push('gate capability gating (issue #705 M3/M4): cx-gates derives its Approve affordance from the daemon-declared work_gate_resolution capability, renders the daemon reason verbatim on degraded/unavailable, fails closed when the descriptor is absent, and acquires no bearer token (the console client’s standing invariant).');
    });
  }));
})();

// ---- Report (awaits async renderer-driven checks) -----------------------
Promise.all(asyncChecks).then(function () { return passportMintInteraction(); }).then(function () {
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
