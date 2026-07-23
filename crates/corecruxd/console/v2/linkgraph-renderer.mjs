// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.
//
// Custom WebGL link-graph renderer — GPU points + LineSegments on the already-
// vendored three.js r165 (ExecPlan wikicrux-link-graph-explorer-2026-07-23, M4;
// renderer decision D5). ZERO new trust-kernel surface: `three` resolves through
// the console's import map to /console-3d/vendor/three.module.min.js (MIT, sha256
// 1af5bef9…), the same artifact console-3d already loads. No build chain, no CDN,
// no external requests, plain ESM.
//
// Public API (a factory returning the handle used by both the Nuxt explorer and
// the Crux console pane — one module, verbatim):
//   const r = createLinkGraphRenderer();
//   r.mount(container, { theme, reducedMotion, onNodeClick });
//   r.setData({ nodes, edges, edgeKinds, paths, seeds });
//   r.expandData({ nodes, edges, edgeKinds });   // merge (ego click-to-expand)
//   r.setTheme(themeId, tokens);
//   r.onNodeClick(fn);
//   r.destroy();
//
// Rendering posture: render-on-demand ONLY (no perpetual rAF loop). Redraws fire
// on data change, theme change, pan, zoom, hover and click — which satisfies the
// prefers-reduced-motion "no perpetual animation" floor natively (D5). Layout is
// deterministic (no Math.random): a layered/radial seed placement plus a bounded,
// fixed-iteration relaxation for small subgraphs; positions are stable across
// rebuilds of the same subgraph.

import * as THREE from 'three';

// ── Deterministic colour helpers ─────────────────────────────────────────────

// Golden-angle hue per community id → evenly spread, stable, no palette table.
function communityColor(community, isCategory, tokens) {
  if (isCategory) { return tokens.category; }
  if (community === undefined || community === null) { return tokens.nodeNeutral; }
  const hue = (community * 137.508) % 360;
  return hslToHex(hue, 0.62, tokens.dark ? 0.62 : 0.48);
}

function hslToHex(h, s, l) {
  h /= 360;
  const a = s * Math.min(l, 1 - l);
  const f = function (n) {
    const k = (n + h * 12) % 12;
    return l - a * Math.max(-1, Math.min(k - 3, Math.min(9 - k, 1)));
  };
  return (Math.round(f(0) * 255) << 16) | (Math.round(f(8) * 255) << 8) | Math.round(f(4) * 255);
}

// A soft circular sprite so nodes read as dots, not squares — generated once,
// no image asset (T.5: no external/binary asset dependency).
function makeDiscTexture() {
  const size = 64;
  const cv = document.createElement('canvas');
  cv.width = cv.height = size;
  const ctx = cv.getContext('2d');
  const g = ctx.createRadialGradient(size / 2, size / 2, 0, size / 2, size / 2, size / 2);
  g.addColorStop(0, 'rgba(255,255,255,1)');
  g.addColorStop(0.55, 'rgba(255,255,255,1)');
  g.addColorStop(0.75, 'rgba(255,255,255,0.55)');
  g.addColorStop(1, 'rgba(255,255,255,0)');
  ctx.fillStyle = g;
  ctx.beginPath();
  ctx.arc(size / 2, size / 2, size / 2, 0, Math.PI * 2);
  ctx.fill();
  const tex = new THREE.CanvasTexture(cv);
  tex.colorSpace = THREE.SRGBColorSpace;
  return tex;
}

// ── Theme token defaults (overridden by the console's Light/Dark/Glass tokens) ─

const THEME_TOKENS = {
  light: { dark: false, bg: 0xf6f8fb, edge: 0x9fb2c4, edgeCategory: 0xc8b6e2, path: 0x0369a1, nodeNeutral: 0x64748b, category: 0x8b5cf6, label: '#0c4a6e', labelBg: 'rgba(255,255,255,0.86)' },
  dark: { dark: true, bg: 0x0b1120, edge: 0x33415a, edgeCategory: 0x4c3f6b, path: 0x38bdf8, nodeNeutral: 0x94a3b8, category: 0xa78bfa, label: '#e2e8f0', labelBg: 'rgba(15,23,42,0.82)' },
  glass: { dark: true, bg: 0x0e1526, edge: 0x3a4a63, edgeCategory: 0x53456f, path: 0x5eead4, nodeNeutral: 0xa3b2c7, category: 0xc4b5fd, label: '#e6eefb', labelBg: 'rgba(17,25,44,0.7)' }
};

function tokensFor(themeId, override) {
  const base = THEME_TOKENS[themeId] || THEME_TOKENS.light;
  return Object.assign({}, base, override || {});
}

// ── Factory ──────────────────────────────────────────────────────────────────

export function createLinkGraphRenderer() {
  let container = null;
  let renderer = null;
  let scene = null;
  let camera = null;
  let disc = null;
  let labelLayer = null;
  let clickCb = null;
  let reducedMotion = false;
  let tokens = tokensFor('light');
  let themeId = 'light';

  // Graph model (merge-friendly for expandData).
  const model = { nodes: [], index: new Map(), edges: [], edgeKinds: [], adj: new Map(), paths: [], seeds: [], pos: new Map() };

  let nodePoints = null;      // THREE.Points
  let edgeLines = null;       // THREE.LineSegments (base edges)
  let pathLines = null;       // THREE.LineSegments (highlighted shortest-path edges)
  let listeners = [];         // [target, type, fn] for clean teardown
  let ro = null;              // ResizeObserver

  // ── Mount ────────────────────────────────────────────────────────────────
  function mount(el, opts) {
    opts = opts || {};
    container = el;
    reducedMotion = !!opts.reducedMotion;
    clickCb = typeof opts.onNodeClick === 'function' ? opts.onNodeClick : null;
    themeId = opts.theme || 'light';
    tokens = tokensFor(themeId, opts.tokens);

    const w = Math.max(1, el.clientWidth);
    const h = Math.max(1, el.clientHeight);

    renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false, powerPreference: 'low-power' });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.setSize(w, h, false);
    renderer.setClearColor(tokens.bg, 1);
    renderer.domElement.style.width = '100%';
    renderer.domElement.style.height = '100%';
    renderer.domElement.style.display = 'block';
    renderer.domElement.setAttribute('role', 'img');
    renderer.domElement.setAttribute('aria-label', 'Link graph — nodes are articles, edges are wikilinks. Use the path search and click a node to expand its neighbourhood.');
    renderer.domElement.tabIndex = 0;   // focusable (a11y: keyboard reachable, visible focus via console CSS)
    el.appendChild(renderer.domElement);

    // HTML label overlay (projected, not WebGL text — crisp + theme-able).
    labelLayer = document.createElement('div');
    labelLayer.className = 'lg-label-layer';
    labelLayer.setAttribute('aria-hidden', 'true');
    labelLayer.style.cssText = 'position:absolute;inset:0;pointer-events:none;overflow:hidden;';
    el.appendChild(labelLayer);

    scene = new THREE.Scene();
    // Orthographic 2D view — a link graph is planar; ortho gives clean pan/zoom.
    const aspect = w / h;
    const frustum = 1000;
    camera = new THREE.OrthographicCamera(-frustum * aspect, frustum * aspect, frustum, -frustum, -1, 10);
    camera.position.set(0, 0, 5);

    disc = makeDiscTexture();

    wireInteraction();

    if (typeof ResizeObserver !== 'undefined') {
      ro = new ResizeObserver(function () { resize(); });
      ro.observe(el);
    }
    return handle;
  }

  function resize() {
    if (!renderer || !container) { return; }
    const w = Math.max(1, container.clientWidth);
    const h = Math.max(1, container.clientHeight);
    const aspect = w / h;
    const half = (camera.top - camera.bottom) / 2;
    camera.left = -half * aspect;
    camera.right = half * aspect;
    camera.updateProjectionMatrix();
    renderer.setSize(w, h, false);
    render();
  }

  // ── Data ingest ────────────────────────────────────────────────────────────
  function ingest(data, merge) {
    data = data || {};
    if (!merge) {
      model.nodes = []; model.index = new Map(); model.edges = []; model.edgeKinds = [];
      model.adj = new Map(); model.paths = []; model.seeds = []; model.pos = new Map();
    }
    (data.nodes || []).forEach(function (n) {
      if (!model.index.has(n.id)) {
        model.index.set(n.id, model.nodes.length);
        model.nodes.push(n);
        model.adj.set(n.id, model.adj.get(n.id) || []);
      }
    });
    const edges = data.edges || [];
    const kinds = data.edgeKinds || [];
    for (let i = 0; i + 1 < edges.length; i += 2) {
      const a = edges[i], b = edges[i + 1];
      if (!model.index.has(a) || !model.index.has(b)) { continue; }
      model.edges.push(a, b);
      model.edgeKinds.push(kinds[i / 2] || 0);
      (model.adj.get(a) || model.adj.set(a, []).get(a)).push(b);
      (model.adj.get(b) || model.adj.set(b, []).get(b)).push(a);
    }
    if (data.paths) { model.paths = data.paths; }
    if (data.seeds) { model.seeds = data.seeds; }
  }

  function setData(data) {
    ingest(data, false);
    layout(model.nodes);
    rebuild();
    fitView();
    render();
  }

  function expandData(data) {
    const before = new Set(model.index.keys());
    ingest(data, true);
    // Layout only the freshly added nodes; keep existing positions stable.
    const fresh = model.nodes.filter(function (n) { return !before.has(n.id); });
    layout(fresh, true);
    rebuild();
    render();
  }

  // ── Deterministic layout ─────────────────────────────────────────────────
  // Seeds = path union (if any) else the declared ego seeds else the highest-
  // degree node. Assign BFS layer distance, place layers as concentric rings
  // (ego) or left→right columns (path), then a bounded relaxation for small n.
  function layout(subset, keepExisting) {
    if (!model.nodes.length) { return; }
    const isPath = model.paths && model.paths.length > 0;
    const roots = pickRoots();
    const dist = bfsLayers(roots);

    const golden = Math.PI * (3 - Math.sqrt(5));
    subset.forEach(function (n, i) {
      if (keepExisting && model.pos.has(n.id)) { return; }
      const layer = dist.has(n.id) ? dist.get(n.id) : 4;
      let x, y;
      if (isPath) {
        // Path nodes on a straight spine; everything else offset by layer.
        const pIdx = pathPositionOf(n.id);
        if (pIdx >= 0) {
          x = (pIdx - pathSpan() / 2) * 240;
          y = pathRowOf(n.id) * 120;
        } else {
          x = (layer - 3) * 240 + (deterministicJitter(n.id) - 0.5) * 120;
          y = (deterministicJitter(n.id + 7) - 0.5) * 900;
        }
      } else {
        // Concentric rings by hop distance; deterministic angle from index.
        const radius = layer * 260;
        const ang = i * golden + n.id * 0.000001;
        x = Math.cos(ang) * (radius + deterministicJitter(n.id) * 40);
        y = Math.sin(ang) * (radius + deterministicJitter(n.id + 3) * 40);
      }
      model.pos.set(n.id, { x: x, y: y });
    });

    // A small, fixed-iteration relaxation reduces overlap without a live sim.
    // Skip for large subgraphs (keep it O(n·iters); the console budgets are modest).
    if (model.nodes.length <= 1200) { relax(24); }
  }

  function pickRoots() {
    if (model.paths && model.paths.length) {
      const s = new Set();
      model.paths.forEach(function (p) { (p || []).forEach(function (id) { s.add(id); }); });
      return Array.from(s);
    }
    if (model.seeds && model.seeds.length) { return model.seeds.slice(); }
    // Highest-degree node as a fallback anchor.
    let best = null, bestDeg = -1;
    model.nodes.forEach(function (n) {
      const d = (n.degree_in || 0) + (n.degree_out || 0);
      if (d > bestDeg) { bestDeg = d; best = n.id; }
    });
    return best === null ? [] : [best];
  }

  function bfsLayers(roots) {
    const dist = new Map();
    const q = [];
    roots.forEach(function (r) { if (model.index.has(r)) { dist.set(r, 0); q.push(r); } });
    let head = 0;
    while (head < q.length) {
      const cur = q[head++];
      const d = dist.get(cur);
      (model.adj.get(cur) || []).forEach(function (nb) {
        if (!dist.has(nb)) { dist.set(nb, d + 1); q.push(nb); }
      });
    }
    return dist;
  }

  function pathPositionOf(id) {
    for (let r = 0; r < model.paths.length; r++) {
      const idx = (model.paths[r] || []).indexOf(id);
      if (idx >= 0) { return idx; }
    }
    return -1;
  }
  function pathRowOf(id) {
    for (let r = 0; r < model.paths.length; r++) {
      if ((model.paths[r] || []).indexOf(id) >= 0) { return r; }
    }
    return 0;
  }
  function pathSpan() {
    let m = 0;
    model.paths.forEach(function (p) { m = Math.max(m, (p || []).length - 1); });
    return m;
  }

  // Deterministic pseudo-jitter in [0,1) from an integer id (no Math.random).
  function deterministicJitter(id) {
    const x = Math.sin(id * 12.9898) * 43758.5453;
    return x - Math.floor(x);
  }

  // Fixed-iteration Fruchterman–Reingold-style relaxation. Deterministic; runs
  // synchronously once (not animated) — reduced-motion safe.
  function relax(iters) {
    const ids = model.nodes.map(function (n) { return n.id; });
    const k = 200;
    const fixed = new Set();
    if (model.paths) { model.paths.forEach(function (p) { (p || []).forEach(function (id) { fixed.add(id); }); }); }
    for (let it = 0; it < iters; it++) {
      const disp = new Map();
      ids.forEach(function (id) { disp.set(id, { x: 0, y: 0 }); });
      // Repulsion (O(n²) — bounded by the n ≤ 1200 gate).
      for (let a = 0; a < ids.length; a++) {
        const pa = model.pos.get(ids[a]);
        for (let b = a + 1; b < ids.length; b++) {
          const pb = model.pos.get(ids[b]);
          let dx = pa.x - pb.x, dy = pa.y - pb.y;
          let d2 = dx * dx + dy * dy;
          if (d2 < 1) { d2 = 1; dx = (deterministicJitter(ids[a]) - 0.5); dy = (deterministicJitter(ids[b]) - 0.5); }
          const f = (k * k) / d2;
          const da = disp.get(ids[a]), db = disp.get(ids[b]);
          da.x += dx * f * 0.0006; da.y += dy * f * 0.0006;
          db.x -= dx * f * 0.0006; db.y -= dy * f * 0.0006;
        }
      }
      // Attraction along edges.
      for (let i = 0; i + 1 < model.edges.length; i += 2) {
        const pa = model.pos.get(model.edges[i]), pb = model.pos.get(model.edges[i + 1]);
        if (!pa || !pb) { continue; }
        const dx = pa.x - pb.x, dy = pa.y - pb.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const f = (dist * dist) / k;
        const da = disp.get(model.edges[i]), db = disp.get(model.edges[i + 1]);
        da.x -= dx / dist * f * 0.02; da.y -= dy / dist * f * 0.02;
        db.x += dx / dist * f * 0.02; db.y += dy / dist * f * 0.02;
      }
      ids.forEach(function (id) {
        if (fixed.has(id)) { return; }
        const p = model.pos.get(id), d = disp.get(id);
        const mag = Math.sqrt(d.x * d.x + d.y * d.y) || 1;
        const cap = Math.min(mag, 40);
        p.x += d.x / mag * cap; p.y += d.y / mag * cap;
      });
    }
  }

  // ── GPU buffers ────────────────────────────────────────────────────────────
  function rebuild() {
    disposeSceneObjects();
    const n = model.nodes.length;
    const pathEdgeSet = buildPathEdgeSet();

    // Nodes.
    const positions = new Float32Array(n * 3);
    const colors = new Float32Array(n * 3);
    const sizes = new Float32Array(n);
    const c = new THREE.Color();
    model.nodes.forEach(function (node, i) {
      const p = model.pos.get(node.id) || { x: 0, y: 0 };
      positions[i * 3] = p.x; positions[i * 3 + 1] = p.y; positions[i * 3 + 2] = 0;
      const isCat = (node.flags & 1) !== 0;
      const onPath = pathNodeSet.has(node.id);
      c.setHex(onPath ? tokens.path : communityColor(node.community, isCat, tokens));
      colors[i * 3] = c.r; colors[i * 3 + 1] = c.g; colors[i * 3 + 2] = c.b;
      const deg = (node.degree_in || 0) + (node.degree_out || 0);
      sizes[i] = (onPath ? 26 : 12 + Math.min(18, Math.log2(deg + 1) * 2.2));
    });
    const g = new THREE.BufferGeometry();
    g.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    g.setAttribute('color', new THREE.BufferAttribute(colors, 3));
    g.setAttribute('size', new THREE.BufferAttribute(sizes, 1));
    const mat = new THREE.PointsMaterial({ vertexColors: true, map: disc, alphaTest: 0.35, transparent: true, sizeAttenuation: false });
    // Per-point size: PointsMaterial declares `uniform float size;` and emits
    // `gl_PointSize = size;`. Swapping the uniform decl for an attribute decl of
    // the same name makes gl_PointSize read the per-vertex `size` buffer — the
    // canonical r165 recipe (single, exact replacement; degree-scaled hub sizing).
    mat.onBeforeCompile = function (shader) {
      shader.vertexShader = shader.vertexShader.replace('uniform float size;', 'attribute float size;');
    };
    nodePoints = new THREE.Points(g, mat);
    nodePoints.frustumCulled = false;
    scene.add(nodePoints);

    // Base edges.
    const ePos = [];
    const eCol = [];
    const pPos = [];
    const cat = new THREE.Color(tokens.edgeCategory);
    const link = new THREE.Color(tokens.edge);
    for (let i = 0; i + 1 < model.edges.length; i += 2) {
      const a = model.edges[i], b = model.edges[i + 1];
      const pa = model.pos.get(a), pb = model.pos.get(b);
      if (!pa || !pb) { continue; }
      const key = edgeKey(a, b);
      if (pathEdgeSet.has(key)) { pPos.push(pa.x, pa.y, 0.1, pb.x, pb.y, 0.1); continue; }
      ePos.push(pa.x, pa.y, -0.1, pb.x, pb.y, -0.1);
      const col = (model.edgeKinds[i / 2] === 1) ? cat : link;
      eCol.push(col.r, col.g, col.b, col.r, col.g, col.b);
    }
    if (ePos.length) {
      const eg = new THREE.BufferGeometry();
      eg.setAttribute('position', new THREE.BufferAttribute(new Float32Array(ePos), 3));
      eg.setAttribute('color', new THREE.BufferAttribute(new Float32Array(eCol), 3));
      edgeLines = new THREE.LineSegments(eg, new THREE.LineBasicMaterial({ vertexColors: true, transparent: true, opacity: tokens.dark ? 0.5 : 0.65 }));
      edgeLines.frustumCulled = false;
      scene.add(edgeLines);
    }
    if (pPos.length) {
      const pg = new THREE.BufferGeometry();
      pg.setAttribute('position', new THREE.BufferAttribute(new Float32Array(pPos), 3));
      pathLines = new THREE.LineSegments(pg, new THREE.LineBasicMaterial({ color: tokens.path, transparent: true, opacity: 0.95 }));
      pathLines.frustumCulled = false;
      scene.add(pathLines);
    }
    renderLabels();
  }

  const pathNodeSet = new Set();
  function buildPathEdgeSet() {
    pathNodeSet.clear();
    const set = new Set();
    (model.paths || []).forEach(function (p) {
      for (let i = 0; i < (p || []).length; i++) {
        pathNodeSet.add(p[i]);
        if (i + 1 < p.length) { set.add(edgeKey(p[i], p[i + 1])); }
      }
    });
    return set;
  }
  function edgeKey(a, b) { return a < b ? a + ':' + b : b + ':' + a; }

  // ── Labels (path + seeds + hovered/selected only — level-of-detail at 10k) ──
  let hoverId = null;
  function renderLabels() {
    if (!labelLayer) { return; }
    labelLayer.textContent = '';
    const show = new Set();
    pathNodeSet.forEach(function (id) { show.add(id); });
    (model.seeds || []).forEach(function (id) { show.add(id); });
    if (hoverId !== null) { show.add(hoverId); }
    const w = container.clientWidth, h = container.clientHeight;
    show.forEach(function (id) {
      const idx = model.index.get(id);
      if (idx === undefined) { return; }
      const node = model.nodes[idx];
      const p = model.pos.get(id);
      if (!p) { return; }
      const v = new THREE.Vector3(p.x, p.y, 0).project(camera);
      const sx = (v.x * 0.5 + 0.5) * w;
      const sy = (-v.y * 0.5 + 0.5) * h;
      if (sx < -80 || sx > w + 80 || sy < -20 || sy > h + 20) { return; }
      const tag = document.createElement('div');
      tag.className = 'lg-label' + (pathNodeSet.has(id) ? ' lg-label-path' : '');
      tag.textContent = node.title || String(id);
      tag.style.cssText = 'position:absolute;left:' + Math.round(sx) + 'px;top:' + Math.round(sy) + 'px;transform:translate(-50%,-140%);white-space:nowrap;font:600 12px/1.2 system-ui,-apple-system,sans-serif;padding:2px 6px;border-radius:6px;color:' + tokens.label + ';background:' + tokens.labelBg + ';';
      labelLayer.appendChild(tag);
    });
  }

  // ── Camera fit ──────────────────────────────────────────────────────────
  function fitView() {
    if (!model.nodes.length) { render(); return; }
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    model.pos.forEach(function (p) {
      minX = Math.min(minX, p.x); maxX = Math.max(maxX, p.x);
      minY = Math.min(minY, p.y); maxY = Math.max(maxY, p.y);
    });
    const cx = (minX + maxX) / 2, cy = (minY + maxY) / 2;
    const spanX = Math.max(400, (maxX - minX) * 1.15);
    const spanY = Math.max(400, (maxY - minY) * 1.15);
    const w = Math.max(1, container.clientWidth), h = Math.max(1, container.clientHeight);
    const aspect = w / h;
    let half = Math.max(spanY / 2, (spanX / 2) / aspect);
    camera.top = cy + half; camera.bottom = cy - half;
    camera.left = cx - half * aspect; camera.right = cx + half * aspect;
    camera.position.set(cx, cy, 5);
    camera.updateProjectionMatrix();
  }

  // ── Interaction (pan / zoom / click / hover) — render-on-demand ────────────
  function wireInteraction() {
    const dom = renderer.domElement;
    let dragging = false, lastX = 0, lastY = 0, moved = false;

    const onDown = function (ev) { dragging = true; moved = false; lastX = ev.clientX; lastY = ev.clientY; };
    const onMove = function (ev) {
      if (dragging) {
        const dx = ev.clientX - lastX, dy = ev.clientY - lastY;
        if (Math.abs(dx) + Math.abs(dy) > 2) { moved = true; }
        const w = container.clientWidth || 1;
        const worldPerPx = (camera.right - camera.left) / w;
        camera.left -= dx * worldPerPx; camera.right -= dx * worldPerPx;
        camera.top += dy * worldPerPx; camera.bottom += dy * worldPerPx;
        camera.position.x -= dx * worldPerPx; camera.position.y += dy * worldPerPx;
        camera.updateProjectionMatrix();
        lastX = ev.clientX; lastY = ev.clientY;
        render();
      } else {
        hover(ev);
      }
    };
    const onUp = function (ev) {
      dragging = false;
      if (!moved) { pick(ev); }
    };
    const onWheel = function (ev) {
      ev.preventDefault();
      const factor = ev.deltaY > 0 ? 1.12 : 0.89;
      zoomAt(ev, factor);
    };
    add(dom, 'pointerdown', onDown);
    add(window, 'pointermove', onMove);
    add(window, 'pointerup', onUp);
    add(dom, 'wheel', onWheel, { passive: false });
    // Keyboard: +/- zoom, arrows pan (a11y — the canvas is focusable).
    add(dom, 'keydown', function (ev) {
      const pan = 80 * ((camera.right - camera.left) / (container.clientWidth || 1));
      if (ev.key === '+' || ev.key === '=') { zoomCenter(0.85); }
      else if (ev.key === '-' || ev.key === '_') { zoomCenter(1.18); }
      else if (ev.key === 'ArrowLeft') { panBy(-pan, 0); }
      else if (ev.key === 'ArrowRight') { panBy(pan, 0); }
      else if (ev.key === 'ArrowUp') { panBy(0, pan); }
      else if (ev.key === 'ArrowDown') { panBy(0, -pan); }
      else { return; }
      ev.preventDefault();
    });
  }

  function panBy(wx, wy) {
    camera.left -= wx; camera.right -= wx; camera.top -= wy; camera.bottom -= wy;
    camera.position.x -= wx; camera.position.y -= wy;
    camera.updateProjectionMatrix(); render();
  }
  function zoomCenter(factor) {
    const cx = (camera.left + camera.right) / 2, cy = (camera.top + camera.bottom) / 2;
    const hw = (camera.right - camera.left) / 2 * factor, hh = (camera.top - camera.bottom) / 2 * factor;
    camera.left = cx - hw; camera.right = cx + hw; camera.top = cy + hh; camera.bottom = cy - hh;
    camera.updateProjectionMatrix(); render();
  }
  function zoomAt(ev, factor) {
    const rect = renderer.domElement.getBoundingClientRect();
    const nx = (ev.clientX - rect.left) / rect.width;
    const ny = (ev.clientY - rect.top) / rect.height;
    const wx = camera.left + nx * (camera.right - camera.left);
    const wy = camera.top - ny * (camera.top - camera.bottom);
    camera.left = wx + (camera.left - wx) * factor;
    camera.right = wx + (camera.right - wx) * factor;
    camera.top = wy + (camera.top - wy) * factor;
    camera.bottom = wy + (camera.bottom - wy) * factor;
    camera.updateProjectionMatrix(); render();
  }

  function nearestNode(ev) {
    const rect = renderer.domElement.getBoundingClientRect();
    const nx = (ev.clientX - rect.left) / rect.width;
    const ny = (ev.clientY - rect.top) / rect.height;
    const wx = camera.left + nx * (camera.right - camera.left);
    const wy = camera.top - ny * (camera.top - camera.bottom);
    const tol = (camera.right - camera.left) / (rect.width || 1) * 12; // ~12px in world units
    let best = null, bestD = tol * tol;
    model.pos.forEach(function (p, id) {
      const dx = p.x - wx, dy = p.y - wy, d = dx * dx + dy * dy;
      if (d < bestD) { bestD = d; best = id; }
    });
    return best;
  }
  function pick(ev) {
    const id = nearestNode(ev);
    if (id === null) { return; }
    const node = model.nodes[model.index.get(id)];
    if (clickCb && node) { clickCb(node); }
  }
  function hover(ev) {
    const id = nearestNode(ev);
    if (id !== hoverId) {
      hoverId = id;
      renderer.domElement.style.cursor = id === null ? 'grab' : 'pointer';
      renderLabels();
      render();
    }
  }

  // ── Render (single frame — no perpetual loop) ──────────────────────────────
  let raf = 0;
  function render() {
    if (!renderer) { return; }
    if (raf) { return; }
    raf = requestAnimationFrame(function () {
      raf = 0;
      renderer.render(scene, camera);
      renderLabels();
    });
  }

  function setTheme(id, override) {
    themeId = id || themeId;
    tokens = tokensFor(themeId, override);
    if (renderer) { renderer.setClearColor(tokens.bg, 1); }
    if (model.nodes.length) { rebuild(); }
    render();
  }

  function onNodeClick(fn) { clickCb = typeof fn === 'function' ? fn : null; }

  // ── Teardown ───────────────────────────────────────────────────────────────
  function add(target, type, fn, opts) { target.addEventListener(type, fn, opts || false); listeners.push([target, type, fn, opts || false]); }
  function disposeSceneObjects() {
    [nodePoints, edgeLines, pathLines].forEach(function (o) {
      if (!o) { return; }
      scene.remove(o);
      if (o.geometry) { o.geometry.dispose(); }
      if (o.material) { o.material.dispose(); }
    });
    nodePoints = edgeLines = pathLines = null;
  }
  function destroy() {
    if (raf) { cancelAnimationFrame(raf); raf = 0; }
    listeners.forEach(function (l) { l[0].removeEventListener(l[1], l[2], l[3]); });
    listeners = [];
    if (ro) { ro.disconnect(); ro = null; }
    disposeSceneObjects();
    if (disc) { disc.dispose(); disc = null; }
    if (renderer) { renderer.dispose(); if (renderer.domElement && renderer.domElement.parentNode) { renderer.domElement.parentNode.removeChild(renderer.domElement); } renderer = null; }
    if (labelLayer && labelLayer.parentNode) { labelLayer.parentNode.removeChild(labelLayer); }
    labelLayer = null; scene = null; camera = null; container = null;
  }

  const handle = { mount: mount, setData: setData, expandData: expandData, setTheme: setTheme, onNodeClick: onNodeClick, resize: resize, destroy: destroy };
  return handle;
}

export default createLinkGraphRenderer;
