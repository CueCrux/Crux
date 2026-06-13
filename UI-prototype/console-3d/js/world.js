/* ════════════════════════════════════════════════════════════════════════
   Crux Substrate — world builder
   Soft clay-render substrate (Vectr-style). One block form for every node:
   plinth + slab, tinted by state (execplans stack one slab per milestone,
   the daemon is simply a bigger block). Labels are printed FLAT on the top
   face (canvas textures). Links are FLAT circuit traces on the ground
   (L-routed ribbons) with flowing particles. No postprocessing — glow is
   additive sprites + emissive lamps.
   ════════════════════════════════════════════════════════════════════════ */
import * as THREE from 'three';
import { RoundedBoxGeometry } from 'three/addons/geometries/RoundedBoxGeometry.js';
import { NODES, LINKS, DISTRICTS, KIND_LABELS, RINGS } from './data.js';

export const THEMES = {
  light: {
    bg: 0xdde6f2, fogNear: 100, fogFar: 310,
    ground: 0xe3eaf4, clay: 0xf5f8fc, clayShade: 0xe9eef7,
    ink: 0x0f172a, accent: 0x5e6ad2,
    inkCss: '#0b1830', inkSubCss: 'rgba(60,75,99,.85)', accentCss: '#5e6ad2',
    dot: 0x7fa8d9, dotOpacity: 0.55,
    bossBase: 0x596272,   /* dark grey washers (operator request) */
    status: { ok: 0x16a34a, run: 0xd97706, err: 0xdc2626, idle: 0x8093ab },
    stateTint: { done: 0xdcefe2, in_progress: 0xfbe9cf, blocked: 0xf6d8d8, planned: 0xeef1f7 },
    edge: { binds: 0x5e6ad2, drives: 0x3b82f6, gates: 0xd97706, seals: 0x16a34a,
            chain: 0x4fb286, coord: 0x0891b2, handoff: 0x8b5cf6 },
    edgeOpacity: 0.46, hemi: [0xffffff, 0xc4d2e6, 1.15], sun: 1.6,
  },
  dark: {
    /* lightened (operator request): brighter surfaces, fog pushed far out */
    bg: 0x12151d, fogNear: 200, fogFar: 560,
    ground: 0x181c26, clay: 0x323848, clayShade: 0x272d3b,
    ink: 0xededef, accent: 0x7d88e8,
    inkCss: '#eef0f6', inkSubCss: 'rgba(176,182,196,.9)', accentCss: '#9aa4f4',
    dot: 0x4a5b80, dotOpacity: 0.8,
    bossBase: 0x262c38,   /* dark grey washers */
    status: { ok: 0x22c55e, run: 0xf59e0b, err: 0xef4444, idle: 0x64748b },
    stateTint: { done: 0x2c4d39, in_progress: 0x534222, blocked: 0x532c2c, planned: 0x333a4c },
    edge: { binds: 0x7d88e8, drives: 0x60a5fa, gates: 0xf59e0b, seals: 0x34d399,
            chain: 0x2dd4bf, coord: 0x22d3ee, handoff: 0xa78bfa },
    edgeOpacity: 0.58, hemi: [0x8a97ba, 0x1a1f2c, 1.1], sun: 1.25,
  },
};

/* status → block tint bucket (uniform block, colour carries the state) */
const STATUS_TINT = { ok: 'done', run: 'in_progress', err: 'blocked', idle: 'planned' };

/* ×1.5 footprint (operator request): wider/longer blocks, heights unchanged */
const BLOCK = { foot: 8.1, plinth: 9.3, slabH: 1.5, msH: 0.95, msGap: 0.2 };

/* ring platforms: nodes stand ON extruded annular bosses this tall */
export const RING_H = 0.45;
/* all traces ride ONE level — just above the boss tops; the radial layout
   keeps them from overlapping (links radiate along lineage bearings) */
const TRACE_Y = RING_H + 0.07;

/* one big letter per kind, stamped in a corner of every top face */
const KIND_BADGE = {
  daemon: 'D', passport: 'P', session: 'S', execplan: 'E', fact: 'F',
  receipt: 'R', coord: 'C', overlap: '!', punchcard: 'L',
  boot: 'B', tool: 'T', retrieve: 'Q', chunks: 'K', reasoning: 'N',
  submit: 'S', gate: 'G', milestone: 'M', seal: '✓', tokens: 'Σ',
};
const KIND_HUE = {
  daemon: 0x5e6ad2, passport: 0x5e6ad2, session: 0x0891b2, execplan: 0x3b82f6,
  fact: 0xd97706, receipt: 0x16a34a, coord: 0x14b8a6, overlap: 0xdc2626,
  punchcard: 0xd97706, boot: 0x5e6ad2, tool: 0x14b8a6, retrieve: 0x0891b2,
  chunks: 0xd97706, reasoning: 0x8b5cf6, submit: 0xdc2626, gate: 0xdc2626,
  milestone: 0x5e6ad2, seal: 0x16a34a, tokens: 0x3b82f6,
};

/* speckled grain for the ring bosses (multiplies the base colour darker) */
function bossGrainTexture() {
  const c = document.createElement('canvas'); c.width = c.height = 256;
  const g = c.getContext('2d');
  g.fillStyle = '#ffffff'; g.fillRect(0, 0, 256, 256);
  for (let i = 0; i < 520; i++) {
    g.fillStyle = `rgba(0,0,0,${(Math.random() * 0.12 + 0.04).toFixed(3)})`;
    g.beginPath();
    g.arc(Math.random() * 256, Math.random() * 256, Math.random() * 1.7 + 0.4, 0, 7);
    g.fill();
  }
  for (let i = 0; i < 26; i++) {
    g.strokeStyle = `rgba(0,0,0,${(Math.random() * 0.05 + 0.02).toFixed(3)})`;
    g.lineWidth = Math.random() * 1.1 + 0.4;
    const y = Math.random() * 256;
    g.beginPath(); g.moveTo(0, y); g.lineTo(256, y + (Math.random() * 26 - 13)); g.stroke();
  }
  const t = new THREE.CanvasTexture(c);
  t.wrapS = t.wrapT = THREE.RepeatWrapping;
  t.repeat.set(0.08, 0.08);
  return t;
}

function softCircleTexture() {
  const c = document.createElement('canvas'); c.width = c.height = 128;
  const g = c.getContext('2d');
  const grad = g.createRadialGradient(64, 64, 0, 64, 64, 64);
  grad.addColorStop(0, 'rgba(255,255,255,1)');
  grad.addColorStop(0.35, 'rgba(255,255,255,.55)');
  grad.addColorStop(1, 'rgba(255,255,255,0)');
  g.fillStyle = grad; g.fillRect(0, 0, 128, 128);
  const tex = new THREE.CanvasTexture(c); tex.colorSpace = THREE.SRGBColorSpace;
  return tex;
}

/* split a label into ≤2 lines at the friendliest separator */
function wrapLabel(label) {
  if (label.length <= 18) return [label];
  const seps = [' · ', '://', ':', '-', ' ', '.', '_'];
  let best = null;
  for (const s of seps) {
    let idx = -1, from = 0;
    while (true) {
      const i = label.indexOf(s, from);
      if (i < 0) break;
      if (best === null || Math.abs(i - label.length / 2) < Math.abs(best.i - label.length / 2))
        best = { i, s };
      from = i + 1;
    }
    if (best) break;   /* take the highest-priority separator that exists */
  }
  if (!best) return [label.slice(0, Math.ceil(label.length / 2)), label.slice(Math.ceil(label.length / 2))];
  const keep = best.s === ' ' ? '' : best.s;
  return [label.slice(0, best.i + (best.s === ' ' ? 0 : best.s.length)), label.slice(best.i + best.s.length)]
    .map((l, idx2) => (idx2 === 0 && keep && !l.endsWith(keep.trim()) ? l : l).trim());
}

export class World {
  constructor(scene, themeName = 'light', maxAniso = 4) {
    this.scene = scene;
    this.theme = THEMES[themeName];
    this.maxAniso = maxAniso;
    this.nodeGroups = new Map();    // id -> THREE.Group
    this.lamps = [];                // {mesh, status, baseY}
    this.clayMats = [];             // matte mats to retint on theme change
    this.tintMats = [];             // {mat, key}
    this.statusMats = [];           // {mat, key}
    this.edgeItems = [];            // {link, path, mats[], key}
    this.tops = [];                 // {canvas, tex, node} flat top-face labels
    this.haloTex = softCircleTexture();
    this.halos = new Map();         // id -> sprite
    this._buildLights();
    this._buildGround();
    this._buildNodes();
    this._buildEdges();
    this._buildParticles();
    this.applyTheme(themeName);
    this.visibleGroups = [...this.nodeGroups.values()];
    this.visiblePicks = [...this.pickMeshes];
    this._tmpV = new THREE.Vector3();
    this._tmpC = new THREE.Color();
    this.shadowDirty = true;
  }

  /* ── environment ──────────────────────────────────────────────────────── */
  _buildLights() {
    this.hemi = new THREE.HemisphereLight(0xffffff, 0xc4d2e6, 1.15);
    this.scene.add(this.hemi);
    this.sun = new THREE.DirectionalLight(0xffffff, 1.6);
    this.sun.position.set(38, 64, 22);
    this.sun.castShadow = true;
    this.sun.shadow.mapSize.set(2048, 2048);
    const d = 108;   /* must cover the ×1.5-scaled districts */
    Object.assign(this.sun.shadow.camera, { left: -d, right: d, top: d, bottom: -d, near: 10, far: 220 });
    this.sun.shadow.bias = -0.0004;
    this.scene.add(this.sun);
    this.fill = new THREE.DirectionalLight(0xdfe8ff, 0.35);
    this.fill.position.set(-40, 30, -30);
    this.scene.add(this.fill);
  }

  _buildGround() {
    this.groundMat = new THREE.MeshStandardMaterial({ color: 0xe3eaf4, roughness: 1, metalness: 0 });
    const ground = new THREE.Mesh(new THREE.CircleGeometry(340, 72), this.groundMat);
    ground.rotation.x = -Math.PI / 2;
    ground.receiveShadow = true;
    this.scene.add(ground);

    /* dot-ripple field around the current focus point */
    this.dotUniforms = {
      uColor:   { value: new THREE.Color(0x7fa8d9) },
      uFocus:   { value: new THREE.Vector2(0, 0) },
      uTime:    { value: 0 },
      uOpacity: { value: 0.55 },
    };
    const dotMat = new THREE.ShaderMaterial({
      transparent: true, depthWrite: false,
      uniforms: this.dotUniforms,
      vertexShader: `
        varying vec3 vWorld;
        void main(){
          vec4 wp = modelMatrix * vec4(position,1.0);
          vWorld = wp.xyz;
          gl_Position = projectionMatrix * viewMatrix * wp;
        }`,
      fragmentShader: `
        uniform vec3 uColor; uniform vec2 uFocus; uniform float uTime; uniform float uOpacity;
        varying vec3 vWorld;
        void main(){
          vec2 cell = fract(vWorld.xz * 0.5) - 0.5;
          float dotMask = 1.0 - smoothstep(0.13, 0.20, length(cell));
          float distF = distance(vWorld.xz, uFocus);
          float area = 1.0 - smoothstep(9.0, 36.0, distF);
          float wave = 0.6 + 0.4 * sin(uTime * 1.6 - distF * 0.5);
          float a = dotMask * area * wave * uOpacity;
          if (a < 0.01) discard;
          gl_FragColor = vec4(uColor, a);
        }`,
    });
    const dots = new THREE.Mesh(new THREE.PlaneGeometry(400, 400), dotMat);
    dots.rotation.x = -Math.PI / 2;
    dots.position.y = RING_H + 0.015;   /* ride just above the ring bosses */
    this.scene.add(dots);

    /* ring platforms — REAL geometry: one annular boss (circular slab with a
       hole) per lineage ring + a solid podium for the daemon. Nodes stand on
       top (group y = RING_H). Architecture, so always visible. */
    this.bossGroup = new THREE.Group();
    this.bossMats = [];   /* {mat, hue} — retinted per theme in applyTheme */
    const grain = bossGrainTexture();
    const BAND = 4.6;     /* half-width of each annulus band */
    for (const ring of RINGS) {
      let geo;
      if (ring.solid) {
        geo = new THREE.CylinderGeometry(ring.r, ring.r + 0.3, RING_H, 72);
      } else {
        const shape = new THREE.Shape();
        shape.absarc(0, 0, ring.r + BAND, 0, Math.PI * 2, false);
        const hole = new THREE.Path();
        hole.absarc(0, 0, ring.r - BAND, 0, Math.PI * 2, true);
        shape.holes.push(hole);
        geo = new THREE.ExtrudeGeometry(shape, { depth: RING_H, bevelEnabled: false, curveSegments: 96 });
      }
      const mat = new THREE.MeshStandardMaterial({ color: 0xffffff, roughness: 0.96, metalness: 0, map: grain });
      this.bossMats.push({ mat, hue: ring.hue || null });
      const m = new THREE.Mesh(geo, mat);
      if (ring.solid) m.position.y = RING_H / 2;
      else m.rotation.x = -Math.PI / 2;   /* extrusion depth points up */
      m.receiveShadow = true;
      this.bossGroup.add(m);
    }
    this.scene.add(this.bossGroup);
  }

  /* ── materials ────────────────────────────────────────────────────────── */
  _clay(shade = false) {
    const m = new THREE.MeshStandardMaterial({ color: 0xf5f8fc, roughness: 0.92, metalness: 0 });
    m.userData.shade = shade;
    this.clayMats.push(m);
    return m;
  }
  _tint(key) {
    const m = new THREE.MeshStandardMaterial({ color: 0xffffff, roughness: 0.85, metalness: 0 });
    this.tintMats.push({ mat: m, key });
    return m;
  }
  _statusMat(key, emissive = 0.55) {
    const m = new THREE.MeshStandardMaterial({ color: 0xffffff, roughness: 0.45, metalness: 0,
      emissive: 0xffffff, emissiveIntensity: emissive });
    this.statusMats.push({ mat: m, key });
    return m;
  }

  _mesh(geo, mat, x, y, z, group, shadow = true) {
    const m = new THREE.Mesh(geo, mat);
    m.position.set(x, y, z);
    if (shadow) { m.castShadow = true; m.receiveShadow = true; }
    group.add(m);
    return m;
  }

  /* ── flat top-face label ──────────────────────────────────────────────── */
  _drawTop(canvas, n) {
    const g = canvas.getContext('2d');
    const th = this.theme;
    const CW = canvas.width, CH = canvas.height, CX = CW / 2;
    g.clearRect(0, 0, CW, CH);
    g.textAlign = 'center'; g.textBaseline = 'middle';
    /* corner badge: one big letter so the kind reads at any distance —
       the daemon carries the arc-loop brand mark instead */
    const hue = '#' + new THREE.Color(KIND_HUE[n.kind] || 0x5e6ad2).getHexString();
    if (n.kind === 'daemon') {
      g.strokeStyle = hue; g.lineWidth = 10; g.lineCap = 'round';
      g.beginPath(); g.arc(64, 64, 31, -0.5, 4.25); g.stroke();   /* open arc-loop */
      g.fillStyle = hue;
      g.beginPath(); g.arc(64, 64, 11, 0, 7); g.fill();           /* centre dot */
    } else {
      const ch = KIND_BADGE[n.kind] || (n.kind || '?')[0].toUpperCase();
      g.globalAlpha = 0.16; g.fillStyle = hue;
      g.beginPath(); g.roundRect(22, 22, 84, 84, 18); g.fill();
      g.globalAlpha = 1;
      g.strokeStyle = hue; g.lineWidth = 3;
      g.beginPath(); g.roundRect(22, 22, 84, 84, 18); g.stroke();
      g.fillStyle = hue;
      g.font = '800 58px "JetBrains Mono", ui-monospace, monospace';
      g.fillText(ch, 64, 66);
    }
    try { g.letterSpacing = '6px'; } catch (e) { /* older canvas */ }
    g.fillStyle = n.kind === 'daemon' ? th.accentCss : th.inkSubCss;
    g.font = '700 36px "JetBrains Mono", ui-monospace, monospace';
    g.fillText((KIND_LABELS[n.kind] || n.kind).toUpperCase(), CX + 42, 48);
    try { g.letterSpacing = '0px'; } catch (e) { /* noop */ }
    g.fillStyle = th.inkCss;
    const lines = wrapLabel(n.label);
    let f = 62;
    g.font = `700 ${f}px "JetBrains Mono", ui-monospace, monospace`;
    while (f > 28 && lines.some((l) => g.measureText(l).width > CW - 56)) {
      f -= 2;
      g.font = `700 ${f}px "JetBrains Mono", ui-monospace, monospace`;
    }
    if (lines.length === 1) g.fillText(lines[0], CX, 142);
    else { g.fillText(lines[0], CX, 116); g.fillText(lines[1], CX, 180); }
    /* sub line — the extra per-node detail on the face */
    if (n.sub) {
      g.fillStyle = th.inkSubCss;
      let s = 28;
      g.font = `500 ${s}px "JetBrains Mono", ui-monospace, monospace`;
      let sub = n.sub;
      while (g.measureText(sub).width > CW - 60 && sub.length > 6) sub = sub.slice(0, -2);
      if (sub !== n.sub) sub += '…';
      g.fillText(sub, CX, CH - 52);
    }
  }

  _topLabel(group, n, topY, w, h) {
    const canvas = document.createElement('canvas');
    canvas.width = 640; canvas.height = 320;
    this._drawTop(canvas, n);
    const tex = new THREE.CanvasTexture(canvas);
    tex.colorSpace = THREE.SRGBColorSpace;
    tex.anisotropy = this.maxAniso;
    const plane = new THREE.Mesh(
      new THREE.PlaneGeometry(w, h),
      new THREE.MeshBasicMaterial({ map: tex, transparent: true, depthWrite: false }));
    plane.rotation.x = -Math.PI / 2;
    plane.position.y = topY + 0.02;
    group.add(plane);
    this.tops.push({ canvas, tex, node: n });
  }

  redrawTops() {
    for (const t of this.tops) { this._drawTop(t.canvas, t.node); t.tex.needsUpdate = true; }
  }

  /* ── nodes — one block form for everything ────────────────────────────── */
  _buildNodes() {
    for (const n of NODES) {
      const g = new THREE.Group();
      g.position.set(n.pos[0], RING_H, n.pos[1]);   /* standing on its ring boss */
      g.userData.node = n;
      g.userData.home = new THREE.Vector3(n.pos[0], RING_H, n.pos[1]);   /* ring slot for restore */

      let topY;
      if (n.kind === 'daemon') {
        this._mesh(new RoundedBoxGeometry(16.5, 0.6, 16.5, 2, 0.2), this._clay(true), 0, 0.3, 0, g);
        this._mesh(new RoundedBoxGeometry(12.9, 3.1, 12.9, 3, 0.26), this._clay(), 0, 0.6 + 1.55, 0, g);
        topY = 3.7;
        this._topLabel(g, n, topY, 12.3, 6.15);
      } else if (n.kind === 'execplan') {
        this._mesh(new RoundedBoxGeometry(BLOCK.plinth, 0.4, BLOCK.plinth, 2, 0.12), this._clay(true), 0, 0.2, 0, g);
        /* uniform footprint; slab HEIGHT scales with the milestone's tokens */
        const maxTok = Math.max(1, ...(n.milestones || []).map((m) => m.tok || 1));
        let y = 0.4;
        for (const ms of n.milestones || []) {
          const h = 0.5 + 1.85 * ((ms.tok || 1) / maxTok);
          y += BLOCK.msGap + h / 2;
          this._mesh(new RoundedBoxGeometry(BLOCK.foot, h, BLOCK.foot, 2, 0.12),
            this._tint(ms.state), 0, y, 0, g);
          y += h / 2;
        }
        topY = y;
        this._topLabel(g, n, topY, 7.7, 3.85);
      } else {
        this._mesh(new RoundedBoxGeometry(BLOCK.plinth, 0.4, BLOCK.plinth, 2, 0.12), this._clay(true), 0, 0.2, 0, g);
        this._mesh(new RoundedBoxGeometry(BLOCK.foot, BLOCK.slabH, BLOCK.foot, 2, 0.14),
          this._tint(STATUS_TINT[n.status] || 'planned'), 0, 0.4 + BLOCK.slabH / 2, 0, g);
        topY = 0.4 + BLOCK.slabH;
        this._topLabel(g, n, topY, 7.7, 3.85);
      }
      g.userData.topY = topY;

      /* status lamp on the front-right corner of the top face */
      const lampOff = n.kind === 'daemon' ? 5.6 : 3.3;
      const lamp = this._mesh(new THREE.SphereGeometry(0.22, 18, 14),
        this._statusMat(n.status), lampOff, topY + 0.2, lampOff, g, false);
      this.lamps.push({ mesh: lamp, status: n.status, baseY: topY + 0.2 });

      /* invisible pick proxy — raycasting tests ONLY these 1-box-per-node
         meshes, never the full block geometry (mouse-move CPU guard) */
      const pickW = n.kind === 'daemon' ? 16.7 : BLOCK.plinth + 0.2;
      const pick = new THREE.Mesh(
        new THREE.BoxGeometry(pickW, topY + 1.2, pickW),
        new THREE.MeshBasicMaterial({ visible: false }));
      pick.position.y = (topY + 1.2) / 2;
      pick.userData.node = n;
      g.add(pick);
      (this.pickMeshes ||= []).push(pick);

      /* hover/focus halo */
      const halo = new THREE.Sprite(new THREE.SpriteMaterial({
        map: this.haloTex, color: 0x5e6ad2, transparent: true, opacity: 0,
        blending: THREE.AdditiveBlending, depthWrite: false }));
      halo.scale.setScalar(n.kind === 'daemon' ? 22 : 14);
      halo.position.y = topY + 0.4;
      g.add(halo);
      this.halos.set(n.id, halo);

      this.scene.add(g);
      this.nodeGroups.set(n.id, g);
    }
  }

  /* ── edges — polar traces that sweep around the rings, never through the
     core: radius and bearing interpolate together, so a trace between two
     rings spirals along the disc instead of cutting across the middle ───── */
  _polarPoints(a, b, y) {
    const SEG = 28;
    const rA = Math.hypot(a.x, a.z), rB = Math.hypot(b.x, b.z);
    const angB0 = rB < 1e-3 ? 0 : Math.atan2(b.z, b.x);
    const angA = rA < 1e-3 ? angB0 : Math.atan2(a.z, a.x);
    const angB = rB < 1e-3 ? angA : angB0;
    let d = angB - angA;
    while (d > Math.PI) d -= Math.PI * 2;
    while (d < -Math.PI) d += Math.PI * 2;
    const pts = [];
    for (let s = 0; s <= SEG; s++) {
      const t = s / SEG, r = rA + (rB - rA) * t, an = angA + d * t;
      pts.push(new THREE.Vector3(Math.cos(an) * r, y, Math.sin(an) * r));
    }
    return pts;
  }
  _buildEdges() {
    /* rebuildable: traces re-route whenever nodes move (line-up / neighborhood) */
    if (!this.edgeGroup) { this.edgeGroup = new THREE.Group(); this.scene.add(this.edgeGroup); }
    for (const ch of [...this.edgeGroup.children]) { ch.geometry.dispose(); ch.material.dispose(); this.edgeGroup.remove(ch); }
    this.edgeItems = [];
    const W = 0.34, H = 0.07;
    LINKS.forEach((link, idx) => {
      const a = this.nodeGroups.get(link.from).position;
      const b = this.nodeGroups.get(link.to).position;
      const y = TRACE_Y + (idx % 7) * 0.004;       /* hairline lift kills z-fighting only */
      const mat = new THREE.MeshBasicMaterial({ color: 0xffffff, transparent: true,
        opacity: 0.3, depthWrite: false });
      /* flat ribbon: tube along the polar curve (built at y=0), squashed in Y */
      const flat = new THREE.CatmullRomCurve3(this._polarPoints(a, b, 0));
      const seg = new THREE.Mesh(new THREE.TubeGeometry(flat, 56, W / 2, 6, false), mat);
      seg.scale.y = H / W;
      seg.position.y = y;
      this.edgeGroup.add(seg);
      const path = new THREE.CatmullRomCurve3(this._polarPoints(a, b, y));   /* particle rail at trace height */
      this.edgeItems.push({ link, path, mats: [mat], key: link.from + '|' + link.to, mid: path.getPointAt(0.5) });
    });
    this.edgeByKey = new Map(this.edgeItems.map((e) => [e.key, e]));
  }

  rebuildEdges() {
    this._buildEdges();
    const th = this.theme;
    for (const e of this.edgeItems) {
      const col = th.edge[e.link.rel] ?? th.accent;
      for (const m of e.mats) m.color.set(col);
    }
    this._applyVisibility();   /* re-apply hide flags after rebuild */
  }

  /* show only one district's nodes (daemon always stays). null = everything. */
  setDistrictFilter(districtId) {
    this.filterDistrict = districtId || null;
    this.visibleSet = null;
    this._applyVisibility();
  }

  /* arbitrary visible set (neighborhood expand). null = everything. */
  setVisibleSet(idSet) {
    this.visibleSet = idSet || null;
    this.filterDistrict = null;
    this._applyVisibility();
  }

  _applyVisibility() {
    for (const g of this.nodeGroups.values()) {
      const n = g.userData.node;
      g.visible = this.visibleSet
        ? this.visibleSet.has(n.id)
        : (!this.filterDistrict || n.district === this.filterDistrict || n.kind === 'daemon');
    }
    for (const e of this.edgeItems) {
      const a = this.nodeGroups.get(e.link.from), b = this.nodeGroups.get(e.link.to);
      e.hidden = !(a && b && a.visible && b.visible);
    }
    this.visibleGroups = [...this.nodeGroups.values()].filter((g) => g.visible);
    this.visiblePicks = this.pickMeshes.filter((m) => m.parent.visible);
    this.shadowDirty = true;   /* visibility changed → one shadow re-render */
  }

  edgeMid(key) {
    const e = this.edgeByKey.get(key);
    return e ? e.mid : null;
  }

  /* glide a node to a new slot; traces hide while anything is in flight and
     re-route once everything settles */
  setNodeTarget(id, x, z, y = RING_H) {
    (this.moveTargets ||= new Map()).set(id, new THREE.Vector3(x, y, z));
    this.edgesHidden = true;
  }

  _buildParticles() {
    const PER = 3;
    this.particle = { per: PER, count: this.edgeItems.length * PER };
    const pos = new Float32Array(this.particle.count * 3);
    const col = new Float32Array(this.particle.count * 3);
    const geo = new THREE.BufferGeometry();
    geo.setAttribute('position', new THREE.BufferAttribute(pos, 3));
    geo.setAttribute('color', new THREE.BufferAttribute(col, 3));
    const mat = new THREE.PointsMaterial({ size: 0.8, map: this.haloTex, vertexColors: true,
      transparent: true, depthWrite: false, blending: THREE.AdditiveBlending, sizeAttenuation: true });
    this.points = new THREE.Points(geo, mat);
    this.points.frustumCulled = false;
    this.scene.add(this.points);
  }

  /* ── runtime ──────────────────────────────────────────────────────────── */
  setFocusPoint(x, z) {
    this.dotUniforms.uFocus.value.set(x, z);
  }

  setHalo(id, on, colorHex) {
    const h = this.halos.get(id);
    if (!h) return;
    h.material.opacity = on ? 0.4 : 0;
    if (colorHex !== undefined) h.material.color.set(colorHex);
  }

  /* activeBeams: Set of "from|to" keys; reducedMotion: freeze flow */
  update(t, dt, activeBeams, reducedMotion) {
    this.dotUniforms.uTime.value = reducedMotion ? 0 : t;
    const th = this.theme;

    /* glide moving nodes; re-route traces once everything has settled */
    if (this.moveTargets && this.moveTargets.size) {
      let maxd = 0;
      for (const [id, tg] of this.moveTargets) {
        const g = this.nodeGroups.get(id);
        if (!g) continue;
        if (reducedMotion) g.position.copy(tg);
        else g.position.lerp(tg, 1 - Math.exp(-(dt || 0.016) * 5));
        maxd = Math.max(maxd, g.position.distanceTo(tg));
      }
      if (maxd < 0.05) {
        for (const [id, tg] of this.moveTargets) this.nodeGroups.get(id)?.position.copy(tg);
        this.moveTargets.clear();
        this.rebuildEdges();
        this.edgesHidden = false;
      }
      this.shadowDirty = true;   /* nodes in flight → shadows follow */
    }

    for (const l of this.lamps) {
      if (l.status === 'run' && !reducedMotion) {
        const s = 1 + 0.18 * Math.sin(t * 2.4 + l.baseY * 7);
        l.mesh.scale.setScalar(s);
      }
    }

    for (const e of this.edgeItems) {
      const active = activeBeams && activeBeams.has(e.key);
      const o = (this.edgesHidden || e.hidden) ? 0 : active
        ? th.edgeOpacity + 0.5 * (reducedMotion ? 1 : (0.6 + 0.4 * Math.sin(t * 3.0)))
        : th.edgeOpacity;
      for (const m of e.mats) m.opacity = o;
    }

    /* particles flow along the flat traces (no per-frame allocations) */
    const posA = this.points.geometry.attributes.position;
    const colA = this.points.geometry.attributes.color;
    const c = this._tmpC, v = this._tmpV;
    let i = 0;
    for (const e of this.edgeItems) {
      const active = activeBeams && activeBeams.has(e.key);
      const speed = (active ? 0.2 : 0.045) * (reducedMotion ? 0 : 1);
      const intensity = (this.edgesHidden || e.hidden) ? 0 : (active ? 1.0 : 0.26);
      c.set(th.edge[e.link.rel] ?? th.accent).multiplyScalar(intensity);
      for (let p = 0; p < this.particle.per; p++) {
        const tt = (p / this.particle.per + t * speed + (reducedMotion ? p * 0.13 : 0)) % 1;
        e.path.getPointAt(tt, v);
        posA.setXYZ(i, v.x, v.y + 0.18, v.z);
        colA.setXYZ(i, c.r, c.g, c.b);
        i++;
      }
    }
    posA.needsUpdate = true;
    colA.needsUpdate = true;
  }

  applyTheme(name) {
    const th = this.theme = THEMES[name];
    this.scene.background = new THREE.Color(th.bg);
    this.scene.fog = new THREE.Fog(th.bg, th.fogNear, th.fogFar);
    this.groundMat.color.set(th.ground);
    this.hemi.color.set(th.hemi[0]); this.hemi.groundColor.set(th.hemi[1]); this.hemi.intensity = th.hemi[2];
    this.sun.intensity = th.sun;
    for (const m of this.clayMats) m.color.set(m.userData.shade ? th.clayShade : th.clay);
    /* ring bosses: uniform dark grey + grain map (per-level hues parked) */
    for (const { mat } of this.bossMats || []) mat.color.set(th.bossBase);
    for (const { mat, key } of this.tintMats) mat.color.set(th.stateTint[key] ?? th.clay);
    for (const { mat, key } of this.statusMats) {
      mat.color.set(th.status[key] ?? th.status.idle);
      mat.emissive.set(th.status[key] ?? th.status.idle);
    }
    for (const e of this.edgeItems) {
      const col = th.edge[e.link.rel] ?? th.accent;
      for (const m of e.mats) m.color.set(col);
    }
    this.dotUniforms.uColor.value.set(th.dot);
    this.dotUniforms.uOpacity.value = th.dotOpacity;
    this.redrawTops();
    this.shadowDirty = true;
  }

  /* ── ephemeral stat blocks (token in→out, tools used) for neighborhoods ── */
  spawnStatBlocks(specs) {
    this.clearStatBlocks();
    if (!specs || !specs.length) return;
    const th = this.theme;
    this.statGroup = new THREE.Group();
    for (const s of specs) {
      const g = new THREE.Group();
      g.position.set(s.x, RING_H, s.z);
      /* token gauges: slim blue half-transparent towers, DOUBLE height scale.
         tool markers: half footprint, teal. value = block height. */
      const isTok = s.kind === 'tokens';
      const w = isTok ? 1.3 : (s.kind === 'tool' ? 1.95 : 3.9);
      const pw = w + 0.7;
      const h = isTok ? 1.2 + 3.8 * (s.share ?? 1) : 0.6 + 1.9 * (s.share ?? 1);
      const plinth = new THREE.Mesh(new RoundedBoxGeometry(pw, 0.34, pw, 2, 0.1),
        new THREE.MeshStandardMaterial({ color: th.clayShade, roughness: 0.92 }));
      plinth.position.y = 0.17; plinth.castShadow = plinth.receiveShadow = true;
      g.add(plinth);
      const hue = new THREE.Color(KIND_HUE[s.kind] || th.accent);
      const tint = isTok
        ? hue.clone().lerp(new THREE.Color(th.clay), 0.25)        /* strongly blue */
        : new THREE.Color(th.clay).lerp(hue, s.kind === 'tool' ? 0.32 : 0.18);
      const slab = new THREE.Mesh(new RoundedBoxGeometry(w, h, w, 2, 0.1),
        new THREE.MeshStandardMaterial({ color: tint, roughness: 0.8,
          transparent: isTok, opacity: isTok ? 0.5 : 1, depthWrite: !isTok }));
      slab.position.y = 0.34 + h / 2; slab.castShadow = slab.receiveShadow = true;
      g.add(slab);
      const canvas = document.createElement('canvas');
      canvas.width = 640; canvas.height = 320;
      this._drawTop(canvas, { kind: s.kind, label: s.label, sub: s.sub });
      const tex = new THREE.CanvasTexture(canvas);
      tex.colorSpace = THREE.SRGBColorSpace; tex.anisotropy = this.maxAniso;
      const lw = Math.max(w - 0.2, 2.6);   /* narrow towers keep a readable sign */
      const plane = new THREE.Mesh(new THREE.PlaneGeometry(lw, lw / 2),
        new THREE.MeshBasicMaterial({ map: tex, transparent: true, depthWrite: false }));
      plane.rotation.x = -Math.PI / 2;
      plane.position.y = 0.34 + h + 0.02;
      g.add(plane);
      this.statGroup.add(g);
    }
    this.scene.add(this.statGroup);
    this.shadowDirty = true;
  }

  clearStatBlocks() {
    if (!this.statGroup) return;
    this.statGroup.traverse((o) => {
      if (o.isMesh) {
        o.geometry.dispose();
        if (o.material.map) o.material.map.dispose();
        o.material.dispose();
      }
    });
    this.scene.remove(this.statGroup);
    this.statGroup = null;
    this.shadowDirty = true;
  }

  /* ── timeline mode: a left→right "line of events" with spur branches ──
     events: [{k, label, sub, lane}] · lane 0 = main rail, -1 = back spur,
     +1 = front spur. Ephemeral like stat blocks; rings hide while shown.  */
  spawnTimeline(events) {
    this.clearTimeline();
    if (!events || !events.length) return;
    const th = this.theme;
    const TINT = { boot: 0x5e6ad2, execplan: 0x3b82f6, milestone: 0x5e6ad2,
      tool: 0x3b82f6, retrieve: 0x0891b2, chunks: 0xd97706, fact: 0xd97706,
      reasoning: 0x8b5cf6, receipt: 0x16a34a, seal: 0x16a34a,
      submit: 0xdc2626, gate: 0xdc2626 };
    const SP = 6.2, SPUR = 7.4, W = 0.3, RAIL_Y = 0.07;
    const x0 = -((events.length - 1) * SP) / 2;
    this.timelineGroup = new THREE.Group();
    this.timelinePicks = [];
    const g = this.timelineGroup;
    /* the main rail, end to end */
    const railLen = (events.length - 1) * SP + SP * 1.6;
    const rail = new THREE.Mesh(new THREE.BoxGeometry(railLen, 0.07, W),
      new THREE.MeshBasicMaterial({ color: th.accent, transparent: true, opacity: 0.5, depthWrite: false }));
    rail.position.set(0, RAIL_Y, 0);
    g.add(rail);
    events.forEach((ev, i) => {
      const x = x0 + i * SP, lane = ev.lane || 0, z = lane * SPUR;
      if (lane !== 0) {
        /* spur branch off the rail */
        const spur = new THREE.Mesh(new THREE.BoxGeometry(W * 0.7, 0.06, Math.abs(z)),
          new THREE.MeshBasicMaterial({ color: TINT[ev.k] || th.accent, transparent: true, opacity: 0.55, depthWrite: false }));
        spur.position.set(x, RAIL_Y, z / 2);
        g.add(spur);
      }
      /* uniform footprint block — milestones/seals stand taller */
      const w = 3.4, pw = w + 0.6;
      const h = ev.k === 'seal' ? 2.2 : (ev.k === 'milestone' ? 1.7 : 1.15);
      const grp = new THREE.Group();
      grp.position.set(x, 0, z);
      const plinth = new THREE.Mesh(new RoundedBoxGeometry(pw, 0.32, pw, 2, 0.1),
        new THREE.MeshStandardMaterial({ color: th.clayShade, roughness: 0.92 }));
      plinth.position.y = 0.16; plinth.castShadow = plinth.receiveShadow = true;
      grp.add(plinth);
      const tint = new THREE.Color(th.clay).lerp(new THREE.Color(TINT[ev.k] || th.accent), 0.24);
      const slab = new THREE.Mesh(new RoundedBoxGeometry(w, h, w, 2, 0.12),
        new THREE.MeshStandardMaterial({ color: tint, roughness: 0.85 }));
      slab.position.y = 0.32 + h / 2; slab.castShadow = slab.receiveShadow = true;
      slab.userData.event = ev;            /* clickable → detail pane */
      this.timelinePicks.push(slab);
      grp.add(slab);
      const canvas = document.createElement('canvas');
      canvas.width = 640; canvas.height = 320;
      this._drawTop(canvas, { kind: ev.k, label: ev.label, sub: ev.sub });
      const tex = new THREE.CanvasTexture(canvas);
      tex.colorSpace = THREE.SRGBColorSpace; tex.anisotropy = this.maxAniso;
      const plane = new THREE.Mesh(new THREE.PlaneGeometry(w - 0.2, (w - 0.2) / 2),
        new THREE.MeshBasicMaterial({ map: tex, transparent: true, depthWrite: false }));
      plane.rotation.x = -Math.PI / 2;
      plane.position.y = 0.32 + h + 0.02;
      grp.add(plane);
      g.add(grp);
    });
    this.scene.add(g);
    this.shadowDirty = true;
  }

  clearTimeline() {
    if (!this.timelineGroup) return;
    this.timelineGroup.traverse((o) => {
      if (o.isMesh) {
        o.geometry.dispose();
        if (o.material.map) o.material.map.dispose();
        o.material.dispose();
      }
    });
    this.scene.remove(this.timelineGroup);
    this.timelineGroup = null;
    this.timelinePicks = [];
    this.shadowDirty = true;
  }
}

export { DISTRICTS, NODES, LINKS };
