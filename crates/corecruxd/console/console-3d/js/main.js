/* ════════════════════════════════════════════════════════════════════════
   Crux Substrate — boot, camera rig, interaction
   Story mode: scroll scrubs a camera dolly across the substrate (Vectr-style
   chapter rail). Explore mode: free orbit at the end of the scroll.
   Clicking a node NEVER moves the camera — it highlights the node + its
   links and opens the glass detail panel. Esc (or ✕, or scrolling) closes.
   ════════════════════════════════════════════════════════════════════════ */
import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';
import { World } from './world.js';
import { NODES, LINKS, CHAPTERS, DISTRICTS, HERO_CAM, EXPLORE_CAM, KIND_LABELS } from './data.js';

const $ = (s) => document.querySelector(s);
const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;

/* embed mode: hosted inside the classic console (iframe, ?embed=1[&theme=…]).
   Chrome hides, boot lands straight in explore, and the detail panel is the
   HOST's right pane — focus/unfocus round-trip over postMessage. */
const QP = new URLSearchParams(location.search);
const EMBED = QP.has('embed');
if (EMBED) document.documentElement.classList.add('embed');

/* ── renderer / scene ─────────────────────────────────────────────────── */
const canvas = $('#stage');
const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, powerPreference: 'high-performance' });
/* big windows × DPR² × MSAA is a fillrate trap (additive halos + dot shader
   overdraw) — cap the backing-store resolution on large viewports */
const dprCap = () => (innerWidth * innerHeight > 2.2e6 ? 1.5 : 2);
renderer.setPixelRatio(Math.min(devicePixelRatio, dprCap()));
renderer.setSize(innerWidth, innerHeight);
renderer.shadowMap.enabled = true;
renderer.shadowMap.type = THREE.PCFSoftShadowMap;
/* shadows render ON DEMAND (world.shadowDirty), not every frame — the scene
   is static between interactions and the 2k shadow pass was the #1 GPU cost */
renderer.shadowMap.autoUpdate = false;
renderer.shadowMap.needsUpdate = true;

const scene = new THREE.Scene();
const camera = new THREE.PerspectiveCamera(38, innerWidth / innerHeight, 0.5, 600);

const savedTheme = (EMBED && QP.get('theme')) || localStorage.getItem('cx3d-theme') || 'light';
document.documentElement.classList.toggle('dark', savedTheme === 'dark');
const world = new World(scene, savedTheme, renderer.capabilities.getMaxAnisotropy());
/* redraw the printed top-face labels once the webfont lands */
if (document.fonts?.ready) document.fonts.ready.then(() => world.redrawTops());

const controls = new OrbitControls(camera, canvas);
controls.enableDamping = true;
controls.dampingFactor = 0.06;
controls.maxPolarAngle = Math.PI * 0.49;
controls.minDistance = 10;
controls.maxDistance = 230;
controls.enabled = false;
/* operator request: left-drag PANS the plane, middle (or right) drag rotates */
controls.mouseButtons = { LEFT: THREE.MOUSE.PAN, MIDDLE: THREE.MOUSE.ROTATE, RIGHT: THREE.MOUSE.ROTATE };
controls.screenSpacePanning = false;

/* ── camera rig (story scrub ↔ explore orbit; clicks never move it) ───── */
const KEYS = [HERO_CAM, ...CHAPTERS.map((c) => c.cam)];           // 7 keyframes
const SEGS = KEYS.length - 1;
const spacer = $('#scroll-spacer');
spacer.style.height = `${(SEGS + 1) * 100}vh`;

const camTarget = { pos: new THREE.Vector3(...HERO_CAM.pos), look: new THREE.Vector3(...HERO_CAM.look) };
const lookCur = new THREE.Vector3(...HERO_CAM.look);
camera.position.copy(camTarget.pos);
camera.lookAt(lookCur);

let mode = 'story';            // story | explore
let focusedId = null;
let hoveredId = null;
let hoverEvent = null;         // hovered timeline event block
let activeChapter = -1;        // -1 = hero
let activeBeams = new Set();
let scrollProgress = 0;

const ease = (t) => t * t * (3 - 2 * t);

function scrubCamera() {
  if (EMBED) return;            /* no story in embed — explore owns the camera */
  const max = spacer.offsetHeight - innerHeight;
  scrollProgress = max > 0 ? Math.min(1, Math.max(0, scrollY / max)) : 0;
  const x = scrollProgress * SEGS;
  const i = Math.min(Math.floor(x), SEGS - 1);
  const t = ease(x - i);
  const a = KEYS[i], b = KEYS[i + 1];
  camTarget.pos.set(
    a.pos[0] + (b.pos[0] - a.pos[0]) * t,
    a.pos[1] + (b.pos[1] - a.pos[1]) * t,
    a.pos[2] + (b.pos[2] - a.pos[2]) * t);
  camTarget.look.set(
    a.look[0] + (b.look[0] - a.look[0]) * t,
    a.look[1] + (b.look[1] - a.look[1]) * t,
    a.look[2] + (b.look[2] - a.look[2]) * t);
  setChapter(Math.min(Math.round(x) - 1, CHAPTERS.length - 1));
  if (scrollProgress >= 0.995 && mode !== 'explore') enterExplore();
  else if (scrollProgress < 0.995 && mode === 'explore') exitExplore();
}

function chapterHighlights() {
  /* chapter-driven halos/beams/ripple — only while no node is focused */
  activeBeams = new Set();
  if (activeChapter >= 0) {
    const ch = CHAPTERS[activeChapter];
    for (const [f, to] of ch.beams) activeBeams.add(f + '|' + to);
    world.setFocusPoint(ch.cam.look[0], ch.cam.look[2]);
    for (const n of NODES) world.setHalo(n.id, ch.focus.includes(n.id));
  } else {
    world.setFocusPoint(0, 0);
    for (const n of NODES) world.setHalo(n.id, false);
  }
}

function setChapter(idx) {
  if (idx === activeChapter) return;
  activeChapter = idx;
  document.querySelectorAll('.rail-item').forEach((el, i) =>
    el.classList.toggle('active', i === idx));
  $('#hero').classList.toggle('gone', idx >= 0 || scrollProgress > 0.06);
  if (!focusedId) chapterHighlights();
}

function enterExplore() {
  mode = 'explore';
  controls.enabled = true;
  controls.target.copy(camTarget.look);
  $('#explore-hint').classList.add('show');
  $('#rail').classList.add('docked');
}
function exitExplore() {
  mode = 'story';
  controls.enabled = false;
  flight.active = false;
  exitNeighborhood(false);        /* story cameras assume the radial layout */
  exitTimeline(false);
  if (linedUp) restoreLineup();
  $('#explore-hint').classList.remove('show');
  $('#rail').classList.remove('docked');
}

/* ── district filter + line-up — driven by the HOST's sidebar (postMessage).
   The 3D no longer carries its own nav; the classic left rail is the one menu. ── */
const flight = { active: false, pos: new THREE.Vector3(), look: new THREE.Vector3() };
function flyTo(pos, look) {
  flight.pos.set(...pos); flight.look.set(...look); flight.active = true;
  if (reducedMotion) {
    camera.position.copy(flight.pos); controls.target.copy(flight.look); flight.active = false;
  }
}
let linedUp = null;
const districtMembers = (id) => NODES.filter((n) => n.district === id);
function restoreLineup() {
  if (!linedUp) return;
  for (const n of districtMembers(linedUp)) {
    const g = world.nodeGroups.get(n.id);
    world.setNodeTarget(n.id, g.userData.home.x, g.userData.home.z);
  }
  linedUp = null;
  chapterHighlights();
}
/* show only one district: others hide, members line up through the centre,
   camera flies to frame the line. null = everything back. */
function applyDistrictFilter(id) {
  unfocus();
  if (mode !== 'explore') enterExplore();
  if (linedUp && linedUp !== id) restoreLineup();
  world.setDistrictFilter(id || null);
  /* rule: washers ONLY on the All-Panels home view */
  world.bossGroup.visible = !id;
  if (!id) {
    if (linedUp) restoreLineup();
    activeBeams = new Set();
    for (const n of NODES) world.setHalo(n.id, false);
    world.setFocusPoint(0, 0);
    flyTo(EXPLORE_CAM.pos, EXPLORE_CAM.look);
    return;
  }
  const d = DISTRICTS.find((x) => x.id === id);
  if (!d) return;
  const members = districtMembers(id);
  const S = 14, c = d.pos;   /* line-up pitch clears the ×1.5 block footprint */
  members.forEach((n, i) => world.setNodeTarget(n.id, c[0] + (i - (members.length - 1) / 2) * S, c[1]));
  linedUp = id;
  activeBeams = new Set();
  for (const n of NODES) world.setHalo(n.id, n.district === id);
  world.setFocusPoint(c[0], c[1]);
  const width = Math.max(36, members.length * S);
  flyTo([c[0], width * 0.5 + 16, c[1] + width * 0.62 + 14], [c[0], 1, c[1]]);
}

/* ── focus = highlight + panel (camera stays put) ─────────────────────── */
/* what each relation MEANS — shown on the trace tags + panel link chips */
const REL_EXPLAIN = {
  binds:   'identity — attributes this session’s writes',
  drives:  'session executes this plan',
  gates:   'milestone gate recorded as a fact',
  seals:   'mutation sealed as a CROWN receipt',
  chain:   'append-only receipt sequence',
  coord:   'live presence / lease on the board',
  handoff: 'state handed to a peer session',
};
let relLabels = [];   // {el, key} — flat tags pinned to the focused node's traces
function clearRelLabels() {
  for (const r of relLabels) r.el.remove();
  relLabels = [];
}
function buildRelLabels(id) {
  clearRelLabels();
  for (const l of LINKS) {
    if (l.from !== id && l.to !== id) continue;
    const other = NODES.find((x) => x.id === (l.from === id ? l.to : l.from));
    const el = document.createElement('div');
    el.className = 'rlabel';
    el.dataset.rel = l.rel;
    el.innerHTML = `<b></b><span></span>`;
    el.children[0].textContent = (l.from === id ? `${l.rel} → ${other.label}` : `${other.label} → ${l.rel}`);
    el.children[1].textContent = REL_EXPLAIN[l.rel] || '';
    labelLayer.appendChild(el);
    relLabels.push({ el, key: l.from + '|' + l.to });
  }
}

/* ── neighborhood expand: clicking a node filters the disc to its references
   and arranges them in an orbit around it (Esc / ✕ / empty click restores) ── */
let hood = null;            // { id, moved: Set<nodeId>, back: districtId|null }
function enterNeighborhood(id) {
  /* remember the rail filter to return to on exit — survives hood→hood walks */
  const back = linedUp || (hood && hood.back) || (tl && tl.back) || null;
  exitNeighborhood(false);
  exitTimeline(false);
  if (linedUp) restoreLineup();
  /* expansions never show the washers */
  world.bossGroup.visible = false;
  const nbr = new Set([id]);
  for (const l of LINKS) {
    if (l.from === id) nbr.add(l.to);
    if (l.to === id) nbr.add(l.from);
  }
  if (nbr.size < 2) return;            /* nothing referenced — panel only */
  world.setVisibleSet(nbr);
  const g0 = world.nodeGroups.get(id);
  const cx = g0.position.x, cz = g0.position.z;
  const others = [...nbr].filter((x) => x !== id);
  const R = Math.max(16, others.length * 2.9);   /* tight orbit, scaled for the ×1.5 blocks */
  const moved = new Set();
  others.forEach((nid, i) => {
    const a = (i / others.length) * Math.PI * 2 - Math.PI / 2;
    world.setNodeTarget(nid, cx + Math.cos(a) * R, cz + Math.sin(a) * R);
    moved.add(nid);
  });
  hood = { id, moved, back };
  /* ephemeral stat blocks on an inner arc facing the camera:
     execplan → token usage in → out · session → tools used */
  const n0 = g0.userData.node;
  const specs = [];
  if (n0.kind === 'execplan' && n0.tok) {
    specs.push({ kind: 'tokens', label: `${n0.tok.in}k in`,  sub: 'context fed to the plan',   share: 1 });
    specs.push({ kind: 'tokens', label: `${n0.tok.out}k out`, sub: 'completions written back', share: Math.max(0.4, n0.tok.out / Math.max(1, n0.tok.in)) });
  } else if (n0.kind === 'session' && n0.tools) {
    const top = n0.tools[0][1];
    n0.tools.slice(0, 4).forEach(([t, c]) =>
      specs.push({ kind: 'tool', label: `${t} ×${c}`, sub: 'tool calls this session', share: 0.55 + 0.45 * (c / top) }));
  }
  if (specs.length) {
    const statR = Math.max(7.5, R * 0.52);
    const spread = 26 * Math.PI / 180, mid = Math.PI / 2;   /* front arc, facing the camera */
    specs.forEach((s, i) => {
      const a = mid + (i - (specs.length - 1) / 2) * spread;
      s.x = cx + Math.cos(a) * statR;
      s.z = cz + Math.sin(a) * statR;
      s.w = 2.9 + 1.7 * (s.share ?? 1);
    });
    world.spawnStatBlocks(specs);
  }
  world.setFocusPoint(cx, cz);
  flyTo([cx, R * 1.4 + 16, cz + R * 1.8 + 14], [cx, 1, cz]);
}
function exitNeighborhood(flyHome = true) {
  if (!hood) return;
  const back = hood.back;
  for (const nid of hood.moved) {
    const g = world.nodeGroups.get(nid);
    world.setNodeTarget(nid, g.userData.home.x, g.userData.home.z);
  }
  world.setVisibleSet(null);
  world.clearStatBlocks();
  world.bossGroup.visible = true;
  hood = null;
  if (!flyHome) return;
  if (back) applyDistrictFilter(back);            /* back to the rail filter, not the disc */
  else if (mode === 'explore') flyTo(EXPLORE_CAM.pos, EXPLORE_CAM.look);
}

/* ── timeline mode: sessions + traced receipts replay as a left→right
   line of events (rings off, everything else hidden) ── */
let tl = null;              // { id, back: districtId|null }
function enterTimeline(id) {
  const back = linedUp || (hood && hood.back) || (tl && tl.back) || null;
  exitNeighborhood(false);
  exitTimeline(false);
  if (linedUp) restoreLineup();
  const g0 = world.nodeGroups.get(id);
  const n = g0.userData.node;
  world.bossGroup.visible = false;
  world.setVisibleSet(new Set([id]));
  const SP = 6.2, W = (n.timeline.length - 1) * SP;
  /* the clicked node parks at the head of the line, on the ground */
  world.setNodeTarget(id, -W / 2 - SP * 1.7, 0, 0);
  world.spawnTimeline(n.timeline);
  tl = { id, back };
  world.setFocusPoint(0, 0);
  flyTo([0, W * 0.26 + 15, W * 0.34 + 18], [0, 0, 0]);
}
function exitTimeline(flyHome = true) {
  if (!tl) return;
  const back = tl.back;
  world.clearTimeline();
  world.bossGroup.visible = true;
  const g = world.nodeGroups.get(tl.id);
  world.setNodeTarget(tl.id, g.userData.home.x, g.userData.home.z);
  world.setVisibleSet(null);
  tl = null;
  if (!flyHome) return;
  if (back) applyDistrictFilter(back);            /* back to the rail filter */
  else if (mode === 'explore') flyTo(EXPLORE_CAM.pos, EXPLORE_CAM.look);
}

const crumbs = [];
function focusNode(id, pushCrumb = true) {
  const g = world.nodeGroups.get(id);
  if (!g) return;
  focusedId = id;
  const n = g.userData.node;
  world.setFocusPoint(g.position.x, g.position.z);
  activeBeams = new Set();
  for (const l of LINKS)
    if (l.from === id || l.to === id) activeBeams.add(l.from + '|' + l.to);
  for (const node of NODES) world.setHalo(node.id, node.id === id);
  buildRelLabels(id);
  /* All-Panels click → pull the node's references CLOSE (orbit + links).
     Timelines (the linear arrangement) only inside the matching rail mode.
     Clicking the parked node inside its own timeline = panel only. */
  if (mode === 'explore' && !(tl && tl.id === id)) {
    if (linedUp && n.district === linedUp && n.timeline) enterTimeline(id);
    else enterNeighborhood(id);
  }
  if (EMBED) {
    const links = LINKS.filter((l) => l.from === id || l.to === id).map((l) => {
      const otherId = l.from === id ? l.to : l.from;
      return { id: otherId, rel: l.rel, dir: l.from === id ? '→' : '←',
        other: (NODES.find((x) => x.id === otherId) || {}).label || otherId,
        explain: REL_EXPLAIN[l.rel] || '' };
    });
    parent.postMessage({ type: 'cx3d:focus', node: {
      kind: n.kind, status: n.status, state: n.state, label: n.label, sub: n.sub,
      fields: [...(n.fields || []), ...(n.milestones || []).map((ms) => [ms.m, ms.state])],
      doc: [n.doc, n.payload].filter(Boolean).join('\n\n──────────\n\n'),
      links } }, location.origin);
  } else openPanel(n);
  if (pushCrumb && crumbs[crumbs.length - 1] !== id) {
    crumbs.push(id);
    if (crumbs.length > 5) crumbs.shift();
  }
  renderCrumbs();
}

function unfocus() {
  if (!focusedId) return;
  focusedId = null;
  if (EMBED) parent.postMessage({ type: 'cx3d:unfocus' }, location.origin);
  exitNeighborhood();
  exitTimeline();
  closePanel();
  clearRelLabels();
  crumbs.length = 0;
  renderCrumbs();
  if (linedUp) {
    for (const n of NODES) world.setHalo(n.id, n.district === linedUp);
    activeBeams = new Set();
  } else chapterHighlights();
}

function renderCrumbs() {
  const el = $('#crumbs');
  el.innerHTML = '';
  if (!crumbs.length) { el.classList.remove('show'); return; }
  el.classList.add('show');
  crumbs.forEach((id, i) => {
    const n = NODES.find((x) => x.id === id);
    const b = document.createElement('button');
    b.className = 'crumb' + (i === crumbs.length - 1 ? ' last' : '');
    b.textContent = n.label;
    b.onclick = () => { crumbs.length = i + 1; focusNode(id, false); };
    el.appendChild(b);
    if (i < crumbs.length - 1) {
      const s = document.createElement('span');
      s.className = 'crumb-sep'; s.textContent = '→';
      el.appendChild(s);
    }
  });
}

/* ── detail panel ─────────────────────────────────────────────────────── */
function openPanel(n) {
  $('#p-kind').textContent = KIND_LABELS[n.kind] || n.kind;
  $('#p-kind').dataset.kind = n.kind;
  const st = $('#p-status');
  st.textContent = n.state || n.status || '';
  st.dataset.s = n.status || 'idle';
  $('#p-title').textContent = n.label;
  $('#p-sub').textContent = n.sub || '';
  const f = $('#p-fields');
  f.innerHTML = '';
  for (const [k, v] of n.fields || []) {
    const row = document.createElement('div'); row.className = 'frow';
    row.innerHTML = `<span class="fk"></span><span class="fv"></span>`;
    row.children[0].textContent = k; row.children[1].textContent = v;
    f.appendChild(row);
  }
  if (n.milestones) {
    for (const ms of n.milestones) {
      const row = document.createElement('div'); row.className = 'frow ms';
      row.innerHTML = `<span class="fk"></span><span class="fv state" data-st=""></span>`;
      row.children[0].textContent = ms.m;
      row.children[1].textContent = ms.state;
      row.children[1].dataset.st = ms.state;
      f.appendChild(row);
    }
  }
  const doc = $('#p-doc');
  const txt = [n.doc, n.payload].filter(Boolean).join('\n\n──────────\n\n');
  doc.textContent = txt; doc.style.display = txt ? '' : 'none';
  const ln = $('#p-links');
  ln.innerHTML = '';
  for (const l of LINKS) {
    if (l.from !== n.id && l.to !== n.id) continue;
    const otherId = l.from === n.id ? l.to : l.from;
    const other = NODES.find((x) => x.id === otherId);
    const b = document.createElement('button');
    b.className = 'link-chip'; b.dataset.rel = l.rel;
    b.innerHTML = `<i></i><div class="lc-body"><div class="lc-row"><span></span><em></em></div><small></small></div>`;
    b.querySelector('span').textContent = (l.from === n.id ? l.rel + ' → ' : '← ' + l.rel + ' ');
    b.querySelector('em').textContent = other.label;
    b.querySelector('small').textContent = REL_EXPLAIN[l.rel] || '';
    b.onclick = () => focusNode(otherId);
    ln.appendChild(b);
  }
  $('#panel').classList.add('open');
}
function closePanel() { $('#panel').classList.remove('open'); }

/* ── district labels (DOM, projected; node text is printed on the blocks) */
const labelLayer = $('#labels');
const districtEls = DISTRICTS.map((d) => {
  const el = document.createElement('div');
  el.className = 'dlabel';
  el.innerHTML = `<b></b><i></i>`;
  el.children[0].textContent = d.label;
  el.children[1].textContent = d.sub;
  labelLayer.appendChild(el);
  const lp = d.labelPos || [d.pos[0], d.pos[1] + 6.5];
  return { d, el, v: new THREE.Vector3(lp[0], 0.2, lp[1]) };
});
const pv = new THREE.Vector3();
function updateLabels() {
  const w = innerWidth, h = innerHeight;
  for (const { d, el, v } of districtEls) {
    if (world.visibleSet) { el.style.opacity = 0; continue; }   /* neighborhood: no district labels */
    if (world.filterDistrict && d.id !== world.filterDistrict && d.id !== 'core') { el.style.opacity = 0; continue; }
    pv.copy(v).project(camera);
    const vis = pv.z < 1;
    el.style.opacity = vis ? Math.max(0, 1 - camera.position.distanceTo(v) / 230) : 0;
    if (vis) el.style.transform = `translate(-50%,-50%) translate(${(pv.x * 0.5 + 0.5) * w}px,${(-pv.y * 0.5 + 0.5) * h}px)`;
  }
  /* relationship tags ride the focused node's traces — nudged apart when
     several midpoints project onto the same screen spot */
  const placed = [];
  for (const { el, key } of relLabels) {
    const item = world.edgeByKey.get(key);
    const vis = item && !item.hidden && !world.edgesHidden;
    if (!vis) { el.style.opacity = 0; continue; }
    pv.copy(item.mid).setY(0.4).project(camera);
    if (pv.z >= 1) { el.style.opacity = 0; continue; }
    let sx = (pv.x * 0.5 + 0.5) * w, sy = (-pv.y * 0.5 + 0.5) * h;
    let bumped = true;
    while (bumped) {
      bumped = false;
      for (const p of placed)
        if (Math.abs(sx - p.x) < 170 && Math.abs(sy - p.y) < 42) { sy = p.y + 42; bumped = true; }
    }
    placed.push({ x: sx, y: sy });
    el.style.opacity = 1;
    el.style.transform = `translate(-50%,-110%) translate(${sx}px,${sy}px)`;
  }
}

/* ── raycast ──────────────────────────────────────────────────────────── */
const ray = new THREE.Raycaster();
const mouse = new THREE.Vector2(-2, -2);
let pointerDirty = false;
canvas.addEventListener('pointermove', (e) => {
  mouse.set((e.clientX / innerWidth) * 2 - 1, -(e.clientY / innerHeight) * 2 + 1);
  pointerDirty = true;
});
let downAt = null;
canvas.addEventListener('pointerdown', (e) => { downAt = [e.clientX, e.clientY]; });
canvas.addEventListener('click', (e) => {
  /* ignore the click that ends an orbit drag */
  if (downAt && (Math.abs(e.clientX - downAt[0]) > 5 || Math.abs(e.clientY - downAt[1]) > 5)) return;
  if (hoverEvent) { showEventPanel(hoverEvent); return; }   /* timeline step → detail, stay in mode */
  if (hoveredId) focusNode(hoveredId);
  else unfocus();                          /* clicking empty ground clears */
});
/* a timeline step's detail in the pane — without leaving the timeline */
function showEventPanel(ev) {
  const pseudo = { kind: ev.k, label: ev.label, sub: ev.sub || '',
    fields: [['step', ev.k], ['lane', ev.lane === 0 ? 'main rail' : (ev.lane < 0 ? 'reasoning spur' : 'artifact spur')]],
    doc: '' };
  if (EMBED) parent.postMessage({ type: 'cx3d:focus', node: { ...pseudo, links: [] } }, location.origin);
  else openPanel(pseudo);
}
function chapterHasHalo(id) {
  return activeChapter >= 0 && CHAPTERS[activeChapter].focus.includes(id) && !focusedId;
}
function pick() {
  if (!pointerDirty) return;
  pointerDirty = false;
  ray.setFromCamera(mouse, camera);
  /* one flat box per node — never the full block geometry */
  const hits = ray.intersectObjects(world.visiblePicks, false);
  const id = hits.length ? hits[0].object.userData.node.id : null;
  /* timeline step blocks are hoverable too */
  hoverEvent = null;
  if (tl && world.timelinePicks && world.timelinePicks.length) {
    const evHits = ray.intersectObjects(world.timelinePicks, false);
    if (evHits.length) hoverEvent = evHits[0].object.userData.event;
  }
  if (id !== hoveredId) {
    if (hoveredId && hoveredId !== focusedId)
      world.setHalo(hoveredId, chapterHasHalo(hoveredId));
    hoveredId = id;
    if (id) world.setHalo(id, true);
  }
  canvas.style.cursor = (id || hoverEvent) ? 'pointer' : (mode === 'explore' ? 'grab' : 'default');
}

/* ── chrome wiring ────────────────────────────────────────────────────── */
const rail = $('#rail');
CHAPTERS.forEach((c, i) => {
  const item = document.createElement('button');
  item.className = 'rail-item';
  item.innerHTML = `<span class="rail-num"></span><span class="rail-t"></span><span class="rail-body"></span>`;
  item.children[0].textContent = c.num;
  item.children[1].textContent = c.title;
  item.children[2].textContent = c.body;
  item.onclick = () => {
    const max = spacer.offsetHeight - innerHeight;
    scrollTo({ top: ((i + 1) / SEGS) * max, behavior: reducedMotion ? 'auto' : 'smooth' });
  };
  rail.appendChild(item);
});

rail.appendChild($('#skip'));   /* keep the skip CTA at the foot of the rail */
$('#skip').onclick = () => {
  const max = spacer.offsetHeight - innerHeight;
  scrollTo({ top: max, behavior: reducedMotion ? 'auto' : 'smooth' });
};
$('#p-close').onclick = unfocus;
addEventListener('keydown', (e) => {
  if (e.key === 'Escape') unfocus();
});

$('#theme').onclick = () => {
  const dark = !document.documentElement.classList.contains('dark');
  document.documentElement.classList.toggle('dark', dark);
  world.applyTheme(dark ? 'dark' : 'light');
  localStorage.setItem('cx3d-theme', dark ? 'dark' : 'light');
  if (focusedId) focusNode(focusedId, false);   /* refresh rel-tag colors */
};

/* search / jump (no camera move — highlights + ripple locate the node) */
const dl = $('#node-list');
NODES.forEach((n) => {
  const o = document.createElement('option');
  o.value = n.label;
  dl.appendChild(o);
});
$('#search').addEventListener('change', (e) => {
  const n = NODES.find((x) => x.label === e.target.value);
  if (n) { focusNode(n.id); e.target.blur(); e.target.value = ''; }
});

/* ── loop ─────────────────────────────────────────────────────────────── */
addEventListener('scroll', () => {
  if (focusedId) unfocus();      /* scrolling resumes the story highlights */
  scrubCamera();
}, { passive: true });
addEventListener('resize', () => {
  camera.aspect = innerWidth / innerHeight;
  camera.updateProjectionMatrix();
  renderer.setPixelRatio(Math.min(devicePixelRatio, dprCap()));
  renderer.setSize(innerWidth, innerHeight);
});

const clock = new THREE.Clock();
let last = 0;
let paused = false;            /* host hides the iframe → stop burning GPU */
let lastInput = 0;             /* clock time of last user interaction */
let degraded = false, lowSince = null, frameNo = 0;
const perf = { frames: 0, slow: 0, worstDt: 0, fps: 60 };
for (const ev of ['pointermove', 'pointerdown', 'wheel'])
  canvas.addEventListener(ev, () => { lastInput = clock.getElapsedTime(); }, { passive: true });
addEventListener('scroll', () => { lastInput = clock.getElapsedTime(); }, { passive: true });

/* perf HUD — ?hud=1 or press "p". Watchdog logs main-thread stalls always. */
let hudEl = null;
function toggleHud(on) {
  if (on && !hudEl) { hudEl = document.createElement('div'); hudEl.id = 'perfhud'; document.body.appendChild(hudEl); }
  else if (!on && hudEl) { hudEl.remove(); hudEl = null; }
}
if (QP.has('hud')) toggleHud(true);
addEventListener('keydown', (e) => {
  if (e.key === 'p' && e.target.tagName !== 'INPUT') toggleHud(!hudEl);
});
let beat = performance.now();
setInterval(() => {
  const now = performance.now(), gap = now - beat - 1000;
  if (gap > 400) console.warn(`[cx3d] main-thread stall ≈${Math.round(gap)}ms (fps ${perf.fps.toFixed(0)})`);
  beat = now;
}, 1000);

/* sustained <20fps → shed load instead of letting the tab drown */
function degrade() {
  degraded = true;
  renderer.setPixelRatio(1);
  world.sun.castShadow = false;
  world.shadowDirty = true;
  document.getElementById('perfpill')?.remove();
  const pill = document.createElement('div');
  pill.id = 'perfpill';
  pill.textContent = 'low-power mode · shadows off · dpr 1';
  document.body.appendChild(pill);
  console.warn('[cx3d] sustained low fps — degraded to low-power mode');
}

function frame() {
  if (paused) return;
  requestAnimationFrame(frame);
  const t = clock.getElapsedTime();
  frameNo++;
  /* frame budget: same-origin iframes SHARE the host page's main thread, so
     the embed must never saturate it — embed runs at 30fps (except during
     camera flights / node glides), idle halves again, degraded halves again */
  const animating = flight.active || (world.moveTargets && world.moveTargets.size);
  const calm = !animating && !world.edgesHidden && (t - lastInput > 4);
  let div = 1;
  if (EMBED && !animating) div *= 2;
  if (calm) div *= 2;
  if (degraded) div *= 2;
  if (div > 1 && frameNo % div) return;
  const dt = Math.min(t - last, 0.1); last = t;
  perf.frames++; if (dt > 0.12) perf.slow++; if (dt > perf.worstDt) perf.worstDt = dt;
  perf.fps = perf.fps * 0.92 + (1 / Math.max(dt, 1e-3)) * 0.08;
  if (!degraded && t > 12) {
    if (perf.fps < 20 && !calm) { lowSince ??= t; if (t - lowSince > 8) degrade(); }
    else lowSince = null;
  }
  pick();
  if (mode === 'explore') {
    if (flight.active) {
      const k = 1 - Math.exp(-dt * 4);
      camera.position.lerp(flight.pos, k);
      controls.target.lerp(flight.look, k);
      if (camera.position.distanceTo(flight.pos) < 0.3) flight.active = false;
    }
    controls.update();
  } else {
    const k = reducedMotion ? 1 : 1 - Math.exp(-dt * 5);
    camera.position.lerp(camTarget.pos, k);
    lookCur.lerp(camTarget.look, k);
    camera.lookAt(lookCur);
  }
  world.update(t, dt, activeBeams, reducedMotion || degraded);
  /* shadow maps are light-space (camera-independent): re-render only when
     objects moved / visibility / theme changed */
  if (world.shadowDirty) { renderer.shadowMap.needsUpdate = true; world.shadowDirty = false; }
  updateLabels();
  renderer.render(scene, camera);
  if (hudEl && (frameNo % 30) === 0) {
    hudEl.textContent =
      `fps ${perf.fps.toFixed(0)}  dpr ${renderer.getPixelRatio()}  calls ${renderer.info.render.calls}` +
      `  geo ${renderer.info.memory.geometries}  tex ${renderer.info.memory.textures}` +
      (performance.memory ? `  heap ${(performance.memory.usedJSHeapSize / 1048576).toFixed(0)}MB` : '') +
      `  ${calm ? 'idle½' : 'live'}${degraded ? ' · LOW-POWER' : ''}`;
  }
}
function setPaused(p) {
  if (paused === p) return;
  paused = p;
  if (!p) { last = clock.getElapsedTime(); frame(); }
}
/* tab/iframe hidden → halt the loop (Chrome throttles rAF but not to zero GPU) */
document.addEventListener('visibilitychange', () => setPaused(document.hidden));
/* runtime stats for soak-testing (tools/profile.cjs) */
window.__cx3dStats = () => ({
  heapMB: performance.memory ? Math.round(performance.memory.usedJSHeapSize / 1048576) : null,
  geometries: renderer.info.memory.geometries,
  textures: renderer.info.memory.textures,
  programs: renderer.info.programs.length,
  calls: renderer.info.render.calls,
  triangles: renderer.info.render.triangles,
  labels: labelLayer.children.length,
  frames: perf.frames, slow: perf.slow, paused,
  fps: Math.round(perf.fps), degraded, dpr: renderer.getPixelRatio(),
});
scrubCamera();
frame();

if (EMBED) {
  /* land straight in explore at the overview vantage; host drives the panel */
  spacer.style.height = '0px';
  camTarget.pos.set(...EXPLORE_CAM.pos); camTarget.look.set(...EXPLORE_CAM.look);
  camera.position.copy(camTarget.pos); lookCur.copy(camTarget.look);
  enterExplore();
  addEventListener('message', (e) => {
    if (e.origin !== location.origin || !e.data) return;
    if (e.data.type === 'cx3d:focusId') focusNode(e.data.id);
    if (e.data.type === 'cx3d:unfocus') unfocus();
    if (e.data.type === 'cx3d:filter') applyDistrictFilter(e.data.district || null);
    if (e.data.type === 'cx3d:pause') setPaused(true);
    if (e.data.type === 'cx3d:resume') setPaused(false);
    if (e.data.type === 'cx3d:theme') {
      const dark = e.data.theme === 'dark';
      document.documentElement.classList.toggle('dark', dark);
      world.applyTheme(dark ? 'dark' : 'light');
      if (focusedId) focusNode(focusedId, false);
    }
  });
}

/* boot status pill */
$('#stat-facts').textContent = '3,823 facts';
$('#stat-mode').textContent = 'local_only';
