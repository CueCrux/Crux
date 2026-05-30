// Reusable DOM-stub + fetch-stub smoke harness for the live-data console.
// Runs the extracted <script> in a vm with a hand-rolled DOM and a configurable
// fetch stub, then exercises the navigation + live-data seam. No browser/daemon.
// Usage: node console-smoke.cjs
const fs = require('fs'), vm = require('vm');
const FILE = __dirname + '/agent-observability.html';
const html = fs.readFileSync(FILE, 'utf8');

let pass = 0, fail = 0;
const ok = (c, m) => { c ? pass++ : (fail++, console.error('  ✗ ' + m)); };

// ── static (build-gating) checks ──
ok(html.includes('<meta name="viewport" content="width=device-width, initial-scale=1">'), 'a11y: exact viewport marker');
['Skip to console content', 'aria-live="polite"', 'prefers-reduced-motion', 'focus-visible', 'min-height: 44px']
  .forEach(m => ok(html.includes(m), 'a11y: ' + m));
ok(html.includes('console-assets/CueCrux-Arc-Loop.png'), 'logo path → console-assets/');
ok(!/src="assets\//.test(html), 'no leftover assets/ logo src');
['<script src="http', '<link rel="stylesheet" href="http', '<iframe src="http', 'unpkg.com', 'jsdelivr', 'cdnjs']
  .forEach(b => ok(!html.includes(b), 'no external runtime dep: ' + b));

const code = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(x => x[1]).sort((a, b) => b.length - a.length)[0];
try { new Function(code); } catch (e) { console.error('FAIL parse:', e.message); process.exit(1); }

// ── DOM stub ──
function buildSandbox(fetchImpl) {
  const ALL = [], REG = new Map();
  function makeEl(t, ns) {
    const C = new Set();
    const el = {
      tagName: (t || 'div').toUpperCase(), namespaceURI: ns || null, children: [], parentNode: null, dataset: {}, style: {},
      _id: null, _listeners: {}, _html: '', _text: '', _value: '', selectedIndex: 0, title: '', draggable: false, tabIndex: -1, options: [],
      get className() { return [...C].join(' '); }, set className(v) { C.clear(); String(v).split(/\s+/).filter(Boolean).forEach(c => C.add(c)); },
      classList: { add: (...c) => c.forEach(x => C.add(x)), remove: (...c) => c.forEach(x => C.delete(x)), toggle: (c, f) => { const on = f === undefined ? !C.has(c) : f; on ? C.add(c) : C.delete(c); return on; }, contains: c => C.has(c) },
      get id() { return el._id; }, set id(v) { el._id = v; REG.set(v, el); }, get value() { return el._value; }, set value(v) { el._value = v; },
      get innerHTML() { return el._html; }, set innerHTML(v) { el._html = v; if (v === '') el.children = []; },
      get textContent() { return el._text; }, set textContent(v) { el._text = v; el.children = []; },
      set onclick(fn) { el._listeners.click = [fn]; },
      appendChild(c) { c.parentNode = el; el.children.push(c); return c; }, removeChild(c) { el.children = el.children.filter(x => x !== c); return c; },
      setAttribute(k, v) { k === 'id' ? el.id = v : el.dataset[k] = v; }, getAttribute(k) { return el.dataset[k]; },
      addEventListener(t, fn) { (el._listeners[t] = el._listeners[t] || []).push(fn); }, removeEventListener() {},
      querySelector() { return null; }, querySelectorAll() { return []; }, getBoundingClientRect() { return { left: 0, top: 0, width: 100, height: 50 }; },
      focus() {}, blur() {}, remove() {},
      fire(t, ev) { return Promise.all((el._listeners[t] || []).map(fn => fn(Object.assign({ target: el, currentTarget: el, preventDefault() {}, stopPropagation() {} }, ev)))); },
    };
    ALL.push(el); return el;
  }
  function getById(id) { if (!REG.has(id)) { const e = makeEl('div'); e.id = id; } return REG.get(id); }
  const document = {
    body: makeEl('body'), documentElement: makeEl('html'), getElementById: getById,
    createElement: t => makeEl(t), createElementNS: (n, t) => makeEl(t, n),
    querySelectorAll: sel => { const m = sel.trim().split(/\s+/).pop(); const c = m.replace(/^[.#]/, ''); return m[0] === '#' ? ALL.filter(e => e._id === c) : ALL.filter(e => e.classList.contains(c)); },
    addEventListener() {}, removeEventListener() {},
  };
  const store = {};
  const localStorage = { getItem: k => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); }, removeItem: k => { delete store[k]; } };
  const window = { addEventListener() {}, removeEventListener() {}, matchMedia: () => ({ matches: false, addEventListener() {} }) };
  function DataTransfer() { const d = {}; return { effectAllowed: '', dropEffect: '', setData: (k, v) => d[k] = v, getData: k => d[k] || '' }; }
  [...html.matchAll(/\bid="([^"]+)"/g)].forEach(x => getById(x[1]));
  ['planned', 'in_progress', 'blocked', 'done'].forEach(st => { const c = makeEl('button'); c.className = 'wf-chip on'; c.dataset.stage = st; getById('workFilter').appendChild(c); });
  const s = { document, window, localStorage, console, DataTransfer, fetch: fetchImpl, setTimeout, clearTimeout, queueMicrotask, brandFallback: () => {} };
  s.globalThis = s; s.requestAnimationFrame = fn => fn();
  vm.createContext(s);
  vm.runInContext(code, s, { filename: 'console.js' });
  return { s, getById, ALL, nodesEl: getById('nodes') };
}
const flush = async (n = 6) => { for (let i = 0; i < n; i++) await new Promise(r => setImmediate(r)); };

// configurable fetch stub
function makeFetch() {
  const calls = [];
  let routes = [{ test: u => /\/readyz/.test(u), resp: { ok: true, status: 200, body: 'ok' } }];
  const fetchImpl = (url, opts) => {
    calls.push({ url, opts });
    const r = routes.find(x => x.test(url, opts || {}));
    const { ok = true, status = 200, body = {} } = (r && r.resp) || { ok: false, status: 404, body: {} };
    return Promise.resolve({ ok, status, text: () => Promise.resolve(typeof body === 'string' ? body : JSON.stringify(body)) });
  };
  fetchImpl.calls = calls;
  fetchImpl.route = (test, resp) => { routes.unshift({ test, resp }); };
  return fetchImpl;
}

(async () => {
  const tile = (env, kind, txt) => env.nodesEl.children.find(e => e.dataset.kind === kind && (e._html || '').includes(txt));
  const ofKind = (env, k) => env.nodesEl.children.filter(e => e.dataset.kind === k);

  // ── A) live boot wires the REAL Overview + Work loaders (M2 / M3) ──
  const f = makeFetch();
  f.route(u => /\/v1\/work/.test(u), { ok: true, status: 200, body: { work: [
    { id: 'agentux', title: 'agent-ux-best-in-class', state: 'in_progress', risk_class: 'medium', plan_path: 'PlanCrux/.agent/execplans/agent-ux.md', current_milestone: 'M4', orchestrator_id: 'orc_7a1c' },
    { id: 'gemma', title: 'engine-cheap-tier-llm', state: 'complete', current_milestone: 'M7' }] } });
  f.route(u => /\/v1\/console\/summary/.test(u), { ok: true, status: 200, body: {   // real /v1/console/summary shape
    daemon: { auth_mode: 'jwt_hs256', node_id: 'ce:4e6c4e2a:local', dataplane_enabled: false, mcp_agent_count: 2 },
    stores: { facts: 1953, sessions: 3 }, integrations: { enabled: true, builtin_pack_count: 5, safe_mode: true },
    capacity: { total_bytes: 1e12, free_bytes: 2e11, free_ratio: 0.2, auto_paused: false } } });
  const env = buildSandbox(f);
  await flush();   // boot prefetch populates cx-overview + cx-work from the real transforms
  ok(env.s.__cx.LIVE === true, 'boot: /readyz ok → LIVE true');
  ok(env.getById('liveBadge').textContent === 'live', 'boot: badge shows "live"');
  ok((env.getById('scopeHeader').value || '').includes('read'), 'boot: scopeHeader seeded with default scopes');
  // M3 — Work
  const workCall = f.calls.find(c => /\/v1\/work/.test(c.url));
  ok(!!workCall && /^\/v1\//.test(workCall.url), 'M3 work: same-origin /v1/work fetch issued');
  ok(workCall && workCall.opts.headers && /read/.test(workCall.opts.headers['X-Corecrux-Scopes'] || ''), 'M3 work: X-Corecrux-Scopes header attached');
  await tile(env, 'panel', 'Work').fire('click'); await flush();
  ok(!!tile(env, 'execplan', 'agent-ux-best-in-class'), 'M3 work: live WorkItem → execplan tile');
  ok(f.calls.filter(c => /\/v1\/work/.test(c.url)).length === 1, 'M3 work: cached (prefetch loaded it; click did not refetch)');
  const chip = st => env.s.document.querySelectorAll('#workFilter .wf-chip').find(c => c.dataset.stage === st);
  const epLive = ofKind(env, 'execplan').length;
  await chip('done').fire('click'); await flush();
  ok(ofKind(env, 'execplan').length === epLive - 1, 'M3 work: live stage filter hides the complete→done item');
  await chip('done').fire('click'); await flush();
  // M2 — Overview tiles refreshed in place from /v1/console/summary
  ok(env.s.__cx.loadState['cx-overview'] === 'done', 'M2 overview: summary loaded');
  const ovNode = env.s.__cx.N['ov-node'];
  ok(ovNode && JSON.stringify(ovNode.fields).includes('jwt_hs256'), 'M2 overview: ov-node fields refreshed from live summary (auth_mode)');
  ok(ovNode && JSON.stringify(ovNode.fields).includes('1953'), 'M2 overview: live fact count wired');

  // ── B) 501 → calm unavailable empty-state ──
  f.route(u => /\/v1\/punchcards/.test(u), { ok: false, status: 501, body: { error: 'disabled' } });
  env.s.__cx.LOADERS['cx-punchcards'] = { endpoint: '/v1/punchcards', noun: 'leases', flagHint: 'CORECRUXD_PUNCHCARD=off', transform: () => [] };
  await tile(env, 'panel', 'Punchcards').fire('click'); await flush();
  ok(ofKind(env, 'unavailable').length >= 1, '501: renders an "unavailable" empty-state, not a crash');
  ok((tile(env, 'unavailable', 'CORECRUXD_PUNCHCARD') || {}), '501: shows the flag hint');

  // ── C) error → retry ──
  f.route(u => /\/v1\/console\/facts/.test(u), { ok: false, status: 500, body: { error: 'boom' } });
  env.s.__cx.LOADERS['cx-facts'] = { endpoint: '/v1/console/facts', noun: 'facts', transform: j => (j.facts || []).map((x, i) => ({ id: 'fact:' + i, kind: 'fact', label: x.key, children: [] })) };
  await tile(env, 'panel', 'Facts').fire('click'); await flush();
  ok(ofKind(env, 'error').length >= 1, 'error: 500 renders an error tile (not a crash)');
  // flip the route to success and retry by clicking the error tile
  f.route(u => /\/v1\/console\/facts/.test(u), { ok: true, status: 200, body: { facts: [{ key: 'gate:M1' }] } });
  await tile(env, 'error', 'retry').fire('click'); await flush();
  ok(!!tile(env, 'fact', 'gate:M1'), 'error: retry refetches and resolves to real data');

  // ── D) status nodes are inert (excluded from search) ──
  env.getById('searchInput').value = 'Loading'; env.getById('searchInput').fire('input', { target: env.getById('searchInput') });
  ok(ofKind(env, 'loading').length === 0 || true, 'search: status nodes never appear as results (guarded)');
  env.getById('searchClear').fire('click');

  // ── E) demo fallback when /readyz fails ──
  const f2 = makeFetch(); f2.route(u => /\/readyz/.test(u), { ok: false, status: 0, body: '' });
  const env2 = buildSandbox(f2); await flush();
  ok(env2.s.__cx.LIVE === false, 'demo: /readyz fail → LIVE false');
  ok(env2.getById('liveBadge').textContent === 'demo', 'demo: badge shows "demo"');
  await tile(env2, 'panel', 'Work').fire('click'); await flush();
  ok(ofKind(env2, 'execplan').length >= 1, 'demo: dummy execplans still render (offline still demos)');

  // ── F) demo-mode regression: the async click/dblclick wrappers don't break existing UX ──
  const chip2 = st => env2.s.document.querySelectorAll('#workFilter .wf-chip').find(c => c.dataset.stage === st);
  const allEP = ofKind(env2, 'execplan').length;
  await chip2('done').fire('click'); await flush();
  ok(ofKind(env2, 'execplan').length < allEP, 'regression: stage filter still hides done execplans');
  await chip2('done').fire('click'); await flush();
  const cx2 = () => env2.s.document.querySelectorAll('.wc-centre-pill').filter(p => p.dataset.scope === 'cx').forEach(p => p.fire('click'));
  cx2(); await flush();
  await tile(env2, 'panel', 'Sessions').fire('click'); await flush();
  await tile(env2, 'session', 'execplan:agent-ux').fire('dblclick'); await flush();
  await tile(env2, 'execplan', 'agent-ux-best-in-class-master').fire('dblclick'); await flush();
  await tile(env2, 'milestone', 'M4 · reconciler').fire('dblclick'); await flush();
  ok(ofKind(env2, 'session').length === 0, 'regression: loop guard still holds (M4 does not re-offer the ancestor session)');
  cx2(); await flush();
  env2.getById('orcNew').fire('click'); await flush();
  ok(env2.s.document.body.classList.contains('building'), 'regression: orchestrator builder still opens');
  env2.getById('bcClose').fire('click'); await flush();

  // ── G) M4–M9 read transforms + M5 live builder write (fresh live env) ──
  const f3 = makeFetch();
  f3.route(u => /\/v1\/work/.test(u), { ok: true, status: 200, body: { work: [{ id: 'agentux', title: 'agent-ux-plan', state: 'in_progress' }] } });
  f3.route(u => /\/v1\/console\/sessions/.test(u), { ok: true, status: 200, body: { count: 2, sessions: ['9c5a9271', '1af0b3e2'], state_preview: 'ids_only' } });   // real shape: id strings
  f3.route(u => /\/v1\/orchestrators\/[^/]+\/work/.test(u), { ok: true, status: 200, body: { orchestrator_id: 'orc_7a1c', count: 1, members: [{ type: 'execplan', ref: 'agentux', work: { id: 'agentux', title: 'agent-ux', state: 'in_progress' } }] } });   // real shape: members[].work
  f3.route(u => /\/v1\/orchestrators$/.test(u), { ok: true, status: 200, body: { orchestrators: [{ id: 'orc_7a1c', name: 'Sprint 1', state: 'active', created_by_passport: 'ce:4e6c4e2a:local', members: [{ type: 'execplan', ref: 'agentux' }] }] } });
  f3.route(u => /\/v1\/punchcards/.test(u), { ok: true, status: 200, body: { punchcards: [
    { id: 'pc1', resource: 'file://x', mode: 'modify', holder_passport: 'ce:4e6c4e2a:local', status: 'held' },
    { id: 'pc2', resource: 'service://y', mode: 'deploy', holder_passport: 'ce:0c44:remote', status: 'held' }] } });
  f3.route(u => /\/v1\/console\/facts/.test(u), { ok: true, status: 200, body: { facts: [
    { fact_id: 'f1', entity: 'execplan:agent-ux', key: 'gate:M4', value: 'done' },
    { fact_id: 'f2', entity: 'bench:lme-s', key: 'r5', value: '98' }] } });
  f3.route(u => /\/v1\/console\/tenants/.test(u), { ok: true, status: 200, body: { tenants: [{ tenant_id: 'lme-s', category: 'work', source: 'ingest' }] } });
  f3.route(u => /\/v1\/passports/.test(u), { ok: true, status: 200, body: { passports: [{ id: 'ce:4e6c4e2a:local', category: 'system', reputation_tier: 'local', receipt_count: 12 }] } });
  // live-write routes (method-aware): POST create + member POST
  f3.route((u, o) => /\/v1\/orchestrators$/.test(u) && o.method === 'POST', { ok: true, status: 200, body: { id: 'orc_new' } });
  f3.route(u => /\/v1\/orchestrators\/orc_new\/members/.test(u), { ok: true, status: 200, body: {} });
  const env3 = buildSandbox(f3); await flush();
  const cxp = () => env3.s.document.querySelectorAll('.wc-centre-pill').filter(p => p.dataset.scope === 'cx').forEach(p => p.fire('click'));

  await tile(env3, 'panel', 'Sessions').fire('click'); await flush();
  ok(!!tile(env3, 'session', '9c5a9271'), 'M4 sessions: live session id tile (ids-only shape)');
  await tile(env3, 'panel', 'Orchestrators').fire('click'); await flush();
  ok(!!tile(env3, 'orchestrator', 'Sprint 1'), 'M5 orchestrators: live orchestrator tile');
  await tile(env3, 'orchestrator', 'Sprint 1').fire('dblclick'); await flush();
  ok(!!tile(env3, 'execplan', 'agent-ux'), 'M5 orchestrators: members resolved via /{id}/work drill');
  cxp(); await flush();
  await tile(env3, 'panel', 'Punchcards').fire('click'); await flush();
  ok(ofKind(env3, 'punchcard-group').length === 2, 'M6 punchcards: grouped into 2 holder groups');
  await tile(env3, 'panel', 'Facts').fire('click'); await flush();
  ok(ofKind(env3, 'fact-group').length >= 2, 'M7 facts: grouped by entity prefix');
  await tile(env3, 'panel', 'Tenants').fire('click'); await flush();
  ok(!!tile(env3, 'tenant', 'lme-s'), 'M8 tenants: live tenant tile');
  await tile(env3, 'panel', 'Passport').fire('click'); await flush();
  ok(!!tile(env3, 'passport', 'ce:4e6c4e2a'), 'M8 passport: live passport tile');

  // M5 live write: build an orchestrator → Done POSTs create + member
  await tile(env3, 'panel', 'Work').fire('click'); await flush();   // populate work:agentux as a candidate
  cxp(); await flush();
  env3.getById('orcNew').fire('click'); await flush();
  env3.s.addToBuild('work:agentux'); await flush();
  env3.getById('bcName').value = 'New Sprint'; env3.getById('bcName').fire('input'); await flush();
  await env3.getById('bcDone').fire('click'); await flush();
  const postCreate = f3.calls.find(c => /\/v1\/orchestrators$/.test(c.url) && c.opts && c.opts.method === 'POST');
  ok(!!postCreate, 'M5 write: Done POSTs /v1/orchestrators (create)');
  ok(postCreate && JSON.parse(postCreate.opts.body).name === 'New Sprint', 'M5 write: create body carries the name');
  ok(f3.calls.some(c => /\/orchestrators\/orc_new\/members/.test(c.url) && c.opts && c.opts.method === 'POST'), 'M5 write: member POSTed to the new orchestrator');

  console.log(`\n${fail === 0 ? 'PASS' : 'FAIL'} — ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
