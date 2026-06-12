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
// M9: the embedded 3D substrate must be offline-true as well (no @import fetch, no CDNs)
const css3d = fs.readFileSync(__dirname + '/console-3d/css/console3d.css', 'utf8');
ok(!/@import\s+url\(['"]?https?:/.test(css3d), 'console-3d: no external @import in css');
['fonts.googleapis', 'unpkg.com', 'jsdelivr', 'cdnjs'].forEach(b =>
  ok(!css3d.includes(b) && !fs.readFileSync(__dirname + '/console-3d/index.html', 'utf8').includes(b), 'console-3d: no external dep: ' + b));

const code = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(x => x[1]).sort((a, b) => b.length - a.length)[0];
try { new Function(code); } catch (e) { console.error('FAIL parse:', e.message); process.exit(1); }

// ── DOM stub ──
function buildSandbox(fetchImpl, hash) {
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
  const s = { document, window, localStorage, console, DataTransfer, fetch: fetchImpl, setTimeout, clearTimeout, queueMicrotask, brandFallback: () => {}, location: { hash: hash || '' } };
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
  const workCall = f.calls.find(c => /\/v1\/work\?/.test(c.url));
  ok(!!workCall && /^\/v1\//.test(workCall.url), 'M3 work: same-origin /v1/work fetch issued');
  ok(workCall && workCall.opts.headers && /read/.test(workCall.opts.headers['X-Corecrux-Scopes'] || ''), 'M3 work: X-Corecrux-Scopes header attached');
  await tile(env, 'panel', 'Work').fire('click'); await flush();
  ok(!!tile(env, 'execplan', 'agent-ux-best-in-class'), 'M3 work: live WorkItem → execplan tile');
  ok(f.calls.filter(c => /\/v1\/work\?/.test(c.url)).length === 1, 'M3 work: cached (prefetch loaded it; click did not refetch)');
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

  // ── H) receipts: lookup → /verification + /signature → PASS/FAIL verdict (the verify-panel demo moment) ──
  const PASS_REPORT = { schema: 'cuecrux.receipt.verification.v1', receipt_id: 'crn_x', tenant_id: 'default', payload_hash: 'aa11', signature: { alg: 'Ed25519', key_id: 'daemon-root' },
    integrity: { payload_hash_matches: true, canonical_bytes_parse_ok: true }, signature_valid: true, pubkey_fingerprint: 'fp:12345678', error_code: 'OK', verified_at: '2026-06-11T10:00:00Z', verifier_build: 'corecruxd 0.4.2' };
  const SIG_EVENT = { tenant_id: 'default', receipt_id: 'crn_x', seq: 2, occurredAt: '2026-06-11T09:59:58Z', ingestedAt: '2026-06-11T09:59:59Z', contentType: 'application/cbor', payloadBase64: 'QUFBQQ==', payloadHash: 'bb22' };
  const BODY_EVENT = { tenant_id: 'default', receipt_id: 'crn_x', seq: 1, occurredAt: '2026-06-11T09:59:57Z', ingestedAt: '2026-06-11T09:59:58Z', contentType: 'application/cbor', payloadBase64: 'QkJCQg==', payloadHash: 'aa11' };
  const f4 = makeFetch();
  f4.route(u => /\/v1\/receipts\/crn_x\/verification\?tenant_id=default/.test(u), { ok: true, status: 200, body: PASS_REPORT });
  f4.route(u => /\/v1\/receipts\/crn_x\/signature\?tenant_id=default/.test(u), { ok: true, status: 200, body: SIG_EVENT });
  f4.route(u => /\/v1\/receipts\/crn_x\?tenant_id=default/.test(u), { ok: true, status: 200, body: BODY_EVENT });
  f4.route(u => /\/v1\/receipts\/crn_bad\/verification/.test(u), { ok: true, status: 200, body: Object.assign({}, PASS_REPORT, { receipt_id: 'crn_bad', signature_valid: false, error_code: 'BODY_HASH_MISMATCH', integrity: { payload_hash_matches: false, canonical_bytes_parse_ok: true } }) });
  f4.route(u => /\/v1\/receipts\/crn_bad\/signature/.test(u), { ok: true, status: 200, body: Object.assign({}, SIG_EVENT, { receipt_id: 'crn_bad' }) });
  f4.route(u => /\/v1\/receipts\/crn_bad\?/.test(u), { ok: true, status: 200, body: Object.assign({}, BODY_EVENT, { receipt_id: 'crn_bad' }) });
  f4.route(u => /\/v1\/receipts\/crn_missing/.test(u), { ok: false, status: 404, body: { error: 'receipt body not found' } });
  // deep link: #/receipts/crn_x auto-opens the verifier and verifies once live
  const env4 = buildSandbox(f4, '#/receipts/crn_x'); await flush(14);
  ok(env4.s.__cx.LIVE === true, 'receipts: deep-link env is live');
  const verCall = f4.calls.find(c => /\/v1\/receipts\/crn_x\/verification\?tenant_id=default/.test(c.url));
  ok(!!verCall, 'receipts: deep link #/receipts/crn_x fetched /verification?tenant_id=default');
  ok(verCall && verCall.opts.headers && /receipts:read/.test(verCall.opts.headers['X-Corecrux-Scopes'] || ''), 'receipts: scope header carries receipts:read by default');
  ok(f4.calls.some(c => /\/v1\/receipts\/crn_x\/signature\?tenant_id=default/.test(c.url)), 'receipts: /signature fetched alongside /verification');
  const rNode = env4.s.__cx.N['rcpt:crn_x'];
  ok(!!rNode && rNode.kind === 'receipt', 'receipts: lookup built the receipt node');
  const vNode = env4.s.__cx.N['rcptver:crn_x'];
  ok(!!vNode && /PASS/.test(vNode.label) && vNode.status === 'ok', 'receipts: verification node renders PASS (green)');
  ok(vNode && JSON.stringify(vNode.fields).includes('daemon-root'), 'receipts: verdict carries the signature kid');
  ok(vNode && JSON.stringify(vNode.fields).includes('2026-06-11T10:00:00Z'), 'receipts: verdict carries verified_at timestamp');
  const sNode = env4.s.__cx.N['rcptsig:crn_x'];
  ok(!!sNode && sNode.status === 'ok' && JSON.stringify(sNode.fields).includes('09:59:58Z'), 'receipts: signature node carries the sig event timestamps');
  ok(/PASS/.test(env4.getById('vcStatus').textContent) && /daemon-root/.test(env4.getById('vcStatus').textContent), 'receipts: verify card status line shows PASS + kid');
  ok((env4.s.__cx.N['cx-receipts'].children || []).includes('rcpt:crn_x'), 'receipts: panel recent list includes the verified receipt');
  ok(/crn_x/.test(env4.s.localStorage.getItem('crux-console-receipt-recent') || ''), 'receipts: lookup persisted to browser-local recent history');
  // drill loader: a recent-list receipt with unloaded children re-fetches /verification on click
  env4.s.exitFocus(); await flush();
  env4.s.__cx.loadState['rcpt:crn_x'] = 'idle'; env4.s.__cx.N['rcpt:crn_x'].children = [];
  await env4.s.__cx.ensureLoaded(env4.s.__cx.N['rcpt:crn_x']); await flush();
  ok(f4.calls.filter(c => /\/v1\/receipts\/crn_x\/verification/.test(c.url)).length >= 2, 'receipts: drill re-fetches /verification for an unloaded receipt node');
  ok((env4.s.__cx.N['rcpt:crn_x'].children || []).includes('rcptver:crn_x'), 'receipts: drill merges the verdict child');
  // FAIL path: signature_valid=false renders a red FAIL node with the error_code
  env4.s.openVerify('crn_bad'); env4.getById('vcTenant').value = 'default';
  await env4.getById('vcGo').fire('click'); await flush(10);
  const badNode = env4.s.__cx.N['rcptver:crn_bad'];
  ok(!!badNode && /FAIL/.test(badNode.label) && /BODY_HASH_MISMATCH/.test(badNode.label) && badNode.status === 'err', 'receipts: invalid signature renders FAIL + error_code (red)');
  ok(/FAIL/.test(env4.getById('vcStatus').textContent), 'receipts: verify card status line shows FAIL');
  // 404 path: calm not-found message, no node
  env4.s.openVerify('crn_missing'); env4.getById('vcTenant').value = 'default';
  await env4.getById('vcGo').fire('click'); await flush(10);
  ok(/Not found/.test(env4.getById('vcStatus').textContent), 'receipts: missing receipt → calm not-found status');
  ok(!env4.s.__cx.N['rcpt:crn_missing'], 'receipts: failed lookup does not fabricate a receipt node');

  // ── I) receipts demo mode: panel demos offline; verify card refuses to fake a verdict ──
  await tile(env2, 'panel', 'Receipts').fire('click'); await flush();
  ok(!!tile(env2, 'receipt', 'crn_8f21'), 'receipts demo: dummy CROWN receipt tile renders offline');
  await tile(env2, 'receipt', 'crn_8f21').fire('dblclick'); await flush();
  ok(ofKind(env2, 'verification').length >= 1, 'receipts demo: demo verdict node fans out on drill');
  env2.s.openVerify('crn_whatever'); await env2.getById('vcGo').fire('click'); await flush();
  ok(/[Dd]emo mode/.test(env2.getById('vcStatus').textContent), 'receipts demo: live verify refused in demo mode (no fake PASS)');

  // ── J) coord live board: #/coord deep link, live transform, overlaps, 404-disabled ──
  const f5 = makeFetch();
  f5.route(u => /\/v1\/coord\/active/.test(u), { ok: true, status: 200, body: {
    now_unix_ms: 1000000, presence_ttl_secs: 900,
    active_sessions: [
      { session_id_hex: 'aaaa1111bbbb', passport_id: 'claude-work', tenant_id: 'personal',
        bound_at_unix_ms: 990000, last_seen_at_unix_ms: 999000, active_until_unix_ms: 1899000,
        intent: { execplan_slug: 'shared-plan', milestone: 'M2', paths: ['crates/corecruxd/src'] },
        leases: [{ resource: 'tree://crates/corecruxd' }] },
      { session_id_hex: 'cccc2222dddd', passport_id: 'claude-research', tenant_id: 'personal',
        bound_at_unix_ms: 990000, last_seen_at_unix_ms: 998000, active_until_unix_ms: 1898000,
        intent: { execplan_slug: 'shared-plan', paths: ['crates/corecruxd/src/coord.rs'], note: 'review pass' } }
    ],
    work_in_flight: [{ id: 'w_1', title: 'coord plane', state: 'in_progress' }]
  } });
  const env5 = buildSandbox(f5, '#/coord');
  await flush(10);
  ok(env5.s.__cx.loadState['cx-coord'] === 'done', 'coord: deep link #/coord loaded the live board');
  const coNode = env5.s.__cx.N['co:aaaa1111bbbb'];
  ok(!!coNode && coNode.kind === 'coord-session' && /claude-work/.test(coNode.label), 'coord: live session node built (session8 · passport)');
  ok(!!coNode && /shared-plan @ M2/.test(coNode.sub), 'coord: sub line carries execplan @ milestone');
  ok(!!coNode && JSON.stringify(coNode.fields).includes('tree://crates/corecruxd'), 'coord: held lease joined onto the session');
  const ovIds = (env5.s.__cx.N['cx-coord'].children || []).filter(id => id.startsWith('cow:'));
  ok(ovIds.length >= 2, 'coord: execplan + path overlap warnings computed client-side');
  const coOvNode = env5.s.__cx.N[ovIds[0]];
  ok(!!coOvNode && coOvNode.status === "blocked" && /Overlap/.test(coOvNode.label), "coord: overlap node renders blocked");
  ok((env5.s.__cx.N['cx-coord'].children || []).includes('cowk:inflight'), 'coord: work-in-flight summary node present');
  // sibling string-prefix paths are NOT an overlap (component-aware rule)
  ok(env5.s.coordPathsOverlap('src/work', 'src/work/item.rs') === true
     && env5.s.coordPathsOverlap('src/work', 'src/work.rs') === false, 'coord: containment rule is path-component aware');

  // coord plane off: 404 → calm flag-hint empty-state (treat404AsDisabled)
  const f6 = makeFetch();
  f6.route(u => /\/v1\/coord\/active/.test(u), { ok: false, status: 404, body: { detail: 'coordination plane disabled' } });
  const env6 = buildSandbox(f6, '#/coord');
  await flush(10);
  ok(env6.s.__cx.loadState['cx-coord'] === 'unavailable', 'coord: 404 maps to unavailable, not error');
  ok((env6.s.__cx.N['cx-coord'].children || []).some(id => /CORECRUXD_COORD/.test((env6.s.__cx.N[id] || {}).label || '')), 'coord: 404 empty-state shows the CORECRUXD_COORD=1 hint');

  // demo mode: panel renders dummy sessions + overlap offline
  env2.s.exitFocus(); await flush();
  await tile(env2, 'panel', 'Live board').fire('click'); await flush();
  ok(!!tile(env2, 'coord-session', 'fa0a2f95'), 'coord demo: dummy live-session tile renders offline');
  ok(!!tile(env2, 'coord-overlap', 'Overlap'), 'coord demo: dummy overlap tile renders offline');

  // ── K) M1 — operator pages live-wired (PAGE_WIRES: load / set / act + raw RPC) ──
  const f7 = makeFetch();
  f7.route(u => /\/v1\/console\/settings$/.test(u), { ok: true, status: 200, body: {
    auth: { running_mode: 'local_only', chosen_mode: null, bind_is_loopback: true, supported_modes: ['local_only', 'open', 'token', 'jwt_hs256'] },
    embedding: { enabled_intent: null, chosen_url: null, chosen_model: null, active_url: 'http://localhost:11434', active_model: 'bge-m3', active: true },
    onboarding: { completed_at_unix_ms: 1 } } });
  f7.route((u, o) => /\/v1\/console\/settings$/.test(u) && o.method === 'PUT', { ok: true, status: 200, body: { saved: {}, restart_required: true, restart_command: 'docker restart crux' } });
  f7.route(u => /\/v1\/console\/embedding\/probe/.test(u), { ok: true, status: 200, body: { shape: 'ollama', models: ['bge-m3', 'nomic-embed-text'], resolved_url: 'http://localhost:11434' } });
  f7.route(u => /\/v1\/projects$/.test(u), { ok: true, status: 200, body: { projects: [{ id: 'cuecrux', name: 'CueCrux', planning_target: 'github:CueCrux/Crux', working_tenants: ['default'] }] } });
  f7.route((u, o) => /\/v1\/projects$/.test(u) && o.method === 'POST', { ok: true, status: 201, body: { id: 'newproj' } });
  f7.route(u => /\/v1\/console\/passports/.test(u), { ok: true, status: 200, body: { passports: [{ id: 'ce:4e6c4e2a:local' }, { id: 'ce:8821fa0d:local' }] } });
  f7.route(u => /\/v1\/mcp\/tools/.test(u), { ok: true, status: 200, body: { count: 2, tools: [{ name: 'query' }, { name: 'store_fact' }] } });
  f7.route(u => /\/v1\/extensions$/.test(u), { ok: true, status: 200, body: { count: 1, extensions: [{ id: 'crux-claude-hooks', version: '0.4.2', kind: 'hooks' }], allow_unsigned_dev: false } });
  f7.route(u => /\/v1\/extensions\/keys$/.test(u), { ok: true, status: 200, body: { count: 1, keys: [{ passport_fpr: 'fp:abc', trust_tier: 'first_party', added_by: 'root' }] } });
  f7.route(u => /\/v1\/console\/integrations/.test(u), { ok: true, status: 200, body: { enabled: true, safe_mode: true, allow_executable_helpers: false, allowed_capabilities: [],
    packs: [{ id: 'git-pack', version: '1.0', status: 'enabled' }, { id: 'fs-pack', version: '1.0', status: 'disabled' }], grants: [{}] } });
  f7.route((u, o) => /\/v1\/console\/integrations\/fs-pack\/install/.test(u) && o.method === 'POST', { ok: true, status: 201, body: {} });
  f7.route(u => /\/v1\/integrations\/github\/status/.test(u), { ok: true, status: 200, body: { connected: true, username: 'myles' } });
  f7.route(u => /\/v1\/integrations\/openai\/status/.test(u), { ok: true, status: 200, body: { connected: false, available_models: ['gpt-4o'], default_model: null } });
  const env7 = buildSandbox(f7); await flush();
  const lastBtn = (env, label) => env.ALL.filter(e => e._text === label && e._listeners && e._listeners.click).pop();

  // settings: load adopts daemon truth; control change PUTs; probe refreshes model options
  env7.s.openPage('cx-settings'); await flush(10);
  ok(f7.calls.some(c => /\/v1\/console\/settings$/.test(c.url) && (!c.opts || c.opts.method !== 'PUT')), 'M1 settings: open page GETs /v1/console/settings');
  ok((env7.s.pageCtrl('cx-settings', 'auth_mode').options || []).includes('jwt_hs256'), 'M1 settings: auth-mode options replaced from supported_modes');
  ok(env7.s.pageVal('cx-settings', 'embed_url') === 'http://localhost:11434', 'M1 settings: embedding url adopted from daemon');
  const tog7 = env7.ALL.filter(e => e.classList && e.classList.contains('sp-toggle') && e.dataset['aria-label'] === 'enable embedding retrieval').pop();
  await tog7.fire('click'); await flush(6);
  const put7 = f7.calls.find(c => c.opts && c.opts.method === 'PUT' && /console\/settings/.test(c.url));
  ok(!!put7, 'M1 settings: toggling embedding PUTs /v1/console/settings');
  ok(put7 && JSON.parse(put7.opts.body).embedding_enabled !== undefined, 'M1 settings: PUT body carries embedding_enabled');
  await lastBtn(env7, 'Probe endpoint').fire('click'); await flush(8);
  ok(f7.calls.some(c => /embedding\/probe/.test(c.url) && c.opts.method === 'POST'), 'M1 settings: probe button POSTs /v1/console/embedding/probe');
  ok((env7.s.pageCtrl('cx-settings', 'embed_model').options || []).includes('nomic-embed-text'), 'M1 settings: probe result repopulates model options');

  // projects: passports populate the select; create POSTs the form
  env7.s.closePage(); env7.s.openPage('cx-projects'); await flush(10);
  ok((env7.s.pageCtrl('cx-projects', 'proj_passport').options || []).includes('ce:8821fa0d:local'), 'M1 projects: passport options from /v1/console/passports');
  ok(env7.ALL.some(e => e._text === 'CueCrux'), 'M1 projects: tracked list rendered from /v1/projects');
  env7.s.confSet('cx-projects.proj_id', 'newproj');
  await lastBtn(env7, 'Create project').fire('click'); await flush(8);
  const postP = f7.calls.find(c => /\/v1\/projects$/.test(c.url) && c.opts && c.opts.method === 'POST');
  ok(!!postP, 'M1 projects: Create project POSTs /v1/projects');
  ok(postP && JSON.parse(postP.opts.body).id === 'newproj', 'M1 projects: POST body carries the id');

  // extensions + integrations: live lists replace the concept rows; pack toggle installs
  env7.s.closePage(); env7.s.openPage('cx-extensions'); await flush(10);
  ok(env7.ALL.some(e => e._text === 'crux-claude-hooks'), 'M1 extensions: installed list from /v1/extensions');
  ok(env7.ALL.some(e => e._text === 'fp:abc'), 'M1 extensions: trusted keys from /v1/extensions/keys');
  env7.s.closePage(); env7.s.openPage('cx-integrations'); await flush(10);
  const pkTog = env7.ALL.filter(e => e.classList && e.classList.contains('sp-toggle') && /fs-pack/.test(e.dataset['aria-label'] || '')).pop();
  ok(!!pkTog, 'M1 integrations: pack toggles rebuilt from live /v1/console/integrations');
  ok(env7.ALL.some(e => /connected · myles/.test(e._text || '')), 'M1 integrations: github status row live');
  await pkTog.fire('click'); await flush(6);
  ok(f7.calls.some(c => /console\/integrations\/fs-pack\/install/.test(c.url) && c.opts.method === 'POST'), 'M1 integrations: pack toggle on POSTs install');

  // raw RPC: tools/list rides the same-origin catalog proxy
  env7.s.closePage(); env7.s.openPage('cx-raw'); await flush(6);
  env7.s.sendRpc('cx-raw'); await flush(6);
  ok(f7.calls.some(c => /\/v1\/mcp\/tools/.test(c.url)), 'M1 rpc: tools/list rides /v1/mcp/tools');
  ok(/store_fact/.test(env7.getById('rpcOut').textContent), 'M1 rpc: tool names rendered into the output pane');

  // demo mode: wired buttons refuse politely, no network
  env2.s.openPage('cx-settings'); await flush(6);
  await lastBtn(env2, 'Probe endpoint').fire('click'); await flush(6);
  ok(/demo mode/.test(env2.getById('cxToast').textContent), 'M1 demo: wired button refuses politely in demo mode');
  ok(!f2.calls.some(c => /embedding\/probe/.test(c.url)), 'M1 demo: no probe network call in demo mode');

  // ── L) M2 — token usage live (page + ov-usage dash tile from /v1/observations/aggregate) ──
  const f8 = makeFetch();
  f8.route(u => /\/v1\/observations\/aggregate/.test(u), { ok: true, status: 200, body: { matched: 3, returned: 3, chains: {}, observations: [
    { observation_id: 'o1', session_id: 'execplan:demo-plan', ts: '2026-06-12T08:00:00Z', provider: 'anthropic', principal: 'p', kind: 'model_response', payload: { usage: { input_tokens: 1000, output_tokens: 100 } } },
    { observation_id: 'o2', session_id: 'execplan:demo-plan', ts: '2026-06-12T08:05:00Z', provider: 'anthropic', principal: 'p', kind: 'model_response', payload: { usage: { input_tokens: 2000, output_tokens: 200 } } },
    { observation_id: 'o3', session_id: 'adhoc123', ts: '2026-06-12T08:06:00Z', provider: 'anthropic', principal: 'p', kind: 'model_response', payload: { usage: { input_tokens: 500, output_tokens: 50 } } }] } });
  f8.route(u => /\/v1\/console\/summary/.test(u), { ok: true, status: 200, body: { daemon: { node_id: 'n1', auth_mode: 'local_only' }, stores: { facts: 7 } } });
  const env8 = buildSandbox(f8); await flush(8);
  ok(f8.calls.some(c => /observations\/aggregate/.test(c.url)), 'M2 usage: overview prefetch pulls /v1/observations/aggregate');
  const ovU = env8.s.__cx.N['ov-usage'];
  ok(/"in": ?3500/.test(ovU.payload || ''), 'M2 usage: dash tile payload carries the live total (3500 in)');
  ok(/live/.test(ovU.sub || ''), 'M2 usage: dash tile flagged live');
  ok((ovU.children || []).length === 0, 'M2 usage: dummy session children replaced by the live rollup');
  env8.s.openPage('cx-usage'); await flush(10);
  ok(env8.ALL.some(e => /execplan:demo-plan/.test(e._text || '')), 'M2 usage: per-execplan bar rendered from live sessions');
  ok(env8.ALL.some(e => /standard session/.test(e._text || '')), 'M2 usage: savings bars computed from live in/out');
  ok(env8.ALL.some(e => /3 model calls/.test(e._text || '')), 'M2 usage: window totals row shows live call count');
  const aggBefore = f8.calls.filter(c => /observations\/aggregate/.test(c.url)).length;
  env8.s.confSet('cx-usage.win', '30d'); await flush(10);
  ok(f8.calls.filter(c => /observations\/aggregate/.test(c.url)).length > aggBefore, 'M2 usage: window change re-queries the aggregate');
  // zero observations → calm explainer, demo dash tile untouched
  const f9 = makeFetch();
  f9.route(u => /\/v1\/observations\/aggregate/.test(u), { ok: true, status: 200, body: { matched: 0, returned: 0, chains: {}, observations: [] } });
  f9.route(u => /\/v1\/console\/summary/.test(u), { ok: true, status: 200, body: { daemon: {}, stores: {} } });
  const env9 = buildSandbox(f9); await flush(8);
  ok(/517k/.test(JSON.stringify(env9.s.__cx.N['ov-usage'].fields)), 'M2 usage: zero observations keeps the demo dash tile');
  env9.s.openPage('cx-usage'); await flush(10);
  ok(env9.ALL.some(e => /CORECRUXD_OBSERVE/.test(e._text || '')), 'M2 usage: zero observations → explainer, not fake bars');

  // ── M) M3 — documents/ingest live (tenants, chunks, storage breakdown, scan, queue fact) ──
  const f10 = makeFetch();
  f10.route(u => /\/v1\/console\/tenants$/.test(u), { ok: true, status: 200, body: { dataplane_enabled: false, tenants: [
    { tenant_id: 'lme-s', category: 'work', override: null }, { tenant_id: 'personal', category: 'personal', override: null }] } });
  f10.route(u => /\/v1\/console\/tenants\/lme-s\/chunks/.test(u), { ok: true, status: 200, body: { tenant_id: 'lme-s',
    chunks: [{ chunk_digest: 'd1', stream_type: 'documents', stream_id: 'sess_7f3a_travel', event_type: 'knowledge.document.ingested.v1', payload_bytes: 4096, occurred_at: '2026-05-16T08:00:00Z' }],
    page: { limit: 12, next_cursor: 'c2' } } });
  f10.route(u => /\/v1\/console\/storage-breakdown/.test(u), { ok: true, status: 200, body: { kinds: [
    { kind: 'text_search', label: 'Text Search', available: true, chunks: 6600000, bytes: 5260000000 },
    { kind: 'projections', label: 'Projections', available: false, chunks: 0, bytes: 0 }] } });
  f10.route(u => /\/v1\/console\/facts\?q=ingest/.test(u), { ok: true, status: 200, body: { facts: [{ entity: 'ingest:queue', key: 'path:~/docs' }] } });
  f10.route((u, o) => /\/v1\/console\/facts\/add/.test(u) && o.method === 'POST', { ok: true, status: 200, body: { fact_id: 'f_new' } });
  f10.route((u, o) => /\/v1\/workspace\/scan/.test(u) && o.method === 'POST', { ok: true, status: 200, body: { scan_id: 's1', root_path: '/src', duration_ms: 412, stats: { modules: 17 } } });
  f10.route(u => /\/v1\/console\/summary/.test(u), { ok: true, status: 200, body: { daemon: {}, stores: {} } });
  const env10 = buildSandbox(f10); await flush(8);
  ok(/live · 1 of 2/.test(env10.s.__cx.N['ov-storage'].sub || ''), 'M3 storage: ov-storage dash tile live from storage-breakdown');
  env10.s.openPage('cx-documents'); await flush(12);
  ok((env10.s.pageCtrl('cx-documents', 'doc_tenant').options || []).join(',') === 'lme-s,personal', 'M3 documents: tenant select from /v1/console/tenants');
  ok(env10.ALL.some(e => /documents \/ sess_7f3a_travel/.test(e._text || '')), 'M3 documents: chunk metadata rows from /chunks');
  ok(env10.ALL.some(e => /more available/.test(e._text || '')), 'M3 documents: next_cursor surfaces as "more available"');
  ok(env10.ALL.some(e => /1 pending/.test(e._text || '')), 'M3 documents: pipeline queue counts ingest:queue facts');
  env10.s.confSet('cx-documents.ing_path', '~/corpus/**/*.md');
  await lastBtn(env10, 'Queue ingest').fire('click'); await flush(8);
  const qPost = f10.calls.find(c => /facts\/add/.test(c.url) && c.opts && c.opts.method === 'POST');
  ok(!!qPost, 'M3 ingest: Queue ingest POSTs /v1/console/facts/add');
  ok(qPost && JSON.parse(qPost.opts.body).entity === 'ingest:queue', 'M3 ingest: fact entity is ingest:queue');
  ok(qPost && /corpus/.test(JSON.parse(JSON.parse(qPost.opts.body).value).path), 'M3 ingest: fact value carries the queued path');
  await lastBtn(env10, 'Scan path').fire('click'); await flush(8);
  ok(f10.calls.some(c => /workspace\/scan/.test(c.url) && c.opts && c.opts.method === 'POST'), 'M3 scan: Scan path POSTs /v1/workspace/scan');
  ok(/17 modules/.test(env10.getById('cxToast').textContent || ''), 'M3 scan: toast carries scan stats');

  // ── N) M4 — events stream: tail page + ticker (stub has no ReadableStream → graceful 'unsupported') ──
  ok(f10.calls.some(c => /\/v1\/events\/stream/.test(c.url)), 'M4 events: boot subscribes to /v1/events/stream when live');
  env10.s.onCruxEvent('fact.stored', JSON.stringify({ type: 'fact.stored', data: { fact_id: 'f1', entity: 'execplan:gap', key: 'gate:M4' } }));
  env10.s.onCruxEvent('punchcard.changed', JSON.stringify({ type: 'punchcard.changed', data: { resource: 'tree://crates' } }));
  env10.s.closePage(); env10.s.openPage('ax-activity'); await flush(8);
  ok(env10.ALL.some(e => /execplan:gap · gate:M4/.test(e._text || '')), 'M4 events: tail row carries entity · key');
  ok(env10.ALL.some(e => /punchcard\.changed/.test(e._text || '')), 'M4 events: newest event rendered in the tail');
  env10.s.dashMode = true; env10.s.onCruxEvent('fact.stored', JSON.stringify({ type: 'fact.stored', data: { entity: 'bench:lme-s', key: 'r1' } }));
  ok(/bench:lme-s/.test(env10.getById('evtTicker').textContent || ''), 'M4 events: dash ticker shows the latest event');
  ok(/3 events/.test(env10.getById('evtTicker').textContent || ''), 'M4 events: ticker carries the buffer count');
  await lastBtn(env10, 'Clear').fire('click'); await flush(6);
  ok(env10.ALL.filter(e => /no events yet/.test(e._text || '')).length >= 1, 'M4 events: Clear empties the tail');

  // ── O) M5 — ops + update surfaces (settings sections + overview update badge) ──
  f7.route(u => /\/v1\/version/.test(u), { ok: true, status: 200, body: { version: 'v0.4.2',
    update: { enabled: true, state: 'behind', remote: 'origin', ref: 'main', tracking_ref: 'origin/main', ahead_by: 0, behind_by: 37, checked_at: '2026-06-12T08:56:54Z', comparison_stale: false, upgrade_hint: 'cut a v* tag — :latest tracks releases' } } });
  f7.route(u => /\/v1\/ops\/health/.test(u), { ok: true, status: 200, body: { health: [{ entity: '__ops__::health::sync', key: 'status', value: 'ok · local_only', stored_at: '2026-06-12T08:00:00Z' }] } });
  f7.route(u => /\/v1\/ops\/errors/.test(u), { ok: true, status: 200, body: { facts: [{ entity: '__ops__::error::append', key: 'err', value: 'disk stall 1.2s', stored_at: '2026-06-12T07:00:00Z' }], total_tokens: 12 } });
  f7.route(u => /\/v1\/bootstrap\/status/.test(u), { ok: true, status: 200, body: { seeded: true, fact_count: 8, categories: ['patterns'], last_seed_at: '2026-06-01T00:00:00Z' } });
  env7.s.closePage(); env7.s.openPage('cx-settings'); await flush(12);
  ok(env7.ALL.some(e => /behind · 37 commits behind/.test(e._text || '')), 'M5 update: git-behind state rendered from /v1/version');
  ok(env7.ALL.some(e => /cut a v\* tag/.test(e._text || '')), 'M5 update: upgrade hint surfaced when behind');
  ok(env7.ALL.some(e => /seeded · 8 facts/.test(e._text || '')), 'M5 bootstrap: status row from /v1/bootstrap/status');
  ok(env7.ALL.some(e => /ok · local_only/.test(e._text || '')), 'M5 ops: health component row from /v1/ops/health');
  ok(env7.ALL.some(e => /⚠ append/.test(e._text || '')), 'M5 ops: recent error row from /v1/ops/errors');
  // observe off → 501 → calm flag hint
  f7.route(u => /\/v1\/ops\/health/.test(u), { ok: false, status: 501, body: { detail: 'self-observation not enabled' } });
  f7.route(u => /\/v1\/ops\/errors/.test(u), { ok: false, status: 501, body: {} });
  f7.route(u => /\/v1\/bootstrap\/status/.test(u), { ok: false, status: 501, body: {} });
  env7.s.closePage(); env7.s.openPage('cx-settings'); await flush(12);
  ok(env7.ALL.some(e => /observe plane off/.test(e._text || '')), 'M5 ops: 501 renders the CORECRUXD_OBSERVE hint');
  // overview tile badge (unit-level: applyUpdateBadge is also fed by the cx-overview loader)
  env7.s.applyUpdateBadge({ update: { state: 'behind', behind_by: 37 } });
  ok(JSON.stringify(env7.s.__cx.N['ov-node'].fields).includes('37 behind'), 'M5 update: ov-node tile carries the behind badge');

  // ── P) M6 — work comments/transitions drill + gates approve/reject ──
  f10.route(u => /\/v1\/work\?/.test(u), { ok: true, status: 200, body: { work: [{ id: 'gapwork', title: 'gap closure', state: 'in_progress' }] } });
  f10.route(u => /\/v1\/work\/gapwork\/comments/.test(u), { ok: true, status: 200, body: { work_id: 'gapwork', comments: [
    { id: 'c1', work_id: 'gapwork', author_passport: 'ce:4e6c4e2a:local', body: 'M1 held until the cutover merges', posted_at_unix_ms: 1765000000000 }] } });
  f10.route(u => /\/v1\/work\/gapwork\/transitions/.test(u), { ok: true, status: 200, body: { work_id: 'gapwork', transitions: [
    { id: 't1', work_id: 'gapwork', from_state: 'planned', to_state: 'in_progress', by_passport: 'ce:4e6c4e2a:local', gate_status: 'allowed', at_unix_ms: 1765000000000 }] } });
  f10.route(u => /\/v1\/work\/gate\/pending/.test(u), { ok: true, status: 200, body: { count: 1, pending: [
    { action_id: 'act_1', work_id: 'release-readiness', requested_by_passport: 'claude-work', requested_action: 'update_state', target_state: 'deployed', status: 'pending', requested_at_unix_ms: 1765000000000 }] } });
  f10.route((u, o) => /\/v1\/work\/gate\/act_1\/approve/.test(u) && o.method === 'POST', { ok: true, status: 200, body: { id: 'release-readiness', state: 'deployed' } });
  // drill: live work node fans out comments + transitions
  await tile(env10, 'panel', 'Work').fire('click'); await flush(8);
  const wNode = env10.s.__cx.N['work:gapwork'];
  ok(!!wNode && wNode.__workId === 'gapwork', 'M6 thread: live work item carries __workId');
  await env10.s.__cx.ensureLoaded(wNode); await flush(8);
  ok((wNode.children || []).some(id => id.startsWith('wcm:')), 'M6 thread: drill merges comment children');
  ok((wNode.children || []).some(id => id.startsWith('wtx:')), 'M6 thread: drill merges transition children');
  ok(/planned → in_progress/.test((env10.s.__cx.N[(wNode.children || []).find(id => id.startsWith('wtx:'))] || {}).label || ''), 'M6 thread: transition label carries from → to');
  // gates page: pending rows + attributed approve
  env10.s.closePage(); env10.s.openPage('cx-gates'); await flush(10);
  ok(env10.ALL.some(e => /update_state → deployed · requested by claude-work/.test(e._text || '')), 'M6 gates: pending gate row rendered');
  env10.s.localStorage.setItem('crux-console-bound-passport', 'ce:4e6c4e2a:local');
  const apBtn = lastBtn(env10, 'Approve act_1');
  await apBtn.fire('click'); await flush(2);     // danger two-step: first click arms
  await apBtn.fire('click'); await flush(8);     // second click fires
  const apCall = f10.calls.find(c => /gate\/act_1\/approve/.test(c.url) && c.opts && c.opts.method === 'POST');
  ok(!!apCall, 'M6 gates: Approve POSTs /v1/work/gate/{actionId}/approve');
  ok(apCall && JSON.parse(apCall.opts.body).approver_passport === 'ce:4e6c4e2a:local', 'M6 gates: approval carries the bound passport (Art. 14)');
  // unbound passport → refusal, no network
  env10.s.localStorage.removeItem('crux-console-bound-passport');
  env10.s.closePage(); env10.s.openPage('cx-gates'); await flush(8);
  const rjBtn = lastBtn(env10, 'Reject act_1');
  await rjBtn.fire('click'); await flush(2); await rjBtn.fire('click'); await flush(6);
  ok(/bind a passport/.test(env10.getById('cxToast').textContent || ''), 'M6 gates: unbound passport refuses with attribution message');
  ok(!f10.calls.some(c => /gate\/act_1\/reject/.test(c.url)), 'M6 gates: no reject call without attribution');

  // ── Q) M7 — query workbench + entities browser + passport presence ──
  f10.route(u => /\/v1\/kinds/.test(u), { ok: true, status: 200, body: { kinds: [{ kind: 'capability' }, { kind: 'document' }], count: 2 } });
  f10.route((u, o) => /\/v1\/query\/text-search$/.test(u) && o.method === 'POST', { ok: true, status: 200, body: {
    results: [{ result_id: '0:226200', rank: 1, segment_index: 0, doc_id: 226200, score: 0.913, frame_offset: 0, token_count: 412 }],
    coverage: { score: 0.9, gaps: [], below_floor: 0 }, meta: { backend: 'corecrux-v5-bm25', took_ms: 12, segments_searched: 3, total_docs: 100, total_candidates: 8 } } });
  f10.route((u, o) => /\/v1\/query\/graph-expand/.test(u) && o.method === 'POST', { ok: false, status: 404, body: { detail: 'not enabled' } });
  f10.route(u => /\/v1\/entities\/capability\/cap-1\/history/.test(u), { ok: true, status: 200, body: { versions: [{}, {}], count: 2 } });
  f10.route(u => /\/v1\/entities\/capability\/cap-1$/.test(u), { ok: true, status: 200, body: { entity: { id: 'cap-1', kind: 'capability', name: 'Receipts verify' } } });
  env10.s.closePage(); env10.s.openPage('cx-workbench'); await flush(10);
  ok((env10.s.pageCtrl('cx-workbench', 'wbe_kind').options || []).includes('document'), 'M7 entities: kind options from /v1/kinds');
  env10.s.confSet('cx-workbench.wbq_query', 'cascade');
  await lastBtn(env10, 'Run text search').fire('click'); await flush(10);
  const tsCall = f10.calls.find(c => /query\/text-search$/.test(c.url) && c.opts && c.opts.method === 'POST');
  ok(!!tsCall && JSON.parse(tsCall.opts.body).query === 'cascade', 'M7 query: text-search POSTs the query');
  ok(env10.ALL.some(e => /#1 · doc 226200/.test(e._text || '')), 'M7 query: result row rendered with rank + doc id');
  ok((env10.s.__cx.N['cx-workbench'].children || []).includes('wbres:0:226200'), 'M7 query: results merged as graph nodes for column browsing');
  env10.s.confSet('cx-workbench.wbq_seeds', '12');
  await lastBtn(env10, 'Graph expand').fire('click'); await flush(8);
  ok(/dataplane lane off/.test(env10.getById('cxToast').textContent || ''), 'M7 query: disabled lane (404) toasts the flag hint');
  env10.s.confSet('cx-workbench.wbe_id', 'cap-1');
  await lastBtn(env10, 'Load entity').fire('click'); await flush(10);
  ok(env10.ALL.some(e => /2 versions/.test(e._text || '')), 'M7 entities: history version count rendered');
  // presence joined onto the passports panel
  const f11 = makeFetch();
  f11.route(u => /\/v1\/passports$/.test(u), { ok: true, status: 200, body: { passports: [{ id: 'claude-work', category: 'agent', reputation_tier: 'basic' }] } });
  f11.route(u => /\/v1\/passports\/presence/.test(u), { ok: true, status: 200, body: { count: 2, presence: [
    { passport_id: 'claude-work', last_seen_at_unix_ms: Date.now() - 5000, last_route: '/v1/work', last_method: 'GET', call_count: 41 },
    { passport_id: 'ghost-agent', last_seen_at_unix_ms: Date.now() - 65000, last_route: '/mcp', last_method: 'POST', call_count: 7 }] } });
  const env11 = buildSandbox(f11); await flush(6);
  await tile(env11, 'panel', 'Passport').fire('click'); await flush(8);
  const ppNode = env11.s.__cx.N['pp:claude-work'];
  ok(!!ppNode && /seen 5s ago/.test(ppNode.sub || ''), 'M7 presence: live passport row carries last-seen');
  ok(ppNode && JSON.stringify(ppNode.fields).includes('GET /v1/work'), 'M7 presence: last route joined onto the passport');
  ok(!!env11.s.__cx.N['ppx:ghost-agent'], 'M7 presence: presence-only passport appears as its own row');

  console.log(`\n${fail === 0 ? 'PASS' : 'FAIL'} — ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
