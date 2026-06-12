/* ════════════════════════════════════════════════════════════════════════
   Crux Substrate — concept graph data
   Dummy data, daemon-styled. Same lineage as UI-prototype/agent-observability.html
   registry (N). Swap point for live data: replace NODES/LINKS with /v1/work,
   /v1/facts, /v1/coord/active, /v1/receipts/{id} projections.

   RADIAL LAYOUT — the daemon sits at the origin; everything else is arranged
   on rings along its lineage bearings (linear lines drawn out from the core):
     ring 1 (back)  passports
     ring 2 (back)  sessions, behind the daemon, on their passport's bearing
     ring 3 (back)  execplans — a half-circle fed by their sessions
     ring 4 (back)  memory: execplan-linked facts sit outward of their plan
     front          coord plane + orphan facts; the receipt chain arcs
                    front-left reading seq 1→5
   Bearings: x = cos(a)·r, z = sin(a)·r; +z faces the default camera (front),
   so "behind the daemon" = a≈270°. Links are straight single-level traces.
   ════════════════════════════════════════════════════════════════════════ */

/* Districts are lineage zones. pos = [x, z] centroid; labelPos = label spot. */
export const DISTRICTS = [
  { id: 'core',     label: 'DAEMON',    pos: [0, 0],      labelPos: [0, 11.5],
    sub: 'ce:4e6c4e2a:local · local_only' },
  { id: 'passport', label: 'PASSPORT',  pos: [0, -18],    labelPos: [0, -25.5],
    sub: 'identities · ring 1' },
  { id: 'sessions', label: 'SESSIONS',  pos: [0, -32],    labelPos: [0, -39.5],
    sub: 'execplan-scoped · behind the core' },
  { id: 'work',     label: 'WORK',      pos: [0, -56],    labelPos: [0, -63.5],
    sub: 'execplans · slab height = tokens' },
  { id: 'memory',   label: 'MEMORY',    pos: [0, -80],    labelPos: [0, -88],
    sub: 'facts gate their plans' },
  { id: 'receipts', label: 'RECEIPTS',  pos: [-59, 34],   labelPos: [-66, 41],
    sub: 'CROWN chain · seq 1→5' },
  { id: 'coord',    label: 'COORD',     pos: [-10, 44],   labelPos: [-10, 53],
    sub: 'live board · in front' },
];

/* status: ok | run | err | idle  (corner lamp)
   state : done | in_progress | blocked | planned  (block tint)             */
export const NODES = [
  /* ── daemon core — the centre of the disc ───────────────────────────── */
  { id: 'daemon', kind: 'daemon', district: 'core', pos: [0, 0],
    label: 'crux daemon', sub: 'local-first · memory · retrieval · receipts', status: 'run',
    fields: [['mode', 'local_only'], ['facts', '3,823'], ['sessions', '3 active'],
             ['http', ':14800'], ['mcp', ':14801'], ['grpc', ':4007'],
             ['signer', 'Ed25519 · daemon-root'], ['build', '7417c9f']],
    doc: 'CRUX DAEMON — the substrate\n\nEverything on this plane is a projection of the\ndaemon’s stores: work items, sessions, facts,\nreceipts, coordination presence. Nothing here is\ndrawn from chat history — it is all replayable\nstate behind /v1/* endpoints.' },

  /* ── ring 1: passports (back arc, wired straight into the core) ─────── */
  { id: 'pp-main', kind: 'passport', district: 'passport', pos: [-0.0, -18.0],
    label: 'ce:4e6c4e2a:local', sub: 'claude-work · tier basic · 76 receipts', status: 'run',
    fields: [['tier', 'basic'], ['group', 'work'], ['receipts', '76'], ['capabilities', '14'],
             ['session ttl', '3600s']],
    doc: 'PASSPORT ce:4e6c4e2a:local\n\nThe identity every write is attributed to.\nCapabilities load as a ladder at session bind;\nreputation accrues from verified receipts.' },
  { id: 'pp-sonnet', kind: 'passport', district: 'passport', pos: [-8.5, -15.9],
    label: 'ce:8821fa0d:local', sub: 'claude-sonnet · tier local', status: 'idle',
    fields: [['tier', 'local'], ['group', 'work'], ['receipts', '12']] },
  { id: 'pp-ops', kind: 'passport', district: 'passport', pos: [8.5, -15.9],
    label: 'ce:0c4419ab:remote', sub: 'ops · deploy lane', status: 'idle',
    fields: [['tier', 'remote'], ['group', 'ops'], ['receipts', '31']] },

  /* ── ring 2: sessions, behind the daemon on their passport's bearing ── */
  { id: 'sess-agentux', kind: 'session', district: 'sessions', pos: [-4.5, -31.7],
    label: 'execplan:agent-ux', sub: '9c5a9271 · 42 turns · 312k/41k tok', status: 'run',
    tools: [['Read', 38], ['Edit', 12], ['Bash', 9], ['store_fact', 5]],
    timeline: [
      { k: 'boot',      label: 'session bind',              sub: 'ce:4e6c4e2a:local · 13:02Z', lane: 0 },
      { k: 'execplan',  label: 'agent-ux-best-in-class',    sub: 'M4 · reconciler picked up', lane: -1 },
      { k: 'tool',      label: 'Read ×2',                   sub: 'work.rs · projection.rs', lane: 0 },
      { k: 'reasoning', label: 'projection unsorted',       sub: 'hash order before kanban merge', lane: -1 },
      { k: 'receipt',   label: 'crn_8f21 sealed',           sub: 'diagnose step · risk low', lane: 1 },
      { k: 'milestone', label: 'M4 → in_progress',          sub: 'gate:M4 opened', lane: 0 },
      { k: 'tool',      label: 'Write reconcile.rs',        sub: '+140 lines', lane: 0 },
      { k: 'tool',      label: 'Edit projection.rs',        sub: '+33 −12', lane: 0 },
      { k: 'fact',      label: 'decision:reconciler-sort',  sub: 'stable sort by updated_at', lane: 1 },
      { k: 'receipt',   label: 'crn_b033 sealed',           sub: '2 mutations · risk medium', lane: 1 },
      { k: 'tool',      label: 'Bash cargo test',           sub: 'exit 101 · 4 failing', lane: 0 },
      { k: 'reasoning', label: 'do not retry blindly',      sub: 'defer until loopback-auth lands', lane: -1 },
      { k: 'fact',      label: 'gate:M4 stored',            sub: 'tests_passing:false · failing:4', lane: 1 },
      { k: 'receipt',   label: 'crn_c7a9 sealed',           sub: 'test run · exit 101', lane: 1 },
      { k: 'milestone', label: 'M4 blocked',                sub: 'session note 13:24Z', lane: 0 },
    ],
    fields: [['session', '9c5a9271…'], ['passport', 'ce:4e6c4e2a:local'],
             ['execplan', 'agent-ux-best-in-class-master'], ['milestone', 'M4 · reconciler'],
             ['tokens', '312k in · 41k out']],
    doc: 'SESSION 9c5a9271 · execplan-scoped\n\nBound to passport ce:4e6c4e2a:local, working\nagent-ux M4. Owns two punchcard leases; every\nmutation it makes seals a CROWN receipt.' },
  { id: 'sess-chaincrux', kind: 'session', district: 'sessions', pos: [-17.0, -27.1],
    label: 'execplan:chaincrux', sub: 'b17c277d · review pass', status: 'run',
    tools: [['Read', 21], ['Grep', 7], ['query', 4]],
    timeline: [
      { k: 'boot',      label: 'session bind',           sub: 'b17c277d · review pass', lane: 0 },
      { k: 'execplan',  label: 'chaincrux-cascade-route', sub: 'M3 · wire decide()', lane: -1 },
      { k: 'tool',      label: 'Read ×21',               sub: 'cascade_gate.rs · route shim', lane: 0 },
      { k: 'reasoning', label: 'decide() never invoked', sub: 'dead code on the retrieve path', lane: -1 },
      { k: 'fact',      label: 'gate:M3 → blocked',      sub: 'incident:2026-05-25 linked', lane: 1 },
      { k: 'milestone', label: 'M3 blocked',             sub: 'path C parked', lane: 0 },
    ],
    fields: [['session', 'b17c277d…'], ['passport', 'ce:8821fa0d:local'],
             ['execplan', 'chaincrux-cascade-route-integration'], ['note', 'review pass']] },
  { id: 'sess-trait', kind: 'session', district: 'sessions', pos: [4.5, -31.7],
    label: 'execplan:trait-expansion', sub: 'f3d09a44 · idle 2h', status: 'idle',
    tools: [['Read', 6], ['Bash', 2]],
    fields: [['session', 'f3d09a44…'], ['passport', 'ce:4e6c4e2a:local'],
             ['execplan', 'corecrux-trait-expansion-global-default-on']] },

  /* ── ring 3: execplans — half-circle fed by their sessions ──────────── */
  { id: 'ep-plancrux', kind: 'execplan', district: 'work', pos: [-50.8, -23.7],
    label: 'plancrux-retirement', sub: 'risk medium', state: 'in_progress', status: 'run', tok: { in: 64, out: 9 },
    milestones: [
      { m: 'M1 · feature lens', state: 'done', tok: 31 },
      { m: 'M2 · proxy cutover', state: 'in_progress', tok: 24 },
      { m: 'M3 · retire API',   state: 'planned', tok: 9 },
    ],
    fields: [['state', 'in_progress']] },
  { id: 'ep-chaincrux', kind: 'execplan', district: 'work', pos: [-40.3, -38.9],
    label: 'chaincrux-cascade-route', sub: 'risk medium · M3 blocked', state: 'blocked', status: 'err', tok: { in: 110, out: 14 },
    milestones: [
      { m: 'M1 · route shim',    state: 'done', tok: 36 },
      { m: 'M2 · cascade gate',  state: 'done', tok: 42 },
      { m: 'M3 · wire decide()', state: 'blocked', tok: 24 },
      { m: 'M4 · A/B Q500',      state: 'planned', tok: 8 },
    ],
    fields: [['state', 'blocked'], ['blocker', 'decide() never invoked'], ['see', 'incident:2026-05-25']] },
  { id: 'ep-agentux', kind: 'execplan', district: 'work', pos: [-17.3, -53.3],
    label: 'agent-ux-best-in-class', sub: 'risk medium · M4 in flight', state: 'in_progress', status: 'run', tok: { in: 271, out: 38 },
    milestones: [
      { m: 'M1 · aggregator',       state: 'done', tok: 58 },
      { m: 'M2 · work API',         state: 'done', tok: 71 },
      { m: 'M3 · header decode',    state: 'done', tok: 49 },
      { m: 'M4 · reconciler',       state: 'in_progress', tok: 84 },
      { m: 'M5 · wizard guardrails', state: 'planned', tok: 9 },
    ],
    fields: [['state', 'in_progress'], ['risk_class', 'medium'], ['milestones', '5'],
             ['tests', '1118/1118 corecruxd green'], ['updated', '2026-06-09']],
    doc: '# agent-ux-best-in-class-master\n\nWork aggregator, /v1/work source merge, MCP\nloopback auth, SPA chip group, reconciler, wizard\nguardrails. M4 blocked on 4 projection-diff tests;\nfix is a stable sort by updated_at before the\nkanban merge.' },
  { id: 'ep-trait', kind: 'execplan', district: 'work', pos: [11.6, -54.8],
    label: 'trait-expansion-default-on', sub: 'risk medium · pilot green', state: 'in_progress', status: 'run', tok: { in: 95, out: 12 },
    milestones: [
      { m: 'M1 · overlay persist',   state: 'done', tok: 29 },
      { m: 'M2 · 50-tenant pilot',   state: 'done', tok: 51 },
      { m: 'M3 · global default-on', state: 'in_progress', tok: 15 },
    ],
    fields: [['state', 'in_progress'], ['pilot', '+2 R@5 · zero regressions']] },
  { id: 'ep-gemma', kind: 'execplan', district: 'work', pos: [32.1, -45.9],
    label: 'cheap-tier-llm-ab', sub: 'done · gemma wins', state: 'done', status: 'ok', tok: { in: 41, out: 6 },
    milestones: [{ m: 'M1 · harness', state: 'done', tok: 26 }, { m: 'M2 · A/B run', state: 'done', tok: 15 }],
    fields: [['state', 'done'], ['result', 'gemma 100% vs 50% schema']] },
  { id: 'ep-verbatim', kind: 'execplan', district: 'work', pos: [42.9, -36.0],
    label: 'verbatim-indexing-closeout', sub: 'done', state: 'done', status: 'ok', tok: { in: 18, out: 3 },
    milestones: [{ m: 'M1 · pointers', state: 'done', tok: 11 }, { m: 'M2 · closeout', state: 'done', tok: 7 }],
    fields: [['state', 'done']] },
  { id: 'ep-cruxengine', kind: 'execplan', district: 'work', pos: [49.9, -25.4],
    label: 'cruxengine-carry-all', sub: 'risk low · queued', state: 'planned', status: 'idle', tok: { in: 5, out: 1 },
    milestones: [{ m: 'M1 · flag-off merge', state: 'planned', tok: 5 }],
    fields: [['state', 'planned'], ['risk_class', 'low']] },

  /* ── ring 4: memory — execplan-linked facts sit outward of their plan ── */
  { id: 'f-gate-au4', kind: 'fact', district: 'memory', pos: [-33.8, -72.5],
    label: 'gate:M4', sub: 'execplan:agent-ux · in_progress', status: 'run',
    fields: [['entity', 'execplan:agent-ux-best-in-class-master'], ['key', 'gate:M4'],
             ['tests_passing', 'false · 4 failing'], ['commit_sha', '—']],
    payload: '{ "key":"gate:M4", "value":{ "status":"in_progress",\n  "commit_sha":null, "tests_passing":false, "failing":4 } }' },
  { id: 'f-gate-au3', kind: 'fact', district: 'memory', pos: [-24.7, -76.1],
    label: 'gate:M3', sub: 'execplan:agent-ux · done', status: 'ok',
    fields: [['key', 'gate:M3'], ['commit_sha', 'c4e8810'], ['tests_passing', 'true']] },
  { id: 'f-dec-sort', kind: 'fact', district: 'memory', pos: [-15.3, -78.5],
    label: 'decision:reconciler-sort', sub: 'execplan:agent-ux', status: 'ok',
    fields: [['key', 'decision:reconciler-sort'], ['commit_sha', '9b21d04'],
             ['choice', 'stable sort by updated_at']] },
  { id: 'f-gate-cc3', kind: 'fact', district: 'memory', pos: [-57.5, -55.6],
    label: 'gate:M3 · blocked', sub: 'execplan:chaincrux', status: 'err',
    fields: [['key', 'gate:M3'], ['status', 'blocked'], ['reason', 'decide() never invoked']] },
  { id: 'f-bench', kind: 'fact', district: 'memory', pos: [45.9, -65.5],
    label: 'bench:lme-s-q500', sub: 'corpus LME-S · 91.7%', status: 'ok',
    fields: [['metric', 'gated accuracy'], ['value', '91.7%'], ['corpus', 'LME-S'],
             ['lane_flags', 'LME_INJECT_FACTS+DOSSIERS'], ['commit_sha', '5e72c3c'], ['run_id', 'q500-0530']] },
  /* orphan facts (no execplan gate) live IN FRONT with the live plane */
  { id: 'f-incident', kind: 'fact', district: 'memory', pos: [42.4, 67.8],
    label: 'incident:2026-06-11', sub: 'vault tokens expired', status: 'err',
    fields: [['symptom', 'estate tokens expired'], ['cause', 'TTL lapse'],
             ['fix_sha', 'pending'], ['repro', 'vault login → mint']] },
  { id: 'f-design', kind: 'fact', district: 'memory', pos: [57.5, 55.6],
    label: 'design:coord-plane', sub: 'links .agent/ design doc', status: 'idle',
    fields: [['entity', 'design:coord-plane'], ['ref', 'PlanCrux/.agent/execplans/…design.md']] },

  /* ── front-left: the CROWN receipt chain arcs seq 1→5 ───────────────── */
  { id: 'rc-1', kind: 'receipt', district: 'receipts', pos: [-67.0, 11.8],
    label: 'crn_8f21', sub: 'seq 1 · diagnose M4 · verified', status: 'ok',
    fields: [['receipt', 'crn_8f21…'], ['actor', 'ce:4e6c4e2a:local'], ['risk', 'low'],
             ['signature_valid', 'true · Ed25519'], ['kid', 'daemon-root'], ['payload_hash_ok', 'true']],
    doc: 'CROWN RECEIPT crn_8f21…\n\nGET /v1/receipts/{id}            body + hashes\nGET /v1/receipts/{id}/signature  sig event\nGET /v1/receipts/{id}/verification PASS\n\nAnyone with receipts:read can replay the chain\noffline. Tampering flips verification to FAIL\nwith an error_code.' },
  { id: 'rc-2', kind: 'receipt', district: 'receipts', pos: [-63.9, 23.3],
    label: 'crn_b033', sub: 'seq 2 · write reconciler · verified', status: 'ok',
    fields: [['receipt', 'crn_b033…'], ['mutations', '2'], ['risk', 'medium'], ['signature_valid', 'true']] },
  { id: 'rc-3', kind: 'receipt', district: 'receipts', pos: [-58.9, 34.0],
    label: 'crn_c7a9', sub: 'seq 3 · cargo test exit 101', status: 'ok',
    fields: [['receipt', 'crn_c7a9…'], ['exit', '101'], ['risk', 'low'], ['signature_valid', 'true']] },
  { id: 'rc-4', kind: 'receipt', district: 'receipts', pos: [-52.1, 43.7],
    label: 'crn_pc1', sub: 'punchcard acquire', status: 'ok',
    fields: [['receipt', 'crn_pc1…'], ['resource', 'file://…/reconcile.rs'], ['mode', 'modify']] },
  { id: 'rc-5', kind: 'receipt', district: 'receipts', pos: [-43.7, 52.1],
    label: 'crn_d4e2', sub: 'store_fact gate:M4', status: 'ok',
    fields: [['receipt', 'crn_d4e2…'], ['op', 'store_fact'], ['entity', 'execplan:agent-ux…']] },

  { id: 'rc-bench', kind: 'receipt', district: 'receipts', pos: [-34.0, 58.9],
    label: 'q efc3f7c2 · LME-S', sub: 'gated multicall · sealed T4 · 706s', status: 'ok',
    fields: [['qid', 'efc3f7c2'], ['corpus', 'LME-S'], ['question', 'How much earlier do I wake up on Fridays vs other weekdays?'],
             ['gold', '30 minutes'], ['final', '"30" · accepted'], ['retrieves', '11'], ['submits', '5 (4 gate-rejected)'],
             ['sealed', 'tier 4 · wall 706s'], ['trace', 'AuditCrux …/q500-baseline-post-a1a2-20260524/traces/efc3f7c2.json']],
    doc: 'END-TO-END GATED WORK-SESSION (real trace)\n\nA multi-session LME-S question driven by the\ngated multicall loop: the agent retrieves until the\nseal gate (lme500-aggregation@v1) accepts. Four\nsubmits were BLOCKED (saturation_not_met,\ncount≠enumerated) before tier-4 sealed the gold\nanswer. Click to replay the whole line of events.',
    timeline: [
      { k: 'boot',      label: 'work-session 399af43b',          sub: 'tenant __longmemeval_s_efc3f7c2 · gated', lane: 0 },
      { k: 'reasoning', label: 'Q: Friday wake-up vs weekdays?',  sub: 'multi-session · NOW 2023-05-30', lane: -1 },
      { k: 'retrieve',  label: 'retrieve ×5 · verbatim',          sub: 'question phrasing · k 8 → 16', lane: 0 },
      { k: 'chunks',    label: 'ccxi:0:226200 · 232465',          sub: '2023-05-29 + 05-24 · morning routine', lane: 1 },
      { k: 'reasoning', label: 'enumerate Fri 6:00 vs 6:30',      sub: 'gpt-5.5 · refined_state grows', lane: -1 },
      { k: 'retrieve',  label: '“Friday wake time not regular…”', sub: 'rephrase #1 · 16 chunks', lane: 0 },
      { k: 'retrieve',  label: '“usual weekday vs Friday start”', sub: 'rephrases #2–4 · 16 chunks each', lane: 0 },
      { k: 'submit',    label: 'submit “30 minutes earlier”',     sub: 'REJECTED · saturation_not_met', lane: 0 },
      { k: 'gate',      label: 'count ≠ enumerated(2)',           sub: 'gate lme500-aggregation@v1', lane: 1 },
      { k: 'reasoning', label: 'gate-gaming: “minute 1…30”',      sub: '609 tok · enumerates 30 items', lane: -1 },
      { k: 'submit',    label: 'submit ×3 more',                  sub: 'REJECTED · + one infra error', lane: 0 },
      { k: 'milestone', label: 'escalation → tier 4',             sub: 'after 4 blocked submits', lane: 0 },
      { k: 'retrieve',  label: 'retrieve ×3 · T4',                sub: '“Friday 6 AM vs 6:30 AM” · k16', lane: 0 },
      { k: 'submit',    label: 'submit “30”',                     sub: 'integer matches enumeration', lane: 0 },
      { k: 'seal',      label: 'SEALED · gold ✓',                 sub: 'tier 4 · 927 tok out · 706s wall', lane: 0 },
    ] },

  /* ── front: the coordination plane ──────────────────────────────────── */
  { id: 'co-1', kind: 'coord', district: 'coord', pos: [-1.5, 44.0],
    label: 'fa0a2f95 · claude-work', sub: 'presence M5 · seen 12s ago', status: 'run',
    fields: [['execplan', 'crux-agent-presence-coordination'], ['milestone', 'M5'],
             ['paths', 'crates/corecruxd/src'], ['holds', 'tree://crates/corecruxd']] },
  { id: 'co-2', kind: 'coord', district: 'coord', pos: [-19.3, 39.5],
    label: 'b17c277d · claude-research', sub: 'review pass · seen 40s ago', status: 'run',
    fields: [['note', 'review pass'], ['paths', 'crates/corecruxd/src/coord.rs']] },
  { id: 'co-overlap', kind: 'overlap', district: 'coord', pos: [-10.6, 42.7],
    label: 'overlap · intent_path', sub: 'advisory — coordinate, not a lock', status: 'err',
    fields: [['kind', 'intent_path'], ['sessions', 'fa0a2f95 × b17c277d'],
             ['advisory', 'coordinate via work comments']],
    doc: 'OVERLAP WARNING\n\nTwo live sessions staked overlapping paths\n(component-aware containment, the punchcard rule).\nAdvisory by design: a crashed session must never\ndeadlock its peers.' },
  { id: 'pc-file', kind: 'punchcard', district: 'coord', pos: [7.6, 43.3],
    label: 'file://…/reconcile.rs', sub: 'held · modify · TTL 14:24Z', status: 'run',
    fields: [['holder', 'ce:4e6c4e2a:local'], ['mode', 'modify'], ['expires', '14:24Z'],
             ['enforce', 'PreToolUse deny']] },
  { id: 'pc-svc', kind: 'punchcard', district: 'coord', pos: [-27.1, 34.7],
    label: 'service://corecruxd@gpu-1', sub: 'held · deploy lease', status: 'run',
    fields: [['holder', 'ce:0c4419ab:remote'], ['mode', 'deploy'], ['preflight', 'cargo-deploy aborts if held']] },
];

/* rel kinds → palette key (see world.js EDGE colors) */
export const LINKS = [
  /* identity plane — passports wire straight into the core */
  { from: 'pp-main',   to: 'daemon',        rel: 'binds' },
  { from: 'pp-sonnet', to: 'daemon',        rel: 'binds' },
  { from: 'pp-ops',    to: 'daemon',        rel: 'binds' },
  { from: 'pp-main',   to: 'sess-agentux',  rel: 'binds' },
  { from: 'pp-main',   to: 'sess-trait',    rel: 'binds' },
  { from: 'pp-sonnet', to: 'sess-chaincrux', rel: 'binds' },
  /* work plane */
  { from: 'sess-agentux',   to: 'ep-agentux',   rel: 'drives' },
  { from: 'sess-chaincrux', to: 'ep-chaincrux', rel: 'drives' },
  { from: 'sess-trait',     to: 'ep-trait',     rel: 'drives' },
  /* gates */
  { from: 'ep-agentux',   to: 'f-gate-au4', rel: 'gates' },
  { from: 'ep-agentux',   to: 'f-gate-au3', rel: 'gates' },
  { from: 'ep-agentux',   to: 'f-dec-sort', rel: 'gates' },
  { from: 'ep-chaincrux', to: 'f-gate-cc3', rel: 'gates' },
  { from: 'ep-gemma',     to: 'f-bench',    rel: 'gates' },
  /* receipts */
  { from: 'sess-agentux', to: 'rc-1', rel: 'seals' },
  { from: 'sess-agentux', to: 'rc-2', rel: 'seals' },
  { from: 'sess-agentux', to: 'rc-3', rel: 'seals' },
  { from: 'pc-file',      to: 'rc-4', rel: 'seals' },
  { from: 'f-gate-au4',   to: 'rc-5', rel: 'seals' },
  { from: 'rc-1', to: 'rc-2', rel: 'chain' },
  { from: 'rc-2', to: 'rc-3', rel: 'chain' },
  { from: 'rc-3', to: 'rc-4', rel: 'chain' },
  { from: 'rc-4', to: 'rc-5', rel: 'chain' },
  { from: 'rc-5', to: 'rc-bench', rel: 'chain' },
  /* coordination */
  { from: 'sess-agentux',   to: 'co-1', rel: 'coord' },
  { from: 'sess-chaincrux', to: 'co-2', rel: 'coord' },
  { from: 'co-1', to: 'co-overlap', rel: 'coord' },
  { from: 'co-2', to: 'co-overlap', rel: 'coord' },
  { from: 'co-1', to: 'pc-file',    rel: 'coord' },
  { from: 'pp-ops', to: 'pc-svc',   rel: 'coord' },
  /* handoff */
  { from: 'sess-agentux', to: 'sess-chaincrux', rel: 'handoff' },
];

/* ── scrollytelling chapters (standalone page) ──────────────────────────── */
export const CHAPTERS = [
  { num: '01', title: 'A session boots',
    body: 'cuecrux_session binds a passport. Capabilities load as a ladder; everything the agent does from here is attributed — identity is the first ring out from the core.',
    cam: { pos: [0, 30, 40], look: [0, 0, -19] },
    focus: ['pp-main', 'pp-sonnet', 'pp-ops', 'daemon', 'sess-agentux'],
    beams: [['pp-main', 'daemon'], ['pp-sonnet', 'daemon'], ['pp-ops', 'daemon'], ['pp-main', 'sess-agentux']] },
  { num: '02', title: 'Work is ExecPlans',
    body: 'Sessions feed a half-circle of execplans behind the core. Each block is a plan; each slab a milestone, tinted by its gate state.',
    cam: { pos: [0, 44, 24], look: [0, 0, -53] },
    focus: ['ep-agentux', 'ep-chaincrux', 'ep-trait', 'ep-gemma', 'ep-plancrux'],
    beams: [['sess-agentux', 'ep-agentux'], ['sess-chaincrux', 'ep-chaincrux']] },
  { num: '03', title: 'Milestones gate on facts',
    body: 'Every gate stores a fact on the outer ring, on its plan’s bearing — status, commit_sha, tests_passing — so the audit trail replays.',
    cam: { pos: [-6, 52, 12], look: [-12, 0, -75] },
    focus: ['f-gate-au4', 'f-gate-au3', 'f-dec-sort', 'f-gate-cc3', 'f-bench', 'ep-agentux'],
    beams: [['ep-agentux', 'f-gate-au4'], ['ep-chaincrux', 'f-gate-cc3']] },
  { num: '04', title: 'Every mutation seals a receipt',
    body: 'CROWN receipts arc in front of the core, seq 1→5: Ed25519-signed, append-only, replayable offline. The chain is the proof.',
    cam: { pos: [-52, 30, 76], look: [-59, 0, 34] },
    focus: ['rc-1', 'rc-2', 'rc-3', 'rc-4', 'rc-5'],
    beams: [['sess-agentux', 'rc-2'], ['f-gate-au4', 'rc-5'], ['rc-1', 'rc-2'], ['rc-2', 'rc-3'], ['rc-3', 'rc-4'], ['rc-4', 'rc-5']] },
  { num: '05', title: 'Sessions coordinate, not collide',
    body: 'The live board sits in front: presence × intents × punchcard leases assembled at read time. Overlaps are advisory — never a lock.',
    cam: { pos: [-6, 33, 92], look: [-10, 0, 44] },
    focus: ['co-1', 'co-2', 'co-overlap', 'pc-file', 'pc-svc'],
    beams: [['sess-agentux', 'co-1'], ['co-1', 'co-overlap'], ['co-2', 'co-overlap'], ['co-1', 'pc-file']] },
  { num: '06', title: 'The substrate remembers',
    body: 'One disc, every plane: identity, work, memory, proof, presence — radiating from the daemon. Click any node to expand its references.',
    cam: { pos: [0, 130, 98], look: [0, 0, -14] },
    focus: [],
    beams: [['pp-main', 'sess-agentux'], ['sess-agentux', 'ep-agentux'], ['ep-agentux', 'f-gate-au4'], ['f-gate-au4', 'rc-5'], ['sess-agentux', 'co-1']] },
];

/* hero (chapter 0) camera + final explore camera */
export const HERO_CAM    = { pos: [-16, 40, 100], look: [0, 0, 0] };
export const EXPLORE_CAM = { pos: [0, 130, 98], look: [0, 0, -14] };


/* ring platforms — real geometry; uniform dark grey for now. radii spaced
   so adjacent washers (band ±4.6) never intersect. solid = centre podium. */
export const RINGS = [
  { r: 9,  solid: true },   /* daemon podium */
  { r: 18 },                /* passports */
  { r: 32 },                /* sessions */
  { r: 44 },                /* coord (front) */
  { r: 56 },                /* execplans */
  { r: 68 },                /* receipts */
  { r: 80 },                /* memory */
];


export const KIND_LABELS = {
  daemon: 'daemon', passport: 'passport', session: 'session', execplan: 'execplan',
  fact: 'fact', receipt: 'receipt', coord: 'live session', overlap: 'overlap',
  punchcard: 'punchcard',
};
