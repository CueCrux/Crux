import { atom, read, update } from 'claude-code'
import type { EngineInterface, McpToolResult, Register } from 'claude-code'

import type { CruxCall, CruxHealth, CruxSave } from '../types'

// Installed and configured by `corecruxctl mods install` (crux-config-wizard
// `mods_install`). With this mod installed, it owns session continuity: the
// classic SessionStart banner and PreCompact save hooks are not wired.

// MCP server names the Crux daemon is registered under when the installer did
// not name one: the CLI's `crux` entry and the Claude Desktop extension (.mcpb).
const FALLBACK_SERVERS = ['crux', 'Crux Daemon']
const PANE = 'crux'
const HEALTH_EVERY_MS = 5 * 60 * 1000
// Bounds on daemon work that sits in front of the user: the continuity block
// delays the first prompt, and session.end has one short budget for every hook.
const CONTINUITY_TIMEOUT_MS = 4000
const END_SAVE_MARGIN_MS = 150

const health = atom({ plugin: 'crux-desktop', key: 'health' } as const, null)
const calls = atom({ plugin: 'crux-desktop', key: 'calls' } as const, [])
const lastSave = atom({ plugin: 'crux-desktop', key: 'lastSave' } as const, null)
const hasContinuity = atom({ plugin: 'crux-desktop', key: 'hasContinuity' } as const, false)

const toolPrefix = (server: string) => `mcp__${server.replace(/[^A-Za-z0-9_-]/g, '_')}__`

const textOf = (r: McpToolResult) =>
  r.content
    .map(b => (b.type === 'text' && 'text' in b ? String(b.text) : ''))
    .join('\n')

const jsonOf = (r: McpToolResult): Record<string, unknown> | null => {
  try {
    return JSON.parse(textOf(r))
  } catch {
    return null
  }
}

const clip = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s)

const errorText = (err: unknown) => clip(err instanceof Error ? err.message : String(err), 200)

// Module variables reset on hot reload; the server is re-resolved on demand.
// `candidates` is fixed at register time from the plugin's `server` option: a
// configured name is the only one tried, so a session never silently falls
// over to a different daemon (a hosted `crux` entry shadowing the local one).
let candidates: string[] = FALLBACK_SERVERS
let server: string | null = null

const isCruxTool = (tool: string) => candidates.some(s => tool.startsWith(toolPrefix(s)))

// Resolves to `undefined` if `work` has not settled within `ms`.
async function within<T>($: EngineInterface, ms: number, work: Promise<T>): Promise<T | undefined> {
  return Promise.race([work, $.clock.sleep(Math.max(0, ms)).then(() => undefined)])
}

async function call($: EngineInterface, tool: string, args?: Record<string, unknown>) {
  if (server === null) await probe($)
  if (server === null) throw new Error('no Crux MCP server connected')
  const r = await $.mcp.call(server, tool, args)
  if (r.isError) throw new Error(clip(textOf(r), 200))
  return r
}

// Finds the first connected Crux server and records its health.
async function probe($: EngineInterface): Promise<CruxHealth> {
  const checkedAt = await $.clock.now()
  const order = server ? [server, ...candidates.filter(c => c !== server)] : candidates
  let lastError = `no Crux MCP server connected (tried ${candidates.map(c => `"${c}"`).join(', ')})`
  for (const candidate of order) {
    try {
      const r = await $.mcp.call(candidate, 'sync_status')
      if (r.isError) {
        lastError = clip(textOf(r), 200)
        continue
      }
      const s = jsonOf(r) ?? {}
      server = candidate
      const h: CruxHealth = {
        server: candidate,
        facts: typeof s.local_fact_count === 'number' ? s.local_fact_count : null,
        mode: typeof s.mode === 'string' ? s.mode : null,
        checkedAt,
      }
      await update($, health, () => h)
      showStatus($, h, await read($, lastSave))
      return h
    } catch (err) {
      lastError = errorText(err)
    }
  }
  server = null
  const h: CruxHealth = { server: null, facts: null, mode: null, checkedAt, error: lastError }
  await update($, health, () => h)
  showStatus($, h, await read($, lastSave))
  return h
}

function showStatus($: EngineInterface, h: CruxHealth | null, s: CruxSave | null) {
  if (!h) return $.ui.status(undefined)
  if (!h.server) return $.ui.status('Crux ○ offline')
  const facts = h.facts === null ? '' : ` · ${h.facts.toLocaleString('en-GB')} facts`
  const saved = s === null ? '' : s.isOk ? ' · saved' : ' · save failed'
  $.ui.status(`Crux ●${facts}${saved}`)
}

// The session id the classic PreCompact hook used, so a machine moving from the
// hooks to this mod keeps one saved session per conversation, not two.
async function cruxSessionId($: EngineInterface) {
  return `hook:session:${await $.session.id()}`
}

// Saves this conversation's state under its own Crux session id.
async function save($: EngineInterface, reason: string): Promise<CruxSave> {
  const at = await $.clock.now()
  let result: CruxSave
  try {
    const [id, messages, repo, cwd, model, turns, recent] = await Promise.all([
      cruxSessionId($),
      $.session.messages(),
      $.session.repo(),
      $.session.root(),
      $.session.model(),
      $.session.turns(),
      read($, calls),
    ])
    const firstPrompt = messages.find(m => m.role === 'user' && m.text.trim())?.text ?? ''
    const lastAnswer = [...messages].reverse().find(m => m.role === 'assistant' && m.text.trim())?.text ?? ''
    const lastPrompt = [...messages].reverse().find(m => m.role === 'user' && m.text.trim())?.text ?? ''
    await call($, 'save_session', {
      session_id: id,
      state: {
        title: clip(firstPrompt.replace(/\s+/g, ' ').trim() || 'Claude Code session', 80),
        summary: clip(lastAnswer.trim(), 1200),
        last_prompt: clip(lastPrompt.trim(), 400),
        client: 'claude-code',
        surfaces: await $.session.surfaces(),
        cwd,
        repo: repo ? { ...repo } : null,
        model,
        turns,
        crux_tools_used: [...new Set(recent.map(c => c.tool))],
        saved_reason: reason,
      },
    })
    await $.store.set(`last-session:${cwd}`, id)
    result = { at, reason, isOk: true }
  } catch (err) {
    result = { at, reason, isOk: false, error: errorText(err) }
  }
  await update($, lastSave, () => result)
  showStatus($, await read($, health), result)
  return result
}

// The block the first user message carries: where Crux is, how this session is
// saved, the previous session in this directory, and the bootstrap patterns.
async function continuity($: EngineInterface): Promise<string | null> {
  const h = await probe($)
  if (!h.server) return null
  const [id, cwd] = await Promise.all([cruxSessionId($), $.session.root()])
  const lines = [
    `The Crux Daemon (persistent memory, facts, receipts) is connected as MCP server "${h.server}" (tools \`${toolPrefix(h.server)}*\`)${h.facts === null ? '' : `, holding ${h.facts} facts`}.`,
    `This conversation is saved to Crux automatically as session \`${id}\` after every turn and before compaction; do not call save_session for it yourself.`,
    'Before re-deriving project knowledge, query Crux (query, query_facts, memory_view). Store durable decisions, gotchas and conventions with store_fact.',
  ]

  const previous = (await $.store.get(`last-session:${cwd}`)) as string | undefined
  if (previous && previous !== id) {
    try {
      const s = jsonOf(await call($, 'get_session', { session_id: previous }))
      const state = (s?.state ?? s) as Record<string, unknown> | null
      if (state && (state.title || state.summary)) {
        lines.push(
          '',
          `Previous Claude Code session in this directory (\`${previous}\`):`,
          `- Title: ${String(state.title ?? '(untitled)')}`,
          `- Where it stood: ${clip(String(state.summary ?? ''), 1200)}`,
        )
      }
    } catch {
      // A missing or expired previous session is not worth surfacing.
    }
  }

  try {
    const b = textOf(await call($, 'get_bootstrap', { topic: 'patterns', token_budget: 500 })).trim()
    if (b) lines.push('', 'Crux bootstrap patterns:', clip(b, 4000))
  } catch {
    // Bootstrap is optional context.
  }
  return lines.join('\n')
}

export const register: Register = (on, options) => {
  const configured = typeof options.server === 'string' ? options.server.trim() : ''
  candidates = configured ? [configured] : FALLBACK_SERVERS

  on('session.start', async ($, e, next) => {
    await $.command.register({
      name: 'crux',
      description: 'Crux Daemon: open the pane, or `save` / `status`',
    })
    void probe($)
    $.clock.every(HEALTH_EVERY_MS, () => void probe($))
    return next(e)
  })

  on('prompt.context', async ($, e, next) => {
    try {
      const text = await within($, CONTINUITY_TIMEOUT_MS, continuity($))
      if (!text) return next(e)
      await update($, hasContinuity, () => true)
      return next({ ...e, blocks: [...e.blocks, { name: 'cruxContinuity', text }] })
    } catch {
      return next(e)
    }
  })

  on('turn.complete', async ($, e, next) => {
    const done = await next(e)
    if (e.agentId === undefined && e.reason !== 'aborted') void save($, 'turn')
    return done
  })

  on('session.compact', async ($, e, next) => {
    if (e.agentId === undefined) await save($, `compact:${e.trigger}`)
    return next(e)
  })

  // One short wall-clock budget covers every session.end hook and core, so the
  // final save gets what is left of it and the exit never waits on the daemon.
  on('session.end', async ($, e, next) => {
    const left = next.budget.remainingMs
    await (Number.isFinite(left) ? within($, left - END_SAVE_MARGIN_MS, save($, 'end')) : save($, 'end'))
    return next(e)
  })

  on('tool.call', async ($, e, next) => {
    if (!isCruxTool(e.tool)) return next(e)
    const ran = await next(e)
    const entry: CruxCall = {
      id: e.tool_use_id,
      tool: e.tool.slice(toolPrefix(candidates.find(s => e.tool.startsWith(toolPrefix(s))) ?? '').length),
      at: await $.clock.now(),
      isOk: ran.deny === undefined && ran.isError !== true,
    }
    await update($, calls, list => [...list, entry].slice(-100))
    return ran
  })

  on('command.run', { command: 'crux' }, async ($, e) => {
    const arg = e.args.trim()
    if (arg === 'save') {
      const s = await save($, 'command')
      return { text: s.isOk ? `Saved to Crux as ${await cruxSessionId($)}.` : `Crux save failed: ${s.error}` }
    }
    if (arg === 'status') {
      const h = await probe($)
      return {
        text: h.server
          ? `Crux connected via "${h.server}" · ${h.facts ?? '?'} facts · ${h.mode ?? 'unknown mode'}`
          : `Crux offline: ${h.error}`,
      }
    }
    const opened = await $.ui.open({ id: PANE, title: 'Crux' })
    void probe($)
    return { text: opened.isPlaced ? 'Crux pane opened.' : `Crux pane is waiting: ${opened.reason}` }
  })

  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    const { Box, Text, Button } = $.ui.resolve(e)
    const [h, list, s, ctx, id, now] = await Promise.all([
      read($, health),
      read($, calls),
      read($, lastSave),
      read($, hasContinuity),
      cruxSessionId($),
      $.clock.now(),
    ])
    const ago = (t: number) => {
      const m = Math.round((now - t) / 60000)
      return m < 1 ? 'just now' : `${m}m ago`
    }
    const room = Math.max(3, (e.viewport?.rows ?? 24) - 14)

    return (
      <Box flexDirection="column" gap={1}>
        <Box flexDirection="column">
          {h === null && <Text dimColor>Checking the daemon…</Text>}
          {h !== null && h.server !== null && (
            <Text>
              <Text color="green">●</Text> Connected via “{h.server}”
            </Text>
          )}
          {h !== null && h.server === null && (
            <Text>
              <Text color="red">○</Text> Offline: {h.error}
            </Text>
          )}
          {h?.server && (
            <Text dimColor>
              {h.facts?.toLocaleString('en-GB') ?? '?'} facts · {h.mode ?? '?'} · checked {ago(h.checkedAt)}
            </Text>
          )}
        </Box>

        <Box flexDirection="column">
          <Text bold>This session</Text>
          <Text dimColor>{id}</Text>
          <Text dimColor>Continuity {ctx ? 'loaded at start' : 'not loaded'}</Text>
          {s === null && <Text dimColor>Not saved yet</Text>}
          {s !== null && (
            <Text color={s.isOk ? undefined : 'red'} dimColor={s.isOk}>
              {s.isOk ? 'Saved' : 'Save failed'} {ago(s.at)} ({s.reason}){s.error ? `: ${s.error}` : ''}
            </Text>
          )}
        </Box>

        <Box flexDirection="column">
          <Text bold>Crux calls ({list.length})</Text>
          {list.length === 0 && <Text dimColor>None yet</Text>}
          {list.slice(-room).map(c => (
            <Text dimColor={c.isOk} color={c.isOk ? undefined : 'red'}>
              {c.isOk ? '✓' : '✗'} {c.tool} · {ago(c.at)}
            </Text>
          ))}
        </Box>

        <Box gap={1}>
          <Button key="save" label="Save now" hotkey="s" variant="primary" onPress={() => void save($, 'button')} />
          <Button key="refresh" label="Refresh" hotkey="r" onPress={() => void probe($)} />
        </Box>
      </Box>
    )
  })
}
