import { expect, mock, test } from 'claude-code/testing'
import type { On } from 'claude-code'

// Run with `claude plugin test crates/crux-config-wizard/assets/mods/crux-desktop`.
// Not shipped: `mods install` writes only the files `mods_install::FILES` lists.

// What auto mode answered a background `$.mcp.call` with on 2026-11-10.
const refusal = (server: string) =>
  `crux-desktop: $.mcp.call(${server}, sync_status) refused: The server-side auto mode classifier gave no ` +
  `verdict for mcp__${server.replace(/[^A-Za-z0-9_-]/g, '_')}__sync_status: the request that produced this ` +
  'action did not ask for it'

const TOOLS = ['sync_status', 'get_session', 'get_bootstrap', 'save_session']

const STARTUP_TOTAL_MS = 1500 + 5000 + 15000 + 45000

type Answer = { content: { type: 'text'; text: string }[]; isError: boolean }

const answer = (text: string, isError = false): Answer => ({ content: [{ type: 'text', text }], isError })
const missing = (server: string) =>
  answer(`no tool "sync_status" on a server named "${server}"; servers with tools: none`, true)

// Stands for the engine beneath the mod: keeps each status line and the server
// of every call that reached the daemon's servers.
function world(on: On, daemon: (server: string) => Answer) {
  const seen = { status: [] as (string | undefined)[], servers: [] as string[] }
  on('command.register', () => ({ value: { command: 'crux' } }))
  on('session.start', (_, e) => ({ cwd: e.cwd }))
  on('ui.status', (_, e) => {
    seen.status.push(e.text)
    return { value: undefined }
  })
  on('mcp.call', (_, e) => {
    seen.servers.push(e.server)
    return { value: daemon(e.server) }
  })
  return seen
}

// The engine stamps `origin` and `presentation` on the run itself.
const STATUS = { command: 'crux', args: 'status' }

test('a refused call reads as blocked, names the rules, and is not retried on a timer', async ($, on) => {
  const clock = mock.clock(on)
  // No `server` option: the mod tries "crux", then "Crux Daemon".
  const seen = world(on, server => (server === 'Crux Daemon' ? answer(refusal(server), true) : missing(server)))

  await $.session.start({ cwd: '/', surface: 'desktop', isInteractive: true })
  // Nothing is asked of the daemon at start: no MCP server has connected yet.
  expect(seen.servers.length).toBe(0)
  expect(seen.status.at(-1)).toBe('Crux … connecting')

  await clock.advance(1500)
  expect(seen.servers).toEqual(['crux', 'Crux Daemon'])
  expect(seen.status.at(-1)).toBe('Crux ○ blocked by permissions')

  // Neither the startup back-off nor the five-minute check asks again.
  await clock.advance(STARTUP_TOTAL_MS + 11 * 60 * 1000)
  expect(seen.servers.length).toBe(2)

  const said = String((await $.command.run(STATUS as Parameters<typeof $.command.run>[0]))?.text ?? '')
  expect(said.startsWith('Crux blocked:')).toBe(true)
  for (const tool of TOOLS) expect(said.includes(`mcp__Crux_Daemon__${tool}`)).toBe(true)
  expect(said.includes('permissions.allow')).toBe(true)
  expect(said.includes('~/.claude/settings.json')).toBe(true)
})

test(
  'with the installer’s server option, the rules name that server and no other is tried',
  { options: { server: 'crux' } },
  async ($, on) => {
    const clock = mock.clock(on)
    const seen = world(on, server => answer(refusal(server), true))

    await $.session.start({ cwd: '/', surface: 'desktop', isInteractive: true })
    await clock.advance(1500)
    expect(seen.servers).toEqual(['crux'])
    expect(seen.status.at(-1)).toBe('Crux ○ blocked by permissions')

    const said = String((await $.command.run(STATUS as Parameters<typeof $.command.run>[0]))?.text ?? '')
    for (const tool of TOOLS) expect(said.includes(`mcp__crux__${tool}`)).toBe(true)
    expect(said.includes('Crux_Daemon')).toBe(false)
    expect(seen.servers.every(s => s === 'crux')).toBe(true)
  },
)

test('once the rules are added, the next look connects', async ($, on) => {
  const clock = mock.clock(on)
  let isAllowed = false
  const seen = world(on, server =>
    server !== 'Crux Daemon'
      ? missing(server)
      : isAllowed
        ? answer(JSON.stringify({ local_fact_count: 20672, mode: 'local_only' }))
        : answer(refusal(server), true),
  )

  await $.session.start({ cwd: '/', surface: 'desktop', isInteractive: true })
  await clock.advance(1500)
  expect(seen.status.at(-1)).toBe('Crux ○ blocked by permissions')

  isAllowed = true
  const said = String((await $.command.run(STATUS as Parameters<typeof $.command.run>[0]))?.text ?? '')
  expect(said.startsWith('Crux connected via "Crux Daemon"')).toBe(true)
  expect(seen.status.at(-1)).toBe('Crux ● · 20,672 facts')
})

test('a daemon that connects after startup is picked up without showing offline', async ($, on) => {
  const clock = mock.clock(on)
  let isUp = false
  const seen = world(on, server =>
    isUp && server === 'Crux Daemon'
      ? answer(JSON.stringify({ local_fact_count: 20672, mode: 'local_only' }))
      : missing(server),
  )

  await $.session.start({ cwd: '/', surface: 'desktop', isInteractive: true })
  await clock.advance(1500)
  expect(seen.servers.length).toBe(2)
  expect(seen.status.at(-1)).toBe('Crux … connecting')

  isUp = true
  await clock.advance(5000)
  expect(seen.status.at(-1)).toBe('Crux ● · 20,672 facts')
  expect(seen.status.includes('Crux ○ offline')).toBe(false)

  // Connected: the startup back-off stops.
  const asked = seen.servers.length
  await clock.advance(15000 + 45000)
  expect(seen.servers.length).toBe(asked)
})

test('a daemon that never answers reads offline only after the last startup attempt', async ($, on) => {
  const clock = mock.clock(on)
  const seen = world(on, missing)

  await $.session.start({ cwd: '/', surface: 'desktop', isInteractive: true })
  await clock.advance(1500 + 5000 + 15000)
  expect(seen.status.includes('Crux ○ offline')).toBe(false)
  expect(seen.status.at(-1)).toBe('Crux … connecting')

  await clock.advance(45000)
  expect(seen.status.at(-1)).toBe('Crux ○ offline')
})
