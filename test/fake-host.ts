// A stand-in Mac for testing clients (the iOS app) against the real
// protocol and relay, with predictable content. Run: node test/fake-host.ts
//
// Starts a relay (or uses RELAY_URL), connects as a host (named FAKE_HOST_NAME, or "Test
// Mac"), and prints JSON lines:
//   {"event":"ready","relay":…,"link":…}       a pairing link (valid 10 minutes)
//   {"event":"paired","name":…}                a device paired
//   {"event":"session","name":…}               a device connected
//   {"event":"message","msg":{…}}              something a device sent
// Content: two streams; a Claude tab with a chat and a pending approval, a shell tab
// (with command blocks), and a web tab. Lines on stdin are JSON host messages to send to every device.
import { spawn, execFileSync, type ChildProcess } from 'node:child_process'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import { createInterface } from 'node:readline'
import { generateKeyPair, hostIdFor } from '../protocol/crypto.ts'
import { pairingLink, type ChatItem, type HostMessage } from '../protocol/messages.ts'
import { RelayHost, type PairedClient } from '../protocol/session.ts'

const NAME = process.env.FAKE_HOST_NAME || 'Test Mac'
const out = (o: object): void => void process.stdout.write(JSON.stringify(o) + '\n')

let relay: ChildProcess | undefined
async function startRelay(): Promise<string> {
  if (process.env.RELAY_URL) return process.env.RELAY_URL
  const port = 19000 + Math.floor(Math.random() * 1000)
  const dir = mkdtempSync(join(tmpdir(), 'fake-host-relay-'))
  execFileSync('go', ['build', '-o', join(dir, 'relay'), '.'], { cwd: join(import.meta.dirname, '..') })
  relay = spawn(join(dir, 'relay'), ['-addr', `127.0.0.1:${port}`, '-data', dir], { stdio: 'ignore' })
  const url = `http://127.0.0.1:${port}`
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fetch(`${url}/health`)).ok) return url
    } catch {}
    await new Promise((r) => setTimeout(r, 100))
  }
  throw new Error('relay did not start')
}

const CLAUDE = 11
const SHELL = 12
const WEB = 13
let nextId = 100
/** Uploads being received, by id; then what arrived whole (name, size). */
const uploads = new Map<string, Buffer[]>()
const uploaded = new Map<string, { name: string; size: number }>()
const IMAGE = /\.(png|jpe?g|gif|webp|heic)$/i

const state: HostMessage = {
  t: 'state',
  host: NAME,
  active: { stream: 'convoke', tab: 1 },
  streams: [
    {
      id: 'convoke',
      name: 'Convoke',
      tabs: [
        { id: 1, focused: CLAUDE, panes: [{ id: CLAUDE, kind: 'terminal', title: 'Fix the relay cache', cwd: '/Users/me/code/convoke', agent: 'claude', attention: { kind: 'approval', text: 'Needs approval' } }] },
        { id: 2, focused: SHELL, panes: [{ id: SHELL, kind: 'terminal', title: 'zsh', cwd: '/Users/me/code/convoke' }] },
        { id: 3, focused: WEB, panes: [{ id: WEB, kind: 'web', title: 'Example Domain', url: 'https://example.com/' }] }
      ]
    },
    // A tab split in two (side by side): each split closes on its own.
    { id: 'other', name: 'Other one', tabs: [{ id: 4, focused: 14, layout: { dir: 'row', ratio: 0.5, a: { pane: 14 }, b: { pane: 15 } }, panes: [
      { id: 14, kind: 'terminal', title: 'npm run dev', cwd: '/Users/me/code/site' },
      { id: 15, kind: 'terminal', title: 'tail -f server.log', cwd: '/Users/me/code/site' }
    ] }] }
  ]
}

const approvals: HostMessage = {
  t: 'approvals',
  items: [{ id: 'ap1', pane: CLAUDE, agent: 'claude', tool: 'Bash', summary: 'Run: npm test', detail: 'npm test', createdAt: Date.now() }]
}

const chat: ChatItem[] = [
  { id: 'u1', k: 'user', text: 'Why does the phone show the old web client after a deploy?' },
  { id: 't1', k: 'thinking', text: 'Probably caching: check the headers.', ms: 4200 },
  { id: 'tool1', k: 'tool', tool: 'Bash', title: 'Check caching headers', detail: 'curl -sD - https://relay.cnvk.si/web/src/app.js', status: 'ok', output: 'cache-control: max-age=14400' },
  {
    id: 'tool2',
    k: 'tool',
    tool: 'Edit',
    title: 'Edited build.ts',
    detail: '/Users/me/code/convoke/build.ts',
    status: 'ok',
    diff: [' const files = list(dist)', "-  writeFileSync(f, src)", "+  writeFileSync(f, versioned(src, v))"]
  },
  { id: 'a1', k: 'assistant', text: 'Cloudflare overrides the relay\'s **no-cache** for scripts:\n\n- `max-age=14400` on `app.js`\n- so phones keep the old client for 4 hours\n\nI version the asset URLs instead.' },
  { id: 'turn1', k: 'turn', ms: 47000 },
  { id: 'u2', k: 'user', text: 'Run the tests' },
  { id: 'tool3', k: 'tool', tool: 'Bash', title: 'Run the tests', detail: 'npm test', status: 'running' }
]

async function main(): Promise<void> {
  const url = await startRelay()
  const clients: PairedClient[] = []
  const key = await generateKeyPair()
  const host = new RelayHost({
    relay: url,
    // Key-bound, as a real Mac's: clients refuse a pairing link whose id the key doesn't derive.
    hostId: await hostIdFor(key.publicKey),
    hostSecret: 'fake-host-secret-'.padEnd(40, 'x'),
    hostName: NAME,
    key,
    clients: () => clients,
    onPaired: (c) => {
      clients.push(c)
      out({ event: 'paired', name: c.name })
      // Codes are one-time: offer the next device a fresh one.
      out({ event: 'ready', relay: url, link: pairingLink(host.newPairing(10 * 60_000)) })
    },
    onSession: (conn, client) => {
      if (!client) return
      out({ event: 'session', name: client.name })
      void host.send(conn, state)
      void host.send(conn, approvals)
    },
    onMessage: (conn, _client, msg) => {
      out({ event: 'message', msg })
      if (msg.t === 'subscribe' && msg.pane === CLAUDE) void host.send(conn, { t: 'chat', pane: CLAUDE, items: chat, reset: true, title: 'Fix the relay cache', mode: 'default', working: true,
          model: 'claude-opus-5-5', context: { used: 124_000, limit: 200_000 },
          models: [{ label: 'Opus', command: '/model opus' }, { label: 'Sonnet', command: '/model sonnet' }, { label: 'Haiku', command: '/model haiku' }] })
      if (msg.t === 'subscribe' && msg.pane === SHELL) {
        void host.send(conn, { t: 'screen', pane: SHELL, text: '➜  convoke git status\nOn branch main\nnothing to commit, working tree clean\n➜  convoke ', cols: 80, rows: 24 })
        void host.send(conn, { t: 'blocks', pane: SHELL, reset: true, items: [
          { id: 'b1', command: 'git status', startedAt: Date.now() - 60_000, running: false, exit: 0, ms: 140, output: 'On branch main\nnothing to commit, working tree clean' },
          { id: 'b2', command: 'npm test', startedAt: Date.now() - 30_000, running: false, exit: 1, ms: 8200, output: '✖ 1 failing\n  relay: queue budget' }
        ] })
      }
      // A command run from the shell view: it shows up as a block, as on a real Mac.
      if (msg.t === 'text' && msg.pane === SHELL && msg.submit && msg.text)
        void host.send(conn, { t: 'blocks', pane: SHELL, items: [{ id: `b${nextId++}`, command: msg.text, startedAt: Date.now(), running: false, exit: 0, ms: 12, output: `ran: ${msg.text}` }] })
      if (msg.t === 'ping') void host.send(conn, { t: 'pong' })
      // Layout from the device: change the state, broadcast it, answer with the ids.
      if (msg.t === 'layout') {
        const st = state as Extract<HostMessage, { t: 'state' }>
        let result: Record<string, unknown> = { error: 'unknown op' }
        if (msg.op === 'new-stream') {
          const id = `s${nextId++}`
          st.streams.push({ id, name: msg.name, tabs: [] })
          result = { stream: id }
        } else if (msg.op === 'new-tab') {
          const stream = st.streams.find((x) => x.id === msg.stream)
          if (stream) {
            const tab = nextId++
            const pane = nextId++
            stream.tabs.push({ id: tab, focused: pane, panes: [{ id: pane, kind: msg.url ? 'web' : 'terminal', title: msg.url ?? msg.run ?? 'zsh', ...(msg.url && { url: msg.url }) }] })
            result = { stream: stream.id, tab, pane }
          } else result = { error: 'no such stream' }
        } else if (msg.op === 'close-tab') {
          for (const x of st.streams) x.tabs = x.tabs.filter((t) => t.id !== msg.tab)
          result = {}
        } else if (msg.op === 'close-pane') {
          // One split: the tab keeps the rest (and goes with its last).
          for (const x of st.streams) {
            for (const t of x.tabs) t.panes = t.panes.filter((p) => p.id !== msg.pane)
            x.tabs = x.tabs.filter((t) => t.panes.length > 0)
            for (const t of x.tabs) if (t.panes.length === 1) {
              delete t.layout
              t.focused = t.panes[0].id
            }
          }
          result = {}
        }
        void host.send('all', st).then(() => host.send(conn, { t: 'result', rid: msg.rid, ...result } as HostMessage))
      }
      // A file in chunks: reported whole (with its hash, to check against what was sent).
      if (msg.t === 'upload') {
        const parts = uploads.get(msg.id) ?? []
        parts[msg.seq] = Buffer.from(msg.data, 'base64')
        uploads.set(msg.id, parts)
        if (msg.last) {
          const data = Buffer.concat(parts)
          uploads.delete(msg.id)
          const ok = data.length === msg.size
          if (ok) uploaded.set(msg.id, { name: msg.name, size: data.length })
          out({ event: 'uploaded', id: msg.id, name: msg.name, size: data.length, sha256: createHash('sha256').update(data).digest('hex') })
          void host.send(conn, { t: 'uploaded', id: msg.id, ...(!ok && { error: 'size mismatch' }) })
        }
      }
      // A prompt typed into the agent shows up in its transcript a moment later, as with a
      // real agent: images dropped with it as Claude records them ("[Image #1] text").
      if (msg.t === 'text' && msg.submit && msg.pane === CLAUDE) {
        const images = (msg.files ?? []).filter((id) => IMAGE.test(uploaded.get(id)?.name ?? '')).length
        const text = [...Array.from({ length: images }, (_, i) => `[Image #${i + 1}]`), msg.text].filter(Boolean).join(' ')
        setTimeout(() => void host.send('all', { t: 'chat', pane: CLAUDE, items: [{ id: `u-${Date.now()}`, k: 'user', text, ...(images && { images }) }] }), 6000)
      }
    },
    onStatus: (s, detail) => out({ event: 'status', status: s, detail })
  })
  host.start()
  for (let i = 0; i < 100 && !host.connected; i++) await new Promise((r) => setTimeout(r, 50))
  out({ event: 'ready', relay: url, link: pairingLink(host.newPairing(10 * 60_000)) })
  createInterface({ input: process.stdin }).on('line', (line) => {
    try {
      void host.send('all', JSON.parse(line))
    } catch {}
  })
  const quit = (): void => {
    host.stop()
    relay?.kill()
    process.exit(0)
  }
  process.on('SIGTERM', quit)
  process.on('SIGINT', quit)
  process.stdin.on('end', quit)
}

void main()
