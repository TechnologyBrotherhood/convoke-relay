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
// (with command blocks), and a web tab that Claude is driving (live frames when watched
// `live`; each `web` action from the device brings a new frame). Lines on stdin are JSON host messages to send to every device.
import { spawn, execFileSync, type ChildProcess } from 'node:child_process'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import { createInterface } from 'node:readline'
import { generateKeyPair, hostIdFor } from '../protocol/crypto.ts'
import { pairingLink, type Approval, type ChatItem, type HostMessage } from '../protocol/messages.ts'
import { FAKE_FRAME } from './fake-frame.ts'
import { RelayHost, type PairedClient } from '../protocol/session.ts'

const NAME = process.env.FAKE_HOST_NAME || 'Test Mac'
const out = (o: object): void => void process.stdout.write(JSON.stringify(o) + '\n')

// FAKE_MOVE_RELAY=1: a Mac that has moved relays. It tells each device that connects to
// move to a second relay it starts, and is there too: {"event":"session","relay":"moved"}.

const relays: ChildProcess[] = []
async function startRelay(): Promise<string> {
  if (process.env.RELAY_URL) return process.env.RELAY_URL
  return spawnRelay()
}

async function spawnRelay(): Promise<string> {
  const port = 19000 + Math.floor(Math.random() * 1000)
  const dir = mkdtempSync(join(tmpdir(), 'fake-host-relay-'))
  execFileSync('go', ['build', '-o', join(dir, 'relay'), '.'], { cwd: join(import.meta.dirname, '..') })
  relays.push(spawn(join(dir, 'relay'), ['-addr', `127.0.0.1:${port}`, '-data', dir], { stdio: 'ignore' }))
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
/** An agent tab with a long conversation that takes a moment to arrive. */
const LONG = 16
const SHELL = 12
const WEB = 13
let nextId = 100
/** Panes whose agent a device started (a hand-off): their chats echo what is sent. */
const madeAgents = new Set<number>()
/** The fake web tab has its extension's popup open over it. */
let popupOpen = false
/** Uploads being received, by id; then what arrived whole (name, size). */
const uploads = new Map<string, Buffer[]>()
const uploaded = new Map<string, { name: string; size: number }>()
const IMAGE = /\.(png|jpe?g|gif|webp|heic)$/i

const state: HostMessage = {
  t: 'state',
  broadcast: 'Finish the open tickets',
  host: NAME,
  features: ['live-web'],
  active: { stream: 'convoke', tab: 1 },
  streams: [
    {
      id: 'convoke',
      name: 'Convoke',
      tabs: [
        { id: 1, focused: CLAUDE, panes: [{ id: CLAUDE, kind: 'terminal', title: 'Fix the relay cache', cwd: '/Users/me/code/convoke', agent: 'claude', attention: { kind: 'approval', text: 'Needs approval' } }] },
        { id: 2, focused: SHELL, panes: [{ id: SHELL, kind: 'terminal', title: 'zsh', cwd: '/Users/me/code/convoke', ports: [5173] }] },
        { id: 3, focused: WEB, panes: [{ id: WEB, kind: 'web', title: 'Example Domain', url: 'https://example.com/', driving: 'Claude' }] }
      ]
    },
    // A tab split in two (side by side): each split closes on its own.
    { id: 'other', name: 'Other one', tabs: [{ id: 4, focused: 14, layout: { dir: 'row', ratio: 0.5, a: { pane: 14 }, b: { pane: 15 } }, panes: [
      { id: 14, kind: 'terminal', title: 'npm run dev', cwd: '/Users/me/code/site' },
      { id: 15, kind: 'terminal', title: 'tail -f server.log', cwd: '/Users/me/code/site' }
    ] }, { id: 5, focused: LONG, panes: [{ id: LONG, kind: 'terminal', title: 'A long conversation', cwd: '/Users/me/code/site', agent: 'claude' }] }] }
  ]
}

const longChat: HostMessage = {
  t: 'chat',
  pane: LONG,
  reset: true,
  working: false,
  items: [
    ...Array.from({ length: 299 }, (_, i): ChatItem => ({
      id: `long-${i}`,
      k: 'assistant',
      text: `Message ${i}\n\n${'Some lines of a reply of varying length, to make the heights differ. '.repeat(1 + (i % 7))}`
    })),
    { id: 'long-last', k: 'assistant', text: 'The newest message' }
  ]
}

const approvals: Extract<HostMessage, { t: 'approvals' }> = {
  t: 'approvals',
  items: [{ id: 'ap1', pane: CLAUDE, agent: 'claude', tool: 'Bash', summary: 'Run: npm test', detail: 'npm test', createdAt: Date.now() }]
}

const CHART_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 100"><rect x="10" y="40" width="30" height="50" fill="#4a90d9"/><rect x="60" y="20" width="30" height="70" fill="#4a90d9"/><rect x="110" y="60" width="30" height="30" fill="#4a90d9"/><text x="10" y="15" font-size="12">Build times</text></svg>'
const MOCKUP_HTML = '<!doctype html><html><head><meta name="viewport" content="width=device-width"></head><body style="font-family:-apple-system"><h1 id="h">Sign in</h1><button onclick="document.getElementById(\'h\').textContent=\'Clicked\'">Continue</button><p id="net">checking network</p><img src="https://example.com/track.png"><script>fetch("https://example.com/leak").then(()=>{document.getElementById("net").textContent="network reached"}).catch(()=>{document.getElementById("net").textContent="network blocked"})</script></body></html>'

/** A program in the Claude tab asking for a secret (`convoke secret`), sent on "ask secret". */
const secretAsk: Approval = {
  id: 's1',
  pane: CLAUDE,
  agent: 'terminal',
  tool: 'secret',
  summary: 'Wants a secret: NPM_TOKEN',
  secret: { name: 'NPM_TOKEN', why: 'to publish the package' },
  createdAt: Date.now()
}

const question: Approval = {
  id: 'q1',
  pane: CLAUDE,
  agent: 'claude',
  tool: 'AskUserQuestion',
  summary: 'Which colour? (and 1 more)',
  createdAt: Date.now(),
  questions: [
    { question: 'Which colour?', header: 'Colour', options: [{ label: 'Red', description: 'Warm' }, { label: 'Blue', description: 'Cool' }] },
    { question: 'Which extras?', header: 'Extras', multiSelect: true, options: [{ label: 'Nuts' }, { label: 'Cream' }, { label: 'Syrup' }] }
  ]
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

/** The Claude tab's conversation, sent when a device opens it. */
const claudeChat: HostMessage = { t: 'chat', pane: CLAUDE, items: chat, reset: true, title: 'Fix the relay cache', mode: 'default', working: true,
          model: 'claude-opus-5-5', context: { used: 124_000, limit: 200_000 },
          models: [{ label: 'Opus', command: '/model opus' }, { label: 'Sonnet', command: '/model sonnet' }, { label: 'Haiku', command: '/model haiku' }] }

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
      if (moved) void host.send(conn, { t: 'relay-move', relay: moved.url })
    },
    onMessage: (conn, _client, msg) => {
      out({ event: 'message', msg })
      // FAKE_CHAT_FROM_STDIN: the Claude tab's chat comes from stdin instead (a real transcript replayed).
      if (msg.t === 'subscribe' && msg.pane === CLAUDE && !process.env.FAKE_CHAT_FROM_STDIN) void host.send(conn, claudeChat)
      // What the agent showed: a chart (an SVG). "show me" adds a page (HTML, which tries the network).
      if (msg.t === 'subscribe' && msg.pane === CLAUDE)
        void host.send(conn, { t: 'visuals', pane: CLAUDE, reset: true, items: [{ id: 'v1', title: 'Build times', type: 'svg', at: Date.now() - 60_000, data: CHART_SVG }] })
      if (msg.t === 'text' && msg.pane === CLAUDE && msg.text === 'show me')
        void host.send(conn, { t: 'visuals', pane: CLAUDE, items: [{ id: `v${nextId++}`, title: 'Mockup', type: 'html', at: Date.now(), data: MOCKUP_HTML }] })
      if (msg.t === 'subscribe' && msg.pane === LONG) setTimeout(() => void host.send(conn, longChat), 1500)
      // Sent to the long tab: the whole chat again, as after a reconnect.
      if (msg.t === 'text' && msg.pane === LONG && msg.text !== 'flap') void host.send(conn, longChat)
      // The agent's flag off for a moment, as when a session ends and the next registers.
      if (msg.t === 'text' && msg.pane === LONG && msg.text === 'flap') {
        const st = state as Extract<HostMessage, { t: 'state' }>
        const off = { ...st, streams: st.streams.map((x) => ({ ...x, tabs: x.tabs.map((t) => ({ ...t, panes: t.panes.map((p) => (p.id === LONG ? { ...p, agent: undefined } : p)) })) })) }
        void host.send(conn, off)
        setTimeout(() => void host.send(conn, state), 2500)
      }
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
      // A dev server on port 5173 (a page, and a script it loads by path); nothing elsewhere.
      if (msg.t === 'http') {
        const files: Record<string, [string, string]> = {
          '/': ['text/html', '<!doctype html><meta name="viewport" content="width=device-width"><h1 id="t">Dev server</h1><script src="/app.js"></script>'],
          '/app.js': ['text/javascript', 'document.getElementById("t").textContent = "Dev server: script loaded"']
        }
        const f = msg.port === 5173 ? files[msg.path.split('?')[0]] : undefined
        if (msg.port !== 5173) void host.send(conn, { t: 'http-res', id: msg.id, last: true, error: `Nothing is listening on port ${msg.port}.` })
        else if (!f) void host.send(conn, { t: 'http-res', id: msg.id, status: 404, headers: { 'content-type': 'text/plain' }, data: Buffer.from('not found').toString('base64'), last: true })
        else {
          // In two pieces, as a big answer comes.
          const body = Buffer.from(f[1])
          const half = Math.floor(body.length / 2)
          void host.send(conn, { t: 'http-res', id: msg.id, status: 200, headers: { 'content-type': f[0] }, data: body.subarray(0, half).toString('base64'), last: false })
          void host.send(conn, { t: 'http-res', id: msg.id, data: body.subarray(half).toString('base64'), last: true })
        }
      }
      // A message to an agent the device started: the chat shows it, as a real one's would.
      if (msg.t === 'text' && madeAgents.has(msg.pane) && msg.text)
        void host.send(conn, { t: 'chat', pane: msg.pane, items: [{ id: `u${nextId++}`, k: 'user', text: msg.text }] })
      // The web tab, as on the Mac: a frame on a live subscribe, and after each action.
      // Its extensions (a password manager), whose popup the device can open over the page:
      // frames of the popup (a `surface`) until it's closed.
      if (msg.t === 'subscribe' && msg.pane === WEB && msg.live) {
        popupOpen = false
        void host.send(conn, { t: 'web-extensions', pane: WEB, items: [{ id: 'nngceckbapebfimnlniiiahkandclblb', name: 'Bitwarden' }] })
      }
      if (msg.t === 'web' && msg.pane === WEB && msg.op === 'extension') popupOpen = true
      if (msg.t === 'web' && msg.pane === WEB && msg.op === 'close-surface') popupOpen = false
      if ((msg.t === 'subscribe' && msg.pane === WEB && msg.live) || (msg.t === 'web' && msg.pane === WEB))
        void host.send(conn, {
          t: 'frame', pane: WEB, seq: nextId++, data: FAKE_FRAME,
          ...(popupOpen ? { w: 380, h: 600, surface: { ext: 'nngceckbapebfimnlniiiahkandclblb', title: 'Bitwarden' } } : { w: 640, h: 400 })
        })
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
            stream.tabs.push({ id: tab, focused: pane, panes: [{ id: pane, kind: msg.url ? 'web' : 'terminal', title: msg.url ?? msg.run ?? 'zsh', ...(msg.url && { url: msg.url }), ...(msg.cwd && { cwd: msg.cwd }) }] })
            result = { stream: stream.id, tab, pane }
            // An agent started there (a hand-off): it says it's there a moment later, as a real one does.
            if (msg.run && ['claude', 'codex', 'omp'].includes(msg.run)) {
              const agent = msg.run
              setTimeout(() => {
                const p = st.streams.flatMap((x) => x.tabs).flatMap((t) => t.panes).find((x) => x.id === pane)
                if (p) p.agent = agent
                madeAgents.add(pane)
                void host.send(conn, state)
                void host.send(conn, { t: 'chat', pane, reset: true, items: [] })
              }, 800)
            }
          } else result = { error: 'no such stream' }
        } else if (msg.op === 'background') {
          const tab = st.streams.flatMap((x) => x.tabs).find((t) => t.id === msg.tab)
          if (tab) {
            if (msg.on) tab.background = true
            else delete tab.background
            result = {}
          } else result = { error: 'no such tab' }
        } else if (msg.op === 'settle' || msg.op === 'snooze') {
          const tab = st.streams.flatMap((x) => x.tabs).find((t) => t.id === msg.tab)
          if (tab) {
            if (msg.op === 'settle') {
              if (msg.on) tab.settled = true
              else delete tab.settled
            } else if (msg.until > Date.now()) tab.snoozedUntil = msg.until
            else delete tab.snoozedUntil
            if (msg.op === 'settle' && msg.on) for (const p of tab.panes) if (p.attention && p.attention.kind !== 'approval') delete p.attention
            result = {}
          } else result = { error: 'no such tab' }
        } else if (msg.op === 'mode') {
          // As a Claude session started without bypass would: it isn't one of the modes.
          if (msg.mode === 'bypassPermissions') result = { error: "Bypass permissions isn't available in this session." }
          else {
            void host.send(conn, { t: 'chat', pane: msg.pane, items: [], mode: msg.mode })
            result = {}
          }
        } else if (msg.op === 'start-agent') {
          // The shell becomes the agent's: it says so in the state.
          const pane = st.streams.flatMap((x) => x.tabs).flatMap((t) => t.panes).find((p) => p.id === msg.pane)
          if (pane) {
            pane.agent = msg.agent
            result = {}
          } else result = { error: 'no such pane' }
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
      if (msg.t === 'broadcast') void host.send(conn, { t: 'broadcasted', sent: 2, skipped: 1 })
      if (msg.t === 'usage') {
        const days = typeof msg.days === 'number' ? msg.days : 30
        const today = new Date().toISOString().slice(0, 10)
        void host.send(conn, {
          t: 'usage',
          report: {
            host: NAME,
            generatedAt: Date.now(),
            days,
            totals: { input: 42_000, output: 8_500, cacheRead: 310_000, cacheWrite: 24_000, turns: 19, costUsd: 1.84 },
            byAgent: {
              claude: { input: 28_000, output: 6_200, cacheRead: 250_000, cacheWrite: 24_000, turns: 13, costUsd: 1.52 },
              codex: { input: 14_000, output: 2_300, cacheRead: 60_000, cacheWrite: 0, turns: 6, costUsd: 0.32 }
            },
            byModel: [
              { agent: 'claude', model: 'claude-opus-5-5', input: 28_000, output: 6_200, cacheRead: 250_000, cacheWrite: 24_000, turns: 13, costUsd: 1.52 },
              { agent: 'codex', model: 'gpt-6.2-sol', input: 14_000, output: 2_300, cacheRead: 60_000, cacheWrite: 0, turns: 6, costUsd: 0.32 }
            ],
            byDay: [{ day: today, input: 42_000, output: 8_500, cacheRead: 310_000, cacheWrite: 24_000, turns: 19, costUsd: 1.84 }],
            limits: [{ agent: 'codex', plan: 'team', windows: [{ label: '7d', usedPercent: 18, resetsAt: Date.now() + 3 * 86_400_000 }], updatedAt: Date.now() }]
          }
        })
      }
      // Being told "ask me": the agent asks a question, until it's answered.
      if (msg.t === 'text' && msg.pane === CLAUDE && msg.text === 'ask me') void host.send(conn, { ...approvals, items: [...approvals.items, question] })
      if (msg.t === 'decide' && msg.id === question.id) void host.send(conn, approvals)
      if (msg.t === 'text' && msg.pane === CLAUDE && msg.text === 'ask secret') void host.send(conn, { ...approvals, items: [...approvals.items, secretAsk] })
      if (msg.t === 'decide' && msg.id === secretAsk.id) void host.send(conn, approvals)
      // Being told "fill context": nearly full (a phone then offers Compact, Recent, Reset).
      if (msg.t === 'text' && msg.pane === CLAUDE && msg.text === 'fill context')
        void host.send(conn, { t: 'chat', pane: CLAUDE, items: [], context: { used: 184_000, limit: 200_000 } })
      // Being told "finish turn": the turn ends (the chat says it's no longer working).
      if (msg.t === 'text' && msg.pane === CLAUDE && msg.text === 'finish turn')
        setTimeout(() => void host.send(conn, { t: 'chat', pane: CLAUDE, items: [{ id: `t-${Date.now()}`, k: 'turn', ms: 4000 }], working: false }), 1000)
      // /compact takes a while, then a note and a smaller context.
      if (msg.t === 'text' && msg.pane === CLAUDE && msg.text === '/compact')
        setTimeout(() => void host.send(conn, { t: 'chat', pane: CLAUDE, items: [{ id: `n-${Date.now()}`, k: 'note', text: 'Compacted to 30k tokens' }], context: { used: 30_000, limit: 200_000 } }), 8000)
      // /clear starts a fresh session, as in Claude Code: the conversation starts over, empty.
      if (msg.t === 'text' && msg.pane === CLAUDE && msg.text === '/clear')
        setTimeout(() => void host.send(conn, { t: 'chat', pane: CLAUDE, items: [], reset: true, title: 'Fix the relay cache', mode: 'default', working: false, context: { used: 18_000, limit: 200_000 } }), 500)
      // A prompt typed into the agent shows up in its transcript a moment later, as with a
      // real agent: images dropped with it as Claude records them ("[Image #1] text").
      if (msg.t === 'text' && msg.submit && msg.pane === CLAUDE) {
        const images = (msg.files ?? []).filter((id) => IMAGE.test(uploaded.get(id)?.name ?? '')).length
        const text = [...Array.from({ length: images }, (_, i) => `[Image #${i + 1}]`), msg.text].filter(Boolean).join(' ')
        // Claude Code tags a large paste (what a phone sends is one).
        const tagged = text.length > 200 ? `\n\n<pasted_content id="ab12">\n${text}\n</pasted_content id="ab12">\n` : text
        setTimeout(() => void host.send('all', { t: 'chat', pane: CLAUDE, items: [{ id: `u-${Date.now()}`, k: 'user', text: tagged, ...(images && { images }) }] }), 6000)
      }
    },
    onStatus: (s, detail) => out({ event: 'status', status: s, detail })
  })
  host.start()
  // The relay this Mac moved to: the same Mac (key, devices) there.
  let moved: { url: string; host: RelayHost } | null = null
  if (process.env.FAKE_MOVE_RELAY) {
    const url2 = await spawnRelay()
    const there: RelayHost = new RelayHost({
      relay: url2,
      hostId: await hostIdFor(key.publicKey),
      hostSecret: 'fake-host-secret-'.padEnd(40, 'x'),
      hostName: NAME,
      key,
      clients: () => clients,
      onPaired: () => {},
      onSession: (conn, client) => {
        if (!client) return
        out({ event: 'session', name: client.name, relay: 'moved' })
        void there.send(conn, state)
      },
      onMessage: (conn, _client, msg) => {
        out({ event: 'message', relay: 'moved', msg })
        if (msg.t === 'subscribe' && msg.pane === CLAUDE) void there.send(conn, claudeChat)
      },
      onStatus: () => {}
    })
    there.start()
    moved = { url: url2, host: there }
  }
  for (let i = 0; i < 100 && !host.connected; i++) await new Promise((r) => setTimeout(r, 50))
  out({ event: 'ready', relay: url, link: pairingLink(host.newPairing(10 * 60_000)) })
  createInterface({ input: process.stdin }).on('line', (line) => {
    try {
      void host.send('all', JSON.parse(line))
    } catch {}
  })
  const quit = (): void => {
    host.stop()
    moved?.host.stop()
    for (const r of relays) r.kill()
    process.exit(0)
  }
  process.on('SIGTERM', quit)
  process.on('SIGINT', quit)
  process.stdin.on('end', quit)
}

void main()
