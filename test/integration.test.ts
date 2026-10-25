// End to end through the real Go relay: pairing, encrypted session, revocation.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, execFileSync, type ChildProcess } from 'node:child_process'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { b64u, generateKeyPair, hostIdFor, sessionClientStart, unb64u } from '../protocol/crypto.ts'
import { pairWithHost, RelayClient, RelayHost, type PairedClient } from '../protocol/session.ts'
import { UPLOAD_CHUNK_BYTES, type ClientMessage, type HostMessage } from '../protocol/messages.ts'

// RELAY_URL tests an already-running relay (e.g. the deployment, via port-forward);
// otherwise a fresh one is built and started.
const PORT = 18000 + Math.floor(Math.random() * 1000)
const RELAY = process.env.RELAY_URL ?? `http://127.0.0.1:${PORT}`
let relay: ChildProcess
let relayLog = ''

before(async () => {
  if (process.env.RELAY_URL) return
  const dir = mkdtempSync(join(tmpdir(), 'relay-'))
  execFileSync('go', ['build', '-o', join(dir, 'relay'), '.'], { cwd: join(import.meta.dirname, '..') })
  relay = spawn(join(dir, 'relay'), ['-addr', `127.0.0.1:${PORT}`, '-data', dir])
  relay.stderr!.on('data', (d) => (relayLog += d))
  for (let i = 0; i < 50; i++) {
    try {
      if ((await fetch(`${RELAY}/health`)).ok) return
    } catch {}
    await new Promise((r) => setTimeout(r, 100))
  }
  throw new Error('relay did not start')
})

after(() => relay?.kill())

const until = async <T>(fn: () => T | undefined, ms = 5000): Promise<T> => {
  const end = Date.now() + ms
  while (Date.now() < end) {
    const v = fn()
    if (v !== undefined && v !== false) return v
    await new Promise((r) => setTimeout(r, 25))
  }
  throw new Error('timed out')
}

async function startHost(opts: { keyBound?: boolean } = { keyBound: true }) {
  const clients: PairedClient[] = []
  const received: { client: string; msg: ClientMessage }[] = []
  let status = ''
  const key = await generateKeyPair()
  const host = new RelayHost({
    relay: RELAY,
    hostId: opts.keyBound ? await hostIdFor(key.publicKey) : 'test-host-' + Math.random().toString(36).slice(2, 12),
    hostSecret: 'secret-'.padEnd(40, 'x'),
    hostName: 'Test Mac',
    key,
    clients: () => clients,
    onPaired: (c) => clients.push(c),
    onMessage: (_conn, client, msg) => {
      if (msg.t !== 'ping') received.push({ client: client.name, msg }) // the client pings on connect
    },
    onSession: () => {},
    onStatus: (s) => (status = s)
  })
  host.start()
  await until(() => status === 'online')
  return { host, clients, received }
}

test('pair, then talk end to end through the relay', async () => {
  const { host, clients, received } = await startHost({ keyBound: true })
  const phoneKey = await generateKeyPair()
  const identity = await pairWithHost(phoneKey, host.newPairing(), 'Test iPhone')
  assert.equal(identity.hostName, 'Test Mac')
  assert.equal(clients.length, 1)
  assert.equal(clients[0].name, 'Test iPhone')

  const got: HostMessage[] = []
  let status = ''
  const phone = new RelayClient({ identity, onMessage: (m) => got.push(m), onStatus: (s) => (status = s) })
  phone.start()
  await until(() => status === 'online')
  await phone.send({ t: 'text', pane: 7, text: 'npm test', submit: true })
  const r = await until(() => received[0])
  assert.deepEqual(r, { client: 'Test iPhone', msg: { t: 'text', pane: 7, text: 'npm test', submit: true } })
  // A full upload chunk (incompressible bytes) still fits a client frame.
  const chunk = Buffer.from(Array.from({ length: UPLOAD_CHUNK_BYTES }, () => Math.floor(Math.random() * 256))).toString('base64')
  await phone.send({ t: 'upload', id: 'up1', name: 'photo.jpg', size: UPLOAD_CHUNK_BYTES, seq: 0, data: chunk, last: true })
  const up = await until(() => received[1])
  assert.equal(up.msg.t === 'upload' && up.msg.data, chunk)
  await host.send('all', { t: 'pong' })
  assert.deepEqual(await until(() => got[0]), { t: 'pong' })
  // The relay only ever logs routing, never content.
  if (!process.env.RELAY_URL) assert.ok(!relayLog.includes('npm test'))
  phone.stop()
  host.stop()
})

test('a device counts as live only once it proves its key', async () => {
  const { host, clients } = await startHost()
  const key = await generateKeyPair()
  const identity = await pairWithHost(key, host.newPairing(), 'Phone')
  // A raw hello names the key id (which isn't secret) but can't prove the key.
  const hostUrl = RELAY.replace(/^http/, 'ws') + `/v1/client?host=${encodeURIComponent(identity.host)}`
  const raw = new WebSocket(hostUrl)
  await new Promise((r) => (raw.onopen = r))
  const hello = await sessionClientStart(key, unb64u(identity.hostPub))
  raw.send(JSON.stringify(hello.message))
  await new Promise((r) => (raw.onmessage = r))
  await new Promise((r) => setTimeout(r, 200))
  assert.equal(host.sessions().length, 0, 'a hello alone must not count')
  raw.close()
  // A real client's first (ping) record does.
  let status = ''
  const phone = new RelayClient({ identity, onMessage: () => {}, onStatus: (s) => (status = s) })
  phone.start()
  await until(() => host.sessions().length === 1 || undefined)
  assert.equal(clients.length, 1)
  phone.stop()
  host.stop()
})

test('a pairing code works once', async () => {
  const { host } = await startHost()
  const info = host.newPairing()
  await pairWithHost(await generateKeyPair(), info, 'first')
  await assert.rejects(pairWithHost(await generateKeyPair(), info, 'second'), /expired or was already used/)
  host.stop()
})

test('a revoked device is told it was removed and stops retrying', async () => {
  const { host, clients } = await startHost()
  const identity = await pairWithHost(await generateKeyPair(), host.newPairing(), 'Old phone')
  let status = ''
  const phone = new RelayClient({ identity, onMessage: () => {}, onStatus: (s) => (status = s) })
  phone.start()
  await until(() => status === 'online')
  // Revoke on the Mac: forget the key and drop its live session.
  const cid = clients[0].cid
  clients.splice(0)
  host.disconnectClient(cid)
  // The phone reconnects, presents a key the Mac no longer knows, and is told so.
  await until(() => status === 'unpaired', 15000)
  phone.stop()
  host.stop()
})

test('an offline host is reported as such', async () => {
  const { host } = await startHost()
  const identity = await pairWithHost(await generateKeyPair(), host.newPairing(), 'p')
  host.stop()
  await new Promise((r) => setTimeout(r, 200))
  let status = ''
  const phone = new RelayClient({ identity, onMessage: () => {}, onStatus: (s) => (status = s) })
  phone.start()
  await until(() => status === 'host-offline')
  phone.stop()
})

test('a key-bound host id: only the key that derives it can be that host', async () => {
  const key = await generateKeyPair()
  const id = await hostIdFor(key.publicKey)
  const statuses: string[] = []
  const impostor = new RelayHost({
    relay: RELAY,
    hostId: id,
    hostSecret: 'secret-'.padEnd(40, 'y'),
    hostName: 'Impostor',
    key: await generateKeyPair(), // a different key
    clients: () => [],
    onPaired: () => {},
    onMessage: () => {},
    onSession: () => {},
    onStatus: (s, d) => statuses.push(`${s}:${d ?? ''}`)
  })
  impostor.start()
  await until(() => statuses.find((s) => s.startsWith('offline')))
  assert.equal(statuses.includes('online:'), false)
  impostor.stop()
})

test("a pairing link with someone else's key and the Mac's id is refused before connecting (CONVOKE-40)", async () => {
  const { host, clients } = await startHost()
  const info = host.newPairing()
  const attacker = await generateKeyPair()
  await assert.rejects(pairWithHost(await generateKeyPair(), { ...info, hostPub: b64u(attacker.publicKey) }, 'p'), /doesn't match its Mac's key/)
  assert.equal(clients.length, 0)
  host.stop()
})
