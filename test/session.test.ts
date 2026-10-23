// Adversarial checks of the session state machines (CONVOKE-24..29): what a relay in the
// middle can do by duplicating, replaying or racing frames, and races with revocation.
// Real protocol code over fake sockets; the host's private handlers are driven directly
// so deliveries can overlap the way they can on a real socket.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { b64u, generateKeyPair, keyId, pairClientStart, sessionClientStart, sessionHostAccept, unb64u, type KeyPair } from '../protocol/crypto.ts'
import type { ClientMessage, HostMessage } from '../protocol/messages.ts'
import { RelayClient, RelayHost, type PairedClient } from '../protocol/session.ts'

/* eslint-disable @typescript-eslint/no-explicit-any */
type Sent = { t: string; conn?: number; data?: string }

async function fixture() {
  const key = await generateKeyPair()
  const deviceKey = await generateKeyPair()
  const device: PairedClient = { cid: await keyId(deviceKey.publicKey), pub: b64u(deviceKey.publicKey), name: 'test', pairedAt: 0 }
  let clients = [device]
  const paired: PairedClient[] = []
  const received: ClientMessage[] = []
  const sent: Sent[] = []
  const host = new RelayHost({
    relay: 'http://localhost',
    hostId: 'test-host-0000000000',
    hostSecret: 'x'.repeat(40),
    hostName: 'test',
    key,
    clients: () => clients,
    onPaired: (c) => paired.push(c),
    onMessage: (_n, _c, m) => received.push(m),
    onSession: () => {},
    onStatus: () => {}
  })
  const h = host as any
  h.ws = { send: (s: string) => sent.push(JSON.parse(s)), readyState: 1 }
  const open = (conn: number) => h.onFrame(JSON.stringify({ t: 'open', conn }))
  const deliver = (conn: number, data: unknown): Promise<void> => h.onClientData(conn, JSON.stringify(data))
  /** Messages the host sent to one connection (decoded from the relay envelope). */
  const to = (conn: number): any[] => sent.filter((f) => f.t === 'msg' && f.conn === conn).map((f) => JSON.parse(f.data!))
  const kicked = (conn: number): boolean => sent.some((f) => f.t === 'kick' && f.conn === conn)
  const revoke = () => {
    clients = []
    host.disconnectClient(device.cid)
  }
  /** A connection with a finished handshake; returns the device's channel. */
  const session = async (conn: number) => {
    await open(conn)
    const start = await sessionClientStart(deviceKey, key.publicKey)
    await deliver(conn, start.message)
    return (await start.finish(to(conn).find((m) => m.t === 'hello-ok'))).channel
  }
  return { key, deviceKey, device, host, paired, received, sent, open, deliver, to, kicked, revoke, session, stop: () => { for (const c of [...h.conns.keys()]) h.end(c) } }
}

test('a record delivered twice at once is dispatched once', async () => {
  const f = await fixture()
  const channel = await f.session(1)
  const rec = { t: 'rec', r: await channel.seal({ t: 'text', pane: 7, text: 'make deploy', submit: true }) }
  await Promise.all([f.deliver(1, rec), f.deliver(1, rec)])
  assert.equal(f.received.length, 1)
  f.stop()
})

test('records delivered concurrently are dispatched once each, in order', async () => {
  const f = await fixture()
  const channel = await f.session(1)
  const recs = await Promise.all(['a', 'b', 'c'].map((text) => channel.seal({ t: 'text', pane: 1, text, submit: false })))
  await Promise.all(recs.map((r) => f.deliver(1, { t: 'rec', r })))
  assert.deepEqual(f.received.map((m) => (m as { text: string }).text), ['a', 'b', 'c'])
  f.stop()
})

test('one pairing code pairs one device, even when two race for it', async () => {
  const f = await fixture()
  const info = f.host.newPairing()
  const a = await pairClientStart(await generateKeyPair(), f.key.publicKey, unb64u(info.code), 'a')
  const b = await pairClientStart(await generateKeyPair(), f.key.publicKey, unb64u(info.code), 'b')
  await f.open(1)
  await f.open(2)
  await Promise.all([f.deliver(1, a.message), f.deliver(2, b.message)])
  assert.equal(f.paired.length, 1)
  assert.equal([f.kicked(1), f.kicked(2)].filter(Boolean).length, 1, 'the loser is refused')
  f.stop()
})

test('a wrong code does not use up the real one; a used or cancelled code pairs nobody', async () => {
  const f = await fixture()
  const info = f.host.newPairing()
  const wrong = await pairClientStart(await generateKeyPair(), f.key.publicKey, new Uint8Array(16), 'wrong')
  await f.open(1)
  await f.deliver(1, wrong.message)
  assert.ok(f.kicked(1))
  const right = await pairClientStart(await generateKeyPair(), f.key.publicKey, unb64u(info.code), 'right')
  await f.open(2)
  await f.deliver(2, right.message)
  assert.equal(f.paired.length, 1)
  const again = await pairClientStart(await generateKeyPair(), f.key.publicKey, unb64u(info.code), 'again')
  await f.open(3)
  await f.deliver(3, again.message)
  assert.equal(f.paired.length, 1, 'sequential reuse refused')
  const info2 = f.host.newPairing()
  const late = await pairClientStart(await generateKeyPair(), f.key.publicKey, unb64u(info2.code), 'late')
  await f.open(4)
  const pending = f.deliver(4, late.message)
  f.host.cancelPairing() // cancelled while the request is being checked
  await pending
  assert.equal(f.paired.length, 1)
  f.stop()
})

test('revoking during a handshake: no session, and no command runs', async () => {
  const f = await fixture()
  await f.open(1)
  const start = await sessionClientStart(f.deviceKey, f.key.publicKey)
  const pending = f.deliver(1, start.message)
  f.revoke()
  await pending
  // The hello is answered either way (revealing nothing): with a decoy if the revocation
  // came first (its welcome won't open), else for real, and then the first record finds it
  // revoked.
  const opened = await start.finish(f.to(1).find((m) => m.t === 'hello-ok')).catch(() => null)
  if (opened) {
    await f.deliver(1, { t: 'rec', r: await opened.channel.seal({ t: 'text', pane: 1, text: 'rm -rf ~', submit: true }) })
    assert.ok(f.kicked(1))
  }
  assert.equal(f.host.sessions().length, 0)
  assert.deepEqual(f.received, [], 'no command ran')
  f.stop()
})

test('nothing is sent to a device before it proves its key (CONVOKE-41)', async () => {
  const f = await fixture()
  await f.open(1)
  const start = await sessionClientStart(f.deviceKey, f.key.publicKey)
  await f.deliver(1, start.message)
  await f.host.send('all', { t: 'pong' })
  await f.host.send(1, { t: 'pong' })
  assert.deepEqual(f.to(1).map((m) => m.t), ['hello-ok'], 'only the handshake reply')
  const channel = (await start.finish(f.to(1).find((m) => m.t === 'hello-ok'))).channel
  await f.deliver(1, { t: 'rec', r: await channel.seal({ t: 'ping' }) })
  await f.host.send('all', { t: 'pong' })
  assert.deepEqual(f.to(1).map((m) => m.t), ['hello-ok', 'rec'], 'state flows once it has proved its key')
  f.stop()
})

test("a hello for an unknown device looks like one for a known device that hasn't proved its key (CONVOKE-41)", async () => {
  const f = await fixture()
  const stranger = await generateKeyPair()
  await f.open(1)
  await f.deliver(1, (await sessionClientStart(f.deviceKey, f.key.publicKey)).message)
  await f.open(2)
  const strange = await sessionClientStart(stranger, f.key.publicKey)
  await f.deliver(2, strange.message)
  const known = f.to(1)
  const unknown = f.to(2)
  assert.deepEqual(unknown.map((m) => m.t), known.map((m) => m.t), 'the same frames')
  assert.deepEqual(Object.keys(unknown[0]).sort(), Object.keys(known[0]).sort())
  assert.equal(unknown[0].box.length, known[0].box.length, 'the same size')
  assert.equal(f.kicked(2), false, 'not kicked straight away (that would tell)')
  await assert.rejects(strange.finish(unknown[0]), 'the decoy welcome does not open')
  f.stop()
})

test('revoking while a record decrypts: it is not dispatched', async () => {
  const f = await fixture()
  const channel = await f.session(1)
  const pending = f.deliver(1, { t: 'rec', r: await channel.seal({ t: 'text', pane: 7, text: 'x', submit: true }) })
  f.revoke()
  await pending
  assert.equal(f.received.length, 0)
  assert.equal(f.host.sessions().length, 0)
  f.stop()
})

test('a hello naming a known device, without its key, never becomes live and times out', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const f = await fixture()
  await f.open(1)
  // Anyone can name the device's key id; only the device can then decrypt the reply.
  const impostor = await sessionClientStart(await generateKeyPair(), f.key.publicKey)
  await f.deliver(1, { t: 'hello', ce: impostor.message.ce, cid: f.device.cid }) // v1 form: the id in the clear
  assert.equal(f.host.sessions().length, 0)
  t.mock.timers.tick(11_000)
  assert.ok(f.kicked(1), 'dropped at the handshake deadline')
  // A real device proves its key with its first record and is not dropped.
  const channel = await f.session(2)
  await f.deliver(2, { t: 'rec', r: await channel.seal({ t: 'ping' }) })
  t.mock.timers.tick(11_000)
  assert.equal(f.kicked(2), false)
  assert.equal(f.host.sessions().length, 1)
  assert.ok(f.sent.some((x) => x.t === 'verified' && x.conn === 2), 'the relay is told, so the device keeps its slot')
  assert.equal(f.sent.some((x) => x.t === 'verified' && x.conn === 1), false)
  f.stop()
})

test('a connection that never says anything times out', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const f = await fixture()
  await f.open(1)
  t.mock.timers.tick(11_000)
  assert.ok(f.kicked(1))
  f.stop()
})

test('client: a replayed hello-ok does not reset the channel (no nonce reuse)', async () => {
  const hostKey = await generateKeyPair()
  const deviceKey = await generateKeyPair()
  const Original = globalThis.WebSocket
  let ws: any
  class FakeWS {
    static OPEN = 1
    readyState = 1
    sent: any[] = []
    onopen?: () => Promise<void>
    onmessage?: (ev: { data: string }) => Promise<void>
    onclose?: () => void
    constructor() {
      ws = this // eslint-disable-line @typescript-eslint/no-this-alias
    }
    send(s: string) {
      this.sent.push(JSON.parse(s))
    }
    close() {}
  }
  ;(globalThis as any).WebSocket = FakeWS
  try {
    const got: HostMessage[] = []
    const phone = new RelayClient({
      identity: { key: deviceKey, relay: 'http://localhost', host: 'h', hostPub: b64u(hostKey.publicKey), hostName: 'h' },
      onMessage: (m) => got.push(m),
      onStatus: () => {}
    })
    phone.start()
    await ws.onopen()
    const { reply, channel } = await sessionHostAccept(hostKey, deviceKey.publicKey, ws.sent[0], {})
    await ws.onmessage({ data: JSON.stringify(reply) })
    const record = { t: 'rec', r: await channel.seal({ t: 'pong' }) }
    await ws.onmessage({ data: JSON.stringify(record) })
    await ws.onmessage({ data: JSON.stringify(reply) }) // replayed by the relay
    await phone.send({ t: 'text', pane: 7, text: 'bbbb', submit: true })
    const counters = ws.sent.filter((m: any) => m.t === 'rec').map((m: any) => Number(new DataView(unb64u(m.r).buffer).getBigUint64(0)))
    assert.equal(new Set(counters).size, counters.length, `counters never repeat: ${counters}`)
    await ws.onmessage({ data: JSON.stringify(record) }) // and an old host record is still refused
    assert.equal(got.length, 1)
    phone.stop()
  } finally {
    ;(globalThis as any).WebSocket = Original
  }
})

test('client: forged plaintext errors and garbage replies never stop it for good', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const hostKey = await generateKeyPair()
  const deviceKey = await generateKeyPair()
  const Original = globalThis.WebSocket
  const sockets: any[] = []
  class FakeWS {
    static OPEN = 1
    readyState = 1
    sent: any[] = []
    onopen?: () => Promise<void>
    onmessage?: (ev: { data: string }) => Promise<void>
    onclose?: (ev: { code: number; reason: string }) => void
    constructor() {
      sockets.push(this)
    }
    send(s: string) {
      this.sent.push(JSON.parse(s))
    }
    close() {
      this.onclose?.({ code: 1000, reason: '' })
    }
  }
  ;(globalThis as any).WebSocket = FakeWS
  try {
    const statuses: string[] = []
    const phone = new RelayClient({
      identity: { key: deviceKey, relay: 'http://localhost', host: 'h', hostPub: b64u(hostKey.publicKey), hostName: 'h' },
      onMessage: () => {},
      onStatus: (s, d) => statuses.push(d ? `${s}:${d}` : s)
    })
    phone.start()
    await sockets[0].onopen()
    await sockets[0].onmessage({ data: 'not json' })
    t.mock.timers.tick(20_000)
    assert.equal(sockets.length, 2, 'garbage closes the socket, then it reconnects')
    await sockets[1].onopen()
    await sockets[1].onmessage({ data: JSON.stringify({ t: 'hello-ok', he: b64u((await generateKeyPair()).publicKey), box: 'AAAA' }) })
    assert.ok(statuses.at(-1)?.startsWith('unpaired'), "a welcome that doesn't open: removed, or not our Mac")
    t.mock.timers.tick(61_000)
    assert.equal(sockets.length, 3, 'a bad reply is retried, not final')
    await sockets[2].onopen()
    await sockets[2].onmessage({ data: JSON.stringify({ t: 'error', code: 'revoked' }) })
    sockets[2].close()
    assert.ok(statuses.at(-1)?.startsWith('unpaired'))
    t.mock.timers.tick(61_000)
    assert.equal(sockets.length, 4, 'an unauthenticated "revoked" is checked again later')
    // A handshake reply that never comes: the client starts over.
    await sockets[3].onopen()
    t.mock.timers.tick(16_000)
    t.mock.timers.tick(20_000)
    assert.equal(sockets.length, 5)
    phone.stop()
  } finally {
    ;(globalThis as any).WebSocket = Original
  }
})

test('a device paired with an approval-required code gets no session until approved', async () => {
  const f = await fixture()
  const info = f.host.newPairing(60_000, { approval: true })
  const newKey = await generateKeyPair()
  const p = await pairClientStart(newKey, f.key.publicKey, unb64u(info.code), 'script-requested')
  await f.open(1)
  await f.deliver(1, p.message)
  assert.equal(f.paired.length, 1)
  assert.equal(f.paired[0].pending, true)
  // While pending it's told so only after proving its key, and gets no session.
  const h = f.host as any
  const clients = [f.device, f.paired[0]]
  h.opts.clients = () => clients
  await f.open(2)
  const start = await sessionClientStart(newKey, f.key.publicKey)
  await f.deliver(2, start.message)
  assert.equal(f.to(2).some((m) => m.t === 'error'), false, 'nothing said before the key is proved')
  const ch = (await start.finish(f.to(2).find((m) => m.t === 'hello-ok'))).channel
  await f.deliver(2, { t: 'rec', r: await ch.seal({ t: 'ping' }) })
  assert.ok(f.to(2).some((m) => m.t === 'error' && m.code === 'pending-approval'))
  assert.equal(f.host.sessions().length, 0)
  // Approved: it connects.
  clients[1] = { ...clients[1], pending: false }
  await f.open(3)
  const again = await sessionClientStart(newKey, f.key.publicKey)
  await f.deliver(3, again.message)
  const ch3 = (await again.finish(f.to(3).find((m) => m.t === 'hello-ok'))).channel
  await f.deliver(3, { t: 'rec', r: await ch3.seal({ t: 'ping' }) })
  assert.equal(f.host.sessions().length, 1)
  f.stop()
})

test("client: the host's first record right behind the handshake reply is not dropped", async () => {
  const hostKey = await generateKeyPair()
  const deviceKey = await generateKeyPair()
  const Original = globalThis.WebSocket
  let ws: any
  class FakeWS {
    static OPEN = 1
    readyState = 1
    sent: any[] = []
    onopen?: () => Promise<void>
    onmessage?: (ev: { data: string }) => Promise<void>
    onclose?: (ev: { code: number; reason: string }) => void
    constructor() {
      ws = this // eslint-disable-line @typescript-eslint/no-this-alias
    }
    send(s: string) {
      this.sent.push(JSON.parse(s))
    }
    close() {
      this.onclose?.({ code: 1000, reason: '' })
    }
  }
  ;(globalThis as any).WebSocket = FakeWS
  try {
    const got: HostMessage[] = []
    const phone = new RelayClient({
      identity: { key: deviceKey, relay: 'http://localhost', host: 'h', hostPub: b64u(hostKey.publicKey), hostName: 'h' },
      onMessage: (m) => got.push(m),
      onStatus: () => {}
    })
    phone.start()
    await ws.onopen()
    const { reply, channel } = await sessionHostAccept(hostKey, deviceKey.publicKey, ws.sent[0], {})
    const first = { t: 'rec', r: await channel.seal({ t: 'pong' }) }
    const second = { t: 'rec', r: await channel.seal({ t: 'approvals', items: [] }) }
    // As on a real socket: the frames arrive back to back, while the handshake is still being finished.
    const a = ws.onmessage({ data: JSON.stringify(reply) })
    const b = ws.onmessage({ data: JSON.stringify(first) })
    await ws.onmessage({ data: JSON.stringify(second) })
    await Promise.all([a, b])
    assert.deepEqual(got.map((m) => m.t), ['pong', 'approvals'])
    phone.stop()
  } finally {
    ;(globalThis as any).WebSocket = Original
  }
})

test('a hello hides the device id from the relay; a cleartext (v1) hello is refused (CONVOKE-45)', async () => {
  const f = await fixture()
  const start = await sessionClientStart(f.deviceKey, f.key.publicKey)
  const wire = JSON.stringify(start.message)
  assert.equal(wire.includes(f.device.cid), false, 'the id is not on the wire')
  assert.equal('cid' in start.message, false)
  await f.open(1)
  await f.deliver(1, start.message)
  assert.ok(f.to(1).some((m) => m.t === 'hello-ok'), 'the host finds the device anyway')
  const old = await sessionClientStart(f.deviceKey, f.key.publicKey)
  await f.open(2)
  await f.deliver(2, { t: 'hello', ce: old.message.ce, cid: f.device.cid })
  assert.ok(f.kicked(2))
  assert.equal(f.to(2).some((m) => m.t === 'hello-ok'), false)
  f.stop()
})

test('every hello has a fresh ephemeral key and nonce (CONVOKE-47)', async () => {
  const f = await fixture()
  const hellos = await Promise.all(Array.from({ length: 8 }, () => sessionClientStart(f.deviceKey, f.key.publicKey)))
  const ces = new Set(hellos.map((h) => h.message.ce))
  const ivs = new Set(hellos.map((h) => b64u(unb64u(h.message.cidBox).subarray(0, 12))))
  assert.equal(ces.size, 8)
  assert.equal(ivs.size, 8)
  assert.ok([...ivs].every((iv) => iv !== b64u(new Uint8Array(12))), 'never the all-zero nonce')
  f.stop()
})
