import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  b64u,
  CryptoError,
  helloClientId,
  exportKeyPair,
  generateKeyPair,
  importKeyPair,
  keyId,
  pairClientStart,
  pairHostAccept,
  randomBytes,
  sessionClientStart,
  sessionHostAccept,
  unb64u,
  hostFingerprint,
  hostIdFor,
  hostIdMatchesKey
} from '../protocol/crypto.ts'
import { pairingLink, parsePairingLink } from '../protocol/messages.ts'

test('pairing: the right code registers the client key both ways', async () => {
  const host = await generateKeyPair()
  const client = await generateKeyPair()
  const code = randomBytes(16)
  const start = await pairClientStart(client, host.publicKey, code, 'iPhone')
  const accepted = await pairHostAccept(host, code, start.message, 'Mac')
  assert.deepEqual(accepted.clientPub, client.publicKey)
  assert.equal(accepted.name, 'iPhone')
  assert.deepEqual(await start.finish(accepted.reply), { hostName: 'Mac' })
})

test('pairing: a wrong code is rejected', async () => {
  const host = await generateKeyPair()
  const client = await generateKeyPair()
  const start = await pairClientStart(client, host.publicKey, randomBytes(16), 'x')
  await assert.rejects(pairHostAccept(host, randomBytes(16), start.message, 'Mac'), CryptoError)
})

test('session: both sides derive the same channel; records flow both ways', async () => {
  const host = await generateKeyPair()
  const client = await generateKeyPair()
  const c = await sessionClientStart(client, host.publicKey)
  assert.equal(await helloClientId(host, c.message), await keyId(client.publicKey), 'the host recovers the id; the relay never sees it')
  const h = await sessionHostAccept(host, client.publicKey, c.message, { hello: 'from host' })
  const { channel: cc, welcome } = await c.finish(h.reply)
  assert.deepEqual(welcome, { hello: 'from host' })
  assert.deepEqual(await h.channel.open(await cc.seal({ t: 'ping' })), { t: 'ping' })
  assert.deepEqual(await cc.open(await h.channel.seal({ t: 'pong' })), { t: 'pong' })
})

test('session: an impostor client (wrong static key) cannot talk to the host', async () => {
  const host = await generateKeyPair()
  const real = await generateKeyPair()
  const impostor = await generateKeyPair()
  // Impostor claims to be `real` (host looks up real's key) but holds a different private key.
  const c = await sessionClientStart(impostor, host.publicKey)
  const h = await sessionHostAccept(host, real.publicKey, c.message, {})
  await assert.rejects(c.finish(h.reply), CryptoError) // keys differ: can't even read the welcome
})

test('session: an impostor host (wrong static key) is detected by the client', async () => {
  const realHost = await generateKeyPair()
  const fakeHost = await generateKeyPair()
  const client = await generateKeyPair()
  const c = await sessionClientStart(client, realHost.publicKey)
  const h = await sessionHostAccept(fakeHost, client.publicKey, c.message, {})
  await assert.rejects(c.finish(h.reply), CryptoError)
})

test('records: tampering and replay are rejected', async () => {
  const host = await generateKeyPair()
  const client = await generateKeyPair()
  const c = await sessionClientStart(client, host.publicKey)
  const h = await sessionHostAccept(host, client.publicKey, c.message, {})
  const { channel } = await c.finish(h.reply)
  const r1 = await channel.seal({ n: 1 })
  const bytes = unb64u(r1)
  bytes[bytes.length - 1] ^= 1
  const tampered = Buffer.from(bytes).toString('base64url')
  await assert.rejects(h.channel.open(tampered), CryptoError)
  assert.deepEqual(await h.channel.open(r1), { n: 1 })
  await assert.rejects(h.channel.open(r1), /replayed/)
})

async function pair(): Promise<{ client: Awaited<ReturnType<typeof sessionHostAccept>>['channel']; host: Awaited<ReturnType<typeof sessionHostAccept>>['channel'] }> {
  const host = await generateKeyPair()
  const client = await generateKeyPair()
  const c = await sessionClientStart(client, host.publicKey)
  const h = await sessionHostAccept(host, client.publicKey, c.message, {})
  return { client: (await c.finish(h.reply)).channel, host: h.channel }
}

test('records: two copies arriving together are delivered once', async () => {
  const { client, host } = await pair()
  const r = await client.seal({ t: 'text', text: 'rm -rf build', submit: true })
  const results = await Promise.allSettled([host.open(r), host.open(r)])
  assert.deepEqual(results.map((x) => x.status), ['fulfilled', 'rejected'])
})

test('records: sealing keeps call order, even when a later record is much smaller', async () => {
  const { client, host } = await pair()
  const order: number[] = []
  const big = client.seal({ n: 0, pad: 'x'.repeat(2_000_000) }).then((r) => (order.push(0), r))
  const small = client.seal({ n: 1 }).then((r) => (order.push(1), r))
  const [r0, r1] = await Promise.all([big, small])
  assert.deepEqual(order, [0, 1], 'resolved in call order, so senders put them on the wire in order')
  assert.equal(((await host.open(r0)) as { n: number }).n, 0)
  assert.deepEqual(await host.open(r1), { n: 1 })
})

test('records: concurrent opens of in-order records all succeed, in order', async () => {
  const { client, host } = await pair()
  const records = await Promise.all([1, 2, 3, 4].map((n) => client.seal({ n })))
  const opened = await Promise.all(records.map((r) => host.open<{ n: number }>(r)))
  assert.deepEqual(opened.map((m) => m.n), [1, 2, 3, 4])
})

test('records: a withheld record is detected', async () => {
  const { client, host } = await pair()
  const r0 = await client.seal({ n: 0 })
  await client.seal({ n: 1 }) // withheld by the relay
  const r2 = await client.seal({ n: 2 })
  assert.deepEqual(await host.open(r0), { n: 0 })
  await assert.rejects(host.open(r2), /missing record/)
})

test('keys survive export/import', async () => {
  const k = await generateKeyPair()
  const back = await importKeyPair(JSON.parse(JSON.stringify(await exportKeyPair(k))))
  const other = await generateKeyPair()
  const c = await sessionClientStart(other, back.publicKey)
  const h = await sessionHostAccept(back, other.publicKey, c.message, 'ok')
  assert.equal((await c.finish(h.reply)).welcome, 'ok')
})

test('pairing links round-trip', () => {
  const p = { relay: 'https://relay.cnvk.si', host: 'host-0123456789abcdef', hostPub: b64u(new Uint8Array(32)), code: b64u(new Uint8Array(16)), name: "George's Mac" }
  assert.deepEqual(parsePairingLink(pairingLink(p)), p)
  assert.equal(parsePairingLink('https://x/#nope'), null)
})

test('pairing links: only a safe relay, well-formed ids, keys and codes', () => {
  const good = { relay: 'https://relay.cnvk.si', host: 'host-0123456789abcdef', hostPub: b64u(new Uint8Array(32)), code: b64u(new Uint8Array(16)), name: 'Mac' }
  const bad = (change: Record<string, unknown>) => parsePairingLink(pairingLink({ ...good, ...change } as typeof good))
  for (const relay of ['http://relay.cnvk.si', 'ws://relay.cnvk.si', 'javascript:alert(1)', 'https://user:pw@relay.cnvk.si', 'https://relay.cnvk.si/?x=1', '', 'relay.cnvk.si']) {
    assert.equal(bad({ relay }), null, relay)
  }
  assert.ok(bad({ relay: 'http://127.0.0.1:8080' }), 'loopback http is fine (tests, local relays)')
  assert.equal(bad({ host: 'short' }), null)
  assert.equal(bad({ hostPub: b64u(new Uint8Array(31)) }), null)
  assert.equal(bad({ code: b64u(new Uint8Array(8)) }), null)
  assert.equal(bad({ name: 7 }), null)
})

test('records are padded: their size does not reveal how much was typed', async () => {
  const host = await generateKeyPair()
  const client = await generateKeyPair()
  const c = await sessionClientStart(client, host.publicKey)
  const h = await sessionHostAccept(host, client.publicKey, c.message, {})
  const { channel } = await c.finish(h.reply)
  const sizes = await Promise.all(['a', 'hunter2', 'correct horse battery staple'].map(async (text) => (await channel.seal({ t: 'text', pane: 1, text, submit: true })).length))
  assert.equal(new Set(sizes).size, 1)
  const big = await channel.seal({ t: 'text', pane: 1, text: 'x'.repeat(300), submit: true })
  assert.ok(big.length > sizes[0], 'longer messages grow in 256-byte steps')
})

// X25519 points of small order: each gives an all-zero shared secret (CONVOKE-46).
const LOW_ORDER = [
  new Uint8Array(32),
  Uint8Array.from([1, ...new Array(31).fill(0)]),
  Uint8Array.from(Buffer.from('e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800', 'hex')),
  Uint8Array.from(Buffer.from('5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157', 'hex'))
]

test('low-order public keys are refused before they feed a key (CONVOKE-46)', async () => {
  const host = await generateKeyPair()
  const client = await generateKeyPair()
  for (const bad of LOW_ORDER) {
    await assert.rejects(sessionClientStart(client, bad), CryptoError, 'as the host key in a pairing link')
    await assert.rejects(pairClientStart(client, bad, randomBytes(16), 'p'), CryptoError)
    await assert.rejects(helloClientId(host, { t: 'hello', ce: b64u(bad), cidBox: b64u(randomBytes(40)) }), CryptoError, 'as a hello ephemeral key')
    const start = await sessionClientStart(client, host.publicKey)
    await assert.rejects(start.finish({ he: b64u(bad), box: 'AAAA' }), CryptoError, "as the host's ephemeral key")
  }
})

test('a pairing link must carry the host id its key derives (CONVOKE-40)', async () => {
  const mac = await generateKeyPair()
  const attacker = await generateKeyPair()
  const id = await hostIdFor(mac.publicKey)
  assert.equal(await hostIdMatchesKey(id, mac.publicKey), true)
  assert.equal(await hostIdMatchesKey(id, attacker.publicKey), false, "the Mac's id with someone else's key")
  assert.equal(await hostIdMatchesKey('test-host-0000000000', mac.publicKey), false, 'not a key-bound id')
})

test('host fingerprints: stable, comparable, and different per key', async () => {
  const a = await generateKeyPair()
  const b = await generateKeyPair()
  const fa = await hostFingerprint(a.publicKey)
  assert.match(fa, /^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}$/)
  assert.equal(await hostFingerprint(a.publicKey), fa)
  assert.notEqual(await hostFingerprint(b.publicKey), fa)
})
