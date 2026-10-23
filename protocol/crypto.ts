// End-to-end encryption between a Convoke host (the Mac) and a client (phone/web),
// using only WebCrypto so the same code runs in Electron, browsers and Node.
//
//   keys      X25519 static key per device, plus ephemeral keys per session
//   pairing   one-time code (from the QR) as a PSK; client sends its static key
//   session   Noise-KK-like: es + ee + se → HKDF → one AES-256-GCM key per direction
//   records   12-byte nonce = 4 zero bytes + 64-bit counter; receivers reject replays
//
// The relay only ever sees ciphertext and routing ids.

const subtle = globalThis.crypto.subtle

/** Bytes backed by a plain ArrayBuffer: what WebCrypto's BufferSource accepts. */
export type Bytes = Uint8Array<ArrayBuffer>
const enc = new TextEncoder()
const dec = new TextDecoder()

export function b64u(bytes: Bytes): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function unb64u(s: string): Bytes {
  const pad = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4)
  const bin = atob(pad)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

export function randomBytes(n: number): Bytes {
  return globalThis.crypto.getRandomValues(new Uint8Array(n))
}

function concat(...parts: Bytes[]): Bytes {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

export async function sha256(bytes: Bytes): Promise<Bytes> {
  return new Uint8Array(await subtle.digest('SHA-256', bytes))
}

// --- X25519 ------------------------------------------------------------------------

export interface KeyPair {
  privateKey: CryptoKey
  publicKey: Bytes // raw 32 bytes
}

/** A storable static key: the private part as JWK, the public part as base64url. */
export interface StoredKey {
  jwk: JsonWebKey
  pub: string
}

/**
 * A new static key. `extractable: false` keeps the private key inside WebCrypto: it can
 * be stored (as a CryptoKey, e.g. in IndexedDB) and used, but never read back out.
 */
export async function generateKeyPair(extractable = true): Promise<KeyPair> {
  const k = (await subtle.generateKey({ name: 'X25519' }, extractable, ['deriveBits'])) as CryptoKeyPair
  return { privateKey: k.privateKey, publicKey: new Uint8Array(await subtle.exportKey('raw', k.publicKey)) }
}

export async function exportKeyPair(k: KeyPair): Promise<StoredKey> {
  return { jwk: await subtle.exportKey('jwk', k.privateKey), pub: b64u(k.publicKey) }
}

export async function importKeyPair(s: StoredKey, extractable = true): Promise<KeyPair> {
  const privateKey = await subtle.importKey('jwk', s.jwk, { name: 'X25519' }, extractable, ['deriveBits'])
  return { privateKey, publicKey: unb64u(s.pub) }
}

/**
 * X25519. A low-order public key (one an attacker picks so the result is guessable)
 * gives an all-zero shared secret: refused, so it never feeds a key derivation.
 */
async function dh(priv: CryptoKey, pubRaw: Bytes): Promise<Bytes> {
  if (pubRaw.length !== 32) throw new CryptoError('bad public key')
  let pub: CryptoKey
  let shared: Bytes
  try {
    pub = await subtle.importKey('raw', pubRaw, { name: 'X25519' }, false, [])
    shared = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: pub }, priv, 256))
  } catch {
    throw new CryptoError('bad public key')
  }
  if (shared.every((b) => b === 0)) throw new CryptoError('low-order public key')
  return shared
}

async function hkdf(ikm: Bytes, salt: Bytes, info: string, length: number): Promise<Bytes> {
  const key = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits'])
  return new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(info) }, key, length * 8))
}

// --- AEAD records ---------------------------------------------------------------------

async function aesKey(raw: Bytes): Promise<CryptoKey> {
  return subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt'])
}

function nonce(counter: number): Bytes {
  const n = new Uint8Array(12)
  new DataView(n.buffer).setBigUint64(4, BigInt(counter))
  return n
}

export class CryptoError extends Error {}

/**
 * A message's bytes padded with spaces to a multiple of PAD_BYTES, so record sizes don't
 * reveal how long a message is (e.g. how many characters were typed). JSON allows
 * trailing whitespace, so receivers parse it as is.
 */
const PAD_BYTES = 256
export function padded(json: string): Bytes {
  const bytes = enc.encode(json)
  const pad = (PAD_BYTES - (bytes.length % PAD_BYTES)) % PAD_BYTES
  return concat(bytes, new Uint8Array(pad).fill(0x20))
}

/**
 * One direction-keyed encrypted channel. Records are `b64u(counter8 || ciphertext)`;
 * the receiver requires each record's counter to be exactly the next one, so replayed,
 * reordered or dropped records are rejected (WebSockets deliver in order, so a gap
 * means someone in between withheld a record).
 *
 * WebCrypto is async, so seal() and open() each run one at a time, in call order:
 * otherwise a small record could finish sealing before a big one sealed earlier (and
 * go out first, breaking the order), or two copies of one record could both pass the
 * replay check before either updated the counter.
 */
export class Channel {
  private sendCounter = 0
  private recvCounter = -1
  private sendKey: CryptoKey
  private recvKey: CryptoKey
  private sealing: Promise<unknown> = Promise.resolve()
  private opening: Promise<unknown> = Promise.resolve()

  // Explicit fields, not parameter properties: this file runs under Node's type stripping.
  private constructor(sendKey: CryptoKey, recvKey: CryptoKey) {
    this.sendKey = sendKey
    this.recvKey = recvKey
  }

  static async create(sendRaw: Bytes, recvRaw: Bytes): Promise<Channel> {
    return new Channel(await aesKey(sendRaw), await aesKey(recvRaw))
  }

  /** Seal a message. Results resolve in call order, so send each as soon as it resolves. */
  seal(value: unknown): Promise<string> {
    const next = this.sealing.then(() => this.sealNow(value))
    this.sealing = next.catch(() => {})
    return next
  }

  /** Open the next record. Calls are handled in order; any failure is final for the caller. */
  open<T = unknown>(record: string): Promise<T> {
    const next = this.opening.then(() => this.openNow<T>(record))
    this.opening = next.catch(() => {})
    return next
  }

  private async sealNow(value: unknown): Promise<string> {
    const counter = this.sendCounter++
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: nonce(counter) }, this.sendKey, padded(JSON.stringify(value))))
    const head = new Uint8Array(8)
    new DataView(head.buffer).setBigUint64(0, BigInt(counter))
    return b64u(concat(head, ct))
  }

  private async openNow<T>(record: string): Promise<T> {
    const bytes = unb64u(record)
    if (bytes.length < 8 + 16) throw new CryptoError('record too short')
    const counter = Number(new DataView(bytes.buffer, bytes.byteOffset).getBigUint64(0))
    if (counter <= this.recvCounter) throw new CryptoError('replayed or reordered record')
    if (counter !== this.recvCounter + 1) throw new CryptoError('missing record')
    let pt: ArrayBuffer
    try {
      pt = await subtle.decrypt({ name: 'AES-GCM', iv: nonce(counter) }, this.recvKey, bytes.subarray(8))
    } catch {
      throw new CryptoError('decryption failed')
    }
    this.recvCounter = counter
    return JSON.parse(dec.decode(pt)) as T
  }
}

// --- Pairing: one-time code from the QR, client registers its static key -------------------

// --- Key-bound host ids (see hostkey.go in the relay) -----------------------------------

/**
 * The relay id for a host's static key: "k1" + 30 base64url characters. The relay lets a
 * host use it only after a proof of the key, so nobody else can ever take it over.
 */
export async function hostIdFor(pub: Bytes): Promise<string> {
  return 'k1' + b64u(await sha256(concat(enc.encode('convoke-host-id-v1'), pub))).slice(0, 30)
}

export function isKeyBoundHostId(id: string): boolean {
  return id.length === 32 && id.startsWith('k1')
}

/**
 * A short code for a host's key, shown on the Mac's pairing sheet and on the device
 * before it pairs: if they differ, the link didn't come from that Mac. 16 Crockford
 * base32 characters (80 bits) in groups of four, e.g. "7F3K-92QD-M4XA-B8RT".
 */
export async function hostFingerprint(pub: Bytes): Promise<string> {
  const digest = await sha256(concat(enc.encode('convoke-fingerprint-v1'), pub))
  const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
  let bits = 0
  let value = 0
  let out = ''
  for (const byte of digest.subarray(0, 10)) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  return out.match(/.{4}/g)!.join('-')
}

/** Whether a pairing link's host id is the one its host key derives (else it's forged or garbled). */
export async function hostIdMatchesKey(host: string, hostPub: Bytes): Promise<boolean> {
  return isKeyBoundHostId(host) && (await hostIdFor(hostPub)) === host
}

/** The answer to the relay's challenge (`e`: its ephemeral key, `n`: nonce, both b64u). */
export async function relayAuthProof(key: KeyPair, id: string, e: string, n: string): Promise<string> {
  const shared = await dh(key.privateKey, unb64u(e))
  const mac = await subtle.importKey('raw', shared, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  return b64u(new Uint8Array(await subtle.sign('HMAC', mac, concat(enc.encode('convoke-relay-auth-v1'), enc.encode(id), unb64u(n)))))
}

/** Short id for a client's static key: lets the host find the right key without sending it. */
export async function keyId(pub: Bytes): Promise<string> {
  return b64u((await sha256(pub)).subarray(0, 12))
}

/** The pairing channel for one side: the client sends with the first half, the host with the second. */
async function pairingChannel(role: 'client' | 'host', shared: Bytes, code: Bytes, ce: Bytes): Promise<Channel> {
  const k = await hkdf(shared, concat(code, ce), 'convoke/pair/v1', 64)
  const c2h = k.subarray(0, 32)
  const h2c = k.subarray(32)
  return role === 'client' ? Channel.create(c2h, h2c) : Channel.create(h2c, c2h)
}

/** Client side of pairing. `hostPub` and `code` come from the QR. */
export async function pairClientStart(
  client: KeyPair,
  hostPub: Bytes,
  code: Bytes,
  name: string
): Promise<{ message: { t: 'pair'; ce: string; box: string }; finish: (reply: { box: string }) => Promise<{ hostName: string }> }> {
  const ce = await generateKeyPair()
  const channel = await pairingChannel('client', await dh(ce.privateKey, hostPub), code, ce.publicKey)
  const box = await channel.seal({ cs: b64u(client.publicKey), name })
  return {
    message: { t: 'pair', ce: b64u(ce.publicKey), box },
    finish: async (reply) => channel.open<{ hostName: string }>(reply.box)
  }
}

/** Host side of pairing: returns the client's static key and name if the code matched. */
export async function pairHostAccept(
  host: KeyPair,
  code: Bytes,
  msg: { ce: string; box: string },
  hostName: string
): Promise<{ clientPub: Bytes; name: string; reply: { t: 'pair-ok'; box: string } }> {
  const ce = unb64u(msg.ce)
  const channel = await pairingChannel('host', await dh(host.privateKey, ce), code, ce)
  const body = await channel.open<{ cs: string; name: string }>(msg.box) // throws on a wrong code
  return { clientPub: unb64u(body.cs), name: String(body.name).slice(0, 80), reply: { t: 'pair-ok', box: await channel.seal({ hostName }) } }
}

// --- Session handshake (every connection) -------------------------------------------------------

/** Session keys: the transcript binds a protocol label, the host's static key, the client id and both ephemeral keys. */
async function sessionKeys(es: Bytes, ee: Bytes, se: Bytes, cid: string, ce: Bytes, he: Bytes, hostPub: Bytes) {
  const salt = await sha256(concat(enc.encode('convoke/session/v2'), hostPub, enc.encode(cid), ce, he))
  const k = await hkdf(concat(es, ee, se), salt, 'convoke/session/v2', 64)
  return { c2h: k.subarray(0, 32), h2c: k.subarray(32) }
}

/**
 * The key that hides a hello's client id from the relay: only the host (static key) and
 * this connection's client (ephemeral key) can derive it. One per ephemeral key, and
 * every hello also gets a random nonce, so a nonce is never reused under it.
 */
async function helloKey(es: Bytes, hostPub: Bytes, ce: Bytes): Promise<CryptoKey> {
  const k = await hkdf(es, await sha256(concat(enc.encode('convoke/hello/v2'), hostPub, ce)), 'convoke/hello/v2', 32)
  return subtle.importKey('raw', k, 'AES-GCM', false, ['encrypt', 'decrypt'])
}

/**
 * A client's hello: `cidBox` is the client id encrypted for the host (12-byte random
 * nonce, then AES-GCM), so the relay can't link connections to a device. The older
 * hello with a client id in the clear is no longer accepted.
 */
export interface ClientHello {
  t: 'hello'
  ce: string
  cidBox: string
}

/** Client: send `message`, then pass the host's reply to `finish` to get the channel. */
export async function sessionClientStart(
  client: KeyPair,
  hostPub: Bytes
): Promise<{ message: ClientHello; finish: (reply: { he: string; box: string }) => Promise<{ channel: Channel; welcome: unknown }> }> {
  const ce = await generateKeyPair()
  const cid = await keyId(client.publicKey)
  const es = await dh(ce.privateKey, hostPub)
  const iv = randomBytes(12)
  const sealed = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, await helloKey(es, hostPub, ce.publicKey), enc.encode(cid)))
  return {
    message: { t: 'hello', ce: b64u(ce.publicKey), cidBox: b64u(concat(iv, sealed)) },
    finish: async (reply) => {
      const he = unb64u(reply.he)
      const ee = await dh(ce.privateKey, he)
      const se = await dh(client.privateKey, he)
      const keys = await sessionKeys(es, ee, se, cid, ce.publicKey, he, hostPub)
      const channel = await Channel.create(keys.c2h, keys.h2c)
      // The welcome only decrypts if the host holds its static key: host authenticated.
      const welcome = await channel.open(reply.box)
      return { channel, welcome }
    }
  }
}

/** Host: the client id a hello names (decrypting it), or throws. */
export async function helloClientId(host: KeyPair, hello: ClientHello): Promise<string> {
  if (typeof hello.cidBox !== 'string' || typeof hello.ce !== 'string') throw new CryptoError('hello without a client id')
  const box = unb64u(hello.cidBox)
  if (box.length < 12 + 16) throw new CryptoError('hello does not open')
  const ce = unb64u(hello.ce)
  const key = await helloKey(await dh(host.privateKey, ce), host.publicKey, ce)
  try {
    return dec.decode(await subtle.decrypt({ name: 'AES-GCM', iv: box.subarray(0, 12) }, key, box.subarray(12)))
  } catch {
    throw new CryptoError('hello does not open')
  }
}

/**
 * Host: answer a hello from a known client (`clientPub`, looked up by helloClientId).
 * The client is authenticated by its first record decrypting (only the holder of
 * its static key can derive `se`).
 */
export async function sessionHostAccept(
  host: KeyPair,
  clientPub: Bytes,
  hello: ClientHello,
  welcome: unknown
): Promise<{ channel: Channel; reply: { t: 'hello-ok'; he: string; box: string } }> {
  const ce = unb64u(hello.ce)
  const cid = await keyId(clientPub)
  const he = await generateKeyPair()
  const es = await dh(host.privateKey, ce)
  const ee = await dh(he.privateKey, ce)
  const se = await dh(he.privateKey, clientPub)
  const keys = await sessionKeys(es, ee, se, cid, ce, he.publicKey, host.publicKey)
  const channel = await Channel.create(keys.h2c, keys.c2h)
  return { channel, reply: { t: 'hello-ok', he: b64u(he.publicKey), box: await channel.seal(welcome) } }
}
