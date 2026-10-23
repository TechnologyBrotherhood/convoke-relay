// Relay sessions for both ends, over the platform WebSocket (browsers, Electron, Node ≥22).
//
// A client connection carries, in order:
//   pairing (first time only)   c→h {t:'pair', ce, box}      h→c {t:'pair-ok', box}
//   handshake                   c→h {t:'hello', cid, ce}     h→c {t:'hello-ok', he, box}
//   records                     both ways {t:'rec', r: <sealed message>}
//   errors (plaintext, then the host kicks the connection)    h→c {t:'error', code}

import {
  b64u,
  type Bytes,
  Channel,
  type ClientHello,
  type KeyPair,
  generateKeyPair,
  helloClientId,
  hostIdMatchesKey,
  isKeyBoundHostId,
  keyId,
  pairClientStart,
  pairHostAccept,
  randomBytes,
  relayAuthProof,
  sessionClientStart,
  sessionHostAccept,
  unb64u
} from './crypto.ts'
import { PROTOCOL_VERSION, type ClientMessage, type DeviceRole, type HostMessage, type PairingInfo } from './messages.ts'

export interface PairedClient {
  cid: string
  pub: string // b64u
  name: string
  pairedAt: number
  /** Paired with a code that needs approval: no sessions until someone approves it. */
  pending?: boolean
  /** What the device may do (absent = full control). Enforced by the host app. */
  role?: DeviceRole
}

function wsUrl(relay: string, path: string): string {
  return relay.replace(/^http/, 'ws').replace(/\/$/, '') + path
}

// ---------------------------------------------------------------------------------------
// Host (the Mac)

export interface HostOptions {
  relay: string
  hostId: string
  hostSecret: string
  hostName: string
  key: KeyPair
  /** Known clients, by cid. */
  clients: () => PairedClient[]
  /** A device just paired: persist it. */
  onPaired: (c: PairedClient) => void
  onMessage: (conn: number, client: PairedClient, msg: ClientMessage) => void
  onSession: (conn: number, client: PairedClient | null) => void // null = session ended
  /** The client proved it holds its key (its first record decrypted): only now is it a live device. */
  onVerified?: (conn: number, client: PairedClient) => void
  onStatus: (s: 'connecting' | 'online' | 'offline', detail?: string) => void
}

interface PendingCode {
  code: Bytes
  expires: number
  /** A device paired with this code is pending until approved (see PairedClient.pending). */
  approval?: boolean
}

/**
 * A connection whose device hasn't proved its key (its first record decrypted) this soon
 * after opening is dropped: until then it only holds one of the host's relay slots, and
 * a hello alone proves nothing (the key id it names isn't secret).
 */
const HANDSHAKE_TIMEOUT_MS = 10_000

interface ConnState {
  channel?: Channel
  client?: PairedClient
  /** Set once a record from the client decrypts: the hello alone only names a key id, which isn't secret. */
  verified?: boolean
  /** A hello is being answered: a second one (even a concurrent one) is refused. */
  hello?: boolean
  /** A pairing request is being checked: one per connection. */
  pairing?: boolean
  /** Answered with a decoy (an unknown device): nothing it sends can open. */
  decoy?: boolean
  timer?: ReturnType<typeof setTimeout>
}

/** The host side: one socket to the relay, many client connections multiplexed over it. */
export class RelayHost {
  private ws: WebSocket | null = null
  private conns = new Map<number, ConnState>()
  private codes: PendingCode[] = []
  private stopped = false
  private retry = 0
  private opts: HostOptions

  constructor(opts: HostOptions) {
    this.opts = opts
  }

  start(): void {
    this.stopped = false
    this.connect()
  }

  stop(): void {
    this.stopped = true
    this.ws?.close()
    this.ws = null
  }

  get connected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN
  }

  /** Clients with an established session right now. */
  sessions(): { conn: number; client: PairedClient }[] {
    return [...this.conns].filter(([, s]) => s.channel && s.client && s.verified).map(([conn, s]) => ({ conn, client: s.client! }))
  }

  /** A fresh one-time pairing code (valid for `ttlMs`) and the link/QR payload for it. */
  newPairing(ttlMs = 5 * 60_000, opts: { approval?: boolean } = {}): PairingInfo {
    const code = globalThis.crypto.getRandomValues(new Uint8Array(16))
    this.codes = this.codes.filter((c) => c.expires > Date.now())
    this.codes.push({ code, expires: Date.now() + ttlMs, approval: opts.approval })
    return { relay: this.opts.relay, host: this.opts.hostId, hostPub: b64u(this.opts.key.publicKey), code: b64u(code), name: this.opts.hostName }
  }

  cancelPairing(): void {
    this.codes = []
  }

  /** Send to one client, or to every live session (only ever to a device that has proved its key). */
  async send(conn: number | 'all', msg: HostMessage): Promise<void> {
    const targets = conn === 'all' ? [...this.conns.keys()] : [conn]
    for (const c of targets) {
      const st = this.conns.get(c)
      if (!st?.channel || !st.verified) continue
      this.raw(c, { t: 'rec', r: await st.channel.seal(msg) })
    }
  }

  /** Drop every session of a client after revoking it, telling it why. */
  disconnectClient(cid: string): void {
    for (const [conn, st] of this.conns) if (st.client?.cid === cid) this.kick(conn, 'revoked')
  }

  private raw(conn: number, data: unknown): void {
    this.ws?.send(JSON.stringify({ t: 'msg', conn, data: JSON.stringify(data) }))
  }

  private kick(conn: number, code?: string): void {
    if (code) this.raw(conn, { t: 'error', code })
    this.ws?.send(JSON.stringify({ t: 'kick', conn }))
    this.end(conn)
  }

  private end(conn: number): void {
    const st = this.conns.get(conn)
    this.conns.delete(conn)
    if (st?.timer) clearTimeout(st.timer)
    if (st?.client && st.verified) this.opts.onSession(conn, null)
  }

  private connect(): void {
    if (this.stopped) return
    this.opts.onStatus('connecting')
    const ws = new WebSocket(wsUrl(this.opts.relay, `/v1/host?id=${encodeURIComponent(this.opts.hostId)}`))
    this.ws = ws
    // A key-bound id answers the relay's challenge with a proof of the key; any other id
    // presents its secret straight away.
    const keyBound = isKeyBoundHostId(this.opts.hostId)
    ws.onopen = () => {
      if (!keyBound) ws.send(JSON.stringify({ t: 'auth', secret: this.opts.hostSecret }))
    }
    // Frames are handled one at a time, in arrival order: handling awaits crypto, and a
    // later frame must never overtake an earlier one.
    let frames: Promise<void> = Promise.resolve()
    ws.onmessage = (ev) => (frames = frames.then(() => this.onFrame(String(ev.data))).catch(() => {}))
    ws.onclose = (ev) => {
      if (this.ws !== ws) return
      for (const conn of [...this.conns.keys()]) this.end(conn)
      this.ws = null
      this.opts.onStatus('offline', ev.code === 4403 ? 'host id claimed by another key' : ev.reason || `closed (${ev.code})`)
      if (this.stopped || ev.code === 4403) return
      const delay = Math.min(30_000, 1000 * 2 ** this.retry++) * (0.75 + Math.random() / 2)
      setTimeout(() => this.connect(), delay)
    }
  }

  private async onFrame(text: string): Promise<void> {
    let f: { t: string; conn?: number; data?: string; e?: string; n?: string }
    try {
      f = JSON.parse(text)
    } catch {
      return
    }
    if (f.t === 'challenge') {
      if (isKeyBoundHostId(this.opts.hostId) && typeof f.e === 'string' && typeof f.n === 'string') {
        const proof = await relayAuthProof(this.opts.key, this.opts.hostId, f.e, f.n)
        this.ws?.send(JSON.stringify({ t: 'auth', pub: b64u(this.opts.key.publicKey), proof }))
      }
      return
    }
    if (f.t === 'ready') {
      this.retry = 0
      this.opts.onStatus('online')
      return
    }
    if (f.conn === undefined) return
    if (f.t === 'open') {
      const conn = f.conn
      const st: ConnState = {}
      st.timer = setTimeout(() => {
        if (this.conns.get(conn) === st && !st.verified) this.kick(conn, 'timeout')
      }, HANDSHAKE_TIMEOUT_MS)
      this.conns.set(conn, st)
    }
    else if (f.t === 'close') this.end(f.conn)
    else if (f.t === 'msg' && f.data !== undefined) await this.onClientData(f.conn, f.data)
  }

  private async onClientData(conn: number, data: string): Promise<void> {
    const st = this.conns.get(conn)
    if (!st) return
    let m: { t: string; [k: string]: unknown }
    try {
      m = JSON.parse(data)
    } catch {
      return this.kick(conn, 'malformed')
    }
    try {
      // One pairing attempt per connection, and never on one that has started a session.
      if (m.t === 'pair' && !st.hello && !st.pairing) return await this.onPair(conn, st, m as unknown as { ce: string; box: string })
      if (m.t === 'hello' && !st.hello && !st.pairing) return await this.onHello(conn, st, m as unknown as ClientHello)
      if (m.t === 'rec' && st.channel && st.client && typeof m.r === 'string') {
        const client = st.client
        const msg = await st.channel.open<ClientMessage>(m.r)
        // Revoked (or the connection ended) while this record was being decrypted: drop it.
        if (!this.current(conn, st)) return
        if (!st.verified) {
          // It proved its key: only now may it learn it's pending, or count as a session.
          const now = this.opts.clients().find((c) => c.cid === client.cid && c.pub === client.pub)
          if (now?.pending) return this.kick(conn, 'pending-approval')
          if (!this.authorized(client)) return this.kick(conn, 'revoked')
          st.verified = true
          if (st.timer) clearTimeout(st.timer)
          // The relay keeps verified connections when the host's slots are full.
          this.ws?.send(JSON.stringify({ t: 'verified', conn }))
          this.opts.onVerified?.(conn, client)
          this.opts.onSession(conn, client)
        }
        if (!this.authorized(client)) return this.kick(conn, 'revoked')
        return this.opts.onMessage(conn, client, msg)
      }
      // A decoy session (unknown device): its records can't open; drop it like any other bad record.
      if (m.t === 'rec' && st.decoy) return this.kick(conn, 'crypto')
      this.kick(conn, 'unexpected')
    } catch {
      this.kick(conn, 'crypto')
    }
  }

  /** Whether `st` is still the live state of `conn` (it may have ended during an await). */
  private current(conn: number, st: ConnState): boolean {
    return this.conns.get(conn) === st
  }

  /** Whether a device is still paired and approved (it may have been revoked during an await). */
  private authorized(client: PairedClient): boolean {
    return this.opts.clients().some((c) => c.cid === client.cid && c.pub === client.pub && !c.pending)
  }

  private async onPair(conn: number, st: ConnState, m: { ce: string; box: string }): Promise<void> {
    st.pairing = true
    for (const pending of this.codes.filter((c) => c.expires > Date.now())) {
      let r: Awaited<ReturnType<typeof pairHostAccept>>
      let cid: string
      try {
        r = await pairHostAccept(this.opts.key, pending.code, m, this.opts.hostName)
        cid = await keyId(r.clientPub)
      } catch {
        continue // not this code; try the next (a wrong guess doesn't use up a code)
      }
      if (!this.current(conn, st)) return
      // Claim the code with no await in between: of concurrent requests with one code,
      // only the first to get here pairs. Cancelled or expired meanwhile counts as gone.
      if (!this.codes.includes(pending) || pending.expires <= Date.now()) break
      this.codes = this.codes.filter((c) => c !== pending)
      this.opts.onPaired({ cid, pub: b64u(r.clientPub), name: r.name || 'Device', pairedAt: Date.now(), ...(pending.approval && { pending: true }) })
      this.raw(conn, r.reply)
      return
    }
    this.kick(conn, 'bad-code')
  }

  /**
   * Answer a hello. Nothing about the device is revealed until it proves its key with a
   * record: an unknown device gets a decoy reply shaped like a real one (its welcome just
   * won't open), and a pending or revoked one is told so only after proving its key. So a
   * hello can't be used to learn which device ids exist.
   */
  private async onHello(conn: number, st: ConnState, hello: ClientHello): Promise<void> {
    st.hello = true
    const cid = await helloClientId(this.opts.key, hello)
    if (!this.current(conn, st)) return
    const welcome = { v: PROTOCOL_VERSION, host: this.opts.hostName }
    const client = this.opts.clients().find((c) => c.cid === cid)
    if (!client) {
      const decoy = await Channel.create(randomBytes(32), randomBytes(32))
      const he = await generateKeyPair()
      if (!this.current(conn, st)) return
      st.decoy = true
      this.raw(conn, { t: 'hello-ok', he: b64u(he.publicKey), box: await decoy.seal(welcome) })
      return // the handshake timeout drops it
    }
    const { channel, reply } = await sessionHostAccept(this.opts.key, unb64u(client.pub), hello, welcome)
    // The connection ended while the handshake was being computed.
    if (!this.current(conn, st)) return
    st.channel = channel
    st.client = client
    this.raw(conn, reply)
  }
}

// ---------------------------------------------------------------------------------------
// Client (phone / browser)

export interface ClientIdentity {
  key: KeyPair
  relay: string
  host: string
  hostPub: string
  hostName: string
}

export interface ClientOptions {
  identity: ClientIdentity
  onMessage: (msg: HostMessage) => void
  onStatus: (s: 'connecting' | 'online' | 'offline' | 'host-offline' | 'unpaired', detail?: string) => void
}

/** Pair once with a scanned/linked code; returns what the client should store. */
export async function pairWithHost(key: KeyPair, info: PairingInfo, deviceName: string): Promise<ClientIdentity> {
  // The host id must be the one its key derives: a link with someone else's key and the
  // Mac's id (or the other way round) is forged.
  if (!(await hostIdMatchesKey(info.host, unb64u(info.hostPub)))) throw new Error("This pairing link doesn't match its Mac's key")
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl(info.relay, `/v1/client?host=${encodeURIComponent(info.host)}`))
    let finish: ((reply: { box: string }) => Promise<{ hostName: string }>) | null = null
    ws.onopen = async () => {
      const start = await pairClientStart(key, unb64u(info.hostPub), unb64u(info.code), deviceName)
      finish = start.finish
      ws.send(JSON.stringify(start.message))
    }
    ws.onmessage = async (ev) => {
      const m = JSON.parse(String(ev.data))
      if (m.t === 'pair-ok' && finish) {
        try {
          const { hostName } = await finish(m)
          ws.close()
          resolve({ key, relay: info.relay, host: info.host, hostPub: info.hostPub, hostName: hostName || info.name })
        } catch {
          reject(new Error('The Mac answered with the wrong key'))
        }
      } else if (m.t === 'error') {
        reject(new Error(m.code === 'bad-code' ? 'This pairing code has expired or was already used' : `Pairing failed (${m.code})`))
      }
    }
    ws.onclose = (ev) => {
      if (ev.code === 4404) reject(new Error('Your Mac is offline (Convoke not running, or remote access off)'))
      else reject(new Error(`Connection closed (${ev.code})`))
    }
  })
}

/** A client session that reconnects (with backoff) until stopped. */
/** A client whose handshake hasn't finished this soon after connecting starts over. */
const CLIENT_HANDSHAKE_TIMEOUT_MS = 15_000
/** How often a device told it was removed checks again (the message isn't authenticated). */
const UNPAIRED_RETRY_MS = 60_000
/** How often a device waiting for approval checks again. */
const PENDING_RETRY_MS = 5_000

export class RelayClient {
  private ws: WebSocket | null = null
  private channel: Channel | null = null
  private stopped = false
  private retry = 0
  private opts: ClientOptions

  constructor(opts: ClientOptions) {
    this.opts = opts
  }

  start(): void {
    this.stopped = false
    this.connect()
  }

  stop(): void {
    this.stopped = true
    this.ws?.close()
  }

  /** Send a message; resolves false if it couldn't leave this device (not connected). */
  async send(msg: ClientMessage): Promise<boolean> {
    if (!this.channel || this.ws?.readyState !== WebSocket.OPEN) return false
    const ws = this.ws
    const record = await this.channel.seal(msg)
    if (ws.readyState !== WebSocket.OPEN) return false
    ws.send(JSON.stringify({ t: 'rec', r: record }))
    return true
  }

  private connect(): void {
    if (this.stopped) return
    const id = this.opts.identity
    this.opts.onStatus('connecting')
    const ws = new WebSocket(wsUrl(id.relay, `/v1/client?host=${encodeURIComponent(id.host)}`))
    this.ws = ws
    this.channel = null
    // This connection's channel: records arriving on an older socket never reach a newer one.
    let channel: Channel | null = null
    let finish: ((r: { he: string; box: string }) => Promise<{ channel: Channel; welcome: unknown }>) | null = null
    // Plaintext, so anyone in between (the relay) can send it: it's reported, never acted
    // on beyond retrying slowly. Only the user forgets a Mac.
    let unpaired = false
    let pendingApproval = false
    // A handshake that doesn't finish in time (a lost or withheld reply) starts over.
    const deadline = setTimeout(() => {
      if (!channel) ws.close()
    }, CLIENT_HANDSHAKE_TIMEOUT_MS)
    ws.onopen = async () => {
      const start = await sessionClientStart(id.key, unb64u(id.hostPub))
      finish = start.finish
      ws.send(JSON.stringify(start.message))
    }
    // One frame at a time, in order: finishing the handshake awaits crypto, and the host's
    // first record may arrive meanwhile; it must wait for the channel, not be dropped.
    let frames: Promise<void> = Promise.resolve()
    ws.onmessage = (ev) => (frames = frames.then(() => onFrame(ev)).catch(() => {}))
    const onFrame = async (ev: { data: unknown }): Promise<void> => {
      if (this.ws !== ws) return
      let m: { t?: string; code?: string; r?: unknown; he?: string; box?: string }
      try {
        m = JSON.parse(String(ev.data))
      } catch {
        return ws.close()
      }
      if (m.t === 'hello-ok' && finish) {
        // Single use: a replayed hello-ok must not rebuild the channel (counters back at 0 would reuse nonces).
        const complete = finish
        finish = null
        try {
          channel = (await complete(m as { he: string; box: string })).channel
          this.channel = channel
          this.retry = 0
          this.opts.onStatus('online')
          // Proves to the host that we hold our key, so it counts this device as live.
          void this.send({ t: 'ping' })
        } catch {
          // The welcome didn't open: the Mac doesn't know this device any more (it answers
          // unknown devices with a decoy), or something else is answering for it.
          unpaired = true
          ws.close()
        }
      } else if (m.t === 'rec' && channel && typeof m.r === 'string') {
        try {
          this.opts.onMessage(await channel.open<HostMessage>(m.r))
        } catch {
          ws.close()
        }
      } else if (m.t === 'error' && (m.code === 'unknown-client' || m.code === 'revoked')) {
        unpaired = true
      } else if (m.t === 'error' && m.code === 'pending-approval') {
        // Told after the handshake (once this device proved its key).
        pendingApproval = true
      }
    }
    ws.onclose = (ev) => {
      clearTimeout(deadline)
      if (this.ws !== ws) return
      this.channel = null
      if (unpaired) this.opts.onStatus('unpaired', "This device was removed on the Mac (or something else is answering for it)")
      else if (pendingApproval) this.opts.onStatus('offline', 'Waiting for approval on your Mac')
      else this.opts.onStatus(ev.code === 4404 ? 'host-offline' : 'offline', ev.reason)
      if (this.stopped) return
      const delay = unpaired ? UNPAIRED_RETRY_MS : pendingApproval ? PENDING_RETRY_MS : Math.min(15_000, 1000 * 2 ** this.retry++) * (0.75 + Math.random() / 2)
      setTimeout(() => this.connect(), delay)
    }
  }
}
