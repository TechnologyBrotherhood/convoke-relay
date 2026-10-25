// What travels inside the encrypted channel, and the pairing link format.
// Versioned: bump PROTOCOL_VERSION for incompatible changes.

export const PROTOCOL_VERSION = 1

export type AttentionKind = 'failed' | 'notify' | 'bell' | 'done' | 'approval'

export interface RemotePane {
  id: number
  kind: 'terminal' | 'web'
  title: string
  cwd?: string
  url?: string
  attention?: { kind: AttentionKind; text: string }
  /** Percent 0-100, or -1 when indeterminate. */
  progress?: number
  /** The agent running here, if an integration has registered one (e.g. "claude"). */
  agent?: string
  /**
   * An agent runs here without its Convoke integration, so there's no chat: `install`
   * (the integration isn't installed on the Mac) or `restart` (it is, but this session
   * started before it was).
   */
  agentSetup?: 'install' | 'restart'
  /** The agent `agentSetup` is about ("claude" when absent, "omp", "codex"). */
  setupAgent?: string
}

export interface RemoteTab {
  id: number
  panes: RemotePane[]
  focused: number
}

export interface RemoteStream {
  id: string
  name: string
  tabs: RemoteTab[]
}

/** A permission request from an agent integration, answerable from any device. */
export interface Approval {
  id: string
  pane: number
  agent: string
  tool: string
  /** One-line human summary, e.g. "Run: npm test". */
  summary: string
  /** Fuller detail (command, diff preview, …), may be long. */
  detail?: string
  createdAt: number
}

/**
 * One entry of an agent's conversation, for the chat view. Items are keyed by `id`:
 * a later item with the same id replaces the earlier one (e.g. a tool call gets its
 * result).
 */
export type ChatItem =
  | { id: string; k: 'user'; text: string; images?: number; queued?: boolean }
  /** Something that happened in the session rather than a message (a slash command, an interruption, a background task). */
  | { id: string; k: 'note'; text: string }
  /** Markdown. */
  | { id: string; k: 'assistant'; text: string }
  /** Folded by default. `text` is absent when the agent didn't record its thinking. */
  | { id: string; k: 'thinking'; text?: string; ms?: number }
  | {
      id: string
      k: 'tool'
      tool: string
      /** One line, e.g. "Ran npm test" or "Edited app.ts". */
      title: string
      /** The command, path, query, … in full. */
      detail?: string
      status: 'running' | 'ok' | 'error'
      /** Output, trimmed to a few KB (`truncated` says so). */
      output?: string
      truncated?: boolean
      /** Unified diff lines ("+", "-", " " prefixes) for file edits. */
      diff?: string[]
    }
  /** End of a turn: "Worked for 2m 3s". */
  | { id: string; k: 'turn'; ms: number }

/** What a paired device may do: everything, or only watch (no typing, keys or approvals). */
export type DeviceRole = 'full' | 'view'

/** The answer to a client's `layout`: what it made, or why not. */
export interface LayoutResult {
  t: 'result'
  rid: string
  error?: string
  stream?: string
  tab?: number
  pane?: number
}

export type HostMessage =
  /** `role`: what this device may do ("view": watch only; absent = full control). */
  | LayoutResult
  | { t: 'state'; host: string; streams: RemoteStream[]; active: { stream: string; tab: number | null }; role?: DeviceRole }
  /**
   * An agent pane's conversation: everything on subscribe (`reset`), then new and
   * changed items. `title`, `mode` (e.g. "default", "acceptEdits", "plan") and
   * `working` (mid-turn) describe the session as of this message.
   */
  | {
      t: 'chat'
      pane: number
      items: ChatItem[]
      reset?: boolean
      title?: string
      mode?: string
      working?: boolean
      /** The agent's model (as it names it, e.g. "claude-opus-5-5", "openai-codex/gpt-6.1-sol"). */
      model?: string
      /** Thinking level, where the agent has one (oh-my-pi: "off", "low", "medium", …). */
      thinking?: string
      /** Tokens in the context now, and the model's window when known. */
      context?: { used: number; limit?: number }
      /** Models to offer for switching: `command` is what to type (e.g. "/model opus", "/switch provider/id"). */
      models?: { label: string; command: string }[]
    }
  /** A terminal pane's visible text. (Web panes open on the device itself, from the URL in the state.) */
  | { t: 'screen'; pane: number; text: string; cols: number; rows: number }
  /**
   * A plain shell pane's commands, for a native view: on subscribe the recent ones
   * (`reset`), then each new or changed block (upserted by id).
   */
  | { t: 'blocks'; pane: number; items: ShellBlock[]; reset?: boolean }
  | { t: 'approvals'; items: Approval[] }
  /** An `upload` arrived whole and was saved (or why not): `text` can now name it in `files`. */
  | { t: 'uploaded'; id: string; error?: string }
  | { t: 'error'; message: string }
  | { t: 'pong' }

/** One command in a shell pane: what ran, how it went, and its output (the end of it). */
export interface ShellBlock {
  id: string
  command: string
  /** When it started (ms since the epoch, the Mac's clock). */
  startedAt: number
  running: boolean
  /** Exit status, once it ended. */
  exit?: number
  /** How long it ran, once it ended. */
  ms?: number
  output: string
  /** Only the end of the output is kept. */
  truncated?: boolean
}

/**
 * Raw bytes per `upload` chunk: base64 in the message, then sealed and base64 again,
 * comes to about 1.8x, well under the relay's 1 MiB client frame.
 */
export const UPLOAD_CHUNK_BYTES = 384 * 1024
/** The largest upload a Mac accepts. */
export const UPLOAD_MAX_BYTES = 32 * 1024 * 1024

/** Keys the remote keyboard row can send. */
export const REMOTE_KEYS = ['enter', 'escape', 'tab', 'backspace', 'up', 'down', 'left', 'right', 'ctrl-c', 'ctrl-d', 'shift-tab'] as const
export type RemoteKey = (typeof REMOTE_KEYS)[number]

export type ClientMessage =
  | { t: 'subscribe'; pane: number | null }
  /**
   * `typed`: key by key, as at the keyboard (not a paste): agents only run slash commands typed.
   * `files`: ids of finished uploads, dropped on the terminal before the text, as if
   * dragged there from Finder (agents attach images dropped that way).
   */
  | { t: 'text'; pane: number; text: string; submit?: boolean; typed?: boolean; files?: string[] }
  /**
   * A file (a photo, a document) for an agent, in chunks that each fit a relay frame:
   * `data` is base64 of bytes `seq * UPLOAD_CHUNK_BYTES` onwards. `size` is the whole
   * file's. The Mac answers the last chunk with `uploaded`.
   */
  | { t: 'upload'; id: string; name: string; size: number; seq: number; data: string; last?: boolean }
  | { t: 'key'; pane: number; key: RemoteKey }
  | { t: 'decide'; id: string; allow: boolean }
  | { t: 'ping' }
  /**
   * Change the Mac's layout (answered with a `result` carrying the same `rid`). Made in
   * the background: the Mac's own view doesn't switch. `run` is typed into a new
   * terminal's shell (e.g. "claude"); `url` makes a web tab.
   */
  | ({ t: 'layout'; rid: string } & (
      | { op: 'new-stream'; name: string }
      | { op: 'new-tab'; stream: string; url?: string; run?: string; cwd?: string; title?: string }
      | { op: 'close-tab'; tab: number }
    ))

/** What a pairing QR / link carries. */
export interface PairingInfo {
  relay: string // e.g. https://convoke.skybright.dev
  host: string // host id on the relay
  hostPub: string // b64u X25519 public key
  code: string // b64u one-time pairing secret
  name: string // host display name
}

/** `https://<relay>/#pair=<b64u(json)>`: the phone's camera opens the web client directly. */
export function pairingLink(p: PairingInfo): string {
  const payload = btoa(JSON.stringify(p)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  return `${p.relay.replace(/\/$/, '')}/#pair=${payload}`
}

export function parsePairingLink(link: string): PairingInfo | null {
  const m = /#pair=([A-Za-z0-9_-]+)/.exec(link)
  if (!m) return null
  try {
    const s = m[1].replace(/-/g, '+').replace(/_/g, '/')
    const p = JSON.parse(atob(s + '='.repeat((4 - (s.length % 4)) % 4))) as PairingInfo
    const ok =
      [p.relay, p.host, p.hostPub, p.code, p.name].every((v) => typeof v === 'string') &&
      safeRelay(p.relay) &&
      /^[A-Za-z0-9_-]{16,64}$/.test(p.host) &&
      b64uLength(p.hostPub) === 32 &&
      b64uLength(p.code) === 16
    return ok ? { relay: p.relay, host: p.host, hostPub: p.hostPub, code: p.code, name: p.name.slice(0, 80) } : null
  } catch {
    return null
  }
}

/**
 * Whether a relay URL from a pairing link is acceptable: https with a plain host name
 * (no credentials, query or fragment). Plain http only to this machine, for tests.
 * A link is attacker-controllable (a QR anyone can print), so this is checked before
 * connecting anywhere.
 */
export function safeRelay(relay: string): boolean {
  let u: URL
  try {
    u = new URL(relay)
  } catch {
    return false
  }
  if (u.username || u.password || u.search || u.hash || !u.hostname) return false
  if (u.protocol === 'https:') return true
  return u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname)
}

/** Decoded length of a base64url string, or -1 if it isn't one. */
function b64uLength(s: string): number {
  if (!/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) return -1
  return Math.floor((s.length * 3) / 4)
}
