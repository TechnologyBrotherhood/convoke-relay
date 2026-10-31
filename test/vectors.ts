// Known-answer vectors from the TypeScript protocol, for other implementations (the
// iOS app's ConvokeKit) to reproduce byte for byte: node test/vectors.ts > vectors.json
import { b64u, Channel, hostFingerprint, hostIdFor, keyId, openPush, sealPush, unb64u } from '../protocol/crypto.ts'

const bytes = (n: number, seed: number): Uint8Array<ArrayBuffer> => Uint8Array.from({ length: n }, (_, i) => (i * 31 + seed) & 0xff)
const sendKey = bytes(32, 1)
const recvKey = bytes(32, 2)
const pub = bytes(32, 3)
const messages = [{ t: 'subscribe', pane: 12 }, { t: 'text', pane: 12, text: 'héllo ✓', submit: true }]

const sender = await Channel.create(sendKey, recvKey)
const records = []
for (const m of messages) records.push({ json: JSON.stringify(m), record: await sender.seal(m) })

// The other end decrypts with the keys swapped.
const receiver = await Channel.create(recvKey, sendKey)
for (const r of records) await receiver.open(r.record)

// A sealed push alert (fixed key and nonce), and that it opens.
const pushKey = bytes(32, 4)
const alert = { title: 'Wikipen: Blog post SEO', body: 'Claude needs your permission to use Bash ✓', pane: 271, host: 'h-1' }
const push = { key: b64u(pushKey), alert, sealed: await sealPush(pushKey, alert, bytes(12, 5)) }
if (JSON.stringify(await openPush(pushKey, push.sealed)) !== JSON.stringify(alert)) throw new Error('push vector does not open')

process.stdout.write(
  JSON.stringify({ sendKey: b64u(sendKey), recvKey: b64u(recvKey), pub: b64u(pub), keyId: await keyId(pub), hostId: await hostIdFor(pub), fingerprint: await hostFingerprint(pub), records, roundTrip: b64u(unb64u(b64u(pub))), push }, null, 2) + '\n'
)
