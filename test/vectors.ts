// Known-answer vectors from the TypeScript protocol, for other implementations (the
// iOS app's ConvokeKit) to reproduce byte for byte: node test/vectors.ts > vectors.json
import { b64u, Channel, hostFingerprint, hostIdFor, keyId, unb64u } from '../protocol/crypto.ts'

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

process.stdout.write(
  JSON.stringify({ sendKey: b64u(sendKey), recvKey: b64u(recvKey), pub: b64u(pub), keyId: await keyId(pub), hostId: await hostIdFor(pub), fingerprint: await hostFingerprint(pub), records, roundTrip: b64u(unb64u(b64u(pub))) }, null, 2) + '\n'
)
