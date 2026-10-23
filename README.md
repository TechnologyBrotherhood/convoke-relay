# convoke-relay

The relay for [Convoke](https://cnvk.si), a Mac IDE of task streams. Your Mac and the
Convoke iPhone app both connect *out* to the relay, so neither needs to accept incoming
connections. The relay passes traffic between them.

The relay is **untrusted by design**. Everything between the Mac and a phone is
end-to-end encrypted, and the relay only ever handles ciphertext. Convoke runs one at
`https://relay.cnvk.si`, which is the default, and you can run your own with the code
in this repo.

This repo also holds the remote protocol in TypeScript (`protocol/`), which the Mac app
uses. The iPhone app has a byte-compatible Swift port, checked against the
known-answer vectors in `test/vectors.ts`.

## What the relay can and can't see

The endpoints do the cryptography (`protocol/crypto.ts`, `protocol/session.ts`):

- **Pairing:** the Mac shows a QR code holding a one-time 16-byte code, valid for 5
  minutes, plus its public key. The code never reaches the relay; it's used as a
  pre-shared key, so a relay can't pair itself in between.
- **Sessions:** each connection does an X25519 handshake (static and ephemeral keys,
  Noise-KK-like `es+ee+se`), then derives AES-256-GCM keys with HKDF-SHA256, one per
  direction. Records carry counters, and each side accepts only the next one, so a
  relay can't replay, reorder or drop records unnoticed.

A relay operator **can't** read or change what you type, your terminal output, your
agent conversations, approvals, URLs, or your Mac's or phone's names. It **can** see
metadata:

- your Mac's host id: a hash of its public key, stable while it stays paired
- a SHA-256 hash of the Mac's relay secret (`claims.json`), so nobody else can take its id
- the IP addresses of the Mac and the phones, when they connect, and how long they stay connected
- the size and timing of encrypted records, and how many devices are connected

It logs when a Mac connects or disconnects (with a short prefix of its id), plus
refusals: rate limiting, failed authentication and dropped connections, each with the
IP address involved. It stores nothing besides `claims.json`.

## Run your own

You need a machine with a public address, a domain name, and Docker.

```sh
git clone https://github.com/TechnologyBrotherhood/convoke-relay
cd convoke-relay/deploy/selfhost
# Point an A/AAAA record for relay.example.com at this machine, and open ports 80 and 443.
RELAY_DOMAIN=relay.example.com docker compose up -d --build
curl https://relay.example.com/health    # → ok
```

`compose.yaml` builds the relay from this checkout and puts
[Caddy](https://caddyserver.com) in front of it. Caddy gets a Let's Encrypt
certificate and terminates TLS; the Convoke apps only connect to `https` relays.

Then point Convoke at it. On the Mac, add this to `~/.config/convoke/config` (Convoke
picks the change up when you save):

```
remote-relay = https://relay.example.com
```

The iPhone app needs no setting: a pairing link names its relay, so a phone uses
whichever relay its Mac paired it through. Phones paired before the change still use
the old relay, so pair them again.

### Without Docker

The relay is a single static Go binary (Go 1.25+):

```sh
go build -o relay .
./relay -addr 127.0.0.1:8080 -data /var/lib/convoke-relay -web ./web
```

Put any reverse proxy that handles TLS and WebSockets in front of it: Caddy, or nginx
with `proxy_http_version 1.1`, the `Upgrade`/`Connection` headers, and a long
`proxy_read_timeout`, since the relay pings every 30 s. The proxy should append the
client address to `X-Forwarded-For`, which nginx does with
`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for`.

### Settings

Every flag can also be set with an environment variable.

| Flag | Environment | Default | What it does |
|---|---|---|---|
| `-addr` | `RELAY_ADDR` | `:8080` | Listen address (plain HTTP; TLS is the proxy's job). |
| `-data` | `RELAY_DATA` | memory only | Directory for `claims.json`. Without it, a restart frees every host id. |
| `-web` | `RELAY_WEB` | none | Directory with the pairing hand-off page (`web/`), shown when a pairing link is opened in a browser. |
| `-trusted-proxies` | `RELAY_TRUSTED_PROXIES` | `private` | Which peers' `X-Forwarded-For` gives the client address for rate limiting: `private` (private and loopback addresses, e.g. a proxy on the same machine or Docker network), `none` (no proxy; the relay faces clients directly), or comma-separated CIDRs. |
| `-trust-cf-header` | `RELAY_TRUST_CF_HEADER=1` | off | Behind a Cloudflare tunnel: take the client address from `CF-Connecting-IP` when the request came through a trusted proxy. With `RELAY_CF_EDGE_SECRET` set, the request must also carry that value in `X-Relay-Edge`, added by a Cloudflare transform rule. |

Limits are in `DefaultLimits` in `hub.go`: 1 MiB frames, 16 devices per Mac, and 60
connections per IP per minute. Host ids unused for a year are forgotten.

## Develop

```sh
go test ./...                       # relay
npm install && npm test             # protocol: crypto, sessions, and an end-to-end run against the Go relay
```

`test/fake-host.ts` runs a scripted Mac against a relay, which the iPhone app's tests use.

## The relay.cnvk.si deployment

`skybuild.toml`, `deploy/k8s/` and `bin/deploy` are how Convoke's own relay runs: k3s
behind a Cloudflare tunnel. They're here for transparency; for your own relay, use
`deploy/selfhost/`.

## License

Apache-2.0. See `LICENSE`.
