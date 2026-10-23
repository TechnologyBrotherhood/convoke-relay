package main

// The hub routes opaque, end-to-end encrypted frames between one host (a Convoke
// Mac) and its connected clients (phone, browser). It never sees plaintext:
// pairing and session keys are negotiated by the endpoints (protocol/crypto.ts).
//
// Host socket (/v1/host?id=<hostId>), JSON frames:
//   relay → host   {"t":"challenge","e":"…","n":"…"} on connect (for key-bound ids, see hostkey.go)
//   host → relay   {"t":"auth","secret":"…"}         first frame: claim/prove the host id
//                  {"t":"auth","pub":"…","proof":"…"}   (or, for a key-bound id, prove the key)
//                  {"t":"msg","conn":N,"data":"…"}   deliver data to client N
//                  {"t":"kick","conn":N}             disconnect client N
//                  {"t":"verified","conn":N}         client N proved its key (it keeps its slot when full)
//   relay → host   {"t":"ready"}                     auth accepted
//                  {"t":"open","conn":N}             client N connected
//                  {"t":"msg","conn":N,"data":"…"}   data from client N
//                  {"t":"close","conn":N}            client N went away
// Client socket (/v1/client?host=<hostId>): raw text frames, delivered verbatim.

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

type Limits struct {
	MaxMessage      int64         // bytes per frame from a client
	MaxHostMessage  int64         // bytes per frame from a host (it wraps client data, and is authenticated)
	MaxClients      int           // concurrent clients per host
	MaxClientsPerIP int           // concurrent clients per host from one IP
	MaxConnsPerIP   int           // concurrent connections (hosts and clients) from one IP, relay-wide
	SendQueue       int           // data frames buffered per connection before it's dropped as too slow
	QueueBytes      int64         // bytes buffered per connection before it's dropped as too slow
	HostQueueBytes  int64         // bytes buffered for one host and its clients together: one host can't spend the relay's budget
	TotalQueueBytes int64         // bytes buffered across the relay: past this, senders are dropped
	AuthTimeout     time.Duration // host must authenticate within this
	PingInterval    time.Duration
	ConnectsPerMin  int // new connections per client IP per minute
	ClientMsgRate   int // frames per second a client may send (burst: twice this)
	NewClaimsPerDay int // host ids one IP may claim per day
}

var DefaultLimits = Limits{
	MaxMessage:      1 << 20,
	MaxHostMessage:  4 << 20,
	MaxClients:      32,
	MaxClientsPerIP: 8,
	MaxConnsPerIP:   64,
	SendQueue:       256,
	QueueBytes:      8 << 20,
	HostQueueBytes:  32 << 20,  // a fifth of the total: a hostile host leaves room for everyone else
	TotalQueueBytes: 160 << 20, // the pod's memory limit is 256 MiB
	AuthTimeout:     10 * time.Second,
	PingInterval:    30 * time.Second,
	ConnectsPerMin:  60,
	ClientMsgRate:   50,
	NewClaimsPerDay: 10,
}

// controlReserve is queue room kept for control frames (open/close/ready), so a
// queue full of data never forces dropping the host to report a client coming or going.
const controlReserve = 128

// Close codes sent to clients (4000-4999 are application-defined).
const (
	closeHostOffline  websocket.StatusCode = 4404
	closeTooMany      websocket.StatusCode = 4429
	closeUnauthorized websocket.StatusCode = 4403
	closeReplaced     websocket.StatusCode = 4409
	closeKicked       websocket.StatusCode = 4410
	closeSlow         websocket.StatusCode = 4408
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)

type frame struct {
	T      string `json:"t"`
	Conn   uint64 `json:"conn,omitempty"`
	Data   string `json:"data,omitempty"`
	Secret string `json:"secret,omitempty"`
	Pub    string `json:"pub,omitempty"`
	Proof  string `json:"proof,omitempty"`
	E      string `json:"e,omitempty"`
	N      string `json:"n,omitempty"`
}

// conn is one websocket with a dedicated writer goroutine.
type conn struct {
	hub    *Hub
	ws     *websocket.Conn
	out    chan outFrame
	cancel context.CancelFunc
	once   sync.Once
	ip     string

	// Bytes queued and not yet written, counted here, in the group's total (a host and
	// its clients) and in the hub's.
	qmu    sync.Mutex
	queued int64
	group  *atomic.Int64
	done   bool // the writer has stopped: nothing more is queued

	verified bool // (clients) the host says it proved its key; guarded by the host's mu
}

// outFrame is data to write, or (closeCode != 0) a close that happens only after
// everything queued before it has been written.
type outFrame struct {
	data      []byte
	control   bool // doesn't count against the data limits
	closeCode websocket.StatusCode
	reason    string
}

// newConn makes a connection counted in group: the host's own, shared with its clients.
func (h *Hub) newConn(ws *websocket.Conn, cancel context.CancelFunc, ip string, group *atomic.Int64) *conn {
	return &conn{hub: h, ws: ws, out: make(chan outFrame, h.limits.SendQueue+controlReserve), cancel: cancel, ip: ip, group: group}
}

// trySend queues a data frame if it fits this connection's, its host's and the relay's
// limits; the caller decides what a full queue means. The host's limit comes first: a
// host whose clients don't read loses them before it can use up the relay's budget.
func (c *conn) trySend(b []byte) bool {
	n := int64(len(b))
	l := c.hub.limits
	c.qmu.Lock()
	defer c.qmu.Unlock()
	if c.done || len(c.out) >= l.SendQueue || c.queued+n > l.QueueBytes {
		return false
	}
	if c.group.Add(n) > l.HostQueueBytes {
		c.group.Add(-n)
		return false
	}
	if c.hub.queued.Add(n) > l.TotalQueueBytes {
		c.release(n)
		return false
	}
	select {
	case c.out <- outFrame{data: b}:
		c.queued += n
		return true
	default:
		c.release(n)
		return false
	}
}

// release uncounts n queued bytes from the group's and the hub's totals.
func (c *conn) release(n int64) {
	c.group.Add(-n)
	c.hub.queued.Add(-n)
}

// send queues a data frame; a connection that can't keep up is closed rather than
// letting it hold memory or stall everyone else.
func (c *conn) send(b []byte) bool {
	if c.trySend(b) {
		return true
	}
	c.close(closeSlow, "too slow")
	return false
}

// sendControl queues a small control frame in the room kept for them.
func (c *conn) sendControl(b []byte) {
	select {
	case c.out <- outFrame{data: b, control: true}:
	default:
		c.close(closeSlow, "too slow")
	}
}

func (c *conn) written(n int64) {
	c.qmu.Lock()
	c.queued -= n
	c.qmu.Unlock()
	c.release(n)
}

// stopped releases whatever is still queued once the writer has stopped.
func (c *conn) stopped() {
	c.qmu.Lock()
	c.done = true
	c.release(c.queued)
	c.queued = 0
	c.qmu.Unlock()
}

// closeAfterDrain closes once frames already queued are written, so a final
// message (e.g. the host's reason for kicking) isn't overtaken by the close.
func (c *conn) closeAfterDrain(code websocket.StatusCode, reason string) {
	select {
	case c.out <- outFrame{closeCode: code, reason: reason}:
	default:
		c.close(code, reason)
	}
}

// close never blocks: the closing handshake can wait seconds for the peer, and
// callers may hold the hub's locks (e.g. replacing a host).
func (c *conn) close(code websocket.StatusCode, reason string) {
	c.once.Do(func() {
		// Send the close frame (with its code) first, then tear down: cancelling
		// first would drop the socket before the peer learns why.
		go func() {
			c.ws.Close(code, reason)
			c.cancel()
		}()
	})
}

func (c *conn) writeLoop(ctx context.Context) {
	defer c.stopped()
	for {
		select {
		case <-ctx.Done():
			return
		case f := <-c.out:
			if f.closeCode != 0 {
				c.close(f.closeCode, f.reason)
				return
			}
			wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := c.ws.Write(wctx, websocket.MessageText, f.data)
			cancel()
			if !f.control {
				c.written(int64(len(f.data)))
			}
			if err != nil {
				c.close(websocket.StatusGoingAway, "write failed")
				return
			}
		}
	}
}

func (c *conn) pingLoop(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pctx, cancel := context.WithTimeout(ctx, every)
			err := c.ws.Ping(pctx)
			cancel()
			if err != nil {
				c.close(websocket.StatusGoingAway, "ping timeout")
				return
			}
		}
	}
}

type host struct {
	*conn
	id      string
	mu      sync.Mutex
	clients map[uint64]*conn
	next    uint64
	gone    bool // disconnected: no more clients may attach
}

type Hub struct {
	limits    Limits
	claims    *ClaimStore
	rate      *rateLimiter
	claimRate *rateLimiter
	queued    atomic.Int64 // bytes queued across all connections

	ipMu    sync.Mutex
	ipConns map[string]int

	// TrustedProxies are the peers whose X-Forwarded-For is believed; see clientIP.
	// nil means private and loopback addresses (a proxy on the same machine or network).
	TrustedProxies *ProxySet
	// TrustCFHeader: use CF-Connecting-IP as the client IP when the request came
	// through an in-cluster hop (cloudflared); see clientIP.
	TrustCFHeader bool
	// CFEdgeSecret, if set, must also arrive in cfEdgeHeader for CF-Connecting-IP to
	// count: it proves the request passed Cloudflare, not just some private address.
	CFEdgeSecret string

	mu    sync.Mutex
	hosts map[string]*host
}

func NewHub(limits Limits, claims *ClaimStore) *Hub {
	return &Hub{
		limits:    limits,
		claims:    claims,
		rate:      newRateLimiter(limits.ConnectsPerMin, time.Minute),
		claimRate: newRateLimiter(limits.NewClaimsPerDay, 24*time.Hour),
		ipConns:   map[string]int{},
		hosts:     map[string]*host{},
	}
}

// admitIP counts a connection from ip against the relay-wide per-IP limit; release with leaveIP.
func (h *Hub) admitIP(ip string) bool {
	h.ipMu.Lock()
	defer h.ipMu.Unlock()
	if h.ipConns[ip] >= h.limits.MaxConnsPerIP {
		return false
	}
	h.ipConns[ip]++
	return true
}

func (h *Hub) leaveIP(ip string) {
	h.ipMu.Lock()
	defer h.ipMu.Unlock()
	if h.ipConns[ip]--; h.ipConns[ip] <= 0 {
		delete(h.ipConns, ip)
	}
}

// CloseAll tells every connection the relay is going away (on shutdown), so endpoints
// reconnect promptly instead of waiting for pings to fail.
func (h *Hub) CloseAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, hc := range h.hosts {
		hc.mu.Lock()
		for _, c := range hc.clients {
			c.close(websocket.StatusGoingAway, "relay restarting")
		}
		hc.mu.Unlock()
		hc.close(websocket.StatusGoingAway, "relay restarting")
	}
}

func (h *Hub) accept(w http.ResponseWriter, r *http.Request, readLimit int64) (*websocket.Conn, error) {
	// Origin isn't checked: nothing here relies on ambient credentials (no cookies);
	// hosts prove a secret and all content is end-to-end encrypted.
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	ws.SetReadLimit(readLimit)
	return ws, nil
}

// marshal encodes a frame without HTML escaping: escaping turns each <, > or & in
// relayed data into six bytes, which would let a client inflate what the relay buffers.
func marshal(f frame) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(f)
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

// readText reads the next frame, which must be text: the protocol is JSON, and
// binary frames would be corrupted on the way through.
func readText(ctx context.Context, ws *websocket.Conn) ([]byte, error) {
	typ, data, err := ws.Read(ctx)
	if err != nil {
		return nil, err
	}
	if typ != websocket.MessageText {
		ws.Close(websocket.StatusUnsupportedData, "text frames only")
		return nil, errBinary
	}
	return data, nil
}

var errBinary = errors.New("binary frame")

// ServeHost handles /v1/host?id=…
func (h *Hub) ServeHost(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if !idPattern.MatchString(id) {
		http.Error(w, "bad host id", http.StatusBadRequest)
		return
	}
	ip := h.clientIP(r)
	if !h.rate.allow(ip) {
		slog.Warn("rate limited", "ip", ip, "route", "host")
		http.Error(w, "slow down", http.StatusTooManyRequests)
		return
	}
	if !h.admitIP(ip) {
		slog.Warn("too many connections from one ip", "ip", ip, "route", "host")
		http.Error(w, "too many connections", http.StatusTooManyRequests)
		return
	}
	defer h.leaveIP(ip)
	ws, err := h.accept(w, r, h.limits.MaxHostMessage)
	if err != nil {
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// A challenge first: a host with a key-bound id answers it with a proof of its key.
	// (Hosts using a secret ignore it.)
	ch, err := newChallenge()
	if err != nil {
		ws.Close(websocket.StatusInternalError, "")
		return
	}
	actx, acancel := context.WithTimeout(ctx, h.limits.AuthTimeout)
	if err := ws.Write(actx, websocket.MessageText, marshal(ch.frame())); err != nil {
		acancel()
		return
	}
	// First frame from the host: a key proof, or the secret that claims (first time) or
	// proves (afterwards) this id.
	data, err := readText(actx, ws)
	acancel()
	var auth frame
	if err != nil || json.Unmarshal(data, &auth) != nil || auth.T != "auth" {
		slog.Warn("host auth missing", "host", short(id), "ip", ip)
		ws.Close(closeUnauthorized, "auth required")
		return
	}
	if isKeyBoundID(id) {
		if !ch.verify(id, auth.Pub, auth.Proof) {
			slog.Warn("host key proof refused", "host", short(id), "ip", ip)
			ws.Close(closeUnauthorized, "key proof failed")
			return
		}
	} else {
		if len(auth.Secret) < 32 {
			slog.Warn("host auth missing", "host", short(id), "ip", ip)
			ws.Close(closeUnauthorized, "auth required")
			return
		}
		// Claiming a new id costs from a per-IP daily budget, so nobody can fill the store
		// with made-up ids and lock new hosts out.
		if !h.claims.Known(id) && !h.claimRate.allow(ip) {
			slog.Warn("new host id refused: claim budget spent", "host", short(id), "ip", ip)
			ws.Close(closeUnauthorized, "too many new host ids from this address")
			return
		}
		if !h.claims.Check(id, auth.Secret) {
			slog.Warn("host auth refused", "host", short(id), "ip", ip)
			ws.Close(closeUnauthorized, "id claimed by another host")
			return
		}
	}

	hc := &host{conn: h.newConn(ws, cancel, ip, new(atomic.Int64)), id: id, clients: map[uint64]*conn{}}
	h.mu.Lock()
	if old := h.hosts[id]; old != nil {
		old.close(closeReplaced, "replaced by a newer connection")
	}
	h.hosts[id] = hc
	h.mu.Unlock()
	slog.Info("host connected", "host", short(id))
	defer func() {
		h.mu.Lock()
		if h.hosts[id] == hc {
			delete(h.hosts, id)
		}
		h.mu.Unlock()
		hc.mu.Lock()
		hc.gone = true
		for _, c := range hc.clients {
			c.close(closeHostOffline, "host went away")
		}
		hc.mu.Unlock()
		hc.close(websocket.StatusNormalClosure, "")
		slog.Info("host disconnected", "host", short(id))
	}()

	go hc.writeLoop(ctx)
	go hc.pingLoop(ctx, h.limits.PingInterval)
	hc.sendControl(marshal(frame{T: "ready"}))

	for {
		data, err := readText(ctx, ws)
		if err != nil {
			return
		}
		var f frame
		if json.Unmarshal(data, &f) != nil {
			continue
		}
		hc.mu.Lock()
		c := hc.clients[f.Conn]
		hc.mu.Unlock()
		if c == nil {
			continue
		}
		switch f.T {
		case "msg":
			c.send([]byte(f.Data))
		case "kick":
			c.closeAfterDrain(closeKicked, "closed by host")
		case "verified":
			hc.mu.Lock()
			c.verified = true
			hc.mu.Unlock()
		}
	}
}

// ServeClient handles /v1/client?host=…
func (h *Hub) ServeClient(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("host")
	if !idPattern.MatchString(id) {
		http.Error(w, "bad host id", http.StatusBadRequest)
		return
	}
	ip := h.clientIP(r)
	if !h.rate.allow(ip) {
		slog.Warn("rate limited", "ip", ip, "route", "client")
		http.Error(w, "slow down", http.StatusTooManyRequests)
		return
	}
	if !h.admitIP(ip) {
		slog.Warn("too many connections from one ip", "ip", ip, "route", "client")
		http.Error(w, "too many connections", http.StatusTooManyRequests)
		return
	}
	defer h.leaveIP(ip)
	ws, err := h.accept(w, r, h.limits.MaxMessage)
	if err != nil {
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	h.mu.Lock()
	hc := h.hosts[id]
	h.mu.Unlock()
	if hc == nil {
		ws.Close(closeHostOffline, "host offline")
		return
	}
	cc := h.newConn(ws, cancel, ip, hc.group)
	hc.mu.Lock()
	// Checked under the host's lock: a host that left after the lookup above has
	// already closed its clients, and this one would never hear about it.
	if hc.gone {
		hc.mu.Unlock()
		ws.Close(closeHostOffline, "host offline")
		return
	}
	if reason := hc.admit(ip, h.limits); reason != "" {
		hc.mu.Unlock()
		slog.Warn("client refused", "host", short(id), "ip", ip, "reason", reason)
		ws.Close(closeTooMany, reason)
		return
	}
	hc.next++
	n := hc.next
	hc.clients[n] = cc
	hc.mu.Unlock()
	defer func() {
		hc.mu.Lock()
		if hc.clients[n] == cc {
			delete(hc.clients, n)
		}
		hc.mu.Unlock()
		hc.sendControl(marshal(frame{T: "close", Conn: n}))
		cc.close(websocket.StatusNormalClosure, "")
	}()

	go cc.writeLoop(ctx)
	go cc.pingLoop(ctx, h.limits.PingInterval)
	hc.sendControl(marshal(frame{T: "open", Conn: n}))
	bucket := newBucket(float64(h.limits.ClientMsgRate), float64(2*h.limits.ClientMsgRate))

	for {
		data, err := readText(ctx, ws)
		if err != nil {
			return
		}
		// A flooding client must lose its own connection, not take the host (and every
		// other client) down with it, so overflow here never closes the host socket.
		if !bucket.take() || !hc.trySend(marshal(frame{T: "msg", Conn: n, Data: string(data)})) {
			slog.Warn("client dropped: too fast", "host", short(id), "ip", ip)
			cc.close(closeSlow, "too fast")
			return
		}
	}
}

// admit makes room for a new client from ip, or says why not (hc.mu held). When every
// slot is taken, the oldest client that hasn't proved its key to the host is dropped
// for the newcomer: connections that never authenticate can't keep real devices out.
func (hc *host) admit(ip string, l Limits) string {
	fromIP := 0
	for _, c := range hc.clients {
		if c.ip == ip {
			fromIP++
		}
	}
	if fromIP >= l.MaxClientsPerIP {
		return "too many clients from this address"
	}
	if len(hc.clients) < l.MaxClients {
		return ""
	}
	var oldest uint64
	for n, c := range hc.clients {
		if !c.verified && (oldest == 0 || n < oldest) {
			oldest = n
		}
	}
	if oldest == 0 {
		return "too many clients"
	}
	victim := hc.clients[oldest]
	delete(hc.clients, oldest)
	slog.Warn("unverified client evicted for a newcomer", "host", short(hc.id), "ip", victim.ip)
	victim.close(closeTooMany, "evicted: never authenticated")
	return ""
}

func short(id string) string {
	if len(id) > 6 {
		return id[:6] + "…"
	}
	return id
}

// clientIP is the address to rate-limit. Trust follows the socket, never the Host
// header (the client picks that):
//   - a peer that isn't a trusted proxy is the client itself;
//   - a trusted peer is the reverse proxy, and the address it saw (the "hop") is the
//     last X-Forwarded-For entry (it appends; anything before that came from the client);
//   - CF-Connecting-IP counts only when the hop is a trusted proxy too (cloudflared
//     behind an ingress), and, with CFEdgeSecret set, the request carries the header
//     Cloudflare's edge adds.
func (h *Hub) clientIP(r *http.Request) string {
	peer := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		peer = host
	}
	if !h.TrustedProxies.Contains(peer) {
		return peer
	}
	hop := peer
	if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
		parts := strings.Split(xff[len(xff)-1], ",")
		if last := strings.TrimSpace(parts[len(parts)-1]); net.ParseIP(last) != nil {
			hop = last
		}
	}
	if h.TrustCFHeader && h.TrustedProxies.Contains(hop) && h.fromCFEdge(r) {
		if ip := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); net.ParseIP(ip) != nil {
			return ip
		}
	}
	return hop
}

// fromCFEdge reports whether the request carries the secret Cloudflare's edge adds
// (always true when none is configured). Needed because a private hop alone doesn't
// prove cloudflared: the node's load balancer masquerades tailnet and LAN clients to
// a pod address on their way to the ingress.
func (h *Hub) fromCFEdge(r *http.Request) bool {
	if h.CFEdgeSecret == "" {
		return true
	}
	got := r.Header.Get(cfEdgeHeader)
	return subtle.ConstantTimeCompare([]byte(got), []byte(h.CFEdgeSecret)) == 1
}

// cfEdgeHeader is set by a Cloudflare request-header transform rule to CFEdgeSecret.
const cfEdgeHeader = "X-Relay-Edge"

// ProxySet is the set of addresses trusted to report a client's address in
// X-Forwarded-For. A nil set means private and loopback addresses: a reverse proxy
// on the same machine or network. (Tailnet addresses are CGNAT, 100.64/10, which is
// neither, so tailnet clients count as clients.)
type ProxySet struct{ nets []*net.IPNet }

// ParseProxySet parses -trusted-proxies: "private" (the default), "none" (the relay
// faces clients directly), or comma-separated CIDRs and addresses.
func ParseProxySet(s string) (*ProxySet, error) {
	switch s = strings.TrimSpace(s); s {
	case "", "private":
		return nil, nil
	case "none":
		return &ProxySet{}, nil
	}
	set := &ProxySet{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			ip := net.ParseIP(part)
			if ip == nil {
				return nil, fmt.Errorf("trusted proxy %q: not an address or CIDR", part)
			}
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			part = fmt.Sprintf("%s/%d", ip, bits)
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: %v", part, err)
		}
		set.nets = append(set.nets, n)
	}
	return set, nil
}

// Contains reports whether s is an address of a trusted proxy.
func (p *ProxySet) Contains(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	if p == nil {
		return ip.IsPrivate() || ip.IsLoopback()
	}
	for _, n := range p.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
