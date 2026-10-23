package main

import (
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

const hostID = "host-0123456789abcdef"
const secret = "s3cret-0123456789-0123456789-0123456789"

func newTestRelay(t *testing.T, claims *ClaimStore) *httptest.Server {
	t.Helper()
	if claims == nil {
		claims, _ = NewClaimStore("")
	}
	srv := httptest.NewServer(routes(NewHub(DefaultLimits, claims), ""))
	t.Cleanup(srv.Close)
	return srv
}

func dial(t *testing.T, srv *httptest.Server, path string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+path, nil)
	if err != nil {
		t.Fatalf("dial %s: %v", path, err)
	}
	t.Cleanup(func() { ws.CloseNow() })
	// Hosts are challenged first (for key-bound ids); secret-based tests skip it.
	if strings.HasPrefix(path, "/v1/host") {
		if f := readFrame(t, ws); f.T != "challenge" {
			t.Fatalf("want challenge first, got %+v", f)
		}
	}
	return ws
}

func write(t *testing.T, ws *websocket.Conn, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	if s, ok := v.(string); ok {
		b = []byte(s)
	}
	if err := ws.Write(context.Background(), websocket.MessageText, b); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func read(t *testing.T, ws *websocket.Conn) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, b, err := ws.Read(ctx)
	return string(b), err
}

func readFrame(t *testing.T, ws *websocket.Conn) frame {
	t.Helper()
	s, err := read(t, ws)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var f frame
	json.Unmarshal([]byte(s), &f)
	return f
}

func connectHost(t *testing.T, srv *httptest.Server, sec string) *websocket.Conn {
	t.Helper()
	ws := dial(t, srv, "/v1/host?id="+hostID)
	write(t, ws, frame{T: "auth", Secret: sec})
	return ws
}

func closeCode(err error) websocket.StatusCode { return websocket.CloseStatus(err) }

func TestRoutesBothWaysAndReportsClose(t *testing.T) {
	srv := newTestRelay(t, nil)
	host := connectHost(t, srv, secret)
	if f := readFrame(t, host); f.T != "ready" {
		t.Fatalf("want ready, got %+v", f)
	}
	client := dial(t, srv, "/v1/client?host="+hostID)
	open := readFrame(t, host)
	if open.T != "open" || open.Conn == 0 {
		t.Fatalf("want open, got %+v", open)
	}
	write(t, client, "hello from client")
	if f := readFrame(t, host); f.T != "msg" || f.Data != "hello from client" || f.Conn != open.Conn {
		t.Fatalf("host got %+v", f)
	}
	write(t, host, frame{T: "msg", Conn: open.Conn, Data: "hello from host"})
	if s, _ := read(t, client); s != "hello from host" {
		t.Fatalf("client got %q", s)
	}
	client.Close(websocket.StatusNormalClosure, "")
	if f := readFrame(t, host); f.T != "close" || f.Conn != open.Conn {
		t.Fatalf("want close, got %+v", f)
	}
}

func TestClientToOfflineHost(t *testing.T) {
	srv := newTestRelay(t, nil)
	client := dial(t, srv, "/v1/client?host="+hostID)
	_, err := read(t, client)
	if closeCode(err) != closeHostOffline {
		t.Fatalf("want 4404, got %v", err)
	}
}

func TestWrongSecretCannotTakeAClaimedID(t *testing.T) {
	srv := newTestRelay(t, nil)
	h1 := connectHost(t, srv, secret)
	readFrame(t, h1)
	h2 := connectHost(t, srv, "another-secret-0123456789-0123456789")
	if _, err := read(t, h2); closeCode(err) != closeUnauthorized {
		t.Fatalf("want 4403, got %v", err)
	}
}

func TestReconnectReplacesOldHostAndDropsItsClients(t *testing.T) {
	srv := newTestRelay(t, nil)
	h1 := connectHost(t, srv, secret)
	readFrame(t, h1)
	c1 := dial(t, srv, "/v1/client?host="+hostID)
	readFrame(t, h1) // open
	h2 := connectHost(t, srv, secret)
	if f := readFrame(t, h2); f.T != "ready" {
		t.Fatalf("new host not ready: %+v", f)
	}
	if _, err := read(t, h1); closeCode(err) != closeReplaced {
		t.Fatalf("old host: want 4409, got %v", err)
	}
	if _, err := read(t, c1); closeCode(err) != closeHostOffline {
		t.Fatalf("old client: want 4404, got %v", err)
	}
}

func TestHostCanKickAClient(t *testing.T) {
	srv := newTestRelay(t, nil)
	host := connectHost(t, srv, secret)
	readFrame(t, host)
	client := dial(t, srv, "/v1/client?host="+hostID)
	open := readFrame(t, host)
	write(t, host, frame{T: "kick", Conn: open.Conn})
	if _, err := read(t, client); closeCode(err) != closeKicked {
		t.Fatalf("want 4410, got %v", err)
	}
}

func TestAuthRequired(t *testing.T) {
	srv := newTestRelay(t, nil)
	ws := dial(t, srv, "/v1/host?id="+hostID)
	write(t, ws, frame{T: "auth", Secret: "short"})
	if _, err := read(t, ws); closeCode(err) != closeUnauthorized {
		t.Fatalf("want 4403, got %v", err)
	}
}

func TestClaimsPersistAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "claims.json")
	s1, _ := NewClaimStore(path)
	if !s1.Check(hostID, secret) {
		t.Fatal("first claim should succeed")
	}
	s2, err := NewClaimStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Check(hostID, "someone-else-0123456789-0123456789") {
		t.Fatal("a restart must not free a claimed id")
	}
	if !s2.Check(hostID, secret) {
		t.Fatal("the owner must still get in")
	}
}

func TestHealth(t *testing.T) {
	srv := newTestRelay(t, nil)
	resp, err := srv.Client().Get(srv.URL + "/health")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("health: %v %v", err, resp)
	}
}

func TestKickDeliversQueuedMessagesFirst(t *testing.T) {
	srv := newTestRelay(t, nil)
	host := connectHost(t, srv, secret)
	readFrame(t, host)
	client := dial(t, srv, "/v1/client?host="+hostID)
	open := readFrame(t, host)
	write(t, host, frame{T: "msg", Conn: open.Conn, Data: "last words"})
	write(t, host, frame{T: "kick", Conn: open.Conn})
	if s, err := read(t, client); s != "last words" {
		t.Fatalf("want the queued message before the close, got %q (%v)", s, err)
	}
	if _, err := read(t, client); closeCode(err) != closeKicked {
		t.Fatalf("want 4410 after it, got %v", err)
	}
}

func TestFloodingClientLosesItsOwnConnectionNotTheHost(t *testing.T) {
	srv := newTestRelay(t, nil)
	host := connectHost(t, srv, secret)
	readFrame(t, host)
	flooder := dial(t, srv, "/v1/client?host="+hostID)
	other := dial(t, srv, "/v1/client?host="+hostID)
	// Never read from the host: its frames pile up while the flooder keeps sending.
	var closed error
	for i := 0; i < 5000 && closed == nil; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if err := flooder.Write(ctx, websocket.MessageText, []byte("x")); err != nil {
			closed = err
		}
		cancel()
	}
	if _, err := read(t, flooder); closeCode(err) != closeSlow {
		t.Fatalf("want the flooder closed with 4408, got %v", err)
	}
	// The host and the other client are untouched.
	write(t, host, frame{T: "msg", Conn: 2, Data: "still here"})
	if s, err := read(t, other); s != "still here" {
		t.Fatalf("other client got %q (%v)", s, err)
	}
}

func TestClaimStoreIsBounded(t *testing.T) {
	s, _ := NewClaimStore("")
	for i := 0; i < maxClaims; i++ {
		if !s.Check(fmt.Sprintf("id-%d", i), secret) {
			t.Fatalf("claim %d should fit", i)
		}
	}
	if s.Check("one-too-many", secret) {
		t.Fatal("a claim beyond the cap must be refused")
	}
	if !s.Check("id-0", secret) {
		t.Fatal("an existing host must still get in when full")
	}
}

func TestCFHeaderIsIgnoredUnlessTrusted(t *testing.T) {
	r := httptest.NewRequest("GET", "/v1/client", nil)
	r.RemoteAddr = "10.1.2.3:5555"
	r.Header.Set("CF-Connecting-IP", "1.2.3.4")
	h := NewHub(DefaultLimits, nil)
	if ip := h.clientIP(r); ip != "10.1.2.3" {
		t.Fatalf("forged header honoured: %q", ip)
	}
	h.TrustCFHeader = true
	if ip := h.clientIP(r); ip != "1.2.3.4" {
		t.Fatalf("trusted header ignored: %q", ip)
	}
}

func TestSpoofedCFHeaderOnlyCountsFromTheTrustedHop(t *testing.T) {
	h := NewHub(DefaultLimits, nil)
	h.TrustCFHeader = true
	const traefik, cloudflared = "10.44.0.32:5555", "10.44.1.233"
	for _, c := range []struct {
		name, peer, xff, cf, host, want string
	}{
		// Reached directly from outside the cluster: whatever the Host, the peer is the client.
		{"direct, public host", "203.0.113.9:5555", "", "1.2.3.4", "relay.cnvk.si", "203.0.113.9"},
		{"direct, forged xff", "203.0.113.9:5555", "10.44.1.233", "1.2.3.4", "relay.cnvk.si", "203.0.113.9"},
		// Via the ingress from a tailnet address, claiming the public Host: not Cloudflare.
		{"tailnet hop, public host", traefik, "100.64.0.7", "1.2.3.4", "relay.cnvk.si", "100.64.0.7"},
		{"tailnet hop, prepended xff", traefik, "10.44.1.233, 100.64.0.7", "1.2.3.4", "relay.cnvk.si", "100.64.0.7"},
		// Via cloudflared → ingress: honoured, and the Host makes no difference either way.
		{"cloudflared hop", traefik, cloudflared, "1.2.3.4", "relay.cnvk.si", "1.2.3.4"},
		{"cloudflared hop, internal host", traefik, cloudflared, "1.2.3.4", "convoke-relay.internal", "1.2.3.4"},
		{"cloudflared hop, junk header", traefik, cloudflared, "not an ip", "relay.cnvk.si", cloudflared},
	} {
		r := httptest.NewRequest("GET", "/v1/client", nil)
		r.RemoteAddr, r.Host = c.peer, c.host
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		r.Header.Set("CF-Connecting-IP", c.cf)
		if ip := h.clientIP(r); ip != c.want {
			t.Errorf("%s: want %s, got %s", c.name, c.want, ip)
		}
	}

	// With an edge secret, a private hop isn't enough: the request must carry it.
	h.CFEdgeSecret = "edge-0123456789"
	r := httptest.NewRequest("GET", "/v1/client", nil)
	r.RemoteAddr = traefik
	r.Header.Set("X-Forwarded-For", "10.44.0.28") // svclb: a masqueraded tailnet/LAN client
	r.Header.Set("CF-Connecting-IP", "1.2.3.4")
	if ip := h.clientIP(r); ip != "10.44.0.28" {
		t.Fatalf("header honoured without the edge secret: %s", ip)
	}
	r.Header.Set(cfEdgeHeader, "edge-wrong")
	if ip := h.clientIP(r); ip != "10.44.0.28" {
		t.Fatalf("header honoured with a wrong edge secret: %s", ip)
	}
	r.Header.Set(cfEdgeHeader, "edge-0123456789")
	if ip := h.clientIP(r); ip != "1.2.3.4" {
		t.Fatalf("header ignored with the edge secret: %s", ip)
	}
}

func TestPerAddressCapsHoldUnderCFHeaderRotation(t *testing.T) {
	l := DefaultLimits
	l.MaxConnsPerIP = 2
	claims, _ := NewClaimStore("")
	hub := NewHub(l, claims)
	hub.TrustCFHeader = true
	hub.CFEdgeSecret = "edge-0123456789"
	srv := httptest.NewServer(routes(hub, ""))
	t.Cleanup(srv.Close)
	dialAs := func(i int, edge string) error {
		hdr := http.Header{}
		hdr.Set("CF-Connecting-IP", fmt.Sprintf("198.51.100.%d", i))
		if edge != "" {
			hdr.Set(cfEdgeHeader, edge)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/v1/host?id="+hostID, &websocket.DialOptions{HTTPHeader: hdr})
		if err == nil {
			t.Cleanup(func() { ws.CloseNow() }) // held open (unauthenticated) to keep its slot
		}
		return err
	}
	// Without the edge secret, a fresh CF-Connecting-IP per connection gains nothing.
	for i := 0; i < 3; i++ {
		err := dialAs(i, "")
		if i < 2 && err != nil {
			t.Fatalf("connection %d should fit: %v", i, err)
		}
		if i == 2 && err == nil {
			t.Fatal("rotating CF-Connecting-IP escaped the per-address cap")
		}
	}
	// Through Cloudflare (the secret present), each address really is its own.
	for i := 10; i < 13; i++ {
		if err := dialAs(i, "edge-0123456789"); err != nil {
			t.Fatalf("a Cloudflare client was refused: %v", err)
		}
	}
}

func TestWebDirectoriesAreNotListed(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "sub"), 0o755)
	os.WriteFile(filepath.Join(dir, "sub", "a.js"), []byte("1"), 0o644)
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("hi"), 0o644)
	srv := httptest.NewServer(routes(NewHub(DefaultLimits, nil), dir))
	defer srv.Close()
	for path, want := range map[string]int{"/": 200, "/sub/a.js": 200, "/sub/": 404} {
		resp, err := srv.Client().Get(srv.URL + path)
		if err != nil || resp.StatusCode != want {
			t.Fatalf("%s: want %d, got %v %v", path, want, resp, err)
		}
		if path == "/" && resp.Header.Get("Content-Security-Policy") == "" {
			t.Fatal("missing CSP")
		}
	}
}

func newLimitedRelay(t *testing.T, edit func(*Limits)) *httptest.Server {
	t.Helper()
	l := DefaultLimits
	edit(&l)
	claims, _ := NewClaimStore("")
	srv := httptest.NewServer(routes(NewHub(l, claims), ""))
	t.Cleanup(srv.Close)
	return srv
}

// waitOpen reads host frames until a client's open notice and returns its conn number.
func waitOpen(t *testing.T, host *websocket.Conn) uint64 {
	t.Helper()
	for {
		if f := readFrame(t, host); f.T == "open" {
			return f.Conn
		}
	}
}

func TestIdleClientsCannotKeepRealDevicesOut(t *testing.T) {
	srv := newLimitedRelay(t, func(l *Limits) { l.MaxClients = 3; l.MaxClientsPerIP = 10 })
	host := connectHost(t, srv, secret)
	readFrame(t, host)
	device := dial(t, srv, "/v1/client?host="+hostID)
	n := waitOpen(t, host)
	write(t, host, frame{T: "verified", Conn: n}) // the device proved its key to the host
	idle1 := dial(t, srv, "/v1/client?host="+hostID)
	waitOpen(t, host)
	dial(t, srv, "/v1/client?host="+hostID)
	waitOpen(t, host)
	// Full. A newcomer still gets in: the oldest unverified client makes room.
	dial(t, srv, "/v1/client?host="+hostID)
	waitOpen(t, host)
	if _, err := read(t, idle1); closeCode(err) != closeTooMany {
		t.Fatalf("want the oldest idle client evicted with 4429, got %v", err)
	}
	write(t, host, frame{T: "msg", Conn: n, Data: "still here"})
	if s, err := read(t, device); s != "still here" {
		t.Fatalf("the verified device must keep its slot: got %q (%v)", s, err)
	}
}

func TestClientsPerAddressAreCapped(t *testing.T) {
	srv := newLimitedRelay(t, func(l *Limits) { l.MaxClientsPerIP = 2 })
	host := connectHost(t, srv, secret)
	readFrame(t, host)
	dial(t, srv, "/v1/client?host="+hostID)
	dial(t, srv, "/v1/client?host="+hostID)
	third := dial(t, srv, "/v1/client?host="+hostID)
	if _, err := read(t, third); closeCode(err) != closeTooMany {
		t.Fatalf("want 4429 for a third client from one address, got %v", err)
	}
}

func TestQueuedBytesAreBoundedAndTheHostSurvives(t *testing.T) {
	srv := newLimitedRelay(t, func(l *Limits) { l.QueueBytes = 1 << 20; l.ClientMsgRate = 1000 })
	host := connectHost(t, srv, secret)
	host.SetReadLimit(-1)
	readFrame(t, host)
	flooder := dial(t, srv, "/v1/client?host="+hostID)
	other := dial(t, srv, "/v1/client?host="+hostID)
	// Characters JSON would HTML-escape six-fold; the host never reads meanwhile.
	big := []byte(strings.Repeat("<", 900_000))
	for i := 0; i < 50; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := flooder.Write(ctx, websocket.MessageText, big)
		cancel()
		if err != nil {
			break
		}
	}
	if _, err := read(t, flooder); closeCode(err) != closeSlow {
		t.Fatalf("want the flooder closed with 4408, got %v", err)
	}
	// The host is still connected and hears about the flooder leaving (control frames have room).
	sawClose := false
	for i := 0; i < 10 && !sawClose; i++ {
		raw, err := read(t, host)
		if err != nil {
			t.Fatalf("host read: %v", err)
		}
		var f frame
		json.Unmarshal([]byte(raw), &f)
		sawClose = f.T == "close"
		if f.T == "msg" && strings.Contains(raw, "\\u003c") {
			t.Fatal("relayed data must not be HTML-escaped")
		}
	}
	if !sawClose {
		t.Fatal("the host should be told the flooder left")
	}
	write(t, host, frame{T: "msg", Conn: 2, Data: "still here"})
	if s, err := read(t, other); s != "still here" {
		t.Fatalf("other client got %q (%v)", s, err)
	}
}

func TestNewHostIDsPerAddressAreBudgeted(t *testing.T) {
	srv := newLimitedRelay(t, func(l *Limits) { l.NewClaimsPerDay = 2 })
	for i := 0; i < 3; i++ {
		ws := dial(t, srv, fmt.Sprintf("/v1/host?id=host-%d-0123456789abcdef", i))
		write(t, ws, frame{T: "auth", Secret: secret})
		f, err := read(t, ws)
		if i < 2 && !strings.Contains(f, "ready") {
			t.Fatalf("claim %d should succeed: %q %v", i, f, err)
		}
		if i == 2 && closeCode(err) != closeUnauthorized {
			t.Fatalf("a third new id from one address should be refused, got %q %v", f, err)
		}
	}
	// A host that already holds its id is unaffected.
	ws := dial(t, srv, "/v1/host?id=host-0-0123456789abcdef")
	write(t, ws, frame{T: "auth", Secret: secret})
	if f := readFrame(t, ws); f.T != "ready" {
		t.Fatalf("known host should reconnect, got %+v", f)
	}
}

func TestBinaryFramesAreRefused(t *testing.T) {
	srv := newTestRelay(t, nil)
	host := connectHost(t, srv, secret)
	readFrame(t, host)
	client := dial(t, srv, "/v1/client?host="+hostID)
	if err := client.Write(context.Background(), websocket.MessageBinary, []byte{0xff, 0xfe}); err != nil {
		t.Fatal(err)
	}
	if _, err := read(t, client); closeCode(err) != websocket.StatusUnsupportedData {
		t.Fatalf("want 1003 for a binary frame, got %v", err)
	}
}

func TestClaimsSurviveAsAFileWrittenDurably(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewClaimStore(filepath.Join(dir, "claims.json"))
	s.Check(hostID, secret)
	if _, err := os.Stat(filepath.Join(dir, "claims.json.tmp")); !os.IsNotExist(err) {
		t.Fatal("the temp file should have been renamed into place")
	}
	again, err := NewClaimStore(filepath.Join(dir, "claims.json"))
	if err != nil || !again.Known(hostID) {
		t.Fatalf("claim not persisted: %v", err)
	}
}

func TestRateLimitIsPerAddressWithoutWindowBursts(t *testing.T) {
	r := newRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !r.allow("a") {
			t.Fatalf("event %d should pass", i)
		}
	}
	if r.allow("a") {
		t.Fatal("the fourth event in a minute must be refused")
	}
	if !r.allow("b") {
		t.Fatal("another address has its own allowance")
	}
}

// dialChallenged connects as a host and returns the challenge (for key-bound ids).
func dialChallenged(t *testing.T, srv *httptest.Server, id string) (*websocket.Conn, frame) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/v1/host?id="+id, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ws.CloseNow() })
	return ws, readFrame(t, ws)
}

// proveKey answers a challenge as the holder of priv.
func proveKey(t *testing.T, priv *ecdh.PrivateKey, id string, ch frame) frame {
	t.Helper()
	e, _ := b64u.DecodeString(ch.E)
	n, _ := b64u.DecodeString(ch.N)
	ePub, err := ecdh.X25519().NewPublicKey(e)
	if err != nil {
		t.Fatal(err)
	}
	shared, _ := priv.ECDH(ePub)
	mac := hmac.New(sha256.New, shared)
	mac.Write([]byte("convoke-relay-auth-v1"))
	mac.Write([]byte(id))
	mac.Write(n)
	return frame{T: "auth", Pub: b64u.EncodeToString(priv.PublicKey().Bytes()), Proof: b64u.EncodeToString(mac.Sum(nil))}
}

func TestKeyBoundHostIDsNeedTheKey(t *testing.T) {
	srv := newTestRelay(t, nil)
	owner, _ := ecdh.X25519().GenerateKey(rand.Reader)
	id := hostIDFor(owner.PublicKey().Bytes())
	if !isKeyBoundID(id) || !idPattern.MatchString(id) {
		t.Fatalf("derived id %q has the wrong form", id)
	}
	// The owner gets in, every time (no claim involved).
	for i := 0; i < 2; i++ {
		ws, ch := dialChallenged(t, srv, id)
		write(t, ws, proveKey(t, owner, id, ch))
		if f := readFrame(t, ws); f.T != "ready" {
			t.Fatalf("owner should get in, got %+v", f)
		}
	}
	// Someone else: their own key doesn't derive this id; a secret isn't accepted for it;
	// and a proof replayed from an earlier challenge doesn't verify.
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	ws, ch := dialChallenged(t, srv, id)
	write(t, ws, proveKey(t, other, id, ch))
	if _, err := read(t, ws); closeCode(err) != closeUnauthorized {
		t.Fatalf("another key must be refused, got %v", err)
	}
	ws, _ = dialChallenged(t, srv, id)
	write(t, ws, frame{T: "auth", Secret: secret})
	if _, err := read(t, ws); closeCode(err) != closeUnauthorized {
		t.Fatalf("a secret must not claim a key-bound id, got %v", err)
	}
	ws1, ch1 := dialChallenged(t, srv, id)
	old := proveKey(t, owner, id, ch1)
	ws1.Close(websocket.StatusNormalClosure, "")
	ws2, _ := dialChallenged(t, srv, id)
	write(t, ws2, old)
	if _, err := read(t, ws2); closeCode(err) != closeUnauthorized {
		t.Fatalf("a replayed proof must be refused, got %v", err)
	}
}

func TestHostReplacedWhileClientsAttachLeavesNoneBehind(t *testing.T) {
	srv := newLimitedRelay(t, func(l *Limits) {
		l.MaxClientsPerIP = 1000
		l.MaxClients = 1000
		l.MaxConnsPerIP = 1000
		l.ConnectsPerMin = 100000
	})
	for round := 0; round < 20; round++ {
		host := connectHost(t, srv, secret)
		readFrame(t, host)
		done := make(chan *websocket.Conn, 8)
		for i := 0; i < 8; i++ {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/v1/client?host="+hostID, nil)
				if err != nil {
					done <- nil
					return
				}
				done <- ws
			}()
		}
		// Replace the host while those clients attach.
		replacement := connectHost(t, srv, secret)
		readFrame(t, replacement)
		replacement.Close(websocket.StatusNormalClosure, "")
		host.CloseNow()
		// Every client attached to either host must be closed, never left on a dead one.
		for i := 0; i < 8; i++ {
			ws := <-done
			if ws == nil {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_, _, err := ws.Read(ctx)
			cancel()
			if code := websocket.CloseStatus(err); code != closeHostOffline && code != closeReplaced {
				t.Fatalf("round %d: a client stayed attached (read: %v)", round, err)
			}
			ws.CloseNow()
		}
	}
}

func TestTailnetRouteKeysOnTheIngressForwardedAddress(t *testing.T) {
	h := NewHub(DefaultLimits, nil)
	r := httptest.NewRequest("GET", "/v1/client", nil)
	r.Host = "convoke-relay.internal"
	r.RemoteAddr = "10.44.0.32:5555" // the ingress
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 100.64.0.7")
	if ip := h.clientIP(r); ip != "100.64.0.7" {
		t.Fatalf("want the address the ingress saw, got %s", ip)
	}
	r.RemoteAddr = "203.0.113.9:5555" // not from inside the cluster: header ignored
	if ip := h.clientIP(r); ip != "203.0.113.9" {
		t.Fatalf("want the peer, got %s", ip)
	}
	r.Host = "relay.cnvk.si"
	r.RemoteAddr = "10.44.0.32:5555"
	if ip := h.clientIP(r); ip != "100.64.0.7" {
		t.Fatalf("the Host header must not change what the ingress is trusted for, got %s", ip)
	}
	r.Header.Del("X-Forwarded-For") // no proxy in front: the peer itself
	if ip := h.clientIP(r); ip != "10.44.0.32" {
		t.Fatalf("want the peer, got %s", ip)
	}
}

func TestSlowAndIdleHTTPConnectionsAreClosedButWebsocketsStay(t *testing.T) {
	claims, _ := NewClaimStore("")
	h := routes(NewHub(DefaultLimits, claims), "")
	tm := serverTimeouts{readHeader: 300 * time.Millisecond, read: 400 * time.Millisecond, write: 400 * time.Millisecond, idle: 500 * time.Millisecond}
	srv := httptest.NewUnstartedServer(h)
	srv.Config = newServer("", h, tm)
	srv.Start()
	t.Cleanup(srv.Close)
	addr := strings.TrimPrefix(srv.URL, "http://")

	// closedWithin reports whether the server hangs up on c within d (reading whatever it sends).
	closedWithin := func(c net.Conn, d time.Duration) bool {
		c.SetReadDeadline(time.Now().Add(d))
		_, err := io.Copy(io.Discard, c)
		// EOF or a reset: the server closed it; a timeout means it's still open.
		var ne net.Error
		return !errors.As(err, &ne) || !ne.Timeout()
	}

	// Slow headers: a byte at a time, never finishing.
	ws := dial(t, srv, "/v1/host?id="+hostID) // up before the slow peers, outlives them all
	write(t, ws, frame{T: "auth", Secret: secret})
	if f := readFrame(t, ws); f.T != "ready" {
		t.Fatalf("host not ready: %+v", f)
	}
	slow, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Close()
	go func() {
		for _, b := range []byte("GET /health HTTP/1.1\r\nHost: x\r\nX-Slow: aaaaaaaaaaaaaaaaaaaa") {
			if _, err := slow.Write([]byte{b}); err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	if !closedWithin(slow, 3*time.Second) {
		t.Fatal("a slow-loris connection was left open")
	}

	// Idle keep-alive: one request, then silence.
	idle, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	fmt.Fprint(idle, "GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
	if !closedWithin(idle, 3*time.Second) {
		t.Fatal("an idle kept-alive connection was left open")
	}

	// The websocket, open for longer than every timeout, still works both ways.
	client := dial(t, srv, "/v1/client?host="+hostID)
	n := waitOpen(t, ws)
	time.Sleep(time.Second)
	write(t, client, "hello")
	if f := readFrame(t, ws); f.T != "msg" || f.Data != "hello" {
		t.Fatalf("host got %+v", f)
	}
	write(t, ws, frame{T: "msg", Conn: n, Data: "still here"})
	if s, err := read(t, client); s != "still here" {
		t.Fatalf("client got %q (%v)", s, err)
	}
}

func TestOneHostCannotSpendEveryonesQueueBudget(t *testing.T) {
	l := DefaultLimits
	l.QueueBytes = 4 << 20
	l.HostQueueBytes = 3 << 20
	l.TotalQueueBytes = 8 << 20
	l.MaxClientsPerIP, l.MaxConnsPerIP, l.ConnectsPerMin = 100, 1000, 100000
	claims, _ := NewClaimStore("")
	hub := NewHub(l, claims)
	srv := httptest.NewServer(routes(hub, ""))
	t.Cleanup(srv.Close)

	// A hostile host with clients that never read, streaming large frames to all of them:
	// without its own quota it would fill the relay-wide budget (4 clients × 4 MB > 8 MB).
	evil := "evil-0123456789abcdef"
	hostile := dial(t, srv, "/v1/host?id="+evil)
	write(t, hostile, frame{T: "auth", Secret: secret})
	readFrame(t, hostile)
	var sinks []*websocket.Conn
	for i := 0; i < 4; i++ {
		sink := dial(t, srv, "/v1/client?host="+evil)
		sink.SetReadLimit(-1)
		sinks = append(sinks, sink)
		waitOpen(t, hostile)
	}
	big := strings.Repeat("a", 500_000)
	for round := 0; round < 12; round++ {
		for n := uint64(1); n <= 4; n++ {
			write(t, hostile, frame{T: "msg", Conn: n, Data: big})
		}
	}
	// Wait until the relay has taken in the flood (the queue stops growing).
	var last int64 = -1
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		q := hub.queued.Load()
		if q > l.HostQueueBytes {
			t.Fatalf("one host holds %d queued bytes, over its %d quota", q, l.HostQueueBytes)
		}
		if q > 0 && q == last {
			break
		}
		last = q
	}
	// Its non-reading clients are the ones dropped.
	dropped := 0
	for _, s := range sinks {
		var err error
		for err == nil {
			_, err = read(t, s)
		}
		if closeCode(err) == closeSlow {
			dropped++
		}
	}
	if dropped == 0 {
		t.Fatal("want the hostile host's slow clients closed with 4408")
	}

	// Another host is served normally, both ways.
	victim := connectHost(t, srv, secret)
	readFrame(t, victim)
	client := dial(t, srv, "/v1/client?host="+hostID)
	client.SetReadLimit(-1)
	n := waitOpen(t, victim)
	write(t, client, "hello")
	if f := readFrame(t, victim); f.T != "msg" || f.Data != "hello" {
		t.Fatalf("victim host got %+v", f)
	}
	write(t, victim, frame{T: "msg", Conn: n, Data: strings.Repeat("b", 400_000)})
	if s, err := read(t, client); len(s) != 400_000 {
		t.Fatalf("victim client got %d bytes (%v)", len(s), err)
	}
}

func TestTrustedProxiesChooseWhoseForwardedAddressCounts(t *testing.T) {
	req := func(peer, xff string) *http.Request {
		r := httptest.NewRequest("GET", "/v1/client", nil)
		r.RemoteAddr = peer
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}
	for _, c := range []struct {
		name, flag, peer, xff, want string
	}{
		// Default: a proxy on the same machine or a private network (Caddy, docker).
		{"private: loopback proxy", "private", "127.0.0.1:5555", "203.0.113.9", "203.0.113.9"},
		{"private: docker proxy", "", "172.18.0.2:5555", "6.6.6.6, 203.0.113.9", "203.0.113.9"},
		{"private: public peer", "private", "198.51.100.4:5555", "203.0.113.9", "198.51.100.4"},
		// Exposed directly: nobody's header counts, not even a private peer's.
		{"none: private peer", "none", "10.0.0.5:5555", "203.0.113.9", "10.0.0.5"},
		{"none: loopback peer", "none", "127.0.0.1:5555", "203.0.113.9", "127.0.0.1"},
		// Explicit list: a public proxy can be trusted, and other private peers aren't.
		{"cidrs: listed public proxy", "198.51.100.0/24", "198.51.100.4:5555", "203.0.113.9", "203.0.113.9"},
		{"cidrs: bare address", "198.51.100.4, ::1", "[::1]:5555", "203.0.113.9", "203.0.113.9"},
		{"cidrs: unlisted private peer", "198.51.100.0/24", "10.0.0.5:5555", "203.0.113.9", "10.0.0.5"},
		{"cidrs: junk header", "198.51.100.0/24", "198.51.100.4:5555", "not an ip", "198.51.100.4"},
	} {
		set, err := ParseProxySet(c.flag)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		h := NewHub(DefaultLimits, nil)
		h.TrustedProxies = set
		if ip := h.clientIP(req(c.peer, c.xff)); ip != c.want {
			t.Errorf("%s: want %s, got %s", c.name, c.want, ip)
		}
	}
	for _, bad := range []string{"10.0.0.0/33", "relay.example", "1.2.3"} {
		if _, err := ParseProxySet(bad); err == nil {
			t.Errorf("ParseProxySet(%q) accepted", bad)
		}
	}
}
