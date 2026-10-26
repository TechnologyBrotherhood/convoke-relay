package push

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// A fake APNs: HTTP/2 over TLS, checking the provider token and recording deliveries.
type fakeAPNs struct {
	t      *testing.T
	pub    *ecdsa.PublicKey
	mu     sync.Mutex
	got    []delivery
	reply  int    // status to answer with (0 = 200)
	reason string // with a non-200 reply
	srv    *httptest.Server
}

type delivery struct {
	token   string
	headers http.Header
	body    map[string]any
}

func newFakeAPNs(t *testing.T, pub *ecdsa.PublicKey) *fakeAPNs {
	f := &fakeAPNs{t: t, pub: pub}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("APNs needs HTTP/2, got %s", r.Proto)
		}
		if !f.validJWT(strings.TrimPrefix(r.Header.Get("authorization"), "bearer ")) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"reason":"InvalidProviderToken"}`)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.got = append(f.got, delivery{token: strings.TrimPrefix(r.URL.Path, "/3/device/"), headers: r.Header.Clone(), body: body})
		reply, reason := f.reply, f.reason
		f.mu.Unlock()
		if reply != 0 {
			w.WriteHeader(reply)
			_, _ = io.WriteString(w, `{"reason":"`+reason+`"}`)
		}
	}))
	f.srv.EnableHTTP2 = true
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

// validJWT checks an ES256 provider token against the key, with kid and iss.
func (f *fakeAPNs) validJWT(tok string) bool {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return false
	}
	enc := base64.RawURLEncoding
	var header map[string]string
	var claims map[string]any
	h, _ := enc.DecodeString(parts[0])
	c, _ := enc.DecodeString(parts[1])
	sig, _ := enc.DecodeString(parts[2])
	if json.Unmarshal(h, &header) != nil || json.Unmarshal(c, &claims) != nil || len(sig) != 64 {
		return false
	}
	if header["alg"] != "ES256" || header["kid"] != "KEY1234567" || claims["iss"] != "TEAM123456" {
		return false
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return ecdsa.Verify(f.pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
}

func (f *fakeAPNs) deliveries() []delivery {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]delivery(nil), f.got...)
}

// A service with a fresh APNs key, sending to a fake APNs; returns its API server too.
func setup(t *testing.T, mod func(*Config)) (*Service, *fakeAPNs, *httptest.Server, *time.Time) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	apns := newFakeAPNs(t, &key.PublicKey)
	now := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	cfg := Config{
		KeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		KeyID:  "KEY1234567", TeamID: "TEAM123456", DataDir: t.TempDir(),
		Hosts:  map[string]string{"production": apns.srv.URL, "sandbox": apns.srv.URL},
		Client: apns.srv.Client(),
		Now:    func() time.Time { return now },
	}
	if mod != nil {
		mod(&cfg)
	}
	svc, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(svc.Handler())
	t.Cleanup(api.Close)
	return svc, apns, api, &now
}

func post(t *testing.T, api *httptest.Server, path string, body any) (int, map[string]string) {
	b, _ := json.Marshal(body)
	resp, err := http.Post(api.URL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

var token = strings.Repeat("ab", 32)

func TestRegisterThenWakeSendsAContentFreeAlert(t *testing.T) {
	_, apns, api, _ := setup(t, nil)
	code, reg := post(t, api, "/v1/register", map[string]string{"token": token, "env": "sandbox"})
	if code != 200 || reg["id"] == "" {
		t.Fatalf("register: %d %v", code, reg)
	}
	if strings.Contains(reg["id"], token[:8]) {
		t.Fatal("the push id must not reveal the token")
	}
	code2, again := post(t, api, "/v1/register", map[string]string{"token": strings.ToUpper(token), "env": "sandbox"})
	if code2 != 200 || again["id"] != reg["id"] {
		t.Fatal("registering again gives the same id")
	}
	if code, _ := post(t, api, "/v1/push", map[string]string{"id": reg["id"]}); code != http.StatusAccepted {
		t.Fatalf("push: %d", code)
	}
	got := apns.deliveries()
	if len(got) != 1 || got[0].token != token {
		t.Fatalf("deliveries: %+v", got)
	}
	h := got[0].headers
	if h.Get("apns-topic") != "dev.convoke.ios" || h.Get("apns-push-type") != "alert" || h.Get("apns-collapse-id") == "" {
		t.Fatalf("headers: %v", h)
	}
	b, _ := json.Marshal(got[0].body)
	want := `{"aps":{"alert":{"body":"Something needs you on your Mac.","title":"Convoke"},"content-available":1,"sound":"default"}}`
	if string(b) != want {
		t.Fatalf("payload must be exactly the fixed, content-free alert:\n got %s\nwant %s", b, want)
	}
}

func TestWakeUpsAreRateLimitedPerDevice(t *testing.T) {
	_, apns, api, now := setup(t, nil)
	_, reg := post(t, api, "/v1/register", map[string]string{"token": token, "env": "production"})
	for i := 0; i < 5; i++ {
		post(t, api, "/v1/push", map[string]string{"id": reg["id"]})
	}
	if n := len(apns.deliveries()); n != 1 {
		t.Fatalf("a burst wakes once, got %d", n)
	}
	*now = now.Add(31 * time.Second)
	post(t, api, "/v1/push", map[string]string{"id": reg["id"]})
	if n := len(apns.deliveries()); n != 2 {
		t.Fatalf("later, again: %d", n)
	}
}

func TestAnUnregisteredDeviceIsForgotten(t *testing.T) {
	svc, apns, api, _ := setup(t, nil)
	_, reg := post(t, api, "/v1/register", map[string]string{"token": token, "env": "production"})
	apns.reply, apns.reason = http.StatusGone, "Unregistered"
	if code, _ := post(t, api, "/v1/push", map[string]string{"id": reg["id"]}); code != http.StatusGone {
		t.Fatalf("APNs 410 → 410, got %d", code)
	}
	if len(svc.regs) != 0 {
		t.Fatal("the registration is dropped")
	}
	if code, _ := post(t, api, "/v1/push", map[string]string{"id": "made-up"}); code != http.StatusGone {
		t.Fatalf("an unknown id → 410, got %d", code)
	}
}

func TestRegistrationsSurviveARestart(t *testing.T) {
	dir := t.TempDir()
	secret := []byte("0123456789abcdef0123456789abcdef")
	_, _, api, _ := setup(t, func(c *Config) { c.DataDir, c.IDSecret = dir, secret })
	_, reg := post(t, api, "/v1/register", map[string]string{"token": token, "env": "production"})
	svc2, err := New(Config{DataDir: dir, IDSecret: secret})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := svc2.regs[reg["id"]]; !ok {
		t.Fatal("registration kept across restarts")
	}
}

func TestBadInputAndLimits(t *testing.T) {
	_, _, api, _ := setup(t, func(c *Config) { c.RegistrationsPerMinute = 2 })
	for _, body := range []map[string]string{{"token": "nothex", "env": "production"}, {"token": token, "env": "staging"}, {}} {
		if code, _ := post(t, api, "/v1/register", body); code != http.StatusBadRequest {
			t.Fatalf("%v → %d", body, code)
		}
	}
	codes := []int{}
	for i := 0; i < 3; i++ {
		code, _ := post(t, api, "/v1/register", map[string]string{"token": strings.Repeat(string(rune('a'+i)), 64), "env": "production"})
		codes = append(codes, code)
	}
	if codes[0] != 200 || codes[1] != 200 || codes[2] != http.StatusTooManyRequests {
		t.Fatalf("new registrations a minute are capped: %v", codes)
	}
}

func TestWithoutAKeyItRegistersButCantSend(t *testing.T) {
	svc, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(svc.Handler())
	defer api.Close()
	_, reg := post(t, api, "/v1/register", map[string]string{"token": token, "env": "production"})
	if code, _ := post(t, api, "/v1/push", map[string]string{"id": reg["id"]}); code != http.StatusServiceUnavailable {
		t.Fatalf("no key → 503, got %d", code)
	}
}
