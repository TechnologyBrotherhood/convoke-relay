// Package push is Convoke's push service: it lets a Mac wake its paired iPhone through
// Apple's push service (APNs) without the relay, or anyone, learning what it's about.
//
// The iPhone registers its APNs device token here and gets back an opaque push id. It
// gives that id to its Mac inside their end-to-end encrypted session. When something
// needs the user (an agent asks for approval, a long task finishes) and the phone isn't
// connected, the Mac posts the id here and this service sends a content-free alert
// ("Something needs you on your Mac"). The phone opens, connects, and gets the details
// end to end. So this service knows device tokens and when wake-ups happen, nothing else.
//
// It's separate from the relay because anyone can run a relay, but only Convoke has the
// APNs key for the App Store app.
//
//	POST /v1/register {"token":"<hex>","env":"production"|"sandbox"} → {"id":"<push id>"}
//	POST /v1/push     {"id":"<push id>"}                              → 202 (or 410: gone)
//	GET  /health
package push

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// APNs endpoints, by environment (development builds get sandbox tokens).
var apnsHosts = map[string]string{
	"production": "https://api.push.apple.com",
	"sandbox":    "https://api.sandbox.push.apple.com",
}

// The one alert every wake-up shows: it says nothing about what happened.
const alertBody = "Something needs you on your Mac."

var tokenPattern = regexp.MustCompile(`^[0-9a-fA-F]{64,200}$`)

// Config for a Service.
type Config struct {
	// The APNs auth key (the .p8 file's PEM), its key id and the team id. Without a key
	// the service still registers devices, but can't send (POST /v1/push → 503).
	KeyPEM []byte
	KeyID  string
	TeamID string
	// The app's bundle id (the APNs topic).
	Topic string
	// Where registrations are kept (registrations.json); empty: in memory only.
	DataDir string
	// Secret for deriving push ids from tokens (so registering again gives the same id);
	// random when empty (ids then change across restarts unless DataDir keeps them).
	IDSecret []byte
	// Minimum time between two wake-ups for one device.
	MinInterval time.Duration
	// At most this many devices, and this many new ones a minute (anyone can register,
	// so neither memory nor the file can be grown without bound).
	MaxRegistrations       int
	RegistrationsPerMinute int
	// APNs base URLs by environment (tests point these at a fake); defaults to Apple's.
	Hosts map[string]string
	// The HTTP client for APNs (needs HTTP/2); defaults to one with a 10 s timeout.
	Client *http.Client
	Now    func() time.Time
}

// Registration is one device: its APNs token, environment, and when it last woke.
type Registration struct {
	Token string    `json:"token"`
	Env   string    `json:"env"`
	Added time.Time `json:"added"`
}

// Service is the push service's state.
type Service struct {
	cfg  Config
	key  *ecdsa.PrivateKey
	mu   sync.Mutex
	regs map[string]Registration // push id → registration
	last map[string]time.Time    // push id → last wake-up sent
	jwt  struct {
		token string
		at    time.Time
	}
	// New registrations this minute.
	window struct {
		start time.Time
		n     int
	}
}

// New makes a Service, loading saved registrations from cfg.DataDir.
func New(cfg Config) (*Service, error) {
	if cfg.Topic == "" {
		cfg.Topic = "dev.convoke.ios"
	}
	if cfg.MinInterval == 0 {
		cfg.MinInterval = 30 * time.Second
	}
	if cfg.MaxRegistrations == 0 {
		cfg.MaxRegistrations = 100_000
	}
	if cfg.RegistrationsPerMinute == 0 {
		cfg.RegistrationsPerMinute = 120
	}
	if cfg.Hosts == nil {
		cfg.Hosts = apnsHosts
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if len(cfg.IDSecret) == 0 {
		cfg.IDSecret = make([]byte, 32)
		if _, err := rand.Read(cfg.IDSecret); err != nil {
			return nil, err
		}
	}
	s := &Service{cfg: cfg, regs: map[string]Registration{}, last: map[string]time.Time{}}
	if len(cfg.KeyPEM) > 0 {
		key, err := parseKey(cfg.KeyPEM)
		if err != nil {
			return nil, fmt.Errorf("APNs key: %w", err)
		}
		if cfg.KeyID == "" || cfg.TeamID == "" {
			return nil, errors.New("APNs key id and team id are required with a key")
		}
		s.key = key
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// parseKey reads an APNs .p8 key (PKCS#8 PEM, P-256).
func parseKey(p []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(p)
	if block == nil {
		return nil, errors.New("not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an EC key")
	}
	return ec, nil
}

// Handler serves the API.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		if s.key == nil {
			_, _ = io.WriteString(w, "ok (no APNs key: registering only)\n")
			return
		}
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("POST /v1/register", s.register)
	mux.HandleFunc("POST /v1/push", s.push)
	return mux
}

func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(v)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// idFor derives a device's push id from its token: the same device registering again
// gets the same id, and the id reveals nothing about the token.
func (s *Service) idFor(token, env string) string {
	m := hmac.New(sha256.New, s.cfg.IDSecret)
	m.Write([]byte(env + ":" + strings.ToLower(token)))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:18])
}

func (s *Service) register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
		Env   string `json:"env"`
	}
	if err := readJSON(r, &req); err != nil || !tokenPattern.MatchString(req.Token) || s.cfg.Hosts[req.Env] == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "want {token: hex, env: production|sandbox}"})
		return
	}
	id := s.idFor(req.Token, req.Env)
	now := s.cfg.Now()
	s.mu.Lock()
	_, known := s.regs[id]
	if !known {
		if now.Sub(s.window.start) >= time.Minute {
			s.window.start, s.window.n = now, 0
		}
		if s.window.n >= s.cfg.RegistrationsPerMinute || len(s.regs) >= s.cfg.MaxRegistrations {
			s.mu.Unlock()
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "try again later"})
			return
		}
		s.window.n++
		s.regs[id] = Registration{Token: strings.ToLower(req.Token), Env: req.Env, Added: now}
	}
	err := s.saveLocked()
	s.mu.Unlock()
	if err != nil {
		slog.Error("saving registrations", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "couldn't save"})
		return
	}
	if !known {
		slog.Info("registered", "id", id[:6])
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": id})
}

func (s *Service) push(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := readJSON(r, &req); err != nil || req.ID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "want {id}"})
		return
	}
	if s.key == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no APNs key configured"})
		return
	}
	now := s.cfg.Now()
	s.mu.Lock()
	reg, ok := s.regs[req.ID]
	recent := ok && now.Sub(s.last[req.ID]) < s.cfg.MinInterval
	if ok && !recent {
		s.last[req.ID] = now
	}
	s.mu.Unlock()
	if !ok {
		// Unknown (or unregistered by APNs): the Mac should stop using it.
		writeJSON(w, http.StatusGone, map[string]string{"error": "unknown push id"})
		return
	}
	if recent {
		// Already woken a moment ago: once is enough.
		w.WriteHeader(http.StatusAccepted)
		return
	}
	status, err := s.send(r.Context(), reg)
	switch {
	case status == http.StatusGone || (status == http.StatusBadRequest && errors.Is(err, errBadToken)):
		// APNs says the token is no longer valid (app removed, or re-registered).
		s.mu.Lock()
		delete(s.regs, req.ID)
		delete(s.last, req.ID)
		_ = s.saveLocked()
		s.mu.Unlock()
		slog.Info("unregistered by APNs", "id", req.ID[:6])
		writeJSON(w, http.StatusGone, map[string]string{"error": "device no longer registered"})
	case err != nil:
		slog.Warn("APNs send failed", "id", req.ID[:6], "status", status, "err", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "APNs didn't take it"})
	default:
		w.WriteHeader(http.StatusAccepted)
	}
}

var errBadToken = errors.New("bad device token")

// send posts the content-free alert to APNs for one device.
func (s *Service) send(ctx context.Context, reg Registration) (int, error) {
	payload, _ := json.Marshal(map[string]any{
		"aps": map[string]any{
			"alert":             map[string]string{"title": "Convoke", "body": alertBody},
			"sound":             "default",
			"content-available": 1,
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.Hosts[reg.Env]+"/3/device/"+reg.Token, bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	jwt, err := s.bearer()
	if err != nil {
		return 0, err
	}
	req.Header.Set("authorization", "bearer "+jwt)
	req.Header.Set("apns-topic", s.cfg.Topic)
	req.Header.Set("apns-push-type", "alert")
	req.Header.Set("apns-priority", "10")
	// Several wake-ups before the phone looks collapse into one notification.
	req.Header.Set("apns-collapse-id", "convoke-attention")
	req.Header.Set("apns-expiration", fmt.Sprint(s.cfg.Now().Add(time.Hour).Unix()))
	resp, err := s.cfg.Client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return resp.StatusCode, nil
	}
	var body struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&body)
	if body.Reason == "BadDeviceToken" || body.Reason == "DeviceTokenNotForTopic" {
		return resp.StatusCode, errBadToken
	}
	return resp.StatusCode, fmt.Errorf("APNs %d %s", resp.StatusCode, body.Reason)
}

// bearer is the provider token for APNs: an ES256 JWT, reused for up to 50 minutes
// (APNs wants a new one at least hourly, and no more often than every 20 minutes).
func (s *Service) bearer() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.cfg.Now()
	if s.jwt.token != "" && now.Sub(s.jwt.at) < 50*time.Minute {
		return s.jwt.token, nil
	}
	enc := base64.RawURLEncoding
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": s.cfg.KeyID})
	claims, _ := json.Marshal(map[string]any{"iss": s.cfg.TeamID, "iat": now.Unix()})
	unsigned := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	r, sv, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		return "", err
	}
	// JWS ES256 signatures are r || s, each 32 bytes.
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sv.FillBytes(sig[32:])
	s.jwt.token = unsigned + "." + enc.EncodeToString(sig)
	s.jwt.at = now
	return s.jwt.token, nil
}

func (s *Service) file() string {
	if s.cfg.DataDir == "" {
		return ""
	}
	return filepath.Join(s.cfg.DataDir, "registrations.json")
}

func (s *Service) load() error {
	f := s.file()
	if f == "" {
		return nil
	}
	b, err := os.ReadFile(f)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &s.regs)
}

func (s *Service) saveLocked() error {
	f := s.file()
	if f == "" {
		return nil
	}
	b, err := json.Marshal(s.regs)
	if err != nil {
		return err
	}
	tmp := f + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f)
}
