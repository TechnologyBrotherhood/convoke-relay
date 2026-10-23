package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ClaimStore remembers which secret owns each host id: the first host to use an id
// claims it, and later connections must present the same secret. Only SHA-256
// hashes are stored. Persisted so a relay restart can't let someone else grab an
// id before its host reconnects.
type ClaimStore struct {
	mu     sync.Mutex
	path   string // "" = memory only
	claims map[string]claim
}

// maxClaims bounds the store: anyone can claim an unused id, so without a cap a
// flood of made-up ids would grow memory and claims.json without limit.
const maxClaims = 10000

// touchEvery is how stale LastSeen may get before a reconnect rewrites the file.
const touchEvery = time.Hour

type claim struct {
	Hash     string    `json:"hash"`
	LastSeen time.Time `json:"lastSeen"`
}

func NewClaimStore(path string) (*ClaimStore, error) {
	s := &ClaimStore{path: path, claims: map[string]claim{}}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(b, &s.claims); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// Known reports whether an id has been claimed.
func (s *ClaimStore) Known(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.claims[id]
	return ok
}

// Check claims an unknown id for this secret, or verifies a known one.
func (s *ClaimStore) Check(id, secret string) bool {
	h := hashSecret(secret)
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.claims[id]
	if ok && subtle.ConstantTimeCompare([]byte(c.Hash), []byte(h)) != 1 {
		return false
	}
	if !ok && len(s.claims) >= maxClaims {
		return false
	}
	now := time.Now().UTC()
	if ok && now.Sub(c.LastSeen) < touchEvery {
		return true // known host reconnecting: no need to rewrite the file each time
	}
	s.claims[id] = claim{Hash: h, LastSeen: now}
	s.saveLocked()
	return true
}

// Prune forgets ids not seen for `maxAge`, so abandoned hosts don't accumulate forever.
func (s *ClaimStore) Prune(maxAge time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, c := range s.claims {
		if time.Since(c.LastSeen) > maxAge {
			delete(s.claims, id)
			n++
		}
	}
	if n > 0 {
		s.saveLocked()
	}
	return n
}

// saveLocked writes the claims durably (temp file, fsync, rename). A failure is
// logged: claims that don't survive a restart could let someone take a host's id.
func (s *ClaimStore) saveLocked() {
	if s.path == "" {
		return
	}
	if err := s.write(); err != nil {
		slog.Error("saving host claims", "err", err)
	}
}

func (s *ClaimStore) write() error {
	b, err := json.MarshalIndent(s.claims, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// rateLimiter allows `limit` events per IP per `period`, as a token bucket per IP
// (so no burst of twice the limit across a window edge). Idle IPs are forgotten.
type rateLimiter struct {
	mu      sync.Mutex
	limit   int
	period  time.Duration
	buckets map[string]*bucket
	swept   time.Time
}

func newRateLimiter(limit int, period time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, period: period, buckets: map[string]*bucket{}, swept: time.Now()}
}

func (r *rateLimiter) allow(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if now.Sub(r.swept) > r.period {
		// A bucket idle for a whole period is full again: same as having none.
		for k, b := range r.buckets {
			if now.Sub(b.last) > r.period {
				delete(r.buckets, k)
			}
		}
		r.swept = now
	}
	b := r.buckets[ip]
	if b == nil {
		b = newBucket(float64(r.limit)/r.period.Seconds(), float64(r.limit))
		r.buckets[ip] = b
	}
	return b.take()
}

// bucket is a token bucket: `rate` tokens per second up to `burst`.
type bucket struct {
	rate, burst, tokens float64
	last                time.Time
}

func newBucket(rate, burst float64) *bucket {
	return &bucket{rate: rate, burst: burst, tokens: burst, last: time.Now()}
}

func (b *bucket) take() bool {
	now := time.Now()
	b.tokens = min(b.burst, b.tokens+now.Sub(b.last).Seconds()*b.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
