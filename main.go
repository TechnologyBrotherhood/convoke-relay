// Command relay is the Convoke relay: a meeting point on the public internet where
// a Convoke host (the Mac) and its paired devices both connect outward, so neither
// needs to accept inbound connections. Traffic is end-to-end encrypted by the
// endpoints; the relay routes ciphertext. It also serves a small page that hands a
// pairing link opened in a browser to the iPhone app.
package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func main() {
	addr := flag.String("addr", envOr("RELAY_ADDR", ":8080"), "listen address")
	data := flag.String("data", envOr("RELAY_DATA", ""), "directory for persistent state (host id claims); empty = memory only")
	web := flag.String("web", envOr("RELAY_WEB", ""), "directory with the pairing hand-off page (web/); empty = no page")
	trusted := flag.String("trusted-proxies", envOr("RELAY_TRUSTED_PROXIES", "private"), "reverse proxies whose X-Forwarded-For gives the client address for rate limiting: \"private\" (private and loopback addresses), \"none\", or comma-separated CIDRs")
	trustCF := flag.Bool("trust-cf-header", os.Getenv("RELAY_TRUST_CF_HEADER") == "1", "take the client IP for rate limiting from CF-Connecting-IP when the request came through an in-cluster hop (cloudflared)")
	flag.Parse()

	claimsPath := ""
	if *data != "" {
		claimsPath = filepath.Join(*data, "claims.json")
	}
	claims, err := NewClaimStore(claimsPath)
	if err != nil {
		slog.Error("loading claims", "err", err)
		os.Exit(1)
	}
	proxies, err := ParseProxySet(*trusted)
	if err != nil {
		slog.Error("-trusted-proxies", "err", err)
		os.Exit(1)
	}
	hub := NewHub(DefaultLimits, claims)
	hub.TrustedProxies = proxies
	hub.TrustCFHeader = *trustCF
	// From the environment only, so the secret isn't in the process's arguments.
	hub.CFEdgeSecret = os.Getenv("RELAY_CF_EDGE_SECRET")

	srv := newServer(*addr, routes(hub, *web), defaultTimeouts)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		// Forget host ids unused for a year. A Mac with paired devices reconnects whenever
		// it runs, so only an id abandoned that long can be claimed by someone else.
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if n := claims.Prune(365 * 24 * time.Hour); n > 0 {
					slog.Info("pruned stale host claims", "count", n)
				}
			}
		}
	}()
	go func() {
		<-ctx.Done()
		hub.CloseAll() // hijacked websockets aren't closed by Shutdown
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()

	slog.Info("relay listening", "addr", *addr, "web", *web != "", "persistent", claimsPath != "")
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("server", "err", err)
		os.Exit(1)
	}
}

type serverTimeouts struct{ readHeader, read, write, idle time.Duration }

var defaultTimeouts = serverTimeouts{readHeader: 10 * time.Second, read: 30 * time.Second, write: 30 * time.Second, idle: 2 * time.Minute}

// newServer bounds every phase of a plain HTTP exchange, so a slow or idle peer can't
// hold a connection. Websockets aren't affected: net/http clears a connection's
// deadlines when the handler hijacks it, and from then on the hub's pings and write
// timeouts govern it.
func newServer(addr string, h http.Handler, t serverTimeouts) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: t.readHeader,
		ReadTimeout:       t.read,
		WriteTimeout:      t.write,
		IdleTimeout:       t.idle, // without it a kept-alive connection waits forever for its next request
	}
}

func routes(hub *Hub, webDir string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /v1/host", hub.ServeHost)
	mux.HandleFunc("GET /v1/client", hub.ServeClient)
	if webDir != "" {
		files := http.FileServer(http.Dir(webDir))
		mux.Handle("GET /", securityHeaders(noListing(files)))
	}
	return mux
}

// securityHeaders locks the web client down: it runs only its own scripts and
// talks only to this relay, so injected content can't exfiltrate keys.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// The only page is the pairing hand-off: it loads its own script and style and
		// connects nowhere.
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		h.Set("Cache-Control", "no-cache")
		next.ServeHTTP(w, r)
	})
}

// noListing serves files but not directory indexes (the built client has none to show).
func noListing(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := r.URL.Path; p != "/" && strings.HasSuffix(p, "/") {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
