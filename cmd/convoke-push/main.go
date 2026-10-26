// Command convoke-push runs Convoke's push service (see package push): it wakes paired
// iPhones through APNs with a content-free alert, on behalf of their Macs.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"convoke-relay/push"
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	addr := flag.String("addr", envOr("PUSH_ADDR", ":8080"), "listen address")
	data := flag.String("data", envOr("PUSH_DATA", ""), "directory for registrations (and the push-id secret); empty = memory only")
	keyFile := flag.String("apns-key", envOr("APNS_KEY_FILE", ""), "APNs auth key (.p8); empty = register only, can't send")
	keyID := flag.String("apns-key-id", envOr("APNS_KEY_ID", ""), "APNs key id")
	teamID := flag.String("apns-team-id", envOr("APNS_TEAM_ID", ""), "Apple team id")
	topic := flag.String("topic", envOr("APNS_TOPIC", "dev.convoke.ios"), "the app's bundle id")
	flag.Parse()

	cfg := push.Config{KeyID: *keyID, TeamID: *teamID, Topic: *topic, DataDir: *data}
	if *keyFile != "" {
		b, err := os.ReadFile(*keyFile)
		switch {
		case errors.Is(err, os.ErrNotExist):
			// Deployed before the key is: register devices, send nothing yet.
			slog.Warn("no APNs key yet: registering only", "file", *keyFile)
		case err != nil:
			slog.Error("reading the APNs key", "err", err)
			os.Exit(1)
		default:
			cfg.KeyPEM = b
		}
	}
	if *data != "" {
		secret, err := idSecret(*data)
		if err != nil {
			slog.Error("push-id secret", "err", err)
			os.Exit(1)
		}
		cfg.IDSecret = secret
	}
	svc, err := push.New(cfg)
	if err != nil {
		slog.Error("starting", "err", err)
		os.Exit(1)
	}
	srv := &http.Server{
		Addr:              *addr,
		Handler:           svc.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	slog.Info("convoke-push listening", "addr", *addr, "apns", len(cfg.KeyPEM) > 0)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("serve", "err", err)
		os.Exit(1)
	}
}

// idSecret is kept with the registrations, so a device registering again after a
// restart gets the same push id.
func idSecret(dir string) ([]byte, error) {
	f := filepath.Join(dir, "id-secret")
	if b, err := os.ReadFile(f); err == nil {
		return hex.DecodeString(string(b))
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return b, os.WriteFile(f, []byte(hex.EncodeToString(b)), 0o600)
}
