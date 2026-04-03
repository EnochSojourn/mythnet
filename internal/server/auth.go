package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// authMiddleware enforces Basic Auth on protected routes.
// Skips auth for health check and static assets.
func authMiddleware(passwordHash []byte, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for static assets (SPA) and health endpoint
			if !strings.HasPrefix(r.URL.Path, "/api/") && !strings.HasPrefix(r.URL.Path, "/proxy/") {
				next.ServeHTTP(w, r)
				return
			}
			if r.URL.Path == "/api/health" {
				next.ServeHTTP(w, r)
				return
			}

			// Check Basic Auth
			_, pass, ok := r.BasicAuth()
			if ok {
				h := sha256.Sum256([]byte(pass))
				if subtle.ConstantTimeCompare(h[:], passwordHash) == 1 {
					next.ServeHTTP(w, r)
					return
				}
			}

			w.Header().Set("WWW-Authenticate", `Basic realm="MythNet"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		})
	}
}

// resolvePassword determines the password from config, env, or generates one.
// Returns the password string and its SHA-256 hash.
func resolvePassword(configured, dataDir string, logger *slog.Logger) (string, []byte) {
	password := configured

	// Check environment variable
	if password == "" {
		password = os.Getenv("MYTHNET_PASSWORD")
	}

	// Check saved password file
	passFile := filepath.Join(dataDir, "password")
	if password == "" {
		if data, err := os.ReadFile(passFile); err == nil {
			password = strings.TrimSpace(string(data))
		}
	}

	// Generate random password
	if password == "" {
		b := make([]byte, 16)
		rand.Read(b)
		password = hex.EncodeToString(b)

		// Save for next boot
		os.MkdirAll(dataDir, 0700)
		os.WriteFile(passFile, []byte(password), 0600)

		logger.Info("generated admin password — save this",
			"password", password,
			"saved_to", passFile,
		)
		fmt.Fprintf(os.Stderr, "\n  ╔══════════════════════════════════════════╗\n")
		fmt.Fprintf(os.Stderr, "  ║  MythNet Admin Password: %-16s ║\n", password)
		fmt.Fprintf(os.Stderr, "  ╚══════════════════════════════════════════╝\n\n")
	}

	hash := sha256.Sum256([]byte(password))
	return password, hash[:]
}
