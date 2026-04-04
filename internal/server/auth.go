package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// PasswordManager handles password storage, validation, and changes.
type PasswordManager struct {
	mu       sync.RWMutex
	hash     []byte
	dataDir  string
	logger   *slog.Logger
	needsSetup bool
}

var GlobalPasswordManager *PasswordManager

func NewPasswordManager(configured, dataDir string, logger *slog.Logger) *PasswordManager {
	pm := &PasswordManager{dataDir: dataDir, logger: logger}

	password := configured
	if password == "" {
		password = os.Getenv("MYTHNET_PASSWORD")
	}

	passFile := filepath.Join(dataDir, "password")
	if password == "" {
		if data, err := os.ReadFile(passFile); err == nil {
			password = strings.TrimSpace(string(data))
		}
	}

	if password == "" {
		// No password set — needs first-run setup
		pm.needsSetup = true
		logger.Info("no password configured — first-run setup required at /setup")
	} else {
		h := sha256.Sum256([]byte(password))
		pm.hash = h[:]
	}

	GlobalPasswordManager = pm
	return pm
}

func (pm *PasswordManager) NeedsSetup() bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.needsSetup
}

func (pm *PasswordManager) Validate(password string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	if pm.needsSetup {
		return false
	}
	h := sha256.Sum256([]byte(password))
	return subtle.ConstantTimeCompare(h[:], pm.hash) == 1
}

func (pm *PasswordManager) SetPassword(newPassword string) error {
	if len(newPassword) < 4 {
		return fmt.Errorf("password must be at least 4 characters")
	}

	h := sha256.Sum256([]byte(newPassword))

	pm.mu.Lock()
	pm.hash = h[:]
	pm.needsSetup = false
	pm.mu.Unlock()

	// Save to file
	passFile := filepath.Join(pm.dataDir, "password")
	os.MkdirAll(pm.dataDir, 0700)
	os.WriteFile(passFile, []byte(newPassword), 0600)

	pm.logger.Info("password updated", "saved_to", passFile)
	return nil
}

func (pm *PasswordManager) Hash() []byte {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.hash
}

// authMiddleware enforces Basic Auth on protected routes.
func authMiddleware(pm *PasswordManager, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for non-API routes (static assets, setup, public pages)
			if !strings.HasPrefix(r.URL.Path, "/api/") && !strings.HasPrefix(r.URL.Path, "/proxy/") {
				next.ServeHTTP(w, r)
				return
			}

			// Skip auth for public endpoints
			if r.URL.Path == "/api/health" || r.URL.Path == "/api/docs" ||
				r.URL.Path == "/api/chat" || r.URL.Path == "/api/ws" ||
				r.URL.Path == "/api/setup" {
				next.ServeHTTP(w, r)
				return
			}

			// If setup not complete, block all API access except setup
			if pm.NeedsSetup() {
				http.Error(w, "Setup required — visit /setup", http.StatusServiceUnavailable)
				return
			}

			// Check Basic Auth
			_, pass, ok := r.BasicAuth()
			if ok && pm.Validate(pass) {
				next.ServeHTTP(w, r)
				return
			}

			w.Header().Set("WWW-Authenticate", `Basic realm="MythNet"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		})
	}
}

// Setup page handler
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		if GlobalPasswordManager != nil && !GlobalPasswordManager.NeedsSetup() {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(setupPageHTML))
		return
	}

	// POST — set password
	if r.Method == "POST" {
		var req struct {
			Password string `json:"password"`
		}

		ct := r.Header.Get("Content-Type")
		if strings.Contains(ct, "json") {
			json.NewDecoder(r.Body).Decode(&req)
		} else {
			r.ParseForm()
			req.Password = r.FormValue("password")
		}

		if req.Password == "" {
			http.Error(w, "Password required", http.StatusBadRequest)
			return
		}

		if GlobalPasswordManager != nil {
			if err := GlobalPasswordManager.SetPassword(req.Password); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}

		// Return success
		if strings.Contains(ct, "json") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status":"ok"}`))
		} else {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
		}
		return
	}
}

// Password change handler (requires current auth)
func (s *Server) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if GlobalPasswordManager == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "password manager unavailable"})
		return
	}

	if !GlobalPasswordManager.Validate(req.Current) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "current password incorrect"})
		return
	}

	if err := GlobalPasswordManager.SetPassword(req.New); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	s.store.Audit("password_change", "", r.RemoteAddr)
	writeJSON(w, http.StatusOK, map[string]string{"status": "password changed"})
}

const setupPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MythNet Setup</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0f1a;color:#e2e8f0;font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh}
.box{width:100%;max-width:400px;padding:24px}
h1{font-size:28px;font-weight:700;margin-bottom:4px;text-align:center}
h1 span{color:#3b82f6}
.sub{text-align:center;color:#64748b;font-size:13px;margin-bottom:32px}
.card{background:#111827;border:1px solid #1e293b;border-radius:12px;padding:24px}
label{display:block;font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px}
input{width:100%;background:#0f172a;border:1px solid #374151;border-radius:8px;padding:12px 16px;color:#e2e8f0;font-size:14px;margin-bottom:12px;outline:none}
input:focus{border-color:#3b82f6}
.hint{font-size:11px;color:#475569;margin-bottom:16px}
button{width:100%;padding:12px;background:#3b82f6;border:none;border-radius:8px;color:#fff;font-size:14px;font-weight:600;cursor:pointer}
button:hover{background:#2563eb}
.err{color:#ef4444;font-size:12px;margin-bottom:8px;display:none}
</style>
</head>
<body>
<div class="box">
<h1><span>Myth</span>Net</h1>
<div class="sub">First-time setup — choose your admin password</div>
<form class="card" method="POST" action="/setup" onsubmit="return validate()">
<label>Admin Password</label>
<input type="password" name="password" id="pw1" placeholder="Choose a password" autofocus>
<label>Confirm Password</label>
<input type="password" id="pw2" placeholder="Confirm password">
<div class="hint">This password protects access to your network dashboard.</div>
<div class="err" id="err"></div>
<button type="submit">Set Password & Launch</button>
</form>
</div>
<script>
function validate(){
var p1=document.getElementById('pw1').value;
var p2=document.getElementById('pw2').value;
var err=document.getElementById('err');
if(p1.length<4){err.textContent='Password must be at least 4 characters';err.style.display='block';return false}
if(p1!==p2){err.textContent='Passwords do not match';err.style.display='block';return false}
return true}
</script>
</body>
</html>`
