package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/mythnet/mythnet/internal/ai"
	"github.com/mythnet/mythnet/internal/config"
	"github.com/mythnet/mythnet/internal/db"
	"github.com/mythnet/mythnet/internal/mesh"
	"github.com/mythnet/mythnet/internal/scanner"
	"github.com/mythnet/mythnet/web"
)

func meshIdentity(dataDir string) (*tls.Config, error) {
	id, err := mesh.LoadOrCreateIdentity(dataDir)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{id.Cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// Server is the HTTP API server.
type Server struct {
	cfg       *config.Config
	store     *db.Store
	scanner   *scanner.Scanner
	ai        ai.Client
	hub       *Hub
	logger    *slog.Logger
	http      *http.Server
	startTime time.Time
}

// New creates a new Server with all routes configured.
func New(cfg *config.Config, store *db.Store, sc *scanner.Scanner, aiClient ai.Client, logger *slog.Logger) *Server {
	hub := NewHub(logger)

	s := &Server{
		cfg:       cfg,
		store:     store,
		scanner:   sc,
		ai:        aiClient,
		hub:       hub,
		logger:    logger,
		startTime: time.Now(),
	}

	// Resolve auth password
	dataDir := cfg.Mesh.DataDir
	if dataDir == "" {
		dataDir = "./mythnet-data"
	}
	_, passwordHash := resolvePassword(cfg.Server.Password, dataDir, logger)

	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)
	r.Use(corsMiddleware)
	r.Use(authMiddleware(passwordHash, logger))
	r.Use(rateLimitMiddleware(newRateLimiter(300))) // 300 req/min per IP
	r.Use(requestLoggingMiddleware(logger))

	// API routes
	r.Route("/api", func(r chi.Router) {
		r.Get("/health", s.handleHealth)
		r.Get("/stats", s.handleStats)
		r.Get("/devices", s.handleListDevices)
		r.Get("/devices/{id}", s.handleGetDevice)
		r.Post("/devices/import", s.handleImportCSV)
		r.Get("/devices/{id}/ports", s.handleGetDevicePorts)
		r.Post("/devices/{id}/adapt", s.handleGenerateAdapter)
		r.Get("/devices/{id}/adapters", s.handleGetAdapters)
		r.Get("/devices/{id}/notes", s.handleGetNotes)
		r.Put("/devices/{id}/notes", s.handleSetNotes)
		r.Post("/devices/{id}/wake", s.handleWakeOnLAN)
		r.Get("/devices/{id}/traceroute", s.handleTraceroute)
		r.Get("/devices/{id}/audit", s.handleSecurityAudit)
		r.Get("/devices/{id}/timeline", s.handleDeviceTimeline)
		r.Get("/devices/{id}/capabilities", s.handleDeviceCapabilities)
		r.Post("/devices/{id}/control", s.handleDeviceControl)
		r.Get("/devices/{id}/tags", s.handleGetTags)
		r.Put("/devices/{id}/tags", s.handleSetTags)
		r.Get("/tags", s.handleAllTags)
		r.Get("/scans", s.handleListScans)
		r.Post("/scans", s.handleTriggerScan)
		r.Get("/events", s.handleListEvents)
		r.Get("/settings", s.handleGetSettings)
		r.Get("/backup", s.handleBackup)
		r.Get("/audit", s.handleAuditLog)
		r.Get("/diff", s.handleDiff)
		r.Get("/analytics", s.handleAnalytics)
		r.Get("/analysis", s.handleLatestAnalysis)
		r.Get("/flows", s.handleFlows)
		r.Get("/traffic", s.handleTrafficGraph)
		r.Get("/traffic/enriched", s.handleEnrichedTraffic)
		r.Get("/traffic/dns", s.handleDNSSummary)
		r.Get("/top-talkers", s.handleTopTalkers)
		r.Get("/playbooks", s.handleListPlaybooks)
		r.Post("/playbooks", s.handleCreatePlaybook)
		r.Get("/sniffer/stats", s.handleSnifferStats)
		r.Get("/sniffer/bandwidth", s.handleBandwidth)
		r.Get("/sniffer/protocols", s.handleProtocols)
		r.Get("/sniffer/dns", s.handleSnifferDNS)
		r.Get("/sniffer/dns/top", s.handleSnifferDNSTop)
		r.Get("/sniffer/ja3", s.handleJA3)
		r.Get("/sniffer/threatfeed", s.handleThreatFeedStats)
		r.Get("/sniffer/honeypots", s.handleHoneypots)
		r.Get("/predict", s.handlePredictions)
		r.Get("/attack-paths", s.handleAttackPaths)
		r.Get("/blast-radius", s.handleBlastRadius)
		r.Get("/firewall", s.handleFirewallList)
		r.Post("/firewall/block", s.handleFirewallBlock)
		r.Post("/firewall/unblock", s.handleFirewallUnblock)
		r.Get("/docs", s.handleAPIDocs)
		r.Get("/subnet", s.handleSubnetCalc)
		r.Get("/rules", s.handleListEventRules)
		r.Post("/rules", s.handleCreateEventRule)
		r.Get("/policies", s.handleListPolicies)
		r.Post("/policies", s.handleCreatePolicy)
		r.Get("/policies/check", s.handleCheckPolicies)
		r.Get("/tools/ping", s.handlePingTool)
		r.Get("/tools/dns", s.handleDNSLookup)
		r.Get("/tools/port", s.handlePortCheck)
		r.Get("/tools/snmpwalk", s.handleSNMPWalk)
		r.Get("/tools/whois", s.handleWhois)
		r.Get("/digest", s.handleDigest)
		r.Get("/sla", s.handleSLA)
		r.Get("/docs/network", s.handleNetworkDoc)
		r.Get("/snapshots", s.handleSnapshots)
		r.Get("/mesh", s.handleMeshStatus)
		r.Get("/chat", s.handleChat)
		r.Post("/reports", s.handleGenerateReport)
		r.Get("/ws", hub.HandleWS)
	})

	// Public endpoints (no auth — outside /api/)
	r.Get("/dashboard", s.handleDashboard)
	r.Get("/dashboard/", s.handleDashboard)
	r.Get("/m", s.handleMobile)
	r.Get("/m/", s.handleMobile)
	r.Get("/warroom", s.handleWarroomPage)
	r.Get("/warroom/", s.handleWarroomPage)
	r.Get("/status", s.handleStatusPage)
	r.Get("/metrics", s.handleMetrics)
	r.Get("/topology.svg", s.handleTopologySVG)
	r.HandleFunc("/debug/pprof/*", pprofHandler())
	r.HandleFunc("/debug/pprof/", pprofHandler())

	// Reverse proxy to device web UIs
	r.HandleFunc("/proxy/{deviceID}/{port}/*", s.handleProxy)
	r.HandleFunc("/proxy/{deviceID}/{port}", s.handleProxy)

	// Serve embedded frontend (SPA with fallback to index.html)
	buildFS, err := fs.Sub(web.Assets, "build")
	if err == nil {
		fileServer := http.FileServer(http.FS(buildFS))
		r.NotFound(spaHandler(buildFS, fileServer))
	}

	// Wire real-time push: Store mutations → WebSocket broadcast
	store.SetNotifyHook(func(table, op string, data any) {
		hub.Broadcast(op, data)
	})

	s.http = &http.Server{Handler: r}

	return s
}

// ListenAndServe starts the HTTP or HTTPS server on the given address.
func (s *Server) ListenAndServe(addr string) error {
	s.http.Addr = addr

	tlsCfg := s.cfg.Server.TLS
	if tlsCfg.Enabled {
		certFile := tlsCfg.CertFile
		keyFile := tlsCfg.KeyFile

		// Auto-generate self-signed cert if none provided
		if certFile == "" || keyFile == "" {
			dataDir := s.cfg.Mesh.DataDir
			if dataDir == "" {
				dataDir = "./mythnet-data"
			}
			identity, err := meshIdentity(dataDir)
			if err != nil {
				return fmt.Errorf("auto-tls: %w", err)
			}
			s.http.TLSConfig = identity
			s.logger.Info("HTTPS enabled (auto-generated certificate)")
			return s.http.ListenAndServeTLS("", "")
		}

		s.logger.Info("HTTPS enabled", "cert", certFile, "key", keyFile)
		return s.http.ListenAndServeTLS(certFile, keyFile)
	}

	return s.http.ListenAndServe()
}

// Shutdown gracefully shuts down the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

// spaHandler serves static files from the embedded filesystem, falling back
// to index.html for any path that doesn't match a real file (SPA routing).
func spaHandler(assets fs.FS, fileServer http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}

		// Check if the requested file exists
		if _, err := fs.Stat(assets, path); err != nil {
			// File doesn't exist — serve index.html for SPA client-side routing
			r.URL.Path = "/"
		}

		fileServer.ServeHTTP(w, r)
	}
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
