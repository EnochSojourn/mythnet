package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mythnet/mythnet/internal/ai"
	"github.com/mythnet/mythnet/internal/alerts"
	"github.com/mythnet/mythnet/internal/config"
	"github.com/mythnet/mythnet/internal/db"
	"github.com/mythnet/mythnet/internal/mesh"
	"github.com/mythnet/mythnet/internal/scanner"
	"github.com/mythnet/mythnet/internal/server"
	"github.com/mythnet/mythnet/internal/telemetry"
)

var version = "dev"

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to configuration file")
	flag.StringVar(cfgPath, "c", "config.yaml", "path to configuration file (shorthand)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("mythnet %s\n", version)
		os.Exit(0)
	}

	// Load config (uses defaults if file not found)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Structured logger
	var level slog.Level
	switch cfg.Log.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	// Startup banner
	fmt.Fprintf(os.Stderr, "\033[36m"+`
  ╔╦╗╦ ╦╔╦╗╦ ╦╔╗╔╔═╗╔╦╗
  ║║║╚╦╝ ║ ╠═╣║║║║╣  ║
  ╩ ╩ ╩  ╩ ╩ ╩╝╚╝╚═╝ ╩  `+"\033[0m %s\n\n", version)

	// Auto-detect local subnets if none configured
	if len(cfg.Scanner.Subnets) == 0 {
		subnets := detectLocalSubnets()
		if len(subnets) > 0 {
			cfg.Scanner.Subnets = subnets
			logger.Info("auto-detected subnets", "subnets", subnets)
		} else {
			logger.Warn("no subnets configured and auto-detection found none")
		}
	}

	// Initialize database
	store, err := db.New(cfg.Database.Path)
	if err != nil {
		logger.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer store.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start scanner
	sc := scanner.New(cfg, store, logger)
	go sc.Run(ctx)

	// Start mesh networking (gossip + mTLS replication)
	meshMgr, err := mesh.NewManager(cfg, store, logger)
	if err != nil {
		logger.Error("failed to initialize mesh", "error", err)
		os.Exit(1)
	}
	if meshMgr != nil {
		go meshMgr.Run(ctx)
		logger.Info("mesh enabled", "node_id", meshMgr.NodeID(), "type", cfg.Mesh.NodeType)
	}

	// Start telemetry (SNMP traps, syslog, API polling)
	tm := telemetry.NewManager(cfg, store, logger)
	go tm.Run(ctx)

	// Start alert manager (webhook notifications)
	alertMgr := alerts.NewManager(&cfg.Alerts, store, logger)
	go alertMgr.Run(ctx)

	// Initialize AI client
	var aiClient ai.Client
	apiKey := cfg.AI.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("ANTHROPIC_API_KEY")
	}
	if cfg.AI.Enabled && apiKey != "" {
		aiClient = ai.NewAnthropicClient(apiKey, cfg.AI.Model)
		logger.Info("AI enabled", "model", cfg.AI.Model)
	} else {
		logger.Info("AI disabled — set ai.api_key or ANTHROPIC_API_KEY to enable")
	}

	// Periodic snapshot recording for dashboard charts
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				store.RecordSnapshot()
				store.PruneSnapshots(48 * time.Hour)
				store.PruneLatency(48 * time.Hour)
			}
		}
	}()

	// Start HTTP server
	srv := server.New(cfg, store, sc, aiClient, logger)

	// Config hot-reload: watch file + SIGHUP
	reloadable := config.NewReloadable(*cfgPath, cfg, logger)
	reloadable.OnChange(func(newCfg *config.Config) {
		cfg = newCfg
		logger.Info("config applied", "subnets", newCfg.Scanner.Subnets)
	})
	go reloadable.Watch(ctx.Done())

	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	go func() {
		for range hupCh {
			if err := reloadable.Reload(); err != nil {
				logger.Error("SIGHUP reload failed", "error", err)
			}
		}
	}()

	// Graceful shutdown on SIGINT/SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		logger.Info("shutting down...")
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		srv.Shutdown(shutdownCtx)
	}()

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)

	// Feature summary
	features := []string{"scanner", "telemetry"}
	if cfg.Mesh.Enabled {
		features = append(features, "mesh")
	}
	if aiClient != nil {
		features = append(features, "ai")
	}
	if cfg.Server.TLS.Enabled {
		features = append(features, "tls")
	}
	fmt.Fprintf(os.Stderr, "  \033[32m→\033[0m Listening on \033[1m%s\033[0m\n", addr)
	fmt.Fprintf(os.Stderr, "  \033[32m→\033[0m Subnets: %v\n", cfg.Scanner.Subnets)
	fmt.Fprintf(os.Stderr, "  \033[32m→\033[0m Features: %v\n", features)
	fmt.Fprintf(os.Stderr, "  \033[32m→\033[0m API docs: http://%s/api/docs\n\n", addr)

	logger.Info("mythnet starting", "version", version, "addr", addr)

	if err := srv.ListenAndServe(addr); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}
}

func detectLocalSubnets() []string {
	var subnets []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.To4() == nil {
				continue
			}
			if ipNet.IP.IsLinkLocalUnicast() {
				continue
			}
			subnets = append(subnets, ipNet.String())
		}
	}
	return subnets
}
