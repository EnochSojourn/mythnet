package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
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
	logFormat := flag.String("log-format", "text", "log format: text or json")
	scanOnce := flag.String("scan", "", "one-shot scan: run a single scan on CIDR and exit (e.g. --scan 192.168.1.0/24)")
	scanJSON := flag.Bool("json", false, "output one-shot scan results as JSON")
	flag.Parse()

	if *showVersion {
		fmt.Printf("mythnet %s\n", version)
		os.Exit(0)
	}

	if *scanOnce != "" {
		runOneShotScan(*scanOnce, *scanJSON)
		return
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
	var handler slog.Handler
	opts := &slog.HandlerOptions{Level: level}
	if *logFormat == "json" {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}
	logger := slog.New(handler)
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

	// Start alert manager (webhook + email notifications)
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

	// Start scheduled report generator
	if aiClient != nil && cfg.Alerts.ReportInterval > 0 {
		sched := alerts.NewReportScheduler(store, aiClient, logger, cfg.Alerts.ReportInterval, &cfg.Alerts.SMTP)
		go sched.Run(ctx)
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

func runOneShotScan(cidr string, asJSON bool) {
	cfg := config.Default()
	cfg.Scanner.Subnets = []string{cidr}

	store, err := db.New(":memory:")
	if err != nil {
		fmt.Fprintf(os.Stderr, "db: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	sc := scanner.New(cfg, store, logger)

	fmt.Fprintf(os.Stderr, "Scanning %s...\n", cidr)
	ctx := context.Background()
	sc.TriggerScan("")
	go sc.Run(ctx)

	// Wait for scan to complete
	time.Sleep(1 * time.Second)
	for sc.IsRunning() {
		time.Sleep(500 * time.Millisecond)
	}

	devices, _ := store.ListDevices()

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(devices)
		return
	}

	// Table format
	fmt.Printf("%-18s %-20s %-20s %-18s %-8s %-6s\n", "IP", "HOSTNAME", "VENDOR", "TYPE", "OS", "PORTS")
	fmt.Println(strings.Repeat("-", 94))
	for _, d := range devices {
		ports, _ := store.GetDevicePorts(d.ID)
		portList := make([]string, len(ports))
		for i, p := range ports {
			portList[i] = fmt.Sprintf("%d/%s", p.Port, p.Service)
		}
		os := d.OSGuess
		if len(os) > 8 {
			os = os[:8]
		}
		vendor := d.Vendor
		if len(vendor) > 20 {
			vendor = vendor[:18] + ".."
		}
		hostname := d.Hostname
		if len(hostname) > 20 {
			hostname = hostname[:18] + ".."
		}
		devType := d.DeviceType
		if len(devType) > 18 {
			devType = devType[:16] + ".."
		}
		fmt.Printf("%-18s %-20s %-20s %-18s %-8s %s\n",
			d.IP, hostname, vendor, devType, os, strings.Join(portList, ","))
	}
	fmt.Fprintf(os.Stderr, "\n%d device(s) found\n", len(devices))
}
