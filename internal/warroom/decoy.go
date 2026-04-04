package warroom

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/mythnet/mythnet/internal/db"
)

// DecoyNetwork creates fake services on unused IPs to detect scanners.
// Any connection to any decoy = confirmed network reconnaissance.
type DecoyNetwork struct {
	store   *db.Store
	logger  *slog.Logger
	subnet  string
	decoys  []string // IPs we're pretending to be
}

// NewDecoyNetwork sets up decoy services on specified ports across multiple IPs.
func NewDecoyNetwork(store *db.Store, logger *slog.Logger) *DecoyNetwork {
	return &DecoyNetwork{
		store:  store,
		logger: logger,
	}
}

// Run starts decoy listeners on high-value ports.
// These supplement the honeypot system by covering more ports.
func (dn *DecoyNetwork) Run(ctx context.Context) {
	// Additional decoy ports beyond the main honeypots
	// These mimic services attackers look for
	decoyPorts := []struct {
		port    int
		service string
		banner  string
	}{
		{4444, "metasploit-default", ""},           // Metasploit default listener
		{5555, "android-debug", ""},                 // Android ADB
		{6667, "irc-botnet", ":irc.local NOTICE * :***\r\n"}, // IRC C2
		{8291, "mikrotik-winbox", ""},               // MikroTik management
		{10000, "webmin", "HTTP/1.0 200 OK\r\nServer: MiniServ/1.900\r\n\r\n"}, // Webmin
		{27017, "mongodb-decoy", ""},                // MongoDB (unauth)
		{11211, "memcached-decoy", ""},              // Memcached
	}

	active := 0
	for _, dp := range decoyPorts {
		go func(port int, service, banner string) {
			ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
			if err != nil {
				return
			}
			defer ln.Close()

			go func() { <-ctx.Done(); ln.Close() }()

			for {
				conn, err := ln.Accept()
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					continue
				}
				go dn.handleDecoy(conn, port, service, banner)
			}
		}(dp.port, dp.service, dp.banner)
		active++
	}

	dn.logger.Info("decoy network active", "additional_ports", active)
	<-ctx.Done()
}

func (dn *DecoyNetwork) handleDecoy(conn net.Conn, port int, service, banner string) {
	defer conn.Close()

	remoteIP := conn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(remoteIP); err == nil {
		remoteIP = host
	}

	// Never alert on our own scanner hitting our own decoys
	if isSelfIP(remoteIP) {
		return
	}

	dn.logger.Warn("DECOY TRIGGERED", "port", port, "service", service, "attacker", remoteIP)

	if banner != "" {
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		conn.Write([]byte(banner))
	}

	// Capture probe
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	probe := ""
	if n > 0 {
		probe = sanitizeProbe(string(buf[:n]))
	}

	body := fmt.Sprintf("## 🎯 Decoy Service Triggered\n\n"+
		"**Attacker:** `%s`  \n"+
		"**Decoy Port:** %d (%s)  \n"+
		"**Time:** %s  \n",
		remoteIP, port, service, time.Now().Format(time.RFC3339))

	if probe != "" {
		body += fmt.Sprintf("\n### Captured Probe\n\n```\n%s\n```\n", probe)
	}

	body += "\n> This is a decoy service. No legitimate device should connect to it. The source is actively probing your network."

	dn.store.InsertEvent(&db.Event{
		Source:     "decoy",
		Severity:   "critical",
		Title:      fmt.Sprintf("DECOY HIT: %s probed :%d (%s)", remoteIP, port, service),
		BodyMD:     body,
		ReceivedAt: time.Now(),
		Tags:       "decoy,intrusion,threat",
	})

	// Auto-block external IPs that hit decoys
	AutoBlock(remoteIP, "hit decoy service: "+service)
}
