package warroom

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/mythnet/mythnet/internal/db"
)

// Honeypot opens fake services to detect network intruders.
// Any connection to these ports = someone is scanning your network.
type Honeypot struct {
	store    *db.Store
	logger   *slog.Logger
	ports    []HoneypotPort
}

// HoneypotPort defines a fake service.
type HoneypotPort struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Banner  string `json:"banner"`
}

// DefaultHoneypots returns a set of enticing fake services.
func DefaultHoneypots() []HoneypotPort {
	return []HoneypotPort{
		{Port: 2222, Service: "ssh-honeypot", Banner: "SSH-2.0-OpenSSH_7.4\r\n"},
		{Port: 8888, Service: "http-honeypot", Banner: "HTTP/1.0 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Admin\"\r\n\r\n"},
		{Port: 3380, Service: "rdp-honeypot", Banner: ""},
		{Port: 1080, Service: "socks-honeypot", Banner: ""},
		{Port: 9200, Service: "elasticsearch-honeypot", Banner: "{\"name\":\"node-1\",\"cluster_name\":\"elasticsearch\"}\n"},
	}
}

func NewHoneypot(store *db.Store, logger *slog.Logger) *Honeypot {
	return &Honeypot{
		store:  store,
		logger: logger,
		ports:  DefaultHoneypots(),
	}
}

// Run starts all honeypot listeners.
func (h *Honeypot) Run(ctx context.Context) {
	for _, hp := range h.ports {
		go h.listen(ctx, hp)
	}

	portList := ""
	for _, hp := range h.ports {
		if portList != "" { portList += ", " }
		portList += fmt.Sprintf("%d/%s", hp.Port, hp.Service)
	}
	h.logger.Info("honeypots active", "ports", portList)

	<-ctx.Done()
}

func (h *Honeypot) listen(ctx context.Context, hp HoneypotPort) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", hp.Port))
	if err != nil {
		h.logger.Debug("honeypot port unavailable", "port", hp.Port, "error", err)
		return
	}
	defer ln.Close()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}

		go h.handleConnection(conn, hp)
	}
}

func (h *Honeypot) handleConnection(conn net.Conn, hp HoneypotPort) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	remoteIP := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteIP = host
	}

	h.logger.Warn("HONEYPOT TRIGGERED",
		"port", hp.Port, "service", hp.Service, "attacker", remoteIP)

	// Send banner to keep attacker engaged briefly
	if hp.Banner != "" {
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		conn.Write([]byte(hp.Banner))
	}

	// Read whatever they send (capture probe data)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	probe := ""
	if n > 0 {
		probe = sanitizeProbe(string(buf[:n]))
	}

	// Generate critical alert
	body := fmt.Sprintf("## 🚨 Honeypot Triggered!\n\n"+
		"**Attacker IP:** `%s`  \n"+
		"**Honeypot Port:** %d (%s)  \n"+
		"**Time:** %s  \n",
		remoteIP, hp.Port, hp.Service, time.Now().Format(time.RFC3339))

	if probe != "" {
		body += fmt.Sprintf("\n### Probe Data\n\n```\n%s\n```\n", probe)
	}

	body += "\n> **This is a confirmed intrusion attempt.** No legitimate device should connect to honeypot ports. The source IP is actively scanning or attacking your network."

	h.store.InsertEvent(&db.Event{
		Source:     "honeypot",
		Severity:   "critical",
		Title:      fmt.Sprintf("INTRUSION: %s connected to honeypot :%d (%s)", remoteIP, hp.Port, hp.Service),
		BodyMD:     body,
		ReceivedAt: time.Now(),
		Tags:       "honeypot,intrusion,critical,threat",
	})
}

func sanitizeProbe(s string) string {
	clean := make([]byte, 0, len(s))
	for _, b := range []byte(s) {
		if b >= 32 && b < 127 || b == '\n' || b == '\r' {
			clean = append(clean, b)
		} else {
			clean = append(clean, '.')
		}
	}
	if len(clean) > 200 {
		clean = clean[:200]
	}
	return string(clean)
}

// GetHoneypotStatus returns which honeypots are active.
func GetHoneypotPorts() []HoneypotPort {
	return DefaultHoneypots()
}
