package alerts

import (
	"fmt"
	"net"
	"time"

	"github.com/mythnet/mythnet/internal/db"
)

// SyslogForwarder sends MythNet events as syslog messages to an external server.
type SyslogForwarder struct {
	addr string
	conn net.Conn
}

// NewSyslogForwarder creates a forwarder to the specified syslog server (host:port).
func NewSyslogForwarder(addr string) (*SyslogForwarder, error) {
	if addr == "" {
		return nil, nil
	}
	conn, err := net.DialTimeout("udp", addr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("syslog forward connect %s: %w", addr, err)
	}
	return &SyslogForwarder{addr: addr, conn: conn}, nil
}

// Forward sends an event as a syslog message (RFC 3164 format).
func (f *SyslogForwarder) Forward(event *db.Event) error {
	if f == nil || f.conn == nil {
		return nil
	}

	// Map MythNet severity to syslog priority
	// facility=local0 (16), severity mapped from event
	facility := 16 // local0
	severity := 6  // info
	switch event.Severity {
	case "critical":
		severity = 2 // critical
	case "warning":
		severity = 4 // warning
	case "debug":
		severity = 7 // debug
	}
	pri := facility*8 + severity

	// RFC 3164: <PRI>TIMESTAMP HOSTNAME APP: MSG
	ts := event.ReceivedAt.Format("Jan  2 15:04:05")
	msg := fmt.Sprintf("<%d>%s mythnet %s[%s]: %s",
		pri, ts, event.Source, event.Severity, event.Title)

	_, err := f.conn.Write([]byte(msg))
	return err
}

// Close closes the forwarding connection.
func (f *SyslogForwarder) Close() {
	if f != nil && f.conn != nil {
		f.conn.Close()
	}
}
