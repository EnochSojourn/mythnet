package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mythnet/mythnet/internal/db"
)

// SyslogListener listens for RFC 3164 syslog messages over UDP.
type SyslogListener struct {
	addr   string
	store  *db.Store
	logger *slog.Logger
}

// NewSyslogListener creates a new syslog listener.
func NewSyslogListener(addr string, store *db.Store, logger *slog.Logger) *SyslogListener {
	return &SyslogListener{addr: addr, store: store, logger: logger}
}

// Run starts listening for syslog messages. Blocks until ctx is cancelled.
func (l *SyslogListener) Run(ctx context.Context) error {
	pc, err := net.ListenPacket("udp", l.addr)
	if err != nil {
		return fmt.Errorf("syslog listen %s: %w", l.addr, err)
	}
	defer pc.Close()

	l.logger.Info("syslog listener starting", "addr", l.addr)

	go func() {
		<-ctx.Done()
		pc.Close()
	}()

	buf := make([]byte, 65536)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}

		sourceIP := ""
		if udpAddr, ok := addr.(*net.UDPAddr); ok {
			sourceIP = udpAddr.IP.String()
		}

		l.handleMessage(sourceIP, string(buf[:n]))
	}
}

var priRe = regexp.MustCompile(`^<(\d{1,3})>(.*)`)

func (l *SyslogListener) handleMessage(sourceIP, raw string) {
	now := time.Now()

	facility := 1 // user
	severity := 6 // info
	hostname := ""
	tag := "syslog"
	message := raw

	if m := priRe.FindStringSubmatch(raw); m != nil {
		pri, _ := strconv.Atoi(m[1])
		facility = pri / 8
		severity = pri % 8
		rest := strings.TrimSpace(m[2])

		parts := strings.SplitN(rest, ": ", 2)
		if len(parts) == 2 {
			header := parts[0]
			message = parts[1]

			fields := strings.Fields(header)
			if len(fields) >= 4 {
				// "Mon DD HH:MM:SS hostname tag[pid]"
				hostname = fields[len(fields)-2]
				tag = fields[len(fields)-1]
			} else if len(fields) >= 2 {
				hostname = fields[0]
				tag = fields[1]
			} else if len(fields) == 1 {
				tag = fields[0]
			}
		}
	}

	// Strip PID from tag: "sshd[12345]" -> "sshd"
	if idx := strings.Index(tag, "["); idx >= 0 {
		tag = tag[:idx]
	}

	event := FormatSyslog(sourceIP, facility, severity, hostname, tag, message, now)
	event.DeviceID = l.resolveDevice(sourceIP)

	l.logger.Debug("syslog received", "source", sourceIP,
		"facility", syslogFacilityName(facility),
		"severity", syslogSeverityName(severity), "tag", tag)

	l.store.InsertEvent(&db.Event{
		DeviceID:   event.DeviceID,
		Source:     event.Source,
		Severity:   event.Severity,
		Title:      event.Title,
		BodyMD:     event.BodyMD,
		RawData:    event.RawData,
		ReceivedAt: now,
		Tags:       JoinTags(event.Tags),
	})
}

func (l *SyslogListener) resolveDevice(ip string) string {
	devices, err := l.store.ListDevices()
	if err != nil {
		return ""
	}
	for _, d := range devices {
		if d.IP == ip {
			return d.ID
		}
	}
	return ""
}
