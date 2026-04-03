package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/mythnet/mythnet/internal/db"
)

// SNMPListener listens for SNMP v1/v2c traps and stores them as events.
type SNMPListener struct {
	addr      string
	community string
	store     *db.Store
	logger    *slog.Logger
}

// NewSNMPListener creates a new SNMP trap listener.
func NewSNMPListener(addr, community string, store *db.Store, logger *slog.Logger) *SNMPListener {
	return &SNMPListener{addr: addr, community: community, store: store, logger: logger}
}

// Run starts listening for SNMP traps. Blocks until ctx is cancelled.
func (l *SNMPListener) Run(ctx context.Context) error {
	tl := gosnmp.NewTrapListener()
	tl.OnNewTrap = l.handleTrap
	tl.Params = gosnmp.Default
	tl.Params.Community = l.community

	l.logger.Info("SNMP trap listener starting", "addr", l.addr)

	go func() {
		<-ctx.Done()
		tl.Close()
	}()

	err := tl.Listen(l.addr)
	if err != nil && ctx.Err() == nil {
		return fmt.Errorf("snmp listen %s: %w", l.addr, err)
	}
	return nil
}

func (l *SNMPListener) handleTrap(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
	sourceIP := addr.IP.String()
	now := time.Now()

	trapOID := ""
	var vars []SNMPVar

	for _, v := range packet.Variables {
		oid := v.Name
		// SNMPv2 trap OID is in snmpTrapOID.0
		if oid == ".1.3.6.1.6.3.1.1.4.1.0" || oid == "1.3.6.1.6.3.1.1.4.1.0" {
			trapOID = fmt.Sprintf("%v", v.Value)
			continue
		}
		vars = append(vars, SNMPVar{
			OID:   oid,
			Type:  v.Type.String(),
			Value: fmt.Sprintf("%v", v.Value),
		})
	}

	// SNMPv1 enterprise OID fallback
	if trapOID == "" && packet.Enterprise != "" {
		trapOID = packet.Enterprise
	}
	if trapOID == "" {
		trapOID = "unknown"
	}

	event := FormatSNMPTrap(sourceIP, trapOID, vars, now)
	event.DeviceID = l.resolveDevice(sourceIP)

	l.logger.Info("SNMP trap received", "source", sourceIP, "oid", trapOID, "vars", len(vars))

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

func (l *SNMPListener) resolveDevice(ip string) string {
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
