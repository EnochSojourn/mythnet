package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/mythnet/mythnet/internal/db"
)

// Standard SNMP OIDs for system info
const (
	oidSysDescr    = "1.3.6.1.2.1.1.1.0"
	oidSysName     = "1.3.6.1.2.1.1.5.0"
	oidSysUpTime   = "1.3.6.1.2.1.1.3.0"
	oidSysContact  = "1.3.6.1.2.1.1.4.0"
	oidSysLocation = "1.3.6.1.2.1.1.6.0"
)

// SNMPPoller actively queries SNMP-enabled devices for system info.
type SNMPPoller struct {
	store     *db.Store
	logger    *slog.Logger
	community string
	interval  time.Duration
}

// NewSNMPPoller creates a new SNMP active poller.
func NewSNMPPoller(store *db.Store, logger *slog.Logger, community string, interval time.Duration) *SNMPPoller {
	if interval == 0 {
		interval = 5 * time.Minute
	}
	return &SNMPPoller{store: store, logger: logger, community: community, interval: interval}
}

// Run starts the SNMP polling loop.
func (p *SNMPPoller) Run(ctx context.Context) {
	p.logger.Info("SNMP active poller starting", "interval", p.interval)

	// Wait for devices to be discovered
	select {
	case <-ctx.Done():
		return
	case <-time.After(30 * time.Second):
	}

	p.pollAll(ctx)

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.pollAll(ctx)
		}
	}
}

func (p *SNMPPoller) pollAll(ctx context.Context) {
	devices, err := p.store.ListDevices()
	if err != nil {
		return
	}

	for _, dev := range devices {
		if !dev.IsOnline {
			continue
		}
		select {
		case <-ctx.Done():
			return
		default:
		}

		p.pollDevice(dev)
	}
}

func (p *SNMPPoller) pollDevice(dev *db.Device) {
	snmp := &gosnmp.GoSNMP{
		Target:    dev.IP,
		Port:      161,
		Community: p.community,
		Version:   gosnmp.Version2c,
		Timeout:   3 * time.Second,
		Retries:   1,
	}

	if err := snmp.Connect(); err != nil {
		return // Device may not support SNMP — silently skip
	}
	defer snmp.Conn.Close()

	oids := []string{oidSysDescr, oidSysName, oidSysUpTime, oidSysContact, oidSysLocation}
	result, err := snmp.Get(oids)
	if err != nil {
		return // Not SNMP-enabled
	}

	info := parseSNMPResult(result)
	if info.sysName == "" && info.sysDescr == "" {
		return
	}

	p.logger.Debug("SNMP polled device",
		"ip", dev.IP,
		"sysName", info.sysName,
		"sysDescr", truncate(info.sysDescr, 60),
		"uptime", info.uptime,
	)

	// Update device with SNMP-enriched data
	if info.sysName != "" && dev.Hostname == "" {
		dev.Hostname = info.sysName
	}
	if info.sysDescr != "" && dev.OSGuess == "" {
		dev.OSGuess = guessSNMPOS(info.sysDescr)
	}
	dev.LastSeen = time.Now()
	p.store.UpsertDevice(dev)

	// Store as a Markdown event (only if first time or sys info changed)
	if p.store.HasRecentEvent(dev.ID, "snmp_poll", "SNMP System Info — "+dev.IP, 1*time.Hour) {
		return
	}

	var b strings.Builder
	fmt.Fprintf(&b, "## SNMP System Info — %s\n\n", dev.IP)
	if info.sysName != "" {
		fmt.Fprintf(&b, "**sysName:** %s  \n", info.sysName)
	}
	if info.sysDescr != "" {
		fmt.Fprintf(&b, "**sysDescr:** %s  \n", info.sysDescr)
	}
	if info.uptime != "" {
		fmt.Fprintf(&b, "**sysUpTime:** %s  \n", info.uptime)
	}
	if info.contact != "" {
		fmt.Fprintf(&b, "**sysContact:** %s  \n", info.contact)
	}
	if info.location != "" {
		fmt.Fprintf(&b, "**sysLocation:** %s  \n", info.location)
	}

	p.store.InsertEvent(&db.Event{
		DeviceID:   dev.ID,
		Source:     "snmp_poll",
		Severity:   "info",
		Title:      "SNMP System Info — " + dev.IP,
		BodyMD:     b.String(),
		RawData:    fmt.Sprintf("sysName=%s sysDescr=%s", info.sysName, info.sysDescr),
		ReceivedAt: time.Now(),
		Tags:       "snmp,poll,sysinfo",
	})
}

type snmpInfo struct {
	sysDescr string
	sysName  string
	uptime   string
	contact  string
	location string
}

func parseSNMPResult(result *gosnmp.SnmpPacket) snmpInfo {
	info := snmpInfo{}
	for _, v := range result.Variables {
		if v.Type == gosnmp.NoSuchObject || v.Type == gosnmp.NoSuchInstance {
			continue
		}
		val := fmt.Sprintf("%s", v.Value)
		switch v.Name {
		case "." + oidSysDescr:
			info.sysDescr = val
		case "." + oidSysName:
			info.sysName = val
		case "." + oidSysUpTime:
			// TimeTicks in hundredths of a second
			if ticks, ok := v.Value.(uint32); ok {
				secs := ticks / 100
				days := secs / 86400
				hours := (secs % 86400) / 3600
				mins := (secs % 3600) / 60
				info.uptime = fmt.Sprintf("%dd %dh %dm", days, hours, mins)
			} else {
				info.uptime = val
			}
		case "." + oidSysContact:
			info.contact = val
		case "." + oidSysLocation:
			info.location = val
		}
	}
	return info
}

func guessSNMPOS(sysDescr string) string {
	lower := strings.ToLower(sysDescr)
	switch {
	case strings.Contains(lower, "cisco ios"):
		return "Cisco IOS"
	case strings.Contains(lower, "junos"):
		return "Juniper JunOS"
	case strings.Contains(lower, "routeros"):
		return "MikroTik RouterOS"
	case strings.Contains(lower, "linux"):
		return "Linux"
	case strings.Contains(lower, "windows"):
		return "Windows"
	case strings.Contains(lower, "freebsd"):
		return "FreeBSD"
	case strings.Contains(lower, "ubiquiti") || strings.Contains(lower, "edgeos"):
		return "Ubiquiti EdgeOS"
	case strings.Contains(lower, "fortinet") || strings.Contains(lower, "fortigate"):
		return "Fortinet FortiOS"
	default:
		if len(sysDescr) > 60 {
			return sysDescr[:60]
		}
		return sysDescr
	}
}
