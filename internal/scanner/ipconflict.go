package scanner

import (
	"fmt"
	"strings"
	"time"

	"github.com/mythnet/mythnet/internal/db"
)

// DetectIPConflicts checks for multiple devices with the same IP but different MACs.
func DetectIPConflicts(store *db.Store) []*db.Event {
	devices, err := store.ListDevices()
	if err != nil {
		return nil
	}

	// Group by IP
	ipToDevices := make(map[string][]*db.Device)
	for _, d := range devices {
		if d.MAC != "" && d.IsOnline {
			ipToDevices[d.IP] = append(ipToDevices[d.IP], d)
		}
	}

	// Also check ARP table for multiple MACs per IP
	arpTable := ReadARPTable()
	macByIP := make(map[string]map[string]bool)
	for ip, mac := range arpTable {
		if macByIP[ip] == nil {
			macByIP[ip] = make(map[string]bool)
		}
		macByIP[ip][mac] = true
	}

	// Add known device MACs
	for _, d := range devices {
		if d.MAC != "" {
			if macByIP[d.IP] == nil {
				macByIP[d.IP] = make(map[string]bool)
			}
			macByIP[d.IP][d.MAC] = true
		}
	}

	var events []*db.Event
	now := time.Now()

	for ip, macs := range macByIP {
		if len(macs) <= 1 {
			continue
		}

		macList := make([]string, 0, len(macs))
		for mac := range macs {
			macList = append(macList, mac)
		}

		title := fmt.Sprintf("IP conflict detected: %s has %d MAC addresses", ip, len(macs))

		var b strings.Builder
		fmt.Fprintf(&b, "## IP Address Conflict — %s\n\n", ip)
		fmt.Fprintf(&b, "**IP:** `%s`  \n", ip)
		fmt.Fprintf(&b, "**MAC addresses seen:**\n\n")
		for _, mac := range macList {
			vendor := LookupVendor(mac)
			fmt.Fprintf(&b, "- `%s`", mac)
			if vendor != "" {
				fmt.Fprintf(&b, " (%s)", vendor)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n> **Security Alert:** Multiple MAC addresses on the same IP may indicate ARP spoofing, a DHCP conflict, or a man-in-the-middle attack.\n")

		events = append(events, &db.Event{
			Source:     "ip_conflict",
			Severity:   "critical",
			Title:      title,
			BodyMD:     b.String(),
			ReceivedAt: now,
			Tags:       "security,arp,conflict",
		})
	}

	return events
}
