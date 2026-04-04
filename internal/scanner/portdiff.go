package scanner

import (
	"fmt"
	"strings"
	"time"

	"github.com/mythnet/mythnet/internal/db"
)

// PortChange represents a detected port state change.
type PortChange struct {
	DeviceID string
	DeviceIP string
	Port     int
	Service  string
	Change   string // "opened" or "closed"
}

// DetectPortChanges compares newly scanned ports against previously known ports.
func DetectPortChanges(store *db.Store, deviceID, deviceIP string, currentPorts []PortResult) []PortChange {
	previousPorts, err := store.GetDevicePorts(deviceID)
	if err != nil || len(previousPorts) == 0 {
		return nil // First scan for this device — no changes to detect
	}

	prevSet := make(map[int]db.Port)
	for _, p := range previousPorts {
		prevSet[p.Port] = p
	}

	currSet := make(map[int]PortResult)
	for _, p := range currentPorts {
		currSet[p.Port] = p
	}

	var changes []PortChange

	// Detect newly opened ports
	for _, p := range currentPorts {
		if _, existed := prevSet[p.Port]; !existed {
			changes = append(changes, PortChange{
				DeviceID: deviceID,
				DeviceIP: deviceIP,
				Port:     p.Port,
				Service:  p.Service,
				Change:   "opened",
			})
		}
	}

	// Detect closed ports (were open, now gone)
	for _, p := range previousPorts {
		if _, stillOpen := currSet[p.Port]; !stillOpen {
			changes = append(changes, PortChange{
				DeviceID: deviceID,
				DeviceIP: deviceIP,
				Port:     p.Port,
				Service:  p.Service,
				Change:   "closed",
			})
		}
	}

	return changes
}

// PortChangesToEvents converts port changes into database events with Markdown bodies.
func PortChangesToEvents(changes []PortChange) []*db.Event {
	var events []*db.Event

	for _, c := range changes {
		severity := "info"
		emoji := "+"
		if c.Change == "closed" {
			severity = "warning"
			emoji = "-"
		}
		// New unexpected ports are more concerning
		if c.Change == "opened" && isDangerousPort(c.Port) {
			severity = "critical"
		}

		title := fmt.Sprintf("Port %d %s on %s", c.Port, c.Change, c.DeviceIP)

		var b strings.Builder
		fmt.Fprintf(&b, "## Port Change — %s\n\n", c.DeviceIP)
		fmt.Fprintf(&b, "**Port:** %d/%s  \n", c.Port, c.Service)
		fmt.Fprintf(&b, "**Change:** %s %s  \n", emoji, c.Change)
		fmt.Fprintf(&b, "**Time:** %s\n", time.Now().Format(time.RFC3339))

		if c.Change == "opened" && isDangerousPort(c.Port) {
			b.WriteString("\n> **Security Warning:** This port is commonly associated with insecure or dangerous services.\n")
		}

		events = append(events, &db.Event{
			DeviceID:   c.DeviceID,
			Source:     "port_change",
			Severity:   severity,
			Title:      title,
			BodyMD:     b.String(),
			ReceivedAt: time.Now(),
			Tags:       fmt.Sprintf("port,%s,%d", c.Change, c.Port),
		})
	}

	return events
}

func isDangerousPort(port int) bool {
	dangerous := map[int]bool{
		23:   true, // telnet
		135:  true, // msrpc
		139:  true, // netbios
		445:  true, // smb
		1433: true, // mssql
		3389: true, // rdp (if unexpected)
		5900: true, // vnc
		6379: true, // redis (often unauthed)
	}
	return dangerous[port]
}
