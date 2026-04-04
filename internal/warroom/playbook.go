package warroom

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/mythnet/mythnet/internal/db"
)

// Playbook defines an automated response to a matching event.
type Playbook struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Trigger     string `json:"trigger"`     // event source to match
	Pattern     string `json:"pattern"`     // substring match on title
	MinSeverity string `json:"min_severity"` // minimum severity to trigger
	Action      string `json:"action"`      // action type
	ActionArgs  string `json:"action_args"` // JSON args
	Enabled     bool   `json:"enabled"`
	LastFired   string `json:"last_fired"`
}

// PlaybookEngine evaluates events against playbooks and executes responses.
type PlaybookEngine struct {
	store  *db.Store
	logger *slog.Logger
	lastID int64
}

func NewPlaybookEngine(store *db.Store, logger *slog.Logger) *PlaybookEngine {
	store.DB().Exec(`
		CREATE TABLE IF NOT EXISTS playbooks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			data TEXT NOT NULL
		)
	`)
	return &PlaybookEngine{store: store, logger: logger}
}

func (pe *PlaybookEngine) Run(ctx context.Context) {
	pe.logger.Info("playbook engine started")

	// Start from latest event
	events, _ := pe.store.ListEvents(1, "", "", "")
	if len(events) > 0 {
		pe.lastID = events[0].ID
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pe.evaluate()
		}
	}
}

func (pe *PlaybookEngine) evaluate() {
	playbooks := pe.loadPlaybooks()
	if len(playbooks) == 0 {
		return
	}

	events, _ := pe.store.ListEvents(20, "", "", "")

	for _, e := range events {
		if e.ID <= pe.lastID {
			continue
		}
		pe.lastID = e.ID

		for _, pb := range playbooks {
			if !pb.Enabled {
				continue
			}
			if pe.matches(&pb, e) {
				pe.execute(&pb, e)
			}
		}
	}
}

func (pe *PlaybookEngine) matches(pb *Playbook, e *db.Event) bool {
	// Source match
	if pb.Trigger != "" && !strings.EqualFold(e.Source, pb.Trigger) {
		return false
	}

	// Pattern match
	if pb.Pattern != "" && !strings.Contains(strings.ToLower(e.Title), strings.ToLower(pb.Pattern)) {
		return false
	}

	// Severity check
	sevLevels := map[string]int{"critical": 0, "warning": 1, "info": 2, "debug": 3}
	if pb.MinSeverity != "" {
		minLevel := sevLevels[pb.MinSeverity]
		evtLevel := sevLevels[e.Severity]
		if evtLevel > minLevel {
			return false
		}
	}

	return true
}

func (pe *PlaybookEngine) execute(pb *Playbook, e *db.Event) {
	pe.logger.Info("playbook triggered", "playbook", pb.Name, "event", e.Title, "action", pb.Action)

	switch pb.Action {
	case "log":
		// Just log it (useful for testing)
		pe.store.InsertEvent(&db.Event{
			Source: "playbook", Severity: "info",
			Title:      "Playbook '" + pb.Name + "' fired on: " + e.Title,
			BodyMD:     "## Playbook Executed\n\n**Playbook:** " + pb.Name + "  \n**Trigger:** " + e.Title + "  \n**Action:** " + pb.Action,
			ReceivedAt: time.Now(), Tags: "playbook,auto-response",
		})

	case "escalate":
		// Re-emit as critical
		pe.store.InsertEvent(&db.Event{
			DeviceID: e.DeviceID, Source: "playbook", Severity: "critical",
			Title:      "ESCALATED: " + e.Title,
			BodyMD:     "## Auto-Escalated by Playbook\n\n**Playbook:** " + pb.Name + "  \n**Original:** " + e.Title + "\n\n" + e.BodyMD,
			ReceivedAt: time.Now(), Tags: "playbook,escalated",
		})

	case "control":
		// Send a command to a device
		var args struct {
			DeviceID string `json:"device_id"`
			Command  string `json:"command"`
		}
		json.Unmarshal([]byte(pb.ActionArgs), &args)
		if args.DeviceID != "" && args.Command != "" {
			ctrl := NewDeviceController(pe.store)
			result := ctrl.SendCommand(args.DeviceID, args.Command, nil)
			pe.store.InsertEvent(&db.Event{
				DeviceID: args.DeviceID, Source: "playbook", Severity: "info",
				Title:      "Auto-response: " + args.Command + " → " + args.DeviceID,
				BodyMD:     fmt.Sprintf("## Auto-Response Executed\n\n**Playbook:** %s  \n**Command:** %s  \n**Result:** %s", pb.Name, args.Command, result.Message),
				ReceivedAt: time.Now(), Tags: "playbook,auto-response,control",
			})
		}

	case "kill_chain":
		// Full automated incident response:
		// 1. Extract attacker IP from event
		// 2. Block at firewall
		// 3. Escalate to critical
		// 4. Generate forensic report

		// Extract IP from event title (pattern: "IP connected" or "from IP")
		attackerIP := extractIP(e.Title)
		if attackerIP == "" {
			attackerIP = extractIP(e.BodyMD)
		}

		steps := []string{}

		// Step 1: Block
		if attackerIP != "" && GlobalFirewall != nil {
			err := GlobalFirewall.BlockIP(attackerIP, "kill chain: "+pb.Name)
			if err == nil {
				steps = append(steps, "✅ Blocked "+attackerIP+" at firewall")
			} else {
				steps = append(steps, "⚠ Block failed: "+err.Error())
			}
		}

		// Step 2: Escalate
		pe.store.InsertEvent(&db.Event{
			DeviceID: e.DeviceID, Source: "kill_chain", Severity: "critical",
			Title: "🚨 KILL CHAIN: " + e.Title,
			BodyMD: fmt.Sprintf("## Automated Incident Response\n\n**Playbook:** %s  \n**Trigger:** %s  \n**Attacker IP:** `%s`  \n\n### Actions Taken\n\n%s\n\n### Original Event\n\n%s",
				pb.Name, e.Title, attackerIP, formatSteps(steps), e.BodyMD),
			ReceivedAt: time.Now(), Tags: "kill_chain,incident,automated",
		})
		steps = append(steps, "✅ Escalated to critical incident")

		pe.logger.Warn("KILL CHAIN EXECUTED",
			"playbook", pb.Name, "attacker", attackerIP, "steps", len(steps))
	}
}

func extractIP(text string) string {
	// Simple IP extraction from text
	parts := strings.Fields(text)
	for _, p := range parts {
		p = strings.Trim(p, "`*[]():")
		octets := strings.Split(p, ".")
		if len(octets) == 4 {
			valid := true
			for _, o := range octets {
				if len(o) == 0 || len(o) > 3 {
					valid = false
					break
				}
				for _, c := range o {
					if c < '0' || c > '9' {
						valid = false
						break
					}
				}
			}
			if valid {
				return p
			}
		}
	}
	return ""
}

func formatSteps(steps []string) string {
	result := ""
	for _, s := range steps {
		result += "- " + s + "\n"
	}
	return result
}

func (pe *PlaybookEngine) loadPlaybooks() []Playbook {
	rows, err := pe.store.DB().Query(`SELECT id, data FROM playbooks ORDER BY id`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var playbooks []Playbook
	for rows.Next() {
		var id int64
		var data string
		rows.Scan(&id, &data)
		var pb Playbook
		json.Unmarshal([]byte(data), &pb)
		pb.ID = id
		playbooks = append(playbooks, pb)
	}
	return playbooks
}
