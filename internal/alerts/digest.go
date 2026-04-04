package alerts

import (
	"fmt"
	"strings"
	"time"

	"github.com/mythnet/mythnet/internal/config"
	"github.com/mythnet/mythnet/internal/db"
)

// BuildDailyDigest creates a plain-text summary of the last 24 hours.
func BuildDailyDigest(store *db.Store) string {
	now := time.Now()
	stats, _ := store.GetStats()
	health := store.CalculateHealthScore()
	events, _ := store.ListEvents(100, "", "", "")
	devices, _ := store.ListDevices()

	cutoff := now.Add(-24 * time.Hour)

	var b strings.Builder
	b.WriteString(fmt.Sprintf("MythNet Daily Digest — %s\n", now.Format("2006-01-02")))
	b.WriteString(strings.Repeat("=", 50) + "\n\n")

	// Health score
	b.WriteString(fmt.Sprintf("Health Score: %d/100 (Grade: %s)\n", health.Score, health.Grade))
	for _, issue := range health.Issues {
		b.WriteString(fmt.Sprintf("  - %s\n", issue))
	}
	b.WriteString("\n")

	// Stats
	b.WriteString(fmt.Sprintf("Devices: %d total, %d online\n", stats.TotalDevices, stats.OnlineDevices))
	b.WriteString(fmt.Sprintf("Open Ports: %d\n", stats.TotalPorts))
	b.WriteString(fmt.Sprintf("Events (24h): %d total, %d critical\n\n", stats.TotalEvents, stats.CriticalEvents))

	// New devices
	var newDevices []string
	for _, d := range devices {
		if d.FirstSeen.After(cutoff) {
			name := d.IP
			if d.Hostname != "" {
				name = d.Hostname + " (" + d.IP + ")"
			}
			newDevices = append(newDevices, name)
		}
	}
	if len(newDevices) > 0 {
		b.WriteString(fmt.Sprintf("NEW DEVICES (%d):\n", len(newDevices)))
		for _, n := range newDevices {
			b.WriteString(fmt.Sprintf("  + %s\n", n))
		}
		b.WriteString("\n")
	}

	// Offline devices
	var offline []string
	for _, d := range devices {
		if !d.IsOnline {
			offline = append(offline, d.IP)
		}
	}
	if len(offline) > 0 {
		b.WriteString(fmt.Sprintf("OFFLINE DEVICES (%d):\n", len(offline)))
		for _, ip := range offline {
			b.WriteString(fmt.Sprintf("  - %s\n", ip))
		}
		b.WriteString("\n")
	}

	// Critical/warning events
	var critEvents []*db.Event
	for _, e := range events {
		if e.ReceivedAt.After(cutoff) && (e.Severity == "critical" || e.Severity == "warning") {
			critEvents = append(critEvents, e)
		}
	}
	if len(critEvents) > 0 {
		b.WriteString(fmt.Sprintf("ALERTS (%d):\n", len(critEvents)))
		for _, e := range critEvents {
			b.WriteString(fmt.Sprintf("  [%s] %s — %s\n", strings.ToUpper(e.Severity), e.Source, e.Title))
		}
		b.WriteString("\n")
	}

	b.WriteString("---\nSent by MythNet Network Monitor\n")
	return b.String()
}

// SendDailyDigest sends the digest via SMTP.
func SendDailyDigest(store *db.Store, smtpCfg *config.SMTPConfig) error {
	if smtpCfg.Host == "" || len(smtpCfg.To) == 0 {
		return nil
	}

	body := BuildDailyDigest(store)
	evt := &db.Event{
		Source:     "digest",
		Severity:   "info",
		Title:      "Daily Digest — " + time.Now().Format("2006-01-02"),
		BodyMD:     "```\n" + body + "\n```",
		ReceivedAt: time.Now(),
		Tags:       "digest,daily",
	}

	return SendEmail(smtpCfg, evt)
}
