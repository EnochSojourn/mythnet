package alerts

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/mythnet/mythnet/internal/config"
	"github.com/mythnet/mythnet/internal/db"
)

// Manager watches for events and fires webhook alerts.
type Manager struct {
	cfg       *config.AlertsConfig
	store     *db.Store
	logger    *slog.Logger
	client    *http.Client
	syslogFwd *SyslogForwarder
	lastID    int64
}

// NewManager creates a new alert manager.
func NewManager(cfg *config.AlertsConfig, store *db.Store, logger *slog.Logger) *Manager {
	fwd, _ := NewSyslogForwarder(cfg.SyslogForward)
	if fwd != nil {
		logger.Info("syslog forwarding enabled", "target", cfg.SyslogForward)
	}
	return &Manager{
		cfg:       cfg,
		syslogFwd: fwd,
		store:  store,
		logger: logger,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Run polls for new events and fires webhooks. Blocks until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) {
	if len(m.cfg.Webhooks) == 0 {
		return
	}

	m.logger.Info("alert manager starting", "webhooks", len(m.cfg.Webhooks), "min_severity", m.cfg.MinSeverity)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Start from latest event
	m.lastID = m.currentMaxID()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.check()
		}
	}
}

func (m *Manager) currentMaxID() int64 {
	events, _ := m.store.ListEvents(1, "", "", "")
	if len(events) > 0 {
		return events[0].ID
	}
	return 0
}

func (m *Manager) check() {
	events, err := m.store.ListEvents(50, "", "", "")
	if err != nil {
		return
	}

	// Process new events (newest first, so iterate in reverse for chronological order)
	var toAlert []*db.Event
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		if e.ID <= m.lastID {
			continue
		}
		if m.shouldAlert(e.Severity) {
			toAlert = append(toAlert, e)
		}
		if e.ID > m.lastID {
			m.lastID = e.ID
		}
	}

	for _, e := range toAlert {
		m.fireWebhooks(e)
		// Forward to external syslog/SIEM
		if m.syslogFwd != nil {
			m.syslogFwd.Forward(e)
		}
		// Send email if SMTP is configured
		if m.cfg.SMTP.Host != "" {
			go func(evt *db.Event) {
				if err := SendEmail(&m.cfg.SMTP, evt); err != nil {
					m.logger.Error("email alert failed", "error", err)
				}
			}(e)
		}
	}
}

func (m *Manager) shouldAlert(severity string) bool {
	levels := map[string]int{"critical": 0, "warning": 1, "info": 2, "debug": 3}
	minLevel, ok := levels[m.cfg.MinSeverity]
	if !ok {
		minLevel = 1 // default: warning and above
	}
	evtLevel, ok := levels[severity]
	if !ok {
		evtLevel = 2
	}
	return evtLevel <= minLevel
}

func (m *Manager) fireWebhooks(event *db.Event) {
	for _, wh := range m.cfg.Webhooks {
		go m.sendWebhook(wh, event)
	}
}

func (m *Manager) sendWebhook(wh config.WebhookConfig, event *db.Event) {
	var payload []byte

	switch detectWebhookType(wh.URL) {
	case "slack":
		payload, _ = json.Marshal(slackPayload(event))
	case "discord":
		payload, _ = json.Marshal(discordPayload(event))
	default:
		payload, _ = json.Marshal(genericPayload(event))
	}

	req, err := http.NewRequest("POST", wh.URL, bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-MythNet-Event", event.Source)

	// HMAC-SHA256 signature for webhook verification
	if wh.Secret != "" {
		mac := hmac.New(sha256.New, []byte(wh.Secret))
		mac.Write(payload)
		sig := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-MythNet-Signature", "sha256="+sig)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		m.logger.Error("webhook failed", "url", wh.URL, "error", err)
		return
	}
	resp.Body.Close()

	m.logger.Debug("webhook sent", "url", wh.URL, "status", resp.StatusCode, "event", event.Title)
}

func detectWebhookType(url string) string {
	if strings.Contains(url, "hooks.slack.com") {
		return "slack"
	}
	if strings.Contains(url, "discord.com/api/webhooks") {
		return "discord"
	}
	return "generic"
}

// --- Payload formats ---

func sevEmoji(sev string) string {
	switch sev {
	case "critical":
		return "🔴"
	case "warning":
		return "🟡"
	default:
		return "🔵"
	}
}

func slackPayload(e *db.Event) map[string]any {
	return map[string]any{
		"text": fmt.Sprintf("%s *[%s]* %s\n`%s` — %s",
			sevEmoji(e.Severity), strings.ToUpper(e.Severity), e.Title, e.Source, e.ReceivedAt.Format(time.RFC3339)),
	}
}

func discordPayload(e *db.Event) map[string]any {
	color := 0x3498db // blue
	switch e.Severity {
	case "critical":
		color = 0xe74c3c
	case "warning":
		color = 0xf39c12
	}
	return map[string]any{
		"embeds": []map[string]any{{
			"title":       fmt.Sprintf("%s %s", sevEmoji(e.Severity), e.Title),
			"description": fmt.Sprintf("**Source:** %s\n**Severity:** %s\n**Time:** %s", e.Source, e.Severity, e.ReceivedAt.Format(time.RFC3339)),
			"color":       color,
		}},
	}
}

func genericPayload(e *db.Event) map[string]any {
	return map[string]any{
		"event":     e.Title,
		"severity":  e.Severity,
		"source":    e.Source,
		"device_id": e.DeviceID,
		"body_md":   e.BodyMD,
		"timestamp": e.ReceivedAt.Format(time.RFC3339),
		"tags":      e.Tags,
	}
}
