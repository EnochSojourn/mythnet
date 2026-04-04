package ai

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/mythnet/mythnet/internal/db"
)

const autoAnalysisPrompt = `You are MythNet AI, analyzing a real network. Based on the data below, provide a DEEP technical analysis. Be specific — reference actual IPs, ports, services, and vendor names.

Analyze these areas:
1. **Device Classification** — For each device, state exactly what it is (model if known), its role on the network, and its risk profile
2. **Security Findings** — Every vulnerability, misconfiguration, exposed service, and missing protection you can identify
3. **Network Architecture** — How the network is structured, segmentation issues, single points of failure
4. **Threat Assessment** — What an attacker could exploit right now if they were on this network
5. **Immediate Actions** — The top 5 things the network owner should do TODAY, in priority order

Be direct. No disclaimers. Actual findings only.

%s`

// RunAutoAnalysis generates a comprehensive AI analysis after each scan.
func RunAutoAnalysis(ctx context.Context, client Client, store *db.Store, logger *slog.Logger) {
	networkCtx := BuildContext(store)

	// Add device-specific details
	devices, _ := store.ListDevices()
	var extra strings.Builder
	for _, d := range devices {
		ports, _ := store.GetDevicePorts(d.ID)
		if len(ports) > 0 {
			name := d.Hostname
			if name == "" { name = d.Vendor }
			if name == "" { name = d.IP }
			extra.WriteString(fmt.Sprintf("\nDevice %s (%s) ports: ", name, d.IP))
			for _, p := range ports {
				extra.WriteString(fmt.Sprintf("%d/%s ", p.Port, p.Service))
				if p.Banner != "" {
					banner := p.Banner
					if len(banner) > 80 { banner = banner[:80] }
					extra.WriteString(fmt.Sprintf("[%s] ", banner))
				}
			}
		}
		// Include notes
		notes, _ := store.GetDeviceNotes(d.ID)
		if notes != "" {
			extra.WriteString(fmt.Sprintf("\n  Notes: %s", notes))
		}
	}

	fullContext := networkCtx + extra.String()
	prompt := fmt.Sprintf(autoAnalysisPrompt, fullContext)

	logger.Info("running automatic AI network analysis")

	messages := []Message{{Role: "user", Content: "Analyze this network comprehensively."}}

	var result strings.Builder
	err := client.Chat(ctx, prompt, messages, func(chunk string) {
		result.WriteString(chunk)
	})

	if err != nil {
		logger.Error("auto-analysis failed", "error", err)
		return
	}

	analysis := result.String()
	if len(analysis) < 50 {
		return
	}

	// Store as event
	store.InsertEvent(&db.Event{
		Source:     "ai_analysis",
		Severity:   "info",
		Title:      "AI Network Analysis — " + time.Now().Format("2006-01-02 15:04"),
		BodyMD:     analysis,
		ReceivedAt: time.Now(),
		Tags:       "ai,analysis,automatic",
	})

	logger.Info("AI analysis complete", "length", len(analysis))
}
