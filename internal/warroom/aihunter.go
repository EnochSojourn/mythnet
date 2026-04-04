package warroom

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/mythnet/mythnet/internal/ai"
	"github.com/mythnet/mythnet/internal/db"
)

// AIHunter continuously monitors sniffer data and uses AI to detect patterns.
type AIHunter struct {
	store    *db.Store
	aiClient ai.Client
	logger   *slog.Logger
	interval time.Duration
}

func NewAIHunter(store *db.Store, aiClient ai.Client, logger *slog.Logger) *AIHunter {
	return &AIHunter{
		store:    store,
		aiClient: aiClient,
		logger:   logger,
		interval: 5 * time.Minute,
	}
}

// Run starts continuous threat hunting.
func (h *AIHunter) Run(ctx context.Context) {
	if h.aiClient == nil {
		return
	}

	h.logger.Info("AI threat hunter started", "interval", h.interval)

	// Wait for data to accumulate
	time.Sleep(2 * time.Minute)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		h.hunt(ctx)

		select {
		case <-ctx.Done():
			return
		case <-time.After(h.interval):
		}
	}
}

func (h *AIHunter) hunt(ctx context.Context) {
	h.logger.Debug("AI threat hunt cycle starting")

	// Gather current intelligence
	var intel strings.Builder

	// Sniffer stats
	stats := GetSnifferStats()
	intel.WriteString(fmt.Sprintf("Sniffer: %d packets, %d KB captured, %d DNS queries\n",
		stats.PacketsCaptured, stats.BytesCaptured/1024, stats.DNSQueries))

	// Top DNS domains
	dnsTop := GetSnifferDNSTopDomains()
	if len(dnsTop) > 0 {
		intel.WriteString("\nTop DNS domains:\n")
		for _, d := range dnsTop {
			if len(dnsTop) > 15 {
				break
			}
			intel.WriteString(fmt.Sprintf("  %d queries → %s (%d devices)\n",
				d["queries"], d["domain"], d["sources"]))
		}
	}

	// Recent DNS queries
	dnsLog := GetSnifferDNSLog()
	if len(dnsLog) > 0 {
		intel.WriteString("\nRecent DNS queries:\n")
		for i, q := range dnsLog {
			if i >= 20 {
				break
			}
			intel.WriteString(fmt.Sprintf("  %s → %s\n", q.SrcIP, q.Query))
		}
	}

	// Protocol breakdown
	if GlobalThreatEngine != nil {
		protos := GlobalThreatEngine.GetProtocols()
		intel.WriteString("\nProtocol breakdown:\n")
		for proto, bytes := range protos {
			intel.WriteString(fmt.Sprintf("  %s: %d KB\n", proto, bytes/1024))
		}
	}

	// Top talkers bandwidth
	if GlobalThreatEngine != nil {
		bw := GlobalThreatEngine.GetBandwidth()
		intel.WriteString("\nBandwidth per device:\n")
		count := 0
		for ip, stats := range bw {
			if count >= 10 {
				break
			}
			intel.WriteString(fmt.Sprintf("  %s: ↑%d KB ↓%d KB\n",
				ip, stats["out"]/1024, stats["in"]/1024))
			count++
		}
	}

	// Threat feed stats
	feedStats := GetFeedStats()
	intel.WriteString(fmt.Sprintf("\nThreat feeds: %v malicious IPs, %v malicious domains loaded\n",
		feedStats["malicious_ips"], feedStats["malicious_domains"]))

	// Recent events
	events, _ := h.store.ListEvents(10, "", "", "")
	if len(events) > 0 {
		intel.WriteString("\nRecent events:\n")
		for _, e := range events {
			intel.WriteString(fmt.Sprintf("  [%s] %s: %s\n", e.Severity, e.Source, e.Title))
		}
	}

	prompt := `You are a network threat hunter analyzing real-time traffic data. Your job is to find things that are WRONG or SUSPICIOUS — not to summarize what's normal.

Look at this network telemetry and identify:
1. Any device communicating with suspicious or unusual domains
2. Abnormal traffic patterns (unexpected bandwidth, unusual protocols)
3. DNS queries that look like malware C2, data exfiltration, or crypto mining
4. Any device that appears compromised based on its behavior
5. Anything a human analyst would flag as worth investigating

If everything looks clean, say "No anomalies detected" and nothing else. Do NOT give generic security advice. Only report SPECIFIC findings from this data.

Current telemetry:
` + intel.String()

	messages := []ai.Message{{Role: "user", Content: "Analyze this traffic for threats."}}

	var result strings.Builder
	err := h.aiClient.Chat(ctx, prompt, messages, func(chunk string) {
		result.WriteString(chunk)
	})

	if err != nil {
		h.logger.Debug("AI hunt failed", "error", err)
		return
	}

	analysis := result.String()
	if strings.Contains(strings.ToLower(analysis), "no anomalies detected") {
		h.logger.Debug("AI threat hunt: clean")
		return
	}

	// Found something — store as event
	h.logger.Warn("AI threat hunter found anomalies")
	h.store.InsertEvent(&db.Event{
		Source:     "ai_hunter",
		Severity:   "warning",
		Title:      "AI Threat Hunt — " + time.Now().Format("15:04"),
		BodyMD:     "## AI Threat Hunt Results\n\n" + analysis,
		ReceivedAt: time.Now(),
		Tags:       "ai,threat_hunt,continuous",
	})
}
