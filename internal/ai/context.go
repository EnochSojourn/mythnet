package ai

import (
	"context"
	"fmt"
	"strings"

	"github.com/mythnet/mythnet/internal/db"
)

const systemPromptTemplate = `You are MythNet AI, a network security analyst embedded in a real-time network monitoring system. You have access to live data about all discovered devices, open ports, services, and security events.

Your capabilities:
- Analyze network topology and device inventory
- Identify security risks from open ports and service banners
- Interpret SNMP traps, syslog messages, and HTTP responses
- Recommend remediation steps for vulnerabilities
- Generate network health summaries

Guidelines:
- Be concise and actionable
- Reference devices by IP and hostname
- Flag dangerous open ports (telnet/23, unencrypted services)
- Note unusual patterns in events
- Format responses in Markdown

Current network state:

%s`

// SystemPrompt builds the full system prompt with current network context.
func SystemPrompt(networkContext string) string {
	return fmt.Sprintf(systemPromptTemplate, networkContext)
}

// BuildContext generates a Markdown summary of the current network state for the AI.
func BuildContext(store *db.Store) string {
	stats, _ := store.GetStats()
	devices, _ := store.ListDevices()
	events, _ := store.ListEvents(25, "", "", "")

	var b strings.Builder

	fmt.Fprintf(&b, "**Summary:** %d devices (%d online), %d open ports, %d events (%d critical)\n\n",
		stats.TotalDevices, stats.OnlineDevices, stats.TotalPorts, stats.TotalEvents, stats.CriticalEvents)

	// Device inventory
	if len(devices) > 0 {
		b.WriteString("## Device Inventory\n\n")
		b.WriteString("| IP | Hostname | Type | OS | Vendor | Status |\n")
		b.WriteString("|---|---|---|---|---|---|\n")
		for _, d := range devices {
			status := "Online"
			if !d.IsOnline {
				status = "Offline"
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n",
				d.IP, d.Hostname, d.DeviceType, d.OSGuess, d.Vendor, status)
		}
	}

	// Open ports per device
	for _, d := range devices {
		ports, _ := store.GetDevicePorts(d.ID)
		if len(ports) == 0 {
			continue
		}
		name := d.IP
		if d.Hostname != "" {
			name = fmt.Sprintf("%s (%s)", d.Hostname, d.IP)
		}
		fmt.Fprintf(&b, "\n### %s — Open Ports\n\n", name)
		for _, p := range ports {
			fmt.Fprintf(&b, "- **%d/%s** %s", p.Port, p.Protocol, p.Service)
			if p.Banner != "" {
				banner := p.Banner
				if len(banner) > 100 {
					banner = banner[:100] + "..."
				}
				fmt.Fprintf(&b, " — `%s`", banner)
			}
			b.WriteString("\n")
		}
	}

	// Recent events
	if len(events) > 0 {
		b.WriteString("\n## Recent Events\n\n")
		for _, e := range events {
			fmt.Fprintf(&b, "- **[%s]** `%s` %s\n", strings.ToUpper(e.Severity), e.Source, e.Title)
		}
	}

	return b.String()
}

const reportPrompt = `Generate a comprehensive network health and security report based on the current network state provided. Structure the report with these sections:

1. **Executive Summary** — 2-3 sentence overview
2. **Device Inventory** — Table of all devices with key details
3. **Port Analysis** — Notable open ports and potential risks
4. **Security Assessment** — Findings from events, banners, and open services
5. **Recommendations** — Prioritized action items

Be specific. Reference actual IPs, ports, and service versions from the data.`

// GenerateReport creates a full network health report using the AI.
func GenerateReport(ctx context.Context, client Client, store *db.Store) (string, error) {
	networkCtx := BuildContext(store)
	sysPrompt := SystemPrompt(networkCtx)

	messages := []Message{
		{Role: "user", Content: reportPrompt},
	}

	var b strings.Builder
	err := client.Chat(ctx, sysPrompt, messages, func(chunk string) {
		b.WriteString(chunk)
	})

	return b.String(), err
}
