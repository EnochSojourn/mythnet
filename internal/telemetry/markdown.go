package telemetry

import (
	"fmt"
	"strings"
	"time"
)

// TelemetryEvent is the intermediate representation before DB storage.
type TelemetryEvent struct {
	DeviceID string
	Source   string
	Severity string
	Title    string
	BodyMD   string
	RawData  string
	Tags     []string
}

// SNMPVar represents a variable binding from an SNMP trap.
type SNMPVar struct {
	OID   string
	Type  string
	Value string
}

// FormatSNMPTrap converts an SNMP trap into a standardized Markdown event.
func FormatSNMPTrap(deviceIP, trapOID string, vars []SNMPVar, ts time.Time) TelemetryEvent {
	title := classifySNMPTitle(trapOID)
	severity := classifySNMPSeverity(trapOID)

	var b strings.Builder
	fmt.Fprintf(&b, "## %s\n\n", title)
	fmt.Fprintf(&b, "**Source:** `%s`  \n", deviceIP)
	fmt.Fprintf(&b, "**Trap OID:** `%s`  \n", trapOID)
	fmt.Fprintf(&b, "**Time:** %s\n\n", ts.Format(time.RFC3339))

	if len(vars) > 0 {
		b.WriteString("### Variable Bindings\n\n")
		b.WriteString("| OID | Type | Value |\n")
		b.WriteString("|-----|------|-------|\n")
		for _, v := range vars {
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n", v.OID, v.Type, truncate(v.Value, 120))
		}
	}

	raw := fmt.Sprintf("oid=%s vars=%d", trapOID, len(vars))
	return TelemetryEvent{
		Source: "snmp_trap", Severity: severity, Title: title,
		BodyMD: b.String(), RawData: raw, Tags: []string{"snmp", "trap"},
	}
}

// FormatSyslog converts a syslog message into standardized Markdown.
func FormatSyslog(deviceIP string, facility, severity int, hostname, tag, message string, ts time.Time) TelemetryEvent {
	sev := syslogSeverityName(severity)
	fac := syslogFacilityName(facility)

	var b strings.Builder
	fmt.Fprintf(&b, "## Syslog — %s\n\n", tag)
	fmt.Fprintf(&b, "**Source:** `%s`", deviceIP)
	if hostname != "" {
		fmt.Fprintf(&b, " (`%s`)", hostname)
	}
	b.WriteString("  \n")
	fmt.Fprintf(&b, "**Facility:** %s  \n", fac)
	fmt.Fprintf(&b, "**Severity:** %s  \n", sev)
	fmt.Fprintf(&b, "**Time:** %s\n\n", ts.Format(time.RFC3339))
	b.WriteString("### Message\n\n```\n")
	b.WriteString(truncate(message, 2000))
	b.WriteString("\n```\n")

	title := fmt.Sprintf("%s: %s", tag, truncate(message, 80))
	return TelemetryEvent{
		Source: "syslog", Severity: sev, Title: title,
		BodyMD: b.String(), RawData: message, Tags: []string{"syslog", fac},
	}
}

// FormatAPIResponse converts an API poll response into standardized Markdown.
func FormatAPIResponse(deviceIP, endpoint string, statusCode int, headers map[string]string, bodyPreview string, ts time.Time) TelemetryEvent {
	severity := "info"
	if statusCode >= 500 {
		severity = "critical"
	} else if statusCode >= 400 {
		severity = "warning"
	}

	title := fmt.Sprintf("HTTP %d — %s", statusCode, endpoint)

	var b strings.Builder
	fmt.Fprintf(&b, "## %s\n\n", title)
	fmt.Fprintf(&b, "**Device:** `%s`  \n", deviceIP)
	fmt.Fprintf(&b, "**Endpoint:** `%s`  \n", endpoint)
	fmt.Fprintf(&b, "**Status:** %d  \n", statusCode)
	fmt.Fprintf(&b, "**Time:** %s\n\n", ts.Format(time.RFC3339))

	if len(headers) > 0 {
		b.WriteString("### Headers\n\n")
		for k, v := range headers {
			fmt.Fprintf(&b, "- **%s:** %s\n", k, v)
		}
		b.WriteString("\n")
	}

	if bodyPreview != "" {
		b.WriteString("### Response Preview\n\n```\n")
		b.WriteString(truncate(bodyPreview, 500))
		b.WriteString("\n```\n")
	}

	tags := []string{"api", fmt.Sprintf("http_%d", statusCode)}
	if s, ok := headers["Server"]; ok {
		tags = append(tags, "server:"+s)
	}

	return TelemetryEvent{
		Source: "api_poll", Severity: severity, Title: title,
		BodyMD: b.String(), RawData: bodyPreview, Tags: tags,
	}
}

func classifySNMPTitle(oid string) string {
	known := map[string]string{
		"1.3.6.1.6.3.1.1.5.1":  "Cold Start",
		"1.3.6.1.6.3.1.1.5.2":  "Warm Start",
		"1.3.6.1.6.3.1.1.5.3":  "Link Down",
		"1.3.6.1.6.3.1.1.5.4":  "Link Up",
		"1.3.6.1.6.3.1.1.5.5":  "Authentication Failure",
		"1.3.6.1.6.3.1.1.5.6":  "EGP Neighbor Loss",
		"1.3.6.1.4.1.9.9.43.2": "Cisco Config Change",
	}
	// Strip leading dot if present
	clean := strings.TrimPrefix(oid, ".")
	if title, ok := known[clean]; ok {
		return "SNMP Trap — " + title
	}
	return "SNMP Trap — " + oid
}

func classifySNMPSeverity(oid string) string {
	clean := strings.TrimPrefix(oid, ".")
	switch clean {
	case "1.3.6.1.6.3.1.1.5.3": // Link Down
		return "warning"
	case "1.3.6.1.6.3.1.1.5.5": // Auth Failure
		return "critical"
	case "1.3.6.1.6.3.1.1.5.1": // Cold Start
		return "warning"
	default:
		return "info"
	}
}

func syslogSeverityName(sev int) string {
	names := []string{"critical", "critical", "critical", "critical", "warning", "warning", "info", "debug"}
	if sev >= 0 && sev < len(names) {
		return names[sev]
	}
	return "info"
}

func syslogFacilityName(fac int) string {
	names := []string{
		"kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
		"uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
		"local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
	}
	if fac >= 0 && fac < len(names) {
		return names[fac]
	}
	return fmt.Sprintf("facility%d", fac)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// JoinTags joins a tag slice into a comma-separated string.
func JoinTags(tags []string) string {
	return strings.Join(tags, ",")
}
