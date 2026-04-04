package scanner

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/mythnet/mythnet/internal/db"
)

// VulnRule matches a service banner pattern to a known vulnerability.
type VulnRule struct {
	Service   string
	Pattern   *regexp.Regexp
	CVE       string
	Severity  string
	Summary   string
}

// Built-in vulnerability rules matching service banners to known CVEs.
var vulnRules = []VulnRule{
	// OpenSSH vulnerabilities
	{Service: "ssh", Pattern: regexp.MustCompile(`OpenSSH[_ ]([0-6]\.|7\.[0-9][^0-9]|8\.[0-7][^0-9]|9\.[0-2][^0-9]|9\.3p1)`),
		CVE: "CVE-2024-6387", Severity: "critical", Summary: "regreSSHion — remote code execution via race condition in signal handler"},
	{Service: "ssh", Pattern: regexp.MustCompile(`OpenSSH[_ ][0-6]\.`),
		CVE: "CVE-2016-0777", Severity: "critical", Summary: "OpenSSH <7.0 — information leak via roaming feature"},

	// Apache httpd
	{Service: "http", Pattern: regexp.MustCompile(`Apache/2\.4\.(4[0-9]|50)\b`),
		CVE: "CVE-2021-44790", Severity: "critical", Summary: "Apache 2.4.40-2.4.50 — buffer overflow in mod_lua"},
	{Service: "http", Pattern: regexp.MustCompile(`Apache/2\.4\.(0|[1-3][0-9]|4[0-8])\b`),
		CVE: "CVE-2021-41773", Severity: "critical", Summary: "Apache 2.4.49 — path traversal and RCE"},

	// nginx
	{Service: "http", Pattern: regexp.MustCompile(`nginx/1\.(1[0-8]|[0-9])\.\d`),
		CVE: "CVE-2021-23017", Severity: "warning", Summary: "nginx <1.20.1 — DNS resolver vulnerability"},

	// Microsoft IIS
	{Service: "http", Pattern: regexp.MustCompile(`Microsoft-IIS/(7\.[05]|8\.[05])`),
		CVE: "CVE-2017-7269", Severity: "critical", Summary: "IIS 6.0-8.5 — WebDAV buffer overflow (actively exploited)"},

	// ProFTPD
	{Service: "ftp", Pattern: regexp.MustCompile(`ProFTPD 1\.3\.[0-5]`),
		CVE: "CVE-2019-12815", Severity: "critical", Summary: "ProFTPD <1.3.6 — arbitrary file copy without auth"},

	// vsftpd
	{Service: "ftp", Pattern: regexp.MustCompile(`vsftpd 2\.3\.4`),
		CVE: "CVE-2011-2523", Severity: "critical", Summary: "vsftpd 2.3.4 — malicious backdoor in distribution"},

	// MySQL / MariaDB
	{Service: "mysql", Pattern: regexp.MustCompile(`(5\.[0-5]\.|5\.6\.[0-9][^0-9]|5\.6\.[12][0-9][^0-9])`),
		CVE: "CVE-2016-6662", Severity: "critical", Summary: "MySQL <5.7 — remote root code execution via config injection"},

	// Redis
	{Service: "redis", Pattern: regexp.MustCompile(`Redis server v=([0-5]\.|6\.[0-1]\.)`),
		CVE: "CVE-2022-0543", Severity: "critical", Summary: "Redis <6.2 — Lua sandbox escape to RCE"},

	// Exim
	{Service: "smtp", Pattern: regexp.MustCompile(`Exim (4\.8[0-9]|4\.9[0-3])`),
		CVE: "CVE-2019-10149", Severity: "critical", Summary: "Exim 4.87-4.93 — remote command execution (The Return of the WIZard)"},

	// Telnet (any version — the protocol itself is the vulnerability)
	{Service: "telnet", Pattern: regexp.MustCompile(`(?i)telnet|login:`),
		CVE: "NOAUTH", Severity: "critical", Summary: "Telnet transmits credentials in cleartext — replace with SSH"},
}

// CheckBannerVulns scans a banner against known vulnerability patterns.
func CheckBannerVulns(deviceID, deviceIP string, port int, service, banner string) []*db.Event {
	if banner == "" {
		return nil
	}

	var events []*db.Event
	now := time.Now()

	for _, rule := range vulnRules {
		// Match by service or check all if service is generic
		if rule.Service != service && service != "" {
			continue
		}

		if !rule.Pattern.MatchString(banner) {
			continue
		}

		title := fmt.Sprintf("%s — %s:%d", rule.CVE, deviceIP, port)

		var b strings.Builder
		fmt.Fprintf(&b, "## Vulnerability Found — %s\n\n", rule.CVE)
		fmt.Fprintf(&b, "**Device:** `%s`  \n", deviceIP)
		fmt.Fprintf(&b, "**Port:** %d/%s  \n", port, service)
		fmt.Fprintf(&b, "**CVE:** %s  \n", rule.CVE)
		fmt.Fprintf(&b, "**Severity:** %s  \n", rule.Severity)
		fmt.Fprintf(&b, "**Summary:** %s  \n\n", rule.Summary)
		fmt.Fprintf(&b, "### Banner\n\n```\n%s\n```\n", truncBanner(banner))
		b.WriteString("\n> **Action Required:** Update the affected service to the latest version.\n")

		events = append(events, &db.Event{
			DeviceID:   deviceID,
			Source:     "vuln_scan",
			Severity:   rule.Severity,
			Title:      title,
			BodyMD:     b.String(),
			ReceivedAt: now,
			Tags:       fmt.Sprintf("cve,%s,%s,port_%d", rule.CVE, service, port),
		})
	}

	return events
}

func truncBanner(s string) string {
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}
