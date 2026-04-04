package db

import (
	"fmt"
	"strings"
	"time"
)

// DeviceRisk is a per-device security risk assessment.
type DeviceRisk struct {
	DeviceID   string   `json:"device_id"`
	IP         string   `json:"ip"`
	Name       string   `json:"name"`
	RiskScore  int      `json:"risk_score"` // 0-100, higher = more risk
	RiskLevel  string   `json:"risk_level"` // "critical", "high", "medium", "low"
	Findings   []string `json:"findings"`
}

// SubnetAnalysis breaks down a subnet's security posture.
type SubnetAnalysis struct {
	Subnet       string       `json:"subnet"`
	DeviceCount  int          `json:"device_count"`
	OnlineCount  int          `json:"online_count"`
	AvgRisk      int          `json:"avg_risk"`
	TypeBreakdown map[string]int `json:"type_breakdown"`
	TopRisks     []DeviceRisk `json:"top_risks"`
	Findings     []string     `json:"findings"`
}

// NetworkAnalytics is the full deep analysis of the network.
type NetworkAnalytics struct {
	GeneratedAt      string           `json:"generated_at"`
	TotalDevices     int              `json:"total_devices"`
	TotalRisk        int              `json:"total_risk_score"` // 0-100
	RiskDistribution map[string]int   `json:"risk_distribution"`
	DeviceRisks      []DeviceRisk     `json:"device_risks"`
	Subnets          []SubnetAnalysis `json:"subnets"`
	SecurityPosture  SecurityPosture  `json:"security_posture"`
}

// SecurityPosture is the overall security assessment.
type SecurityPosture struct {
	Grade           string   `json:"grade"`
	Score           int      `json:"score"`
	CriticalFindings []string `json:"critical_findings"`
	Warnings        []string `json:"warnings"`
	Positives       []string `json:"positives"`
	Recommendations []string `json:"recommendations"`
}

// GenerateAnalytics produces a comprehensive network security analysis.
func (s *Store) GenerateAnalytics() *NetworkAnalytics {
	devices, _ := s.ListDevices()
	events, _ := s.ListEvents(200, "", "", "")
	now := time.Now()

	analytics := &NetworkAnalytics{
		GeneratedAt:      now.Format(time.RFC3339),
		TotalDevices:     len(devices),
		RiskDistribution: map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0},
	}

	// Per-device risk scoring
	subnetMap := make(map[string][]*Device)
	for _, d := range devices {
		risk := s.scoreDeviceRisk(d, events)
		analytics.DeviceRisks = append(analytics.DeviceRisks, risk)
		analytics.RiskDistribution[risk.RiskLevel]++

		// Group by /24 subnet
		parts := strings.Split(d.IP, ".")
		subnet := fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
		subnetMap[subnet] = append(subnetMap[subnet], d)
	}

	// Subnet analysis
	for subnet, devs := range subnetMap {
		sa := s.analyzeSubnet(subnet, devs, analytics.DeviceRisks)
		analytics.Subnets = append(analytics.Subnets, sa)
	}

	// Overall risk score (weighted average)
	if len(analytics.DeviceRisks) > 0 {
		total := 0
		for _, r := range analytics.DeviceRisks {
			total += r.RiskScore
		}
		analytics.TotalRisk = total / len(analytics.DeviceRisks)
	}

	// Security posture
	analytics.SecurityPosture = s.assessSecurityPosture(analytics, events)

	return analytics
}

func (s *Store) scoreDeviceRisk(d *Device, events []*Event) DeviceRisk {
	risk := DeviceRisk{
		DeviceID: d.ID,
		IP:       d.IP,
		Name:     d.Hostname,
		RiskScore: 0,
	}
	if risk.Name == "" {
		risk.Name = d.Vendor
	}
	if risk.Name == "" {
		risk.Name = d.IP
	}

	ports, _ := s.GetDevicePorts(d.ID)
	portSet := make(map[int]bool)
	for _, p := range ports {
		portSet[p.Port] = true
	}

	// Dangerous open ports
	dangerousPorts := map[int]string{
		23: "Telnet (cleartext)", 21: "FTP (often cleartext)",
		135: "MSRPC", 139: "NetBIOS", 445: "SMB",
		3389: "RDP (brute-force target)", 5900: "VNC (often weak auth)",
		6379: "Redis (often no auth)", 1433: "MSSQL",
		27017: "MongoDB (often no auth)",
	}
	for port, desc := range dangerousPorts {
		if portSet[port] {
			risk.RiskScore += 15
			risk.Findings = append(risk.Findings, fmt.Sprintf("Dangerous port open: %d (%s)", port, desc))
		}
	}

	// CVE events for this device
	for _, e := range events {
		if e.DeviceID == d.ID && e.Source == "vuln_scan" {
			risk.RiskScore += 25
			risk.Findings = append(risk.Findings, "CVE vulnerability: "+e.Title)
		}
	}

	// HTTP audit findings
	for _, e := range events {
		if e.DeviceID == d.ID && e.Source == "http_audit" && e.Severity == "critical" {
			risk.RiskScore += 10
			risk.Findings = append(risk.Findings, "HTTP security issues: "+e.Title)
		}
	}

	// TLS cert issues
	for _, e := range events {
		if e.DeviceID == d.ID && e.Source == "tls_check" {
			risk.RiskScore += 10
			risk.Findings = append(risk.Findings, "TLS certificate issue: "+e.Title)
		}
	}

	// Offline = risk (could be compromised/stolen)
	if !d.IsOnline {
		risk.RiskScore += 5
		risk.Findings = append(risk.Findings, "Device is offline")
	}

	// No vendor identification = harder to manage
	if d.Vendor == "" && d.MAC == "" {
		risk.RiskScore += 5
		risk.Findings = append(risk.Findings, "Unidentified device (no MAC/vendor)")
	}

	// Too many open ports
	if len(ports) > 10 {
		risk.RiskScore += 10
		risk.Findings = append(risk.Findings, fmt.Sprintf("Large attack surface: %d open ports", len(ports)))
	}

	// Cap at 100
	if risk.RiskScore > 100 {
		risk.RiskScore = 100
	}

	// Classify
	switch {
	case risk.RiskScore >= 50:
		risk.RiskLevel = "critical"
	case risk.RiskScore >= 30:
		risk.RiskLevel = "high"
	case risk.RiskScore >= 15:
		risk.RiskLevel = "medium"
	default:
		risk.RiskLevel = "low"
	}

	if len(risk.Findings) == 0 {
		risk.Findings = append(risk.Findings, "No issues found")
	}

	return risk
}

func (s *Store) analyzeSubnet(subnet string, devs []*Device, allRisks []DeviceRisk) SubnetAnalysis {
	sa := SubnetAnalysis{
		Subnet:        subnet,
		DeviceCount:   len(devs),
		TypeBreakdown: make(map[string]int),
	}

	riskTotal := 0
	riskCount := 0
	for _, d := range devs {
		if d.IsOnline {
			sa.OnlineCount++
		}
		t := d.DeviceType
		if t == "" {
			t = "Unknown"
		}
		sa.TypeBreakdown[t]++

		for _, r := range allRisks {
			if r.DeviceID == d.ID {
				riskTotal += r.RiskScore
				riskCount++
				if r.RiskScore >= 30 {
					sa.TopRisks = append(sa.TopRisks, r)
				}
			}
		}
	}

	if riskCount > 0 {
		sa.AvgRisk = riskTotal / riskCount
	}

	// Segmentation findings
	hasNetworkEquip := sa.TypeBreakdown["Network Equipment"] > 0
	hasIoT := sa.TypeBreakdown["IoT"] > 0
	hasEndpoint := sa.TypeBreakdown["Endpoint"] > 0 || sa.TypeBreakdown["Mobile Device"] > 0

	if hasIoT && hasEndpoint {
		sa.Findings = append(sa.Findings, "IoT devices share subnet with endpoints — consider VLAN segmentation")
	}
	if !hasNetworkEquip && len(devs) > 5 {
		sa.Findings = append(sa.Findings, "No network equipment detected — may be behind a router on another subnet")
	}

	return sa
}

func (s *Store) assessSecurityPosture(analytics *NetworkAnalytics, events []*Event) SecurityPosture {
	sp := SecurityPosture{}

	// Count issues
	critDevices := analytics.RiskDistribution["critical"]
	highDevices := analytics.RiskDistribution["high"]
	cveCount := 0
	telnetOpen := false
	for _, r := range analytics.DeviceRisks {
		for _, f := range r.Findings {
			if strings.Contains(f, "CVE") {
				cveCount++
			}
			if strings.Contains(f, "Telnet") {
				telnetOpen = true
			}
		}
	}

	// Score
	sp.Score = 100
	sp.Score -= critDevices * 15
	sp.Score -= highDevices * 8
	sp.Score -= cveCount * 10
	if sp.Score < 0 {
		sp.Score = 0
	}

	switch {
	case sp.Score >= 90:
		sp.Grade = "A"
	case sp.Score >= 80:
		sp.Grade = "B"
	case sp.Score >= 70:
		sp.Grade = "C"
	case sp.Score >= 60:
		sp.Grade = "D"
	default:
		sp.Grade = "F"
	}

	// Critical findings
	if cveCount > 0 {
		sp.CriticalFindings = append(sp.CriticalFindings, fmt.Sprintf("%d known CVE vulnerabilities detected", cveCount))
	}
	if telnetOpen {
		sp.CriticalFindings = append(sp.CriticalFindings, "Telnet (cleartext) is open on one or more devices")
	}
	if critDevices > 0 {
		sp.CriticalFindings = append(sp.CriticalFindings, fmt.Sprintf("%d device(s) at critical risk level", critDevices))
	}

	// Warnings
	if highDevices > 0 {
		sp.Warnings = append(sp.Warnings, fmt.Sprintf("%d device(s) at high risk level", highDevices))
	}
	for _, sa := range analytics.Subnets {
		for _, f := range sa.Findings {
			sp.Warnings = append(sp.Warnings, f)
		}
	}

	// Positives
	lowRisk := analytics.RiskDistribution["low"]
	if lowRisk > 0 {
		sp.Positives = append(sp.Positives, fmt.Sprintf("%d device(s) at low risk", lowRisk))
	}
	if len(sp.CriticalFindings) == 0 {
		sp.Positives = append(sp.Positives, "No critical vulnerabilities detected")
	}

	// Recommendations
	if telnetOpen {
		sp.Recommendations = append(sp.Recommendations, "Disable Telnet and use SSH instead")
	}
	if cveCount > 0 {
		sp.Recommendations = append(sp.Recommendations, "Patch or update services with known CVEs")
	}
	for _, sa := range analytics.Subnets {
		if sa.TypeBreakdown["IoT"] > 0 && (sa.TypeBreakdown["Endpoint"] > 0 || sa.TypeBreakdown["Mobile Device"] > 0) {
			sp.Recommendations = append(sp.Recommendations, fmt.Sprintf("Segment IoT devices on %s into a separate VLAN", sa.Subnet))
			break
		}
	}
	sp.Recommendations = append(sp.Recommendations, "Enable network segmentation between device classes")
	sp.Recommendations = append(sp.Recommendations, "Monitor for new/unknown devices joining the network")

	return sp
}
