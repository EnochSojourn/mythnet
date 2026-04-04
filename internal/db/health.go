package db

import (
	"fmt"
	"time"
)

// HealthScore represents the overall network health assessment.
type HealthScore struct {
	Score       int               `json:"score"`       // 0-100
	Grade       string            `json:"grade"`       // A, B, C, D, F
	Factors     map[string]int    `json:"factors"`     // Individual factor scores
	Issues      []string          `json:"issues"`      // Human-readable issues
	CalculatedAt string           `json:"calculated_at"`
}

// CalculateHealthScore computes a 0-100 health score from current network state.
func (s *Store) CalculateHealthScore() *HealthScore {
	stats, _ := s.GetStats()
	now := time.Now()

	h := &HealthScore{
		Factors:      make(map[string]int),
		CalculatedAt: now.Format(time.RFC3339),
	}

	// Factor 1: Device availability (30 points)
	// 100% online = 30, 50% = 15, 0% = 0
	availScore := 30
	if stats.TotalDevices > 0 {
		pct := float64(stats.OnlineDevices) / float64(stats.TotalDevices)
		availScore = int(pct * 30)
		if pct < 0.9 {
			offCount := stats.TotalDevices - stats.OnlineDevices
			h.Issues = append(h.Issues, fmt.Sprintf("%d device(s) offline", offCount))
		}
	}
	h.Factors["availability"] = availScore

	// Factor 2: No critical events in last hour (25 points)
	secScore := 25
	recentCritical := 0
	events, _ := s.ListEvents(100, "", "critical", "")
	cutoff := now.Add(-1 * time.Hour)
	for _, e := range events {
		if e.ReceivedAt.After(cutoff) {
			recentCritical++
		}
	}
	if recentCritical > 0 {
		secScore = max(0, 25-recentCritical*5)
		h.Issues = append(h.Issues, fmt.Sprintf("%d critical event(s) in the last hour", recentCritical))
	}
	h.Factors["security"] = secScore

	// Factor 3: No vulnerabilities (25 points)
	vulnScore := 25
	vulnEvents, _ := s.ListEvents(50, "", "", "cve")
	recentVulns := 0
	for _, e := range vulnEvents {
		if e.ReceivedAt.After(now.Add(-24 * time.Hour)) {
			recentVulns++
		}
	}
	if recentVulns > 0 {
		vulnScore = max(0, 25-recentVulns*5)
		h.Issues = append(h.Issues, fmt.Sprintf("%d vulnerability finding(s)", recentVulns))
	}
	h.Factors["vulnerabilities"] = vulnScore

	// Factor 4: Uptime stability (20 points)
	// Fewer state transitions = more stable
	stabilityScore := 20
	var totalTransitions int
	devices, _ := s.ListDevices()
	for _, d := range devices {
		up, _ := s.GetUptimeStats(d.ID, 24*time.Hour)
		if up != nil {
			totalTransitions += len(up.Transitions)
		}
	}
	// Deduct for excessive flapping (>2 transitions per device)
	if stats.TotalDevices > 0 {
		avgFlap := float64(totalTransitions) / float64(stats.TotalDevices)
		if avgFlap > 4 {
			stabilityScore = 5
			h.Issues = append(h.Issues, "High device flapping detected")
		} else if avgFlap > 2 {
			stabilityScore = 12
			h.Issues = append(h.Issues, "Some devices are flapping")
		}
	}
	h.Factors["stability"] = stabilityScore

	h.Score = availScore + secScore + vulnScore + stabilityScore
	if h.Score > 100 {
		h.Score = 100
	}

	switch {
	case h.Score >= 90:
		h.Grade = "A"
	case h.Score >= 80:
		h.Grade = "B"
	case h.Score >= 70:
		h.Grade = "C"
	case h.Score >= 60:
		h.Grade = "D"
	default:
		h.Grade = "F"
	}

	if len(h.Issues) == 0 {
		h.Issues = append(h.Issues, "All systems nominal")
	}

	return h
}

func max2(a, b int) int {
	if a > b {
		return a
	}
	return b
}
