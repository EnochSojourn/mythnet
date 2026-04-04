package server

import (
	"fmt"
	"net/http"
	"time"
)

func (s *Server) handleStatusPage(w http.ResponseWriter, r *http.Request) {
	stats, _ := s.store.GetStats()
	health := s.store.CalculateHealthScore()
	uptime := time.Since(s.startTime)

	days := int(uptime.Hours()) / 24
	hours := int(uptime.Hours()) % 24
	mins := int(uptime.Minutes()) % 60

	scoreColor := "#22c55e"
	if health.Score < 70 {
		scoreColor = "#ef4444"
	} else if health.Score < 90 {
		scoreColor = "#f59e0b"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MythNet Status</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0f1a;color:#e2e8f0;font-family:system-ui,sans-serif;display:flex;justify-content:center;padding:40px 20px}
.wrap{max-width:500px;width:100%%}
h1{font-size:24px;margin-bottom:4px}
h1 span{color:#3b82f6}
.sub{color:#64748b;font-size:13px;margin-bottom:32px}
.score{text-align:center;margin:24px 0}
.score-num{font-size:72px;font-weight:800;color:%s}
.score-label{color:#94a3b8;font-size:14px}
.grade{display:inline-block;background:%s22;color:%s;font-size:18px;font-weight:700;padding:4px 16px;border-radius:8px;margin-top:8px}
.stats{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:24px 0}
.stat{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:16px}
.stat-val{font-size:28px;font-weight:700}
.stat-label{color:#64748b;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-top:2px}
.online .stat-val{color:#22c55e}
.issues{margin:24px 0}
.issue{color:#94a3b8;font-size:13px;padding:4px 0}
.uptime{text-align:center;color:#475569;font-size:12px;margin-top:32px}
</style></head><body>
<div class="wrap">
<h1><span>Myth</span>Net</h1>
<div class="sub">Network Monitor Status</div>
<div class="score">
<div class="score-num">%d</div>
<div class="score-label">Health Score</div>
<div class="grade">Grade %s</div>
</div>
<div class="stats">
<div class="stat"><div class="stat-val">%d</div><div class="stat-label">Devices</div></div>
<div class="stat online"><div class="stat-val">%d</div><div class="stat-label">Online</div></div>
<div class="stat"><div class="stat-val">%d</div><div class="stat-label">Open Ports</div></div>
<div class="stat"><div class="stat-val">%d</div><div class="stat-label">Events</div></div>
</div>`,
		scoreColor, scoreColor, scoreColor,
		health.Score, health.Grade,
		stats.TotalDevices, stats.OnlineDevices, stats.TotalPorts, stats.TotalEvents)

	if len(health.Issues) > 0 {
		fmt.Fprintf(w, `<div class="issues">`)
		for _, issue := range health.Issues {
			fmt.Fprintf(w, `<div class="issue">→ %s</div>`, issue)
		}
		fmt.Fprintf(w, `</div>`)
	}

	fmt.Fprintf(w, `<div class="uptime">Uptime: %dd %dh %dm</div>`, days, hours, mins)
	fmt.Fprintf(w, `</div></body></html>`)
}
