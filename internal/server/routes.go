package server

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mythnet/mythnet/internal/ai"
	"github.com/mythnet/mythnet/internal/alerts"
	"github.com/mythnet/mythnet/internal/db"
	"github.com/mythnet/mythnet/internal/scanner"
)

func (s *Server) handleAnalytics(w http.ResponseWriter, r *http.Request) {
	analytics := s.store.GenerateAnalytics()
	writeJSON(w, http.StatusOK, analytics)
}

func (s *Server) handleDigest(w http.ResponseWriter, r *http.Request) {
	digest := alerts.BuildDailyDigest(s.store)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(digest))
}

func (s *Server) handleSLA(w http.ResponseWriter, r *http.Request) {
	devices, _ := s.store.ListDevices()
	type slaEntry struct {
		DeviceID string  `json:"device_id"`
		IP       string  `json:"ip"`
		Hostname string  `json:"hostname"`
		SLA24h   float64 `json:"sla_24h"`
		SLA7d    float64 `json:"sla_7d"`
		SLA30d   float64 `json:"sla_30d"`
	}
	var entries []slaEntry
	for _, d := range devices {
		up24, _ := s.store.GetUptimeStats(d.ID, 24*time.Hour)
		up7d, _ := s.store.GetUptimeStats(d.ID, 7*24*time.Hour)
		up30d, _ := s.store.GetUptimeStats(d.ID, 30*24*time.Hour)
		e := slaEntry{DeviceID: d.ID, IP: d.IP, Hostname: d.Hostname}
		if up24 != nil {
			e.SLA24h = up24.UptimePct
		}
		if up7d != nil {
			e.SLA7d = up7d.UptimePct
		}
		if up30d != nil {
			e.SLA30d = up30d.UptimePct
		}
		entries = append(entries, e)
	}
	writeJSON(w, http.StatusOK, entries)
}

func (s *Server) handleNetworkDoc(w http.ResponseWriter, r *http.Request) {
	devices, _ := s.store.ListDevices()
	stats, _ := s.store.GetStats()
	health := s.store.CalculateHealthScore()

	var b strings.Builder
	b.WriteString(fmt.Sprintf("# MythNet Network Documentation\n\n"))
	b.WriteString(fmt.Sprintf("*Generated: %s*\n\n", time.Now().Format("2006-01-02 15:04")))
	b.WriteString(fmt.Sprintf("## Summary\n\n"))
	b.WriteString(fmt.Sprintf("- **Devices:** %d (%d online)\n", stats.TotalDevices, stats.OnlineDevices))
	b.WriteString(fmt.Sprintf("- **Open Ports:** %d\n", stats.TotalPorts))
	b.WriteString(fmt.Sprintf("- **Health Score:** %d/100 (Grade %s)\n\n", health.Score, health.Grade))

	b.WriteString("## Device Inventory\n\n")
	b.WriteString("| IP | Hostname | MAC | Vendor | OS | Type | Status |\n")
	b.WriteString("|---|---|---|---|---|---|---|\n")
	for _, d := range devices {
		status := "Online"
		if !d.IsOnline {
			status = "**Offline**"
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s |\n",
			d.IP, d.Hostname, d.MAC, d.Vendor, d.OSGuess, d.DeviceType, status))
	}

	b.WriteString("\n## Open Ports by Device\n\n")
	for _, d := range devices {
		ports, _ := s.store.GetDevicePorts(d.ID)
		if len(ports) == 0 {
			continue
		}
		name := d.IP
		if d.Hostname != "" {
			name = d.Hostname + " (" + d.IP + ")"
		}
		b.WriteString(fmt.Sprintf("### %s\n\n", name))
		b.WriteString("| Port | Protocol | Service | Banner |\n")
		b.WriteString("|---|---|---|---|\n")
		for _, p := range ports {
			banner := p.Banner
			if len(banner) > 60 {
				banner = banner[:58] + ".."
			}
			banner = strings.ReplaceAll(banner, "|", "\\|")
			banner = strings.ReplaceAll(banner, "\n", " ")
			b.WriteString(fmt.Sprintf("| %d | %s | %s | %s |\n", p.Port, p.Protocol, p.Service, banner))
		}
		b.WriteString("\n")
	}

	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", `inline; filename="mythnet-network-doc.md"`)
	w.Write([]byte(b.String()))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := s.store.CalculateHealthScore()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "ok",
		"version":      "1.5.0",
		"scanning":     s.scanner.IsRunning(),
		"health_score": health.Score,
		"health_grade": health.Grade,
		"health":       health,
	})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.store.GetStats()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	// Check for CSV export
	if r.URL.Query().Get("format") == "csv" {
		s.handleExportCSV(w, r)
		return
	}

	devices, err := s.store.ListDevices()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if devices == nil {
		devices = []*db.Device{}
	}

	// Server-side search filter
	if q := r.URL.Query().Get("q"); q != "" {
		q = strings.ToLower(q)
		var filtered []*db.Device
		for _, d := range devices {
			if strings.Contains(strings.ToLower(d.IP), q) ||
				strings.Contains(strings.ToLower(d.Hostname), q) ||
				strings.Contains(strings.ToLower(d.Vendor), q) ||
				strings.Contains(strings.ToLower(d.DeviceType), q) ||
				strings.Contains(strings.ToLower(d.MAC), q) ||
				strings.Contains(strings.ToLower(d.OSGuess), q) {
				filtered = append(filtered, d)
			}
		}
		devices = filtered
		if devices == nil {
			devices = []*db.Device{}
		}
	}

	writeJSON(w, http.StatusOK, devices)
}

func (s *Server) handleExportCSV(w http.ResponseWriter, r *http.Request) {
	devices, err := s.store.ListDevices()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=mythnet-devices.csv")

	fmt.Fprintln(w, "IP,Hostname,MAC,Vendor,OS,Type,Status,First Seen,Last Seen")
	for _, d := range devices {
		status := "online"
		if !d.IsOnline {
			status = "offline"
		}
		fmt.Fprintf(w, "%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
			csvEscape(d.IP), csvEscape(d.Hostname), csvEscape(d.MAC),
			csvEscape(d.Vendor), csvEscape(d.OSGuess), csvEscape(d.DeviceType),
			status, d.FirstSeen.Format(time.RFC3339), d.LastSeen.Format(time.RFC3339))
	}
}

func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}

func (s *Server) handleGetDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	device, err := s.store.GetDevice(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "device not found"})
		return
	}

	ports, _ := s.store.GetDevicePorts(id)
	device.Ports = ports

	uptime, _ := s.store.GetUptimeStats(id, 24*time.Hour)
	latency, _ := s.store.GetLatencyHistory(id, 30)
	notes, _ := s.store.GetDeviceNotes(id)
	tags, _ := s.store.GetDeviceTags(id)
	if tags == nil {
		tags = []string{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"device":  device,
		"uptime":  uptime,
		"latency": latency,
		"notes":   notes,
		"tags":    tags,
	})
}

func (s *Server) handleGetDevicePorts(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	ports, err := s.store.GetDevicePorts(id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if ports == nil {
		ports = []db.Port{}
	}
	writeJSON(w, http.StatusOK, ports)
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	scans, err := s.store.ListScans(50)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if scans == nil {
		scans = []*db.Scan{}
	}
	writeJSON(w, http.StatusOK, scans)
}

func (s *Server) handleTriggerScan(w http.ResponseWriter, r *http.Request) {
	if s.scanner.IsRunning() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "scan already in progress"})
		return
	}

	var req struct {
		Subnet string `json:"subnet"`
	}
	if r.Body != nil {
		json.NewDecoder(r.Body).Decode(&req)
	}

	s.store.Audit("trigger_scan", req.Subnet, r.RemoteAddr)
	s.scanner.TriggerScan(req.Subnet)
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "scan triggered"})
}

func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	devices, _ := s.store.ListDevices()
	events, _ := s.store.ListEvents(100, "", "", "")

	now := time.Now()
	hour := now.Add(-1 * time.Hour)

	var newDevices, offlineDevices []map[string]string
	var portChanges, vulns []map[string]string

	for _, d := range devices {
		if d.FirstSeen.After(hour) {
			newDevices = append(newDevices, map[string]string{
				"ip": d.IP, "hostname": d.Hostname, "type": d.DeviceType,
			})
		}
		if !d.IsOnline {
			offlineDevices = append(offlineDevices, map[string]string{
				"ip": d.IP, "hostname": d.Hostname, "last_seen": d.LastSeen.Format(time.RFC3339),
			})
		}
	}

	for _, e := range events {
		if !e.ReceivedAt.After(hour) {
			continue
		}
		switch e.Source {
		case "port_change":
			portChanges = append(portChanges, map[string]string{"title": e.Title, "severity": e.Severity})
		case "vuln_scan":
			vulns = append(vulns, map[string]string{"title": e.Title, "severity": e.Severity})
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"period":          "last_hour",
		"new_devices":     coalesce(newDevices),
		"offline_devices": coalesce(offlineDevices),
		"port_changes":    coalesce(portChanges),
		"vulnerabilities": coalesce(vulns),
	})
}

func coalesce(s []map[string]string) []map[string]string {
	if s == nil {
		return []map[string]string{}
	}
	return s
}

func (s *Server) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	entries, err := s.store.GetAuditLog(100)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if entries == nil {
		entries = []map[string]string{}
	}
	writeJSON(w, http.StatusOK, entries)
}

func (s *Server) handleMeshStatus(w http.ResponseWriter, r *http.Request) {
	nodes, _ := s.store.ListMeshNodes()
	if nodes == nil {
		nodes = []*db.MeshNode{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"peers": nodes,
	})
}

func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	deviceID := r.URL.Query().Get("device_id")
	severity := r.URL.Query().Get("severity")

	search := r.URL.Query().Get("q")
	events, err := s.store.ListEvents(limit, deviceID, severity, search)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if events == nil {
		events = []*db.Event{}
	}
	writeJSON(w, http.StatusOK, events)
}

func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	dbPath := s.cfg.Database.Path
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="mythnet-backup.db"`)
	http.ServeFile(w, r, dbPath)
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"scanner": map[string]any{
			"subnets":  s.cfg.Scanner.Subnets,
			"interval": s.cfg.Scanner.Interval,
			"timeout":  s.cfg.Scanner.Timeout,
		},
		"telemetry": map[string]any{
			"snmp_enabled":   s.cfg.Telemetry.SNMP.Enabled,
			"syslog_enabled": s.cfg.Telemetry.Syslog.Enabled,
			"poller_enabled": s.cfg.Telemetry.Poller.Enabled,
		},
		"mesh": map[string]any{
			"enabled":   s.cfg.Mesh.Enabled,
			"node_type": s.cfg.Mesh.NodeType,
		},
		"ai": map[string]any{
			"enabled": s.cfg.AI.Enabled && s.ai != nil,
		},
	})
}

func (s *Server) handleGetTags(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tags, _ := s.store.GetDeviceTags(id)
	if tags == nil {
		tags = []string{}
	}
	writeJSON(w, http.StatusOK, tags)
}

func (s *Server) handleSetTags(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var tags []string
	json.NewDecoder(r.Body).Decode(&tags)
	s.store.Audit("set_tags", id+": "+strings.Join(tags, ","), r.RemoteAddr)
	s.store.SetDeviceTags(id, tags)
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

func (s *Server) handleAllTags(w http.ResponseWriter, r *http.Request) {
	tags, _ := s.store.GetAllTags()
	if tags == nil {
		tags = []string{}
	}
	writeJSON(w, http.StatusOK, tags)
}

func (s *Server) handleSnapshots(w http.ResponseWriter, r *http.Request) {
	hours := 24
	if h := r.URL.Query().Get("hours"); h != "" {
		if n, err := strconv.Atoi(h); err == nil && n > 0 && n <= 168 {
			hours = n
		}
	}
	snaps, err := s.store.GetSnapshots(hours)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if snaps == nil {
		snaps = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, snaps)
}

func (s *Server) handleGetNotes(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	notes, _ := s.store.GetDeviceNotes(id)
	writeJSON(w, http.StatusOK, map[string]string{"notes": notes})
}

func (s *Server) handleSetNotes(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Notes string `json:"notes"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	s.store.Audit("set_notes", id, r.RemoteAddr)
	if err := s.store.SetDeviceNotes(id, req.Notes); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

func (s *Server) handleListEventRules(w http.ResponseWriter, r *http.Request) {
	rules := alerts.LoadEventRules(s.store)
	if rules == nil {
		rules = []alerts.EventRule{}
	}
	writeJSON(w, http.StatusOK, rules)
}

func (s *Server) handleCreateEventRule(w http.ResponseWriter, r *http.Request) {
	var rule alerts.EventRule
	json.NewDecoder(r.Body).Decode(&rule)
	data, _ := json.Marshal(rule)
	s.store.DB().Exec(`INSERT INTO event_rules (data) VALUES (?)`, string(data))
	s.store.Audit("create_event_rule", rule.Name, r.RemoteAddr)
	writeJSON(w, http.StatusCreated, map[string]string{"status": "created"})
}

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	policies, _ := scanner.LoadPolicies(s.store)
	if policies == nil {
		policies = []scanner.Policy{}
	}
	writeJSON(w, http.StatusOK, policies)
}

func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	var pol scanner.Policy
	json.NewDecoder(r.Body).Decode(&pol)
	data, _ := json.Marshal(pol)
	s.store.DB().Exec(`INSERT INTO policies (data) VALUES (?)`, string(data))
	s.store.Audit("create_policy", pol.Name, r.RemoteAddr)
	writeJSON(w, http.StatusCreated, map[string]string{"status": "created"})
}

func (s *Server) handleCheckPolicies(w http.ResponseWriter, r *http.Request) {
	violations, err := scanner.CheckPolicies(s.store)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, violations)
}

func (s *Server) handleImportCSV(w http.ResponseWriter, r *http.Request) {
	file, _, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provide a CSV file as 'file' form field"})
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)
	header, err := reader.Read()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot read CSV header"})
		return
	}

	// Map header columns
	colIdx := make(map[string]int)
	for i, h := range header {
		colIdx[strings.ToLower(strings.TrimSpace(h))] = i
	}

	imported := 0
	now := time.Now()
	for {
		row, err := reader.Read()
		if err != nil {
			break
		}

		get := func(name string) string {
			if idx, ok := colIdx[name]; ok && idx < len(row) {
				return strings.TrimSpace(row[idx])
			}
			return ""
		}

		ip := get("ip")
		if ip == "" {
			continue
		}

		d := &db.Device{
			IP:         ip,
			Hostname:   get("hostname"),
			MAC:        get("mac"),
			Vendor:     get("vendor"),
			OSGuess:    get("os"),
			DeviceType: get("type"),
			FirstSeen:  now,
			LastSeen:   now,
			IsOnline:   false,
		}
		// Generate deterministic ID
		if d.MAC != "" {
			d.ID = fmt.Sprintf("%x", sha256.Sum256([]byte(d.MAC)))[:16]
		} else {
			d.ID = fmt.Sprintf("%x", sha256.Sum256([]byte(d.IP)))[:16]
		}

		s.store.UpsertDevice(d)
		imported++
	}

	s.store.Audit("import_csv", fmt.Sprintf("%d devices", imported), r.RemoteAddr)
	writeJSON(w, http.StatusOK, map[string]any{"imported": imported})
}

func (s *Server) handleDeviceTimeline(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	device, err := s.store.GetDevice(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "device not found"})
		return
	}

	// Collect all data sources for this device
	events, _ := s.store.ListEvents(50, id, "", "")
	uptime, _ := s.store.GetUptimeStats(id, 7*24*time.Hour)
	latency, _ := s.store.GetLatencyHistory(id, 20)

	// Build unified timeline
	type timelineEntry struct {
		Time    string `json:"time"`
		Type    string `json:"type"`
		Title   string `json:"title"`
		Detail  string `json:"detail,omitempty"`
	}

	var timeline []timelineEntry

	// Add events
	for _, e := range events {
		timeline = append(timeline, timelineEntry{
			Time: e.ReceivedAt.Format(time.RFC3339), Type: e.Source,
			Title: e.Title, Detail: e.Severity,
		})
	}

	// Add uptime transitions
	if uptime != nil {
		for _, t := range uptime.Transitions {
			timeline = append(timeline, timelineEntry{
				Time: t.ChangedAt, Type: "state_change",
				Title: "Device went " + t.State,
			})
		}
	}

	// Add discovery
	timeline = append(timeline, timelineEntry{
		Time: device.FirstSeen.Format(time.RFC3339), Type: "discovery",
		Title: "Device first discovered", Detail: device.IP,
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"device":   device.IP,
		"hostname": device.Hostname,
		"timeline": timeline,
		"latency":  latency,
	})
}

func (s *Server) handleSecurityAudit(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	portStr := r.URL.Query().Get("port")
	if portStr == "" {
		portStr = "80"
	}
	port, _ := strconv.Atoi(portStr)

	device, err := s.store.GetDevice(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "device not found"})
		return
	}

	s.store.Audit("security_audit", fmt.Sprintf("%s:%d", device.IP, port), r.RemoteAddr)

	headers, err := scanner.AuditHTTPSecurity(device.IP, port, 5*time.Second)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	result := map[string]any{"headers": headers}

	if port == 443 || port == 8443 {
		if tlsResult, err := scanner.AuditTLS(device.IP, port, 5*time.Second); err == nil {
			result["tls"] = tlsResult
		}
	}

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleTraceroute(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	device, err := s.store.GetDevice(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "device not found"})
		return
	}

	s.store.Audit("traceroute", device.IP, r.RemoteAddr)
	hops := scanner.Traceroute(device.IP, 15)
	writeJSON(w, http.StatusOK, hops)
}

func (s *Server) handleGenerateAdapter(w http.ResponseWriter, r *http.Request) {
	if s.ai == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "AI not configured"})
		return
	}

	deviceID := chi.URLParam(r, "id")
	portStr := r.URL.Query().Get("port")
	if portStr == "" {
		portStr = "80"
	}
	port, _ := strconv.Atoi(portStr)

	device, err := s.store.GetDevice(deviceID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "device not found"})
		return
	}

	adapter, err := ai.GenerateAdapter(r.Context(), s.ai, device, port)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	// Store the adapter
	endpointsJSON, _ := json.Marshal(adapter.Endpoints)
	s.store.UpsertAdapter(&db.DeviceAdapter{
		DeviceID:    device.ID,
		DeviceType:  adapter.DeviceType,
		Vendor:      adapter.Vendor,
		Port:        port,
		Endpoints:   string(endpointsJSON),
		GeneratedAt: adapter.GeneratedAt,
	})

	writeJSON(w, http.StatusOK, adapter)
}

func (s *Server) handleGetAdapters(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "id")
	adapters, err := s.store.GetAdapters(deviceID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if adapters == nil {
		adapters = []*db.DeviceAdapter{}
	}
	writeJSON(w, http.StatusOK, adapters)
}

func (s *Server) handleGenerateReport(w http.ResponseWriter, r *http.Request) {
	if s.ai == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "AI not configured"})
		return
	}

	report, err := ai.GenerateReport(r.Context(), s.ai, s.store)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	// Store as event
	s.store.InsertEvent(&db.Event{
		Source:     "report",
		Severity:   "info",
		Title:      "Network Health Report",
		BodyMD:     report,
		ReceivedAt: time.Now(),
		Tags:       "report,ai",
	})

	writeJSON(w, http.StatusOK, map[string]any{"report": report})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
