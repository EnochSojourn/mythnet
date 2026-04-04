package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mythnet/mythnet/internal/ai"
	"github.com/mythnet/mythnet/internal/db"
)

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
