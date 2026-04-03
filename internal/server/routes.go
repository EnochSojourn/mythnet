package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mythnet/mythnet/internal/ai"
	"github.com/mythnet/mythnet/internal/db"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"version": "0.1.0",
		"scanning": s.scanner.IsRunning(),
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
	devices, err := s.store.ListDevices()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if devices == nil {
		devices = []*db.Device{}
	}
	writeJSON(w, http.StatusOK, devices)
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

	writeJSON(w, http.StatusOK, device)
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

	s.scanner.TriggerScan(req.Subnet)
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "scan triggered"})
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

	events, err := s.store.ListEvents(limit, deviceID, severity)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if events == nil {
		events = []*db.Event{}
	}
	writeJSON(w, http.StatusOK, events)
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
