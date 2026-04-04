package server

import (
	"fmt"
	"net/http"
	"time"
)

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	stats, _ := s.store.GetStats()
	nodes, _ := s.store.ListMeshNodes()

	// Average latency from last 5 minutes
	var avgLat float64
	records, _ := s.store.GetLatencyHistory("", 100)
	if len(records) > 0 {
		var sum float64
		for _, r := range records {
			sum += r.RTTMs
		}
		avgLat = sum / float64(len(records))
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	m := func(name, help, mtype string, value any) {
		fmt.Fprintf(w, "# HELP %s %s\n", name, help)
		fmt.Fprintf(w, "# TYPE %s %s\n", name, mtype)
		fmt.Fprintf(w, "%s %v\n", name, value)
	}

	m("mythnet_devices_total", "Total discovered devices", "gauge", stats.TotalDevices)
	m("mythnet_devices_online", "Currently online devices", "gauge", stats.OnlineDevices)
	m("mythnet_ports_open", "Total open ports across all devices", "gauge", stats.TotalPorts)
	m("mythnet_scans_total", "Total completed scans", "counter", stats.TotalScans)
	m("mythnet_events_total", "Total telemetry events", "counter", stats.TotalEvents)
	m("mythnet_events_critical", "Critical and warning events", "gauge", stats.CriticalEvents)
	m("mythnet_mesh_peers", "Number of mesh peers", "gauge", len(nodes))
	m("mythnet_latency_avg_ms", "Average device latency in milliseconds", "gauge", fmt.Sprintf("%.2f", avgLat))
	m("mythnet_scanner_running", "Whether a scan is in progress", "gauge", boolToInt(s.scanner.IsRunning()))
	m("mythnet_uptime_seconds", "Process uptime in seconds", "counter", fmt.Sprintf("%.0f", time.Since(s.startTime).Seconds()))
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
