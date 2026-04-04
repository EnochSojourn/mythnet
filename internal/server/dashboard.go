package server

import (
	"net/http"
	"os"
)

var dashboardHTML []byte

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if len(dashboardHTML) == 0 {
		data, err := os.ReadFile("web/dashboard.html")
		if err != nil {
			http.Error(w, "Dashboard not found", 404)
			return
		}
		dashboardHTML = data
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(dashboardHTML)
}
