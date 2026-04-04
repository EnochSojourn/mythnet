package server

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/mythnet/mythnet/internal/warroom"
)

func (s *Server) handleTrafficGraph(w http.ResponseWriter, r *http.Request) {
	graph := warroom.GetCommGraph(s.store.DB())
	if graph == nil {
		graph = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, graph)
}

func (s *Server) handleTopTalkers(w http.ResponseWriter, r *http.Request) {
	talkers := warroom.GetTopTalkers(s.store.DB())
	if talkers == nil {
		talkers = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, talkers)
}

func (s *Server) handleDeviceCapabilities(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ctrl := warroom.NewDeviceController(s.store)
	caps := ctrl.GetCapabilities(id)
	writeJSON(w, http.StatusOK, caps)
}

func (s *Server) handleDeviceControl(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req struct {
		Command string            `json:"command"`
		Params  map[string]string `json:"params"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.Command == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "command required"})
		return
	}

	s.store.Audit("device_control", id+": "+req.Command, r.RemoteAddr)

	ctrl := warroom.NewDeviceController(s.store)
	result := ctrl.SendCommand(id, req.Command, req.Params)

	status := http.StatusOK
	if !result.Success {
		status = http.StatusBadRequest
	}
	writeJSON(w, status, result)
}
