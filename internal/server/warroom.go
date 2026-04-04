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

func (s *Server) handleEnrichedTraffic(w http.ResponseWriter, r *http.Request) {
	graph := warroom.EnrichTrafficWithDNS(s.store.DB())
	if graph == nil {
		graph = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, graph)
}

func (s *Server) handleDNSSummary(w http.ResponseWriter, r *http.Request) {
	summary := warroom.GetDNSSummary(s.store.DB())
	if summary == nil {
		summary = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, summary)
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

func (s *Server) handleListPlaybooks(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.DB().Query(`SELECT id, data FROM playbooks ORDER BY id`)
	if err != nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	defer rows.Close()
	var pbs []map[string]any
	for rows.Next() {
		var id int64
		var data string
		rows.Scan(&id, &data)
		var pb map[string]any
		json.Unmarshal([]byte(data), &pb)
		pb["id"] = id
		pbs = append(pbs, pb)
	}
	if pbs == nil {
		pbs = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, pbs)
}

func (s *Server) handleSnifferStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, warroom.GetSnifferStats())
}

func (s *Server) handleSnifferDNS(w http.ResponseWriter, r *http.Request) {
	log := warroom.GetSnifferDNSLog()
	if log == nil {
		log = []warroom.DNSQuery{}
	}
	writeJSON(w, http.StatusOK, log)
}

func (s *Server) handleSnifferDNSTop(w http.ResponseWriter, r *http.Request) {
	top := warroom.GetSnifferDNSTopDomains()
	if top == nil {
		top = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, top)
}

func (s *Server) handleJA3(w http.ResponseWriter, r *http.Request) {
	fps := warroom.GetJA3Fingerprints()
	if fps == nil {
		fps = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, fps)
}

func (s *Server) handleThreatFeedStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, warroom.GetFeedStats())
}

func (s *Server) handleHoneypots(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, warroom.GetHoneypotPorts())
}

func (s *Server) handleBandwidth(w http.ResponseWriter, r *http.Request) {
	if warroom.GlobalThreatEngine == nil {
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}
	writeJSON(w, http.StatusOK, warroom.GlobalThreatEngine.GetBandwidth())
}

func (s *Server) handleProtocols(w http.ResponseWriter, r *http.Request) {
	if warroom.GlobalThreatEngine == nil {
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}
	writeJSON(w, http.StatusOK, warroom.GlobalThreatEngine.GetProtocols())
}

func (s *Server) handleFirewallList(w http.ResponseWriter, r *http.Request) {
	if warroom.GlobalFirewall == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, warroom.GlobalFirewall.GetBlocked())
}

func (s *Server) handleFirewallBlock(w http.ResponseWriter, r *http.Request) {
	if warroom.GlobalFirewall == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "firewall not available"})
		return
	}
	var req struct {
		IP     string `json:"ip"`
		Reason string `json:"reason"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.IP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ip required"})
		return
	}
	err := warroom.GlobalFirewall.BlockIP(req.IP, req.Reason)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "blocked", "ip": req.IP})
}

func (s *Server) handleFirewallUnblock(w http.ResponseWriter, r *http.Request) {
	if warroom.GlobalFirewall == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "firewall not available"})
		return
	}
	var req struct {
		IP string `json:"ip"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	warroom.GlobalFirewall.UnblockIP(req.IP)
	writeJSON(w, http.StatusOK, map[string]string{"status": "unblocked", "ip": req.IP})
}

func (s *Server) handleCreatePlaybook(w http.ResponseWriter, r *http.Request) {
	var pb map[string]any
	json.NewDecoder(r.Body).Decode(&pb)
	data, _ := json.Marshal(pb)
	s.store.DB().Exec(`INSERT INTO playbooks (data) VALUES (?)`, string(data))
	name, _ := pb["name"].(string)
	s.store.Audit("create_playbook", name, r.RemoteAddr)
	writeJSON(w, http.StatusCreated, map[string]string{"status": "created"})
}
