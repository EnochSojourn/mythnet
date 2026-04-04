package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (s *Server) handlePingTool(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provide ?target=IP"})
		return
	}

	s.store.Audit("tool_ping", target, r.RemoteAddr)

	// TCP ping to common ports
	ports := []int{80, 443, 22, 8080}
	count, _ := strconv.Atoi(r.URL.Query().Get("count"))
	if count <= 0 || count > 10 {
		count = 4
	}

	type pingResult struct {
		Seq   int     `json:"seq"`
		RTTMs float64 `json:"rtt_ms"`
		Port  int     `json:"port"`
		OK    bool    `json:"ok"`
	}

	var results []pingResult
	for i := 0; i < count; i++ {
		for _, port := range ports {
			start := time.Now()
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), 2*time.Second)
			rtt := time.Since(start)

			if err == nil {
				conn.Close()
				results = append(results, pingResult{
					Seq: i + 1, RTTMs: float64(rtt.Microseconds()) / 1000.0, Port: port, OK: true,
				})
				break // One success per round
			}

			if strings.Contains(err.Error(), "refused") {
				results = append(results, pingResult{
					Seq: i + 1, RTTMs: float64(rtt.Microseconds()) / 1000.0, Port: port, OK: true,
				})
				break
			}
		}
		if i < count-1 {
			time.Sleep(500 * time.Millisecond)
		}
	}

	// Stats
	var totalRTT float64
	success := 0
	for _, r := range results {
		if r.OK {
			totalRTT += r.RTTMs
			success++
		}
	}
	avgRTT := 0.0
	if success > 0 {
		avgRTT = totalRTT / float64(success)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"target":  target,
		"sent":    count,
		"received": success,
		"loss_pct": float64(count-success) / float64(count) * 100,
		"avg_rtt_ms": avgRTT,
		"results": results,
	})
}

func (s *Server) handleDNSLookup(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provide ?target=hostname_or_ip"})
		return
	}

	s.store.Audit("tool_dns", target, r.RemoteAddr)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	result := map[string]any{"target": target}

	// Forward lookup
	ips, err := net.DefaultResolver.LookupHost(ctx, target)
	if err == nil {
		result["addresses"] = ips
	}

	// Reverse lookup
	names, err := net.DefaultResolver.LookupAddr(ctx, target)
	if err == nil {
		cleaned := make([]string, len(names))
		for i, n := range names {
			cleaned[i] = strings.TrimSuffix(n, ".")
		}
		result["hostnames"] = cleaned
	}

	// MX records
	mxs, err := net.DefaultResolver.LookupMX(ctx, target)
	if err == nil && len(mxs) > 0 {
		var mxList []string
		for _, mx := range mxs {
			mxList = append(mxList, fmt.Sprintf("%s (priority %d)", strings.TrimSuffix(mx.Host, "."), mx.Pref))
		}
		result["mx"] = mxList
	}

	// TXT records
	txts, err := net.DefaultResolver.LookupTXT(ctx, target)
	if err == nil && len(txts) > 0 {
		result["txt"] = txts
	}

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleWhois(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provide ?target=IP"})
		return
	}

	s.store.Audit("tool_whois", target, r.RemoteAddr)

	conn, err := net.DialTimeout("tcp", "whois.iana.org:43", 5*time.Second)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "cannot reach WHOIS server"})
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	fmt.Fprintf(conn, "%s\r\n", target)
	buf := make([]byte, 8192)
	n, _ := conn.Read(buf)
	raw := string(buf[:n])

	// Parse key fields
	result := map[string]any{"target": target, "raw": raw}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "refer:") {
			result["refer"] = strings.TrimSpace(strings.TrimPrefix(line, "refer:"))
		}
		if strings.HasPrefix(line, "organisation:") || strings.HasPrefix(line, "Organization:") {
			result["organization"] = strings.TrimSpace(line[strings.Index(line, ":")+1:])
		}
		if strings.HasPrefix(line, "country:") || strings.HasPrefix(line, "Country:") {
			result["country"] = strings.TrimSpace(line[strings.Index(line, ":")+1:])
		}
		if strings.HasPrefix(line, "netname:") || strings.HasPrefix(line, "NetName:") {
			result["netname"] = strings.TrimSpace(line[strings.Index(line, ":")+1:])
		}
	}

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handlePortCheck(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	portStr := r.URL.Query().Get("port")
	if target == "" || portStr == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provide ?target=IP&port=80"})
		return
	}

	port, _ := strconv.Atoi(portStr)
	if port <= 0 || port > 65535 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid port"})
		return
	}

	s.store.Audit("tool_portcheck", fmt.Sprintf("%s:%d", target, port), r.RemoteAddr)

	start := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), 5*time.Second)
	rtt := time.Since(start)

	result := map[string]any{
		"target": target,
		"port":   port,
		"rtt_ms": float64(rtt.Microseconds()) / 1000.0,
	}

	if err != nil {
		if strings.Contains(err.Error(), "refused") {
			result["state"] = "closed"
			result["reachable"] = true
		} else {
			result["state"] = "filtered"
			result["reachable"] = false
			result["error"] = err.Error()
		}
	} else {
		conn.Close()
		result["state"] = "open"
		result["reachable"] = true
	}

	writeJSON(w, http.StatusOK, result)
}
