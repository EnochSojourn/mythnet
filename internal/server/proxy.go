package server

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
)

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "deviceID")
	portStr := chi.URLParam(r, "port")

	device, err := s.store.GetDevice(deviceID)
	if err != nil {
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}

	// Verify port is a known open port on this device
	ports, _ := s.store.GetDevicePorts(deviceID)
	valid := false
	for _, p := range ports {
		if fmt.Sprintf("%d", p.Port) == portStr {
			valid = true
			break
		}
	}
	if !valid {
		http.Error(w, "port not accessible — not in discovered open ports", http.StatusForbidden)
		return
	}

	scheme := "http"
	if portStr == "443" || portStr == "8443" {
		scheme = "https"
	}

	target, _ := url.Parse(fmt.Sprintf("%s://%s:%s", scheme, device.IP, portStr))
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Strip the /proxy/{deviceID}/{port} prefix from the forwarded path
	prefix := fmt.Sprintf("/proxy/%s/%s", deviceID, portStr)
	r.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)
	if r.URL.Path == "" {
		r.URL.Path = "/"
	}
	r.Host = target.Host
	r.Header.Set("X-Forwarded-For", r.RemoteAddr)
	r.Header.Set("X-Forwarded-Proto", "http")
	r.Header.Set("X-MythNet-Proxy", "true")

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, fmt.Sprintf("proxy error: %v", err), http.StatusBadGateway)
	}

	proxy.ServeHTTP(w, r)
}
