package server

import (
	"net/http"
	"os"
)

var mobileHTML []byte

func init() {
	// Try to load from file at startup
	data, err := os.ReadFile("web/mobile.html")
	if err == nil {
		mobileHTML = data
	}
}

func (s *Server) handleMobile(w http.ResponseWriter, r *http.Request) {
	if len(mobileHTML) == 0 {
		// Try loading again
		data, err := os.ReadFile("web/mobile.html")
		if err != nil {
			http.Error(w, "Mobile UI not found", 404)
			return
		}
		mobileHTML = data
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(mobileHTML)
}
