package server

import (
	"net/http"
	"os"
)

var warroomHTML []byte

func (s *Server) handleWarroomPage(w http.ResponseWriter, r *http.Request) {
	if len(warroomHTML) == 0 {
		data, err := os.ReadFile("web/warroom.html")
		if err != nil {
			http.Error(w, "Warroom UI not found", 404)
			return
		}
		warroomHTML = data
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(warroomHTML)
}
