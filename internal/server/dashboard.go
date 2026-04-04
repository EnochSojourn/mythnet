package server

import (
	"net/http"
)

// handleDashboard redirects to the main SvelteKit app.
// Kept for backwards compatibility with old bookmarks.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusMovedPermanently)
}
