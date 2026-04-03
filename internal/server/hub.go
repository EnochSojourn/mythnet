package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

// Hub manages WebSocket connections and broadcasts updates to all clients.
type Hub struct {
	mu      sync.RWMutex
	clients map[*websocket.Conn]bool
	logger  *slog.Logger
}

// NewHub creates a new broadcast hub.
func NewHub(logger *slog.Logger) *Hub {
	return &Hub{
		clients: make(map[*websocket.Conn]bool),
		logger:  logger,
	}
}

// HandleWS upgrades an HTTP connection to WebSocket and registers it.
func (h *Hub) HandleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	h.mu.Lock()
	h.clients[conn] = true
	h.mu.Unlock()

	// Keep connection alive — read and discard client messages
	defer func() {
		h.mu.Lock()
		delete(h.clients, conn)
		h.mu.Unlock()
		conn.Close()
	}()

	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
}

// Broadcast sends a JSON message to all connected WebSocket clients.
func (h *Hub) Broadcast(msgType string, data any) {
	msg, err := json.Marshal(map[string]any{
		"type": msgType,
		"data": data,
	})
	if err != nil {
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	for conn := range h.clients {
		if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			conn.Close()
			go func(c *websocket.Conn) {
				h.mu.Lock()
				delete(h.clients, c)
				h.mu.Unlock()
			}(conn)
		}
	}
}

// ClientCount returns the number of connected WebSocket clients.
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}
