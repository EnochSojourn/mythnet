package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/websocket"
	"github.com/mythnet/mythnet/internal/ai"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type chatMsg struct {
	Content string `json:"content"`
}

type chatResp struct {
	Type    string `json:"type"` // "chunk", "done", "error"
	Content string `json:"content"`
}

func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	if s.ai == nil {
		http.Error(w, "AI not configured — set ai.api_key or ANTHROPIC_API_KEY", http.StatusServiceUnavailable)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	var history []ai.Message

	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			break
		}

		var msg chatMsg
		json.Unmarshal(raw, &msg)
		if strings.TrimSpace(msg.Content) == "" {
			continue
		}

		history = append(history, ai.Message{Role: "user", Content: msg.Content})

		// Build fresh context each turn
		networkCtx := ai.BuildContext(s.store)
		sysPrompt := ai.SystemPrompt(networkCtx)

		// Stream AI response
		var fullResp strings.Builder
		err = s.ai.Chat(r.Context(), sysPrompt, history, func(chunk string) {
			fullResp.WriteString(chunk)
			conn.WriteJSON(chatResp{Type: "chunk", Content: chunk})
		})

		if err != nil {
			conn.WriteJSON(chatResp{Type: "error", Content: err.Error()})
		}

		conn.WriteJSON(chatResp{Type: "done"})

		if fullResp.Len() > 0 {
			history = append(history, ai.Message{Role: "assistant", Content: fullResp.String()})
		}

		// Keep history manageable
		if len(history) > 20 {
			history = history[len(history)-20:]
		}
	}
}
