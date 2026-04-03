package ai

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Message represents a chat message.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Client is the interface for AI providers.
type Client interface {
	Chat(ctx context.Context, systemPrompt string, messages []Message, onChunk func(string)) error
}

// AnthropicClient calls the Claude API with streaming.
type AnthropicClient struct {
	apiKey string
	model  string
	http   *http.Client
}

// NewAnthropicClient creates a new Claude API client.
func NewAnthropicClient(apiKey, model string) *AnthropicClient {
	if model == "" {
		model = "claude-sonnet-4-20250514"
	}
	return &AnthropicClient{
		apiKey: apiKey,
		model:  model,
		http:   &http.Client{Timeout: 120 * time.Second},
	}
}

func (c *AnthropicClient) Chat(ctx context.Context, systemPrompt string, messages []Message, onChunk func(string)) error {
	body := map[string]any{
		"model":      c.model,
		"max_tokens": 4096,
		"stream":     true,
		"system":     systemPrompt,
		"messages":   messages,
	}

	jsonBody, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("anthropic request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("anthropic %d: %s", resp.StatusCode, string(errBody))
	}

	// Parse SSE stream
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 64*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := line[6:]
		if data == "[DONE]" {
			break
		}

		var event struct {
			Type  string `json:"type"`
			Delta struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"delta"`
		}
		if json.Unmarshal([]byte(data), &event) == nil {
			if event.Type == "content_block_delta" && event.Delta.Type == "text_delta" {
				onChunk(event.Delta.Text)
			}
		}
	}

	return scanner.Err()
}

// ChatSync is a convenience method that collects the full response.
func (c *AnthropicClient) ChatSync(ctx context.Context, systemPrompt string, messages []Message) (string, error) {
	var b strings.Builder
	err := c.Chat(ctx, systemPrompt, messages, func(chunk string) {
		b.WriteString(chunk)
	})
	return b.String(), err
}
