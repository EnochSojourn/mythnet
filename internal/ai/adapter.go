package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mythnet/mythnet/internal/db"
)

// Adapter defines how to poll a specific device's API endpoints.
type Adapter struct {
	DeviceID   string           `json:"device_id"`
	DeviceType string           `json:"device_type"`
	Vendor     string           `json:"vendor"`
	Endpoints  []AdapterEndpoint `json:"endpoints"`
	GeneratedAt string          `json:"generated_at"`
}

// AdapterEndpoint is a single pollable endpoint on a device.
type AdapterEndpoint struct {
	Path        string            `json:"path"`
	Method      string            `json:"method"`
	Description string            `json:"description"`
	Headers     map[string]string `json:"headers,omitempty"`
}

const adapterPrompt = `You are analyzing a network device's HTTP response to identify its API endpoints and capabilities.

Device info:
- IP: %s
- Vendor: %s
- Device type: %s
- Port: %d

Here is the HTTP response from the device's web interface:

Status: %d
Headers:
%s

Body (first 3000 chars):
%s

Based on this response, identify:
1. What kind of device/application this is
2. Any API endpoints that could be polled for health/status data
3. Common API patterns for this vendor/device type

Respond with ONLY a JSON object in this exact format (no markdown, no explanation):
{
  "device_type": "specific device/application name",
  "vendor": "vendor name",
  "endpoints": [
    {
      "path": "/api/endpoint",
      "method": "GET",
      "description": "what this endpoint returns"
    }
  ]
}

If you cannot determine any API endpoints, return an empty endpoints array. Only include endpoints you are reasonably confident exist based on the response.`

// GenerateAdapter fetches a device's HTTP response and uses the LLM to identify API endpoints.
func GenerateAdapter(ctx context.Context, client Client, device *db.Device, port int) (*Adapter, error) {
	// Fetch the device's web response
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/", scheme, device.IP, port)

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch device: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	bodyStr := string(body)
	if len(bodyStr) > 3000 {
		bodyStr = bodyStr[:3000]
	}

	// Format headers
	var headers strings.Builder
	for k, vs := range resp.Header {
		for _, v := range vs {
			fmt.Fprintf(&headers, "%s: %s\n", k, v)
		}
	}

	// Build prompt
	prompt := fmt.Sprintf(adapterPrompt,
		device.IP, device.Vendor, device.DeviceType, port,
		resp.StatusCode, headers.String(), bodyStr,
	)

	// Ask the LLM
	messages := []Message{{Role: "user", Content: prompt}}
	sysPrompt := "You are a network device API analyst. Respond only with valid JSON."

	var result strings.Builder
	err = client.Chat(ctx, sysPrompt, messages, func(chunk string) {
		result.WriteString(chunk)
	})
	if err != nil {
		return nil, fmt.Errorf("LLM request: %w", err)
	}

	// Parse the JSON response
	raw := result.String()
	// Strip markdown fences if present
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "```json")
	raw = strings.TrimPrefix(raw, "```")
	raw = strings.TrimSuffix(raw, "```")
	raw = strings.TrimSpace(raw)

	var parsed struct {
		DeviceType string            `json:"device_type"`
		Vendor     string            `json:"vendor"`
		Endpoints  []AdapterEndpoint `json:"endpoints"`
	}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return nil, fmt.Errorf("parse LLM response: %w (raw: %s)", err, raw[:min(200, len(raw))])
	}

	adapter := &Adapter{
		DeviceID:    device.ID,
		DeviceType:  parsed.DeviceType,
		Vendor:      parsed.Vendor,
		Endpoints:   parsed.Endpoints,
		GeneratedAt: time.Now().Format(time.RFC3339),
	}

	return adapter, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
