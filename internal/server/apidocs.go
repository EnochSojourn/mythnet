package server

import "net/http"

const apiDocsJSON = `{
  "openapi": "3.0.3",
  "info": {
    "title": "MythNet API",
    "version": "1.5.0",
    "description": "AI-native network monitoring and threat detection system"
  },
  "paths": {
    "/api/health": {
      "get": {"summary": "Server health + network health score", "tags": ["System"], "security": [],
        "responses": {"200": {"description": "Health status with score (0-100) and grade (A-F)"}}}
    },
    "/api/stats": {
      "get": {"summary": "Network statistics", "tags": ["System"],
        "responses": {"200": {"description": "Device, port, event, and scan counts"}}}
    },
    "/api/settings": {
      "get": {"summary": "Current configuration", "tags": ["System"],
        "responses": {"200": {"description": "Scanner, telemetry, mesh, and AI settings"}}}
    },
    "/api/devices": {
      "get": {"summary": "List all devices", "tags": ["Devices"],
        "parameters": [
          {"name": "q", "in": "query", "description": "Search by IP, hostname, vendor, type"},
          {"name": "format", "in": "query", "description": "Set to 'csv' for CSV export"}
        ],
        "responses": {"200": {"description": "Array of discovered devices"}}}
    },
    "/api/devices/{id}": {
      "get": {"summary": "Device detail with ports, uptime, latency, notes, tags", "tags": ["Devices"],
        "parameters": [{"name": "id", "in": "path", "required": true}],
        "responses": {"200": {"description": "Device detail object"}}}
    },
    "/api/devices/{id}/notes": {
      "get": {"summary": "Get device notes", "tags": ["Devices"]},
      "put": {"summary": "Set device notes", "tags": ["Devices"],
        "requestBody": {"content": {"application/json": {"schema": {"properties": {"notes": {"type": "string"}}}}}}}
    },
    "/api/devices/{id}/tags": {
      "get": {"summary": "Get device tags", "tags": ["Devices"]},
      "put": {"summary": "Set device tags", "tags": ["Devices"],
        "requestBody": {"content": {"application/json": {"schema": {"type": "array", "items": {"type": "string"}}}}}}
    },
    "/api/devices/{id}/wake": {
      "post": {"summary": "Send Wake-on-LAN magic packet", "tags": ["Devices"]}
    },
    "/api/devices/{id}/adapt": {
      "post": {"summary": "Generate LLM-assisted API adapter", "tags": ["AI"],
        "parameters": [{"name": "port", "in": "query", "description": "HTTP port to probe"}]}
    },
    "/api/scans": {
      "get": {"summary": "Scan history", "tags": ["Scanning"]},
      "post": {"summary": "Trigger immediate scan", "tags": ["Scanning"]}
    },
    "/api/events": {
      "get": {"summary": "List telemetry events", "tags": ["Events"],
        "parameters": [
          {"name": "limit", "in": "query"}, {"name": "device_id", "in": "query"},
          {"name": "severity", "in": "query"}, {"name": "q", "in": "query", "description": "Full-text search"}
        ]}
    },
    "/api/diff": {
      "get": {"summary": "Changes in the last hour: new/offline devices, port changes, vulns", "tags": ["Events"]}
    },
    "/api/snapshots": {
      "get": {"summary": "Time-series snapshots for charts", "tags": ["System"],
        "parameters": [{"name": "hours", "in": "query"}]}
    },
    "/api/mesh": {
      "get": {"summary": "Mesh peer status", "tags": ["Mesh"]}
    },
    "/api/tags": {
      "get": {"summary": "All unique device tags", "tags": ["Devices"]}
    },
    "/api/chat": {
      "get": {"summary": "WebSocket AI chat (upgrade required)", "tags": ["AI"]}
    },
    "/api/ws": {
      "get": {"summary": "WebSocket real-time push (upgrade required)", "tags": ["System"]}
    },
    "/api/reports": {
      "post": {"summary": "Generate AI network health report", "tags": ["AI"]}
    },
    "/api/audit": {
      "get": {"summary": "View audit log of user actions", "tags": ["System"]}
    },
    "/api/backup": {
      "get": {"summary": "Download SQLite database backup", "tags": ["System"]}
    },
    "/metrics": {
      "get": {"summary": "Prometheus metrics (no auth)", "tags": ["System"], "security": []}
    },
    "/topology.svg": {
      "get": {"summary": "Network topology as SVG image (no auth)", "tags": ["System"], "security": []}
    },
    "/proxy/{deviceID}/{port}/{path}": {
      "get": {"summary": "Reverse proxy to device web UI", "tags": ["Devices"]}
    }
  },
  "components": {
    "securitySchemes": {
      "basicAuth": {"type": "http", "scheme": "basic"}
    }
  },
  "security": [{"basicAuth": []}]
}`

func (s *Server) handleAPIDocs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(apiDocsJSON))
}
