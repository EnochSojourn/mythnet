# MythNet

AI-native network monitoring and threat detection system. Single binary, mesh networked, zero setup.

Drop it on any machine — Linux, macOS, Windows, Raspberry Pi — and it instantly scans your network, discovers devices, ingests telemetry, and forms an encrypted mesh with other instances.

## Quick Start

```bash
# Option 1: Docker (easiest)
docker compose up

# Option 2: Download pre-built binary from GitHub Releases
# https://github.com/EnochSojourn/mythnet/releases

# Option 3: Build from source (requires Go 1.24+ and Node.js 18+)
make build
./mythnet

# Open the web UI
# Password is printed to the console on first boot
open http://localhost:8080
```

The binary auto-generates a secure admin password on first boot and saves it to `./mythnet-data/password`. All subsequent runs use the same password.

## Features

**Discovery & Scanning**
- TCP ping sweep and port scanning with concurrent worker pools
- ARP table reading for MAC address resolution
- 300+ vendor OUI database (Apple, Cisco, Ubiquiti, Espressif, etc.)
- OS fingerprinting from service banners and port combinations
- Device type classification (network gear, servers, IoT, cameras, printers, etc.)
- Auto-detects local subnets when none configured

**Interactive Web UI**
- D3.js force-directed network topology map with drag, zoom, pan
- Real-time device list with type badges and online/offline indicators
- Device detail panel with open ports, service banners, and proxy links
- Events feed with severity filtering (SNMP, syslog, API poll)
- WebSocket push for instant updates — no polling delay
- Dark theme built with Tailwind CSS

**Telemetry Ingestion**
- SNMP trap listener (v1/v2c) with OID classification
- Syslog listener (RFC 3164) with facility/severity parsing
- REST API poller with status change deduplication
- All data normalized to standardized Markdown format

**Mesh Networking**
- HashiCorp memberlist (SWIM gossip) for peer discovery
- mTLS replication with ECDSA P-256 certificates (auto-generated)
- Operation log-based sync with idempotent apply
- Full Node: bidirectional sync, complete database
- Sensor Node: push-only, minimal local retention
- AES-256 encrypted gossip with shared secret

**AI Integration**
- Claude API streaming chat via WebSocket
- Network-aware context: devices, ports, events injected into every prompt
- On-demand security and health report generation
- Pluggable provider interface

**Security**
- Auto-generated admin password on first boot
- HTTP Basic Auth on all API and proxy routes
- Auto-TLS with self-signed certificates
- Encrypted credential storage (0600 file permissions)
- mTLS on all mesh communication
- Reverse proxy validates ports against discovered open ports only

## Configuration

Copy `config.example.yaml` to `config.yaml` and customize:

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  password: ""          # auto-generated if empty
  tls:
    enabled: false      # set true for HTTPS

scanner:
  subnets: []           # auto-detect if empty
  interval: "5m"
  timeout: "2s"

telemetry:
  snmp:
    enabled: true
    listen: "0.0.0.0:1162"
  syslog:
    enabled: true
    listen: "0.0.0.0:1514"
  poller:
    enabled: true
    interval: "60s"

mesh:
  enabled: false
  node_type: "full"     # or "sensor"
  bind: "0.0.0.0:7946"
  replica_addr: "0.0.0.0:7947"
  join: []              # seed node addresses
  secret: ""            # shared encryption key

ai:
  enabled: true
  api_key: ""           # or set ANTHROPIC_API_KEY env var
  model: "claude-sonnet-4-20250514"

database:
  path: "mythnet.db"
```

Environment variables: `ANTHROPIC_API_KEY`, `MYTHNET_PASSWORD`

## Docker

```bash
# Quick start
docker compose up

# Or build and run manually
docker build -t mythnet .
docker run -d --network host -v mythnet-data:/data mythnet
```

The `network_mode: host` is required for subnet scanning to reach your local network. The password is printed in the container logs on first boot.

## Cross-Compilation

```bash
make all    # Build for all platforms

# Individual targets:
make linux-amd64
make linux-arm64
make linux-arm        # Raspberry Pi
make darwin-amd64
make darwin-arm64     # Apple Silicon
make windows-amd64
```

## Mesh Setup

```bash
# Node A (full node, first to start)
./mythnet -c node-a.yaml

# Node B (joins A)
# In node-b.yaml: mesh.join: ["node-a-ip:7946"]
./mythnet -c node-b.yaml

# Node C (sensor — push-only, no database copy)
# In node-c.yaml: mesh.node_type: "sensor", mesh.join: ["node-a-ip:7946"]
./mythnet -c node-c.yaml
```

All nodes must share the same `mesh.secret` value.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Server status (no auth required) |
| GET | `/api/stats` | Device, port, event, scan counts |
| GET | `/api/devices` | All discovered devices |
| GET | `/api/devices/{id}` | Device detail with ports |
| GET | `/api/scans` | Scan history |
| POST | `/api/scans` | Trigger immediate scan |
| GET | `/api/events` | Telemetry events (filterable) |
| GET | `/api/mesh` | Mesh peer status |
| GET | `/api/chat` | WebSocket AI chat |
| GET | `/api/ws` | WebSocket real-time push |
| POST | `/api/reports` | Generate AI security report |
| ANY | `/proxy/{id}/{port}/*` | Reverse proxy to device |

## Architecture

```
┌──────────────────────────────────────────────────┐
│                mythnet (14MB binary)              │
│                                                   │
│  ┌──────────┐  ┌──────────┐  ┌────────────────┐  │
│  │ Scanner  │  │  SNMP /  │  │   AI Client    │  │
│  │ (TCP/ARP)│  │  Syslog  │  │ (Claude API)   │  │
│  └────┬─────┘  └────┬─────┘  └───────┬────────┘  │
│       │              │                │           │
│       ▼              ▼                ▼           │
│  ┌─────────────────────────────────────────────┐  │
│  │        SQLite + Oplog (encrypted WAL)       │  │
│  └─────────────────┬───────────────────────────┘  │
│                    │                              │
│  ┌─────────────────┴───────────────────────────┐  │
│  │  Chi HTTP + WebSocket + Embedded SvelteKit  │  │
│  │  (Auth · TLS · Reverse Proxy · Chat · Push) │  │
│  └─────────────────┬───────────────────────────┘  │
│                    │                              │
│  ┌─────────────────┴───────────────────────────┐  │
│  │   Gossip (memberlist) + mTLS Replication    │  │
│  │     Full Node ⟷ Full Node                  │  │
│  │     Sensor Node → Full Node                 │  │
│  └─────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
```

## License

MIT
