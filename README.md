# MythNet

AI-native network monitoring and threat detection system. Single binary, mesh networked, zero setup.

Drop it on any machine — Linux, macOS, Windows, Raspberry Pi — and it instantly scans your network, discovers devices, ingests telemetry, and forms an encrypted mesh with other instances.

## Quick Start

```bash
# Option 1: Download pre-built binary
# https://github.com/EnochSojourn/mythnet/releases
chmod +x mythnet-linux-amd64
./mythnet-linux-amd64

# Option 2: Docker
docker compose up

# Option 3: Build from source
make build
./mythnet

# Open http://localhost:8080
# Password is printed on first boot
```

The binary auto-generates a secure password on first boot and saves it to `./mythnet-data/password`.

## What's Inside

**15MB server binary** with an embedded web UI, compiled to a single file with zero dependencies.

### Discovery & Scanning
- TCP ping sweep and port scanning with concurrent worker pools
- ARP table reading for MAC address resolution
- 300+ vendor OUI database (Apple, Cisco, Ubiquiti, Espressif, etc.)
- OS fingerprinting from service banners and port combinations
- Device type classification (network gear, servers, IoT, cameras, printers)
- mDNS/Bonjour service discovery (AirPlay, printers, Chromecast, HomeKit)
- Auto-detects local subnets when none configured

### Security
- **CVE vulnerability scanning** — 18 rules matching service banners against known CVEs (regreSSHion, Apache RCE, vsftpd backdoor, Redis sandbox escape, etc.)
- **HTTP security header audit** — checks HSTS, CSP, X-Frame-Options, X-Content-Type-Options, detects Server/X-Powered-By leakage
- **TLS cipher audit** — flags deprecated TLS versions and weak ciphers (RC4, 3DES, CBC)
- **TLS certificate monitoring** — warns on certs expiring within 30 days, critical at 7 days
- **Port change detection** — alerts when ports open/close between scans, flags dangerous ports (telnet, SMB, RDP, Redis)
- **IP conflict detection** — detects multiple MACs on the same IP (ARP spoofing indicator)
- **Network policy engine** — define expected state rules ("servers must have SSH", "no telnet on production"), checked every scan
- Password auth with auto-generation, auto-TLS, API rate limiting (300/min), audit log, HMAC-signed webhooks

### Interactive Web UI
- D3.js force-directed network topology map with SVG device icons and animated links
- Real-time updates via WebSocket push (no polling delay)
- Device detail panel with ports, banners, uptime, latency, tags, notes, proxy links
- Command palette (Ctrl+K) for instant search across devices and actions
- Events feed with full-text search and severity filtering
- Sparkline trend charts in the stats dashboard
- Notification bell for critical/warning events
- Login page with session management, logout button
- Network tools panel: ping, DNS lookup, port check, subnet calculator, WHOIS
- Responsive layout for tablets
- Color legend, dark theme

### Telemetry Ingestion
- SNMP trap listener (v1/v2c) with OID classification
- SNMP active polling for sysName, sysDescr, sysUpTime, interface stats
- Syslog listener (RFC 3164) with facility/severity parsing
- HTTP API poller with status change deduplication
- All data normalized to standardized Markdown format

### Mesh Networking
- HashiCorp memberlist (SWIM gossip) for automatic peer discovery
- mTLS replication with ECDSA P-256 certificates (auto-generated on first boot)
- Operation log-based sync with idempotent apply
- **Full Node**: bidirectional sync, complete database copy
- **Sensor Node**: push-only, sends data to full nodes, minimal local retention
- AES-256 encrypted gossip with shared secret

### AI Integration
- Claude API streaming chat via WebSocket with network-aware context
- On-demand security and health report generation
- LLM-assisted device adapter generation (probe unknown device APIs)
- Pluggable provider interface

### Alerting & Reporting
- Webhook notifications: Slack, Discord, generic JSON (with HMAC-SHA256 signatures)
- SMTP email alerts for critical/warning events
- Syslog forwarding to external SIEM servers
- Daily digest email: health score, new devices, offline alerts
- Scheduled AI-generated reports (configurable interval)
- Network health score (0-100, grade A-F) from availability, security, stability, vulns
- SLA uptime reporting (24h/7d/30d percentages per device)
- Custom event rules: pattern-match and re-classify events automatically

### Network Tools
- Ping (TCP with statistics)
- DNS lookup (A, AAAA, MX, TXT records)
- Port check (open/closed/filtered with RTT)
- Subnet calculator (network, broadcast, usable hosts, wildcard)
- Traceroute (tracepath, no root needed)
- Wake-on-LAN (magic packet)
- WHOIS lookup (IP ownership)
- SNMP walk (query any OID tree)

### Export & Integration
- CSV device inventory export
- SVG network topology diagram
- SQLite database backup download
- Prometheus metrics at `/metrics`
- Markdown network documentation generator
- OpenAPI 3.0 spec at `/api/docs`
- Grafana dashboard template included
- Public status page at `/status` (no auth)

### Operations
- `mythnet --scan 10.0.0.0/24` — one-shot scan mode, prints table or JSON, exits
- `mythnet --check-config` — validate config without starting
- `mythnet --update` — self-update from GitHub releases
- `mythnet --log-format=json` — structured JSON logging for log aggregators
- Config hot-reload (watches file + SIGHUP)
- Systemd service with security hardening
- Docker + docker-compose
- `make install` / `make uninstall`
- Cross-compilation for 6 platforms
- Bash completion script

## mythctl — CLI Client

A standalone 6MB binary for managing MythNet instances from any terminal.

```bash
mythctl -s http://mythnet-server:8080 -p mypassword health
mythctl devices
mythctl events -f          # follow mode
mythctl scan               # trigger scan
mythctl sla                # uptime report
mythctl digest             # daily summary
mythctl test               # connectivity check
mythctl config > config.yaml
mythctl update             # self-update
mythctl tools ping 10.0.0.1
mythctl tools dns google.com
mythctl tools subnet 10.0.0.0/22
```

## Configuration

Copy `config.example.yaml` to `config.yaml`:

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  password: ""            # auto-generated if empty
  tls:
    enabled: false

scanner:
  subnets: []             # auto-detect if empty
  interval: "5m"
  timeout: "2s"

telemetry:
  snmp:
    enabled: true
    listen: "0.0.0.0:1162"
    community: "public"
  syslog:
    enabled: true
    listen: "0.0.0.0:1514"
  poller:
    enabled: true
    interval: "60s"

mesh:
  enabled: false
  node_type: "full"       # or "sensor"
  bind: "0.0.0.0:7946"
  replica_addr: "0.0.0.0:7947"
  join: []
  secret: ""
  data_dir: "./mythnet-data"

alerts:
  min_severity: "warning"
  syslog_forward: ""      # e.g. "siem.example.com:514"
  report_schedule: ""     # e.g. "24h" for daily AI reports
  webhooks: []
  # webhooks:
  #   - url: "https://hooks.slack.com/services/..."
  #     secret: "hmac-key"  # optional HMAC-SHA256 signing
  smtp:
    host: ""
    port: 587
    from: ""
    to: []

ai:
  enabled: true
  api_key: ""             # or ANTHROPIC_API_KEY env var
  model: "claude-sonnet-4-20250514"

database:
  path: "mythnet.db"

log:
  level: "info"
```

Environment variables: `ANTHROPIC_API_KEY`, `MYTHNET_PASSWORD`

## Docker

```bash
docker compose up
# or
docker build -t mythnet .
docker run -d --network host -v mythnet-data:/data mythnet
```

Host networking is required for subnet scanning.

## Mesh Setup

```bash
# Node A (first node)
./mythnet -c node-a.yaml

# Node B (joins A): set mesh.join: ["node-a-ip:7946"]
./mythnet -c node-b.yaml

# Sensor node: set mesh.node_type: "sensor"
./mythnet -c sensor.yaml
```

All nodes must share the same `mesh.secret`.

## API (51 endpoints)

Full OpenAPI 3.0 documentation at `/api/docs`. Key endpoints:

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health score + grade (no auth) |
| GET | `/api/stats` | Device, port, event counts |
| GET | `/api/devices` | List devices (?q=search, ?format=csv) |
| GET | `/api/devices/{id}` | Detail with ports, uptime, latency, tags |
| POST | `/api/devices/import` | Import devices from CSV |
| GET | `/api/devices/{id}/timeline` | Chronological event history |
| GET | `/api/devices/{id}/audit` | HTTP security header audit |
| GET | `/api/devices/{id}/traceroute` | Network path |
| POST | `/api/devices/{id}/wake` | Wake-on-LAN |
| POST | `/api/scans` | Trigger scan |
| GET | `/api/events` | Events (?q=search, ?severity=, ?device_id=) |
| GET | `/api/sla` | SLA uptime report (24h/7d/30d) |
| GET | `/api/diff` | Changes in the last hour |
| GET | `/api/digest` | Daily digest summary |
| GET | `/api/policies` | Network policy rules |
| GET | `/api/rules` | Custom event rules |
| GET | `/api/chat` | WebSocket AI chat |
| GET | `/api/ws` | WebSocket real-time push |
| POST | `/api/reports` | Generate AI report |
| GET | `/api/tools/*` | Ping, DNS, port, WHOIS, SNMP walk, subnet calc |
| GET | `/api/backup` | Download database |
| GET | `/status` | Public HTML status page |
| GET | `/metrics` | Prometheus metrics |
| GET | `/topology.svg` | SVG network diagram |
| ANY | `/proxy/{id}/{port}/*` | Reverse proxy to device |

## Architecture

```
┌──────────────────────────────────────────────────┐
│                mythnet (15MB binary)              │
│                                                   │
│  ┌──────────┐  ┌──────────┐  ┌────────────────┐  │
│  │ Scanner  │  │  SNMP /  │  │   AI Client    │  │
│  │  15 mods │  │  Syslog  │  │ (Claude API)   │  │
│  └────┬─────┘  └────┬─────┘  └───────┬────────┘  │
│       │              │                │           │
│       ▼              ▼                ▼           │
│  ┌─────────────────────────────────────────────┐  │
│  │   SQLite (16 tables, WAL, oplog, policies)  │  │
│  └─────────────────┬───────────────────────────┘  │
│                    │                              │
│  ┌─────────────────┴───────────────────────────┐  │
│  │  Chi HTTP + WebSocket + Embedded SvelteKit  │  │
│  │  51 endpoints · Auth · TLS · Rate limit     │  │
│  └─────────────────┬───────────────────────────┘  │
│                    │                              │
│  ┌─────────────────┴───────────────────────────┐  │
│  │   Gossip (memberlist) + mTLS Replication    │  │
│  │     Full ⟷ Full  ·  Sensor → Full           │  │
│  └─────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
```

## Building

```bash
make build          # Build mythnet + mythctl
make all            # Cross-compile all 6 platforms
make install        # Install to /usr/local/bin + systemd
make clean
```

Requires Go 1.24+ and Node.js 18+.

## License

MIT
