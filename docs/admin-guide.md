# MythNet Administration Guide

## Table of Contents

- [Installation](#installation)
- [Initial Setup](#initial-setup)
- [Configuration Reference](#configuration-reference)
- [Command-Line Reference](#command-line-reference)
- [Security](#security)
- [Mesh Networking](#mesh-networking)
- [Telemetry Ingestion](#telemetry-ingestion)
- [Alerting](#alerting)
- [AI Integration](#ai-integration)
- [Network Policies](#network-policies)
- [Database](#database)
- [Monitoring and Observability](#monitoring-and-observability)
- [Firewall Requirements](#firewall-requirements)
- [Systemd Deployment](#systemd-deployment)
- [Docker Deployment](#docker-deployment)
- [Maintenance](#maintenance)
- [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites

- **Build from source:** Go 1.24+, Node.js 18+
- **Binary download:** No dependencies (single static binary)

### Supported Platforms

| Platform | Architecture |
|----------|-------------|
| Linux | amd64, arm64, armv7 |
| macOS | amd64, arm64 (Apple Silicon) |
| Windows | amd64 |

### Option 1: Download Binary

Download the latest release from [GitHub Releases](https://github.com/EnochSojourn/mythnet/releases).

```bash
chmod +x mythnet-linux-amd64
./mythnet-linux-amd64
```

### Option 2: Build from Source

```bash
git clone https://github.com/EnochSojourn/mythnet.git
cd mythnet
make build    # Builds mythnet + mythctl
```

### Option 3: Install as System Service

```bash
sudo make install
sudo useradd -r -s /bin/false mythnet
sudo chown -R mythnet:mythnet /var/lib/mythnet
sudo systemctl daemon-reload
sudo systemctl enable --now mythnet
```

This installs to `/usr/local/bin/mythnet`, creates `/etc/mythnet/config.yaml`, and registers a systemd service.

### Option 4: Docker

```bash
docker compose up
```

Or manually:

```bash
docker build -t mythnet .
docker run -d --network host -v mythnet-data:/data mythnet
```

> **Note:** Host networking (`--network host`) is required for subnet scanning to function.

### Self-Update

```bash
mythnet --update
# or
mythctl update
```

Downloads the latest release from GitHub and replaces the current binary.

---

## Initial Setup

1. Start MythNet:
   ```bash
   ./mythnet
   ```

2. On first boot, a random 32-character password is generated, printed to the console, and saved to `./mythnet-data/password` (mode 0600).

3. Open `http://localhost:8080` and log in with username `admin` and the generated password.

4. MythNet auto-detects local subnets and begins scanning immediately. No configuration is required for basic operation.

5. Copy and customize the config file if needed:
   ```bash
   cp config.example.yaml config.yaml
   ./mythnet -c config.yaml
   ```

---

## Configuration Reference

Configuration is loaded from `config.yaml` (or the path specified with `-c`). All fields are optional — defaults are applied for anything not specified.

Changes to `scanner.subnets` and `scanner.interval` are hot-reloaded (file polled every 10 seconds, also on `SIGHUP`).

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `MYTHNET_PASSWORD` | Admin password (overrides config) |
| `ANTHROPIC_API_KEY` | AI API key (fallback if `ai.api_key` is empty) |

### Server

```yaml
server:
  host: "0.0.0.0"       # Bind address
  port: 8080             # HTTP port
  password: ""           # Auto-generated if empty
  tls:
    enabled: false       # Enable HTTPS
    cert_file: ""        # Path to TLS certificate (auto-generates self-signed if empty)
    key_file: ""         # Path to TLS private key
```

### Scanner

```yaml
scanner:
  subnets: []            # CIDRs to scan (auto-detects local subnets if empty)
  interval: "5m"         # Time between scan cycles
  timeout: "2s"          # TCP connect timeout per port
  max_concurrent_hosts: 100   # Parallel host scans
  max_concurrent_ports: 20    # Parallel port scans per host
  ports:                 # Ports to scan (44 defaults if omitted)
    - 22
    - 80
    - 443
    # ...
```

Default ports (44): 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 548, 554, 631, 993, 995, 1433, 1521, 1883, 3000, 3306, 3389, 5000, 5001, 5353, 5432, 5900, 6379, 7547, 8000, 8008, 8060, 8080, 8443, 8888, 9090, 9100, 27017, 32400, 49152, 62078.

### Telemetry

```yaml
telemetry:
  snmp:
    enabled: true
    listen: "0.0.0.0:1162"    # SNMP trap listener (UDP)
    community: "public"        # Community string
  syslog:
    enabled: true
    listen: "0.0.0.0:1514"    # Syslog listener (UDP, RFC 3164)
  poller:
    enabled: true
    interval: "60s"            # HTTP endpoint poll interval
```

### Mesh

```yaml
mesh:
  enabled: false
  node_type: "full"        # "full" (bidirectional sync) or "sensor" (push-only)
  bind: "0.0.0.0:7946"    # Gossip protocol address
  replica_addr: "0.0.0.0:7947"  # mTLS replication address
  join: []                 # Seed node addresses (e.g., ["10.0.0.1:7946"])
  secret: ""               # Shared secret for AES-256 gossip encryption
  data_dir: "./mythnet-data"   # Identity keypair and password storage
```

### Alerts

```yaml
alerts:
  min_severity: "warning"   # Minimum severity to trigger alerts
  syslog_forward: ""        # External SIEM (e.g., "siem.example.com:514")
  report_schedule: ""       # AI report interval (e.g., "24h")
  webhooks:
    - url: "https://hooks.slack.com/services/..."
      secret: "hmac-key"   # Optional HMAC-SHA256 signing
  smtp:
    host: ""
    port: 587
    username: ""
    password: ""
    from: ""
    to: []
```

### AI

```yaml
ai:
  enabled: true
  api_key: ""                         # Or set ANTHROPIC_API_KEY env
  model: "claude-sonnet-4-20250514"
```

### Database

```yaml
database:
  path: "mythnet.db"     # SQLite file path
```

### Logging

```yaml
log:
  level: "info"    # debug, info, warn, error
```

---

## Command-Line Reference

### mythnet

```
mythnet [flags]

Flags:
  -c, --config string    Config file path (default "config.yaml")
      --version          Print version and exit
      --log-format       Log format: "text" or "json" (default "text")
      --scan CIDR        One-shot scan mode (e.g., --scan 192.168.1.0/24)
      --json             Output scan results as JSON (with --scan)
      --check-config     Validate config and print summary
      --update           Check for updates and self-update
      --demo             Start with fake demo data (in-memory DB)
```

Examples:

```bash
# Normal operation
mythnet -c /etc/mythnet/config.yaml

# One-shot scan
mythnet --scan 10.0.0.0/24
mythnet --scan 10.0.0.0/24 --json

# Validate config
mythnet --check-config -c config.yaml

# JSON logging for log aggregators
mythnet --log-format json

# Demo mode (no real scanning)
mythnet --demo
```

### mythctl

```
mythctl [flags] <command> [args]

Flags:
  -s, --server string    MythNet server URL (default "http://localhost:8080")
  -p, --password string  Admin password (or MYTHNET_PASSWORD env)
      --version          Print version and exit

Commands:
  health, status         Health score and network grade
  devices, dev           List all devices
  devices <id>           Device detail (IP, MAC, vendor, OS, ports)
  events, ev             Recent events (last 20)
  events -f              Follow events in real time
  scan [subnet]          Trigger a network scan
  sla                    SLA uptime report (24h / 7d / 30d)
  digest                 Daily digest summary
  test                   Test server connectivity
  config                 Print config template
  tools ping <ip>        Ping a host
  tools dns <host>       DNS lookup (A, PTR, MX, TXT)
  tools port <ip> <port> Check if port is open
  tools whois <ip>       WHOIS lookup
  tools subnet <cidr>    Subnet calculator
  update                 Self-update from GitHub
  help                   Print help
```

Examples:

```bash
# Connect to remote instance
mythctl -s https://mythnet.example.com:8080 -p mypassword health

# Monitor events
mythctl events -f

# Trigger scan on specific subnet
mythctl scan 192.168.1.0/24

# Network tools
mythctl tools ping 10.0.0.1
mythctl tools dns google.com
mythctl tools subnet 10.0.0.0/22
```

---

## Security

### Authentication

All API endpoints require Basic Auth with username `admin`, except:

- `GET /api/health` — health check
- `GET /api/docs` — OpenAPI spec
- `GET /status` — public status page
- `GET /metrics` — Prometheus metrics
- `GET /topology.svg` — network topology diagram
- `GET /api/ws` — WebSocket real-time push
- `GET /api/chat` — WebSocket AI chat
- Static assets and UI routes (`/`, `/dashboard`, `/m`, `/warroom`)

### Password Management

Password is resolved in this order:

1. `server.password` in config file
2. `MYTHNET_PASSWORD` environment variable
3. Saved password file at `{data_dir}/password`
4. Auto-generate a random 32-character hex password (saved to file, printed on startup)

The password is stored in memory as a SHA-256 hash and compared using constant-time comparison.

### TLS

Enable TLS in config:

```yaml
server:
  tls:
    enabled: true
    cert_file: "/path/to/cert.pem"   # Optional — auto-generates self-signed if empty
    key_file: "/path/to/key.pem"
```

When no cert/key files are provided, MythNet generates a self-signed ECDSA P-256 certificate (valid 10 years, TLS 1.2 minimum).

**Recommendation:** In production, run behind a reverse proxy (nginx, Caddy) that terminates TLS with a real certificate.

### Rate Limiting

- 300 requests/minute per IP (token bucket)
- Respects `X-Real-IP` header when behind a reverse proxy
- Exempted: `/metrics` and `/topology.svg`
- Stale rate limit buckets cleaned every 5 minutes

### Audit Log

All administrative actions are logged with: action type, detail, remote IP, and timestamp. View via `GET /api/audit`.

---

## Mesh Networking

MythNet instances form an encrypted mesh for automatic peer discovery and data replication.

### Architecture

- **Full nodes** maintain a complete copy of the database and sync bidirectionally with other full nodes.
- **Sensor nodes** push data to full nodes but do not store or serve replicated data. Ideal for lightweight deployments on Raspberry Pi or edge devices.

### Setup

**Node A (first node):**

```yaml
mesh:
  enabled: true
  node_type: "full"
  bind: "0.0.0.0:7946"
  replica_addr: "0.0.0.0:7947"
  secret: "your-shared-secret-here"
```

**Node B (joins A):**

```yaml
mesh:
  enabled: true
  node_type: "full"
  bind: "0.0.0.0:7946"
  replica_addr: "0.0.0.0:7947"
  join: ["node-a-ip:7946"]
  secret: "your-shared-secret-here"
```

**Sensor node:**

```yaml
mesh:
  enabled: true
  node_type: "sensor"
  bind: "0.0.0.0:7946"
  join: ["full-node-ip:7946"]
  secret: "your-shared-secret-here"
```

All nodes **must** share the same `mesh.secret`.

### How It Works

- **Discovery:** SWIM gossip protocol (HashiCorp memberlist) for peer discovery and failure detection.
- **Encryption:** Gossip encrypted with AES-256 (derived from SHA-256 of the shared secret).
- **Identity:** Each node generates an ECDSA P-256 keypair on first boot, stored in `{data_dir}/identity/`.
- **Replication:** mTLS (TLS 1.3, mutual certificate auth) over the replica port. Sync runs every 30 seconds.
- **Replicated data:** Device records, port data, events.
- **Oplog retention:** 48 hours, pruned hourly.

### Required Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 7946 | TCP + UDP | Gossip (SWIM) |
| 7947 | TCP | mTLS replication |

---

## Telemetry Ingestion

### SNMP Traps

Listens for SNMP v1/v2c traps on UDP port 1162 (default).

Classified trap types: Cold Start, Warm Start, Link Down, Link Up, Authentication Failure, EGP Neighbor Loss, Cisco Config Change. Unknown OIDs are logged with raw variable bindings.

Configure network devices to send traps to `mythnet-ip:1162` with community string `public` (or as configured).

### SNMP Active Polling

Every 5 minutes, MythNet polls all online devices via SNMP v2c GET for: sysDescr, sysName, sysUpTime, sysContact, sysLocation. Results enrich device hostname and OS identification.

Recognized platforms: Cisco IOS, Juniper JunOS, MikroTik RouterOS, Linux, Windows, FreeBSD, Ubiquiti EdgeOS, Fortinet FortiOS.

### Syslog

Listens for RFC 3164 syslog messages on UDP port 1514 (default).

Configure network devices and servers to forward syslog to `mythnet-ip:1514`.

Severity mapping:

| Syslog Severity | MythNet Level |
|-----------------|---------------|
| 0 (Emergency) | critical |
| 1 (Alert) | critical |
| 2 (Critical) | critical |
| 3 (Error) | warning |
| 4 (Warning) | warning |
| 5 (Notice) | info |
| 6 (Informational) | info |
| 7 (Debug) | debug |

### HTTP Poller

Polls HTTP(S) endpoints on discovered devices every 60 seconds (default). Checks ports 80, 443, 8080, 8443, 9090. Generates events only when HTTP status changes (deduplication).

---

## Alerting

### Webhooks

```yaml
alerts:
  webhooks:
    - url: "https://hooks.slack.com/services/T.../B.../xxx"
    - url: "https://discord.com/api/webhooks/123/abc"
    - url: "https://your-server.com/webhook"
      secret: "your-hmac-secret"
```

- **Slack and Discord** are auto-detected and formatted natively (text for Slack, embeds for Discord).
- **Generic webhooks** receive JSON: `{event, severity, source, device_id, body_md, timestamp, tags}`.
- **HMAC signing:** If `secret` is set, requests include `X-MythNet-Signature: sha256={hex_digest}` for verification.
- Events are checked every 5 seconds. Only events at or above `alerts.min_severity` trigger webhooks.

### Email (SMTP)

```yaml
alerts:
  smtp:
    host: "smtp.example.com"
    port: 587
    username: "alerts@example.com"
    password: "password"
    from: "mythnet@example.com"
    to:
      - "admin@example.com"
      - "oncall@example.com"
```

Subject format: `[MythNet CRITICAL] Event title here`

### Syslog Forwarding

```yaml
alerts:
  syslog_forward: "siem.example.com:514"
```

Forwards events as RFC 3164 syslog over UDP (facility: local0).

### Daily Digest

Available at `GET /api/digest` or via `mythctl digest`. Contains: health score, device counts, new/offline devices, critical and warning events. Automatically emailed when SMTP is configured.

### Scheduled AI Reports

```yaml
alerts:
  report_schedule: "24h"    # Generate an AI report every 24 hours
```

Requires both AI and SMTP to be configured. Reports are stored as events and emailed.

---

## AI Integration

MythNet integrates with the Claude API for intelligent network analysis.

### Configuration

```yaml
ai:
  enabled: true
  api_key: ""                         # Or set ANTHROPIC_API_KEY env var
  model: "claude-sonnet-4-20250514"
```

### Features

| Feature | Trigger | Description |
|---------|---------|-------------|
| Interactive chat | WebSocket at `/api/chat` | Conversational AI with live network context |
| Auto-analysis | After each scan cycle | Device classification, security findings, threat assessment |
| Threat hunting | Every 5 minutes (War Room) | Analyzes sniffer data, DNS queries, traffic patterns |
| On-demand reports | `POST /api/reports` | Structured health and security report |
| Scheduled reports | `alerts.report_schedule` | Periodic reports emailed to admins |
| Device adapters | On new device discovery | Identifies HTTP APIs on unknown devices |

The AI receives full network context each request: device inventory, open ports, recent events, security findings.

---

## Network Policies

Define expected network state. Violations generate events after each scan.

### Creating Policies

`POST /api/policies` with JSON:

```json
{
  "name": "Servers must have SSH",
  "description": "All servers should be reachable via SSH",
  "severity": "warning",
  "match_type": "server",
  "require_port": 22,
  "enabled": true
}
```

### Policy Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Policy name |
| `description` | string | Human-readable description |
| `severity` | string | `"critical"` or `"warning"` |
| `match_tag` | string | Apply only to devices with this tag |
| `match_type` | string | Apply only to devices of this type |
| `require_port` | int | Port that must be open |
| `forbid_port` | int | Port that must NOT be open |
| `require_online` | bool | Device must be online |
| `enabled` | bool | Whether the policy is active |

### Examples

```bash
# No telnet anywhere
curl -u admin:password -X POST http://localhost:8080/api/policies \
  -H "Content-Type: application/json" \
  -d '{"name":"No telnet","severity":"critical","forbid_port":23,"enabled":true}'

# IoT devices must be online
curl -u admin:password -X POST http://localhost:8080/api/policies \
  -H "Content-Type: application/json" \
  -d '{"name":"IoT online","severity":"warning","match_type":"iot","require_online":true,"enabled":true}'
```

Violations are deduped — the same violation is not re-reported within 1 hour.

---

## Database

### Engine

SQLite (pure Go, no CGO) with WAL journaling, 5-second busy timeout, foreign keys enabled.

### Location

- Default: `mythnet.db` in working directory
- Systemd: `/var/lib/mythnet/mythnet.db`
- Docker: `/data/mythnet.db`
- Configurable: `database.path`

### Backup

```bash
# Via API
curl -u admin:password http://localhost:8080/api/backup -o mythnet-backup.db

# Via file copy (safe with WAL mode)
sqlite3 mythnet.db ".backup backup.db"
```

### Data Retention

| Data | Retention | Pruning |
|------|-----------|---------|
| Events | 7 days | Hourly |
| Snapshots | 48 hours | Hourly |
| Latency history | 48 hours | Hourly |
| Oplog (mesh) | 48 hours | Hourly |
| Devices | Permanent | — |
| Audit log | Permanent | — |

### Migration

Tables are auto-created on startup (`CREATE TABLE IF NOT EXISTS`). No manual migration steps are needed.

---

## Monitoring and Observability

### Prometheus Metrics

Endpoint: `GET /metrics` (no authentication required)

| Metric | Type | Description |
|--------|------|-------------|
| `mythnet_devices_total` | gauge | Total discovered devices |
| `mythnet_devices_online` | gauge | Currently online devices |
| `mythnet_ports_open` | gauge | Total open ports |
| `mythnet_scans_total` | counter | Completed scan cycles |
| `mythnet_events_total` | counter | Total events generated |
| `mythnet_events_critical` | gauge | Critical + warning events |
| `mythnet_mesh_peers` | gauge | Connected mesh peers |
| `mythnet_latency_avg_ms` | gauge | Average device latency |
| `mythnet_scanner_running` | gauge | 1 if scan in progress |
| `mythnet_uptime_seconds` | counter | Process uptime |

A Grafana dashboard template is included at `extras/grafana-dashboard.json`.

### Health Endpoint

`GET /api/health` (no auth) returns:

```json
{
  "status": "ok",
  "version": "v4.1.0",
  "scanning": false,
  "health_score": 85,
  "health_grade": "B",
  "factors": {
    "availability": 28,
    "security": 22,
    "vulnerabilities": 20,
    "stability": 15
  },
  "issues": ["2 devices offline", "3 weak TLS ciphers detected"]
}
```

Health score (0–100) is computed from: availability (30 pts), security (25 pts), vulnerabilities (25 pts), stability (20 pts).

### Public Status Page

`GET /status` (no auth) — standalone HTML page with health score, grade, device/event counts, and uptime. Suitable for linking from status dashboards.

### JSON Logging

```bash
mythnet --log-format json
```

Structured JSON output for log aggregators (Loki, Elasticsearch, etc.). HTTP requests are logged with method, path, status, bytes, duration, and client IP.

### Profiling

`GET /debug/pprof/*` exposes Go's built-in profiler. Disable or restrict access in production.

---

## Firewall Requirements

### Inbound

| Port | Protocol | Feature | Required |
|------|----------|---------|----------|
| 8080 | TCP | Web UI + API | Always |
| 1162 | UDP | SNMP trap listener | If SNMP enabled |
| 1514 | UDP | Syslog listener | If syslog enabled |
| 7946 | TCP + UDP | Mesh gossip | If mesh enabled |
| 7947 | TCP | Mesh replication | If mesh enabled |

**Honeypot ports** (War Room feature, inbound detection only): 2222, 8888, 3380, 1080, 9200, 4444, 5555, 6667, 8291, 10000, 27017, 11211.

### Outbound

| Destination | Protocol | Purpose |
|-------------|----------|---------|
| Scanned subnets | ICMP + TCP | Host discovery and port scanning |
| Scanned subnets | UDP/161 | SNMP active polling |
| `api.anthropic.com` | HTTPS | AI features |
| `api.github.com` | HTTPS | Self-update |
| SMTP server | TCP | Email alerts |
| Syslog target | UDP | Syslog forwarding |
| Webhook URLs | HTTPS | Alert delivery |

---

## Systemd Deployment

The included service file (`mythnet.service`) runs MythNet with security hardening:

```ini
[Service]
User=mythnet
Group=mythnet
WorkingDirectory=/var/lib/mythnet
AmbientCapabilities=CAP_NET_RAW CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/mythnet
PrivateTmp=yes
Restart=always
RestartSec=5
```

- `CAP_NET_RAW` — allows ICMP ping for host discovery
- `CAP_NET_BIND_SERVICE` — allows binding to privileged ports (162, 514)
- `ProtectSystem=strict` — read-only filesystem except `/var/lib/mythnet`
- `ProtectHome=yes` — no access to home directories

### Managing the Service

```bash
sudo systemctl start mythnet
sudo systemctl stop mythnet
sudo systemctl restart mythnet
sudo systemctl status mythnet
sudo journalctl -u mythnet -f     # Follow logs
```

---

## Docker Deployment

```yaml
# docker-compose.yml
services:
  mythnet:
    build: .
    network_mode: host           # Required for subnet scanning
    volumes:
      - mythnet-data:/data
    restart: unless-stopped

volumes:
  mythnet-data:
```

Exposed ports: 8080, 1162/udp, 1514/udp, 7946, 7947.

> **Note:** `network_mode: host` gives the container full access to the host network stack. This is required for ARP scanning and raw socket operations. If this is unacceptable, run the binary directly instead.

---

## Maintenance

### Updating

```bash
# Self-update (downloads latest GitHub release)
mythnet --update

# Or manually
wget https://github.com/EnochSojourn/mythnet/releases/latest/download/mythnet-linux-amd64
chmod +x mythnet-linux-amd64
sudo mv mythnet-linux-amd64 /usr/local/bin/mythnet
sudo systemctl restart mythnet
```

### Backup

```bash
# API backup
curl -u admin:password http://localhost:8080/api/backup -o mythnet-backup-$(date +%F).db

# Automate with cron
0 2 * * * curl -su admin:password http://localhost:8080/api/backup -o /backups/mythnet-$(date +\%F).db
```

### Config Reload

MythNet watches the config file and reloads on changes (polled every 10 seconds). You can also send SIGHUP:

```bash
sudo systemctl reload mythnet
# or
kill -HUP $(pidof mythnet)
```

Hot-reloaded settings: `scanner.subnets`, `scanner.interval`.

### Uninstall

```bash
sudo make uninstall
# Removes binary and systemd service
# Config (/etc/mythnet) and data (/var/lib/mythnet) are preserved
```

---

## Troubleshooting

### Cannot access web UI

- Verify MythNet is running: `systemctl status mythnet`
- Check the port: `ss -tlnp | grep 8080`
- Check firewall: `sudo ufw status` or `sudo iptables -L`
- Check logs: `journalctl -u mythnet --no-pager -n 50`

### Password lost

The auto-generated password is stored in `{data_dir}/password`:

```bash
cat /var/lib/mythnet/mythnet-data/password    # systemd install
cat ./mythnet-data/password                    # local run
```

Or set a new one via config or environment variable.

### No devices discovered

- Check that subnets are correct: `mythnet --check-config`
- If subnets are empty, MythNet auto-detects — verify network interfaces are up
- ICMP ping requires `CAP_NET_RAW` — run as root or use the systemd service
- Docker requires `network_mode: host`

### SNMP traps not received

- Verify the listener is running: check logs for `SNMP trap listener started on :1162`
- Test with: `snmptrap -v2c -c public mythnet-ip:1162 "" .1.3.6.1.6.3.1.1.5.3`
- Check that the sending device's community string matches config

### Mesh nodes not connecting

- All nodes must use the same `mesh.secret`
- Verify ports 7946 and 7947 are open between nodes
- Check gossip connectivity: `curl -u admin:password http://localhost:8080/api/health`
- Check mesh status in logs: look for `joined cluster` or connection errors

### High CPU or memory

- Check scan concurrency settings — reduce `max_concurrent_hosts` and `max_concurrent_ports`
- Check if the packet sniffer is running (War Room feature) — this captures all network traffic
- Use profiling: `go tool pprof http://localhost:8080/debug/pprof/heap`

### AI features not working

- Verify API key: `echo $ANTHROPIC_API_KEY`
- Check connectivity to `api.anthropic.com`
- Check logs for AI-related errors
- AI features degrade gracefully — the rest of MythNet works without AI
