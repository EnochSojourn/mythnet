# Changelog

## v2.5.0

- **Self-update**: `mythnet --update` and `mythctl update` check GitHub releases and replace the running binary
- **SNMP walk tool**: query any OID tree on a device via API or mythctl
- **Syslog forwarding**: forward alert events as RFC 3164 syslog to external SIEM servers

## v2.4.0

- **Public status page**: styled HTML health dashboard at `/status` (no auth)
- **HTTP request logging**: structured logs for every API request with method, status, duration
- **Config validation**: `mythnet --check-config` validates and prints config summary
- **mythctl test**: connectivity checker for remote MythNet instances
- **mythctl config**: prints complete config template to stdout

## v2.3.0

- **mythctl CLI client**: standalone 6MB binary for managing MythNet from any terminal
- 13 commands: health, devices, events, scan, sla, digest, test, config, update, tools
- Colored output with tabwriter formatting
- **59 tests** (up from 42): CVE scanner, health score, integration tests

## v2.2.0

- **Daily digest**: automated 24h summary (new devices, offline, alerts, health score)
- **SLA uptime reporting**: 24h/7d/30d uptime percentages per device
- **Network documentation**: auto-generated Markdown inventory at `/api/docs/network`
- **Custom event rules**: pattern-match and re-classify events

## v2.1.0

- **One-shot CLI scan**: `mythnet --scan CIDR` with table or JSON output
- **CSV device import**: upload inventory via `POST /api/devices/import`
- **Webhook HMAC signatures**: `X-MythNet-Signature` header for verification
- **pprof profiling**: `/debug/pprof/*` for production debugging

## v2.0.0

- **HTTP security header audit**: automatic HSTS, CSP, X-Frame-Options checks
- **TLS cipher audit**: flags deprecated versions and weak ciphers
- **Device timeline**: unified chronological view of all events per device
- **WHOIS lookup**: IP ownership lookup in network tools

## v1.9.0

- **Integration tests**: 12 tests covering full HTTP API flow
- **Benchmarks**: 6 benchmarks (device upsert: 87µs, event insert: 53µs)
- **JSON structured logging**: `--log-format=json` flag
- **GitHub Release**: first release with pre-built binaries for 6 platforms

## v1.8.0

- **Network tools panel**: browser-based ping, DNS, port check, subnet calculator
- **Network policy engine**: define expected state rules, alert on violations
- **Grafana dashboard template**: 10-panel dashboard for Prometheus metrics
- **Bash completion script**

## v1.7.0

- **SMTP email alerts**: configurable host/port/auth/recipients
- **Scheduled AI reports**: generate reports on a cron interval
- **Subnet calculator**: `GET /api/subnet?cidr=...`
- **Traceroute**: network path mapping

## v1.6.0

- **Network health score**: 0-100 score from availability, security, stability, vulns
- **Scan diff**: changes in the last hour (new/offline devices, port changes)
- **OpenAPI 3.0 docs**: 23+ endpoints documented at `/api/docs`
- **ASCII startup banner**: colored feature summary on boot

## v1.5.0

- **CVE vulnerability scanner**: 18 rules matching service banners
- **Audit log**: tracks user actions (scans, note edits, tag changes)
- **API rate limiting**: 300 req/min per IP with token bucket
- **Config hot-reload**: file watching + SIGHUP

## v1.4.0

- **Prometheus metrics**: `/metrics` endpoint with device, event, latency gauges
- **mDNS/Bonjour discovery**: finds printers, AirPlay, Chromecast, HomeKit
- **SVG topology export**: standalone network diagram at `/topology.svg`
- **IP conflict detection**: multiple MACs per IP alert

## v1.3.0

- **30 unit tests** across config, db, scanner, telemetry packages
- **Docker**: multi-stage Dockerfile, docker-compose
- **CI/CD workflows**: GitHub Actions for test and release (requires workflow token scope)

## v1.2.0

- **Command palette**: Ctrl+K universal search for devices and actions
- **Animated topology**: flowing dashes on links, breathing glow on nodes
- **Database backup**: `GET /api/backup`
- **Responsive layout**: overlay panels on small screens

## v1.1.0

- **Login page**: styled SPA login replacing browser Basic Auth popup
- **TLS certificate monitoring**: warns on certs expiring within 30 days
- **Device tagging**: user-defined tags per device
- **Settings API**: view current configuration

## v1.0.0

- **Sparkline charts**: 24h trend lines in stats dashboard
- **Wake-on-LAN**: send magic packets to offline devices
- **SVG device icons**: replace text abbreviations in topology map
- **Full-text event search**: search titles, bodies, and tags

## v0.9.0 (port change detection)

- Port change detection with dangerous port flagging
- Device notes (user-editable per device)
- Notification bell with unread count
- Ping latency tracking and history

## v0.8.0 (uptime + SNMP polling)

- Device uptime history and percentage tracking
- SNMP active polling for device enrichment
- Device search/filter in sidebar
- CSV export of device inventory

## v0.7.0 (systemd + alerts)

- Systemd service with security hardening
- Webhook alert manager (Slack, Discord, generic)
- LLM-assisted device adapter generation

## v0.6.0 (auth + WebSocket)

- Password authentication with auto-generation
- Auto-TLS with self-signed certificates
- WebSocket broadcast for real-time UI push
- README

## v0.5.0 (initial release)

Five-phase build:
1. Go binary, subnet scanner, SQLite, device fingerprinting
2. SvelteKit SPA, D3.js topology map, Tailwind dark theme
3. SNMP traps, syslog, HTTP polling, Markdown translation
4. HashiCorp memberlist gossip, mTLS replication, Full/Sensor nodes
5. Claude API chat, AI reports, reverse proxy
