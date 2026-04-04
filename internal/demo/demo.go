package demo

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/mythnet/mythnet/internal/db"
)

type fakeDevice struct {
	IP, MAC, Hostname, Vendor, OS, Type string
	Online                              bool
	Ports                               []fakePort
}

type fakePort struct {
	Port    int
	Service string
	Banner  string
}

var devices = []fakeDevice{
	// Core infrastructure
	{"10.0.1.1", "00:00:0C:AA:01:01", "gw-core-01", "Cisco", "Cisco IOS 15.7", "Network Equipment", true,
		[]fakePort{{22, "ssh", "SSH-2.0-Cisco-1.25"}, {80, "http", "HTTP/1.1 200 OK\r\nServer: cisco-IOS"}, {443, "https", ""}}},
	{"10.0.1.2", "00:00:0C:AA:01:02", "sw-dist-01", "Cisco", "Cisco IOS 15.2", "Network Equipment", true,
		[]fakePort{{22, "ssh", "SSH-2.0-Cisco-1.25"}, {80, "http", ""}}},
	{"10.0.1.3", "00:00:0C:AA:01:03", "sw-access-01", "Cisco", "Cisco IOS 12.2", "Network Equipment", true,
		[]fakePort{{22, "ssh", "SSH-2.0-OpenSSH_6.6"}, {23, "telnet", "login:"}}},
	{"10.0.1.4", "00:09:0F:BB:02:10", "fw-edge-01", "Fortinet", "Fortinet FortiOS 7.2", "Firewall", true,
		[]fakePort{{443, "https", ""}, {22, "ssh", "SSH-2.0-OpenSSH_8.4"}}},
	{"10.0.1.5", "00:0B:86:CC:03:20", "ap-lobby-01", "Aruba", "ArubaOS 8.10", "Network Equipment", true,
		[]fakePort{{443, "https", ""}, {22, "ssh", ""}}},

	// Servers
	{"10.0.10.10", "00:50:56:A1:10:10", "web-prod-01", "VMware", "Linux (Ubuntu)", "Server", true,
		[]fakePort{{22, "ssh", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"}, {80, "http", "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"}, {443, "https", ""}, {3306, "mysql", "5.7.42-log"}}},
	{"10.0.10.11", "00:50:56:A1:10:11", "web-prod-02", "VMware", "Linux (Ubuntu)", "Server", true,
		[]fakePort{{22, "ssh", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"}, {80, "http", "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"}, {443, "https", ""}}},
	{"10.0.10.12", "00:50:56:A1:10:12", "db-prod-01", "VMware", "Linux (Debian)", "Server", true,
		[]fakePort{{22, "ssh", "SSH-2.0-OpenSSH_9.2p1 Debian-2"}, {5432, "postgresql", ""}, {9090, "prometheus", ""}}},
	{"10.0.10.13", "00:50:56:A1:10:13", "mail-01", "VMware", "Linux (CentOS)", "Server", true,
		[]fakePort{{22, "ssh", "SSH-2.0-OpenSSH_8.0"}, {25, "smtp", "220 mail.example.com ESMTP Postfix"}, {143, "imap", ""}, {993, "imaps", ""}}},
	{"10.0.10.14", "00:50:56:A1:10:14", "monitor-01", "VMware", "Linux (Ubuntu)", "Server", true,
		[]fakePort{{22, "ssh", "SSH-2.0-OpenSSH_9.6p1"}, {3000, "http", "HTTP/1.1 200\r\nServer: Grafana"}, {9090, "prometheus", ""}, {8080, "http-proxy", ""}}},
	{"10.0.10.20", "00:50:56:A1:10:20", "backup-01", "VMware", "Linux (Debian)", "Server", false,
		[]fakePort{{22, "ssh", "SSH-2.0-OpenSSH_8.4p1"}}},
	{"10.0.10.21", "00:50:56:A1:10:21", "dev-staging", "VMware", "Linux (Ubuntu)", "Server", true,
		[]fakePort{{22, "ssh", "SSH-2.0-OpenSSH_8.5p1"}, {80, "http", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49"}, {6379, "redis", "Redis server v=5.0.7"}}},

	// Workstations
	{"10.0.20.100", "04:D4:C4:DD:20:01", "ws-alice", "ASUS", "Windows", "Endpoint", true,
		[]fakePort{{135, "msrpc", ""}, {139, "netbios-ssn", ""}, {445, "microsoft-ds", ""}, {3389, "rdp", ""}}},
	{"10.0.20.101", "04:F1:3E:DD:20:02", "ws-bob-mbp", "Apple", "macOS", "Endpoint", true,
		[]fakePort{{22, "ssh", "SSH-2.0-OpenSSH_9.4"}, {5900, "vnc", ""}}},
	{"10.0.20.102", "54:EE:75:DD:20:03", "ws-charlie", "Lenovo", "Linux (Fedora)", "Endpoint", true,
		[]fakePort{{22, "ssh", "SSH-2.0-OpenSSH_9.5"}}},
	{"10.0.20.103", "28:D2:44:DD:20:04", "ws-dana", "Lenovo", "Windows", "Endpoint", false,
		[]fakePort{{445, "microsoft-ds", ""}, {3389, "rdp", ""}}},

	// IoT & Cameras
	{"10.0.30.50", "B8:27:EB:EE:30:01", "pi-sensors", "Raspberry Pi", "Linux", "SBC", true,
		[]fakePort{{22, "ssh", "SSH-2.0-OpenSSH_9.2"}, {8080, "http-proxy", ""}}},
	{"10.0.30.51", "5C:CF:7F:EE:30:02", "iot-hvac-ctrl", "Espressif", "Linux", "IoT", true,
		[]fakePort{{80, "http", "HTTP/1.0 200 OK\r\nServer: ESP32-WebServer"}}},
	{"10.0.30.52", "00:17:88:EE:30:03", "hue-bridge", "Philips Hue", "", "IoT", true,
		[]fakePort{{80, "http", ""}, {443, "https", ""}}},
	{"10.0.30.53", "A4:77:33:EE:30:04", "nest-hub", "Google", "", "IoT", true,
		[]fakePort{{8008, "http", ""}, {8443, "https", ""}}},
	{"10.0.30.60", "A4:14:37:EE:30:10", "cam-lobby", "Hikvision", "", "IP Camera", true,
		[]fakePort{{80, "http", "HTTP/1.1 200\r\nServer: DNVRS-Webs"}, {554, "rtsp", ""}, {8000, "http", ""}}},
	{"10.0.30.61", "A4:14:37:EE:30:11", "cam-parking", "Hikvision", "", "IP Camera", true,
		[]fakePort{{80, "http", ""}, {554, "rtsp", ""}}},
	{"10.0.30.62", "3C:EF:8C:EE:30:12", "cam-warehouse", "Dahua", "", "IP Camera", false,
		[]fakePort{{80, "http", ""}}},

	// Printers & AV
	{"10.0.40.70", "3C:D9:2B:FF:40:01", "printer-lobby", "HP", "", "Printer", true,
		[]fakePort{{80, "http", "HTTP/1.1 200\r\nServer: HP HTTP Server"}, {631, "ipp", ""}, {9100, "jetdirect", ""}}},
	{"10.0.40.71", "00:05:A6:FF:40:02", "extron-conf-rm", "Extron", "", "AV Equipment", true,
		[]fakePort{{80, "http", ""}, {23, "telnet", "Extron Electronics"}}},

	// NAS
	{"10.0.10.30", "00:11:32:FF:50:01", "nas-primary", "Synology", "Linux", "NAS", true,
		[]fakePort{{22, "ssh", ""}, {80, "http", ""}, {443, "https", ""}, {445, "microsoft-ds", ""}, {5000, "http", ""}}},
}

var sampleEvents = []struct {
	source, severity, title, body, tags string
	minutesAgo                          int
}{
	{"syslog", "critical", "kernel: iptables DROP IN=eth0 SRC=203.0.113.5 DST=10.0.1.4 PROTO=TCP DPT=22",
		"## Firewall Block\n\n**Source:** `fw-edge-01`\n\nExternal SSH brute force attempt blocked.", "syslog,security", 5},
	{"syslog", "warning", "sshd: Failed password for admin from 10.0.20.100 port 52341",
		"## SSH Auth Failure\n\n**Source:** `web-prod-01`\n\nFailed login attempt.", "syslog,auth", 12},
	{"port_change", "critical", "Port 23 opened on 10.0.1.3",
		"## Port Change\n\n**Device:** sw-access-01\n**Port:** 23/telnet\n\n> Telnet is insecure.", "port,opened,23", 30},
	{"vuln_scan", "critical", "CVE-2021-41773 — 10.0.10.21:80",
		"## Vulnerability\n\n**Device:** dev-staging\n**CVE:** CVE-2021-41773\n**Summary:** Apache 2.4.49 path traversal and RCE", "cve,apache", 45},
	{"vuln_scan", "critical", "CVE-2022-0543 — 10.0.10.21:6379",
		"## Vulnerability\n\n**Device:** dev-staging\n**CVE:** CVE-2022-0543\n**Summary:** Redis <6.2 Lua sandbox escape to RCE", "cve,redis", 45},
	{"http_audit", "warning", "Security audit — 10.0.10.10:80 (3 issues)",
		"## HTTP Security Audit\n\n| Header | Status |\n|---|---|\n| HSTS | MISSING |\n| CSP | MISSING |\n| X-Frame-Options | MISSING |", "audit,http", 60},
	{"syslog", "warning", "stp: Topology change detected on port GE1/0/24",
		"## STP Change\n\n**Source:** `sw-dist-01`\n\nSpanning tree topology change.", "syslog,stp", 90},
	{"api_poll", "info", "HTTP 200 — http://10.0.10.10:80/",
		"## API Poll\n\n**Server:** nginx/1.24.0", "api,http_200", 120},
	{"snmp_poll", "info", "SNMP System Info — 10.0.1.1",
		"## SNMP\n\n**sysName:** gw-core-01\n**sysDescr:** Cisco IOS 15.7\n**sysUpTime:** 142d 7h 23m", "snmp,sysinfo", 180},
	{"tls_check", "warning", "TLS cert on 10.0.10.10:443 — 21 days left",
		"## TLS Certificate\n\n**Subject:** *.example.com\n**Expires:** 2026-04-24\n**Days Left:** 21", "tls,cert", 200},
	{"ip_conflict", "critical", "IP conflict detected: 10.0.20.100 has 2 MAC addresses",
		"## IP Conflict\n\n**IP:** 10.0.20.100\n- 04:D4:C4:DD:20:01 (ASUS)\n- AA:BB:CC:DD:EE:FF\n\n> Possible ARP spoofing.", "security,arp", 240},
	{"policy", "warning", "Policy violation: No Telnet — 10.0.1.3",
		"## Policy Violation\n\n**Policy:** No Telnet\n**Device:** sw-access-01\n**Issue:** Forbidden port 23 is open", "policy,violation", 300},
}

// Populate fills the database with realistic demo data.
func Populate(store *db.Store) {
	now := time.Now()
	r := rand.New(rand.NewSource(42)) // Deterministic for consistent demo

	for _, d := range devices {
		firstSeen := now.Add(-time.Duration(r.Intn(30*24)+24) * time.Hour) // 1-30 days ago
		dev := &db.Device{
			ID:         fmt.Sprintf("%x", []byte(d.MAC)[:8]),
			IP:         d.IP,
			MAC:        d.MAC,
			Hostname:   d.Hostname,
			Vendor:     d.Vendor,
			OSGuess:    d.OS,
			DeviceType: d.Type,
			FirstSeen:  firstSeen,
			LastSeen:   now,
			IsOnline:   d.Online,
		}
		store.UpsertDevice(dev)
		store.RecordStateChange(dev.ID, boolState(d.Online))

		for _, p := range d.Ports {
			store.UpsertPort(&db.Port{
				DeviceID: dev.ID,
				Port:     p.Port,
				Protocol: "tcp",
				State:    "open",
				Service:  p.Service,
				Banner:   p.Banner,
				LastSeen: now,
			})
		}

		// Fake latency
		latency := 0.1 + r.Float64()*5.0 // 0.1 - 5.1 ms
		if !d.Online {
			latency = 0
		}
		store.RecordLatency(dev.ID, latency)
	}

	// Insert events
	for _, e := range sampleEvents {
		store.InsertEvent(&db.Event{
			Source:     e.source,
			Severity:   e.severity,
			Title:      e.title,
			BodyMD:     e.body,
			ReceivedAt: now.Add(-time.Duration(e.minutesAgo) * time.Minute),
			Tags:       e.tags,
		})
	}

	// Add some tags
	for _, d := range devices {
		id := fmt.Sprintf("%x", []byte(d.MAC)[:8])
		switch d.Type {
		case "Server":
			store.SetDeviceTags(id, []string{"production"})
		case "Network Equipment":
			store.SetDeviceTags(id, []string{"infrastructure"})
		case "IP Camera":
			store.SetDeviceTags(id, []string{"surveillance"})
		}
	}

	// Add a policy
	store.DB().Exec(`INSERT INTO policies (data) VALUES (?)`,
		`{"name":"No Telnet","description":"Telnet must not be open on any device","forbid_port":23,"severity":"warning","enabled":true}`)

	// Record snapshot for sparklines
	store.RecordSnapshot()
}

func boolState(online bool) string {
	if online {
		return "online"
	}
	return "offline"
}
