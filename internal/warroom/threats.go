package warroom

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mythnet/mythnet/internal/db"
)

// ThreatEngine analyzes packets in real time for security threats.
type ThreatEngine struct {
	store  *db.Store
	mu     sync.RWMutex

	// Bandwidth tracking: IP → bytes
	bytesIn  map[string]int64
	bytesOut map[string]int64

	// Protocol stats
	protocols map[string]int64

	// Port scan detection: srcIP → map[dstIP]→set of ports hit
	scanTracker map[string]map[string]map[int]time.Time

	// Recent alerts (dedup)
	recentAlerts map[string]time.Time
}

func NewThreatEngine(store *db.Store) *ThreatEngine {
	return &ThreatEngine{
		store:        store,
		bytesIn:      make(map[string]int64),
		bytesOut:     make(map[string]int64),
		protocols:    make(map[string]int64),
		scanTracker:  make(map[string]map[string]map[int]time.Time),
		recentAlerts: make(map[string]time.Time),
	}
}

// AnalyzePacket processes a single packet for threats.
func (te *ThreatEngine) AnalyzePacket(packet gopacket.Packet) {
	te.mu.Lock()
	defer te.mu.Unlock()

	size := int64(len(packet.Data()))

	// Extract IPs
	var srcIP, dstIP string
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
		te.bytesOut[srcIP] += size
		te.bytesIn[dstIP] += size
	}

	if srcIP == "" {
		return
	}

	// Check against threat intelligence feeds
	if source, found := CheckIP(dstIP); found {
		te.alert("threatfeed_ip_"+dstIP,
			fmt.Sprintf("THREAT INTEL: %s communicating with known malicious IP %s (%s)", srcIP, dstIP, source),
			"critical",
			fmt.Sprintf("## Known Malicious IP Detected\n\n**Source Device:** `%s`  \n**Malicious IP:** `%s`  \n**Intel Source:** %s  \n\n> This IP is listed in threat intelligence feeds as associated with malware, botnets, or criminal infrastructure. **Investigate the source device immediately.**", srcIP, dstIP, source),
			srcIP)
	}

	// Protocol tracking
	var srcPort, dstPort int
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		srcPort = int(tcp.SrcPort)
		dstPort = int(tcp.DstPort)
		te.protocols["tcp"] += size

		// Detect unencrypted HTTP
		if dstPort == 80 || srcPort == 80 {
			te.protocols["http"] += size
			te.checkUnencrypted(packet, srcIP, dstIP, dstPort)
		}
		if dstPort == 443 || srcPort == 443 {
			te.protocols["https"] += size
		}
		if dstPort == 22 || srcPort == 22 {
			te.protocols["ssh"] += size
		}

		// Detect telnet
		if dstPort == 23 || srcPort == 23 {
			te.protocols["telnet"] += size
			te.alert("cleartext_telnet",
				fmt.Sprintf("Telnet traffic detected: %s → %s:23", srcIP, dstIP),
				"critical",
				fmt.Sprintf("## Unencrypted Telnet\n\n**Source:** `%s`  \n**Destination:** `%s:23`  \n\n> Telnet transmits all data including passwords in cleartext. Replace with SSH.", srcIP, dstIP),
				srcIP)
		}

		// Detect FTP
		if dstPort == 21 || srcPort == 21 {
			te.protocols["ftp"] += size
			te.alert("cleartext_ftp",
				fmt.Sprintf("FTP traffic detected: %s → %s:21", srcIP, dstIP),
				"warning",
				fmt.Sprintf("## Unencrypted FTP\n\n**Source:** `%s`  \n**Destination:** `%s:21`  \n\n> FTP transmits credentials in cleartext. Use SFTP instead.", srcIP, dstIP),
				srcIP)
		}

		// Port scan detection: track SYN packets
		if tcp.SYN && !tcp.ACK {
			te.trackScan(srcIP, dstIP, dstPort)
		}

	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		dstPort = int(udp.DstPort)
		te.protocols["udp"] += size

		if dstPort == 53 || int(udp.SrcPort) == 53 {
			te.protocols["dns"] += size
		}
	}

	// Check for DNS to suspicious domains
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns := dnsLayer.(*layers.DNS)
		if !dns.QR { // Query
			for _, q := range dns.Questions {
				te.checkSuspiciousDNS(srcIP, string(q.Name))
			}
		}
	}
}

func (te *ThreatEngine) checkUnencrypted(packet gopacket.Packet, srcIP, dstIP string, port int) {
	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return
	}
	payload := string(appLayer.Payload())

	// Check for credential patterns in HTTP traffic
	lower := strings.ToLower(payload)
	if strings.Contains(lower, "authorization: basic") ||
		strings.Contains(lower, "password=") ||
		strings.Contains(lower, "passwd=") ||
		strings.Contains(lower, "login=") {
		te.alert("cleartext_creds",
			fmt.Sprintf("Cleartext credentials detected: %s → %s:%d", srcIP, dstIP, port),
			"critical",
			fmt.Sprintf("## Cleartext Credentials Detected!\n\n**Source:** `%s`  \n**Destination:** `%s:%d`  \n**Protocol:** HTTP (unencrypted)  \n\n> Passwords or authentication tokens are being transmitted in cleartext over HTTP. This traffic can be intercepted by anyone on the network.\n\n**Action:** Switch to HTTPS immediately.", srcIP, dstIP, port),
			srcIP)
	}
}

func (te *ThreatEngine) trackScan(srcIP, dstIP string, port int) {
	now := time.Now()

	if te.scanTracker[srcIP] == nil {
		te.scanTracker[srcIP] = make(map[string]map[int]time.Time)
	}
	if te.scanTracker[srcIP][dstIP] == nil {
		te.scanTracker[srcIP][dstIP] = make(map[int]time.Time)
	}

	te.scanTracker[srcIP][dstIP][port] = now

	// Clean old entries (>60 seconds)
	for p, t := range te.scanTracker[srcIP][dstIP] {
		if now.Sub(t) > 60*time.Second {
			delete(te.scanTracker[srcIP][dstIP], p)
		}
	}

	// Alert if >10 unique ports in 60 seconds
	if len(te.scanTracker[srcIP][dstIP]) >= 10 {
		te.alert("port_scan_"+srcIP+"_"+dstIP,
			fmt.Sprintf("Port scan detected: %s scanning %s (%d ports)", srcIP, dstIP, len(te.scanTracker[srcIP][dstIP])),
			"critical",
			fmt.Sprintf("## Port Scan Detected\n\n**Scanner:** `%s`  \n**Target:** `%s`  \n**Ports probed:** %d in 60 seconds  \n\n> This is characteristic of network reconnaissance. The source device may be compromised or running unauthorized scanning software.",
				srcIP, dstIP, len(te.scanTracker[srcIP][dstIP])),
			srcIP)
		// Reset to avoid flooding
		te.scanTracker[srcIP][dstIP] = make(map[int]time.Time)
	}
}

// Known suspicious domain patterns
var suspiciousDomains = []string{
	".onion.", "torproject.org",
	"coinhive.com", "coin-hive.com", "minero.cc", "crypto-loot.com",
	".top", ".xyz", ".tk", ".ml", ".ga", ".cf", // Common malware TLDs
}

// DGA detection: domain has high entropy (random-looking)
func isDGA(domain string) bool {
	if len(domain) < 15 {
		return false
	}
	consonants := 0
	for _, c := range strings.ToLower(domain) {
		if c != 'a' && c != 'e' && c != 'i' && c != 'o' && c != 'u' && c >= 'a' && c <= 'z' {
			consonants++
		}
	}
	// If >75% consonants in a long domain, likely DGA
	ratio := float64(consonants) / float64(len(domain))
	return ratio > 0.75
}

func (te *ThreatEngine) checkSuspiciousDNS(srcIP, domain string) {
	lower := strings.ToLower(domain)

	// Check against live threat feeds first
	if source, found := CheckDomain(lower); found {
		te.alert("threatfeed_dns_"+domain,
			fmt.Sprintf("THREAT INTEL: %s queried known malicious domain %s (%s)", srcIP, domain, source),
			"critical",
			fmt.Sprintf("## Known Malicious Domain\n\n**Device:** `%s`  \n**Domain:** `%s`  \n**Intel Source:** %s  \n\n> This domain is listed in threat intelligence feeds. The device may be compromised.", srcIP, domain, source),
			srcIP)
		return
	}

	for _, sus := range suspiciousDomains {
		if strings.Contains(lower, sus) {
			te.alert("suspicious_dns_"+domain,
				fmt.Sprintf("Suspicious DNS query from %s: %s", srcIP, domain),
				"warning",
				fmt.Sprintf("## Suspicious DNS Query\n\n**Device:** `%s`  \n**Domain:** `%s`  \n**Matched pattern:** `%s`  \n\n> This domain matches a pattern associated with malware, crypto mining, or suspicious activity.",
					srcIP, domain, sus),
				srcIP)
			return
		}
	}

	// DGA check
	parts := strings.Split(lower, ".")
	if len(parts) >= 2 && isDGA(parts[0]) {
		te.alert("dga_dns_"+domain,
			fmt.Sprintf("Possible DGA domain from %s: %s", srcIP, domain),
			"warning",
			fmt.Sprintf("## Possible Domain Generation Algorithm\n\n**Device:** `%s`  \n**Domain:** `%s`  \n\n> This domain appears randomly generated, which is a common technique used by malware to communicate with command-and-control servers.",
				srcIP, domain),
			srcIP)
	}
}

func (te *ThreatEngine) alert(key, title, severity, body, deviceIP string) {
	// Dedup: don't fire same alert within 5 minutes
	if t, ok := te.recentAlerts[key]; ok && time.Since(t) < 5*time.Minute {
		return
	}
	te.recentAlerts[key] = time.Now()

	// Find device ID
	deviceID := ""
	devices, _ := te.store.ListDevices()
	for _, d := range devices {
		if d.IP == deviceIP {
			deviceID = d.ID
			break
		}
	}

	te.store.InsertEvent(&db.Event{
		DeviceID:   deviceID,
		Source:     "threat_detect",
		Severity:   severity,
		Title:      title,
		BodyMD:     body,
		ReceivedAt: time.Now(),
		Tags:       "threat,realtime,sniffer",
	})
}

// --- Stats API ---

// GetBandwidth returns bytes per IP.
func (te *ThreatEngine) GetBandwidth() map[string]map[string]int64 {
	te.mu.RLock()
	defer te.mu.RUnlock()
	result := make(map[string]map[string]int64)
	for ip, bytes := range te.bytesOut {
		if result[ip] == nil {
			result[ip] = make(map[string]int64)
		}
		result[ip]["out"] = bytes
	}
	for ip, bytes := range te.bytesIn {
		if result[ip] == nil {
			result[ip] = make(map[string]int64)
		}
		result[ip]["in"] = bytes
	}
	return result
}

// GetProtocols returns protocol breakdown by bytes.
func (te *ThreatEngine) GetProtocols() map[string]int64 {
	te.mu.RLock()
	defer te.mu.RUnlock()
	out := make(map[string]int64)
	for k, v := range te.protocols {
		out[k] = v
	}
	return out
}

// Global threat engine for API access
var GlobalThreatEngine *ThreatEngine

func InitThreatEngine(store *db.Store) *ThreatEngine {
	te := NewThreatEngine(store)
	GlobalThreatEngine = te
	return te
}
