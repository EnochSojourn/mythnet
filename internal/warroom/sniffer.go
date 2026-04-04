package warroom

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/mythnet/mythnet/internal/db"
)

// Sniffer captures live network packets and extracts intelligence.
type Sniffer struct {
	store   *db.Store
	logger  *slog.Logger
	iface   string
	mu      sync.RWMutex
	stats   SnifferStats
	dnsLog  []DNSQuery
}

// SnifferStats tracks packet capture statistics.
type SnifferStats struct {
	PacketsCaptured int64  `json:"packets_captured"`
	BytesCaptured   int64  `json:"bytes_captured"`
	DNSQueries      int64  `json:"dns_queries"`
	StartedAt       string `json:"started_at"`
	Interface       string `json:"interface"`
	Running         bool   `json:"running"`
}

// DNSQuery is a captured DNS query.
type DNSQuery struct {
	Time       string `json:"time"`
	SrcIP      string `json:"src_ip"`
	DstIP      string `json:"dst_ip"`
	Query      string `json:"query"`
	QueryType  string `json:"type"`
	ResponseIP string `json:"response_ip,omitempty"`
}

// NewSniffer creates a packet sniffer on the specified interface.
func NewSniffer(store *db.Store, logger *slog.Logger, iface string) *Sniffer {
	if iface == "" {
		iface = detectInterface()
	}
	return &Sniffer{
		store:  store,
		logger: logger,
		iface:  iface,
	}
}

// Run starts packet capture. Requires CAP_NET_RAW or root.
func (s *Sniffer) Run(ctx context.Context) {
	s.mu.Lock()
	s.stats.Interface = s.iface
	s.stats.StartedAt = time.Now().Format(time.RFC3339)
	s.mu.Unlock()

	handle, err := afpacket.NewTPacket(
		afpacket.OptInterface(s.iface),
		afpacket.OptFrameSize(65536),
		afpacket.OptBlockSize(65536*128),
		afpacket.OptNumBlocks(8),
	)
	if err != nil {
		s.logger.Error("sniffer: cannot open interface (need CAP_NET_RAW)", "iface", s.iface, "error", err)
		s.logger.Info("sniffer: run 'sudo setcap cap_net_raw+ep mythnet' to enable")
		return
	}
	defer handle.Close()

	s.mu.Lock()
	s.stats.Running = true
	s.mu.Unlock()

	s.logger.Info("packet sniffer started", "interface", s.iface)

	source := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	source.NoCopy = true

	for {
		select {
		case <-ctx.Done():
			s.mu.Lock()
			s.stats.Running = false
			s.mu.Unlock()
			return
		default:
		}

		packet, err := source.NextPacket()
		if err != nil {
			continue
		}

		s.mu.Lock()
		s.stats.PacketsCaptured++
		s.stats.BytesCaptured += int64(len(packet.Data()))
		s.mu.Unlock()

		s.processPacket(packet)
	}
}

func (s *Sniffer) processPacket(packet gopacket.Packet) {
	// Extract DNS queries
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer != nil {
		dns := dnsLayer.(*layers.DNS)
		s.processDNS(packet, dns)
	}
}

func (s *Sniffer) processDNS(packet gopacket.Packet, dns *layers.DNS) {
	var srcIP, dstIP string
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	}

	now := time.Now().Format(time.RFC3339)

	// Process queries
	for _, q := range dns.Questions {
		qname := string(q.Name)
		qtype := q.Type.String()

		query := DNSQuery{
			Time: now, SrcIP: srcIP, DstIP: dstIP,
			Query: qname, QueryType: qtype,
		}

		// Get response IPs
		if !dns.QR { // This is a query, not a response
			s.mu.Lock()
			s.stats.DNSQueries++
			s.dnsLog = append(s.dnsLog, query)
			// Keep last 1000 queries
			if len(s.dnsLog) > 1000 {
				s.dnsLog = s.dnsLog[len(s.dnsLog)-1000:]
			}
			s.mu.Unlock()
		}
	}

	// Process answers (responses)
	if dns.QR && len(dns.Questions) > 0 {
		qname := string(dns.Questions[0].Name)
		for _, a := range dns.Answers {
			if a.IP != nil {
				query := DNSQuery{
					Time: now, SrcIP: dstIP, DstIP: srcIP,
					Query: qname, QueryType: "response",
					ResponseIP: a.IP.String(),
				}
				s.mu.Lock()
				s.dnsLog = append(s.dnsLog, query)
				if len(s.dnsLog) > 1000 {
					s.dnsLog = s.dnsLog[len(s.dnsLog)-1000:]
				}
				s.mu.Unlock()
			}
		}
	}
}

// GetStats returns current sniffer statistics.
func (s *Sniffer) GetStats() SnifferStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stats
}

// GetDNSLog returns recent DNS queries.
func (s *Sniffer) GetDNSLog() []DNSQuery {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]DNSQuery, len(s.dnsLog))
	copy(out, s.dnsLog)
	// Reverse (newest first)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// GetDNSTopDomains returns most queried domains.
func (s *Sniffer) GetDNSTopDomains() []map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()

	counts := make(map[string]int)
	sources := make(map[string]map[string]bool)

	for _, q := range s.dnsLog {
		if q.QueryType == "response" {
			continue
		}
		domain := baseDomain(q.Query)
		counts[domain]++
		if sources[domain] == nil {
			sources[domain] = make(map[string]bool)
		}
		sources[domain][q.SrcIP] = true
	}

	var result []map[string]any
	for domain, count := range counts {
		result = append(result, map[string]any{
			"domain":  domain,
			"queries": count,
			"sources": len(sources[domain]),
		})
	}

	// Sort by query count
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j]["queries"].(int) > result[i]["queries"].(int) {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	if len(result) > 50 {
		result = result[:50]
	}
	return result
}

func detectInterface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "eth0"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if strings.HasPrefix(iface.Name, "wl") || strings.HasPrefix(iface.Name, "en") || strings.HasPrefix(iface.Name, "eth") {
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil && !ipNet.IP.IsLoopback() {
					return iface.Name
				}
			}
		}
	}
	return "eth0"
}

// Global sniffer instance for API access
var GlobalSniffer *Sniffer

func InitSniffer(store *db.Store, logger *slog.Logger, iface string) *Sniffer {
	s := NewSniffer(store, logger, iface)
	GlobalSniffer = s
	return s
}

func GetSnifferStats() SnifferStats {
	if GlobalSniffer == nil {
		return SnifferStats{}
	}
	return GlobalSniffer.GetStats()
}

func GetSnifferDNSLog() []DNSQuery {
	if GlobalSniffer == nil {
		return nil
	}
	return GlobalSniffer.GetDNSLog()
}

func GetSnifferDNSTopDomains() []map[string]any {
	if GlobalSniffer == nil {
		return nil
	}
	return GlobalSniffer.GetDNSTopDomains()
}

// FormatSnifferStatus returns a human-readable status string.
func FormatSnifferStatus() string {
	stats := GetSnifferStats()
	if !stats.Running {
		return "Sniffer not running. Run: sudo setcap cap_net_raw+ep mythnet"
	}
	return fmt.Sprintf("Capturing on %s: %d packets, %d DNS queries",
		stats.Interface, stats.PacketsCaptured, stats.DNSQueries)
}
