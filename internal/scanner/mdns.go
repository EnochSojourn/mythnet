package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/mythnet/mythnet/internal/db"
)

// Common mDNS service types to query
var mdnsServices = []string{
	"_http._tcp",
	"_https._tcp",
	"_ssh._tcp",
	"_printer._tcp",
	"_ipp._tcp",
	"_airplay._tcp",
	"_raop._tcp",
	"_smb._tcp",
	"_googlecast._tcp",
	"_hap._tcp",         // HomeKit
	"_companion-link._tcp", // AirPlay companion
}

// MDNSResult holds a discovered mDNS service.
type MDNSResult struct {
	Name    string
	Service string
	Host    string
	IP      string
	Port    int
}

// ScanMDNS sends mDNS queries and collects responses.
func ScanMDNS(ctx context.Context, logger *slog.Logger) []MDNSResult {
	var results []MDNSResult

	// Multicast DNS address
	mdnsAddr := &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		logger.Debug("mDNS listen failed", "error", err)
		return nil
	}
	defer conn.Close()

	// Send PTR queries for each service type
	for _, svc := range mdnsServices {
		query := buildMDNSQuery(svc + ".local")
		conn.WriteToUDP(query, mdnsAddr)
	}

	// Collect responses for 3 seconds
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 65536)

	seen := make(map[string]bool)
	for {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			break // timeout
		}

		records := parseMDNSResponse(buf[:n])
		for _, r := range records {
			if r.IP == "" {
				r.IP = from.IP.String()
			}
			key := fmt.Sprintf("%s:%s:%d", r.IP, r.Service, r.Port)
			if seen[key] {
				continue
			}
			seen[key] = true
			results = append(results, r)
		}
	}

	logger.Debug("mDNS scan complete", "services_found", len(results))
	return results
}

// EnrichDevicesFromMDNS updates device records with mDNS-discovered info.
func EnrichDevicesFromMDNS(store *db.Store, results []MDNSResult, logger *slog.Logger) {
	devices, _ := store.ListDevices()
	deviceMap := make(map[string]*db.Device)
	for _, d := range devices {
		deviceMap[d.IP] = d
	}

	for _, r := range results {
		dev, ok := deviceMap[r.IP]
		if !ok {
			continue
		}

		// Update hostname if empty
		if dev.Hostname == "" && r.Name != "" {
			name := r.Name
			// Strip service suffix
			if idx := strings.Index(name, "._"); idx > 0 {
				name = name[:idx]
			}
			dev.Hostname = name
			dev.LastSeen = time.Now()
			store.UpsertDevice(dev)
		}

		logger.Debug("mDNS service", "ip", r.IP, "name", r.Name, "service", r.Service, "port", r.Port)
	}
}

// buildMDNSQuery creates a minimal DNS PTR query packet.
func buildMDNSQuery(name string) []byte {
	// DNS header: ID=0, flags=0, questions=1
	pkt := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}

	// Encode the query name
	for _, part := range strings.Split(name, ".") {
		pkt = append(pkt, byte(len(part)))
		pkt = append(pkt, []byte(part)...)
	}
	pkt = append(pkt, 0) // Root label

	// Type PTR (12), Class IN (1)
	pkt = append(pkt, 0, 12, 0, 1)

	return pkt
}

// parseMDNSResponse extracts service names and IPs from a DNS response.
func parseMDNSResponse(data []byte) []MDNSResult {
	if len(data) < 12 {
		return nil
	}

	var results []MDNSResult

	// Parse answer section: extract any PTR, SRV, A records
	// This is a simplified parser — handles the common case
	answers := int(data[6])<<8 | int(data[7])
	additional := int(data[10])<<8 | int(data[11])
	totalRecords := answers + additional

	if totalRecords == 0 {
		return nil
	}

	// Skip question section
	offset := 12
	questions := int(data[4])<<8 | int(data[5])
	for i := 0; i < questions && offset < len(data); i++ {
		for offset < len(data) && data[offset] != 0 {
			if data[offset]&0xC0 == 0xC0 {
				offset += 2
				break
			}
			offset += int(data[offset]) + 1
		}
		if offset < len(data) && data[offset] == 0 {
			offset++
		}
		offset += 4 // type + class
	}

	// Extract names from the packet for any PTR answers
	for i := 0; i < totalRecords && offset+10 < len(data); i++ {
		// Skip name (may be compressed)
		nameStart := offset
		for offset < len(data) && data[offset] != 0 {
			if data[offset]&0xC0 == 0xC0 {
				offset += 2
				break
			}
			offset += int(data[offset]) + 1
		}
		if offset < len(data) && data[offset] == 0 {
			offset++
		}

		if offset+10 > len(data) {
			break
		}

		rtype := int(data[offset])<<8 | int(data[offset+1])
		offset += 8 // type + class + TTL
		rdLen := int(data[offset])<<8 | int(data[offset+1])
		offset += 2

		if offset+rdLen > len(data) {
			break
		}

		// Type A (1) — extract IP
		if rtype == 1 && rdLen == 4 {
			ip := fmt.Sprintf("%d.%d.%d.%d", data[offset], data[offset+1], data[offset+2], data[offset+3])
			name := decodeDNSName(data, nameStart)
			results = append(results, MDNSResult{
				Name: name, IP: ip, Service: "mdns",
			})
		}

		offset += rdLen
	}

	return results
}

func decodeDNSName(data []byte, offset int) string {
	var parts []string
	for offset < len(data) && data[offset] != 0 {
		if data[offset]&0xC0 == 0xC0 {
			if offset+1 < len(data) {
				ptr := int(data[offset]&0x3F)<<8 | int(data[offset+1])
				return strings.Join(parts, ".") + "." + decodeDNSName(data, ptr)
			}
			break
		}
		length := int(data[offset])
		offset++
		if offset+length <= len(data) {
			parts = append(parts, string(data[offset:offset+length]))
		}
		offset += length
	}
	return strings.Join(parts, ".")
}
