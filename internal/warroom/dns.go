package warroom

import (
	"context"
	"database/sql"
	"net"
	"sync"
	"time"
)

// DNSCache resolves and caches reverse DNS lookups for traffic graph enrichment.
type DNSCache struct {
	mu    sync.RWMutex
	cache map[string]string // IP → hostname
}

var globalDNS = &DNSCache{cache: make(map[string]string)}

// Resolve returns the hostname for an IP, using cache.
func (d *DNSCache) Resolve(ip string) string {
	d.mu.RLock()
	if host, ok := d.cache[ip]; ok {
		d.mu.RUnlock()
		return host
	}
	d.mu.RUnlock()

	// Do reverse lookup
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	host := ""
	if err == nil && len(names) > 0 {
		host = names[0]
		if len(host) > 0 && host[len(host)-1] == '.' {
			host = host[:len(host)-1]
		}
	}

	d.mu.Lock()
	d.cache[ip] = host
	d.mu.Unlock()

	return host
}

// EnrichTrafficWithDNS adds hostname resolution to the traffic graph.
func EnrichTrafficWithDNS(db *sql.DB) []map[string]any {
	graph := GetCommGraph(db)

	for _, entry := range graph {
		dstIP := entry["dst"].(string)
		host := globalDNS.Resolve(dstIP)
		if host != "" {
			entry["dst_host"] = host
		}
	}

	return graph
}

// GetDNSSummary returns unique destination domains from the traffic graph.
func GetDNSSummary(db *sql.DB) []map[string]any {
	graph := GetCommGraph(db)

	domainConns := make(map[string]int)
	domainIPs := make(map[string]map[string]bool)

	for _, entry := range graph {
		dstIP := entry["dst"].(string)
		host := globalDNS.Resolve(dstIP)
		if host == "" {
			host = dstIP
		}
		// Extract base domain (last 2 parts)
		domain := baseDomain(host)
		conns := entry["connections"].(int)
		domainConns[domain] += conns
		if domainIPs[domain] == nil {
			domainIPs[domain] = make(map[string]bool)
		}
		domainIPs[domain][dstIP] = true
	}

	var result []map[string]any
	for domain, conns := range domainConns {
		result = append(result, map[string]any{
			"domain":      domain,
			"connections": conns,
			"ips":         len(domainIPs[domain]),
		})
	}

	// Sort by connections descending (simple bubble sort for small lists)
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j]["connections"].(int) > result[i]["connections"].(int) {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	if len(result) > 50 {
		result = result[:50]
	}

	return result
}

func baseDomain(host string) string {
	parts := splitDot(host)
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return host
}

func splitDot(s string) []string {
	var parts []string
	current := ""
	for _, c := range s {
		if c == '.' {
			if current != "" {
				parts = append(parts, current)
			}
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}
