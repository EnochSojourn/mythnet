package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// PortResult holds the result of scanning a single port.
type PortResult struct {
	Port    int
	Open    bool
	Service string
	Banner  string
}

// ScanPorts performs concurrent TCP connect scanning on the specified ports.
func ScanPorts(ctx context.Context, ip string, ports []int, timeout time.Duration, maxConcurrent int) []PortResult {
	var (
		results []PortResult
		mu      sync.Mutex
		wg      sync.WaitGroup
		sem     = make(chan struct{}, maxConcurrent)
	)

	for _, port := range ports {
		select {
		case <-ctx.Done():
			return results
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			r := scanPort(ip, p, timeout)
			if r.Open {
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return results
}

func scanPort(ip string, port int, timeout time.Duration) PortResult {
	result := PortResult{Port: port}

	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return result
	}
	defer conn.Close()

	result.Open = true
	result.Service = GuessService(port)

	// Send probe for services that don't send banners unprompted
	if isHTTPPort(port) {
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", ip)
	}

	// Try to grab a banner
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		banner := sanitizeBanner(string(buf[:n]))
		result.Banner = banner
		if svc := IdentifyServiceFromBanner(banner); svc != "" {
			result.Service = svc
		}
	}

	return result
}

func isHTTPPort(port int) bool {
	return port == 80 || port == 443 || port == 8080 || port == 8443 || port == 9090
}

func sanitizeBanner(raw string) string {
	clean := make([]byte, 0, len(raw))
	for _, b := range []byte(raw) {
		if (b >= 32 && b < 127) || b == '\n' || b == '\r' {
			clean = append(clean, b)
		}
	}
	s := strings.TrimSpace(string(clean))
	if len(s) > 256 {
		s = s[:256]
	}
	return s
}

// GuessService returns a service name based on well-known port numbers.
func GuessService(port int) string {
	services := map[int]string{
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		80:    "http",
		110:   "pop3",
		111:   "rpcbind",
		135:   "msrpc",
		139:   "netbios-ssn",
		143:   "imap",
		443:   "https",
		445:   "microsoft-ds",
		993:   "imaps",
		995:   "pop3s",
		1433:  "mssql",
		1521:  "oracle",
		3306:  "mysql",
		3389:  "rdp",
		5432:  "postgresql",
		5900:  "vnc",
		6379:  "redis",
		8080:  "http-proxy",
		8443:  "https-alt",
		9090:  "prometheus",
		27017: "mongodb",
	}
	if svc, ok := services[port]; ok {
		return svc
	}
	return ""
}

// IdentifyServiceFromBanner attempts to identify the service from its banner string.
func IdentifyServiceFromBanner(banner string) string {
	lower := strings.ToLower(banner)
	switch {
	case strings.HasPrefix(lower, "ssh-"):
		return "ssh"
	case strings.HasPrefix(lower, "220") && strings.Contains(lower, "ftp"):
		return "ftp"
	case strings.HasPrefix(lower, "220") && strings.Contains(lower, "smtp"):
		return "smtp"
	case strings.HasPrefix(lower, "http/"):
		return "http"
	case strings.Contains(lower, "mysql"):
		return "mysql"
	case strings.Contains(lower, "postgresql"):
		return "postgresql"
	case strings.Contains(lower, "redis"):
		return "redis"
	case strings.Contains(lower, "mongodb"):
		return "mongodb"
	case strings.Contains(lower, "imap"):
		return "imap"
	case strings.Contains(lower, "pop"):
		return "pop3"
	case strings.Contains(lower, "vnc") || strings.HasPrefix(lower, "rfb"):
		return "vnc"
	default:
		return ""
	}
}
