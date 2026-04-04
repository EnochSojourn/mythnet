package warroom

import (
	"bufio"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ThreatFeed downloads and caches known malicious IPs and domains.
type ThreatFeed struct {
	mu             sync.RWMutex
	maliciousIPs   map[string]string // IP → source
	maliciousDomains map[string]string // domain → source
	lastUpdate     time.Time
	logger         *slog.Logger
}

var globalFeed *ThreatFeed

func InitThreatFeed(logger *slog.Logger) *ThreatFeed {
	f := &ThreatFeed{
		maliciousIPs:     make(map[string]string),
		maliciousDomains: make(map[string]string),
		logger:           logger,
	}
	globalFeed = f
	go f.updateLoop()
	return f
}

func (f *ThreatFeed) updateLoop() {
	f.update()
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		f.update()
	}
}

func (f *ThreatFeed) update() {
	f.logger.Info("updating threat intelligence feeds")

	// abuse.ch Feodo tracker (banking trojans C2)
	f.fetchIPList("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", "feodo")

	// abuse.ch URLhaus (malware distribution)
	f.fetchDomainList("https://urlhaus.abuse.ch/downloads/hostfile/", "urlhaus")

	// Emerging Threats compromised IPs
	f.fetchIPList("https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "emerging_threats")

	f.mu.Lock()
	f.lastUpdate = time.Now()
	f.mu.Unlock()

	f.logger.Info("threat feeds updated",
		"malicious_ips", len(f.maliciousIPs),
		"malicious_domains", len(f.maliciousDomains))
}

func (f *ThreatFeed) fetchIPList(url, source string) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		f.logger.Debug("feed fetch failed", "url", url, "error", err)
		return
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	count := 0
	f.mu.Lock()
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Extract IP (first field)
		parts := strings.Fields(line)
		if len(parts) > 0 {
			ip := parts[0]
			if isValidIP(ip) {
				f.maliciousIPs[ip] = source
				count++
			}
		}
	}
	f.mu.Unlock()
	f.logger.Debug("feed loaded", "source", source, "ips", count)
}

func (f *ThreatFeed) fetchDomainList(url, source string) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		f.logger.Debug("feed fetch failed", "url", url, "error", err)
		return
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	count := 0
	f.mu.Lock()
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// hostfile format: 127.0.0.1 domain.com
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			domain := strings.ToLower(parts[1])
			if domain != "localhost" && strings.Contains(domain, ".") {
				f.maliciousDomains[domain] = source
				count++
			}
		}
	}
	f.mu.Unlock()
	f.logger.Debug("feed loaded", "source", source, "domains", count)
}

// CheckIP returns the threat source if IP is known malicious.
func CheckIP(ip string) (string, bool) {
	if globalFeed == nil {
		return "", false
	}
	globalFeed.mu.RLock()
	defer globalFeed.mu.RUnlock()
	source, found := globalFeed.maliciousIPs[ip]
	return source, found
}

// CheckDomain returns the threat source if domain is known malicious.
func CheckDomain(domain string) (string, bool) {
	if globalFeed == nil {
		return "", false
	}
	globalFeed.mu.RLock()
	defer globalFeed.mu.RUnlock()
	source, found := globalFeed.maliciousDomains[strings.ToLower(domain)]
	return source, found
}

// GetFeedStats returns threat feed statistics.
func GetFeedStats() map[string]any {
	if globalFeed == nil {
		return map[string]any{"loaded": false}
	}
	globalFeed.mu.RLock()
	defer globalFeed.mu.RUnlock()
	return map[string]any{
		"loaded":            true,
		"malicious_ips":     len(globalFeed.maliciousIPs),
		"malicious_domains": len(globalFeed.maliciousDomains),
		"last_update":       globalFeed.lastUpdate.Format(time.RFC3339),
	}
}

func isValidIP(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}
