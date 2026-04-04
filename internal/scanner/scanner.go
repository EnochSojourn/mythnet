package scanner

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/mythnet/mythnet/internal/config"
	"github.com/mythnet/mythnet/internal/db"
)

// Scanner orchestrates network discovery and device fingerprinting.
type Scanner struct {
	cfg     *config.Config
	store   *db.Store
	logger  *slog.Logger
	trigger chan string
	mu      sync.RWMutex
	running bool
}

// New creates a new Scanner instance.
func New(cfg *config.Config, store *db.Store, logger *slog.Logger) *Scanner {
	return &Scanner{
		cfg:     cfg,
		store:   store,
		logger:  logger,
		trigger: make(chan string, 10),
	}
}

// TriggerScan requests an immediate scan of the given subnet (or all if empty).
func (s *Scanner) TriggerScan(subnet string) {
	select {
	case s.trigger <- subnet:
	default:
		s.logger.Warn("scan trigger channel full, skipping")
	}
}

// IsRunning returns whether a scan is currently in progress.
func (s *Scanner) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// Run starts the scanning loop. Blocks until ctx is cancelled.
func (s *Scanner) Run(ctx context.Context) {
	interval := s.cfg.Scanner.IntervalDuration
	if interval == 0 {
		interval = 5 * time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Initial scan on startup
	s.scanAll(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.scanAll(ctx)
		case subnet := <-s.trigger:
			if subnet == "" {
				s.scanAll(ctx)
			} else {
				s.scanSubnet(ctx, subnet)
			}
		}
	}
}

func (s *Scanner) scanAll(ctx context.Context) {
	for _, subnet := range s.cfg.Scanner.Subnets {
		select {
		case <-ctx.Done():
			return
		default:
			s.scanSubnet(ctx, subnet)
		}
	}
}

func (s *Scanner) scanSubnet(ctx context.Context, cidr string) {
	s.mu.Lock()
	s.running = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()

	s.logger.Info("starting subnet scan", "subnet", cidr)

	scan := &db.Scan{
		Subnet:    cidr,
		StartedAt: time.Now(),
		ScanType:  "full",
	}
	scanID, err := s.store.CreateScan(scan)
	if err != nil {
		s.logger.Error("failed to create scan record", "error", err)
		return
	}

	// Enumerate all IPs in the subnet
	ips, err := enumerateSubnet(cidr)
	if err != nil {
		s.logger.Error("failed to enumerate subnet", "subnet", cidr, "error", err)
		return
	}

	s.logger.Info("enumerating hosts", "subnet", cidr, "total_ips", len(ips))

	// Read the system ARP table for MAC addresses
	arpTable := ReadARPTable()

	// mDNS discovery for service names
	mdnsResults := ScanMDNS(ctx, s.logger)
	EnrichDevicesFromMDNS(s.store, mdnsResults, s.logger)

	// Phase 1: Ping sweep to find alive hosts
	aliveHosts, rttMap := s.pingSweep(ctx, ips)
	s.logger.Info("ping sweep complete", "subnet", cidr, "alive", len(aliveHosts))

	// Phase 2: Deep scan alive hosts (port scan + fingerprint)
	var (
		wg           sync.WaitGroup
		sem          = make(chan struct{}, s.cfg.Scanner.MaxConcurrentHosts)
		devicesFound int
		mu           sync.Mutex
	)

	now := time.Now()

	for _, ip := range aliveHosts {
		select {
		case <-ctx.Done():
			return
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			ports := ScanPorts(ctx, ip, s.cfg.Scanner.Ports, s.cfg.Scanner.TimeoutDuration, s.cfg.Scanner.MaxConcurrentPorts)
			hostname := resolveHostname(ip)
			mac := arpTable[ip]
			vendor := LookupVendor(mac)
			fp := Fingerprint(ports, vendor, hostname)
			devID := deviceID(mac, ip)

			// Detect port changes before updating
			portChanges := DetectPortChanges(s.store, devID, ip, ports)
			for _, evt := range PortChangesToEvents(portChanges) {
				s.store.InsertEvent(evt)
				if evt.Severity == "critical" || evt.Severity == "warning" {
					s.logger.Warn("port change detected", "ip", ip, "event", evt.Title)
				}
			}

			device := &db.Device{
				ID:         devID,
				IP:         ip,
				MAC:        mac,
				Hostname:   hostname,
				Vendor:     vendor,
				OSGuess:    fp.OS,
				DeviceType: fp.DeviceType,
				FirstSeen:  now,
				LastSeen:   now,
				IsOnline:   true,
			}

			if err := s.store.UpsertDevice(device); err != nil {
				s.logger.Error("failed to store device", "ip", ip, "error", err)
				return
			}

			// Record uptime state
			s.store.RecordStateChange(device.ID, "online")

			// Record latency
			if rtt, ok := rttMap[ip]; ok {
				s.store.RecordLatency(device.ID, float64(rtt.Microseconds())/1000.0)
			}

			for _, p := range ports {
				port := &db.Port{
					DeviceID: device.ID,
					Port:     p.Port,
					Protocol: "tcp",
					State:    "open",
					Service:  p.Service,
					Banner:   p.Banner,
					LastSeen: now,
				}
				if err := s.store.UpsertPort(port); err != nil {
					s.logger.Error("failed to store port", "ip", ip, "port", p.Port, "error", err)
				}

				// Check banner for known vulnerabilities
				for _, evt := range CheckBannerVulns(device.ID, ip, p.Port, p.Service, p.Banner) {
					if !s.store.HasRecentEvent(device.ID, "vuln_scan", evt.Title, 24*time.Hour) {
						s.store.InsertEvent(evt)
						s.logger.Warn("vulnerability found", "ip", ip, "cve", evt.Title)
					}
				}
			}

			// HTTP security header audit on web ports (once per 24h)
			for _, p := range ports {
				if p.Port == 80 || p.Port == 443 || p.Port == 8080 || p.Port == 8443 {
					auditTitle := fmt.Sprintf("Security audit — %s:%d", ip, p.Port)
					if !s.store.HasRecentEvent(device.ID, "http_audit", auditTitle, 24*time.Hour) {
						headers, err := AuditHTTPSecurity(ip, p.Port, s.cfg.Scanner.TimeoutDuration)
						if err == nil {
							var tlsResult *TLSAuditResult
							if p.Port == 443 || p.Port == 8443 {
								tlsResult, _ = AuditTLS(ip, p.Port, s.cfg.Scanner.TimeoutDuration)
							}
							evt := SecurityAuditToEvent(device.ID, ip, p.Port, headers, tlsResult)
							s.store.InsertEvent(evt)
						}
					}
				}
			}

			// Check TLS certificates on HTTPS ports
			for _, p := range ports {
				if p.Port == 443 || p.Port == 8443 {
					if info := CheckTLS(ip, p.Port, s.cfg.Scanner.TimeoutDuration); info != nil {
						if info.DaysLeft <= 30 || info.IsExpired {
							evt := TLSInfoToEvent(device.ID, ip, info)
							if !s.store.HasRecentEvent(device.ID, "tls_check", evt.Title, 6*time.Hour) {
								s.store.InsertEvent(evt)
							}
						}
					}
				}
			}

			mu.Lock()
			devicesFound++
			mu.Unlock()

			s.logger.Debug("discovered device",
				"ip", ip, "mac", mac, "hostname", hostname,
				"vendor", vendor, "os", fp.OS, "type", fp.DeviceType,
				"open_ports", len(ports),
			)
		}(ip)
	}

	wg.Wait()

	// Check network policies
	if violations, err := CheckPolicies(s.store); err == nil {
		for _, evt := range PolicyViolationsToEvents(violations) {
			if !s.store.HasRecentEvent(evt.DeviceID, "policy", evt.Title, 1*time.Hour) {
				s.store.InsertEvent(evt)
			}
		}
	}

	// Detect IP conflicts
	for _, evt := range DetectIPConflicts(s.store) {
		if !s.store.HasRecentEvent("", "ip_conflict", evt.Title, 1*time.Hour) {
			s.store.InsertEvent(evt)
			s.logger.Warn("IP conflict detected", "event", evt.Title)
		}
	}

	// Mark devices not seen recently as offline
	s.store.MarkOffline(now.Add(-s.cfg.Scanner.IntervalDuration * 2))

	// Complete the scan record
	s.store.CompleteScan(scanID, devicesFound)

	s.logger.Info("scan complete", "subnet", cidr, "devices_found", devicesFound)
}

func (s *Scanner) pingSweep(ctx context.Context, ips []string) ([]string, map[string]time.Duration) {
	var (
		alive  []string
		mu     sync.Mutex
		wg     sync.WaitGroup
		sem    = make(chan struct{}, s.cfg.Scanner.MaxConcurrentHosts)
		rttMap = make(map[string]time.Duration)
	)

	timeout := s.cfg.Scanner.TimeoutDuration
	if timeout == 0 {
		timeout = 2 * time.Second
	}

	for _, ip := range ips {
		select {
		case <-ctx.Done():
			return alive, rttMap
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			result := PingHost(ctx, ip, timeout)
			if result.Alive {
				mu.Lock()
				alive = append(alive, ip)
				if result.RTT > 0 {
					rttMap[ip] = result.RTT
				}
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()
	return alive, rttMap
}

func enumerateSubnet(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}

	var ips []string
	ip := make(net.IP, len(ipNet.IP))
	copy(ip, ipNet.IP)

	for ipNet.Contains(ip) {
		ips = append(ips, ip.String())
		incIP(ip)
	}

	// Remove network and broadcast addresses
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func resolveHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	name := names[0]
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return name
}

func deviceID(mac, ip string) string {
	input := ip
	if mac != "" {
		input = mac
	}
	h := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", h[:8])
}
