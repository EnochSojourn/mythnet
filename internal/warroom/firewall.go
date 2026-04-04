package warroom

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/mythnet/mythnet/internal/db"
)

// Firewall controls iptables to actively block malicious IPs.
type Firewall struct {
	store   *db.Store
	logger  *slog.Logger
	mu      sync.RWMutex
	blocked map[string]time.Time // IP → when blocked
	enabled bool
}

var GlobalFirewall *Firewall

func InitFirewall(store *db.Store, logger *slog.Logger) *Firewall {
	fw := &Firewall{
		store:   store,
		logger:  logger,
		blocked: make(map[string]time.Time),
		enabled: true,
	}

	// Create MythNet chain
	exec.Command("iptables", "-N", "MYTHNET").Run()
	exec.Command("iptables", "-C", "INPUT", "-j", "MYTHNET").Run()
	exec.Command("iptables", "-I", "INPUT", "1", "-j", "MYTHNET").Run()

	GlobalFirewall = fw
	logger.Info("firewall engine initialized (iptables)")
	return fw
}

// BlockIP adds an iptables DROP rule for an IP.
func (fw *Firewall) BlockIP(ip, reason string) error {
	if !fw.enabled {
		return fmt.Errorf("firewall disabled")
	}

	fw.mu.Lock()
	if _, already := fw.blocked[ip]; already {
		fw.mu.Unlock()
		return nil
	}
	fw.blocked[ip] = time.Now()
	fw.mu.Unlock()

	// Add iptables rule
	err := exec.Command("iptables", "-A", "MYTHNET", "-s", ip, "-j", "DROP").Run()
	if err != nil {
		fw.logger.Error("iptables block failed", "ip", ip, "error", err)
		return fmt.Errorf("iptables: %w", err)
	}

	fw.logger.Warn("BLOCKED IP", "ip", ip, "reason", reason)

	fw.store.InsertEvent(&db.Event{
		Source:   "firewall",
		Severity: "critical",
		Title:    fmt.Sprintf("BLOCKED: %s — %s", ip, reason),
		BodyMD:   fmt.Sprintf("## IP Blocked by Firewall\n\n**IP:** `%s`  \n**Reason:** %s  \n**Time:** %s  \n**Method:** iptables DROP in MYTHNET chain\n\n> Traffic from this IP is now dropped at the kernel level.", ip, reason, time.Now().Format(time.RFC3339)),
		ReceivedAt: time.Now(),
		Tags:     "firewall,blocked,active-defense",
	})

	fw.store.Audit("firewall_block", ip+": "+reason, "system")
	return nil
}

// UnblockIP removes the iptables rule.
func (fw *Firewall) UnblockIP(ip string) error {
	fw.mu.Lock()
	delete(fw.blocked, ip)
	fw.mu.Unlock()

	err := exec.Command("iptables", "-D", "MYTHNET", "-s", ip, "-j", "DROP").Run()
	if err != nil {
		return err
	}

	fw.logger.Info("unblocked IP", "ip", ip)
	fw.store.Audit("firewall_unblock", ip, "system")
	return nil
}

// GetBlocked returns all currently blocked IPs.
func (fw *Firewall) GetBlocked() []map[string]any {
	fw.mu.RLock()
	defer fw.mu.RUnlock()

	var list []map[string]any
	for ip, when := range fw.blocked {
		list = append(list, map[string]any{
			"ip":         ip,
			"blocked_at": when.Format(time.RFC3339),
			"duration":   time.Since(when).String(),
		})
	}
	return list
}

// IsBlocked checks if an IP is blocked.
func IsBlocked(ip string) bool {
	if GlobalFirewall == nil {
		return false
	}
	GlobalFirewall.mu.RLock()
	defer GlobalFirewall.mu.RUnlock()
	_, blocked := GlobalFirewall.blocked[ip]
	return blocked
}

// AutoBlock is called by the threat engine to block IPs automatically.
func AutoBlock(ip, reason string) {
	if GlobalFirewall == nil {
		return
	}
	// Don't block local network devices or self
	if isPrivateIPCheck(ip) {
		return // Only block external IPs automatically
	}
	GlobalFirewall.BlockIP(ip, reason)
}

func isPrivateIPCheck(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"} {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}
