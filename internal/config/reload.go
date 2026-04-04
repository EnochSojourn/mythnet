package config

import (
	"log/slog"
	"os"
	"sync"
	"time"
)

// Reloadable wraps a Config with thread-safe hot-reload support.
type Reloadable struct {
	mu       sync.RWMutex
	cfg      *Config
	path     string
	logger   *slog.Logger
	lastMod  time.Time
	onChange func(*Config)
}

// NewReloadable creates a reloadable config wrapper.
func NewReloadable(path string, cfg *Config, logger *slog.Logger) *Reloadable {
	r := &Reloadable{cfg: cfg, path: path, logger: logger}
	if info, err := os.Stat(path); err == nil {
		r.lastMod = info.ModTime()
	}
	return r
}

// Get returns the current config (read-locked).
func (r *Reloadable) Get() *Config {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cfg
}

// OnChange registers a callback for config changes.
func (r *Reloadable) OnChange(fn func(*Config)) {
	r.onChange = fn
}

// Reload re-reads the config file and applies changes.
func (r *Reloadable) Reload() error {
	newCfg, err := Load(r.path)
	if err != nil {
		return err
	}

	r.mu.Lock()
	old := r.cfg
	r.cfg = newCfg
	r.mu.Unlock()

	r.logger.Info("config reloaded",
		"subnets", newCfg.Scanner.Subnets,
		"scan_interval", newCfg.Scanner.Interval,
	)

	if r.onChange != nil && configChanged(old, newCfg) {
		r.onChange(newCfg)
	}

	return nil
}

// Watch polls the config file for changes. Call in a goroutine.
func (r *Reloadable) Watch(stop <-chan struct{}) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			info, err := os.Stat(r.path)
			if err != nil {
				continue
			}
			if info.ModTime().After(r.lastMod) {
				r.lastMod = info.ModTime()
				if err := r.Reload(); err != nil {
					r.logger.Error("config reload failed", "error", err)
				}
			}
		}
	}
}

func configChanged(a, b *Config) bool {
	if len(a.Scanner.Subnets) != len(b.Scanner.Subnets) {
		return true
	}
	for i := range a.Scanner.Subnets {
		if a.Scanner.Subnets[i] != b.Scanner.Subnets[i] {
			return true
		}
	}
	if a.Scanner.Interval != b.Scanner.Interval {
		return true
	}
	return false
}
