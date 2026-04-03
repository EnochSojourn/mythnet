package telemetry

import (
	"context"
	"log/slog"
	"time"

	"github.com/mythnet/mythnet/internal/config"
	"github.com/mythnet/mythnet/internal/db"
)

// Manager starts and coordinates all telemetry listeners.
type Manager struct {
	cfg    *config.Config
	store  *db.Store
	logger *slog.Logger
}

// NewManager creates a new telemetry manager.
func NewManager(cfg *config.Config, store *db.Store, logger *slog.Logger) *Manager {
	return &Manager{cfg: cfg, store: store, logger: logger}
}

// Run starts all enabled telemetry listeners. Blocks until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) {
	if m.cfg.Telemetry.SNMP.Enabled {
		snmp := NewSNMPListener(
			m.cfg.Telemetry.SNMP.Listen,
			m.cfg.Telemetry.SNMP.Community,
			m.store, m.logger,
		)
		go func() {
			if err := snmp.Run(ctx); err != nil {
				m.logger.Error("SNMP listener failed", "error", err)
			}
		}()
	}

	if m.cfg.Telemetry.Syslog.Enabled {
		sl := NewSyslogListener(
			m.cfg.Telemetry.Syslog.Listen,
			m.store, m.logger,
		)
		go func() {
			if err := sl.Run(ctx); err != nil {
				m.logger.Error("syslog listener failed", "error", err)
			}
		}()
	}

	if m.cfg.Telemetry.Poller.Enabled {
		poller := NewPoller(m.store, m.logger, m.cfg.Telemetry.Poller.IntervalDuration)
		go poller.Run(ctx)
	}

	// Prune old events periodically
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.store.PruneEvents(7 * 24 * time.Hour) // Keep 7 days
			}
		}
	}()

	<-ctx.Done()
}
