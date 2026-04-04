package alerts

import (
	"context"
	"log/slog"
	"time"

	"github.com/mythnet/mythnet/internal/ai"
	"github.com/mythnet/mythnet/internal/config"
	"github.com/mythnet/mythnet/internal/db"
)

// ReportScheduler generates periodic AI reports.
type ReportScheduler struct {
	store    *db.Store
	aiClient ai.Client
	logger   *slog.Logger
	interval time.Duration
	emailCfg *config.SMTPConfig
}

// NewReportScheduler creates a new scheduled report generator.
func NewReportScheduler(store *db.Store, aiClient ai.Client, logger *slog.Logger, interval time.Duration, emailCfg *config.SMTPConfig) *ReportScheduler {
	return &ReportScheduler{
		store: store, aiClient: aiClient, logger: logger,
		interval: interval, emailCfg: emailCfg,
	}
}

// Run starts the report scheduler. Blocks until ctx is cancelled.
func (rs *ReportScheduler) Run(ctx context.Context) {
	if rs.aiClient == nil || rs.interval == 0 {
		return
	}

	rs.logger.Info("report scheduler starting", "interval", rs.interval)

	ticker := time.NewTicker(rs.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rs.generate(ctx)
		}
	}
}

func (rs *ReportScheduler) generate(ctx context.Context) {
	rs.logger.Info("generating scheduled report")

	report, err := ai.GenerateReport(ctx, rs.aiClient, rs.store)
	if err != nil {
		rs.logger.Error("scheduled report failed", "error", err)
		return
	}

	// Store as event
	evt := &db.Event{
		Source:     "scheduled_report",
		Severity:   "info",
		Title:      "Scheduled Network Report — " + time.Now().Format("2006-01-02"),
		BodyMD:     report,
		ReceivedAt: time.Now(),
		Tags:       "report,scheduled,ai",
	}
	rs.store.InsertEvent(evt)

	// Email the report if SMTP is configured
	if rs.emailCfg != nil && rs.emailCfg.Host != "" {
		SendEmail(rs.emailCfg, evt)
	}

	rs.logger.Info("scheduled report generated", "length", len(report))
}
