package warroom

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/mythnet/mythnet/internal/db"
	"github.com/mythnet/mythnet/internal/scanner"
)

// ConnTracker builds a persistent communication graph — who talks to whom.
type ConnTracker struct {
	store  *db.Store
	logger *slog.Logger
}

func NewConnTracker(store *db.Store, logger *slog.Logger) *ConnTracker {
	// Create traffic_log table
	store.DB().Exec(`
		CREATE TABLE IF NOT EXISTS traffic_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			src_ip TEXT NOT NULL,
			dst_ip TEXT NOT NULL,
			dst_port INTEGER NOT NULL,
			protocol TEXT NOT NULL DEFAULT 'tcp',
			first_seen TEXT NOT NULL,
			last_seen TEXT NOT NULL,
			conn_count INTEGER DEFAULT 1,
			bytes_est INTEGER DEFAULT 0,
			UNIQUE(src_ip, dst_ip, dst_port, protocol)
		);
		CREATE INDEX IF NOT EXISTS idx_traffic_src ON traffic_log(src_ip);
		CREATE INDEX IF NOT EXISTS idx_traffic_dst ON traffic_log(dst_ip);
	`)

	return &ConnTracker{store: store, logger: logger}
}

func (ct *ConnTracker) Run(ctx context.Context) {
	ct.logger.Info("connection tracker started")

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ct.snapshot()
		}
	}
}

func (ct *ConnTracker) snapshot() {
	devices, _ := ct.store.ListDevices()
	knownIPs := make(map[string]bool)
	for _, d := range devices {
		knownIPs[d.IP] = true
	}

	flows := scanner.GetActiveFlows(knownIPs)
	now := time.Now().Format(time.RFC3339)

	for _, f := range flows {
		if f.State != "established" && f.State != "syn_sent" {
			continue
		}

		ct.store.DB().Exec(`
			INSERT INTO traffic_log (src_ip, dst_ip, dst_port, protocol, first_seen, last_seen, conn_count)
			VALUES (?, ?, ?, ?, ?, ?, 1)
			ON CONFLICT(src_ip, dst_ip, dst_port, protocol) DO UPDATE SET
				last_seen = ?, conn_count = conn_count + 1
		`, f.SrcIP, f.DstIP, f.DstPort, f.Protocol, now, now, now)
	}
}

// GetCommGraph returns the communication graph for the API.
func GetCommGraph(db *sql.DB) []map[string]any {
	rows, err := db.Query(`
		SELECT src_ip, dst_ip, dst_port, protocol, first_seen, last_seen, conn_count
		FROM traffic_log ORDER BY conn_count DESC LIMIT 200
	`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var graph []map[string]any
	for rows.Next() {
		var src, dst, proto, first, last string
		var port, count int
		rows.Scan(&src, &dst, &port, &proto, &first, &last, &count)
		graph = append(graph, map[string]any{
			"src": src, "dst": dst, "port": port, "protocol": proto,
			"first_seen": first, "last_seen": last, "connections": count,
		})
	}
	return graph
}

// GetTopTalkers returns devices with the most connections.
func GetTopTalkers(db *sql.DB) []map[string]any {
	rows, err := db.Query(`
		SELECT src_ip, COUNT(*) as targets, SUM(conn_count) as total_conns
		FROM traffic_log GROUP BY src_ip ORDER BY total_conns DESC LIMIT 20
	`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var talkers []map[string]any
	for rows.Next() {
		var ip string
		var targets, conns int
		rows.Scan(&ip, &targets, &conns)
		talkers = append(talkers, map[string]any{
			"ip": ip, "unique_targets": targets, "total_connections": conns,
		})
	}
	return talkers
}
