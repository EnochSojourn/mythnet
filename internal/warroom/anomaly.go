package warroom

import (
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/mythnet/mythnet/internal/db"
)

// AnomalyDetector baselines device behavior and detects deviations.
type AnomalyDetector struct {
	store  *db.Store
	logger *slog.Logger
}

func NewAnomalyDetector(store *db.Store, logger *slog.Logger) *AnomalyDetector {
	// Create baseline table
	store.DB().Exec(`
		CREATE TABLE IF NOT EXISTS device_baselines (
			device_id TEXT PRIMARY KEY,
			normal_ports TEXT DEFAULT '',
			normal_conn_count INTEGER DEFAULT 0,
			last_baseline TEXT NOT NULL
		)
	`)
	return &AnomalyDetector{store: store, logger: logger}
}

// BaselineAndDetect updates baselines and checks for anomalies.
func (ad *AnomalyDetector) BaselineAndDetect() {
	devices, _ := ad.store.ListDevices()
	now := time.Now()

	for _, d := range devices {
		if !d.IsOnline {
			continue
		}

		ports, _ := ad.store.GetDevicePorts(d.ID)
		currentPorts := portsToString(ports)
		currentConnCount := getDeviceConnCount(ad.store.DB(), d.IP)

		// Get baseline
		var baselinePorts string
		var baselineConns int
		var lastBaseline string
		err := ad.store.DB().QueryRow(
			`SELECT normal_ports, normal_conn_count, last_baseline FROM device_baselines WHERE device_id = ?`,
			d.ID,
		).Scan(&baselinePorts, &baselineConns, &lastBaseline)

		if err == sql.ErrNoRows {
			// First time — set baseline
			ad.store.DB().Exec(
				`INSERT INTO device_baselines (device_id, normal_ports, normal_conn_count, last_baseline) VALUES (?, ?, ?, ?)`,
				d.ID, currentPorts, currentConnCount, now.Format(time.RFC3339),
			)
			continue
		}

		// Check for anomalies
		// 1. New ports that weren't in baseline
		if currentPorts != baselinePorts && baselinePorts != "" {
			newPorts := diffPorts(baselinePorts, currentPorts)
			if newPorts != "" {
				name := d.Hostname
				if name == "" {
					name = d.IP
				}
				ad.logger.Warn("ANOMALY: new ports detected", "device", name, "new_ports", newPorts)
				ad.store.InsertEvent(&db.Event{
					DeviceID: d.ID, Source: "anomaly", Severity: "warning",
					Title: fmt.Sprintf("Anomaly: %s has new ports: %s", name, newPorts),
					BodyMD: fmt.Sprintf("## Anomaly Detected\n\n**Device:** `%s` (%s)  \n**New Ports:** %s  \n**Previous Ports:** %s  \n\n> This device has opened ports not seen in its baseline behavior.",
						name, d.IP, newPorts, baselinePorts),
					ReceivedAt: now, Tags: "anomaly,ports",
				})
			}
		}

		// 2. Massive spike in connection count (3x baseline)
		if baselineConns > 10 && currentConnCount > baselineConns*3 {
			name := d.Hostname
			if name == "" {
				name = d.IP
			}
			ad.logger.Warn("ANOMALY: connection spike", "device", name,
				"baseline", baselineConns, "current", currentConnCount)
			ad.store.InsertEvent(&db.Event{
				DeviceID: d.ID, Source: "anomaly", Severity: "warning",
				Title: fmt.Sprintf("Anomaly: %s connection spike (%d→%d)", name, baselineConns, currentConnCount),
				BodyMD: fmt.Sprintf("## Connection Spike Detected\n\n**Device:** `%s`  \n**Baseline:** %d connections  \n**Current:** %d connections  \n**Increase:** %.0fx  \n\n> This may indicate scanning, data exfiltration, or a compromised device.",
					d.IP, baselineConns, currentConnCount, float64(currentConnCount)/float64(baselineConns)),
				ReceivedAt: now, Tags: "anomaly,connection_spike",
			})
		}

		// Update baseline (rolling average)
		ad.store.DB().Exec(
			`UPDATE device_baselines SET normal_ports = ?, normal_conn_count = ?, last_baseline = ? WHERE device_id = ?`,
			currentPorts, (baselineConns+currentConnCount)/2, now.Format(time.RFC3339), d.ID,
		)
	}
}

func portsToString(ports []db.Port) string {
	s := ""
	for _, p := range ports {
		if s != "" {
			s += ","
		}
		s += fmt.Sprintf("%d", p.Port)
	}
	return s
}

func diffPorts(baseline, current string) string {
	baseSet := make(map[string]bool)
	for _, p := range splitComma(baseline) {
		baseSet[p] = true
	}
	diff := ""
	for _, p := range splitComma(current) {
		if !baseSet[p] {
			if diff != "" {
				diff += ","
			}
			diff += p
		}
	}
	return diff
}

func splitComma(s string) []string {
	if s == "" {
		return nil
	}
	var parts []string
	current := ""
	for _, c := range s {
		if c == ',' {
			parts = append(parts, current)
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

func getDeviceConnCount(database *sql.DB, ip string) int {
	var count int
	database.QueryRow(`SELECT COALESCE(SUM(conn_count), 0) FROM traffic_log WHERE src_ip = ?`, ip).Scan(&count)
	return count
}
