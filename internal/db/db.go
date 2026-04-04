package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db       *sql.DB
	oplogFn  func(table, op string, data any) // mesh replication hook
	notifyFn func(table, op string, data any) // real-time push hook
}

func New(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	db.SetMaxOpenConns(4)

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate database: %w", err)
	}

	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

// DB returns the underlying *sql.DB for direct queries.
func (s *Store) DB() *sql.DB {
	return s.db
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS devices (
			id TEXT PRIMARY KEY,
			ip TEXT NOT NULL,
			mac TEXT DEFAULT '',
			hostname TEXT DEFAULT '',
			vendor TEXT DEFAULT '',
			os_guess TEXT DEFAULT '',
			device_type TEXT DEFAULT '',
			first_seen TEXT NOT NULL,
			last_seen TEXT NOT NULL,
			is_online INTEGER DEFAULT 1
		);

		CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);
		CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);

		CREATE TABLE IF NOT EXISTS ports (
			device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
			port INTEGER NOT NULL,
			protocol TEXT NOT NULL DEFAULT 'tcp',
			state TEXT NOT NULL DEFAULT 'open',
			service TEXT DEFAULT '',
			banner TEXT DEFAULT '',
			last_seen TEXT NOT NULL,
			PRIMARY KEY (device_id, port, protocol)
		);

		CREATE TABLE IF NOT EXISTS scans (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			subnet TEXT NOT NULL,
			started_at TEXT NOT NULL,
			finished_at TEXT,
			devices_found INTEGER DEFAULT 0,
			scan_type TEXT NOT NULL DEFAULT 'full'
		);

		CREATE TABLE IF NOT EXISTS events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			device_id TEXT DEFAULT '',
			source TEXT NOT NULL,
			severity TEXT DEFAULT 'info',
			title TEXT NOT NULL,
			body_md TEXT NOT NULL,
			raw_data TEXT DEFAULT '',
			received_at TEXT NOT NULL,
			tags TEXT DEFAULT ''
		);

		CREATE INDEX IF NOT EXISTS idx_events_device ON events(device_id);
		CREATE INDEX IF NOT EXISTS idx_events_received ON events(received_at);
		CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);

		CREATE TABLE IF NOT EXISTS oplog (
			seq INTEGER PRIMARY KEY AUTOINCREMENT,
			table_name TEXT NOT NULL,
			operation TEXT NOT NULL,
			data TEXT NOT NULL,
			node_id TEXT NOT NULL,
			created_at TEXT NOT NULL
		);

		CREATE TABLE IF NOT EXISTS snapshots (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			online_devices INTEGER DEFAULT 0,
			total_events INTEGER DEFAULT 0,
			avg_latency REAL DEFAULT 0,
			recorded_at TEXT NOT NULL
		);

		CREATE TABLE IF NOT EXISTS latency_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			device_id TEXT NOT NULL,
			rtt_ms REAL NOT NULL,
			recorded_at TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_latency_device ON latency_history(device_id);

		CREATE TABLE IF NOT EXISTS device_notes (
			device_id TEXT PRIMARY KEY,
			notes TEXT DEFAULT '',
			updated_at TEXT NOT NULL
		);

		CREATE TABLE IF NOT EXISTS policies (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			data TEXT NOT NULL
		);

		CREATE TABLE IF NOT EXISTS audit_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			action TEXT NOT NULL,
			detail TEXT DEFAULT '',
			remote_addr TEXT DEFAULT '',
			created_at TEXT NOT NULL
		);

		CREATE TABLE IF NOT EXISTS device_tags (
			device_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (device_id, tag)
		);
		CREATE INDEX IF NOT EXISTS idx_tags_tag ON device_tags(tag);

		CREATE TABLE IF NOT EXISTS uptime_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			device_id TEXT NOT NULL,
			state TEXT NOT NULL,
			changed_at TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_uptime_device ON uptime_history(device_id);

		CREATE TABLE IF NOT EXISTS device_adapters (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			device_id TEXT NOT NULL,
			device_type TEXT DEFAULT '',
			vendor TEXT DEFAULT '',
			port INTEGER NOT NULL,
			endpoints TEXT DEFAULT '[]',
			generated_at TEXT NOT NULL,
			UNIQUE(device_id, port)
		);

		CREATE TABLE IF NOT EXISTS mesh_nodes (
			node_id TEXT PRIMARY KEY,
			name TEXT DEFAULT '',
			address TEXT DEFAULT '',
			node_type TEXT DEFAULT 'full',
			last_seen TEXT NOT NULL
		);
	`)
	return err
}

// SetOplogHook registers a callback that fires after each mutation for mesh replication.
func (s *Store) SetOplogHook(fn func(table, op string, data any)) {
	s.oplogFn = fn
}

// SetNotifyHook registers a callback for real-time push notifications.
func (s *Store) SetNotifyHook(fn func(table, op string, data any)) {
	s.notifyFn = fn
}

func (s *Store) logOp(table, op string, data any) {
	if s.oplogFn != nil {
		s.oplogFn(table, op, data)
	}
	if s.notifyFn != nil {
		s.notifyFn(table, op, data)
	}
}

func (s *Store) UpsertDevice(d *Device) error {
	_, err := s.db.Exec(`
		INSERT INTO devices (id, ip, mac, hostname, vendor, os_guess, device_type, first_seen, last_seen, is_online)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			ip = excluded.ip,
			mac = CASE WHEN excluded.mac != '' THEN excluded.mac ELSE devices.mac END,
			hostname = CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE devices.hostname END,
			vendor = CASE WHEN excluded.vendor != '' THEN excluded.vendor ELSE devices.vendor END,
			os_guess = CASE WHEN excluded.os_guess != '' THEN excluded.os_guess ELSE devices.os_guess END,
			device_type = CASE WHEN excluded.device_type != '' THEN excluded.device_type ELSE devices.device_type END,
			last_seen = excluded.last_seen,
			is_online = excluded.is_online
	`, d.ID, d.IP, d.MAC, d.Hostname, d.Vendor, d.OSGuess, d.DeviceType,
		d.FirstSeen.Format(time.RFC3339), d.LastSeen.Format(time.RFC3339), d.IsOnline)
	if err == nil {
		s.logOp("devices", "upsert_device", d)
	}
	return err
}

func (s *Store) GetDevice(id string) (*Device, error) {
	d := &Device{}
	var firstSeen, lastSeen string
	var isOnline int
	err := s.db.QueryRow(`
		SELECT id, ip, mac, hostname, vendor, os_guess, device_type, first_seen, last_seen, is_online
		FROM devices WHERE id = ?
	`, id).Scan(&d.ID, &d.IP, &d.MAC, &d.Hostname, &d.Vendor, &d.OSGuess, &d.DeviceType, &firstSeen, &lastSeen, &isOnline)
	if err != nil {
		return nil, err
	}
	d.FirstSeen, _ = time.Parse(time.RFC3339, firstSeen)
	d.LastSeen, _ = time.Parse(time.RFC3339, lastSeen)
	d.IsOnline = isOnline != 0
	return d, nil
}

func (s *Store) ListDevices() ([]*Device, error) {
	rows, err := s.db.Query(`
		SELECT id, ip, mac, hostname, vendor, os_guess, device_type, first_seen, last_seen, is_online
		FROM devices ORDER BY last_seen DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []*Device
	for rows.Next() {
		d := &Device{}
		var firstSeen, lastSeen string
		var isOnline int
		if err := rows.Scan(&d.ID, &d.IP, &d.MAC, &d.Hostname, &d.Vendor, &d.OSGuess, &d.DeviceType, &firstSeen, &lastSeen, &isOnline); err != nil {
			return nil, err
		}
		d.FirstSeen, _ = time.Parse(time.RFC3339, firstSeen)
		d.LastSeen, _ = time.Parse(time.RFC3339, lastSeen)
		d.IsOnline = isOnline != 0
		devices = append(devices, d)
	}
	return devices, rows.Err()
}

func (s *Store) UpsertPort(p *Port) error {
	_, err := s.db.Exec(`
		INSERT INTO ports (device_id, port, protocol, state, service, banner, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(device_id, port, protocol) DO UPDATE SET
			state = excluded.state,
			service = CASE WHEN excluded.service != '' THEN excluded.service ELSE ports.service END,
			banner = CASE WHEN excluded.banner != '' THEN excluded.banner ELSE ports.banner END,
			last_seen = excluded.last_seen
	`, p.DeviceID, p.Port, p.Protocol, p.State, p.Service, p.Banner, p.LastSeen.Format(time.RFC3339))
	if err == nil {
		s.logOp("ports", "upsert_port", p)
	}
	return err
}

func (s *Store) GetDevicePorts(deviceID string) ([]Port, error) {
	rows, err := s.db.Query(`
		SELECT device_id, port, protocol, state, service, banner, last_seen
		FROM ports WHERE device_id = ? ORDER BY port
	`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ports []Port
	for rows.Next() {
		p := Port{}
		var lastSeen string
		if err := rows.Scan(&p.DeviceID, &p.Port, &p.Protocol, &p.State, &p.Service, &p.Banner, &lastSeen); err != nil {
			return nil, err
		}
		p.LastSeen, _ = time.Parse(time.RFC3339, lastSeen)
		ports = append(ports, p)
	}
	return ports, rows.Err()
}

func (s *Store) CreateScan(scan *Scan) (int64, error) {
	result, err := s.db.Exec(`
		INSERT INTO scans (subnet, started_at, scan_type) VALUES (?, ?, ?)
	`, scan.Subnet, scan.StartedAt.Format(time.RFC3339), scan.ScanType)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (s *Store) CompleteScan(id int64, devicesFound int) error {
	now := time.Now().Format(time.RFC3339)
	_, err := s.db.Exec(`
		UPDATE scans SET finished_at = ?, devices_found = ? WHERE id = ?
	`, now, devicesFound, id)
	return err
}

func (s *Store) ListScans(limit int) ([]*Scan, error) {
	rows, err := s.db.Query(`
		SELECT id, subnet, started_at, finished_at, devices_found, scan_type
		FROM scans ORDER BY started_at DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []*Scan
	for rows.Next() {
		sc := &Scan{}
		var startedAt string
		var finishedAt sql.NullString
		if err := rows.Scan(&sc.ID, &sc.Subnet, &startedAt, &finishedAt, &sc.DevicesFound, &sc.ScanType); err != nil {
			return nil, err
		}
		sc.StartedAt, _ = time.Parse(time.RFC3339, startedAt)
		if finishedAt.Valid {
			t, _ := time.Parse(time.RFC3339, finishedAt.String)
			sc.FinishedAt = &t
		}
		scans = append(scans, sc)
	}
	return scans, rows.Err()
}

func (s *Store) GetStats() (*Stats, error) {
	st := &Stats{}
	s.db.QueryRow(`SELECT COUNT(*) FROM devices`).Scan(&st.TotalDevices)
	s.db.QueryRow(`SELECT COUNT(*) FROM devices WHERE is_online = 1`).Scan(&st.OnlineDevices)
	s.db.QueryRow(`SELECT COUNT(*) FROM ports`).Scan(&st.TotalPorts)
	s.db.QueryRow(`SELECT COUNT(*) FROM scans`).Scan(&st.TotalScans)
	s.db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&st.TotalEvents)
	s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE severity IN ('critical','warning')`).Scan(&st.CriticalEvents)
	return st, nil
}

func (s *Store) InsertEvent(e *Event) error {
	_, err := s.db.Exec(`
		INSERT INTO events (device_id, source, severity, title, body_md, raw_data, received_at, tags)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, e.DeviceID, e.Source, e.Severity, e.Title, e.BodyMD, e.RawData, e.ReceivedAt.Format(time.RFC3339), e.Tags)
	if err == nil {
		s.logOp("events", "insert_event", e)
	}
	return err
}

func (s *Store) ListEvents(limit int, deviceID, severity, search string) ([]*Event, error) {
	query := `SELECT id, device_id, source, severity, title, body_md, raw_data, received_at, tags FROM events WHERE 1=1`
	args := []any{}

	if deviceID != "" {
		query += ` AND device_id = ?`
		args = append(args, deviceID)
	}
	if severity != "" {
		query += ` AND severity = ?`
		args = append(args, severity)
	}
	if search != "" {
		query += ` AND (title LIKE ? OR body_md LIKE ? OR tags LIKE ?)`
		like := "%" + search + "%"
		args = append(args, like, like, like)
	}

	query += ` ORDER BY received_at DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		e := &Event{}
		var receivedAt string
		if err := rows.Scan(&e.ID, &e.DeviceID, &e.Source, &e.Severity, &e.Title, &e.BodyMD, &e.RawData, &receivedAt, &e.Tags); err != nil {
			return nil, err
		}
		e.ReceivedAt, _ = time.Parse(time.RFC3339, receivedAt)
		events = append(events, e)
	}
	return events, rows.Err()
}

func (s *Store) HasRecentEvent(deviceID, source, title string, within time.Duration) bool {
	cutoff := time.Now().Add(-within).Format(time.RFC3339)
	var count int
	s.db.QueryRow(`
		SELECT COUNT(*) FROM events
		WHERE device_id = ? AND source = ? AND title = ? AND received_at > ?
	`, deviceID, source, title, cutoff).Scan(&count)
	return count > 0
}

func (s *Store) PruneEvents(maxAge time.Duration) error {
	cutoff := time.Now().Add(-maxAge).Format(time.RFC3339)
	_, err := s.db.Exec(`DELETE FROM events WHERE received_at < ?`, cutoff)
	return err
}

func (s *Store) MarkOffline(before time.Time) error {
	// Find devices going offline and record state changes
	rows, err := s.db.Query(`SELECT id FROM devices WHERE is_online = 1 AND last_seen < ?`, before.Format(time.RFC3339))
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id string
			rows.Scan(&id)
			s.RecordStateChange(id, "offline")
		}
	}
	_, err = s.db.Exec(`UPDATE devices SET is_online = 0 WHERE last_seen < ?`, before.Format(time.RFC3339))
	return err
}

// --- Oplog ---

func (s *Store) AppendOplog(table, op string, data any, nodeID string) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
		INSERT INTO oplog (table_name, operation, data, node_id, created_at) VALUES (?, ?, ?, ?, ?)
	`, table, op, string(jsonData), nodeID, time.Now().Format(time.RFC3339))
	return err
}

func (s *Store) GetOpsAfter(seq int64, limit int) ([]OplogEntry, error) {
	rows, err := s.db.Query(`
		SELECT seq, table_name, operation, data, node_id, created_at
		FROM oplog WHERE seq > ? ORDER BY seq LIMIT ?
	`, seq, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ops []OplogEntry
	for rows.Next() {
		var op OplogEntry
		if err := rows.Scan(&op.Seq, &op.TableName, &op.Operation, &op.Data, &op.NodeID, &op.CreatedAt); err != nil {
			return nil, err
		}
		ops = append(ops, op)
	}
	return ops, rows.Err()
}

func (s *Store) LatestOplogSeq() (int64, error) {
	var seq int64
	err := s.db.QueryRow(`SELECT COALESCE(MAX(seq), 0) FROM oplog`).Scan(&seq)
	return seq, err
}

func (s *Store) PruneOplog(maxAge time.Duration) error {
	cutoff := time.Now().Add(-maxAge).Format(time.RFC3339)
	_, err := s.db.Exec(`DELETE FROM oplog WHERE created_at < ?`, cutoff)
	return err
}

// --- Audit Log ---

func (s *Store) Audit(action, detail, remoteAddr string) {
	s.db.Exec(`INSERT INTO audit_log (action, detail, remote_addr, created_at) VALUES (?, ?, ?, ?)`,
		action, detail, remoteAddr, time.Now().Format(time.RFC3339))
}

func (s *Store) GetAuditLog(limit int) ([]map[string]string, error) {
	rows, err := s.db.Query(`SELECT action, detail, remote_addr, created_at FROM audit_log ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []map[string]string
	for rows.Next() {
		var action, detail, addr, at string
		rows.Scan(&action, &detail, &addr, &at)
		entries = append(entries, map[string]string{"action": action, "detail": detail, "remote_addr": addr, "created_at": at})
	}
	return entries, rows.Err()
}

// --- Device Tags ---

func (s *Store) GetDeviceTags(deviceID string) ([]string, error) {
	rows, err := s.db.Query(`SELECT tag FROM device_tags WHERE device_id = ? ORDER BY tag`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tags []string
	for rows.Next() {
		var t string
		rows.Scan(&t)
		tags = append(tags, t)
	}
	return tags, rows.Err()
}

func (s *Store) SetDeviceTags(deviceID string, tags []string) error {
	s.db.Exec(`DELETE FROM device_tags WHERE device_id = ?`, deviceID)
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		s.db.Exec(`INSERT OR IGNORE INTO device_tags (device_id, tag) VALUES (?, ?)`, deviceID, t)
	}
	return nil
}

func (s *Store) GetAllTags() ([]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT tag FROM device_tags ORDER BY tag`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tags []string
	for rows.Next() {
		var t string
		rows.Scan(&t)
		tags = append(tags, t)
	}
	return tags, rows.Err()
}

// --- Snapshots ---

func (s *Store) RecordSnapshot() error {
	stats, _ := s.GetStats()
	// Average latency from the last 5 minutes of readings
	var avgLat float64
	s.db.QueryRow(`SELECT COALESCE(AVG(rtt_ms), 0) FROM latency_history WHERE recorded_at > ?`,
		time.Now().Add(-5*time.Minute).Format(time.RFC3339)).Scan(&avgLat)

	_, err := s.db.Exec(`INSERT INTO snapshots (online_devices, total_events, avg_latency, recorded_at) VALUES (?, ?, ?, ?)`,
		stats.OnlineDevices, stats.TotalEvents, avgLat, time.Now().Format(time.RFC3339))
	return err
}

func (s *Store) GetSnapshots(hours int) ([]map[string]any, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour).Format(time.RFC3339)
	rows, err := s.db.Query(`
		SELECT online_devices, total_events, avg_latency, recorded_at
		FROM snapshots WHERE recorded_at > ? ORDER BY recorded_at
	`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var snaps []map[string]any
	for rows.Next() {
		var online, events int
		var lat float64
		var at string
		rows.Scan(&online, &events, &lat, &at)
		snaps = append(snaps, map[string]any{
			"online_devices": online, "total_events": events,
			"avg_latency": lat, "recorded_at": at,
		})
	}
	return snaps, rows.Err()
}

func (s *Store) PruneSnapshots(maxAge time.Duration) error {
	_, err := s.db.Exec(`DELETE FROM snapshots WHERE recorded_at < ?`, time.Now().Add(-maxAge).Format(time.RFC3339))
	return err
}

// --- Latency ---

func (s *Store) RecordLatency(deviceID string, rttMs float64) error {
	_, err := s.db.Exec(`
		INSERT INTO latency_history (device_id, rtt_ms, recorded_at) VALUES (?, ?, ?)
	`, deviceID, rttMs, time.Now().Format(time.RFC3339))
	return err
}

func (s *Store) GetLatencyHistory(deviceID string, limit int) ([]LatencyRecord, error) {
	var rows *sql.Rows
	var err error
	if deviceID != "" {
		rows, err = s.db.Query(`
			SELECT device_id, rtt_ms, recorded_at FROM latency_history
			WHERE device_id = ? ORDER BY recorded_at DESC LIMIT ?
		`, deviceID, limit)
	} else {
		rows, err = s.db.Query(`
			SELECT device_id, rtt_ms, recorded_at FROM latency_history
			ORDER BY recorded_at DESC LIMIT ?
		`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []LatencyRecord
	for rows.Next() {
		var r LatencyRecord
		if err := rows.Scan(&r.DeviceID, &r.RTTMs, &r.RecordedAt); err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, rows.Err()
}

func (s *Store) PruneLatency(maxAge time.Duration) error {
	cutoff := time.Now().Add(-maxAge).Format(time.RFC3339)
	_, err := s.db.Exec(`DELETE FROM latency_history WHERE recorded_at < ?`, cutoff)
	return err
}

// --- Device Notes ---

func (s *Store) GetDeviceNotes(deviceID string) (string, error) {
	var notes string
	err := s.db.QueryRow(`SELECT notes FROM device_notes WHERE device_id = ?`, deviceID).Scan(&notes)
	if err != nil {
		return "", nil // No notes yet
	}
	return notes, nil
}

func (s *Store) SetDeviceNotes(deviceID, notes string) error {
	_, err := s.db.Exec(`
		INSERT INTO device_notes (device_id, notes, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(device_id) DO UPDATE SET notes = excluded.notes, updated_at = excluded.updated_at
	`, deviceID, notes, time.Now().Format(time.RFC3339))
	return err
}

// --- Uptime History ---

// RecordStateChange logs a state transition if it differs from the last recorded state.
func (s *Store) RecordStateChange(deviceID, state string) error {
	// Check last recorded state
	var lastState string
	err := s.db.QueryRow(`
		SELECT state FROM uptime_history WHERE device_id = ? ORDER BY changed_at DESC LIMIT 1
	`, deviceID).Scan(&lastState)

	if err == nil && lastState == state {
		return nil // No change
	}

	_, err = s.db.Exec(`
		INSERT INTO uptime_history (device_id, state, changed_at) VALUES (?, ?, ?)
	`, deviceID, state, time.Now().Format(time.RFC3339))
	return err
}

// GetUptimeStats calculates uptime percentage and returns recent transitions.
func (s *Store) GetUptimeStats(deviceID string, since time.Duration) (*UptimeStats, error) {
	cutoff := time.Now().Add(-since).Format(time.RFC3339)

	rows, err := s.db.Query(`
		SELECT device_id, state, changed_at FROM uptime_history
		WHERE device_id = ? AND changed_at > ? ORDER BY changed_at
	`, deviceID, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []UptimeRecord
	for rows.Next() {
		var r UptimeRecord
		if err := rows.Scan(&r.DeviceID, &r.State, &r.ChangedAt); err != nil {
			return nil, err
		}
		records = append(records, r)
	}

	stats := &UptimeStats{Transitions: records}

	if len(records) == 0 {
		stats.UptimePct = 100.0
		return stats, nil
	}

	stats.LastChange = records[len(records)-1].ChangedAt

	// Calculate uptime percentage
	totalDuration := since.Seconds()
	onlineSecs := 0.0
	prevTime, _ := time.Parse(time.RFC3339, cutoff)
	prevState := "online" // Assume online before first record

	for _, r := range records {
		t, _ := time.Parse(time.RFC3339, r.ChangedAt)
		dur := t.Sub(prevTime).Seconds()
		if prevState == "online" {
			onlineSecs += dur
		}
		prevTime = t
		prevState = r.State
	}

	// Account for time from last transition to now
	remaining := time.Since(prevTime).Seconds()
	if prevState == "online" {
		onlineSecs += remaining
	}

	if totalDuration > 0 {
		stats.UptimePct = (onlineSecs / totalDuration) * 100
		if stats.UptimePct > 100 {
			stats.UptimePct = 100
		}
	}

	return stats, nil
}

// --- Device Adapters ---

func (s *Store) UpsertAdapter(a *DeviceAdapter) error {
	_, err := s.db.Exec(`
		INSERT INTO device_adapters (device_id, device_type, vendor, port, endpoints, generated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(device_id, port) DO UPDATE SET
			device_type = excluded.device_type, vendor = excluded.vendor,
			endpoints = excluded.endpoints, generated_at = excluded.generated_at
	`, a.DeviceID, a.DeviceType, a.Vendor, a.Port, a.Endpoints, a.GeneratedAt)
	return err
}

func (s *Store) GetAdapters(deviceID string) ([]*DeviceAdapter, error) {
	rows, err := s.db.Query(`
		SELECT id, device_id, device_type, vendor, port, endpoints, generated_at
		FROM device_adapters WHERE device_id = ? ORDER BY port
	`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var adapters []*DeviceAdapter
	for rows.Next() {
		a := &DeviceAdapter{}
		if err := rows.Scan(&a.ID, &a.DeviceID, &a.DeviceType, &a.Vendor, &a.Port, &a.Endpoints, &a.GeneratedAt); err != nil {
			return nil, err
		}
		adapters = append(adapters, a)
	}
	return adapters, rows.Err()
}

// --- Mesh Nodes ---

func (s *Store) UpsertMeshNode(n *MeshNode) error {
	_, err := s.db.Exec(`
		INSERT INTO mesh_nodes (node_id, name, address, node_type, last_seen)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(node_id) DO UPDATE SET
			name = excluded.name, address = excluded.address,
			node_type = excluded.node_type, last_seen = excluded.last_seen
	`, n.NodeID, n.Name, n.Address, n.NodeType, n.LastSeen)
	return err
}

func (s *Store) RemoveMeshNode(nodeID string) error {
	_, err := s.db.Exec(`DELETE FROM mesh_nodes WHERE node_id = ?`, nodeID)
	return err
}

func (s *Store) ListMeshNodes() ([]*MeshNode, error) {
	rows, err := s.db.Query(`SELECT node_id, name, address, node_type, last_seen FROM mesh_nodes ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []*MeshNode
	for rows.Next() {
		n := &MeshNode{}
		if err := rows.Scan(&n.NodeID, &n.Name, &n.Address, &n.NodeType, &n.LastSeen); err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	return nodes, rows.Err()
}
