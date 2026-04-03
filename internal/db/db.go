package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db      *sql.DB
	oplogFn func(table, op string, data any) // optional mesh replication hook
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

func (s *Store) logOp(table, op string, data any) {
	if s.oplogFn != nil {
		s.oplogFn(table, op, data)
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

func (s *Store) ListEvents(limit int, deviceID, severity string) ([]*Event, error) {
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
	_, err := s.db.Exec(`UPDATE devices SET is_online = 0 WHERE last_seen < ?`, before.Format(time.RFC3339))
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
