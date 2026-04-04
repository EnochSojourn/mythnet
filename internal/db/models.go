package db

import "time"

type Device struct {
	ID         string    `json:"id"`
	IP         string    `json:"ip"`
	MAC        string    `json:"mac,omitempty"`
	Hostname   string    `json:"hostname,omitempty"`
	Vendor     string    `json:"vendor,omitempty"`
	OSGuess    string    `json:"os_guess,omitempty"`
	DeviceType string    `json:"device_type,omitempty"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	IsOnline   bool      `json:"is_online"`
	Ports      []Port    `json:"ports,omitempty"`
}

type Port struct {
	DeviceID string    `json:"device_id"`
	Port     int       `json:"port"`
	Protocol string    `json:"protocol"`
	State    string    `json:"state"`
	Service  string    `json:"service,omitempty"`
	Banner   string    `json:"banner,omitempty"`
	LastSeen time.Time `json:"last_seen"`
}

type Scan struct {
	ID           int64      `json:"id"`
	Subnet       string     `json:"subnet"`
	StartedAt    time.Time  `json:"started_at"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
	DevicesFound int        `json:"devices_found"`
	ScanType     string     `json:"scan_type"`
}

type Event struct {
	ID         int64     `json:"id"`
	DeviceID   string    `json:"device_id,omitempty"`
	Source     string    `json:"source"`
	Severity   string    `json:"severity"`
	Title      string    `json:"title"`
	BodyMD     string    `json:"body_md"`
	RawData    string    `json:"raw_data,omitempty"`
	ReceivedAt time.Time `json:"received_at"`
	Tags       string    `json:"tags,omitempty"`
}

type OplogEntry struct {
	Seq       int64  `json:"seq"`
	TableName string `json:"table"`
	Operation string `json:"operation"`
	Data      string `json:"data"`
	NodeID    string `json:"node_id"`
	CreatedAt string `json:"created_at"`
}

type MeshNode struct {
	NodeID   string `json:"node_id"`
	Name     string `json:"name"`
	Address  string `json:"address"`
	NodeType string `json:"node_type"`
	LastSeen string `json:"last_seen"`
}

type DeviceAdapter struct {
	ID          int64  `json:"id"`
	DeviceID    string `json:"device_id"`
	DeviceType  string `json:"device_type"`
	Vendor      string `json:"vendor"`
	Port        int    `json:"port"`
	Endpoints   string `json:"endpoints"` // JSON array
	GeneratedAt string `json:"generated_at"`
}

type Stats struct {
	TotalDevices   int `json:"total_devices"`
	OnlineDevices  int `json:"online_devices"`
	TotalPorts     int `json:"total_ports"`
	TotalScans     int `json:"total_scans"`
	TotalEvents    int `json:"total_events"`
	CriticalEvents int `json:"critical_events"`
}
