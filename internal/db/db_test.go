package db

import (
	"os"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	tmp, _ := os.CreateTemp("", "mythnet-test-*.db")
	tmp.Close()
	t.Cleanup(func() { os.Remove(tmp.Name()) })

	store, err := New(tmp.Name())
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestDeviceCRUD(t *testing.T) {
	s := testStore(t)
	now := time.Now()

	d := &Device{
		ID: "test123", IP: "192.168.1.1", MAC: "AA:BB:CC:DD:EE:FF",
		Hostname: "testhost", Vendor: "TestVendor", OSGuess: "Linux",
		DeviceType: "Server", FirstSeen: now, LastSeen: now, IsOnline: true,
	}

	if err := s.UpsertDevice(d); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := s.GetDevice("test123")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.IP != "192.168.1.1" {
		t.Errorf("expected IP 192.168.1.1, got %s", got.IP)
	}
	if got.Hostname != "testhost" {
		t.Errorf("expected hostname testhost, got %s", got.Hostname)
	}
	if !got.IsOnline {
		t.Error("expected online")
	}

	// Update device
	d.Hostname = "updated"
	d.LastSeen = now.Add(time.Minute)
	s.UpsertDevice(d)

	got, _ = s.GetDevice("test123")
	if got.Hostname != "updated" {
		t.Errorf("expected updated hostname, got %s", got.Hostname)
	}

	// List
	devices, err := s.ListDevices()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(devices) != 1 {
		t.Errorf("expected 1 device, got %d", len(devices))
	}
}

func TestPortCRUD(t *testing.T) {
	s := testStore(t)
	now := time.Now()

	s.UpsertDevice(&Device{ID: "d1", IP: "10.0.0.1", FirstSeen: now, LastSeen: now})

	p := &Port{DeviceID: "d1", Port: 22, Protocol: "tcp", State: "open", Service: "ssh", LastSeen: now}
	if err := s.UpsertPort(p); err != nil {
		t.Fatalf("upsert port: %v", err)
	}

	ports, err := s.GetDevicePorts("d1")
	if err != nil {
		t.Fatalf("get ports: %v", err)
	}
	if len(ports) != 1 || ports[0].Port != 22 {
		t.Errorf("expected port 22, got %v", ports)
	}
}

func TestEventCRUD(t *testing.T) {
	s := testStore(t)
	now := time.Now()

	e := &Event{
		DeviceID: "d1", Source: "test", Severity: "warning",
		Title: "test event", BodyMD: "## Test", ReceivedAt: now, Tags: "test",
	}
	if err := s.InsertEvent(e); err != nil {
		t.Fatalf("insert event: %v", err)
	}

	events, err := s.ListEvents(10, "", "", "")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Title != "test event" {
		t.Errorf("expected title 'test event', got %s", events[0].Title)
	}

	// Search
	found, _ := s.ListEvents(10, "", "", "test")
	if len(found) != 1 {
		t.Errorf("search 'test' should find 1 event, got %d", len(found))
	}
	notFound, _ := s.ListEvents(10, "", "", "nonexistent")
	if len(notFound) != 0 {
		t.Errorf("search 'nonexistent' should find 0, got %d", len(notFound))
	}

	// Filter by severity
	warnings, _ := s.ListEvents(10, "", "warning", "")
	if len(warnings) != 1 {
		t.Errorf("expected 1 warning, got %d", len(warnings))
	}
	criticals, _ := s.ListEvents(10, "", "critical", "")
	if len(criticals) != 0 {
		t.Errorf("expected 0 criticals, got %d", len(criticals))
	}
}

func TestStats(t *testing.T) {
	s := testStore(t)
	now := time.Now()

	s.UpsertDevice(&Device{ID: "a", IP: "10.0.0.1", FirstSeen: now, LastSeen: now, IsOnline: true})
	s.UpsertDevice(&Device{ID: "b", IP: "10.0.0.2", FirstSeen: now, LastSeen: now, IsOnline: false})
	s.UpsertPort(&Port{DeviceID: "a", Port: 80, Protocol: "tcp", State: "open", LastSeen: now})

	stats, err := s.GetStats()
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.TotalDevices != 2 {
		t.Errorf("expected 2 devices, got %d", stats.TotalDevices)
	}
	if stats.OnlineDevices != 1 {
		t.Errorf("expected 1 online, got %d", stats.OnlineDevices)
	}
	if stats.TotalPorts != 1 {
		t.Errorf("expected 1 port, got %d", stats.TotalPorts)
	}
}

func TestMarkOffline(t *testing.T) {
	s := testStore(t)
	old := time.Now().Add(-1 * time.Hour)
	recent := time.Now()

	s.UpsertDevice(&Device{ID: "old", IP: "10.0.0.1", FirstSeen: old, LastSeen: old, IsOnline: true})
	s.UpsertDevice(&Device{ID: "new", IP: "10.0.0.2", FirstSeen: recent, LastSeen: recent, IsOnline: true})

	s.MarkOffline(time.Now().Add(-30 * time.Minute))

	d1, _ := s.GetDevice("old")
	d2, _ := s.GetDevice("new")
	if d1.IsOnline {
		t.Error("old device should be offline")
	}
	if !d2.IsOnline {
		t.Error("new device should still be online")
	}
}

func TestDeviceNotes(t *testing.T) {
	s := testStore(t)

	notes, _ := s.GetDeviceNotes("d1")
	if notes != "" {
		t.Error("expected empty notes for unknown device")
	}

	s.SetDeviceNotes("d1", "important server")
	notes, _ = s.GetDeviceNotes("d1")
	if notes != "important server" {
		t.Errorf("expected 'important server', got %s", notes)
	}
}

func TestDeviceTags(t *testing.T) {
	s := testStore(t)

	s.SetDeviceTags("d1", []string{"production", "critical"})
	tags, _ := s.GetDeviceTags("d1")
	if len(tags) != 2 {
		t.Fatalf("expected 2 tags, got %d", len(tags))
	}

	all, _ := s.GetAllTags()
	if len(all) != 2 {
		t.Errorf("expected 2 unique tags, got %d", len(all))
	}

	// Update tags
	s.SetDeviceTags("d1", []string{"staging"})
	tags, _ = s.GetDeviceTags("d1")
	if len(tags) != 1 || tags[0] != "staging" {
		t.Errorf("expected [staging], got %v", tags)
	}
}

func TestUptimeHistory(t *testing.T) {
	s := testStore(t)

	s.RecordStateChange("d1", "online")
	s.RecordStateChange("d1", "online") // duplicate — should be ignored
	s.RecordStateChange("d1", "offline")

	stats, err := s.GetUptimeStats("d1", 24*time.Hour)
	if err != nil {
		t.Fatalf("uptime stats: %v", err)
	}
	if len(stats.Transitions) != 2 {
		t.Errorf("expected 2 transitions (deduped), got %d", len(stats.Transitions))
	}
}

func TestHasRecentEvent(t *testing.T) {
	s := testStore(t)
	now := time.Now()

	s.InsertEvent(&Event{DeviceID: "d1", Source: "test", Severity: "info", Title: "test title", BodyMD: "body", ReceivedAt: now})

	if !s.HasRecentEvent("d1", "test", "test title", time.Hour) {
		t.Error("should find recent event")
	}
	if s.HasRecentEvent("d1", "test", "different title", time.Hour) {
		t.Error("should not find event with different title")
	}
}
