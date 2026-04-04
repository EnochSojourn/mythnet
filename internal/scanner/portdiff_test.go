package scanner

import (
	"testing"
)

func TestIsDangerousPort(t *testing.T) {
	dangerous := []int{23, 445, 3389, 6379}
	safe := []int{22, 80, 443, 8080}

	for _, p := range dangerous {
		if !isDangerousPort(p) {
			t.Errorf("port %d should be dangerous", p)
		}
	}
	for _, p := range safe {
		if isDangerousPort(p) {
			t.Errorf("port %d should not be dangerous", p)
		}
	}
}

func TestPortChangesToEvents(t *testing.T) {
	changes := []PortChange{
		{DeviceID: "d1", DeviceIP: "10.0.0.1", Port: 80, Service: "http", Change: "opened"},
		{DeviceID: "d1", DeviceIP: "10.0.0.1", Port: 23, Service: "telnet", Change: "opened"},
		{DeviceID: "d1", DeviceIP: "10.0.0.1", Port: 22, Service: "ssh", Change: "closed"},
	}

	events := PortChangesToEvents(changes)
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	// Port 80 opened = info
	if events[0].Severity != "info" {
		t.Errorf("port 80 open should be info, got %s", events[0].Severity)
	}

	// Port 23 (telnet) opened = critical
	if events[1].Severity != "critical" {
		t.Errorf("telnet open should be critical, got %s", events[1].Severity)
	}

	// Port 22 closed = warning
	if events[2].Severity != "warning" {
		t.Errorf("port close should be warning, got %s", events[2].Severity)
	}
}
