package db

import (
	"fmt"
	"testing"
	"time"
)

func TestHealthScoreEmpty(t *testing.T) {
	s := testStore(t)
	h := s.CalculateHealthScore()
	if h.Score < 0 || h.Score > 100 {
		t.Errorf("score out of range: %d", h.Score)
	}
	if h.Grade == "" {
		t.Error("grade should not be empty")
	}
}

func TestHealthScorePerfect(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	for i := 0; i < 5; i++ {
		s.UpsertDevice(&Device{
			ID: fmt.Sprintf("d%d", i), IP: fmt.Sprintf("10.0.0.%d", i),
			FirstSeen: now, LastSeen: now, IsOnline: true,
		})
	}

	h := s.CalculateHealthScore()
	if h.Score != 100 {
		t.Errorf("expected 100 for all-online no-events, got %d", h.Score)
	}
	if h.Grade != "A" {
		t.Errorf("expected grade A, got %s", h.Grade)
	}
}

func TestHealthScoreDegraded(t *testing.T) {
	s := testStore(t)
	now := time.Now()

	// 2 online, 2 offline = 50% availability
	s.UpsertDevice(&Device{ID: "a", IP: "10.0.0.1", FirstSeen: now, LastSeen: now, IsOnline: true})
	s.UpsertDevice(&Device{ID: "b", IP: "10.0.0.2", FirstSeen: now, LastSeen: now, IsOnline: true})
	s.UpsertDevice(&Device{ID: "c", IP: "10.0.0.3", FirstSeen: now, LastSeen: now, IsOnline: false})
	s.UpsertDevice(&Device{ID: "d", IP: "10.0.0.4", FirstSeen: now, LastSeen: now, IsOnline: false})

	// Add critical events
	s.InsertEvent(&Event{Source: "test", Severity: "critical", Title: "bad thing", BodyMD: "x", ReceivedAt: now})
	s.InsertEvent(&Event{Source: "test", Severity: "critical", Title: "worse thing", BodyMD: "x", ReceivedAt: now})

	h := s.CalculateHealthScore()
	if h.Score >= 80 {
		t.Errorf("expected degraded score (<80) with offline devices + criticals, got %d", h.Score)
	}
	if len(h.Issues) < 2 {
		t.Errorf("expected multiple issues, got %d", len(h.Issues))
	}
}
