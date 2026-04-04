package db

import (
	"fmt"
	"testing"
	"time"
)

func BenchmarkUpsertDevice(b *testing.B) {
	s := benchStore(b)
	now := time.Now()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.UpsertDevice(&Device{
			ID: fmt.Sprintf("d%d", i), IP: fmt.Sprintf("10.0.%d.%d", i/256, i%256),
			Hostname: "bench", FirstSeen: now, LastSeen: now, IsOnline: true,
		})
	}
}

func BenchmarkUpsertPort(b *testing.B) {
	s := benchStore(b)
	now := time.Now()
	s.UpsertDevice(&Device{ID: "d1", IP: "10.0.0.1", FirstSeen: now, LastSeen: now})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.UpsertPort(&Port{
			DeviceID: "d1", Port: i%65535 + 1, Protocol: "tcp", State: "open", LastSeen: now,
		})
	}
}

func BenchmarkInsertEvent(b *testing.B) {
	s := benchStore(b)
	now := time.Now()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.InsertEvent(&Event{
			Source: "bench", Severity: "info", Title: fmt.Sprintf("event %d", i),
			BodyMD: "## Bench", ReceivedAt: now, Tags: "bench",
		})
	}
}

func BenchmarkListDevices(b *testing.B) {
	s := benchStore(b)
	now := time.Now()
	for i := 0; i < 100; i++ {
		s.UpsertDevice(&Device{
			ID: fmt.Sprintf("d%d", i), IP: fmt.Sprintf("10.0.0.%d", i),
			FirstSeen: now, LastSeen: now, IsOnline: true,
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.ListDevices()
	}
}

func BenchmarkGetStats(b *testing.B) {
	s := benchStore(b)
	now := time.Now()
	for i := 0; i < 50; i++ {
		s.UpsertDevice(&Device{ID: fmt.Sprintf("d%d", i), IP: fmt.Sprintf("10.0.0.%d", i), FirstSeen: now, LastSeen: now, IsOnline: true})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.GetStats()
	}
}

func BenchmarkHealthScore(b *testing.B) {
	s := benchStore(b)
	now := time.Now()
	for i := 0; i < 20; i++ {
		s.UpsertDevice(&Device{ID: fmt.Sprintf("d%d", i), IP: fmt.Sprintf("10.0.0.%d", i), FirstSeen: now, LastSeen: now, IsOnline: true})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.CalculateHealthScore()
	}
}

func benchStore(b *testing.B) *Store {
	b.Helper()
	s, err := New(":memory:")
	if err != nil {
		b.Fatalf("create store: %v", err)
	}
	b.Cleanup(func() { s.Close() })
	return s
}
