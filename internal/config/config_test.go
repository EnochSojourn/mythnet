package config

import (
	"os"
	"testing"
	"time"
)

func TestDefault(t *testing.T) {
	cfg := Default()

	if cfg.Server.Port != 8080 {
		t.Errorf("expected default port 8080, got %d", cfg.Server.Port)
	}
	if cfg.Scanner.IntervalDuration != 5*time.Minute {
		t.Errorf("expected 5m interval, got %v", cfg.Scanner.IntervalDuration)
	}
	if cfg.Scanner.TimeoutDuration != 2*time.Second {
		t.Errorf("expected 2s timeout, got %v", cfg.Scanner.TimeoutDuration)
	}
	if len(cfg.Scanner.Ports) == 0 {
		t.Error("expected default ports list")
	}
	if cfg.Database.Path != "mythnet.db" {
		t.Errorf("expected default db path, got %s", cfg.Database.Path)
	}
}

func TestLoadMissing(t *testing.T) {
	cfg, err := Load("/nonexistent/config.yaml")
	if err != nil {
		t.Fatalf("loading missing config should not error: %v", err)
	}
	if cfg.Server.Port != 8080 {
		t.Error("should return defaults when file missing")
	}
}

func TestLoadValid(t *testing.T) {
	tmp, _ := os.CreateTemp("", "mythnet-config-*.yaml")
	tmp.WriteString(`
server:
  port: 9090
scanner:
  subnets: ["10.0.0.0/24"]
  interval: "10m"
  timeout: "500ms"
database:
  path: "test.db"
`)
	tmp.Close()
	defer os.Remove(tmp.Name())

	cfg, err := Load(tmp.Name())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Server.Port != 9090 {
		t.Errorf("expected port 9090, got %d", cfg.Server.Port)
	}
	if len(cfg.Scanner.Subnets) != 1 || cfg.Scanner.Subnets[0] != "10.0.0.0/24" {
		t.Errorf("expected subnets [10.0.0.0/24], got %v", cfg.Scanner.Subnets)
	}
	if cfg.Scanner.IntervalDuration != 10*time.Minute {
		t.Errorf("expected 10m, got %v", cfg.Scanner.IntervalDuration)
	}
	if cfg.Scanner.TimeoutDuration != 500*time.Millisecond {
		t.Errorf("expected 500ms, got %v", cfg.Scanner.TimeoutDuration)
	}
	if cfg.Database.Path != "test.db" {
		t.Errorf("expected test.db, got %s", cfg.Database.Path)
	}
	// Unset fields should retain defaults
	if len(cfg.Scanner.Ports) == 0 {
		t.Error("ports should retain defaults when not overridden")
	}
}

func TestLoadInvalidDuration(t *testing.T) {
	tmp, _ := os.CreateTemp("", "mythnet-config-*.yaml")
	tmp.WriteString(`scanner: { interval: "not-a-duration" }`)
	tmp.Close()
	defer os.Remove(tmp.Name())

	_, err := Load(tmp.Name())
	if err == nil {
		t.Error("expected error for invalid duration")
	}
}
