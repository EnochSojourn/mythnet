package telemetry

import (
	"strings"
	"testing"
	"time"
)

func TestFormatSNMPTrap(t *testing.T) {
	vars := []SNMPVar{
		{OID: "1.3.6.1.2.1.2.2.1.1", Type: "Integer", Value: "3"},
	}
	event := FormatSNMPTrap("10.0.0.1", "1.3.6.1.6.3.1.1.5.3", vars, time.Now())

	if event.Source != "snmp_trap" {
		t.Errorf("expected source snmp_trap, got %s", event.Source)
	}
	if event.Severity != "warning" {
		t.Errorf("link down should be warning, got %s", event.Severity)
	}
	if !strings.Contains(event.Title, "Link Down") {
		t.Errorf("expected 'Link Down' in title, got %s", event.Title)
	}
	if !strings.Contains(event.BodyMD, "Variable Bindings") {
		t.Error("expected variable bindings table in markdown")
	}
}

func TestFormatSyslog(t *testing.T) {
	event := FormatSyslog("10.0.0.1", 4, 3, "fw01", "kernel", "iptables DROP", time.Now())

	if event.Source != "syslog" {
		t.Errorf("expected source syslog, got %s", event.Source)
	}
	// Severity 3 = critical
	if event.Severity != "critical" {
		t.Errorf("syslog severity 3 should be critical, got %s", event.Severity)
	}
	if !strings.Contains(event.BodyMD, "fw01") {
		t.Error("expected hostname in markdown")
	}
	if !strings.Contains(event.BodyMD, "auth") {
		t.Error("expected facility name in markdown")
	}
}

func TestFormatAPIResponse(t *testing.T) {
	headers := map[string]string{"Server": "nginx/1.24", "Content-Type": "text/html"}
	event := FormatAPIResponse("10.0.0.1", "http://10.0.0.1/", 200, headers, "<html>OK</html>", time.Now())

	if event.Severity != "info" {
		t.Errorf("200 should be info, got %s", event.Severity)
	}
	if !strings.Contains(event.BodyMD, "nginx/1.24") {
		t.Error("expected server header in markdown")
	}

	// Test error response
	event500 := FormatAPIResponse("10.0.0.1", "http://10.0.0.1/", 500, nil, "error", time.Now())
	if event500.Severity != "critical" {
		t.Errorf("500 should be critical, got %s", event500.Severity)
	}

	event403 := FormatAPIResponse("10.0.0.1", "http://10.0.0.1/", 403, nil, "", time.Now())
	if event403.Severity != "warning" {
		t.Errorf("403 should be warning, got %s", event403.Severity)
	}
}

func TestSyslogSeverityName(t *testing.T) {
	tests := []struct {
		sev      int
		expected string
	}{
		{0, "critical"},
		{4, "warning"},
		{6, "info"},
		{7, "debug"},
		{99, "info"},
	}

	for _, tt := range tests {
		got := syslogSeverityName(tt.sev)
		if got != tt.expected {
			t.Errorf("syslogSeverityName(%d): expected %q, got %q", tt.sev, tt.expected, got)
		}
	}
}

func TestSyslogFacilityName(t *testing.T) {
	if syslogFacilityName(0) != "kern" {
		t.Error("facility 0 should be kern")
	}
	if syslogFacilityName(4) != "auth" {
		t.Error("facility 4 should be auth")
	}
	if syslogFacilityName(99) != "facility99" {
		t.Error("unknown facility should return facilityN")
	}
}

func TestTruncate(t *testing.T) {
	if truncate("short", 100) != "short" {
		t.Error("short string should not be truncated")
	}
	got := truncate("this is a long string that should be cut", 20)
	if len(got) != 20 {
		t.Errorf("expected length 20, got %d", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Error("truncated string should end with ...")
	}
}

func TestJoinTags(t *testing.T) {
	if JoinTags([]string{"a", "b", "c"}) != "a,b,c" {
		t.Error("expected comma-joined tags")
	}
	if JoinTags(nil) != "" {
		t.Error("nil tags should return empty string")
	}
}
