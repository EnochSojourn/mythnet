package scanner

import (
	"testing"
)

func TestCheckBannerVulns(t *testing.T) {
	tests := []struct {
		name     string
		service  string
		banner   string
		wantCVE  bool
		severity string
	}{
		{"OpenSSH vulnerable", "ssh", "SSH-2.0-OpenSSH_8.5p1", true, "critical"},
		{"OpenSSH recent", "ssh", "SSH-2.0-OpenSSH_9.9p1", false, ""},
		{"vsftpd backdoor", "ftp", "220 vsftpd 2.3.4", true, "critical"},
		{"vsftpd safe", "ftp", "220 vsftpd 3.0.5", false, ""},
		{"Telnet always bad", "telnet", "login:", true, "critical"},
		{"Apache vuln", "http", "Apache/2.4.49", true, "critical"},
		{"Apache safe", "http", "Apache/2.4.58", false, ""},
		{"nginx old", "http", "nginx/1.16.1", true, "warning"},
		{"nginx new", "http", "nginx/1.24.0", false, ""},
		{"No banner", "ssh", "", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			events := CheckBannerVulns("d1", "10.0.0.1", 22, tt.service, tt.banner)
			if tt.wantCVE && len(events) == 0 {
				t.Errorf("expected vulnerability finding for banner %q", tt.banner)
			}
			if !tt.wantCVE && len(events) > 0 {
				t.Errorf("unexpected vulnerability for banner %q: %s", tt.banner, events[0].Title)
			}
			if tt.wantCVE && len(events) > 0 && events[0].Severity != tt.severity {
				t.Errorf("expected severity %s, got %s", tt.severity, events[0].Severity)
			}
		})
	}
}
