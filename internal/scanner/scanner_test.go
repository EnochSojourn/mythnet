package scanner

import (
	"testing"
)

func TestEnumerateSubnet(t *testing.T) {
	tests := []struct {
		cidr     string
		expected int
	}{
		{"192.168.1.0/24", 254},
		{"10.0.0.0/30", 2},
		{"172.16.0.0/28", 14},
	}

	for _, tt := range tests {
		ips, err := enumerateSubnet(tt.cidr)
		if err != nil {
			t.Errorf("enumerate %s: %v", tt.cidr, err)
			continue
		}
		if len(ips) != tt.expected {
			t.Errorf("enumerate %s: expected %d IPs, got %d", tt.cidr, tt.expected, len(ips))
		}
	}
}

func TestEnumerateSubnetInvalid(t *testing.T) {
	_, err := enumerateSubnet("not-a-cidr")
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestDeviceID(t *testing.T) {
	// Same MAC should produce same ID
	id1 := deviceID("AA:BB:CC:DD:EE:FF", "10.0.0.1")
	id2 := deviceID("AA:BB:CC:DD:EE:FF", "10.0.0.2")
	if id1 != id2 {
		t.Error("same MAC should produce same device ID regardless of IP")
	}

	// No MAC falls back to IP
	id3 := deviceID("", "10.0.0.1")
	id4 := deviceID("", "10.0.0.2")
	if id3 == id4 {
		t.Error("different IPs without MAC should produce different IDs")
	}
}

func TestLookupVendor(t *testing.T) {
	tests := []struct {
		mac      string
		expected string
	}{
		{"00:00:0C:12:34:56", "Cisco"},
		{"B8:27:EB:AA:BB:CC", "Raspberry Pi"},
		{"00:50:56:11:22:33", "VMware"},
		{"FF:FF:FF:FF:FF:FF", ""},
		{"", ""},
	}

	for _, tt := range tests {
		got := LookupVendor(tt.mac)
		if got != tt.expected {
			t.Errorf("LookupVendor(%q): expected %q, got %q", tt.mac, tt.expected, got)
		}
	}
}

func TestGuessService(t *testing.T) {
	tests := []struct {
		port     int
		expected string
	}{
		{22, "ssh"},
		{80, "http"},
		{443, "https"},
		{3306, "mysql"},
		{99999, ""},
	}

	for _, tt := range tests {
		got := GuessService(tt.port)
		if got != tt.expected {
			t.Errorf("GuessService(%d): expected %q, got %q", tt.port, tt.expected, got)
		}
	}
}

func TestIdentifyServiceFromBanner(t *testing.T) {
	tests := []struct {
		banner   string
		expected string
	}{
		{"SSH-2.0-OpenSSH_8.9", "ssh"},
		{"220 mail.example.com SMTP ready", "smtp"},
		{"220 ftp.example.com FTP ready", "ftp"},
		{"HTTP/1.1 200 OK", "http"},
		{"RFB 003.008", "vnc"},
		{"random garbage", ""},
	}

	for _, tt := range tests {
		got := IdentifyServiceFromBanner(tt.banner)
		if got != tt.expected {
			t.Errorf("IdentifyServiceFromBanner(%q): expected %q, got %q", tt.banner, tt.expected, got)
		}
	}
}

func TestFingerprint(t *testing.T) {
	// Windows-like port combo
	ports := []PortResult{
		{Port: 135, Open: true}, {Port: 139, Open: true}, {Port: 445, Open: true},
	}
	fp := Fingerprint(ports, "", "")
	if fp.OS != "Windows" {
		t.Errorf("expected Windows, got %s", fp.OS)
	}

	// Linux with SSH
	ports = []PortResult{{Port: 22, Open: true}}
	fp = Fingerprint(ports, "", "")
	if fp.OS != "Linux" {
		t.Errorf("expected Linux, got %s", fp.OS)
	}

	// Cisco vendor
	fp = Fingerprint(nil, "Cisco", "")
	if fp.DeviceType != "Network Equipment" {
		t.Errorf("expected Network Equipment, got %s", fp.DeviceType)
	}
}

func TestNormalizeMAC(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF"},
		{"AA-BB-CC-DD-EE-FF", "AA:BB:CC:DD:EE:FF"},
		{"a:b:c:d:e:f", "0A:0B:0C:0D:0E:0F"},
	}

	for _, tt := range tests {
		got := normalizeMAC(tt.input)
		if got != tt.expected {
			t.Errorf("normalizeMAC(%q): expected %q, got %q", tt.input, tt.expected, got)
		}
	}
}
