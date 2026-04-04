package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/mythnet/mythnet/internal/db"
)

// SecurityHeader represents an HTTP security header check result.
type SecurityHeader struct {
	Header  string `json:"header"`
	Present bool   `json:"present"`
	Value   string `json:"value,omitempty"`
	Rating  string `json:"rating"` // "good", "warning", "critical"
	Note    string `json:"note"`
}

// TLSAuditResult holds TLS configuration findings.
type TLSAuditResult struct {
	Version    string   `json:"version"`
	CipherSuite string `json:"cipher_suite"`
	WeakCiphers []string `json:"weak_ciphers,omitempty"`
	Rating     string   `json:"rating"`
}

// AuditHTTPSecurity checks HTTP security headers on a web server.
func AuditHTTPSecurity(ip string, port int, timeout time.Duration) ([]SecurityHeader, error) {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(fmt.Sprintf("%s://%s:%d/", scheme, ip, port))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	checks := []struct {
		header   string
		required bool
		note     string
	}{
		{"Strict-Transport-Security", true, "Enforces HTTPS connections"},
		{"Content-Security-Policy", true, "Prevents XSS and injection attacks"},
		{"X-Frame-Options", true, "Prevents clickjacking"},
		{"X-Content-Type-Options", true, "Prevents MIME-type sniffing"},
		{"X-XSS-Protection", false, "Legacy XSS protection (CSP preferred)"},
		{"Referrer-Policy", false, "Controls referrer information leakage"},
		{"Permissions-Policy", false, "Controls browser feature access"},
		{"Cache-Control", false, "Controls caching of sensitive data"},
	}

	var results []SecurityHeader
	for _, c := range checks {
		val := resp.Header.Get(c.header)
		rating := "good"
		if val == "" {
			if c.required {
				rating = "warning"
			} else {
				rating = "info"
			}
		}

		results = append(results, SecurityHeader{
			Header:  c.header,
			Present: val != "",
			Value:   val,
			Rating:  rating,
			Note:    c.note,
		})
	}

	// Check for information leakage
	if server := resp.Header.Get("Server"); server != "" {
		results = append(results, SecurityHeader{
			Header: "Server", Present: true, Value: server,
			Rating: "warning", Note: "Server version disclosure — consider removing",
		})
	}
	if powered := resp.Header.Get("X-Powered-By"); powered != "" {
		results = append(results, SecurityHeader{
			Header: "X-Powered-By", Present: true, Value: powered,
			Rating: "warning", Note: "Technology disclosure — remove this header",
		})
	}

	return results, nil
}

// AuditTLS checks the TLS configuration of an HTTPS server.
func AuditTLS(ip string, port int, timeout time.Duration) (*TLSAuditResult, error) {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: timeout},
		"tcp", fmt.Sprintf("%s:%d", ip, port),
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	result := &TLSAuditResult{
		Version:     tlsVersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		Rating:      "good",
	}

	// Check for weak TLS versions
	if state.Version < tls.VersionTLS12 {
		result.Rating = "critical"
		result.WeakCiphers = append(result.WeakCiphers, fmt.Sprintf("TLS version %s is deprecated", result.Version))
	}

	// Check cipher suite strength
	cipher := tls.CipherSuiteName(state.CipherSuite)
	weakPatterns := []string{"RC4", "3DES", "CBC", "NULL", "EXPORT"}
	for _, weak := range weakPatterns {
		if strings.Contains(strings.ToUpper(cipher), weak) {
			result.Rating = "warning"
			result.WeakCiphers = append(result.WeakCiphers, fmt.Sprintf("Weak cipher: %s", cipher))
			break
		}
	}

	return result, nil
}

// SecurityAuditToEvent generates a Markdown event from HTTP security audit results.
func SecurityAuditToEvent(deviceID, deviceIP string, port int, headers []SecurityHeader, tlsResult *TLSAuditResult) *db.Event {
	var b strings.Builder
	fmt.Fprintf(&b, "## HTTP Security Audit — %s:%d\n\n", deviceIP, port)

	// Count issues
	warnings := 0
	for _, h := range headers {
		if h.Rating == "warning" || h.Rating == "critical" {
			warnings++
		}
	}

	severity := "info"
	if warnings >= 4 {
		severity = "critical"
	} else if warnings >= 2 {
		severity = "warning"
	}

	b.WriteString("### Security Headers\n\n")
	b.WriteString("| Header | Status | Value |\n")
	b.WriteString("|--------|--------|-------|\n")
	for _, h := range headers {
		status := "✓"
		if !h.Present && (h.Rating == "warning" || h.Rating == "critical") {
			status = "✗ MISSING"
		} else if h.Rating == "warning" {
			status = "⚠"
		}
		val := h.Value
		if val == "" {
			val = "—"
		}
		if len(val) > 50 {
			val = val[:50] + "..."
		}
		fmt.Fprintf(&b, "| %s | %s | %s |\n", h.Header, status, val)
	}

	if tlsResult != nil {
		fmt.Fprintf(&b, "\n### TLS Configuration\n\n")
		fmt.Fprintf(&b, "- **Version:** %s\n", tlsResult.Version)
		fmt.Fprintf(&b, "- **Cipher:** %s\n", tlsResult.CipherSuite)
		if len(tlsResult.WeakCiphers) > 0 {
			severity = "warning"
			for _, w := range tlsResult.WeakCiphers {
				fmt.Fprintf(&b, "- **⚠ %s**\n", w)
			}
		}
	}

	title := fmt.Sprintf("Security audit — %s:%d (%d issues)", deviceIP, port, warnings)

	return &db.Event{
		DeviceID:   deviceID,
		Source:     "http_audit",
		Severity:   severity,
		Title:      title,
		BodyMD:     b.String(),
		ReceivedAt: time.Now(),
		Tags:       fmt.Sprintf("audit,http,security,port_%d", port),
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
