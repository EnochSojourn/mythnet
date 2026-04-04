package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/mythnet/mythnet/internal/db"
)

// TLSInfo holds certificate details from an HTTPS port.
type TLSInfo struct {
	Port       int
	Subject    string
	Issuer     string
	NotAfter   time.Time
	DaysLeft   int
	SAN        []string
	IsExpired  bool
	IsSelfSign bool
}

// CheckTLS connects to an HTTPS port and retrieves certificate info.
func CheckTLS(ip string, port int, timeout time.Duration) *TLSInfo {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: timeout},
		"tcp", addr,
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		return nil
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}

	cert := certs[0]
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)

	info := &TLSInfo{
		Port:       port,
		Subject:    cert.Subject.CommonName,
		Issuer:     cert.Issuer.CommonName,
		NotAfter:   cert.NotAfter,
		DaysLeft:   daysLeft,
		IsExpired:  time.Now().After(cert.NotAfter),
		IsSelfSign: cert.Subject.CommonName == cert.Issuer.CommonName,
	}

	for _, san := range cert.DNSNames {
		info.SAN = append(info.SAN, san)
	}

	return info
}

// TLSInfoToEvent creates a warning/critical event for expiring certificates.
func TLSInfoToEvent(deviceID, deviceIP string, info *TLSInfo) *db.Event {
	severity := "info"
	if info.IsExpired {
		severity = "critical"
	} else if info.DaysLeft <= 7 {
		severity = "critical"
	} else if info.DaysLeft <= 30 {
		severity = "warning"
	}

	title := fmt.Sprintf("TLS cert on %s:%d — %d days left", deviceIP, info.Port, info.DaysLeft)
	if info.IsExpired {
		title = fmt.Sprintf("TLS cert EXPIRED on %s:%d", deviceIP, info.Port)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "## TLS Certificate — %s:%d\n\n", deviceIP, info.Port)
	fmt.Fprintf(&b, "**Subject:** %s  \n", info.Subject)
	fmt.Fprintf(&b, "**Issuer:** %s  \n", info.Issuer)
	fmt.Fprintf(&b, "**Expires:** %s  \n", info.NotAfter.Format("2006-01-02"))
	fmt.Fprintf(&b, "**Days Left:** %d  \n", info.DaysLeft)
	if info.IsSelfSign {
		b.WriteString("**Self-Signed:** Yes  \n")
	}
	if len(info.SAN) > 0 {
		fmt.Fprintf(&b, "**SANs:** %s  \n", strings.Join(info.SAN, ", "))
	}
	if info.IsExpired {
		b.WriteString("\n> **EXPIRED** — This certificate has expired and clients will reject connections.\n")
	} else if info.DaysLeft <= 30 {
		b.WriteString("\n> **Expiring soon** — Renew this certificate before it expires.\n")
	}

	return &db.Event{
		DeviceID:   deviceID,
		Source:     "tls_check",
		Severity:   severity,
		Title:      title,
		BodyMD:     b.String(),
		ReceivedAt: time.Now(),
		Tags:       fmt.Sprintf("tls,cert,port_%d", info.Port),
	}
}
