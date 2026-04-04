package scanner

import (
	"encoding/binary"
	"net"
	"strings"
	"time"
)

// NetBIOSLookup queries a host for its NetBIOS name (Windows machine name).
func NetBIOSLookup(ip string, timeout time.Duration) string {
	conn, err := net.DialTimeout("udp", ip+":137", timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// NetBIOS Name Query packet
	query := []byte{
		0x80, 0x01, // Transaction ID
		0x00, 0x00, // Flags: query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Answer/Authority/Additional: 0
		0x20, // Name length (32 encoded bytes)
		// Encoded "*" (wildcard) name - CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
		0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x00,       // End of name
		0x00, 0x21, // Type: NBSTAT
		0x00, 0x01, // Class: IN
	}

	conn.Write(query)

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 57 {
		return ""
	}

	return parseNetBIOSResponse(buf[:n])
}

func parseNetBIOSResponse(data []byte) string {
	// Skip header (12 bytes) + query section
	if len(data) < 57 {
		return ""
	}

	// Find the answer section - skip to after the name in response
	offset := 12
	// Skip the name
	for offset < len(data) && data[offset] != 0 {
		if data[offset]&0xC0 == 0xC0 {
			offset += 2
			goto foundName
		}
		offset += int(data[offset]) + 1
	}
	offset++ // skip null terminator
foundName:
	if offset >= len(data) {
		return ""
	}

	// Skip type (2) + class (2) + TTL (4) + data length (2)
	offset += 10
	if offset >= len(data) {
		return ""
	}

	// Number of names
	numNames := int(data[offset])
	offset++

	if numNames == 0 || offset+18 > len(data) {
		return ""
	}

	// First name entry: 15 bytes name + 1 byte suffix + 2 bytes flags
	name := strings.TrimRight(string(data[offset:offset+15]), " \x00")
	suffix := data[offset+15]

	// Only return workstation names (suffix 0x00) or server names (suffix 0x20)
	if suffix == 0x00 || suffix == 0x20 {
		return name
	}

	// Try second name if first was a group
	if numNames > 1 && offset+36 <= len(data) {
		name2 := strings.TrimRight(string(data[offset+18:offset+33]), " \x00")
		suffix2 := data[offset+33]
		_ = binary.BigEndian // suppress unused import
		if suffix2 == 0x00 || suffix2 == 0x20 {
			return name2
		}
	}

	return name
}
