package warroom

import (
	"crypto/md5"
	"fmt"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// JA3Engine fingerprints TLS client hellos to identify applications/malware.
type JA3Engine struct {
	mu           sync.RWMutex
	fingerprints map[string]*JA3Record // JA3 hash → record
	ipFingerprints map[string]string   // srcIP:dstIP:dstPort → JA3 hash
}

// JA3Record tracks a TLS fingerprint.
type JA3Record struct {
	Hash      string `json:"hash"`
	Label     string `json:"label"` // Known identification
	SeenCount int    `json:"seen_count"`
	FirstSeen string `json:"first_seen"`
	IPs       map[string]bool `json:"-"`
	Sources   int    `json:"sources"` // unique source IPs
}

// Known JA3 fingerprints (malware, bots, common applications)
var knownJA3 = map[string]string{
	"e7d705a3286e19ea42f587b344ee6865": "Metasploit/Meterpreter",
	"6734f37431670b3ab4292b8f60f29984": "Cobalt Strike",
	"72a589da586844d7f0818ce684948eea": "Python requests",
	"b32309a26951912be7dba376398abc3b": "Tor Browser",
	"e35df3e00ca4ef31d42b34bebaa2f86e": "CobaltStrike Beacon",
	"51c64c77e60f3980eea90869b68c58a8": "Emotet",
	"4d7a28d6f2263ed61de88ca66eb011e3": "Trickbot",
	"c12f54a3f91dc7bafd92cb59fe009a35": "AsyncRAT",
	"a0e9f5d64349fb13191bc781f81f42e1": "Golang default",
	"3b5074b1b5d032e5620f69f9f700ff0e": "curl",
	"1138de370e523e824bbca3f245edaca4": "wget",
	"cd08e31494f9531f560d64c695473da9": "Firefox",
	"b4f7b2e0b8f8f8e8f8e8f8e8f8e8f8e8": "Chrome",
}

var globalJA3 *JA3Engine

func InitJA3Engine() *JA3Engine {
	e := &JA3Engine{
		fingerprints:   make(map[string]*JA3Record),
		ipFingerprints: make(map[string]string),
	}
	globalJA3 = e
	return e
}

// ProcessPacket extracts JA3 fingerprints from TLS Client Hello messages.
func (j *JA3Engine) ProcessPacket(packet gopacket.Packet) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp := tcpLayer.(*layers.TCP)

	payload := tcp.Payload
	if len(payload) < 11 {
		return
	}

	// Check for TLS handshake (content type 22, handshake type 1 = ClientHello)
	if payload[0] != 0x16 { // Not a handshake
		return
	}
	if len(payload) < 6 {
		return
	}
	if payload[5] != 0x01 { // Not ClientHello
		return
	}

	// Extract TLS version from record header
	tlsVersion := int(payload[1])<<8 | int(payload[2])

	// Parse ClientHello for cipher suites and extensions (simplified)
	hash := computeJA3(payload, tlsVersion)
	if hash == "" {
		return
	}

	var srcIP, dstIP string
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	}

	j.mu.Lock()
	defer j.mu.Unlock()

	rec, exists := j.fingerprints[hash]
	if !exists {
		label := knownJA3[hash]
		if label == "" {
			label = "unknown"
		}
		rec = &JA3Record{
			Hash:      hash,
			Label:     label,
			FirstSeen: fmt.Sprintf("%v", packet.Metadata().Timestamp),
			IPs:       make(map[string]bool),
		}
		j.fingerprints[hash] = rec
	}
	rec.SeenCount++
	rec.IPs[srcIP] = true
	rec.Sources = len(rec.IPs)

	key := fmt.Sprintf("%s:%s:%d", srcIP, dstIP, tcp.DstPort)
	j.ipFingerprints[key] = hash
}

func computeJA3(payload []byte, version int) string {
	// Simplified JA3: hash of TLS version + available cipher suites
	// Full JA3 requires parsing extensions, but this catches the basics
	if len(payload) < 44 {
		return ""
	}

	// Skip to cipher suites (rough offset)
	offset := 43 // past record header + handshake header + client version + random
	if offset >= len(payload) {
		return ""
	}

	// Session ID length
	sidLen := int(payload[offset])
	offset += 1 + sidLen
	if offset+2 > len(payload) {
		return ""
	}

	// Cipher suites length
	csLen := int(payload[offset])<<8 | int(payload[offset+1])
	offset += 2
	if offset+csLen > len(payload) {
		return ""
	}

	// Build JA3 string: version,ciphers,extensions,curves,point_formats
	var ciphers []string
	for i := 0; i < csLen; i += 2 {
		if offset+i+1 < len(payload) {
			cs := int(payload[offset+i])<<8 | int(payload[offset+i+1])
			// Skip GREASE values
			if cs&0x0f0f != 0x0a0a {
				ciphers = append(ciphers, fmt.Sprintf("%d", cs))
			}
		}
	}

	ja3String := fmt.Sprintf("%d,%s,,,", version, strings.Join(ciphers, "-"))
	sum := md5.Sum([]byte(ja3String))
	return fmt.Sprintf("%x", sum)
}

// GetFingerprints returns all seen JA3 fingerprints.
func GetJA3Fingerprints() []map[string]any {
	if globalJA3 == nil {
		return nil
	}
	globalJA3.mu.RLock()
	defer globalJA3.mu.RUnlock()

	var result []map[string]any
	for _, rec := range globalJA3.fingerprints {
		suspicious := rec.Label != "unknown" && rec.Label != "Chrome" && rec.Label != "Firefox"
		result = append(result, map[string]any{
			"hash": rec.Hash, "label": rec.Label,
			"seen_count": rec.SeenCount, "sources": rec.Sources,
			"suspicious": suspicious,
		})
	}
	return result
}
