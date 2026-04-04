package scanner

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// TraceHop represents one hop in a traceroute path.
type TraceHop struct {
	Hop   int     `json:"hop"`
	IP    string  `json:"ip,omitempty"`
	RTTMs float64 `json:"rtt_ms"`
	Host  string  `json:"host,omitempty"`
}

// Traceroute runs tracepath (no root needed) to map the network path.
func Traceroute(target string, maxHops int) []TraceHop {
	if maxHops == 0 {
		maxHops = 15
	}

	// Try tracepath first (Linux, no root)
	out, err := exec.Command("tracepath", "-n", "-m", fmt.Sprintf("%d", maxHops), target).Output()
	if err == nil {
		return parseTracepath(string(out))
	}

	// Fallback: measure RTT with increasing connect timeouts as a rough proxy
	return fallbackTrace(target, maxHops)
}

var tracepathRe = regexp.MustCompile(`^\s*(\d+):\s+(\S+)\s+([\d.]+)ms`)

func parseTracepath(output string) []TraceHop {
	var hops []TraceHop
	seen := make(map[int]bool)

	for _, line := range strings.Split(output, "\n") {
		m := tracepathRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		hop, _ := strconv.Atoi(m[1])
		if seen[hop] {
			continue
		}
		seen[hop] = true

		rtt, _ := strconv.ParseFloat(m[3], 64)
		ip := m[2]
		if ip == "no" { // "no reply"
			continue
		}

		hops = append(hops, TraceHop{Hop: hop, IP: ip, RTTMs: rtt})
	}

	return hops
}

func fallbackTrace(target string, maxHops int) []TraceHop {
	// Simple fallback: just report the direct RTT
	start := time.Now()
	conn, err := net.DialTimeout("tcp", target+":80", 3*time.Second)
	if err != nil {
		conn, err = net.DialTimeout("tcp", target+":443", 3*time.Second)
	}
	if err != nil {
		return nil
	}
	rtt := time.Since(start)
	conn.Close()

	return []TraceHop{
		{Hop: 1, IP: target, RTTMs: float64(rtt.Microseconds()) / 1000.0},
	}
}
