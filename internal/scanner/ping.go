package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// PingResult holds the result of a host reachability check.
type PingResult struct {
	IP    string
	Alive bool
	RTT   time.Duration
}

// PingHost checks if a host is reachable using TCP connect probes.
// Probes fire concurrently and return as soon as any succeeds.
func PingHost(ctx context.Context, ip string, timeout time.Duration) PingResult {
	result := PingResult{IP: ip}

	// Quick probe ports — if any respond or refuse, host is alive
	probePorts := []int{80, 443, 22, 445, 8080}

	type probeResult struct {
		alive bool
		rtt   time.Duration
	}

	ch := make(chan probeResult, len(probePorts))

	for _, port := range probePorts {
		go func(p int) {
			start := time.Now()
			addr := fmt.Sprintf("%s:%d", ip, p)
			conn, err := net.DialTimeout("tcp", addr, timeout)
			rtt := time.Since(start)

			if err == nil {
				conn.Close()
				ch <- probeResult{alive: true, rtt: rtt}
				return
			}

			// Connection refused = host is alive, port just isn't open
			if strings.Contains(err.Error(), "refused") {
				ch <- probeResult{alive: true, rtt: rtt}
				return
			}

			ch <- probeResult{alive: false, rtt: rtt}
		}(port)
	}

	for i := 0; i < len(probePorts); i++ {
		select {
		case <-ctx.Done():
			return result
		case r := <-ch:
			if r.alive {
				result.Alive = true
				result.RTT = r.rtt
				return result
			}
		}
	}

	return result
}
