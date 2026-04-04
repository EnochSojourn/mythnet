package scanner

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// Flow represents an active network connection between two IPs.
type Flow struct {
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  int    `json:"src_port"`
	DstPort  int    `json:"dst_port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
}

// GetActiveFlows reads active TCP/UDP connections from /proc/net.
// Returns flows involving known local network IPs.
func GetActiveFlows(knownIPs map[string]bool) []Flow {
	var flows []Flow

	// Read TCP connections
	tcpFlows := readProcNet("/proc/net/tcp", "tcp", knownIPs)
	flows = append(flows, tcpFlows...)

	// Read TCP6 (may contain IPv4-mapped)
	tcp6Flows := readProcNet("/proc/net/tcp6", "tcp", knownIPs)
	flows = append(flows, tcp6Flows...)

	// Read UDP
	udpFlows := readProcNet("/proc/net/udp", "udp", knownIPs)
	flows = append(flows, udpFlows...)

	// Deduplicate
	seen := make(map[string]bool)
	var unique []Flow
	for _, f := range flows {
		key := fmt.Sprintf("%s:%d→%s:%d/%s", f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, f.Protocol)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, f)
		}
	}

	return unique
}

func readProcNet(path, proto string, knownIPs map[string]bool) []Flow {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var flows []Flow
	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}

		srcIP, srcPort := parseHexAddr(fields[1])
		dstIP, dstPort := parseHexAddr(fields[2])

		if srcIP == "" || dstIP == "" {
			continue
		}

		// Skip loopback
		if srcIP == "127.0.0.1" || dstIP == "127.0.0.1" {
			continue
		}
		// Include if either IP is a known network device
		// Also include if source is local and dest is on a known subnet
		srcKnown := knownIPs[srcIP]
		dstKnown := knownIPs[dstIP]
		srcLocal := isLocalIP(srcIP)
		dstLocal := isLocalIP(dstIP)

		if !srcKnown && !dstKnown && !srcLocal && !dstLocal {
			continue
		}
		// Skip pure external connections
		if !srcKnown && !dstKnown && !isPrivateIP(srcIP) && !isPrivateIP(dstIP) {
			continue
		}

		state := "established"
		if len(fields) > 3 {
			state = tcpState(fields[3])
		}

		flows = append(flows, Flow{
			SrcIP: srcIP, DstIP: dstIP,
			SrcPort: srcPort, DstPort: dstPort,
			Protocol: proto, State: state,
		})
	}

	return flows
}

func parseHexAddr(s string) (string, int) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0
	}

	hexIP := parts[0]
	hexPort := parts[1]

	var port int
	fmt.Sscanf(hexPort, "%X", &port)

	// IPv4: 4 bytes in reverse order
	if len(hexIP) == 8 {
		var a, b, c, d uint32
		fmt.Sscanf(hexIP, "%2X%2X%2X%2X", &d, &c, &b, &a)
		return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d), port
	}

	// IPv6: check for IPv4-mapped (::ffff:x.x.x.x)
	if len(hexIP) == 32 {
		// Check if it's IPv4-mapped
		prefix := hexIP[:24]
		if prefix == "0000000000000000FFFF0000" || prefix == "0000000000000000ffff0000" {
			suffix := hexIP[24:]
			var a, b, c, d uint32
			fmt.Sscanf(suffix, "%2X%2X%2X%2X", &d, &c, &b, &a)
			return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d), port
		}
		// Parse as IPv6
		ip := make(net.IP, 16)
		for i := 0; i < 16; i++ {
			fmt.Sscanf(hexIP[i*2:i*2+2], "%02X", &ip[i])
		}
		// Swap byte order within each 4-byte group
		for i := 0; i < 16; i += 4 {
			ip[i], ip[i+3] = ip[i+3], ip[i]
			ip[i+1], ip[i+2] = ip[i+2], ip[i+1]
		}
		return ip.String(), port
	}

	return "", 0
}

func isLocalIP(ip string) bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ipNet.IP.String() == ip {
					return true
				}
			}
		}
	}
	return false
}

func isPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	private := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	for _, cidr := range private {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}

func tcpState(hex string) string {
	states := map[string]string{
		"01": "established", "02": "syn_sent", "03": "syn_recv",
		"04": "fin_wait1", "05": "fin_wait2", "06": "time_wait",
		"07": "close", "08": "close_wait", "09": "last_ack",
		"0A": "listen", "0B": "closing",
	}
	hex = strings.ToUpper(hex)
	if s, ok := states[hex]; ok {
		return s
	}
	return hex
}
