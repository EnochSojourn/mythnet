package server

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
)

func (s *Server) handleSubnetCalc(w http.ResponseWriter, r *http.Request) {
	cidr := r.URL.Query().Get("cidr")
	if cidr == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provide ?cidr=10.0.0.0/24"})
		return
	}

	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid CIDR: " + err.Error()})
		return
	}

	ones, bits := ipNet.Mask.Size()
	totalHosts := 1 << (bits - ones)
	usableHosts := totalHosts - 2
	if usableHosts < 0 {
		usableHosts = 0
	}
	if ones == 32 {
		usableHosts = 1
		totalHosts = 1
	}
	if ones == 31 {
		usableHosts = 2
	}

	// Network and broadcast addresses
	networkIP := ipNet.IP.To4()
	broadcastIP := make(net.IP, 4)
	copy(broadcastIP, networkIP)
	n := binary.BigEndian.Uint32(networkIP)
	b := n | ^binary.BigEndian.Uint32(net.IP(ipNet.Mask).To4())
	binary.BigEndian.PutUint32(broadcastIP, b)

	// First and last usable
	firstUsable := make(net.IP, 4)
	binary.BigEndian.PutUint32(firstUsable, n+1)
	lastUsable := make(net.IP, 4)
	binary.BigEndian.PutUint32(lastUsable, b-1)

	writeJSON(w, http.StatusOK, map[string]any{
		"input":        cidr,
		"ip":           ip.String(),
		"network":      networkIP.String(),
		"broadcast":    broadcastIP.String(),
		"netmask":      net.IP(ipNet.Mask).String(),
		"prefix_len":   ones,
		"total_hosts":  totalHosts,
		"usable_hosts": usableHosts,
		"first_usable": firstUsable.String(),
		"last_usable":  lastUsable.String(),
		"wildcard":     fmt.Sprintf("%d.%d.%d.%d", 255-ipNet.Mask[0], 255-ipNet.Mask[1], 255-ipNet.Mask[2], 255-ipNet.Mask[3]),
	})
}
