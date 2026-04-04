package server

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

func (s *Server) handleWakeOnLAN(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	device, err := s.store.GetDevice(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "device not found"})
		return
	}

	if device.MAC == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no MAC address known for this device"})
		return
	}

	if err := sendWoL(device.MAC); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	s.logger.Info("Wake-on-LAN sent", "device", device.IP, "mac", device.MAC)
	writeJSON(w, http.StatusOK, map[string]string{"status": "magic packet sent", "mac": device.MAC})
}

// sendWoL sends a Wake-on-LAN magic packet to the broadcast address.
func sendWoL(mac string) error {
	mac = strings.ReplaceAll(strings.ReplaceAll(mac, ":", ""), "-", "")
	macBytes, err := hex.DecodeString(mac)
	if err != nil || len(macBytes) != 6 {
		return fmt.Errorf("invalid MAC address")
	}

	// Magic packet: 6x 0xFF + 16x MAC address
	packet := make([]byte, 102)
	for i := 0; i < 6; i++ {
		packet[i] = 0xFF
	}
	for i := 0; i < 16; i++ {
		copy(packet[6+i*6:], macBytes)
	}

	// Send via UDP broadcast on port 9
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.IPv4bcast,
		Port: 9,
	})
	if err != nil {
		return fmt.Errorf("dial broadcast: %w", err)
	}
	defer conn.Close()

	_, err = conn.Write(packet)
	return err
}
