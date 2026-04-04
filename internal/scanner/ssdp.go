package scanner

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// SSDPDevice holds info discovered via UPnP/SSDP.
type SSDPDevice struct {
	IP       string
	Server   string
	Location string
	USN      string
}

// ScanSSDP sends M-SEARCH multicast and collects UPnP device responses.
func ScanSSDP(timeout time.Duration) []SSDPDevice {
	if timeout == 0 {
		timeout = 3 * time.Second
	}

	addr, _ := net.ResolveUDPAddr("udp4", "239.255.255.250:1900")
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil
	}
	defer conn.Close()

	// M-SEARCH request
	msearch := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: ssdp:all\r\n" +
		"\r\n"

	conn.WriteToUDP([]byte(msearch), addr)
	conn.SetReadDeadline(time.Now().Add(timeout))

	seen := make(map[string]bool)
	var devices []SSDPDevice

	buf := make([]byte, 4096)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}

		ip := from.IP.String()
		if seen[ip] {
			continue
		}

		dev := parseSSDPResponse(string(buf[:n]))
		dev.IP = ip
		if dev.Server != "" || dev.Location != "" {
			seen[ip] = true
			devices = append(devices, dev)
		}
	}

	return devices
}

func parseSSDPResponse(data string) SSDPDevice {
	var dev SSDPDevice
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.ToUpper(strings.TrimSpace(line[:idx]))
			val := strings.TrimSpace(line[idx+1:])
			switch key {
			case "SERVER":
				dev.Server = val
			case "LOCATION":
				dev.Location = val
			case "USN":
				dev.USN = val
			}
		}
	}
	return dev
}

// IdentifyFromSSDP extracts vendor/model info from SSDP Server header.
func IdentifyFromSSDP(server string) (vendor, model string) {
	lower := strings.ToLower(server)

	switch {
	case strings.Contains(lower, "roku"):
		return "Roku", extractModel(server)
	case strings.Contains(lower, "chromecast") || strings.Contains(lower, "google"):
		return "Google", "Chromecast"
	case strings.Contains(lower, "sonos"):
		return "Sonos", extractModel(server)
	case strings.Contains(lower, "samsung"):
		return "Samsung", "Smart TV"
	case strings.Contains(lower, "lg"):
		return "LG", "Smart TV"
	case strings.Contains(lower, "philips"):
		return "Philips", extractModel(server)
	case strings.Contains(lower, "plex"):
		return "Plex", "Media Server"
	case strings.Contains(lower, "synology"):
		return "Synology", "NAS"
	case strings.Contains(lower, "mikrotik"):
		return "MikroTik", "Router"
	case strings.Contains(lower, "ubnt") || strings.Contains(lower, "ubiquiti"):
		return "Ubiquiti", extractModel(server)
	case strings.Contains(lower, "linux") && strings.Contains(lower, "upnp"):
		return "", "UPnP Device"
	case strings.Contains(lower, "windows"):
		return "Microsoft", "Windows"
	}

	// Try to extract from "Vendor/Model" pattern
	parts := strings.SplitN(server, "/", 2)
	if len(parts) == 2 && len(parts[0]) > 1 && len(parts[0]) < 30 {
		return parts[0], ""
	}

	return "", ""
}

func extractModel(s string) string {
	// Try to get model from parentheses or after slash
	if idx := strings.Index(s, "("); idx >= 0 {
		if end := strings.Index(s[idx:], ")"); end >= 0 {
			return s[idx+1 : idx+end]
		}
	}
	return ""
}

// FetchUPnPDescription fetches the UPnP XML description for richer device info.
func FetchUPnPDescription(location string, timeout time.Duration) (friendlyName, manufacturer, modelName string) {
	if location == "" || !strings.HasPrefix(location, "http") {
		return
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(location)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Simple XML extraction without a full parser
	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	friendlyName = extractXMLTag(body, "friendlyName")
	manufacturer = extractXMLTag(body, "manufacturer")
	modelName = extractXMLTag(body, "modelName")
	return
}

func extractXMLTag(xml, tag string) string {
	start := fmt.Sprintf("<%s>", tag)
	end := fmt.Sprintf("</%s>", tag)
	idx := strings.Index(xml, start)
	if idx < 0 {
		return ""
	}
	idx += len(start)
	endIdx := strings.Index(xml[idx:], end)
	if endIdx < 0 {
		return ""
	}
	return strings.TrimSpace(xml[idx : idx+endIdx])
}
