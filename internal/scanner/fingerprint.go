package scanner

import "strings"

// FingerprintResult contains OS and device type guesses.
type FingerprintResult struct {
	OS         string
	DeviceType string
}

// Fingerprint guesses the OS and device type from open ports, banners, vendor, and hostname.
func Fingerprint(ports []PortResult, vendor string, hostname string) FingerprintResult {
	result := FingerprintResult{}

	portSet := make(map[int]bool)
	banners := make(map[int]string)
	for _, p := range ports {
		portSet[p.Port] = true
		if p.Banner != "" {
			banners[p.Port] = p.Banner
		}
	}

	result.OS = guessOSFromBanners(banners)
	if result.OS == "" {
		result.OS = guessOSFromPorts(portSet)
	}

	result.DeviceType = guessDeviceType(portSet, vendor, hostname)

	return result
}

func guessOSFromBanners(banners map[int]string) string {
	for _, banner := range banners {
		lower := strings.ToLower(banner)
		switch {
		case strings.Contains(lower, "ubuntu"):
			return "Linux (Ubuntu)"
		case strings.Contains(lower, "debian"):
			return "Linux (Debian)"
		case strings.Contains(lower, "centos"):
			return "Linux (CentOS)"
		case strings.Contains(lower, "red hat") || strings.Contains(lower, "redhat"):
			return "Linux (Red Hat)"
		case strings.Contains(lower, "fedora"):
			return "Linux (Fedora)"
		case strings.Contains(lower, "openssh"):
			return "Linux"
		case strings.Contains(lower, "microsoft") || strings.Contains(lower, "windows"):
			return "Windows"
		case strings.Contains(lower, "freebsd"):
			return "FreeBSD"
		case strings.Contains(lower, "mikrotik"):
			return "MikroTik RouterOS"
		case strings.Contains(lower, "openwrt"):
			return "Linux (OpenWrt)"
		}
	}
	return ""
}

func guessOSFromPorts(portSet map[int]bool) string {
	if portSet[135] && portSet[139] && portSet[445] {
		return "Windows"
	}
	if portSet[3389] && portSet[445] {
		return "Windows"
	}
	if portSet[548] {
		return "macOS"
	}
	if portSet[22] && !portSet[135] && !portSet[445] {
		return "Linux"
	}
	return ""
}

func guessDeviceType(portSet map[int]bool, vendor, hostname string) string {
	lv := strings.ToLower(vendor)
	lh := strings.ToLower(hostname)

	// Network equipment / routers
	for _, v := range []string{"cisco", "juniper", "aruba", "ubiquiti", "netgear", "tp-link", "linksys", "d-link", "asus", "mikrotik", "eero"} {
		if strings.Contains(lv, v) {
			return "Network Equipment"
		}
	}
	if strings.Contains(lh, "gateway") || strings.Contains(lh, "_gateway") {
		return "Network Equipment"
	}
	if strings.Contains(lv, "fortinet") {
		return "Firewall"
	}

	// Fitness equipment
	if strings.Contains(lv, "peloton") {
		return "IoT"
	}

	// Gaming
	if strings.Contains(lv, "sony") {
		return "Media Player"
	}
	if strings.Contains(lv, "nintendo") || strings.Contains(lv, "xbox") || strings.Contains(lv, "valve") {
		return "Media Player"
	}

	// AV equipment
	for _, v := range []string{"extron", "crestron", "shure", "biamp", "qsc"} {
		if strings.Contains(lv, v) {
			return "AV Equipment"
		}
	}

	// IP cameras
	for _, v := range []string{"hikvision", "dahua", "axis", "amcrest"} {
		if strings.Contains(lv, v) {
			return "IP Camera"
		}
	}

	// Smart home / IoT
	if strings.Contains(lv, "philips hue") || strings.Contains(lv, "ring") || strings.Contains(lv, "espressif") ||
		strings.Contains(lv, "tuya") || strings.Contains(lv, "ampak") || strings.Contains(lv, "texas instruments") ||
		strings.Contains(lv, "gaoshengda") {
		return "IoT"
	}
	if strings.Contains(lv, "sonos") || strings.Contains(lv, "roku") {
		return "Media Player"
	}
	if strings.Contains(lv, "google") || (strings.Contains(lv, "amazon") && (strings.Contains(lh, "echo") || strings.Contains(lh, "fire"))) {
		return "IoT"
	}

	// NAS
	if strings.Contains(lv, "synology") || strings.Contains(lv, "qnap") {
		return "NAS"
	}

	// SBC
	if strings.Contains(lv, "raspberry") {
		return "SBC"
	}

	// Virtual machine
	if strings.Contains(lv, "vmware") {
		return "Virtual Machine"
	}

	// Printer
	if portSet[9100] || portSet[631] {
		return "Printer"
	}

	// Server (multiple service ports open)
	serverPorts := 0
	for _, p := range []int{80, 443, 3306, 5432, 1433, 1521, 27017, 6379, 8080, 8443, 9090} {
		if portSet[p] {
			serverPorts++
		}
	}
	if serverPorts >= 3 {
		return "Server"
	}

	// Randomized MAC = phone or tablet
	if strings.Contains(lv, "randomized") {
		return "Mobile Device"
	}

	return "Endpoint"
}
