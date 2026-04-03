package scanner

import (
	"bufio"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

// ReadARPTable reads the system ARP table and returns a map of IP to MAC address.
func ReadARPTable() map[string]string {
	table := make(map[string]string)

	var entries []arpEntry
	switch runtime.GOOS {
	case "linux":
		entries = readLinuxARP()
	default:
		entries = readCommandARP()
	}

	for _, e := range entries {
		if e.mac != "" && e.mac != "00:00:00:00:00:00" {
			table[e.ip] = e.mac
		}
	}

	return table
}

type arpEntry struct {
	ip  string
	mac string
}

func readLinuxARP() []arpEntry {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return readCommandARP()
	}
	defer f.Close()

	var entries []arpEntry
	sc := bufio.NewScanner(f)
	sc.Scan() // skip header

	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 4 {
			mac := normalizeMAC(fields[3])
			if mac != "00:00:00:00:00:00" {
				entries = append(entries, arpEntry{ip: fields[0], mac: mac})
			}
		}
	}

	return entries
}

func readCommandARP() []arpEntry {
	out, err := exec.Command("arp", "-a").Output()
	if err != nil {
		return nil
	}

	var entries []arpEntry
	macRe := regexp.MustCompile(`([0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}`)
	ipRe := regexp.MustCompile(`\((\d+\.\d+\.\d+\.\d+)\)|\b(\d+\.\d+\.\d+\.\d+)\b`)

	for _, line := range strings.Split(string(out), "\n") {
		macMatch := macRe.FindString(line)
		ipMatch := ipRe.FindStringSubmatch(line)

		if macMatch == "" || len(ipMatch) == 0 {
			continue
		}

		ip := ipMatch[1]
		if ip == "" {
			ip = ipMatch[2]
		}
		if ip != "" {
			entries = append(entries, arpEntry{ip: ip, mac: normalizeMAC(macMatch)})
		}
	}

	return entries
}

func normalizeMAC(mac string) string {
	mac = strings.ToUpper(strings.ReplaceAll(mac, "-", ":"))
	parts := strings.Split(mac, ":")
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}
	return strings.Join(parts, ":")
}
