package server

import (
	"fmt"
	"math"
	"net/http"
	"strings"
)

func (s *Server) handleTopologySVG(w http.ResponseWriter, r *http.Request) {
	devices, _ := s.store.ListDevices()
	if len(devices) == 0 {
		http.Error(w, "no devices", 404)
		return
	}

	typeColors := map[string]string{
		"Network Equipment": "#3b82f6", "Server": "#22c55e", "Endpoint": "#64748b",
		"IoT": "#a855f7", "IP Camera": "#ef4444", "AV Equipment": "#06b6d4",
		"Firewall": "#f97316", "NAS": "#14b8a6", "Printer": "#eab308",
		"Virtual Machine": "#6366f1", "Media Player": "#ec4899", "SBC": "#84cc16",
	}

	// Group devices by /24 subnet
	subnets := make(map[string][]int) // subnet → device indices
	for i, d := range devices {
		parts := strings.Split(d.IP, ".")
		key := fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
		subnets[key] = append(subnets[key], i)
	}

	width := 800
	height := 600
	cx, cy := width/2, height/2

	var b strings.Builder
	b.WriteString(fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">`, width, height, width, height))
	b.WriteString(fmt.Sprintf(`<rect width="%d" height="%d" fill="#060a14"/>`, width, height))
	b.WriteString(`<style>text{font-family:system-ui,sans-serif;fill:#9ca3af;font-size:10px;text-anchor:middle}</style>`)

	subnetIdx := 0
	subnetCount := len(subnets)
	for subnet, indices := range subnets {
		// Position subnet node
		angle := 2 * math.Pi * float64(subnetIdx) / float64(max(subnetCount, 1))
		sx := cx + int(80*math.Cos(angle))
		sy := cy + int(80*math.Sin(angle))

		// Subnet node
		b.WriteString(fmt.Sprintf(`<circle cx="%d" cy="%d" r="24" fill="#0f172a" stroke="#334155" stroke-width="2"/>`, sx, sy))
		b.WriteString(fmt.Sprintf(`<text x="%d" y="%d" dy="0.35em" fill="#475569" font-size="8" font-weight="bold">NET</text>`, sx, sy))
		b.WriteString(fmt.Sprintf(`<text x="%d" y="%d" dy="38" font-size="9">%s</text>`, sx, sy, subnet))

		// Position devices around subnet
		for j, idx := range indices {
			d := devices[idx]
			devAngle := angle + 2*math.Pi*float64(j)/float64(max(len(indices), 1)) - math.Pi/4
			radius := 120 + 30*float64(j%3)
			dx := sx + int(radius*math.Cos(devAngle))
			dy := sy + int(radius*math.Sin(devAngle))

			// Clamp to bounds
			dx = max(30, min(dx, width-30))
			dy = max(30, min(dy, height-30))

			color := typeColors[d.DeviceType]
			if color == "" {
				color = "#64748b"
			}
			opacity := "0.85"
			if !d.IsOnline {
				opacity = "0.3"
			}

			// Link
			b.WriteString(fmt.Sprintf(`<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#1e293b" stroke-width="1.5" stroke-opacity="0.4"/>`, sx, sy, dx, dy))

			// Device node
			r := 10
			ports, _ := s.store.GetDevicePorts(d.ID)
			r = max(10, min(22, 10+len(ports)*3))

			b.WriteString(fmt.Sprintf(`<circle cx="%d" cy="%d" r="%d" fill="%s" fill-opacity="%s" stroke="%s" stroke-width="1.5"/>`, dx, dy, r, color, opacity, color))

			// Label
			label := d.Hostname
			if label == "" {
				label = d.IP
			}
			if len(label) > 16 {
				label = label[:14] + "…"
			}
			b.WriteString(fmt.Sprintf(`<text x="%d" y="%d" dy="%d">%s</text>`, dx, dy, r+14, label))
		}

		subnetIdx++
	}

	// Title
	b.WriteString(fmt.Sprintf(`<text x="%d" y="20" font-size="14" font-weight="bold" fill="#e2e8f0">MythNet Topology — %d devices</text>`, cx, len(devices)))

	b.WriteString(`</svg>`)

	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Content-Disposition", `inline; filename="mythnet-topology.svg"`)
	w.Write([]byte(b.String()))
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
