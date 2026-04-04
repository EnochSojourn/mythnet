package warroom

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/mythnet/mythnet/internal/ai"
	"github.com/mythnet/mythnet/internal/db"
)

// AttackPath represents a possible lateral movement path through the network.
type AttackPath struct {
	EntryPoint string     `json:"entry_point"`
	Target     string     `json:"target"`
	Hops       []PathHop  `json:"hops"`
	TotalRisk  int        `json:"total_risk"`
	Difficulty string     `json:"difficulty"` // "trivial", "easy", "moderate", "hard"
}

// PathHop is one step in an attack path.
type PathHop struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Via     string `json:"via"`      // service/port used
	Risk    int    `json:"risk"`     // 1-10, higher = easier to exploit
}

// BlastRadius shows what an attacker can reach from a compromised device.
type BlastRadius struct {
	CompromisedDevice string   `json:"compromised_device"`
	CompromisedIP     string   `json:"compromised_ip"`
	ReachableDevices  []string `json:"reachable_devices"`
	ReachableCount    int      `json:"reachable_count"`
	CriticalAssets    []string `json:"critical_assets_at_risk"`
	MaxDepth          int      `json:"max_depth"`
}

// ThreatPrediction is the AI's forward-looking analysis.
type ThreatPrediction struct {
	GeneratedAt       string        `json:"generated_at"`
	MostVulnerable    []DeviceRiskP `json:"most_vulnerable"`
	AttackPaths       []AttackPath  `json:"attack_paths"`
	BlastRadii        []BlastRadius `json:"blast_radii"`
	AIAnalysis        string        `json:"ai_analysis"`
}

type DeviceRiskP struct {
	IP         string `json:"ip"`
	Name       string `json:"name"`
	RiskScore  int    `json:"risk_score"`
	Reason     string `json:"reason"`
}

// Exploitability ratings for services (1-10, higher = easier to exploit)
var serviceRisk = map[string]int{
	"telnet":       10,
	"ftp":          8,
	"redis":        9,
	"mongodb":      9,
	"microsoft-ds": 8, // SMB
	"vnc":          8,
	"rdp":          7,
	"http":         5,
	"http-proxy":   5,
	"mysql":        6,
	"postgresql":   5,
	"ssh":          3,
	"https":        2,
}

// BuildAttackGraph computes all possible lateral movement paths.
func BuildAttackGraph(store *db.Store) []AttackPath {
	devices, _ := store.ListDevices()
	if len(devices) == 0 {
		return nil
	}

	// Build adjacency: for each device, what services can be attacked
	type node struct {
		device *db.Device
		ports  []db.Port
		risk   int
	}

	nodes := make(map[string]*node)
	for _, d := range devices {
		if !d.IsOnline {
			continue
		}
		ports, _ := store.GetDevicePorts(d.ID)
		maxRisk := 0
		for _, p := range ports {
			if r, ok := serviceRisk[p.Service]; ok && r > maxRisk {
				maxRisk = r
			}
		}
		name := d.Hostname
		if name == "" { name = d.Vendor }
		if name == "" { name = d.IP }
		nodes[d.IP] = &node{device: d, ports: ports, risk: maxRisk}
	}

	var paths []AttackPath

	// For each pair of devices, find attack paths
	for srcIP, src := range nodes {
		for dstIP, dst := range nodes {
			if srcIP == dstIP {
				continue
			}

			// Direct path: can src reach dst via an exploitable service?
			for _, p := range dst.ports {
				risk, ok := serviceRisk[p.Service]
				if !ok || risk < 3 { // Skip low-risk services
					continue
				}

				srcName := src.device.Hostname
				if srcName == "" { srcName = src.device.Vendor }
				if srcName == "" { srcName = srcIP }
				dstName := dst.device.Hostname
				if dstName == "" { dstName = dst.device.Vendor }
				if dstName == "" { dstName = dstIP }

				path := AttackPath{
					EntryPoint: srcName + " (" + srcIP + ")",
					Target:     dstName + " (" + dstIP + ")",
					Hops: []PathHop{{
						From: srcIP, To: dstIP,
						Via:  fmt.Sprintf("%s (port %d)", p.Service, p.Port),
						Risk: risk,
					}},
					TotalRisk: risk,
				}

				switch {
				case risk >= 9:
					path.Difficulty = "trivial"
				case risk >= 7:
					path.Difficulty = "easy"
				case risk >= 5:
					path.Difficulty = "moderate"
				default:
					path.Difficulty = "hard"
				}

				paths = append(paths, path)
			}
		}
	}

	// Sort by risk (most dangerous first)
	sort.Slice(paths, func(i, j int) bool {
		return paths[i].TotalRisk > paths[j].TotalRisk
	})

	// Limit to top 50
	if len(paths) > 50 {
		paths = paths[:50]
	}

	return paths
}

// ComputeBlastRadius calculates what an attacker can reach from a compromised device.
func ComputeBlastRadius(store *db.Store, deviceIP string) *BlastRadius {
	devices, _ := store.ListDevices()

	var compromised *db.Device
	for _, d := range devices {
		if d.IP == deviceIP {
			compromised = d
			break
		}
	}
	if compromised == nil {
		return nil
	}

	name := compromised.Hostname
	if name == "" { name = compromised.Vendor }
	if name == "" { name = compromised.IP }

	br := &BlastRadius{
		CompromisedDevice: name,
		CompromisedIP:     deviceIP,
	}

	// From the compromised device, what can be reached?
	for _, d := range devices {
		if d.IP == deviceIP || !d.IsOnline {
			continue
		}

		ports, _ := store.GetDevicePorts(d.ID)
		reachable := false
		for _, p := range ports {
			if _, ok := serviceRisk[p.Service]; ok {
				reachable = true
				break
			}
		}

		// Same subnet = always reachable at L2
		if sameSubnet(deviceIP, d.IP) {
			reachable = true
		}

		if reachable {
			dName := d.Hostname
			if dName == "" { dName = d.Vendor }
			if dName == "" { dName = d.IP }
			br.ReachableDevices = append(br.ReachableDevices, dName+" ("+d.IP+")")

			// Is this a critical asset?
			if d.DeviceType == "Server" || d.DeviceType == "Network Equipment" ||
				d.Hostname == "_gateway" || d.Hostname == "Robot" {
				br.CriticalAssets = append(br.CriticalAssets, dName)
			}
		}
	}

	br.ReachableCount = len(br.ReachableDevices)
	br.MaxDepth = 1 // Direct reach; multi-hop would be more complex

	return br
}

// PredictThreats uses AI to generate forward-looking threat analysis.
func PredictThreats(ctx context.Context, store *db.Store, aiClient ai.Client, logger *slog.Logger) *ThreatPrediction {
	pred := &ThreatPrediction{
		GeneratedAt: time.Now().Format(time.RFC3339),
	}

	// Build attack graph
	pred.AttackPaths = BuildAttackGraph(store)

	// Find most vulnerable devices
	devices, _ := store.ListDevices()
	for _, d := range devices {
		if !d.IsOnline {
			continue
		}
		ports, _ := store.GetDevicePorts(d.ID)
		maxRisk := 0
		riskService := ""
		for _, p := range ports {
			if r, ok := serviceRisk[p.Service]; ok && r > maxRisk {
				maxRisk = r
				riskService = p.Service
			}
		}
		if maxRisk >= 5 {
			name := d.Hostname
			if name == "" { name = d.Vendor }
			if name == "" { name = d.IP }
			pred.MostVulnerable = append(pred.MostVulnerable, DeviceRiskP{
				IP: d.IP, Name: name, RiskScore: maxRisk * 10,
				Reason: fmt.Sprintf("Exposed %s service (risk %d/10)", riskService, maxRisk),
			})
		}
	}

	sort.Slice(pred.MostVulnerable, func(i, j int) bool {
		return pred.MostVulnerable[i].RiskScore > pred.MostVulnerable[j].RiskScore
	})

	// Compute blast radius for most vulnerable
	for _, v := range pred.MostVulnerable {
		br := ComputeBlastRadius(store, v.IP)
		if br != nil && br.ReachableCount > 0 {
			pred.BlastRadii = append(pred.BlastRadii, *br)
		}
	}

	// Ask AI for predictive analysis
	if aiClient != nil {
		pred.AIAnalysis = aiPredict(ctx, store, aiClient, pred)
	}

	return pred
}

func aiPredict(ctx context.Context, store *db.Store, client ai.Client, pred *ThreatPrediction) string {
	var prompt strings.Builder
	prompt.WriteString("You are a threat modeler. Based on this network's attack surface, predict:\n\n")
	prompt.WriteString("1. Which device is most likely to be compromised NEXT and why\n")
	prompt.WriteString("2. The most dangerous attack path through this network\n")
	prompt.WriteString("3. What this network will look like in a week if no action is taken\n")
	prompt.WriteString("4. The single most important thing the owner should do TODAY\n\n")

	prompt.WriteString("Be specific. Name actual devices and IPs.\n\n")

	// Include network context
	prompt.WriteString(ai.BuildContext(store))

	// Include attack paths
	if len(pred.AttackPaths) > 0 {
		prompt.WriteString("\n## Attack Paths Found\n\n")
		for _, ap := range pred.AttackPaths[:min(10, len(pred.AttackPaths))] {
			prompt.WriteString(fmt.Sprintf("- %s → %s via %s [%s, risk %d]\n",
				ap.EntryPoint, ap.Target, ap.Hops[0].Via, ap.Difficulty, ap.TotalRisk))
		}
	}

	// Include blast radii
	if len(pred.BlastRadii) > 0 {
		prompt.WriteString("\n## Blast Radius Analysis\n\n")
		for _, br := range pred.BlastRadii[:min(5, len(pred.BlastRadii))] {
			prompt.WriteString(fmt.Sprintf("- If %s is compromised: %d devices reachable, critical assets: %s\n",
				br.CompromisedDevice, br.ReachableCount, strings.Join(br.CriticalAssets, ", ")))
		}
	}

	messages := []ai.Message{{Role: "user", Content: "Predict the threats to this network."}}

	var result strings.Builder
	err := client.Chat(ctx, prompt.String(), messages, func(chunk string) {
		result.WriteString(chunk)
	})
	if err != nil {
		return "Prediction unavailable: " + err.Error()
	}

	return result.String()
}

func sameSubnet(a, b string) bool {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")
	if len(aParts) != 4 || len(bParts) != 4 {
		return false
	}
	return aParts[0] == bParts[0] && aParts[1] == bParts[1] && aParts[2] == bParts[2]
}

func min(a, b int) int {
	if a < b { return a }
	return b
}
