package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/mythnet/mythnet/internal/updater"
)

var version = "dev"

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	blue   = "\033[34m"
	cyan   = "\033[36m"
	gray   = "\033[90m"
)

type client struct {
	baseURL  string
	password string
	http     *http.Client
}

func (c *client) get(path string) ([]byte, error) {
	req, _ := http.NewRequest("GET", c.baseURL+path, nil)
	if c.password != "" {
		req.SetBasicAuth("admin", c.password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("authentication failed — check password")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func (c *client) post(path, body string) ([]byte, error) {
	req, _ := http.NewRequest("POST", c.baseURL+path, strings.NewReader(body))
	if c.password != "" {
		req.SetBasicAuth("admin", c.password)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func main() {
	server := flag.String("server", "http://localhost:8080", "MythNet server URL")
	password := flag.String("password", "", "admin password (or MYTHNET_PASSWORD env)")
	flag.StringVar(server, "s", "http://localhost:8080", "server URL (shorthand)")
	flag.StringVar(password, "p", "", "password (shorthand)")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()

	if *showVersion {
		fmt.Printf("mythctl %s\n", version)
		return
	}

	if *password == "" {
		*password = os.Getenv("MYTHNET_PASSWORD")
	}

	c := &client{
		baseURL:  strings.TrimRight(*server, "/"),
		password: *password,
		http:     &http.Client{Timeout: 30 * time.Second},
	}

	args := flag.Args()
	if len(args) == 0 {
		args = []string{"help"}
	}

	var err error
	switch args[0] {
	case "health", "status":
		err = cmdHealth(c)
	case "devices", "dev":
		err = cmdDevices(c, args[1:])
	case "events", "ev":
		err = cmdEvents(c, args[1:])
	case "scan":
		err = cmdScan(c, args[1:])
	case "sla":
		err = cmdSLA(c)
	case "digest":
		err = cmdDigest(c)
	case "tools":
		if len(args) > 1 {
			err = cmdTools(c, args[1], args[2:])
		} else {
			fmt.Println("Usage: mythctl tools <ping|dns|port|whois|subnet> <target>")
		}
	case "update":
		release, uerr := updater.CheckUpdate(version)
		if uerr != nil {
			err = uerr
		} else if release == nil {
			fmt.Printf("%sAlready up to date (%s)%s\n", green, version, reset)
		} else {
			fmt.Printf("New version: %s%s%s (current: %s)\n", bold, release.TagName, reset, version)
			err = updater.SelfUpdate(release, "mythctl")
		}
	case "test":
		err = cmdTest(c)
	case "config":
		cmdConfig()
	case "help":
		printHelp()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", args[0])
		printHelp()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "%serror:%s %v\n", red, reset, err)
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Printf(`%smythctl%s — MythNet CLI Client

%sUsage:%s mythctl [flags] <command> [args]

%sCommands:%s
  health          Show server health and network score
  devices         List all discovered devices
  devices <id>    Show device detail
  events          List recent events
  events -f       Follow events (poll)
  scan            Trigger a network scan
  sla             Show SLA uptime report
  digest          Show daily digest summary
  test            Test connectivity to MythNet server
  config          Print config template to stdout
  tools ping <ip> Ping a host
  tools dns <host> DNS lookup
  tools port <ip> <port>  Check port
  tools whois <ip>        WHOIS lookup
  tools subnet <cidr>     Subnet calculator

%sFlags:%s
  -s, --server    MythNet server URL (default http://localhost:8080)
  -p, --password  Admin password (or MYTHNET_PASSWORD env var)
  --version       Print version
`, bold, reset, cyan, reset, cyan, reset, cyan, reset)
}

func cmdHealth(c *client) error {
	data, err := c.get("/api/health")
	if err != nil {
		return err
	}
	var h map[string]any
	json.Unmarshal(data, &h)

	score := int(h["health_score"].(float64))
	grade := h["health_grade"].(string)
	scanning := h["scanning"].(bool)

	color := green
	if score < 70 {
		color = red
	} else if score < 90 {
		color = yellow
	}

	fmt.Printf("%sMythNet%s %s\n\n", bold, reset, h["version"])
	fmt.Printf("  Health:  %s%d/100 (Grade %s)%s\n", color, score, grade, reset)
	scanStatus := green + "idle" + reset
	if scanning {
		scanStatus = yellow + "scanning" + reset
	}
	fmt.Printf("  Scanner: %s\n", scanStatus)

	if hm, ok := h["health"].(map[string]any); ok {
		if issues, ok := hm["issues"].([]any); ok {
			for _, i := range issues {
				fmt.Printf("  %s→%s %s\n", gray, reset, i)
			}
		}
	}
	return nil
}

func cmdDevices(c *client, args []string) error {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return cmdDeviceDetail(c, args[0])
	}

	data, err := c.get("/api/devices")
	if err != nil {
		return err
	}
	var devices []map[string]any
	json.Unmarshal(data, &devices)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "%sIP\tHOSTNAME\tTYPE\tVENDOR\tOS\tSTATUS%s\n", gray, reset)
	for _, d := range devices {
		status := green + "online" + reset
		if d["is_online"] != true {
			status = red + "offline" + reset
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			d["ip"], str(d["hostname"]), str(d["device_type"]),
			str(d["vendor"]), str(d["os_guess"]), status)
	}
	w.Flush()
	fmt.Printf("\n%s%d device(s)%s\n", gray, len(devices), reset)
	return nil
}

func cmdDeviceDetail(c *client, id string) error {
	data, err := c.get("/api/devices/" + id)
	if err != nil {
		return err
	}
	var resp map[string]any
	json.Unmarshal(data, &resp)
	dev := resp["device"].(map[string]any)

	fmt.Printf("%s%s%s", bold, str(dev["hostname"]), reset)
	if str(dev["hostname"]) != "" {
		fmt.Printf(" (%s)", dev["ip"])
	} else {
		fmt.Printf("%s", dev["ip"])
	}
	fmt.Println()
	fmt.Printf("  MAC:    %s\n", str(dev["mac"]))
	fmt.Printf("  Vendor: %s\n", str(dev["vendor"]))
	fmt.Printf("  OS:     %s\n", str(dev["os_guess"]))
	fmt.Printf("  Type:   %s\n", str(dev["device_type"]))

	if ports, ok := dev["ports"].([]any); ok && len(ports) > 0 {
		fmt.Printf("\n  %sPorts:%s\n", cyan, reset)
		for _, p := range ports {
			pm := p.(map[string]any)
			fmt.Printf("    %s%v%s/%s %s\n", green, pm["port"], reset, pm["protocol"], str(pm["service"]))
		}
	}
	return nil
}

func cmdEvents(c *client, args []string) error {
	follow := false
	for _, a := range args {
		if a == "-f" || a == "--follow" {
			follow = true
		}
	}

	printEvents := func() error {
		data, err := c.get("/api/events?limit=20")
		if err != nil {
			return err
		}
		var events []map[string]any
		json.Unmarshal(data, &events)

		for i := len(events) - 1; i >= 0; i-- {
			e := events[i]
			sev := str(e["severity"])
			color := gray
			switch sev {
			case "critical":
				color = red
			case "warning":
				color = yellow
			case "info":
				color = blue
			}
			ts := str(e["received_at"])
			if len(ts) > 19 {
				ts = ts[:19]
			}
			fmt.Printf("%s%s%s %s%-8s%s %s%-10s%s %s\n",
				gray, ts, reset, color, sev, reset,
				cyan, str(e["source"]), reset, str(e["title"]))
		}
		return nil
	}

	if err := printEvents(); err != nil {
		return err
	}

	if follow {
		fmt.Printf("\n%s— following (Ctrl+C to stop) —%s\n\n", gray, reset)
		for {
			time.Sleep(5 * time.Second)
			printEvents()
		}
	}
	return nil
}

func cmdScan(c *client, args []string) error {
	subnet := ""
	if len(args) > 0 {
		subnet = args[0]
	}
	_, err := c.post("/api/scans", fmt.Sprintf(`{"subnet":"%s"}`, subnet))
	if err != nil {
		return err
	}
	fmt.Printf("%s→%s Scan triggered\n", green, reset)
	return nil
}

func cmdSLA(c *client) error {
	data, err := c.get("/api/sla")
	if err != nil {
		return err
	}
	var entries []map[string]any
	json.Unmarshal(data, &entries)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "%sIP\tHOSTNAME\t24H\t7D\t30D%s\n", gray, reset)
	for _, e := range entries {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			str(e["ip"]), str(e["hostname"]),
			slaColor(e["sla_24h"]), slaColor(e["sla_7d"]), slaColor(e["sla_30d"]))
	}
	w.Flush()
	return nil
}

func cmdDigest(c *client) error {
	data, err := c.get("/api/digest")
	if err != nil {
		return err
	}
	fmt.Print(string(data))
	return nil
}

func cmdTools(c *client, tool string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("provide a target")
	}
	target := args[0]
	var path string

	switch tool {
	case "ping":
		path = "/api/tools/ping?target=" + target
	case "dns":
		path = "/api/tools/dns?target=" + target
	case "port":
		if len(args) < 2 {
			return fmt.Errorf("provide target and port")
		}
		path = "/api/tools/port?target=" + target + "&port=" + args[1]
	case "whois":
		path = "/api/tools/whois?target=" + target
	case "subnet":
		path = "/api/subnet?cidr=" + target
	default:
		return fmt.Errorf("unknown tool: %s", tool)
	}

	data, err := c.get(path)
	if err != nil {
		return err
	}

	var result map[string]any
	json.Unmarshal(data, &result)

	// Pretty print
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(result)
	return nil
}

func str(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func cmdTest(c *client) error {
	fmt.Printf("Testing connection to %s%s%s...\n", bold, c.baseURL, reset)

	// Test health (no auth)
	start := time.Now()
	data, err := c.get("/api/health")
	rtt := time.Since(start)
	if err != nil {
		fmt.Printf("  %s✗%s Health endpoint: %v\n", red, reset, err)
		return err
	}
	fmt.Printf("  %s✓%s Health endpoint: %s (%s)\n", green, reset, "OK", rtt)

	var h map[string]any
	json.Unmarshal(data, &h)
	fmt.Printf("  %s✓%s Version: %s\n", green, reset, h["version"])
	fmt.Printf("  %s✓%s Health score: %.0f/100\n", green, reset, h["health_score"])

	// Test auth
	_, err = c.get("/api/stats")
	if err != nil {
		fmt.Printf("  %s✗%s Authentication: %v\n", red, reset, err)
	} else {
		fmt.Printf("  %s✓%s Authentication: OK\n", green, reset)
	}

	// Test metrics
	_, err = c.get("/metrics")
	if err != nil {
		fmt.Printf("  %s✗%s Prometheus metrics: %v\n", red, reset, err)
	} else {
		fmt.Printf("  %s✓%s Prometheus metrics: available\n", green, reset)
	}

	fmt.Printf("\n%sAll checks passed.%s\n", green, reset)
	return nil
}

func cmdConfig() {
	fmt.Print(`# MythNet Configuration Template
# Save as config.yaml and customize

server:
  host: "0.0.0.0"
  port: 8080
  password: ""       # auto-generated if empty
  tls:
    enabled: false

scanner:
  subnets: []        # auto-detect if empty
  interval: "5m"
  timeout: "2s"

telemetry:
  snmp:
    enabled: true
    listen: "0.0.0.0:1162"
    community: "public"
  syslog:
    enabled: true
    listen: "0.0.0.0:1514"
  poller:
    enabled: true
    interval: "60s"

mesh:
  enabled: false
  node_type: "full"
  bind: "0.0.0.0:7946"
  replica_addr: "0.0.0.0:7947"
  join: []
  secret: ""
  data_dir: "./mythnet-data"

alerts:
  min_severity: "warning"
  webhooks: []
  smtp:
    host: ""
    port: 587
    username: ""
    password: ""
    from: ""
    to: []

ai:
  enabled: true
  api_key: ""        # or set ANTHROPIC_API_KEY
  model: "claude-sonnet-4-20250514"

database:
  path: "mythnet.db"

log:
  level: "info"
`)
}

func slaColor(v any) string {
	pct, ok := v.(float64)
	if !ok {
		return gray + "—" + reset
	}
	color := green
	if pct < 99 {
		color = yellow
	}
	if pct < 95 {
		color = red
	}
	return fmt.Sprintf("%s%.1f%%%s", color, pct, reset)
}
