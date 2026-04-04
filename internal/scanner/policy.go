package scanner

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mythnet/mythnet/internal/db"
)

// Policy defines an expected state rule for the network.
type Policy struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"` // "critical", "warning"
	// Match criteria
	MatchTag  string `json:"match_tag,omitempty"`  // devices with this tag
	MatchType string `json:"match_type,omitempty"` // devices of this type
	// Conditions
	RequirePort   int  `json:"require_port,omitempty"`   // port must be open
	ForbidPort    int  `json:"forbid_port,omitempty"`    // port must NOT be open
	RequireOnline bool `json:"require_online,omitempty"` // device must be online
	Enabled       bool `json:"enabled"`
}

// PolicyViolation is a policy check failure.
type PolicyViolation struct {
	PolicyName string `json:"policy_name"`
	DeviceID   string `json:"device_id"`
	DeviceIP   string `json:"device_ip"`
	Message    string `json:"message"`
}

// CheckPolicies evaluates all enabled policies against the current network state.
func CheckPolicies(store *db.Store) ([]PolicyViolation, error) {
	policies, err := LoadPolicies(store)
	if err != nil {
		return nil, err
	}

	devices, err := store.ListDevices()
	if err != nil {
		return nil, err
	}

	var violations []PolicyViolation

	for _, pol := range policies {
		if !pol.Enabled {
			continue
		}

		for _, dev := range devices {
			if !matchesPolicy(store, &pol, dev) {
				continue
			}

			ports, _ := store.GetDevicePorts(dev.ID)
			portSet := make(map[int]bool)
			for _, p := range ports {
				portSet[p.Port] = true
			}

			if pol.RequireOnline && !dev.IsOnline {
				violations = append(violations, PolicyViolation{
					PolicyName: pol.Name, DeviceID: dev.ID, DeviceIP: dev.IP,
					Message: fmt.Sprintf("Device is offline (policy requires online)"),
				})
			}

			if pol.RequirePort > 0 && !portSet[pol.RequirePort] {
				violations = append(violations, PolicyViolation{
					PolicyName: pol.Name, DeviceID: dev.ID, DeviceIP: dev.IP,
					Message: fmt.Sprintf("Required port %d is not open", pol.RequirePort),
				})
			}

			if pol.ForbidPort > 0 && portSet[pol.ForbidPort] {
				violations = append(violations, PolicyViolation{
					PolicyName: pol.Name, DeviceID: dev.ID, DeviceIP: dev.IP,
					Message: fmt.Sprintf("Forbidden port %d is open", pol.ForbidPort),
				})
			}
		}
	}

	return violations, nil
}

func matchesPolicy(store *db.Store, pol *Policy, dev *db.Device) bool {
	if pol.MatchType != "" && !strings.EqualFold(dev.DeviceType, pol.MatchType) {
		return false
	}
	if pol.MatchTag != "" {
		tags, _ := store.GetDeviceTags(dev.ID)
		found := false
		for _, t := range tags {
			if strings.EqualFold(t, pol.MatchTag) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// PolicyViolationsToEvents converts violations into alert events.
func PolicyViolationsToEvents(violations []PolicyViolation) []*db.Event {
	var events []*db.Event
	now := time.Now()

	for _, v := range violations {
		title := fmt.Sprintf("Policy violation: %s — %s", v.PolicyName, v.DeviceIP)
		body := fmt.Sprintf("## Policy Violation — %s\n\n**Device:** `%s`  \n**Policy:** %s  \n**Issue:** %s\n",
			v.PolicyName, v.DeviceIP, v.PolicyName, v.Message)

		events = append(events, &db.Event{
			DeviceID:   v.DeviceID,
			Source:     "policy",
			Severity:   "warning",
			Title:      title,
			BodyMD:     body,
			ReceivedAt: now,
			Tags:       "policy,violation",
		})
	}
	return events
}

// --- Policy storage in DB ---

func LoadPolicies(store *db.Store) ([]Policy, error) {
	rows, err := store.DB().Query(`SELECT id, data FROM policies WHERE 1=1 ORDER BY id`)
	if err != nil {
		return nil, nil // Table may not exist yet
	}
	defer rows.Close()

	var policies []Policy
	for rows.Next() {
		var id int64
		var data string
		rows.Scan(&id, &data)
		var p Policy
		json.Unmarshal([]byte(data), &p)
		p.ID = id
		policies = append(policies, p)
	}
	return policies, nil
}
