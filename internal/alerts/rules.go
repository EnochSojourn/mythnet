package alerts

import (
	"encoding/json"
	"strings"

	"github.com/mythnet/mythnet/internal/db"
)

// EventRule is a user-defined pattern for matching and re-classifying events.
type EventRule struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Pattern     string `json:"pattern"`      // substring match on title or body
	SourceMatch string `json:"source_match"` // match event source (empty = all)
	SetSeverity string `json:"set_severity"` // override severity if matched
	AddTag      string `json:"add_tag"`      // add this tag if matched
	Enabled     bool   `json:"enabled"`
}

// MatchEvent checks if an event matches this rule.
func (r *EventRule) MatchEvent(e *db.Event) bool {
	if !r.Enabled {
		return false
	}
	if r.SourceMatch != "" && !strings.EqualFold(e.Source, r.SourceMatch) {
		return false
	}
	if r.Pattern == "" {
		return true
	}
	lower := strings.ToLower(r.Pattern)
	return strings.Contains(strings.ToLower(e.Title), lower) ||
		strings.Contains(strings.ToLower(e.BodyMD), lower) ||
		strings.Contains(strings.ToLower(e.Tags), lower)
}

// ApplyRules evaluates all enabled rules against an event and modifies it in place.
func ApplyRules(store *db.Store, e *db.Event) {
	rules := LoadEventRules(store)
	for _, r := range rules {
		if r.MatchEvent(e) {
			if r.SetSeverity != "" {
				e.Severity = r.SetSeverity
			}
			if r.AddTag != "" {
				if e.Tags != "" {
					e.Tags += ","
				}
				e.Tags += r.AddTag
			}
		}
	}
}

// LoadEventRules retrieves all event rules from the database.
func LoadEventRules(store *db.Store) []EventRule {
	rows, err := store.DB().Query(`SELECT id, data FROM event_rules ORDER BY id`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var rules []EventRule
	for rows.Next() {
		var id int64
		var data string
		rows.Scan(&id, &data)
		var r EventRule
		json.Unmarshal([]byte(data), &r)
		r.ID = id
		rules = append(rules, r)
	}
	return rules
}
