package main

import (
	"strings"

	"osint-forge/internal/graph"
	"osint-forge/internal/history"
)

// AlertFilter decides which changes of a monitored target are worth an alert.
// The zero value lets everything through (watches created before filters
// existed keep their behaviour).
type AlertFilter struct {
	// Types lists the node types that count ("subdomain", "port", "finding"…).
	// Empty = every type.
	Types []string `json:"types,omitempty"`
	// MinSeverity drops findings/CVEs below it: info < low < medium < high <
	// critical. Empty = any severity. A CISA-KEV CVE always counts as critical.
	MinSeverity string `json:"minSeverity,omitempty"`
	// IgnoreRemoved: only alert on new things, never on disappeared ones.
	IgnoreRemoved bool `json:"ignoreRemoved,omitempty"`
	// Preset is the UI preset the filter came from (display only).
	Preset string `json:"preset,omitempty"`
}

var sevRank = map[string]int{"info": 0, "none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// PresetFilter returns one of the UI presets:
//   - "all":       every change (also URLs, technologies, parameters…)
//   - "important": infrastructure + security — new subdomains, IPs, open
//     ports, services, certificates, CVEs and findings; no URL/tech noise
//   - "critical":  only new high/critical findings and CVEs, and new ports
func PresetFilter(name string) AlertFilter {
	switch name {
	case "important":
		return AlertFilter{Preset: name, Types: []string{"domain", "subdomain", "ip", "port", "service", "certificate", "cve", "finding", "bucket"}}
	case "critical":
		return AlertFilter{Preset: name, Types: []string{"port", "cve", "finding", "bucket"}, MinSeverity: "high", IgnoreRemoved: true}
	default:
		return AlertFilter{Preset: "all"}
	}
}

// normalize drops unknown values so a hand-edited monitor.json can't break it.
func (f AlertFilter) normalize() AlertFilter {
	var types []string
	seen := map[string]bool{}
	for _, t := range f.Types {
		t = strings.ToLower(strings.TrimSpace(t))
		if t != "" && !seen[t] {
			seen[t] = true
			types = append(types, t)
		}
	}
	f.Types = types
	f.MinSeverity = strings.ToLower(strings.TrimSpace(f.MinSeverity))
	if _, ok := sevRank[f.MinSeverity]; !ok {
		f.MinSeverity = ""
	}
	return f
}

// severityOf ranks a finding/CVE node; ok=false for other node types.
func severityOf(n *graph.Node) (rank int, ok bool) {
	if n.Type != graph.NodeFinding && n.Type != graph.NodeCVE {
		return 0, false
	}
	if kev, _ := n.Props["known_exploited"].(bool); kev {
		return sevRank["critical"], true
	}
	s, _ := n.Props["severity"].(string)
	if r, known := sevRank[strings.ToLower(s)]; known {
		return r, true
	}
	return sevRank["low"], true // unknown (e.g. a Shodan CVE id): low
}

func (f AlertFilter) keep(n *graph.Node) bool {
	if len(f.Types) > 0 {
		match := false
		for _, t := range f.Types {
			if string(n.Type) == t {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}
	if f.MinSeverity != "" {
		if r, ok := severityOf(n); ok && r < sevRank[f.MinSeverity] {
			return false
		}
	}
	return true
}

// Apply returns the part of a diff that passes the filter.
func (f AlertFilter) Apply(d history.Diff) history.Diff {
	f = f.normalize()
	out := d
	out.Added, out.Removed = nil, nil
	for _, n := range d.Added {
		if f.keep(n) {
			out.Added = append(out.Added, n)
		}
	}
	if !f.IgnoreRemoved {
		for _, n := range d.Removed {
			if f.keep(n) {
				out.Removed = append(out.Removed, n)
			}
		}
	}
	return out
}
