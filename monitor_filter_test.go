package main

import (
	"strings"
	"testing"

	"osint-forge/internal/config"
	"osint-forge/internal/graph"
	"osint-forge/internal/history"
)

func n(id, typ string, props map[string]any) *graph.Node {
	return &graph.Node{ID: id, Type: graph.NodeType(typ), Label: id, Props: props}
}

func TestAlertFilterApply(t *testing.T) {
	d := history.Diff{HasPrevious: true,
		Added: []*graph.Node{
			n("subdomain:new.example.com", "subdomain", nil),
			n("url:https://example.com/old-archive", "url", map[string]any{"archived": true}),
			n("technology:nginx", "technology", nil),
			n("finding:spf-missing:x", "finding", map[string]any{"severity": "medium"}),
			n("finding:cors:x", "finding", map[string]any{"severity": "high"}),
			n("cve:CVE-1", "cve", map[string]any{"severity": "LOW"}),
			n("cve:CVE-2", "cve", map[string]any{"known_exploited": true}), // KEV counts as critical
			n("port:1.2.3.4:8080/tcp", "port", nil),
		},
		Removed: []*graph.Node{n("port:1.2.3.4:22/tcp", "port", nil), n("url:https://example.com/x", "url", nil)},
	}

	// Zero filter (watches saved before filters existed) = every change.
	if got := (AlertFilter{}).Apply(d); len(got.Added) != 8 || len(got.Removed) != 2 {
		t.Fatalf("zero filter changed the diff: +%d -%d", len(got.Added), len(got.Removed))
	}

	// "Muhim" preset: infrastructure + security, no URL/tech noise.
	got := PresetFilter("important").Apply(d)
	ids := idsOf(got.Added)
	for _, want := range []string{"subdomain:new.example.com", "finding:cors:x", "port:1.2.3.4:8080/tcp", "cve:CVE-2"} {
		if !strings.Contains(ids, want) {
			t.Errorf("important preset dropped %s (%s)", want, ids)
		}
	}
	for _, noise := range []string{"url:", "technology:"} {
		if strings.Contains(ids, noise) {
			t.Errorf("important preset kept noise %s (%s)", noise, ids)
		}
	}
	if len(got.Removed) != 1 || got.Removed[0].ID != "port:1.2.3.4:22/tcp" {
		t.Errorf("removed = %s", idsOf(got.Removed))
	}

	// Minimum severity applies to findings and CVEs only.
	f := AlertFilter{Types: []string{"finding", "cve", "port"}, MinSeverity: "high"}
	ids = idsOf(f.Apply(d).Added)
	if strings.Contains(ids, "spf-missing") || strings.Contains(ids, "CVE-1") {
		t.Errorf("below-threshold findings kept: %s", ids)
	}
	if !strings.Contains(ids, "cors") || !strings.Contains(ids, "CVE-2") || !strings.Contains(ids, "8080") {
		t.Errorf("threshold dropped real alerts: %s", ids)
	}
	// Removed items can be muted.
	f.IgnoreRemoved = true
	if r := f.Apply(d).Removed; len(r) != 0 {
		t.Errorf("IgnoreRemoved kept %d", len(r))
	}
}

func idsOf(ns []*graph.Node) string {
	var b strings.Builder
	for _, x := range ns {
		b.WriteString(x.ID + " ")
	}
	return b.String()
}

// Only filtered changes are sent; a run whose changes are all filtered out
// sends nothing but says so in the panel.
func TestMonitorAlertsOnlyFilteredChanges(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	srv, got := webhook(t)
	history.Save("example.com", snap("root"))
	m := NewMonitor(&App{cfg: config.Config{WebhookURL: srv.URL}})
	if _, err := m.AddWatch("example.com", 60, false, PresetFilter("important")); err != nil {
		t.Fatal(err)
	}
	noise := graph.Delta{Nodes: []*graph.Node{{ID: "root", Type: "domain"}, {ID: "url:https://example.com/a", Type: "url", Label: "/a"}}}
	m.onScanDone(result(t, ScanRequest{Target: "example.com", Monitor: true}, noise, true))
	expectNone(t, got, "url-only change")
	if lc := m.List()[0].LastChange; !strings.Contains(lc, "filtr") {
		t.Fatalf("LastChange = %q", lc)
	}

	history.Save("example.com", noise)
	real := graph.Delta{Nodes: append(noise.Nodes, &graph.Node{ID: "port:1.2.3.4:3306/tcp", Type: "port", Label: "3306/tcp"})}
	m.onScanDone(result(t, ScanRequest{Target: "example.com", Monitor: true}, real, true))
	body := <-got
	if !strings.Contains(body, "3306/tcp") || strings.Contains(body, "/a") {
		t.Fatalf("alert = %s", body)
	}
}
