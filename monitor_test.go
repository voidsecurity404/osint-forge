package main

import (
	"strings"
	"testing"
	"time"

	"osint-forge/internal/graph"
	"osint-forge/internal/history"
)

func TestMonitorAddListRemove(t *testing.T) {
	m := NewMonitor(&App{})
	if _, err := m.Add("", 10, false); err == nil {
		t.Fatal("empty target should error")
	}
	w, err := m.Add("example.com", 1, true) // below floor → bumped to 5
	if err != nil {
		t.Fatal(err)
	}
	if w.IntervalMin != 5 {
		t.Fatalf("interval floor not applied: %d", w.IntervalMin)
	}
	if w.NextRun.Before(time.Now().Add(4 * time.Minute)) {
		t.Fatal("next run too soon")
	}
	if l := m.List(); len(l) != 1 || l[0].Target != "example.com" {
		t.Fatalf("list wrong: %+v", l)
	}
	// re-add updates in place (no duplicate)
	m.Add("https://example.com/path", 60, false)
	if l := m.List(); len(l) != 1 {
		t.Fatalf("duplicate watch: %+v", l)
	}
	m.Remove("example.com")
	if l := m.List(); len(l) != 0 {
		t.Fatalf("remove failed: %+v", l)
	}
}

func TestFormatAlert(t *testing.T) {
	d := history.Diff{
		Added:   []*graph.Node{{Type: "subdomain", Label: "new.example.com"}, {Type: "port", Label: "8080/tcp"}},
		Removed: []*graph.Node{{Type: "url", Label: "http://example.com/old"}},
	}
	msg := formatAlert("example.com", d)
	for _, want := range []string{"example.com", "+2 новых, −1 исчезло", "➕ subdomain: new.example.com", "➖ url:"} {
		if !strings.Contains(msg, want) {
			t.Errorf("alert missing %q:\n%s", want, msg)
		}
	}
}
