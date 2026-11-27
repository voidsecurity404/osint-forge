package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"osint-forge/internal/config"
	"osint-forge/internal/graph"
	"osint-forge/internal/history"
)

func snap(ids ...string) graph.Delta {
	var d graph.Delta
	for _, id := range ids {
		d.Nodes = append(d.Nodes, &graph.Node{ID: id, Type: "subdomain", Label: id})
	}
	return d
}

// result builds the ScanResult the app hands to hooks: the diff of the new
// snapshot against the last stored scan, computed before saving.
func result(t *testing.T, req ScanRequest, s graph.Delta, complete bool) ScanResult {
	t.Helper()
	d, err := history.DiffAgainstPrevious("example.com", s)
	if err != nil {
		t.Fatal(err)
	}
	return ScanResult{Request: req, Snapshot: s, Diff: d, Complete: complete}
}

// webhook returns a test server that forwards every request body to the
// returned channel.
func webhook(t *testing.T) (*httptest.Server, chan string) {
	got := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- string(b)
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func expectNone(t *testing.T, got chan string, why string) {
	t.Helper()
	select {
	case body := <-got:
		t.Fatalf("%s: unexpected alert %s", why, body)
	case <-time.After(200 * time.Millisecond):
	}
}

// Full glue: a monitor-triggered scan whose result differs from the previous
// stored scan must push an alert to the configured webhook.
func TestMonitorScanDoneAlertsOnChange(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	srv, got := webhook(t)
	history.Save("example.com", snap("root", "a"))

	app := &App{cfg: config.Config{WebhookURL: srv.URL}}
	m := NewMonitor(app)
	m.Add("example.com", 60, false)
	next := snap("root", "a", "new.example.com")

	// Non-monitor scans are ignored.
	m.onScanDone(result(t, ScanRequest{Target: "example.com"}, next, true))
	expectNone(t, got, "manual scan")

	// Monitor scan with a real diff → alert.
	m.onScanDone(result(t, ScanRequest{Target: "example.com", Monitor: true}, next, true))
	select {
	case body := <-got:
		if !strings.Contains(body, "new.example.com") {
			t.Fatalf("alert missing new host: %s", body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no alert sent on change")
	}
}

// A monitor scan that was cancelled or ran out of time sees only part of the
// target: everything it missed looked "removed" and triggered a false alert.
func TestMonitorIgnoresIncompleteScan(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	srv, got := webhook(t)
	history.Save("example.com", snap("root", "a", "b", "c"))

	m := NewMonitor(&App{cfg: config.Config{WebhookURL: srv.URL}})
	m.Add("example.com", 60, false)
	m.onScanDone(result(t, ScanRequest{Target: "example.com", Monitor: true}, snap("root"), false))
	expectNone(t, got, "incomplete scan")
	if l := m.List(); !strings.Contains(l[0].LastChange, "не завершилось полностью") {
		t.Fatalf("LastChange = %q", l[0].LastChange)
	}
}

// Watches used to live only in memory and vanished on every restart.
func TestMonitorPersistsWatches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "monitor.json")
	m := NewMonitor(&App{})
	if err := m.Persist(path); err != nil {
		t.Fatal(err)
	}
	m.Add("https://Example.com/x", 60, true)
	m.Add("1.1.1.1", 5, false)
	m.Remove("1.1.1.1")

	again := NewMonitor(&App{})
	if err := again.Persist(path); err != nil {
		t.Fatal(err)
	}
	l := again.List()
	if len(l) != 1 || l[0].Target != "example.com" || l[0].IntervalMin != 60 || !l[0].Consent {
		t.Fatalf("restored watches = %+v", l)
	}
}

// When another scan is running, a due watch must stay due (retried on the next
// tick) instead of being pushed a whole interval into the future.
func TestMonitorTickRetriesWhenBusy(t *testing.T) {
	app := &App{running: true}
	m := NewMonitor(app)
	m.Add("example.com", 60, false)
	future := time.Now().Add(2 * time.Hour)
	m.tick(future)
	if w := m.List()[0]; !w.LastRun.IsZero() || w.NextRun.After(future) {
		t.Fatalf("busy tick advanced the schedule: %+v", w)
	}
}
