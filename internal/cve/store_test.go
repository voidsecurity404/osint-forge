package cve

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// The web server and a reconcli run share one cve.sqlite. Without a busy
// timeout the second writer failed instantly with SQLITE_BUSY ("database is
// locked") and the CVE cache silently stopped working for that scan.
func TestStoreWaitsForConcurrentWriter(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cve.sqlite")
	a, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	tx, err := a.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO query_log(query, fetched_at) VALUES('x', 1)`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- b.Save("nginx 1.18.0", []Match{{ID: "CVE-2021-23017", Severity: "HIGH", Score: 7.7}}) }()
	time.Sleep(300 * time.Millisecond)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("second writer failed instead of waiting: %v", err)
	}
	if m, fresh, err := a.Cached("nginx 1.18.0"); err != nil || !fresh || len(m) != 1 {
		t.Fatalf("cached = %v fresh=%v err=%v", m, fresh, err)
	}
}

// CVEs reported directly by Shodan (no service match) were never flagged as
// CISA KEV or scored with EPSS — and with no service nodes the whole CVE
// source returned early.
func TestKEVAppliedToAllCVENodes(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "cve.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.saveKEV([]string{"CVE-2021-44228"}); err != nil {
		t.Fatal(err)
	}

	g := graph.New()
	c := core.NewCollector(core.ParseTarget("example.com"), g, nil)
	c.Node(graph.NodeCVE, "CVE-2021-44228", "CVE-2021-44228", map[string]any{"source": "shodan"})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // no network in tests: EPSS fetch is skipped on a dead context
	src := Source{Cfg: config.Default(), Store: st, Client: NewClient("", "test")}
	if err := src.Run(ctx, c); err != nil {
		t.Fatal(err)
	}
	n, _ := c.GetNode(graph.NodeCVE, "CVE-2021-44228")
	if n.Props["known_exploited"] != true {
		t.Fatalf("Shodan CVE not flagged as KEV: %+v", n.Props)
	}
}
