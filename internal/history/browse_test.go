package history

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"osint-forge/internal/graph"
)

func delta(ids ...string) graph.Delta {
	var d graph.Delta
	for _, id := range ids {
		d.Nodes = append(d.Nodes, &graph.Node{ID: id, Type: "subdomain", Label: id})
	}
	for i := 1; i < len(ids); i++ {
		d.Edges = append(d.Edges, &graph.Edge{ID: ids[0] + "->" + ids[i], Source: ids[0], Target: ids[i]})
	}
	return d
}

func TestBrowseCompareDelete(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	if _, err := Save("example.com", delta("root", "a", "b")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, err := Save("example.com", delta("root", "b", "c")); err != nil {
		t.Fatal(err)
	}

	ts, err := Targets()
	if err != nil || len(ts) != 1 || ts[0].Scans != 2 {
		t.Fatalf("targets = %+v, %v", ts, err)
	}
	list, _ := List("example.com")
	if len(list) != 2 || !list[0].When.After(list[1].When) {
		t.Fatalf("list not newest-first: %+v", list)
	}

	c, err := CompareScans("example.com", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Added) != 1 || c.Added[0] != "c" || len(c.Removed) != 1 || c.Removed[0] != "a" {
		t.Fatalf("compare added=%v removed=%v", c.Added, c.Removed)
	}
	// union graph keeps the removed node and its old edge
	if len(c.Graph.Nodes) != 4 || len(c.Graph.Edges) != 3 {
		t.Fatalf("union graph nodes=%d edges=%d", len(c.Graph.Nodes), len(c.Graph.Edges))
	}

	if _, _, ok := Latest(); !ok {
		t.Fatal("Latest not found")
	}
	if _, err := Load("example.com", "../../etc/passwd"); err == nil {
		t.Fatal("path traversal id accepted")
	}
	if err := Delete("example.com", list[0].ID); err != nil {
		t.Fatal(err)
	}
	if l, _ := List("example.com"); len(l) != 1 {
		t.Fatalf("delete failed, %d left", len(l))
	}
}

// Reading history for a target that was never scanned must not create an
// empty directory, and must explain itself instead of "no such file".
func TestReadsDoNotCreateDirs(t *testing.T) {
	cache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	if _, err := CompareScans("https://never.example/", "", ""); err == nil || err.Error() != ErrNoScans.Error() {
		t.Fatalf("err = %v, want ErrNoScans", err)
	}
	List("never.example")
	DiffLastTwo("never.example")
	if ts, _ := Targets(); len(ts) != 0 {
		t.Fatalf("reads created history entries: %+v", ts)
	}
	if entries, _ := os.ReadDir(filepath.Join(cache, "osint-forge", "history")); len(entries) != 0 {
		t.Fatalf("reads created %d directories", len(entries))
	}
}

// An IPv6 target is stored under a sanitised directory name; listing must
// still give back the real target so it can be scanned/opened again.
func TestTargetsKeepRealLabel(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	Save("2606:4700::1111", delta("root"))
	ts, _ := Targets()
	if len(ts) != 1 || ts[0].Target != "2606:4700::1111" {
		t.Fatalf("targets = %+v", ts)
	}
	if l, _ := List(ts[0].Target); len(l) != 1 {
		t.Fatalf("list via real label failed: %+v", l)
	}
}

// Monitoring every 5 minutes used to store a new file per run forever. A scan
// identical to the previous one replaces it, and the total is capped.
func TestSaveDedupesAndCaps(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	Save("example.com", delta("root", "a"))
	time.Sleep(2 * time.Millisecond)
	Save("example.com", delta("root", "a")) // identical → replaces
	if l, _ := List("example.com"); len(l) != 1 {
		t.Fatalf("identical scan stored twice: %d", len(l))
	}
	for i := 0; i < maxScansPerTarget+5; i++ {
		Save("example.com", delta("root", fmt.Sprint("n", i)))
	}
	if l, _ := List("example.com"); len(l) != maxScansPerTarget {
		t.Fatalf("history not capped: %d", len(l))
	}
}
