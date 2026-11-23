package history

import (
	"testing"

	"osint-forge/internal/graph"
)

func node(id string) *graph.Node { return &graph.Node{ID: id, Label: id} }

func TestDiffLastTwo(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	target := "example.com"

	first := graph.Delta{Nodes: []*graph.Node{node("ip:1.1.1.1"), node("subdomain:a.example.com")}}
	if _, err := Save(target, first); err != nil {
		t.Fatal(err)
	}
	second := graph.Delta{Nodes: []*graph.Node{
		node("ip:1.1.1.1"),              // unchanged
		node("subdomain:b.example.com"), // added
		// a.example.com removed
	}}
	if _, err := Save(target, second); err != nil {
		t.Fatal(err)
	}

	diff, err := DiffLastTwo(target)
	if err != nil {
		t.Fatal(err)
	}
	if !diff.HasPrevious {
		t.Fatal("expected a previous snapshot")
	}
	if len(diff.Added) != 1 || diff.Added[0].ID != "subdomain:b.example.com" {
		t.Errorf("unexpected added: %+v", diff.Added)
	}
	if len(diff.Removed) != 1 || diff.Removed[0].ID != "subdomain:a.example.com" {
		t.Errorf("unexpected removed: %+v", diff.Removed)
	}
}

func TestDiffNoPrevious(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	diff, err := DiffLastTwo("fresh.example")
	if err != nil {
		t.Fatal(err)
	}
	if diff.HasPrevious {
		t.Error("expected no previous snapshot")
	}
}
