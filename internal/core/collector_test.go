package core

import (
	"testing"

	"osint-forge/internal/graph"
)

type recEmitter struct{ deltas []graph.Delta }

func (r *recEmitter) EmitDelta(d graph.Delta) { r.deltas = append(r.deltas, d) }
func (r *recEmitter) EmitLog(LogLine)         {}

// Every edge the UI receives must have both endpoint nodes in the same or an
// earlier delta — otherwise Cytoscape throws mid-batch (thick grey bar bug).
func TestFlushNeverSendsEdgeBeforeItsNodes(t *testing.T) {
	g := graph.New()
	em := &recEmitter{}
	base := NewCollector(ParseTarget("example.com"), g, em)
	root := base.Node(graph.NodeDomain, "example.com", "example.com", map[string]any{"root": true})
	base.Flush()

	a := base.forSource("a") // creates the node, flushes LATER
	b := base.forSource("b") // links to it and flushes FIRST
	sub := a.Node(graph.NodeSubdomain, "www.example.com", "www.example.com", nil)
	b.Edge(root, sub, "subdomain")
	b.Flush()
	a.Flush()

	seen := map[string]bool{}
	for _, d := range em.deltas {
		for _, n := range d.Nodes {
			seen[n.ID] = true
		}
		for _, e := range d.Edges {
			if !seen[e.Source] || !seen[e.Target] {
				t.Fatalf("edge %s sent before its endpoint nodes", e.ID)
			}
		}
	}
}

func TestEdgeToMissingNodeIsDropped(t *testing.T) {
	g := graph.New()
	c := NewCollector(ParseTarget("example.com"), g, nil)
	root := c.Node(graph.NodeDomain, "example.com", "example.com", nil)
	c.Edge(root, "url:https://nowhere.example.com", "path")
	c.Edge(root, root, "self")
	if _, e := g.Counts(); e != 0 {
		t.Fatalf("dangling/self edges stored: %d", e)
	}
	for _, e := range g.Snapshot().Edges {
		t.Fatalf("snapshot has dangling edge %s", e.ID)
	}
}

// tls/takeover used to build subdomain:<root> ids that don't exist.
func TestHostIDResolvesRootDomain(t *testing.T) {
	g := graph.New()
	c := NewCollector(ParseTarget("example.com"), g, nil)
	root := c.Node(graph.NodeDomain, "example.com", "example.com", nil)
	if got := c.HostID("example.com"); got != root {
		t.Fatalf("HostID = %q, want %q", got, root)
	}
	c.Finding("high", "k", "title", "desc", graph.NodeID(graph.NodeSubdomain, "example.com"))
	if _, e := g.Counts(); e != 1 {
		t.Fatalf("finding not linked to root domain, edges=%d", e)
	}
}

func TestEmptyKeyCreatesNoNode(t *testing.T) {
	g := graph.New()
	c := NewCollector(ParseTarget("example.com"), g, nil)
	if id := c.Node(graph.NodeSubdomain, "", "", nil); id != "" {
		t.Fatalf("got id %q for empty key", id)
	}
	if n, _ := g.Counts(); n != 0 {
		t.Fatalf("nameless node created")
	}
}
