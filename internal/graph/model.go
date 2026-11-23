// Package graph defines the central data model of osint-forge: a graph of
// discovered entities (nodes) connected by relationships (edges). Every piece
// of information a scan finds becomes one or more nodes plus the edges that
// link it to what it was discovered from. The frontend renders this graph with
// Cytoscape.js in an Obsidian-like layout.
package graph

import (
	"sort"
	"sync"
)

// NodeType enumerates the kinds of entities the graph can hold.
type NodeType string

const (
	NodeIP        NodeType = "ip"
	NodeDomain    NodeType = "domain"
	NodeSubdomain NodeType = "subdomain"
	NodePort      NodeType = "port"
	NodeService   NodeType = "service"
	NodeTech      NodeType = "technology"
	NodeCert      NodeType = "certificate"
	NodeASN       NodeType = "asn"
	NodeWhois     NodeType = "whois_org"
	NodeURL       NodeType = "url"
	NodeEmail     NodeType = "email"
	NodeCVE       NodeType = "cve"
	NodeFinding   NodeType = "finding" // a security issue / misconfiguration
)

// Node is a single entity in the graph. ID must be stable and deterministic so
// that the same entity discovered via different sources collapses into one node
// (e.g. "ip:1.2.3.4"). Props carries type-specific detail shown in the UI.
type Node struct {
	ID    string         `json:"id"`
	Type  NodeType       `json:"type"`
	Label string         `json:"label"`
	Props map[string]any `json:"props,omitempty"`
}

// Edge is a directed relationship between two nodes (e.g. "resolves_to").
type Edge struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Target string `json:"target"`
	Label  string `json:"label"`
}

// Delta is an incremental batch of new nodes/edges, streamed to the frontend so
// the graph fills in live while a scan runs.
type Delta struct {
	Nodes []*Node `json:"nodes"`
	Edges []*Edge `json:"edges"`
}

// Empty reports whether the delta carries nothing new.
func (d Delta) Empty() bool { return len(d.Nodes) == 0 && len(d.Edges) == 0 }

// Graph is a concurrency-safe collection of nodes and edges with de-duplication.
type Graph struct {
	mu    sync.Mutex
	nodes map[string]*Node
	edges map[string]*Edge
}

// New returns an empty graph.
func New() *Graph {
	return &Graph{
		nodes: make(map[string]*Node),
		edges: make(map[string]*Edge),
	}
}

// NodeID builds a stable node id from a type and a natural key.
func NodeID(t NodeType, key string) string { return string(t) + ":" + key }

// AddNode inserts a node if absent, or merges new Props into an existing one.
// It returns a SNAPSHOT COPY (safe to serialize/emit concurrently) of the
// resulting node and whether it was newly created. Returning the live pointer
// would let a concurrent merge mutate the node's Props map while the UI layer
// serializes it — a fatal "concurrent map write" that would crash the app.
func (g *Graph) AddNode(n *Node) (*Node, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if existing, ok := g.nodes[n.ID]; ok {
		if n.Props != nil {
			if existing.Props == nil {
				existing.Props = map[string]any{}
			}
			for k, v := range n.Props {
				existing.Props[k] = v
			}
		}
		if existing.Label == "" {
			existing.Label = n.Label
		}
		return existing.copy(), false
	}
	if n.Props == nil {
		n.Props = map[string]any{}
	}
	g.nodes[n.ID] = n
	return n.copy(), true
}

// copy returns a shallow clone with a copied Props map, safe to hand to other
// goroutines. Must be called while the graph lock is held (the source node is
// shared state).
func (n *Node) copy() *Node {
	props := make(map[string]any, len(n.Props))
	for k, v := range n.Props {
		props[k] = v
	}
	return &Node{ID: n.ID, Type: n.Type, Label: n.Label, Props: props}
}

// AddEdge inserts at most ONE edge per directed node pair. The id intentionally
// ignores the label: a node discovered through several relationships (e.g. a host
// that is both an "ns" and a "subdomain" of the domain) would otherwise get
// multiple parallel edges, which render as a thick fanned-out band/wedge between
// the two nodes. The first relationship's label is kept.
func (g *Graph) AddEdge(source, target, label string) (*Edge, bool) {
	id := source + "->" + target
	g.mu.Lock()
	defer g.mu.Unlock()
	if e, ok := g.edges[id]; ok {
		return e, false
	}
	e := &Edge{ID: id, Source: source, Target: target, Label: label}
	g.edges[id] = e
	return e, true
}

// Snapshot returns a stable, sorted copy of the whole graph.
func (g *Graph) Snapshot() Delta {
	g.mu.Lock()
	defer g.mu.Unlock()
	d := Delta{}
	for _, n := range g.nodes {
		d.Nodes = append(d.Nodes, n.copy()) // copies: safe to serialize outside the lock
	}
	for _, e := range g.edges {
		ec := *e
		d.Edges = append(d.Edges, &ec)
	}
	sort.Slice(d.Nodes, func(i, j int) bool { return d.Nodes[i].ID < d.Nodes[j].ID })
	sort.Slice(d.Edges, func(i, j int) bool { return d.Edges[i].ID < d.Edges[j].ID })
	return d
}

// Counts returns the number of nodes and edges currently held.
func (g *Graph) Counts() (nodes, edges int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.nodes), len(g.edges)
}

// Get returns the node with the given id, if present. The returned pointer is
// shared; callers must only read it.
func (g *Graph) Get(id string) (*Node, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	n, ok := g.nodes[id]
	return n, ok
}

// ListByType returns the natural keys (id without the type prefix) of all nodes
// of the given type, sorted. Used by active scanners to enumerate discovered
// hosts/IPs to probe.
func (g *Graph) ListByType(t NodeType) []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	prefix := string(t) + ":"
	var out []string
	for id := range g.nodes {
		if len(id) > len(prefix) && id[:len(prefix)] == prefix {
			out = append(out, id[len(prefix):])
		}
	}
	sort.Strings(out)
	return out
}
