package core

import (
	"sync"

	"osint-forge/internal/graph"
)

// LogLevel classifies pipeline log lines surfaced in the UI.
type LogLevel string

const (
	LogInfo  LogLevel = "info"
	LogWarn  LogLevel = "warn"
	LogError LogLevel = "error"
)

// LogLine is a single human-readable progress message from a source.
type LogLine struct {
	Source  string   `json:"source"`
	Level   LogLevel `json:"level"`
	Message string   `json:"message"`
}

// Emitter receives live updates from a running scan. The App implementation
// forwards these to the frontend over Wails events.
type Emitter interface {
	EmitDelta(graph.Delta)
	EmitLog(LogLine)
}

// Collector is handed to every Source. It adds entities to the shared graph,
// buffers what is new, and flushes batches to the Emitter so the UI fills live.
type Collector struct {
	Target Target

	g     *graph.Graph
	em    Emitter
	name  string // current source name, for log attribution
	scope Scope  // active-probing allowlist

	mu      sync.Mutex
	pending graph.Delta
}

// NewCollector creates a collector bound to a graph and emitter.
func NewCollector(t Target, g *graph.Graph, em Emitter) *Collector {
	return &Collector{Target: t, g: g, em: em}
}

// SetScope sets the active-probing allowlist.
func (c *Collector) SetScope(s Scope) { c.scope = s }

// InScope reports whether an active source may probe the given host. Active
// sources MUST gate every outbound probe on this so intrusive traffic never
// reaches hosts the user is not authorized to test.
func (c *Collector) InScope(host string) bool { return c.scope.Allows(host) }

// forSource returns a shallow copy tagged with a source name for logging.
func (c *Collector) forSource(name string) *Collector {
	return &Collector{Target: c.Target, g: c.g, em: c.em, name: name, scope: c.scope}
}

// Node adds or merges a node and buffers it for the UI. It returns the id so
// callers can wire edges to it.
//
// The node is buffered both when newly created AND when props are merged into an
// existing node, so enrichment added by a later source (e.g. EPSS scores on a
// CVE, WHOIS country on the root) actually reaches the frontend. Merging without
// re-emitting was a bug: the UI only ever saw the first source's props.
func (c *Collector) Node(t graph.NodeType, key, label string, props map[string]any) string {
	id := graph.NodeID(t, key)
	merged, isNew := c.g.AddNode(&graph.Node{ID: id, Type: t, Label: label, Props: props})
	if isNew || len(props) > 0 {
		c.mu.Lock()
		c.pending.Nodes = append(c.pending.Nodes, merged)
		c.mu.Unlock()
	}
	return id
}

// Edge links two existing node ids and buffers it if newly created.
func (c *Collector) Edge(source, target, label string) {
	e, isNew := c.g.AddEdge(source, target, label)
	if isNew {
		c.mu.Lock()
		c.pending.Edges = append(c.pending.Edges, e)
		c.mu.Unlock()
	}
}

// Flush sends everything buffered since the last flush to the UI.
func (c *Collector) Flush() {
	c.mu.Lock()
	d := c.pending
	c.pending = graph.Delta{}
	c.mu.Unlock()
	if !d.Empty() && c.em != nil {
		c.em.EmitDelta(d)
	}
}

// ListByType exposes discovered node keys of a type to active sources (e.g. the
// set of IPs for a port scan).
func (c *Collector) ListByType(t graph.NodeType) []string { return c.g.ListByType(t) }

// Finding records a security issue / misconfiguration as a node, linked to the
// affected target. severity is one of: critical, high, medium, low, info.
func (c *Collector) Finding(severity, key, title, description, targetID string) {
	id := c.Node(graph.NodeFinding, key, title, map[string]any{
		"severity":    severity,
		"description": description,
		"source":      c.name,
	})
	if targetID != "" {
		c.Edge(targetID, id, "finding")
	}
}

// GetNode returns a discovered node by type and key for reading its props
// (used by the CVE engine to read a service's product/version/cpe).
func (c *Collector) GetNode(t graph.NodeType, key string) (*graph.Node, bool) {
	return c.g.Get(graph.NodeID(t, key))
}

// Logf emits a formatted progress line attributed to the current source.
func (c *Collector) Log(level LogLevel, msg string) {
	if c.em != nil {
		c.em.EmitLog(LogLine{Source: c.name, Level: level, Message: msg})
	}
}
