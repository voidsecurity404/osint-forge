package core

import (
	"net"
	"strings"
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

	// resolved holds the IPs that in-scope names resolved to during this scan.
	// Shared (by pointer) between every source's collector.
	resolved *ipSet

	mu      sync.Mutex
	pending graph.Delta

	nNodes, nEdges int // new nodes/edges this collector created (timing stats)
}

// ipSet is a concurrency-safe set of normalised IP strings.
type ipSet struct {
	mu sync.Mutex
	m  map[string]bool
}

func (s *ipSet) add(ip string) {
	s.mu.Lock()
	s.m[ip] = true
	s.mu.Unlock()
}

func (s *ipSet) has(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[ip]
}

// normIP returns the canonical form of an IP literal (brackets stripped), or "".
func normIP(s string) string {
	ip := net.ParseIP(strings.Trim(strings.TrimSpace(s), "[]"))
	if ip == nil {
		return ""
	}
	return ip.String()
}

// added reports how many new nodes and edges this collector created.
func (c *Collector) added() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.nNodes, c.nEdges
}

// NewCollector creates a collector bound to a graph and emitter.
func NewCollector(t Target, g *graph.Graph, em Emitter) *Collector {
	return &Collector{Target: t, g: g, em: em, resolved: &ipSet{m: map[string]bool{}}}
}

// SetScope sets the active-probing allowlist.
func (c *Collector) SetScope(s Scope) { c.scope = s }

// InScope reports whether an active source may probe the given host. Active
// sources MUST gate every outbound probe on this so intrusive traffic never
// reaches hosts the user is not authorized to test.
//
// An IP is in scope when the static scope allows it (target IP, extra CIDR) or
// when an in-scope name resolved to it during this scan (MarkResolved).
func (c *Collector) InScope(host string) bool {
	if c.scope.Allows(host) {
		return true
	}
	if ip := normIP(host); ip != "" && c.resolved != nil {
		return c.resolved.has(ip)
	}
	return false
}

// MarkResolved records that host currently resolves (live DNS) to ip. When the
// host is in scope, the IP becomes in scope for active probing too. Historical
// data (passive DNS) must NOT be recorded here: an IP a name pointed to years
// ago may belong to someone else today.
func (c *Collector) MarkResolved(host, ip string) {
	if c.resolved == nil || !c.scope.Allows(host) {
		return
	}
	if n := normIP(ip); n != "" {
		c.resolved.add(n)
	}
}

// forSource returns a shallow copy tagged with a source name for logging.
func (c *Collector) forSource(name string) *Collector {
	return &Collector{Target: c.Target, g: c.g, em: c.em, name: name, scope: c.scope, resolved: c.resolved}
}

// Node adds or merges a node and buffers it for the UI. It returns the id so
// callers can wire edges to it.
//
// The node is buffered both when newly created AND when props are merged into an
// existing node, so enrichment added by a later source (e.g. EPSS scores on a
// CVE, WHOIS country on the root) actually reaches the frontend. Merging without
// re-emitting was a bug: the UI only ever saw the first source's props.
func (c *Collector) Node(t graph.NodeType, key, label string, props map[string]any) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return "" // e.g. a null MX "." — never create a nameless "subdomain:" node
	}
	if strings.TrimSpace(label) == "" {
		label = key
	}
	id := graph.NodeID(t, key)
	// A host name reported as a "subdomain" may already exist as the root
	// "domain" node (or vice versa): reuse that node instead of creating a
	// duplicate of the same host under a second type.
	if t == graph.NodeSubdomain || t == graph.NodeDomain {
		if existing, ok := c.g.Resolve(id); ok {
			id = existing
		}
	}
	merged, isNew := c.g.AddNode(&graph.Node{ID: id, Type: t, Label: label, Props: props})
	if isNew || len(props) > 0 {
		c.mu.Lock()
		c.pending.Nodes = append(c.pending.Nodes, merged)
		if isNew {
			c.nNodes++
		}
		c.mu.Unlock()
	}
	return id
}

// Edge links two existing node ids and buffers it if newly created. Host ids of
// the wrong type are resolved to the node that really exists; an edge whose
// endpoint does not exist at all is silently dropped.
func (c *Collector) Edge(source, target, label string) {
	if source == "" || target == "" {
		return
	}
	source, okS := c.g.Resolve(source)
	target, okT := c.g.Resolve(target)
	if !okS || !okT {
		return
	}
	e, isNew := c.g.AddEdge(source, target, label)
	if isNew {
		c.mu.Lock()
		c.pending.Edges = append(c.pending.Edges, e)
		c.nEdges++
		c.mu.Unlock()
	}
}

// rootID is the node id of the scan target.
func (c *Collector) rootID() string {
	if c.Target.IsIP {
		return graph.NodeID(graph.NodeIP, c.Target.IP)
	}
	if c.Target.Domain != "" {
		return graph.NodeID(graph.NodeDomain, c.Target.Domain)
	}
	return ""
}

// HostID returns the id of the existing node for a host name or IP, whichever
// type it was stored as (domain, subdomain or ip). Falls back to a subdomain id.
func (c *Collector) HostID(host string) string {
	id, _ := c.g.Resolve(graph.NodeID(graph.NodeSubdomain, host))
	return id
}

// Flush sends everything buffered since the last flush to the UI.
//
// Every source has its own collector and buffer, so an edge buffered here may
// point at a node that a DIFFERENT source created and has not flushed yet. To
// guarantee the UI never receives an edge before its endpoints, the endpoint
// nodes are attached to the same delta (the UI merges duplicates idempotently).
func (c *Collector) Flush() {
	c.mu.Lock()
	d := c.pending
	c.pending = graph.Delta{}
	c.mu.Unlock()
	if len(d.Edges) > 0 {
		have := make(map[string]bool, len(d.Nodes))
		for _, n := range d.Nodes {
			have[n.ID] = true
		}
		var extra []*graph.Node
		for _, e := range d.Edges {
			for _, id := range [2]string{e.Source, e.Target} {
				if have[id] {
					continue
				}
				have[id] = true
				if n, ok := c.g.Copy(id); ok {
					extra = append(extra, n)
				}
			}
		}
		d.Nodes = append(extra, d.Nodes...)
	}
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
	if id == "" {
		return
	}
	// Link to the affected target; if that node can't be found (e.g. a URL id
	// built from a tool's output that never became a node), fall back to the
	// scan root so the finding is never an orphan floating in the graph.
	if t, ok := c.g.Resolve(targetID); targetID != "" && ok {
		c.Edge(t, id, "finding")
	} else if root := c.rootID(); root != "" {
		c.Edge(root, id, "finding")
	}
}

// GetNode returns a SNAPSHOT COPY of a discovered node for reading its props
// (used by the CVE engine, liveBaseURLs, the TLS source…). It must be a copy:
// other sources of the same stage merge props into the live node concurrently,
// and reading the shared map during that write is a fatal, unrecoverable
// "concurrent map read and map write".
func (c *Collector) GetNode(t graph.NodeType, key string) (*graph.Node, bool) {
	return c.g.Copy(graph.NodeID(t, key))
}

// Logf emits a formatted progress line attributed to the current source.
func (c *Collector) Log(level LogLevel, msg string) {
	if c.em != nil {
		c.em.EmitLog(LogLine{Source: c.name, Level: level, Message: msg})
	}
}
