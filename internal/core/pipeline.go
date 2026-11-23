package core

import (
	"context"
	"fmt"
	"sync"
	"time"

	"osint-forge/internal/graph"
)

// Stage orders sources into waves. Passive discovery runs first and seeds the
// graph with hosts/IPs; active probing runs second against what was found.
type Stage int

const (
	StageDiscovery Stage = iota // passive: dns, whois, crt.sh, otx, brute-force (find names)
	StageResolve                // resolve discovered names → IPs (must finish before probing)
	StageProbe                  // active: port scan, http probe, reverse-ip, zone transfer
	StageEnrich                 // derived: cve, tls, web checks, fuzz, takeover, report data
)

// Source is one unit of reconnaissance. Implementations live in internal/recon
// and internal/scan.
type Source interface {
	Name() string
	Stage() Stage
	// Applicable reports whether the source can run for this target.
	Applicable(Target) bool
	// Run performs the work, adding findings through the collector.
	Run(ctx context.Context, c *Collector) error
}

// Progress is a coarse status update for the UI progress bar / status line.
type Progress struct {
	Phase     string `json:"phase"`
	Done      int    `json:"done"`
	Total     int    `json:"total"`
	Running   string `json:"running"`
	Nodes     int    `json:"nodes"`
	Edges     int    `json:"edges"`
	Finished  bool   `json:"finished"`
	StartedAt int64  `json:"startedAt"`
}

// Pipeline orchestrates a set of sources against one target, emitting live
// graph deltas, logs and progress through the emitter.
type Pipeline struct {
	sources []Source
	g       *graph.Graph
	em      Emitter
	scope   Scope
}

// NewPipeline builds a pipeline from the given sources.
func NewPipeline(em Emitter, g *graph.Graph, sources ...Source) *Pipeline {
	return &Pipeline{sources: sources, g: g, em: em}
}

// SetScope installs the active-probing allowlist used by every source's
// collector.
func (p *Pipeline) SetScope(s Scope) { p.scope = s }

// ProgressEmitter is an optional capability: emitters that implement it receive
// Progress updates in addition to deltas and logs.
type ProgressEmitter interface {
	EmitProgress(Progress)
}

func (p *Pipeline) emitProgress(pr Progress) {
	if pe, ok := p.em.(ProgressEmitter); ok {
		pe.EmitProgress(pr)
	}
}

// Run executes every applicable source, stage by stage. Within a stage the
// sources run concurrently. It is cancellable through ctx.
func (p *Pipeline) Run(ctx context.Context, t Target) {
	started := time.Now().Unix()
	base := NewCollector(t, p.g, p.em)
	base.SetScope(p.scope)

	// Seed the graph with the root node so the UI always has an anchor.
	if t.IsIP {
		base.Node(graph.NodeIP, t.IP, t.IP, map[string]any{"root": true})
	} else {
		base.Node(graph.NodeDomain, t.Domain, t.Domain, map[string]any{"root": true})
	}
	base.Flush()

	stages := []Stage{StageDiscovery, StageResolve, StageProbe, StageEnrich}
	stageName := map[Stage]string{
		StageDiscovery: "Discovery", StageResolve: "Resolve",
		StageProbe: "Probe", StageEnrich: "Enrich",
	}

	// Pre-filter applicable sources once.
	var applicable []Source
	for _, s := range p.sources {
		if s.Applicable(t) {
			applicable = append(applicable, s)
		}
	}
	total := len(applicable)
	done := 0

	for _, stage := range stages {
		var wave []Source
		for _, s := range applicable {
			if s.Stage() == stage {
				wave = append(wave, s)
			}
		}
		if len(wave) == 0 {
			continue
		}

		var wg sync.WaitGroup
		for _, s := range wave {
			wg.Add(1)
			go func(s Source) {
				defer wg.Done()
				if ctx.Err() != nil {
					return
				}
				c := base.forSource(s.Name())
				// A panic in any single source must never crash the whole app:
				// recover, log it, and let the rest of the scan continue.
				defer func() {
					if r := recover(); r != nil {
						c.Log(LogError, fmt.Sprintf("panic recovered: %v", r))
						c.Flush()
					}
				}()
				nodes, edges := p.g.Counts()
				p.emitProgress(Progress{
					Phase: stageName[stage], Running: s.Name(),
					Done: done, Total: total, Nodes: nodes, Edges: edges, StartedAt: started,
				})
				c.Log(LogInfo, "started")
				if err := s.Run(ctx, c); err != nil {
					c.Log(LogError, err.Error())
				}
				c.Flush()
			}(s)
		}
		wg.Wait()
		done += len(wave)
		nodes, edges := p.g.Counts()
		p.emitProgress(Progress{
			Phase: stageName[stage], Done: done, Total: total,
			Nodes: nodes, Edges: edges, StartedAt: started,
		})
	}

	nodes, edges := p.g.Counts()
	p.emitProgress(Progress{
		Phase: "Done", Done: total, Total: total,
		Nodes: nodes, Edges: edges, Finished: true, StartedAt: started,
	})
}
