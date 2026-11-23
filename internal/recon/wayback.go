package recon

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// waybackLimit caps how many archived URLs are pulled, to keep the graph legible.
const waybackLimit = 60

// WaybackSource pulls historical URLs for the target domain from the Internet
// Archive's CDX API (keyless). These reveal old endpoints and paths worth
// reviewing.
type WaybackSource struct{ Cfg config.Config }

func (WaybackSource) Name() string                  { return "wayback" }
func (WaybackSource) Stage() core.Stage             { return core.StageEnrich }
func (WaybackSource) Applicable(t core.Target) bool { return t.Domain != "" }

func (s WaybackSource) Run(ctx context.Context, c *core.Collector) error {
	domain := c.Target.Domain
	q := url.Values{
		"url":      {domain + "/*"},
		"output":   {"json"},
		"fl":       {"original"},
		"collapse": {"urlkey"},
		"limit":    {fmt.Sprint(waybackLimit)},
	}
	endpoint := "http://web.archive.org/cdx/search/cdx?" + q.Encode()

	// CDX returns a JSON array of arrays; the first row is the header.
	var rows [][]string
	if err := getJSON(ctx, s.Cfg, endpoint, nil, &rows); err != nil {
		return fmt.Errorf("wayback: %w", err)
	}

	domID := graph.NodeID(graph.NodeDomain, domain)
	count := 0
	for i, row := range rows {
		if i == 0 || len(row) == 0 { // skip header
			continue
		}
		u := strings.TrimSpace(row[0])
		if u == "" {
			continue
		}
		id := c.Node(graph.NodeURL, u, u, map[string]any{"source": "wayback", "archived": true})
		c.Edge(domID, id, "archived")
		count++
	}
	c.Log(core.LogInfo, fmt.Sprintf("%d archived URLs", count))
	c.Flush()
	return nil
}
