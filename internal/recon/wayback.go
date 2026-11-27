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

// plausibleArchivedURL filters out the broken/payload URLs the archive often
// holds (XSS payloads, truncated HTML fragments, control chars) so they don't
// flood the graph. A usable URL parses cleanly and its decoded path+query has no
// whitespace, quotes, angle brackets or other HTML/markup characters.
func plausibleArchivedURL(u string) bool {
	if u == "" || len(u) > 512 {
		return false
	}
	p, err := url.Parse(u)
	if err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" {
		return false
	}
	// Decode %xx so payloads hidden behind encoding are caught too.
	decoded := p.Path
	if q, err := url.QueryUnescape(p.RawQuery); err == nil {
		decoded += q
	} else {
		decoded += p.RawQuery
	}
	if dp, err := url.PathUnescape(p.Path); err == nil {
		decoded = dp + decoded[len(p.Path):]
	}
	const bad = " \"'<>{}|\\^`"
	for _, r := range decoded {
		if r < 0x20 || strings.ContainsRune(bad, r) {
			return false
		}
	}
	return true
}

func (s WaybackSource) Run(ctx context.Context, c *core.Collector) error {
	domain := c.Target.Domain
	q := url.Values{
		"url":      {domain + "/*"},
		"output":   {"json"},
		"fl":       {"original"},
		"collapse": {"urlkey"},
		"limit":    {fmt.Sprint(waybackLimit)},
	}
	// HTTPS: the cleartext endpoint leaked the target domain on the wire.
	endpoint := "https://web.archive.org/cdx/search/cdx?" + q.Encode()

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
		if !plausibleArchivedURL(u) {
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
