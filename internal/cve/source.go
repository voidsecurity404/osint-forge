package cve

import (
	"context"
	"fmt"
	"strings"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// maxCVEPerService caps how many CVE nodes are attached to one service, keeping
// the graph readable (most severe are kept).
const maxCVEPerService = 20

// Source is the enrichment stage that matches discovered services to CVEs via
// the local cache, falling back to the NVD API.
type Source struct {
	Cfg    config.Config
	Store  *Store
	Client *Client
}

func (Source) Name() string      { return "cve" }
func (Source) Stage() core.Stage { return core.StageEnrich }

// Applicable only when a store is available (opened at startup).
func (s Source) Applicable(core.Target) bool { return s.Store != nil }

func (s Source) Run(ctx context.Context, c *core.Collector) error {
	services := c.ListByType(graph.NodeService)
	if len(services) == 0 {
		return nil
	}

	// Load the CISA KEV set once so we can flag actively-exploited CVEs.
	kev := s.Store.LoadKEV(ctx, s.Cfg.HTTPUserAgent)

	// Deduplicate identical product/version queries within this run.
	done := map[string][]Match{}
	cveIDs := map[string]bool{}

	for _, key := range services {
		node, ok := c.GetNode(graph.NodeService, key)
		if !ok {
			continue
		}
		cpe, _ := node.Props["cpe"].(string)
		product, _ := node.Props["product"].(string)
		version, _ := node.Props["version"].(string)

		query, isCPE := buildQuery(cpe, product, version)
		if query == "" {
			continue
		}

		matches, cached := done[query]
		if !cached {
			var err error
			matches, err = s.resolve(ctx, query, isCPE)
			if err != nil {
				c.Log(core.LogWarn, "cve "+query+": "+err.Error())
			}
			done[query] = matches
		}
		// Keyword matches from NVD are broad; drop any CVE whose summary does not
		// even mention the product, which cuts most false positives.
		if !isCPE {
			matches = filterByProduct(matches, product)
		}
		if len(matches) == 0 {
			continue
		}

		svcID := graph.NodeID(graph.NodeService, key)
		n := len(matches)
		if n > maxCVEPerService {
			n = maxCVEPerService
		}
		for _, m := range matches[:n] {
			props := map[string]any{
				"severity":  m.Severity,
				"score":     m.Score,
				"summary":   m.Summary,
				"published": m.Published,
				"url":       "https://nvd.nist.gov/vuln/detail/" + m.ID,
			}
			if kev[m.ID] {
				props["known_exploited"] = true // CISA KEV — actively exploited
			}
			cveID := c.Node(graph.NodeCVE, m.ID, m.ID, props)
			c.Edge(svcID, cveID, "has_cve")
			cveIDs[m.ID] = true
		}
		c.Log(core.LogInfo, fmt.Sprintf("%s → %d CVEs", node.Label, len(matches)))
		c.Flush()
	}

	// Enrich every CVE node with its EPSS exploitation-probability score.
	if len(cveIDs) > 0 {
		ids := make([]string, 0, len(cveIDs))
		for id := range cveIDs {
			ids = append(ids, id)
		}
		epss := FetchEPSS(ctx, s.Cfg.HTTPUserAgent, ids)
		for id, score := range epss {
			c.Node(graph.NodeCVE, id, id, map[string]any{"epss": score})
		}
		c.Log(core.LogInfo, fmt.Sprintf("EPSS scored %d/%d CVEs", len(epss), len(ids)))
		c.Flush()
	}
	return nil
}

// resolve returns matches for a query, using the cache when fresh and the NVD
// API otherwise (then caching the result).
func (s Source) resolve(ctx context.Context, query string, isCPE bool) ([]Match, error) {
	if matches, fresh, err := s.Store.Cached(query); err == nil && fresh {
		return matches, nil
	}
	var (
		matches []Match
		err     error
	)
	if isCPE {
		matches, err = s.Client.QueryCPE(ctx, query)
	} else {
		matches, err = s.Client.QueryKeyword(ctx, query)
	}
	if err != nil {
		return nil, err
	}
	_ = s.Store.Save(query, matches) // best-effort cache
	return matches, nil
}

// filterByProduct keeps only matches whose summary mentions the product's most
// distinctive token (lower-cased, ≥3 chars). This suppresses the noisy matches
// NVD keyword search returns for generic terms.
func filterByProduct(in []Match, product string) []Match {
	key := longestToken(product)
	if key == "" {
		return in
	}
	out := in[:0:0]
	for _, m := range in {
		if strings.Contains(strings.ToLower(m.Summary), key) {
			out = append(out, m)
		}
	}
	return out
}

func longestToken(s string) string {
	best := ""
	cur := strings.Builder{}
	flush := func() {
		if t := cur.String(); len(t) >= 3 && len(t) > len(best) {
			best = t
		}
		cur.Reset()
	}
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			cur.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	return best
}

// buildQuery turns a service's fingerprint into an NVD query. It prefers a
// version-pinned CPE; otherwise it falls back to a product+version keyword.
func buildQuery(cpe, product, version string) (query string, isCPE bool) {
	if cpe23, ok := toCPE23(cpe); ok && hasVersion(cpe23) {
		return cpe23, true
	}
	product = strings.TrimSpace(product)
	version = strings.TrimSpace(version)
	if product == "" || version == "" {
		// Too little to match precisely; skip to avoid flooding with noise.
		return "", false
	}
	return product + " " + version, false
}
