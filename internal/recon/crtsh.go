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

// CrtShSource enumerates subdomains from Certificate Transparency logs via the
// public crt.sh JSON endpoint. No API key required.
type CrtShSource struct{ Cfg config.Config }

func (CrtShSource) Name() string                  { return "crt.sh" }
func (CrtShSource) Stage() core.Stage             { return core.StageDiscovery }
func (CrtShSource) Applicable(t core.Target) bool { return t.Domain != "" }

type crtshEntry struct {
	NameValue  string `json:"name_value"`
	CommonName string `json:"common_name"`
	IssuerName string `json:"issuer_name"`
}

func (s CrtShSource) Run(ctx context.Context, c *core.Collector) error {
	domain := c.Target.Domain
	domID := graph.NodeID(graph.NodeDomain, domain)
	q := url.Values{"q": {"%." + domain}, "output": {"json"}}
	endpoint := "https://crt.sh/?" + q.Encode()

	var entries []crtshEntry
	if err := getJSON(ctx, s.Cfg, endpoint, nil, &entries); err != nil {
		return fmt.Errorf("crt.sh: %w", err)
	}

	seen := map[string]bool{}
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.ToLower(strings.TrimSpace(name))
			name = strings.TrimPrefix(name, "*.")
			// Reject emails and malformed values; require a proper subdomain of
			// the target (dot-boundary suffix, not just a string suffix).
			if name == "" || seen[name] || strings.ContainsAny(name, " @") {
				continue
			}
			if name != domain && !strings.HasSuffix(name, "."+domain) {
				continue
			}
			seen[name] = true
			if name == domain {
				continue
			}
			id := c.Node(graph.NodeSubdomain, name, name, map[string]any{"via": "crt.sh"})
			c.Edge(domID, id, "subdomain")
		}
	}
	c.Log(core.LogInfo, fmt.Sprintf("found %d subdomains", len(seen)))
	c.Flush()
	return nil
}
