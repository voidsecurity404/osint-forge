package scan

import (
	"strconv"
	"strings"

	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// liveBaseURLs returns the root URLs (scheme://host) that answered the HTTP
// probe — the shared target set for fuzzing, robots/sitemap parsing, web
// checks, nuclei and screenshots. Archived (wayback) and non-probed URLs are
// excluded, and only root URLs (exactly two slashes after trimming) are kept.
func liveBaseURLs(c *core.Collector) []string {
	var out []string
	for _, u := range c.ListByType(graph.NodeURL) {
		n, ok := c.GetNode(graph.NodeURL, u)
		if !ok {
			continue
		}
		if archived, _ := n.Props["archived"].(bool); archived {
			continue
		}
		if _, hasStatus := n.Props["status"]; !hasStatus {
			continue
		}
		if strings.Count(strings.TrimSuffix(u, "/"), "/") == 2 {
			out = append(out, strings.TrimSuffix(u, "/"))
		}
	}
	return out
}

func itoa(n int) string { return strconv.Itoa(n) }
