package scan

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// robotsPathLimit caps how many paths are imported per host.
const robotsPathLimit = 100

var locRe = regexp.MustCompile(`(?is)<loc>\s*(.*?)\s*</loc>`)

// RobotsSource harvests real endpoints a server advertises in robots.txt and
// sitemap.xml. These are authoritative (server-declared) paths, so they carry no
// false positives — unlike brute-force fuzzing.
type RobotsSource struct{ Cfg config.Config }

func (RobotsSource) Name() string                { return "robots/sitemap" }
func (RobotsSource) Stage() core.Stage           { return core.StageEnrich }
func (RobotsSource) Applicable(core.Target) bool { return true }

func (s RobotsSource) Run(ctx context.Context, c *core.Collector) error {
	for _, base := range s.liveBases(c) {
		s.parseRobots(ctx, c, base)
		s.parseSitemap(ctx, c, base)
		c.Flush()
	}
	return nil
}

// liveBases mirrors the fuzz source: root URLs that responded to the probe.
func (s RobotsSource) liveBases(c *core.Collector) []string { return liveBaseURLs(c) }

func (s RobotsSource) get(ctx context.Context, url string) (int, []byte) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil
	}
	req.Header.Set("User-Agent", s.Cfg.HTTPUserAgent)
	resp, err := probeClient.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, b
}

func (s RobotsSource) parseRobots(ctx context.Context, c *core.Collector, base string) {
	status, body := s.get(ctx, base+"/robots.txt")
	if status != 200 || len(body) == 0 {
		return
	}
	baseID := graph.NodeID(graph.NodeURL, base)
	count := 0
	var sitemaps []string
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	for sc.Scan() && count < robotsPathLimit {
		line := strings.TrimSpace(sc.Text())
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "disallow:"), strings.HasPrefix(lower, "allow:"):
			p := strings.TrimSpace(line[strings.IndexByte(line, ':')+1:])
			if p == "" || p == "/" || strings.ContainsAny(p, "*$") {
				continue
			}
			u := base + "/" + strings.TrimPrefix(p, "/")
			id := c.Node(graph.NodeURL, u, p, map[string]any{"source": "robots.txt"})
			c.Edge(baseID, id, "robots")
			count++
		case strings.HasPrefix(lower, "sitemap:"):
			sitemaps = append(sitemaps, strings.TrimSpace(line[strings.IndexByte(line, ':')+1:]))
		}
	}
	if count > 0 {
		c.Log(core.LogInfo, fmt.Sprintf("%s/robots.txt → %d paths", base, count))
	}
	// Follow any sitemaps the robots.txt points to.
	for _, sm := range sitemaps {
		s.importSitemap(ctx, c, base, sm)
	}
}

func (s RobotsSource) parseSitemap(ctx context.Context, c *core.Collector, base string) {
	s.importSitemap(ctx, c, base, base+"/sitemap.xml")
}

func (s RobotsSource) importSitemap(ctx context.Context, c *core.Collector, base, sitemapURL string) {
	status, body := s.get(ctx, sitemapURL)
	if status != 200 || len(body) == 0 {
		return
	}
	baseID := graph.NodeID(graph.NodeURL, base)
	matches := locRe.FindAllSubmatch(body, robotsPathLimit)
	count := 0
	for _, m := range matches {
		loc := strings.TrimSpace(string(m[1]))
		if loc == "" || !strings.HasPrefix(loc, "http") {
			continue
		}
		id := c.Node(graph.NodeURL, loc, trimToPath(loc), map[string]any{"source": "sitemap"})
		c.Edge(baseID, id, "sitemap")
		count++
	}
	if count > 0 {
		c.Log(core.LogInfo, fmt.Sprintf("%s → %d sitemap URLs", sitemapURL, count))
	}
}

// trimToPath returns the path portion of a URL for a compact node label.
func trimToPath(u string) string {
	i := strings.Index(u, "://")
	if i < 0 {
		return u
	}
	rest := u[i+3:]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		return rest[j:]
	}
	return "/"
}
