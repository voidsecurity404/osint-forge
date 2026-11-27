package scan

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// JSAnalyzeSource downloads the JavaScript referenced by live pages and pulls
// two high-value things out of it: additional endpoints/paths (so they become
// URL nodes the fuzzer and web checks can follow up), and likely leaked secrets
// (API keys, tokens) reported as findings. This is read-only analysis of files
// the target already serves — no exploitation.
type JSAnalyzeSource struct{ Cfg config.Config }

func (JSAnalyzeSource) Name() string                { return "js-analyze" }
func (JSAnalyzeSource) Stage() core.Stage           { return core.StageEnrich }
func (JSAnalyzeSource) Applicable(core.Target) bool { return true }

// script src="..." in HTML.
var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)

// Endpoint-ish strings inside JS: "/api/v1/x", './thing', "https://host/path".
var endpointRe = regexp.MustCompile(`["'` + "`" + `]((?:/[A-Za-z0-9_./-]{2,120}|https?://[A-Za-z0-9_.:/-]{4,160})(?:\?[A-Za-z0-9_.=&%/:+-]{0,160})?)["'` + "`" + `]`)

// Secret fingerprints. Each is deliberately specific to keep false positives low.
var secretRes = []struct {
	name string
	re   *regexp.Regexp
}{
	{"AWS access key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"Google API key", regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`)},
	{"Slack token", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,48}`)},
	{"GitHub token", regexp.MustCompile(`gh[pousr]_[0-9A-Za-z]{36}`)},
	{"Stripe secret key", regexp.MustCompile(`sk_live_[0-9A-Za-z]{24}`)},
	{"Private key block", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`)},
	{"JWT", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
}

const (
	maxJSFiles   = 40
	maxJSBytes   = 2 << 20 // 2 MB per file
	maxEndpoints = 60
)

func (s JSAnalyzeSource) Run(ctx context.Context, c *core.Collector) error {
	ctx = withScope(ctx, c) // redirects never leave the scope
	bases := liveBaseURLs(c)
	if len(bases) == 0 {
		return nil
	}

	// Collect script URLs from each live base page.
	scripts := map[string]string{} // script URL -> base it belongs to
	for _, base := range bases {
		if !inScopeURL(c, base) {
			continue
		}
		_, body := s.get(ctx, base)
		for _, m := range scriptSrcRe.FindAllSubmatch(body, -1) {
			if abs := absURL(base, string(m[1])); abs != "" {
				if _, ok := scripts[abs]; !ok {
					scripts[abs] = base
				}
			}
		}
		if len(scripts) >= maxJSFiles {
			break
		}
	}
	if len(scripts) == 0 {
		return nil
	}

	conc := s.Cfg.MaxConcurrent
	if conc <= 0 {
		conc = 8
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	var mu sync.Mutex
	endpoints := map[string]string{} // endpoint URL -> source JS node id
	type secret struct{ kind, sample, js string }
	var secrets []secret

	for jsURL, base := range scripts {
		wg.Add(1)
		sem <- struct{}{}
		go func(jsURL, base string) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil || !inScopeURL(c, jsURL) {
				return
			}
			status, body := s.get(ctx, jsURL)
			if status == 0 || len(body) == 0 {
				return
			}
			jsID := c.Node(graph.NodeURL, jsURL, trimToPath(jsURL), map[string]any{"status": status, "source": "script"})
			c.Edge(c.HostID(hostOf(base)), jsID, "script")

			text := string(body)
			for _, m := range endpointRe.FindAllStringSubmatch(text, -1) {
				ep := m[1]
				if skipEndpoint(ep) {
					continue
				}
				abs := absURL(base, ep)
				if abs == "" || !inScopeURL(c, abs) {
					continue
				}
				mu.Lock()
				if _, ok := endpoints[abs]; !ok && len(endpoints) < maxEndpoints {
					endpoints[abs] = jsID
				}
				mu.Unlock()
			}
			for _, sr := range secretRes {
				if m := sr.re.FindString(text); m != "" {
					mu.Lock()
					secrets = append(secrets, secret{sr.name, mask(m), jsID})
					mu.Unlock()
				}
			}
		}(jsURL, base)
	}
	wg.Wait()

	eps := make([]string, 0, len(endpoints))
	for ep := range endpoints {
		eps = append(eps, ep)
	}
	sort.Strings(eps)
	for _, ep := range eps {
		id := c.Node(graph.NodeURL, ep, trimToPath(ep), map[string]any{"source": "js", "discovered": true})
		c.Edge(endpoints[ep], id, "endpoint")
	}
	for _, sec := range secrets {
		c.Finding("high", "js-secret:"+sec.kind+":"+sec.sample,
			"Секрет в JavaScript: "+sec.kind,
			"В JavaScript-файле найдено значение, похожее на "+sec.kind+" (образец: "+sec.sample+"). Проверьте, действует ли ключ, и замените его.",
			sec.js)
	}
	c.Log(core.LogInfo, "js-analyze: скриптов "+itoa(len(scripts))+", эндпоинтов "+itoa(len(eps))+", секретов "+itoa(len(secrets)))
	c.Flush()
	return nil
}

func (s JSAnalyzeSource) get(ctx context.Context, u string) (int, []byte) {
	cctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, nil
	}
	req.Header.Set("User-Agent", s.Cfg.HTTPUserAgent)
	resp, err := probeClient.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxJSBytes))
	return resp.StatusCode, b
}

// --- helpers ---

// skipEndpoint drops noise: data URIs, mime types, file extensions that aren't
// endpoints, and obvious static assets.
func skipEndpoint(ep string) bool {
	low := strings.ToLower(ep)
	if strings.HasPrefix(low, "http") {
		// keep only same interest; assets filtered below too
	}
	for _, s := range []string{".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".woff", ".ttf", ".ico", ".map", "//w3.org", "schema.org", "data:"} {
		if strings.Contains(low, s) {
			return true
		}
	}
	// pure version-ish or single words aren't endpoints
	if !strings.Contains(ep, "/") {
		return true
	}
	return false
}

func mask(s string) string {
	if len(s) <= 10 {
		return s[:2] + "…"
	}
	return s[:6] + "…" + s[len(s)-4:]
}

func hostOf(base string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	return u.Hostname()
}

func absURL(base, ref string) string {
	b, err := url.Parse(base)
	if err != nil {
		return ""
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	out := b.ResolveReference(r)
	if out.Scheme != "http" && out.Scheme != "https" {
		return ""
	}
	out.Fragment = ""
	return out.String()
}

// inScopeURL gates analysis on the configured scope using the URL's host.
func inScopeURL(c *core.Collector, u string) bool {
	return c.InScope(hostOf(u))
}
