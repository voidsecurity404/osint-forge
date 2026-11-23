package scan

import (
	"context"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// notFoundMarkers are phrases that indicate a "not found" page even when the
// server wrongly returns HTTP 200 (soft-404). Matched case-insensitively.
var notFoundMarkers = []string{
	"404 not found", "error 404", "not found", "page not found",
	"page doesn't exist", "page does not exist", "does not exist",
	"no such file", "file not found", "cannot be found", "could not be found",
	"nothing found", "sahifa topilmadi", "не найдено", "страница не найдена",
}

var fuzzTitleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// FuzzSource performs content/path discovery against every live web host, using
// a SecLists wordlist and aggressive false-positive filtering (soft-404
// calibration, body "not found" markers, and wildcard-host suppression).
// Active (consent) only.
type FuzzSource struct {
	Cfg    config.Config
	filter StatusFilter
}

func (FuzzSource) Name() string                  { return "fuzz" }
func (FuzzSource) Stage() core.Stage             { return core.StageEnrich }
func (s FuzzSource) Applicable(core.Target) bool { return s.Cfg.FuzzEnabled }

func (s FuzzSource) Run(ctx context.Context, c *core.Collector) error {
	s.filter = ParseStatusFilter(s.Cfg.StatusCodes) // local copy; seen by worker goroutines
	bases := s.liveBases(c)
	if len(bases) == 0 {
		return nil
	}
	words, label := LoadWordlist(s.Cfg.FuzzWordlist)
	if len(words) == 0 {
		return nil
	}
	c.Log(core.LogInfo, fmt.Sprintf("fuzzing %d host(s) × %d paths (%s)", len(bases), len(words), label))
	for _, base := range bases {
		s.fuzzBase(ctx, c, base, words)
		c.Flush()
	}
	return nil
}

// liveBases returns root URLs that responded to the http probe.
func (s FuzzSource) liveBases(c *core.Collector) []string { return liveBaseURLs(c) }

type fuzzHit struct {
	url    string
	word   string
	status int
	size   int
	title  string
}

func (s FuzzSource) fuzzBase(ctx context.Context, c *core.Collector, base string, words []string) {
	// Calibrate twice against random paths to learn the soft-404 signature.
	s1, l1, _ := s.probe(ctx, base+"/"+randToken())
	s2, l2, _ := s.probe(ctx, base+"/"+randToken())
	softStatus := s1
	softLen := l1
	stableSoft := s1 == s2 && math.Abs(float64(l1-l2)) < 64
	if !stableSoft {
		// Soft-404 size is unstable (dynamic page); rely on status + markers only.
		softLen = -1
	}

	conc := s.Cfg.MaxConcurrent
	if conc <= 0 {
		conc = 16
	}
	// Polite pacing: cap requests/second against this single host so the fuzzer
	// never behaves like a DoS. 0 = internal default.
	rate := s.Cfg.RateLimitPerHost
	if rate <= 0 {
		rate = 40
	}
	tick := time.NewTicker(time.Second / time.Duration(rate))
	defer tick.Stop()

	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var hits []fuzzHit

	for _, word := range words {
		wg.Add(1)
		sem <- struct{}{}
		go func(word string) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			select {
			case <-tick.C:
			case <-ctx.Done():
				return
			}
			target := base + "/" + word
			status, size, body := s.probe(ctx, target)
			if !s.filter.Allows(status) {
				return
			}
			// Reject soft-404s that return a "not found" page with HTTP 200/etc.
			if looksNotFound(body) {
				return
			}
			// Reject responses matching the calibrated soft-404 signature.
			if status == softStatus && softLen >= 0 && math.Abs(float64(size-softLen)) < tolerance(softLen) {
				return
			}
			mu.Lock()
			hits = append(hits, fuzzHit{url: target, word: word, status: status, size: size, title: pageTitle(body)})
			mu.Unlock()
		}(word)
	}
	wg.Wait()

	// Wildcard-host guard: if a large fraction of paths "matched", the host
	// answers everything the same way — suppress to avoid a flood of noise.
	threshold := len(words) / 5
	if threshold < 120 {
		threshold = 120
	}
	if len(hits) > threshold {
		c.Log(core.LogWarn, fmt.Sprintf("%s → %d hits looks like a wildcard/soft-404 host; suppressed", base, len(hits)))
		return
	}

	baseID := graph.NodeID(graph.NodeURL, base)
	for _, h := range hits {
		id := c.Node(graph.NodeURL, h.url, "/"+h.word, map[string]any{
			"status": h.status, "size": h.size, "title": h.title, "source": "fuzz",
		})
		c.Edge(baseID, id, "path")
	}
	c.Log(core.LogInfo, fmt.Sprintf("%s → %d paths", base, len(hits)))
}

func tolerance(softLen int) float64 {
	t := float64(softLen) * 0.05
	if t < 80 {
		t = 80
	}
	return t
}

// probe GETs a URL and returns status, body size and a capped body copy.
func (s FuzzSource) probe(ctx context.Context, url string) (status, size int, body []byte) {
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, 0, nil
	}
	req.Header.Set("User-Agent", s.Cfg.HTTPUserAgent)
	resp, err := probeClient.Do(req)
	if err != nil {
		return 0, 0, nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 128<<10))
	return resp.StatusCode, len(b), b
}

func looksNotFound(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	lower := strings.ToLower(string(body[:min(len(body), 8192)]))
	title := strings.ToLower(pageTitle(body))
	if strings.Contains(title, "not found") || strings.Contains(title, "404") {
		return true
	}
	for _, m := range notFoundMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

func pageTitle(body []byte) string {
	if m := fuzzTitleRe.FindSubmatch(body); m != nil {
		return strings.TrimSpace(string(m[1]))
	}
	return ""
}

func randToken() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 16)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return "zz" + string(b) + "zz"
}
