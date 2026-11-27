package scan

import (
	"context"
	"embed"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// regexpRe aliases the compiled-regex type used in template matchers.
type regexpRe = regexp.Regexp

//go:embed checks/*.json
var checkFS embed.FS

// checkMatcher is one condition on a response (nuclei-style, minimal subset).
type checkMatcher struct {
	Type      string   `json:"type"`                // status | word | regex
	Status    []int    `json:"status,omitempty"`    // for type=status
	Words     []string `json:"words,omitempty"`     // for type=word
	Regex     []string `json:"regex,omitempty"`     // for type=regex
	Part      string   `json:"part,omitempty"`      // body | header (default body)
	Condition string   `json:"condition,omitempty"` // and | or (default or) — within this matcher
	Negative  bool     `json:"negative,omitempty"`  // invert the match
}

// checkTemplate is one read-only HTTP check. It performs a single GET of Path
// and reports a finding when its matchers pass. All templates are safe,
// non-destructive information-disclosure / exposed-resource checks.
type checkTemplate struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Severity   string         `json:"severity"`
	Path       string         `json:"path"`
	Condition  string         `json:"condition"` // and | or across matchers (default and)
	Matchers   []checkMatcher `json:"matchers"`
	Desc       string         `json:"desc"`
	compiledRe [][]*regexpRe
}

var (
	loadedTemplates []checkTemplate
	loadOnce        sync.Once
)

func loadTemplates() []checkTemplate {
	loadOnce.Do(func() {
		entries, _ := checkFS.ReadDir("checks")
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			data, err := checkFS.ReadFile("checks/" + e.Name())
			if err != nil {
				continue
			}
			var batch []checkTemplate
			if json.Unmarshal(data, &batch) != nil {
				// also allow a single object per file
				var one checkTemplate
				if json.Unmarshal(data, &one) == nil && one.ID != "" {
					batch = []checkTemplate{one}
				}
			}
			for i := range batch {
				t := &batch[i]
				t.compiledRe = make([][]*regexpRe, len(t.Matchers))
				for mi, m := range t.Matchers {
					for _, rx := range m.Regex {
						if re, err := regexp.Compile(rx); err == nil {
							t.compiledRe[mi] = append(t.compiledRe[mi], re)
						}
					}
				}
				loadedTemplates = append(loadedTemplates, *t)
			}
		}
	})
	return loadedTemplates
}

// BuiltinChecksSource runs the embedded template checks in-process against live
// web hosts. No external binary or template download — everything ships in the
// binary. Active; gated on consent and the config toggle.
type BuiltinChecksSource struct{ Cfg config.Config }

func (BuiltinChecksSource) Name() string      { return "checks" }
func (BuiltinChecksSource) Stage() core.Stage { return core.StageEnrich }
func (s BuiltinChecksSource) Applicable(core.Target) bool {
	return s.Cfg.BuiltinChecks && len(loadTemplates()) > 0
}

func (s BuiltinChecksSource) Run(ctx context.Context, c *core.Collector) error {
	ctx = withScope(ctx, c) // redirects never leave the scope
	bases := liveBaseURLs(c)
	if len(bases) == 0 {
		return nil
	}
	tmpls := loadTemplates()

	conc := s.Cfg.MaxConcurrent
	if conc <= 0 {
		conc = 12
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	var mu sync.Mutex
	count := 0

	for _, base := range bases {
		if !inScopeURL(c, base) || ctx.Err() != nil {
			continue
		}
		baseID := graph.NodeID(graph.NodeURL, base)
		// Soft-404 calibration: what does a path that cannot exist look like?
		cal := softPages(s.calibrate(ctx, base))
		for i := range tmpls {
			wg.Add(1)
			sem <- struct{}{}
			go func(base, baseID string, t checkTemplate) {
				defer wg.Done()
				defer func() { <-sem }()
				if ctx.Err() != nil {
					return
				}
				status, header, body := s.fetch(ctx, base+t.Path)
				if status == 0 {
					return
				}
				if !matchTemplate(t, status, header, body) {
					return
				}
				if cal.explains(t, status, header, body) {
					return // the host answers every path like this: not a finding
				}
				at := base + t.Path
				mu.Lock()
				count++
				mu.Unlock()
				desc := t.Desc
				if desc == "" {
					desc = t.Name
				}
				c.Finding(normaliseSeverity(t.Severity), "check:"+t.ID+":"+at,
					t.Name+" ("+at+")", desc+"\n\nНайдено: "+at, baseID)
				c.Flush()
			}(base, baseID, tmpls[i])
		}
	}
	wg.Wait()
	c.Log(core.LogInfo, "проверки: совпадений "+itoa(count)+" (шаблонов "+itoa(len(tmpls))+" × хостов "+itoa(len(bases))+")")
	return nil
}

// softPage is a host's answer for a random path that cannot exist.
type softPage struct {
	status int
	header http.Header
	body   []byte
}

// calibrate fetches two random, non-existent paths (one plain, one with a
// file extension like the templates use).
func (s BuiltinChecksSource) calibrate(ctx context.Context, base string) []softPage {
	var out []softPage
	for _, p := range []string{"/" + randToken(), "/" + randToken() + ".php"} {
		if st, h, b := s.fetch(ctx, base+p); st != 0 {
			out = append(out, softPage{st, h, b})
		}
	}
	return out
}

type softPages []softPage

// explains reports whether a template match is just the host's catch-all
// behaviour: a random path that cannot exist ALSO matches the template, or the
// "hit" is a same-status page of practically the same size as the catch-all
// page (servers that echo the requested path, SPA index fallbacks, custom
// 200 "not found" pages).
func (cal softPages) explains(t checkTemplate, status int, header http.Header, body []byte) bool {
	for _, p := range cal {
		if matchTemplate(t, p.status, p.header, p.body) {
			return true
		}
		if p.status == status && math.Abs(float64(len(body)-len(p.body))) < tolerance(len(p.body)) {
			return true
		}
	}
	return false
}

func (s BuiltinChecksSource) fetch(ctx context.Context, url string) (int, http.Header, []byte) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, nil
	}
	req.Header.Set("User-Agent", s.Cfg.HTTPUserAgent)
	resp, err := probeClient.Do(req)
	if err != nil {
		return 0, nil, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	return resp.StatusCode, resp.Header, body
}

// matchTemplate evaluates all matchers with the template's and/or condition.
func matchTemplate(t checkTemplate, status int, header http.Header, body []byte) bool {
	and := strings.ToLower(t.Condition) != "or" // default AND
	headerText := headerString(header)
	bodyLower := strings.ToLower(string(body))

	result := and
	for mi, m := range t.Matchers {
		ok := matchOne(m, t.compiledRe[mi], status, headerText, string(body), bodyLower)
		if m.Negative {
			ok = !ok
		}
		if and {
			result = result && ok
			if !result {
				return false
			}
		} else {
			result = result || ok
		}
	}
	return result
}

func matchOne(m checkMatcher, res []*regexpRe, status int, headerText, body, bodyLower string) bool {
	switch m.Type {
	case "status":
		for _, s := range m.Status {
			if s == status {
				return true
			}
		}
		return false
	case "word":
		hay := bodyLower
		if m.Part == "header" {
			hay = strings.ToLower(headerText)
		}
		orMode := strings.ToLower(m.Condition) != "and" // words default OR
		got := !orMode
		for _, w := range m.Words {
			has := strings.Contains(hay, strings.ToLower(w))
			if orMode {
				got = got || has
			} else {
				got = got && has
			}
		}
		return got
	case "regex":
		hay := body
		if m.Part == "header" {
			hay = headerText
		}
		for _, re := range res {
			if re.MatchString(hay) {
				return true
			}
		}
		return false
	}
	return false
}

func headerString(h http.Header) string {
	var b strings.Builder
	for k, vs := range h {
		for _, v := range vs {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\n")
		}
	}
	return b.String()
}
