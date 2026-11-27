package scan

import (
	"context"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// ParamSource extracts query parameters from every discovered URL (archived,
// fuzzed, JS-sourced) and records each as a `param` node, classified by the kind
// of test it is a candidate for (SQLi, XSS, redirect, LFI/SSRF, IDOR). This is
// passive analysis of URLs already in the graph — it sends no requests.
type ParamSource struct{ Cfg config.Config }

func (ParamSource) Name() string                { return "params" }
func (ParamSource) Stage() core.Stage           { return core.StagePost }
func (ParamSource) Applicable(core.Target) bool { return true }

// Parameter name hints → the class of issue that parameter is a candidate for.
// These only MARK candidates for manual testing; they assert nothing.
var paramHints = []struct {
	kind  string
	names []string
}{
	{"redirect", []string{"redirect", "redir", "url", "next", "return", "returnurl", "continue", "dest", "destination", "goto", "callback", "forward"}},
	{"lfi/path", []string{"file", "path", "page", "template", "doc", "document", "folder", "download", "load", "include", "dir"}},
	{"ssrf", []string{"uri", "link", "site", "host", "port", "target", "feed", "proxy", "fetch", "endpoint"}},
	{"sqli", []string{"id", "user", "userid", "uid", "order", "orderby", "sort", "category", "cat", "product", "pid", "item", "query", "search", "q", "filter", "name", "select"}},
	{"xss", []string{"q", "search", "query", "s", "keyword", "message", "msg", "comment", "text", "title", "lang", "ref", "referrer"}},
	{"idor", []string{"id", "uid", "userid", "account", "number", "no", "doc", "invoice", "order_id", "orderid", "key"}},
}

// paramNameRe accepts realistic parameter names and rejects junk keys that
// archived/fuzzed URLs produce (e.g. ",-", "@_~", quoted payloads). A real name
// is short, alphanumeric-ish, and contains at least one letter or digit.
var paramNameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.\[\]-]{0,63}$`)

func validParamName(name string) bool {
	if !paramNameRe.MatchString(name) {
		return false
	}
	for _, r := range name {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
			return true // require at least one letter
		}
	}
	return false
}

func classifyParam(name string) []string {
	n := strings.ToLower(name)
	var kinds []string
	seen := map[string]bool{}
	for _, h := range paramHints {
		for _, want := range h.names {
			if n == want && !seen[h.kind] {
				seen[h.kind] = true
				kinds = append(kinds, h.kind)
				break
			}
		}
	}
	return kinds
}

const maxParams = 200

func (s ParamSource) Run(ctx context.Context, c *core.Collector) error {
	// name -> set of endpoints (path only) that carry it, and candidate kinds.
	type info struct {
		endpoints map[string]bool
		kinds     map[string]bool
	}
	params := map[string]*info{}

	for _, u := range c.ListByType(graph.NodeURL) {
		raw := strings.TrimPrefix(u, "")
		parsed, err := url.Parse(raw)
		if err != nil || parsed.RawQuery == "" {
			continue
		}
		pathOnly := parsed.Scheme + "://" + parsed.Host + parsed.Path
		for name := range parsed.Query() {
			if !validParamName(name) {
				continue
			}
			it := params[name]
			if it == nil {
				it = &info{endpoints: map[string]bool{}, kinds: map[string]bool{}}
				params[name] = it
			}
			it.endpoints[pathOnly] = true
			for _, k := range classifyParam(name) {
				it.kinds[k] = true
			}
		}
	}
	if len(params) == 0 {
		return nil
	}

	names := make([]string, 0, len(params))
	for n := range params {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) > maxParams {
		names = names[:maxParams]
	}

	count := 0
	for _, name := range names {
		it := params[name]
		eps := keysOf(it.endpoints)
		kinds := keysOf(it.kinds)
		sort.Strings(eps)
		sort.Strings(kinds)
		label := name
		if len(kinds) > 0 {
			label = name + " (" + strings.Join(kinds, ", ") + ")"
		}
		props := map[string]any{
			"name":      name,
			"endpoints": eps,
			"source":    "params",
		}
		if len(kinds) > 0 {
			props["candidate"] = strings.Join(kinds, ", ")
		}
		pID := c.Node(graph.NodeParam, name, label, props)
		// Link the param to the first endpoint's host so it sits near its context.
		if len(eps) > 0 {
			if host := hostOf(eps[0]); host != "" {
				c.Edge(c.HostID(host), pID, "param")
			}
		}
		count++
	}
	c.Log(core.LogInfo, "params: "+itoa(count)+" unique query parameters")
	c.Flush()
	return nil
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
