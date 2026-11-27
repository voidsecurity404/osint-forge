package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

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

// crtshMaxBytes caps how much of a crt.sh answer is read. Popular domains return
// hundreds of MB; the entries are streamed, so the cap bounds time, not memory.
const crtshMaxBytes = 64 << 20

// decodeCrtSh streams a crt.sh JSON array entry by entry. If the body is cut
// short (size cap, dropped connection) the complete entries read so far are
// returned together with the error, instead of losing everything.
func decodeCrtSh(r io.Reader) ([]crtshEntry, error) {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return nil, fmt.Errorf("неожиданный ответ crt.sh")
	}
	var out []crtshEntry
	for dec.More() {
		var e crtshEntry
		if err := dec.Decode(&e); err != nil {
			return out, err
		}
		out = append(out, e)
	}
	return out, nil
}

func (s CrtShSource) fetch(ctx context.Context, endpoint string) ([]crtshEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", s.Cfg.HTTPUserAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return decodeCrtSh(io.LimitReader(resp.Body, crtshMaxBytes))
}

// retryable reports whether a crt.sh failure is worth retrying.
func retryable(err error) bool {
	m := err.Error()
	for _, code := range []string{"HTTP 404", "HTTP 429", "HTTP 500", "HTTP 502", "HTTP 503", "HTTP 504", "timeout", "EOF", "connection reset"} {
		if strings.Contains(m, code) {
			return true
		}
	}
	return false
}

func (s CrtShSource) Run(ctx context.Context, c *core.Collector) error {
	domain := c.Target.Domain
	domID := graph.NodeID(graph.NodeDomain, domain)
	q := url.Values{"q": {"%." + domain}, "output": {"json"}}
	endpoint := "https://crt.sh/?" + q.Encode()

	// crt.sh is a free, heavily loaded service: it often answers 404/429/5xx
	// for a moment. Two retries with a pause keep one hiccup from losing the
	// whole CT-log source.
	entries, err := s.fetch(ctx, endpoint)
	for _, pause := range []time.Duration{2 * time.Second, 5 * time.Second} {
		if err == nil || len(entries) > 0 || !retryable(err) {
			break
		}
		c.Log(core.LogWarn, fmt.Sprintf("crt.sh временно не ответил (%v) — повтор через %v", err, pause))
		select {
		case <-time.After(pause):
		case <-ctx.Done():
			return nil
		}
		entries, err = s.fetch(ctx, endpoint)
	}
	if err != nil {
		if len(entries) == 0 {
			return fmt.Errorf("crt.sh: %w", err)
		}
		c.Log(core.LogWarn, fmt.Sprintf("ответ crt.sh прочитан не полностью (%v) — продолжаем с %d записями", err, len(entries)))
	}

	seen := map[string]bool{}
	found := 0
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.ToLower(strings.TrimSpace(name))
			name = strings.TrimPrefix(name, "*.")
			// Reject emails and malformed values; require a proper subdomain of
			// the target (dot-boundary suffix, not just a string suffix).
			if name == "" || seen[name] || strings.ContainsAny(name, " @") {
				continue
			}
			seen[name] = true
			if name == domain || !strings.HasSuffix(name, "."+domain) {
				continue
			}
			id := c.Node(graph.NodeSubdomain, name, name, map[string]any{"via": "crt.sh"})
			c.Edge(domID, id, "subdomain")
			found++
		}
	}
	c.Log(core.LogInfo, fmt.Sprintf("найдено поддоменов: %d", found))
	c.Flush()
	return nil
}
