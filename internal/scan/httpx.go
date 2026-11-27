package scan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// HTTPSource probes discovered hosts over HTTP/HTTPS, recording the live URL,
// status, page title and detected technologies.
type HTTPSource struct {
	Cfg    config.Config
	filter StatusFilter
}

func (HTTPSource) Name() string                { return "http-probe" }
func (HTTPSource) Stage() core.Stage           { return core.StageProbe }
func (HTTPSource) Applicable(core.Target) bool { return true }

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
var generatorRe = regexp.MustCompile(`(?is)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)
var emailRe = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

// maxEmailsPerPage caps harvested emails per page.
const maxEmailsPerPage = 15

// scopeCtxKey carries the scan's scope check on request contexts, so the shared
// http client can refuse to follow a redirect to an out-of-scope host.
type scopeCtxKey struct{}

// withScope attaches the collector's scope guard to ctx. Every active source
// derives its request contexts from it.
func withScope(ctx context.Context, c *core.Collector) context.Context {
	return context.WithValue(ctx, scopeCtxKey{}, c.InScope)
}

// httpClient ignores TLS validation errors — recon targets often use self-signed
// or mismatched certs and we still want to fingerprint them.
var probeClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return http.ErrUseLastResponse
		}
		// Stay inside the scope: an in-scope host redirecting to another
		// organisation's server must not make us request that server. The 3xx
		// itself is returned (and recorded with its Location).
		if allow, ok := req.Context().Value(scopeCtxKey{}).(func(string) bool); ok && !allow(req.URL.Hostname()) {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

// Page is a fetched HTTP response surfaced to the UI ("view HTML").
type Page struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Server string `json:"server"`
	Title  string `json:"title"`
	Body   string `json:"body"`
}

// FetchPage performs a single GET and returns status, server, title and the
// (size-capped) response body. Used by the detail panel to show a node's page.
func FetchPage(ctx context.Context, userAgent, rawurl string) (Page, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return Page{}, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := probeClient.Do(req)
	if err != nil {
		return Page{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10)) // 256KB
	p := Page{URL: rawurl, Status: resp.StatusCode, Server: resp.Header.Get("Server"), Body: string(body)}
	if m := titleRe.FindSubmatch(body); m != nil {
		p.Title = strings.TrimSpace(html(string(m[1])))
	}
	return p, nil
}

func (s HTTPSource) Run(ctx context.Context, c *core.Collector) error {
	ctx = withScope(ctx, c)
	s.filter = ParseStatusFilter(s.Cfg.StatusCodes) // local copy; seen by probe goroutines
	hosts := map[string]graph.NodeType{}
	if c.Target.Domain != "" {
		hosts[c.Target.Domain] = graph.NodeDomain
	}
	for _, h := range c.ListByType(graph.NodeSubdomain) {
		hosts[h] = graph.NodeSubdomain
	}
	for _, ip := range c.ListByType(graph.NodeIP) {
		hosts[ip] = graph.NodeIP
	}

	conc := s.Cfg.MaxConcurrent
	if conc <= 0 {
		conc = 16
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup

	for host, ht := range hosts {
		if !c.InScope(host) || ctx.Err() != nil {
			continue
		}
		for _, scheme := range []string{"https", "http"} {
			wg.Add(1)
			sem <- struct{}{}
			go func(host string, ht graph.NodeType, scheme string) {
				defer wg.Done()
				defer func() { <-sem }()
				s.probe(ctx, c, host, "", graph.NodeID(ht, host), scheme)
			}(host, ht, scheme)
		}
	}
	wg.Wait()
	c.Flush()
	return nil
}

// probe GETs scheme://host[:port] and records the response as a URL node linked
// to parentID (the host node, or the port node for non-standard ports).
func (s HTTPSource) probe(ctx context.Context, c *core.Collector, host, port, parentID, scheme string) {
	url := scheme + "://" + urlHost(host)
	if port != "" {
		url += ":" + port
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", s.Cfg.HTTPUserAgent)
	resp, err := probeClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	// Only record responses whose status passes the user's status-code filter
	// (default excludes 404). Keeps noise like missing root pages off the graph.
	if !s.filter.Allows(resp.StatusCode) {
		return
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10)) // 512KB

	title := ""
	if m := titleRe.FindSubmatch(body); m != nil {
		title = strings.TrimSpace(html(string(m[1])))
	}

	hostID := parentID
	props := map[string]any{
		"status": resp.StatusCode,
		"title":  title,
		"server": resp.Header.Get("Server"),
	}
	if missing := missingSecurityHeaders(resp.Header); len(missing) > 0 {
		props["missing_security_headers"] = missing
	}
	if resp.TLS != nil {
		props["https"] = true
	}
	if vendor, waf := detectCDN(resp.Header); vendor != "" || waf {
		if vendor != "" {
			props["cdn"] = vendor
		}
		if waf {
			props["waf"] = true
		}
	}
	// Record where redirects ultimately landed (useful for apex→www, http→https).
	if resp.Request != nil && resp.Request.URL != nil {
		if final := resp.Request.URL.String(); final != "" && final != url {
			props["final_url"] = final
		}
	}
	// A redirect that was not followed (out of scope / too many hops).
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if loc, err := resp.Location(); err == nil {
			props["location"] = loc.String()
		}
	}
	if s.Cfg.FaviconHash {
		if h, ok := s.favicon(ctx, url); ok {
			props["favicon_hash"] = h // pivot on Shodan http.favicon.hash:<h>
		}
	}
	urlID := c.Node(graph.NodeURL, url, url, props)
	c.Edge(hostID, urlID, "http")

	// TLS certificate details (only present on https responses).
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		s.addCert(c, hostID, host, resp.TLS.PeerCertificates[0])
	}

	for _, tech := range detectTech(resp.Header, body) {
		tID := c.Node(graph.NodeTech, tech, tech, nil)
		c.Edge(urlID, tID, "has_technology")
	}
	// Turn version-bearing fingerprints (Server: nginx/1.18.0, X-Powered-By:
	// PHP/7.4, <meta generator="WordPress 6.2">) into service nodes so the CVE
	// engine can match them even when nmap never ran. Without this, a web-only
	// target with a known server version produced no CVEs at all.
	for _, raw := range techVersionCandidates(resp.Header, body) {
		if product, version, ok := parseProductVersion(raw); ok {
			key := "web:" + host + ":" + strings.ToLower(product)
			label := strings.TrimSpace(product+" "+version) + " (web)"
			sID := c.Node(graph.NodeService, key, label, map[string]any{
				"name": strings.ToLower(product), "product": product, "version": version,
				"cpe": "", "source": "http-header", "host": host,
			})
			c.Edge(urlID, sID, "runs_service")
		}
	}
	for _, email := range harvestEmails(body) {
		eID := c.Node(graph.NodeEmail, email, email, nil)
		c.Edge(urlID, eID, "mentions")
	}
	c.Log(core.LogInfo, fmt.Sprintf("%s → %d %q", url, resp.StatusCode, title))
	c.Flush()
}

// favicon fetches /favicon.ico and returns its Shodan-style mmh3 hash.
func (s HTTPSource) favicon(ctx context.Context, base string) (int32, bool) {
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, base+"/favicon.ico", nil)
	if err != nil {
		return 0, false
	}
	req.Header.Set("User-Agent", s.Cfg.HTTPUserAgent)
	resp, err := probeClient.Do(req)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if len(body) == 0 {
		return 0, false
	}
	return faviconHash(body), true
}

// addCert records the leaf TLS certificate and expands its SAN hostnames that
// belong to the target domain into subdomain nodes (certs often leak internal
// hostnames).
func (s HTTPSource) addCert(c *core.Collector, hostID, host string, cert *x509.Certificate) {
	issuer := cert.Issuer.CommonName
	if issuer == "" && len(cert.Issuer.Organization) > 0 {
		issuer = cert.Issuer.Organization[0]
	}
	certID := c.Node(graph.NodeCert, host, "cert: "+cert.Subject.CommonName, map[string]any{
		"subject_cn": cert.Subject.CommonName,
		"issuer":     issuer,
		"expires":    cert.NotAfter.Format("2006-01-02"),
		"sans":       cert.DNSNames,
	})
	c.Edge(hostID, certID, "issued_cert")

	dom := c.Target.Domain
	for _, san := range cert.DNSNames {
		san = strings.ToLower(strings.TrimPrefix(san, "*."))
		if dom == "" || !(san == dom || strings.HasSuffix(san, "."+dom)) {
			continue
		}
		sID := c.Node(graph.NodeSubdomain, san, san, map[string]any{"via": "tls-san"})
		c.Edge(certID, sID, "san")
	}
}

// urlHost brackets a bare IPv6 address so the URL authority is valid
// (https://2606:4700::1 is malformed; https://[2606:4700::1] is correct).
func urlHost(host string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			return "[" + host + "]"
		}
	}
	return host
}

// securityHeaders lists the response headers a hardened site should set.
var securityHeaders = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Referrer-Policy",
	"Permissions-Policy",
}

// missingSecurityHeaders returns which recommended security headers are absent.
func missingSecurityHeaders(h http.Header) []string {
	var missing []string
	for _, name := range securityHeaders {
		if h.Get(name) == "" {
			missing = append(missing, name)
		}
	}
	return missing
}

// detectTech applies lightweight header/body signatures (a mini-Wappalyzer).
func detectTech(h http.Header, body []byte) []string {
	var techs []string
	add := func(t string) {
		if t != "" {
			techs = append(techs, t)
		}
	}
	add(h.Get("Server"))
	add(h.Get("X-Powered-By"))
	if m := generatorRe.FindSubmatch(body); m != nil {
		add(strings.TrimSpace(string(m[1])))
	}
	b := strings.ToLower(string(body))
	switch {
	case strings.Contains(b, "/wp-content/"):
		add("WordPress")
	case strings.Contains(b, "window.__nuxt__"):
		add("Nuxt.js")
	case strings.Contains(b, "data-reactroot") || strings.Contains(b, "__next_data__"):
		add("React/Next.js")
	}
	if h.Get("X-Drupal-Cache") != "" {
		add("Drupal")
	}
	return dedupe(techs)
}

// productVersionRe extracts "name/1.2.3" or "name 1.2.3" style product+version
// pairs from server banners and meta generators. It requires a dotted numeric
// version so bare product names (which would match the whole CVE database) are
// ignored.
var productVersionRe = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9._+\- ]*?)[/ ]v?(\d+(?:\.\d+)+)`)

func parseProductVersion(s string) (product, version string, ok bool) {
	s = strings.TrimSpace(s)
	m := productVersionRe.FindStringSubmatch(s)
	if m == nil {
		return "", "", false
	}
	product = strings.TrimSpace(m[1])
	if product == "" {
		return "", "", false
	}
	return product, m[2], true
}

// techVersionCandidates gathers raw strings that may carry a product+version.
func techVersionCandidates(h http.Header, body []byte) []string {
	var out []string
	if v := h.Get("Server"); v != "" {
		out = append(out, v)
	}
	if v := h.Get("X-Powered-By"); v != "" {
		out = append(out, v)
	}
	if m := generatorRe.FindSubmatch(body); m != nil {
		out = append(out, strings.TrimSpace(string(m[1])))
	}
	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// harvestEmails extracts up to maxEmailsPerPage unique email addresses, skipping
// obvious asset filenames that resemble emails.
func harvestEmails(body []byte) []string {
	matches := emailRe.FindAll(body, -1)
	var out []string
	seen := map[string]bool{}
	for _, m := range matches {
		e := strings.ToLower(string(m))
		// Skip values that are really image/asset names (e.g. logo@2x.png).
		if strings.HasSuffix(e, ".png") || strings.HasSuffix(e, ".jpg") ||
			strings.HasSuffix(e, ".gif") || strings.HasSuffix(e, ".webp") ||
			strings.HasSuffix(e, ".svg") || seen[e] {
			continue
		}
		seen[e] = true
		out = append(out, e)
		if len(out) >= maxEmailsPerPage {
			break
		}
	}
	return out
}

// html unescapes the few entities that commonly appear in <title>.
func html(s string) string {
	r := strings.NewReplacer("&amp;", "&", "&lt;", "<", "&gt;", ">", "&quot;", `"`, "&#39;", "'")
	return r.Replace(s)
}

// WebPortsSource probes HTTP(S) services the port scan found on non-standard
// ports (8080, 8443, 3000, …). HTTPSource only tries scheme://host (80/443) and
// runs concurrently with the port scan, so without this stage web apps on other
// ports never got a URL node, a status code, fuzzing or web checks.
type WebPortsSource struct{ Cfg config.Config }

func (WebPortsSource) Name() string                { return "http-ports" }
func (WebPortsSource) Stage() core.Stage           { return core.StageWeb }
func (WebPortsSource) Applicable(core.Target) bool { return true }

// webPortHints are ports treated as web even when the service name is unknown.
var webPortHints = map[string]bool{
	"81": true, "591": true, "3000": true, "4443": true, "5000": true, "7001": true,
	"8000": true, "8008": true, "8080": true, "8081": true, "8443": true, "8888": true,
	"9000": true, "9090": true, "9443": true,
}

func (s WebPortsSource) Run(ctx context.Context, c *core.Collector) error {
	ctx = withScope(ctx, c)
	h := HTTPSource{Cfg: s.Cfg}
	h.filter = ParseStatusFilter(s.Cfg.StatusCodes)

	conc := s.Cfg.MaxConcurrent
	if conc <= 0 {
		conc = 16
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	count := 0
	for _, key := range c.ListByType(graph.NodePort) {
		// key: "<ip>:<port>/<proto>" (ip may be IPv6, so split on the LAST ':').
		hp, proto, _ := strings.Cut(key, "/")
		if proto != "tcp" {
			continue
		}
		i := strings.LastIndex(hp, ":")
		if i <= 0 {
			continue
		}
		ip, port := hp[:i], hp[i+1:]
		if port == "80" || port == "443" {
			continue // already covered by HTTPSource
		}
		n, ok := c.GetNode(graph.NodePort, key)
		if !ok {
			continue
		}
		svc := strings.ToLower(fmt.Sprint(n.Props["service"]))
		if !strings.Contains(svc, "http") && !webPortHints[port] {
			continue
		}
		if !c.InScope(ip) {
			continue
		}
		portID := graph.NodeID(graph.NodePort, key)
		for _, scheme := range []string{"https", "http"} {
			wg.Add(1)
			count++
			sem <- struct{}{}
			go func(ip, port, scheme string) {
				defer wg.Done()
				defer func() { <-sem }()
				if ctx.Err() == nil {
					h.probe(ctx, c, ip, port, portID, scheme)
				}
			}(ip, port, scheme)
		}
	}
	wg.Wait()
	c.Flush()
	if count > 0 {
		c.Log(core.LogInfo, fmt.Sprintf("probed %d web port endpoints", count/2))
	}
	return nil
}
