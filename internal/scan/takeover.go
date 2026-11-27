package scan

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// takeoverSig links a CNAME target substring to the "unclaimed" fingerprint a
// dangling service returns — the basis for subdomain-takeover detection.
type takeoverSig struct {
	service     string
	cnameSubstr string
	fingerprint string
}

var takeoverSigs = []takeoverSig{
	{"GitHub Pages", "github.io", "There isn't a GitHub Pages site here"},
	{"Heroku", "herokuapp.com", "No such app"},
	{"Heroku", "herokudns.com", "No such app"},
	{"AWS S3", "amazonaws.com", "NoSuchBucket"},
	{"Shopify", "myshopify.com", "Sorry, this shop is currently unavailable"},
	{"Fastly", "fastly.net", "Fastly error: unknown domain"},
	{"Pantheon", "pantheonsite.io", "The gods are wise, but do not know of the site"},
	{"Tumblr", "domains.tumblr.com", "Whatever you were looking for doesn't currently exist"},
	{"Zendesk", "zendesk.com", "Help Center Closed"},
	{"Readthedocs", "readthedocs.io", "unknown to Read the Docs"},
	{"Surge.sh", "surge.sh", "project not found"},
	{"Bitbucket", "bitbucket.io", "Repository not found"},
}

// TakeoverSource checks each subdomain whose CNAME points at a third-party
// service for the fingerprint of an unclaimed (dangling) resource — a subdomain
// takeover opportunity.
type TakeoverSource struct{ Cfg config.Config }

func (TakeoverSource) Name() string                { return "takeover" }
func (TakeoverSource) Stage() core.Stage           { return core.StageEnrich }
func (TakeoverSource) Applicable(core.Target) bool { return true }

func (s TakeoverSource) Run(ctx context.Context, c *core.Collector) error {
	ctx = withScope(ctx, c) // redirects never leave the scope
	conc := s.Cfg.MaxConcurrent
	if conc <= 0 {
		conc = 16
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup

	for _, host := range c.ListByType(graph.NodeSubdomain) {
		if !c.InScope(host) {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			s.check(ctx, c, host)
		}(host)
	}
	wg.Wait()
	return nil
}

func (s TakeoverSource) check(ctx context.Context, c *core.Collector, host string) {
	cname, err := net.DefaultResolver.LookupCNAME(ctx, host) // honours cancel/budget
	if err != nil {
		return
	}
	cname = strings.ToLower(strings.TrimSuffix(cname, "."))
	for _, sig := range takeoverSigs {
		if !strings.Contains(cname, sig.cnameSubstr) {
			continue
		}
		if s.hasFingerprint(ctx, host, sig.fingerprint) {
			hostID := c.HostID(host) // real node id: domain, subdomain or ip
			c.Finding("high", "takeover:"+host,
				"Возможен захват поддомена: "+host+" ("+sig.service+")",
				host+" → "+cname+" ("+sig.service+") — найден невостребованный ресурс; поддомен можно захватить.", hostID)
			c.Log(core.LogWarn, "возможен захват: "+host+" ("+sig.service+")")
			c.Flush()
		}
		break
	}
}

func (s TakeoverSource) hasFingerprint(ctx context.Context, host, fp string) bool {
	for _, scheme := range []string{"https://", "http://"} {
		cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		req, err := http.NewRequestWithContext(cctx, http.MethodGet, scheme+host, nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", s.Cfg.HTTPUserAgent)
		resp, err := probeClient.Do(req)
		if err != nil {
			cancel()
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 128<<10))
		resp.Body.Close()
		cancel()
		if strings.Contains(string(body), fp) {
			return true
		}
	}
	return false
}
