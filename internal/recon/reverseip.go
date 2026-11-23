package recon

import (
	"context"
	"fmt"
	"strings"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// ReverseIPSource finds other domains hosted on the discovered IPs, plus extra
// subdomains, using SecurityTrails and/or VirusTotal. Requires an API key; it
// skips any provider whose key is absent. Runs in the probe stage so that IPs
// resolved during discovery are available.
type ReverseIPSource struct{ Cfg config.Config }

func (ReverseIPSource) Name() string      { return "reverse-ip" }
func (ReverseIPSource) Stage() core.Stage { return core.StageProbe }

func (s ReverseIPSource) Applicable(core.Target) bool {
	return s.Cfg.SecurityTrailsKey != "" || s.Cfg.VirusTotalKey != ""
}

func (s ReverseIPSource) Run(ctx context.Context, c *core.Collector) error {
	ips := c.ListByType(graph.NodeIP)
	for _, ip := range ips {
		if s.Cfg.SecurityTrailsKey != "" {
			s.securityTrailsIP(ctx, c, ip)
		}
		if s.Cfg.VirusTotalKey != "" {
			s.virusTotalIP(ctx, c, ip)
		}
		c.Flush()
	}
	// Extra subdomains for the root domain.
	if d := c.Target.Domain; d != "" {
		if s.Cfg.SecurityTrailsKey != "" {
			s.securityTrailsSubdomains(ctx, c, d)
		}
		c.Flush()
	}
	return nil
}

func (s ReverseIPSource) addHostOnIP(c *core.Collector, ip, host, via string) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return
	}
	ipID := c.Node(graph.NodeIP, ip, ip, nil)
	hID := c.Node(graph.NodeSubdomain, host, host, map[string]any{"via": via})
	c.Edge(ipID, hID, "hosts")
}

// --- SecurityTrails ---

func (s ReverseIPSource) securityTrailsIP(ctx context.Context, c *core.Collector, ip string) {
	// SecurityTrails reverse-IP is a POST DSL query: find all domains whose A
	// record is this IP.
	url := "https://api.securitytrails.com/v1/domains/list?include_ips=false"
	payload := map[string]any{"filter": map[string]any{"ipv4": ip}}
	var resp struct {
		Records []struct {
			Hostname string `json:"hostname"`
		} `json:"records"`
	}
	headers := map[string]string{"APIKEY": s.Cfg.SecurityTrailsKey}
	if err := postJSON(ctx, s.Cfg, url, headers, payload, &resp); err != nil {
		c.Log(core.LogWarn, "securitytrails ip "+ip+": "+err.Error())
		return
	}
	for _, r := range resp.Records {
		s.addHostOnIP(c, ip, r.Hostname, "securitytrails")
	}
	c.Log(core.LogInfo, fmt.Sprintf("securitytrails %s: %d domains", ip, len(resp.Records)))
}

func (s ReverseIPSource) securityTrailsSubdomains(ctx context.Context, c *core.Collector, domain string) {
	url := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", domain)
	var resp struct {
		Subdomains []string `json:"subdomains"`
	}
	headers := map[string]string{"APIKEY": s.Cfg.SecurityTrailsKey}
	if err := getJSON(ctx, s.Cfg, url, headers, &resp); err != nil {
		c.Log(core.LogWarn, "securitytrails subdomains: "+err.Error())
		return
	}
	domID := graph.NodeID(graph.NodeDomain, domain)
	for _, sub := range resp.Subdomains {
		full := sub + "." + domain
		id := c.Node(graph.NodeSubdomain, full, full, map[string]any{"via": "securitytrails"})
		c.Edge(domID, id, "subdomain")
	}
	c.Log(core.LogInfo, fmt.Sprintf("securitytrails: %d subdomains", len(resp.Subdomains)))
}

// --- VirusTotal ---

func (s ReverseIPSource) virusTotalIP(ctx context.Context, c *core.Collector, ip string) {
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s/resolutions?limit=40", ip)
	var resp struct {
		Data []struct {
			Attributes struct {
				HostName string `json:"host_name"`
			} `json:"attributes"`
		} `json:"data"`
	}
	headers := map[string]string{"x-apikey": s.Cfg.VirusTotalKey}
	if err := getJSON(ctx, s.Cfg, url, headers, &resp); err != nil {
		c.Log(core.LogWarn, "virustotal ip "+ip+": "+err.Error())
		return
	}
	for _, d := range resp.Data {
		s.addHostOnIP(c, ip, d.Attributes.HostName, "virustotal")
	}
	c.Log(core.LogInfo, fmt.Sprintf("virustotal %s: %d resolutions", ip, len(resp.Data)))
}
