package recon

import (
	"context"
	"fmt"
	"net"
	"strings"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// OTXSource queries AlienVault OTX passive DNS (keyless) for hostnames and IPs
// historically associated with the target domain.
type OTXSource struct{ Cfg config.Config }

func (OTXSource) Name() string                  { return "otx" }
func (OTXSource) Stage() core.Stage             { return core.StageDiscovery }
func (OTXSource) Applicable(t core.Target) bool { return t.Domain != "" }

type otxPassiveDNS struct {
	PassiveDNS []struct {
		Hostname string `json:"hostname"`
		Address  string `json:"address"`
	} `json:"passive_dns"`
}

func (s OTXSource) Run(ctx context.Context, c *core.Collector) error {
	domain := c.Target.Domain
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
	var resp otxPassiveDNS
	if err := getJSON(ctx, s.Cfg, url, nil, &resp); err != nil {
		// The keyless API rate-limits per IP: that is not a fault of the scan.
		if strings.Contains(err.Error(), "HTTP 429") {
			c.Log(core.LogWarn, "OTX so'rov limiti (HTTP 429) — bu safar passiv DNS olinmadi, keyinroq qayta urinib ko'ring")
			return nil
		}
		return fmt.Errorf("otx: %w", err)
	}

	domID := graph.NodeID(graph.NodeDomain, domain)
	seen := 0
	for _, r := range resp.PassiveDNS {
		if ctx.Err() != nil {
			break
		}
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.Hostname), "."))
		if host == "" || !(host == domain || strings.HasSuffix(host, "."+domain)) {
			continue
		}
		subID := c.Node(graph.NodeSubdomain, host, host, map[string]any{"via": "otx"})
		c.Edge(domID, subID, "subdomain")
		// Passive DNS is HISTORICAL: the address may have been reassigned to
		// someone else since, so it is linked but never marked as in-scope
		// (no MarkResolved) — only live resolution admits an IP for probing.
		if ip := net.ParseIP(strings.TrimSpace(r.Address)); ip != nil {
			ipID := c.Node(graph.NodeIP, ip.String(), ip.String(), nil)
			c.Edge(subID, ipID, "passive_dns")
		}
		seen++
	}
	c.Log(core.LogInfo, fmt.Sprintf("otx: %d passive-dns records", seen))
	c.Flush()
	return nil
}
