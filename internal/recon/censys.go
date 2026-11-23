package recon

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// CensysSource enriches discovered IPs with Censys Search API v2 host data:
// services with software product/version (→ CVE input) and DNS names. Requires
// an API ID + secret; skipped when either is absent. Passive.
type CensysSource struct{ Cfg config.Config }

func (CensysSource) Name() string      { return "censys" }
func (CensysSource) Stage() core.Stage { return core.StageProbe } // before CVE enrich
func (s CensysSource) Applicable(core.Target) bool {
	return s.Cfg.CensysID != "" && s.Cfg.CensysSecret != ""
}

type censysHost struct {
	Result struct {
		Services []struct {
			Port              int    `json:"port"`
			ServiceName       string `json:"service_name"`
			TransportProtocol string `json:"transport_protocol"`
			Software          []struct {
				Product string `json:"product"`
				Version string `json:"version"`
				URI     string `json:"uniform_resource_identifier"`
			} `json:"software"`
		} `json:"services"`
		DNS struct {
			Names []string `json:"names"`
		} `json:"dns"`
	} `json:"result"`
}

func (s CensysSource) Run(ctx context.Context, c *core.Collector) error {
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(s.Cfg.CensysID+":"+s.Cfg.CensysSecret))
	headers := map[string]string{"Authorization": auth}

	for _, ip := range c.ListByType(graph.NodeIP) {
		var h censysHost
		endpoint := "https://search.censys.io/api/v2/hosts/" + ip
		if err := getJSON(ctx, s.Cfg, endpoint, headers, &h); err != nil {
			c.Log(core.LogWarn, "censys "+ip+": "+err.Error())
			continue
		}
		ipID := c.Node(graph.NodeIP, ip, ip, nil)

		for _, name := range h.Result.DNS.Names {
			name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
			if name == "" {
				continue
			}
			nID := c.Node(graph.NodeSubdomain, name, name, map[string]any{"via": "censys"})
			c.Edge(ipID, nID, "hosts")
		}

		for _, svc := range h.Result.Services {
			if svc.Port == 0 {
				continue
			}
			proto := strings.ToLower(svc.TransportProtocol)
			if proto == "" {
				proto = "tcp"
			}
			product, version, cpe := "", "", ""
			if len(svc.Software) > 0 {
				product = svc.Software[0].Product
				version = svc.Software[0].Version
				cpe = svc.Software[0].URI
			}
			addShodanPort(c, ipID, ip, svc.Port, proto, product, version, cpe)
		}
		c.Log(core.LogInfo, fmt.Sprintf("censys %s: %d services, %d names", ip, len(h.Result.Services), len(h.Result.DNS.Names)))
		c.Flush()
	}
	return nil
}
