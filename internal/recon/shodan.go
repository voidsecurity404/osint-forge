package recon

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// ShodanSource enriches each discovered IP with Shodan's passive host data:
// open ports, service banners (product/version → CVE input) and extra
// hostnames. Requires an API key; skipped when absent. Passive (no packets hit
// the target), so it runs regardless of consent.
type ShodanSource struct{ Cfg config.Config }

func (ShodanSource) Name() string                  { return "shodan" }
func (ShodanSource) Stage() core.Stage             { return core.StageProbe } // before CVE enrich
func (s ShodanSource) Applicable(core.Target) bool { return s.Cfg.ShodanKey != "" }

type shodanHost struct {
	Ports     []int    `json:"ports"`
	Hostnames []string `json:"hostnames"`
	Vulns     []string `json:"vulns"`
	Data      []struct {
		Port      int      `json:"port"`
		Transport string   `json:"transport"`
		Product   string   `json:"product"`
		Version   string   `json:"version"`
		CPE       []string `json:"cpe"`
	} `json:"data"`
}

func (s ShodanSource) Run(ctx context.Context, c *core.Collector) error {
	for _, ip := range c.ListByType(graph.NodeIP) {
		// Only the target's own infrastructure: the MX/NS servers of a domain
		// belong to other organisations and would just burn API quota and flood
		// the graph with unrelated hosts.
		if !c.InScope(ip) || ctx.Err() != nil {
			continue
		}
		endpoint := "https://api.shodan.io/shodan/host/" + ip + "?key=" + url.QueryEscape(s.Cfg.ShodanKey)
		var h shodanHost
		if err := getJSON(ctx, s.Cfg, endpoint, nil, &h); err != nil {
			c.Log(core.LogWarn, "shodan "+ip+": "+err.Error())
			continue
		}
		ipID := c.Node(graph.NodeIP, ip, ip, nil)

		for _, host := range h.Hostnames {
			host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
			if host == "" {
				continue
			}
			hID := c.Node(graph.NodeSubdomain, host, host, map[string]any{"via": "shodan"})
			c.Edge(ipID, hID, "hosts")
		}

		for _, d := range h.Data {
			if d.Port == 0 {
				continue
			}
			proto := d.Transport
			if proto == "" {
				proto = "tcp"
			}
			cpe := ""
			if len(d.CPE) > 0 {
				cpe = d.CPE[0]
			}
			addShodanPort(c, ipID, ip, d.Port, proto, d.Product, d.Version, cpe)
		}

		// Shodan already knows some CVEs for the host; surface them directly.
		for _, v := range h.Vulns {
			v = strings.ToUpper(strings.TrimSpace(v))
			if !strings.HasPrefix(v, "CVE-") {
				continue
			}
			cveID := c.Node(graph.NodeCVE, v, v, map[string]any{
				"source": "shodan", "url": "https://nvd.nist.gov/vuln/detail/" + v,
			})
			c.Edge(ipID, cveID, "has_cve")
		}
		c.Log(core.LogInfo, fmt.Sprintf("shodan %s: портов %d, имён %d, уязвимостей %d", ip, len(h.Ports), len(h.Hostnames), len(h.Vulns)))
		c.Flush()
	}
	return nil
}

// addShodanPort mirrors scan.addPort but lives in recon to avoid an import
// cycle; it creates port + service nodes the CVE engine can consume.
func addShodanPort(c *core.Collector, ipID, ip string, port int, proto, product, version, cpe string) {
	portKey := fmt.Sprintf("%s:%d/%s", ip, port, proto)
	pID := c.Node(graph.NodePort, portKey, fmt.Sprintf("%d/%s", port, proto), map[string]any{
		"port": fmt.Sprint(port), "proto": proto, "source": "shodan",
	})
	c.Edge(ipID, pID, "has_port")
	if product == "" {
		return
	}
	svcLabel := strings.TrimSpace(product + " " + version)
	svcKey := fmt.Sprintf("%s:%d", ip, port)
	sID := c.Node(graph.NodeService, svcKey, svcLabel, map[string]any{
		"name": strings.ToLower(product), "product": product, "version": version,
		"cpe": cpe, "ip": ip, "port": fmt.Sprint(port), "source": "shodan",
	})
	c.Edge(pID, sID, "runs_service")
}
