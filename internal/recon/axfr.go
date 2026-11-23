package recon

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// AXFRSource attempts a DNS zone transfer (AXFR) against each of the domain's
// name servers. A successful transfer is a serious misconfiguration that leaks
// the entire zone; any records returned are also imported as subdomains.
type AXFRSource struct{ Cfg config.Config }

func (AXFRSource) Name() string      { return "zone-transfer" }
func (AXFRSource) Stage() core.Stage { return core.StageProbe }
func (s AXFRSource) Applicable(t core.Target) bool {
	return t.Domain != "" && s.Cfg.ZoneTransfer
}

func (s AXFRSource) Run(ctx context.Context, c *core.Collector) error {
	domain := c.Target.Domain
	nss, err := net.LookupNS(domain)
	if err != nil || len(nss) == 0 {
		return nil
	}
	domID := graph.NodeID(graph.NodeDomain, domain)

	for _, ns := range nss {
		server := strings.TrimSuffix(ns.Host, ".")
		records, ok := s.transfer(domain, server)
		if !ok {
			continue
		}
		// Zone transfer succeeded — a notable finding.
		c.Finding("high", "axfr:"+server,
			"Zone transfer (AXFR) ochiq: "+server,
			fmt.Sprintf("%s name serveri AXFR so'roviga butun zonani (%d yozuv) qaytardi. Bu barcha DNS yozuvlarini oshkor qiladi.", server, len(records)),
			domID)
		for _, host := range records {
			host = strings.ToLower(strings.TrimSuffix(host, "."))
			if host == "" || !strings.HasSuffix(host, domain) {
				continue
			}
			id := c.Node(graph.NodeSubdomain, host, host, map[string]any{"via": "axfr"})
			c.Edge(domID, id, "subdomain")
		}
		c.Log(core.LogWarn, fmt.Sprintf("AXFR OPEN on %s: %d records", server, len(records)))
		c.Flush()
	}
	return nil
}

// transfer performs the AXFR and returns the hostnames found.
func (s AXFRSource) transfer(domain, server string) ([]string, bool) {
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(domain))
	tr := &dns.Transfer{DialTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second}
	ch, err := tr.In(m, net.JoinHostPort(server, "53"))
	if err != nil {
		return nil, false
	}
	var hosts []string
	got := false
	for env := range ch {
		if env.Error != nil {
			return nil, false
		}
		got = true
		for _, rr := range env.RR {
			hosts = append(hosts, rr.Header().Name)
		}
	}
	return hosts, got && len(hosts) > 0
}
