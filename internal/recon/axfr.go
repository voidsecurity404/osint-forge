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

// inDomain reports whether host is domain itself or a subdomain of it (with a
// proper dot boundary — "evilexample.com" is NOT inside "example.com").
func inDomain(host, domain string) bool {
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func (s AXFRSource) Run(ctx context.Context, c *core.Collector) error {
	domain := c.Target.Domain
	nss, err := resolver.LookupNS(ctx, domain)
	if err != nil || len(nss) == 0 {
		return nil
	}
	domID := graph.NodeID(graph.NodeDomain, domain)

	for _, ns := range nss {
		if ctx.Err() != nil {
			return nil
		}
		server := strings.TrimSuffix(ns.Host, ".")
		records, ok := s.transfer(ctx, domain, server)
		if !ok {
			continue
		}
		// Zone transfer succeeded — a notable finding.
		c.Finding("high", "axfr:"+server,
			"Открыт перенос зоны (AXFR): "+server,
			fmt.Sprintf("Сервер имён %s отдал всю зону (%d записей) по запросу AXFR. Это раскрывает все DNS-записи.", server, len(records)),
			domID)
		for _, host := range records {
			host = strings.ToLower(strings.TrimSuffix(host, "."))
			if host == "" || host == domain || !inDomain(host, domain) {
				continue
			}
			id := c.Node(graph.NodeSubdomain, host, host, map[string]any{"via": "axfr"})
			c.Edge(domID, id, "subdomain")
		}
		c.Log(core.LogWarn, fmt.Sprintf("AXFR ОТКРЫТ на %s: %d записей", server, len(records)))
		c.Flush()
	}
	return nil
}

// maxAXFRRecords caps how many records are read from an (open) zone transfer.
const maxAXFRRecords = 50000

// transfer performs the AXFR and returns the hostnames found. It gives up when
// ctx is cancelled (the transfer itself has its own dial/read timeouts).
func (s AXFRSource) transfer(ctx context.Context, domain, server string) ([]string, bool) {
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(domain))
	tr := &dns.Transfer{DialTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second}
	ch, err := tr.In(m, net.JoinHostPort(server, "53"))
	if err != nil {
		return nil, false
	}
	defer func() {
		for range ch { // drain so the transfer goroutine can exit
		}
	}()
	var hosts []string
	got := false
	for {
		select {
		case <-ctx.Done():
			return nil, false
		case env, ok := <-ch:
			if !ok {
				return hosts, got && len(hosts) > 0
			}
			if env.Error != nil {
				return nil, false
			}
			got = true
			for _, rr := range env.RR {
				if len(hosts) < maxAXFRRecords {
					hosts = append(hosts, rr.Header().Name)
				}
			}
		}
	}
}
