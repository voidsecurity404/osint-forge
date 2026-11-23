// Package recon holds passive/OSINT discovery sources: DNS, WHOIS/RDAP,
// certificate transparency (crt.sh) and reverse-IP lookups.
package recon

import (
	"context"
	"net"
	"strings"

	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// resolver is used by DNS sources; a custom one could set timeouts/servers.
var resolver = &net.Resolver{}

// DNSSource gathers DNS records for the root target and does reverse DNS.
type DNSSource struct{}

func (DNSSource) Name() string                { return "dns" }
func (DNSSource) Stage() core.Stage           { return core.StageDiscovery }
func (DNSSource) Applicable(core.Target) bool { return true }

func (DNSSource) Run(ctx context.Context, c *core.Collector) error {
	t := c.Target
	if t.Domain != "" {
		resolveHost(ctx, c, t.Domain, graph.NodeDomain)
		lookupRecords(ctx, c, t.Domain)
	}
	if t.IP != "" {
		reverseLookup(ctx, c, t.IP)
	}
	c.Flush()
	return nil
}

// resolveHost resolves a hostname to its A/AAAA addresses and links them.
func resolveHost(ctx context.Context, c *core.Collector, host string, hostType graph.NodeType) {
	hostID := graph.NodeID(hostType, host)
	addrs, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return
	}
	for _, a := range addrs {
		ip := a.IP.String()
		ipID := c.Node(graph.NodeIP, ip, ip, nil)
		c.Edge(hostID, ipID, "resolves_to")
	}
	c.Log(core.LogInfo, host+" → "+itoaAddrs(addrs))
}

func lookupRecords(ctx context.Context, c *core.Collector, domain string) {
	domID := graph.NodeID(graph.NodeDomain, domain)

	if cname, err := resolver.LookupCNAME(ctx, domain); err == nil {
		cname = strings.TrimSuffix(cname, ".")
		if cname != "" && cname != domain {
			id := c.Node(graph.NodeSubdomain, cname, cname, map[string]any{"via": "cname"})
			c.Edge(domID, id, "cname")
		}
	}
	if mxs, err := resolver.LookupMX(ctx, domain); err == nil {
		for _, mx := range mxs {
			h := strings.TrimSuffix(mx.Host, ".")
			id := c.Node(graph.NodeSubdomain, h, h, map[string]any{"via": "mx"})
			c.Edge(domID, id, "mx")
		}
	}
	if nss, err := resolver.LookupNS(ctx, domain); err == nil {
		for _, ns := range nss {
			h := strings.TrimSuffix(ns.Host, ".")
			id := c.Node(graph.NodeSubdomain, h, h, map[string]any{"via": "ns"})
			c.Edge(domID, id, "ns")
		}
	}
	var txts []string
	if t, err := resolver.LookupTXT(ctx, domain); err == nil && len(t) > 0 {
		txts = t
		c.Node(graph.NodeDomain, domain, domain, map[string]any{"txt": txts})
	}
	checkEmailSecurity(ctx, c, domain, domID, txts)
}

// checkEmailSecurity flags missing/weak SPF and DMARC — common email-spoofing
// exposures.
func checkEmailSecurity(ctx context.Context, c *core.Collector, domain, domID string, txts []string) {
	var spf string
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
			spf = t
			break
		}
	}
	if spf == "" {
		c.Finding("medium", "spf-missing:"+domain, "SPF yozuvi yo'q",
			"Domenda SPF yozuvi topilmadi — email spoofing osonlashadi.", domID)
	} else if strings.Contains(spf, "+all") {
		c.Finding("high", "spf-weak:"+domain, "SPF juda ochiq (+all)",
			"SPF '+all' har qanday serverga domen nomidan xat yuborishga ruxsat beradi.", domID)
	}

	// DMARC lives at _dmarc.<domain> as a TXT record.
	dmarc := ""
	if t, err := resolver.LookupTXT(ctx, "_dmarc."+domain); err == nil {
		for _, r := range t {
			if strings.HasPrefix(strings.ToLower(r), "v=dmarc1") {
				dmarc = r
				break
			}
		}
	}
	if dmarc == "" {
		c.Finding("medium", "dmarc-missing:"+domain, "DMARC yozuvi yo'q",
			"DMARC siyosati yo'q — spoofing xatlariga qarshi himoya zaif.", domID)
	} else if strings.Contains(strings.ToLower(dmarc), "p=none") {
		c.Finding("low", "dmarc-none:"+domain, "DMARC p=none",
			"DMARC faqat kuzatuv rejimida (p=none) — spoofing bloklanmaydi.", domID)
	}
}

func reverseLookup(ctx context.Context, c *core.Collector, ip string) {
	ipID := c.Node(graph.NodeIP, ip, ip, nil)
	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil {
		return
	}
	for _, n := range names {
		n = strings.TrimSuffix(n, ".")
		id := c.Node(graph.NodeSubdomain, n, n, map[string]any{"via": "ptr"})
		c.Edge(ipID, id, "ptr")
	}
}

// ResolveSource runs in the probe stage and resolves every host discovered so
// far (e.g. subdomains from crt.sh) to IPs, bridging passive discovery into the
// active-scan host set.
type ResolveSource struct{}

func (ResolveSource) Name() string                { return "dns-resolve" }
func (ResolveSource) Stage() core.Stage           { return core.StageResolve }
func (ResolveSource) Applicable(core.Target) bool { return true }

func (ResolveSource) Run(ctx context.Context, c *core.Collector) error {
	for _, h := range c.ListByType(graph.NodeSubdomain) {
		resolveHost(ctx, c, h, graph.NodeSubdomain)
		c.Flush()
	}
	return nil
}

func itoaAddrs(addrs []net.IPAddr) string {
	parts := make([]string, 0, len(addrs))
	for _, a := range addrs {
		parts = append(parts, a.IP.String())
	}
	return strings.Join(parts, ", ")
}
