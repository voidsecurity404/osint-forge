// Package recon holds passive/OSINT discovery sources: DNS, WHOIS/RDAP,
// certificate transparency (crt.sh) and reverse-IP lookups.
package recon

import (
	"context"
	"errors"
	"net"
	"strings"

	"golang.org/x/net/publicsuffix"

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
		c.MarkResolved(host, ip) // live resolution of an in-scope name → in-scope IP
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
			if h == "" {
				continue // null MX (RFC 7505): the domain accepts no mail
			}
			id := c.Node(graph.NodeSubdomain, h, h, map[string]any{"via": "mx"})
			c.Edge(domID, id, "mx")
		}
	}
	if nss, err := resolver.LookupNS(ctx, domain); err == nil {
		for _, ns := range nss {
			h := strings.TrimSuffix(ns.Host, ".")
			if h == "" {
				continue
			}
			id := c.Node(graph.NodeSubdomain, h, h, map[string]any{"via": "ns"})
			c.Edge(domID, id, "ns")
		}
	}
	txts, err := resolver.LookupTXT(ctx, domain)
	if err != nil && !isNotFound(err) {
		// SERVFAIL / timeout: we simply don't know — never report "SPF missing"
		// or "DMARC missing" on a lookup failure (false positive).
		c.Log(core.LogWarn, "запрос TXT не удался, проверки SPF/DMARC пропущены: "+err.Error())
		return
	}
	if len(txts) > 0 {
		c.Node(graph.NodeDomain, domain, domain, map[string]any{"txt": txts})
	}
	checkEmailSecurity(ctx, c, domain, domID, txts)
}

// isNotFound reports whether a lookup error means "no such record / name"
// (an authoritative answer) rather than a transient failure.
func isNotFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

// orgDomain returns the organisational (registrable) domain of a host, e.g.
// api.eu.example.co.uk → example.co.uk.
func orgDomain(host string) string {
	if reg, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return reg
	}
	return host
}

// lookupDMARC returns the DMARC record governing domain. Per RFC 7489 §6.6.3 a
// subdomain without its own _dmarc record inherits the organisational
// domain's policy. ok=false means the lookup failed (unknown, not "missing").
func lookupDMARC(ctx context.Context, domain string) (record string, ok bool) {
	names := []string{"_dmarc." + domain}
	if org := orgDomain(domain); org != domain {
		names = append(names, "_dmarc."+org)
	}
	for _, name := range names {
		recs, err := resolver.LookupTXT(ctx, name)
		if err != nil && !isNotFound(err) {
			return "", false
		}
		for _, r := range recs {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(r)), "v=dmarc1") {
				return r, true
			}
		}
	}
	return "", true
}

// checkEmailSecurity flags missing/weak SPF and DMARC — common email-spoofing
// exposures.
func checkEmailSecurity(ctx context.Context, c *core.Collector, domain, domID string, txts []string) {
	var spf string
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1") {
			spf = t
			break
		}
	}
	// SPF matters for names that send/receive mail. A plain subdomain (www,
	// api…) without MX records not having SPF is normal, not a finding.
	isOrg := orgDomain(domain) == domain
	hasMX := false
	if mxs, err := resolver.LookupMX(ctx, domain); err == nil {
		for _, mx := range mxs {
			if strings.TrimSuffix(mx.Host, ".") != "" {
				hasMX = true
			}
		}
	}
	switch {
	case spf == "" && (isOrg || hasMX):
		c.Finding("medium", "spf-missing:"+domain, "Нет записи SPF",
			"У домена нет записи SPF — подделка отправителя писем упрощается.", domID)
	case spf != "" && strings.Contains(strings.ToLower(spf), "+all"):
		c.Finding("high", "spf-weak:"+domain, "SPF слишком открыт (+all)",
			"SPF '+all' разрешает любому серверу отправлять письма от имени домена.", domID)
	}

	// DMARC lives at _dmarc.<domain> (or the organisational domain) as TXT.
	dmarc, ok := lookupDMARC(ctx, domain)
	if !ok {
		return
	}
	if dmarc == "" {
		c.Finding("medium", "dmarc-missing:"+domain, "Нет записи DMARC",
			"Политики DMARC нет — защита от поддельных писем слабая.", domID)
	} else if dmarcTag(dmarc, "p") == "none" {
		c.Finding("low", "dmarc-none:"+domain, "DMARC p=none",
			"DMARC только в режиме мониторинга (p=none) — поддельные письма не блокируются.", domID)
	}
}

// dmarcTag returns the lower-cased value of one tag of a DMARC record
// ("v=DMARC1; p=reject; sp=none" → p = "reject"). A plain substring search
// would read "sp=none" as "p=none".
func dmarcTag(record, tag string) string {
	for _, part := range strings.Split(record, ";") {
		k, v, ok := strings.Cut(part, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), tag) {
			return strings.ToLower(strings.TrimSpace(v))
		}
	}
	return ""
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
