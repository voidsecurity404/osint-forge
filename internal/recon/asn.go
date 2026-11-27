package recon

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// ASNSource maps each discovered IP to its Autonomous System (network operator)
// using Team Cymru's IP-to-ASN DNS service. This is keyless and, unlike the
// previous cleartext http://ip-api.com lookup, does not leak the target IPs in
// a plaintext HTTP URL to a third-party web server. It also returns the routed
// BGP prefix (CIDR), which is recorded on the ASN node.
type ASNSource struct{ Cfg config.Config }

func (ASNSource) Name() string                { return "asn" }
func (ASNSource) Stage() core.Stage           { return core.StageEnrich }
func (ASNSource) Applicable(core.Target) bool { return true }

func (s ASNSource) Run(ctx context.Context, c *core.Collector) error {
	// Lookups run in parallel: one by one, every unanswered DNS query cost a
	// 2 s timeout per resolver — 16 IPs took ~35 s on a real target.
	var (
		mu        sync.Mutex
		nameCache = map[string]string{}
		wg        sync.WaitGroup
		sem       = make(chan struct{}, asnWorkers)
	)
	asName := func(asn string) string {
		mu.Lock()
		name, ok := nameCache[asn]
		mu.Unlock()
		if ok {
			return name
		}
		name = cymruASName(ctx, asn)
		mu.Lock()
		nameCache[asn] = name
		mu.Unlock()
		return name
	}
	for _, ip := range c.ListByType(graph.NodeIP) {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			asn, prefix, country, ok := cymruOrigin(ctx, ip)
			if !ok {
				return
			}
			name := asName(asn)
			label := "AS" + asn
			if name != "" {
				label = "AS" + asn + " " + name
			}
			if country != "" {
				c.Node(graph.NodeIP, ip, ip, map[string]any{"country": country})
			}
			asProps := map[string]any{"name": name}
			if prefix != "" {
				asProps["prefix"] = prefix // routed CIDR — enables netblock pivoting
			}
			asID := c.Node(graph.NodeASN, "AS"+asn, label, asProps)
			c.Edge(graph.NodeID(graph.NodeIP, ip), asID, "belongs_to_asn")
			c.Flush()
		}(ip)
	}
	wg.Wait()
	return nil
}

// asnWorkers bounds concurrent Team Cymru lookups.
const asnWorkers = 8

// cymruOrigin looks up the ASN, BGP prefix and country for an IP via
// <reversed-ip>.origin.asn.cymru.com (origin6 for IPv6).
func cymruOrigin(ctx context.Context, ipStr string) (asn, prefix, country string, ok bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", "", "", false
	}
	var qname string
	if v4 := ip.To4(); v4 != nil {
		qname = reverseOctets(v4) + ".origin.asn.cymru.com."
	} else {
		qname = reverseNibbles(ip) + ".origin6.asn.cymru.com."
	}
	return parseCymruOrigin(txtLookup(ctx, qname))
}

// parseCymruOrigin parses "15169 | 8.8.8.0/24 | US | arin | 1992-12-01". A
// malformed answer (empty ASN field) yields ok=false instead of a panic.
func parseCymruOrigin(txt string) (asn, prefix, country string, ok bool) {
	parts := splitPipe(txt)
	if len(parts) < 3 {
		return "", "", "", false
	}
	fields := strings.Fields(parts[0])
	if len(fields) == 0 {
		return "", "", "", false
	}
	asn = fields[0] // first ASN if multi-origin
	for _, r := range asn {
		if r < '0' || r > '9' {
			return "", "", "", false
		}
	}
	return asn, parts[1], parts[2], true
}

// cymruASName resolves an AS number to its name via ASxxxx.asn.cymru.com.
func cymruASName(ctx context.Context, asn string) string {
	txt := txtLookup(ctx, "AS"+asn+".asn.cymru.com.")
	if txt == "" {
		return ""
	}
	// "15169 | US | arin | 1992-12-01 | GOOGLE, US"
	parts := splitPipe(txt)
	if len(parts) < 5 {
		return ""
	}
	name := parts[4]
	if i := strings.LastIndex(name, ", "); i > 0 { // trim trailing country code
		name = name[:i]
	}
	return strings.TrimSpace(name)
}

func txtLookup(ctx context.Context, qname string) string {
	m := new(dns.Msg)
	m.SetQuestion(qname, dns.TypeTXT)
	for i := range dnsResolvers {
		r, _, err := dnsClient.ExchangeContext(ctx, m, dnsResolvers[i%len(dnsResolvers)])
		if err != nil || r == nil {
			continue
		}
		for _, rr := range r.Answer {
			if t, ok := rr.(*dns.TXT); ok && len(t.Txt) > 0 {
				return strings.Join(t.Txt, "")
			}
		}
		return ""
	}
	return ""
}

func splitPipe(s string) []string {
	parts := strings.Split(s, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func reverseOctets(v4 net.IP) string {
	return strings.Join([]string{
		strconv.Itoa(int(v4[3])), strconv.Itoa(int(v4[2])),
		strconv.Itoa(int(v4[1])), strconv.Itoa(int(v4[0])),
	}, ".")
}

func reverseNibbles(ip net.IP) string {
	ip = ip.To16()
	const hexd = "0123456789abcdef"
	var sb strings.Builder
	for i := len(ip) - 1; i >= 0; i-- {
		b := ip[i]
		sb.WriteByte(hexd[b&0x0f])
		sb.WriteByte('.')
		sb.WriteByte(hexd[b>>4])
		if i > 0 {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}
