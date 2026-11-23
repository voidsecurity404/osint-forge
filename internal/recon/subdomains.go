package recon

import (
	"bufio"
	"context"
	"embed"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// dnsResolvers are fast public resolvers queried directly (round-robin) for
// brute-forcing — far quicker than the system resolver on NXDOMAIN.
var dnsResolvers = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}

var dnsClient = &dns.Client{Timeout: 2 * time.Second}

// fastLookupA sends a single A query and returns the resolved IPv4 addresses.
// A nil result means the name does not resolve (NXDOMAIN or error).
func fastLookupA(ctx context.Context, host string, serverIdx int) []string {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	server := dnsResolvers[serverIdx%len(dnsResolvers)]
	r, _, err := dnsClient.ExchangeContext(ctx, m, server)
	if err != nil || r == nil || r.Rcode != dns.RcodeSuccess {
		return nil
	}
	var ips []string
	for _, rr := range r.Answer {
		if a, ok := rr.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}
	return ips
}

// SecLists DNS subdomain wordlist, embedded for offline brute-forcing.
//
//go:embed wordlists/subdomains-5000.txt
var subdomainFS embed.FS

// BruteforceSource discovers subdomains by resolving a wordlist of common names
// against the target domain. Keyless and offline-capable; only names that
// actually resolve are added, so it produces no false positives.
type BruteforceSource struct{ Cfg config.Config }

func (BruteforceSource) Name() string      { return "subdomain-brute" }
func (BruteforceSource) Stage() core.Stage { return core.StageDiscovery }
func (s BruteforceSource) Applicable(t core.Target) bool {
	return t.Domain != "" && s.Cfg.SubdomainBruteforce
}

func (s BruteforceSource) Run(ctx context.Context, c *core.Collector) error {
	words := loadSubdomainWords()
	if len(words) == 0 {
		return nil
	}
	domain := c.Target.Domain
	domID := graph.NodeID(graph.NodeDomain, domain)

	// Wildcard detection: if a random subdomain resolves, the domain answers
	// everything — record those IPs so we can discard wildcard noise.
	wildcard := map[string]bool{}
	if ips := fastLookupA(ctx, randSub()+"."+domain, 0); len(ips) > 0 {
		for _, ip := range ips {
			wildcard[ip] = true
		}
		c.Log(core.LogWarn, fmt.Sprintf("wildcard DNS detected (%d IPs) — filtering brute-force noise", len(wildcard)))
	}

	conc := s.Cfg.MaxConcurrent * 8
	if conc < 150 {
		conc = 150
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	var found int64
	var idx int64

	for _, w := range words {
		wg.Add(1)
		sem <- struct{}{}
		go func(w string) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			host := w + "." + domain
			si := int(atomic.AddInt64(&idx, 1))
			ips := fastLookupA(ctx, host, si)
			if len(ips) == 0 {
				return
			}
			// Skip hosts that resolve only to the wildcard IPs.
			real := false
			for _, ip := range ips {
				if !wildcard[ip] {
					real = true
					break
				}
			}
			if !real {
				return
			}
			subID := c.Node(graph.NodeSubdomain, host, host, map[string]any{"via": "bruteforce"})
			c.Edge(domID, subID, "subdomain")
			for _, ip := range ips {
				ipID := c.Node(graph.NodeIP, ip, ip, nil)
				c.Edge(subID, ipID, "resolves_to")
			}
			atomic.AddInt64(&found, 1)
			c.Flush()
		}(w)
	}
	wg.Wait()
	c.Log(core.LogInfo, fmt.Sprintf("brute-forced %d live subdomains from %d candidates", found, len(words)))
	return nil
}

func randSub() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 12)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return "zzz" + string(b)
}

func loadSubdomainWords() []string {
	f, err := subdomainFS.Open("wordlists/subdomains-5000.txt")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		w := strings.TrimSpace(sc.Text())
		if w != "" && !strings.HasPrefix(w, "#") {
			out = append(out, w)
		}
	}
	return out
}
