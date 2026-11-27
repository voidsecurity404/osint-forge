package core

import (
	"testing"

	"osint-forge/internal/graph"
)

func TestScopeStrict(t *testing.T) {
	s := NewScope(ParseTarget("example.com"), true, []string{"partner.org", "10.0.0.0/8"})

	in := []string{
		"example.com", "www.example.com", "a.b.example.com",
		"partner.org", "api.partner.org",
		"10.1.2.3", // extra CIDR
	}
	for _, h := range in {
		if !s.Allows(h) {
			t.Errorf("expected %q in scope", h)
		}
	}
	out := []string{
		"evil.com", "example.com.attacker.net", "notexample.com",
		// A bare IP is NOT in scope by itself: it must be the target, inside an
		// extra CIDR, or resolved from an in-scope name (see the collector test).
		"1.2.3.4",
	}
	for _, h := range out {
		if s.Allows(h) {
			t.Errorf("expected %q out of scope", h)
		}
	}
}

func TestScopeTargetIP(t *testing.T) {
	s := NewScope(ParseTarget("93.184.216.34"), true, nil)
	if !s.Allows("93.184.216.34") {
		t.Error("the target IP itself must be in scope")
	}
	if s.Allows("93.184.216.35") {
		t.Error("a neighbouring IP must not be in scope")
	}
	v6 := NewScope(ParseTarget("[2606:4700::1111]:443"), true, nil)
	if !v6.Allows("2606:4700:0:0:0:0:0:1111") || !v6.Allows("[2606:4700::1111]") {
		t.Error("IPv6 target must match regardless of notation")
	}
}

func TestScopeDisabledAllowsAll(t *testing.T) {
	s := NewScope(ParseTarget("example.com"), false, nil)
	for _, h := range []string{"anything.com", "1.2.3.4", "evil.net"} {
		if !s.Allows(h) {
			t.Errorf("non-strict scope should allow %q", h)
		}
	}
}

func TestScopeSubdomainTarget(t *testing.T) {
	// A subdomain target still scopes to the whole registrable domain.
	s := NewScope(ParseTarget("api.example.com"), true, nil)
	if !s.Allows("www.example.com") {
		t.Error("expected sibling subdomain in scope via eTLD+1")
	}
}

// IPs become in scope only when an in-scope NAME resolves to them. The MX/NS
// servers of a domain (e.g. Google mail, Cloudflare DNS) are resolved during
// discovery too, but they belong to someone else and must never be actively
// probed — previously every discovered IP was treated as target infrastructure.
func TestCollectorIPScopeFollowsResolution(t *testing.T) {
	c := NewCollector(ParseTarget("example.com"), graph.New(), nil)
	c.SetScope(NewScope(ParseTarget("example.com"), true, nil))
	src := c.forSource("dns")

	src.MarkResolved("www.example.com", "93.184.216.34")
	src.MarkResolved("aspmx.l.google.com", "142.250.1.27") // MX host: out of scope

	if !src.InScope("93.184.216.34") {
		t.Error("IP of an in-scope name must be in scope")
	}
	if src.InScope("142.250.1.27") {
		t.Error("IP of an out-of-scope MX host must stay out of scope")
	}
	// Shared across every source's collector in the same scan.
	if !c.forSource("nmap").InScope("93.184.216.34") {
		t.Error("resolved-IP set must be shared between sources")
	}
	// Non-strict mode keeps the permissive behaviour.
	loose := NewCollector(ParseTarget("example.com"), graph.New(), nil)
	loose.SetScope(NewScope(ParseTarget("example.com"), false, nil))
	if !loose.InScope("142.250.1.27") {
		t.Error("non-strict scope should allow any IP")
	}
}

// A host that is already the root domain must not be duplicated as a
// "subdomain:" node when another source (OTX, Shodan, reverse-IP…) reports it.
func TestNodeReusesExistingHostOfAnotherType(t *testing.T) {
	g := graph.New()
	c := NewCollector(ParseTarget("example.com"), g, nil)
	root := c.Node(graph.NodeDomain, "example.com", "example.com", map[string]any{"root": true})
	id := c.Node(graph.NodeSubdomain, "example.com", "example.com", map[string]any{"via": "otx"})
	if id != root {
		t.Fatalf("got %q, want the existing root %q", id, root)
	}
	if n, _ := g.Counts(); n != 1 {
		t.Fatalf("duplicate host node created: %d nodes", n)
	}
	if n, _ := g.Copy(root); n.Props["via"] != "otx" {
		t.Fatalf("props not merged into the existing node: %+v", n.Props)
	}
}
