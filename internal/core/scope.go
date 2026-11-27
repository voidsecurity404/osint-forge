package core

import (
	"net"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Scope decides which hosts active (intrusive) sources are allowed to probe.
//
// Passive OSINT runs against anything; but active probing (nmap, http probe,
// fuzzing, zone transfer, takeover checks…) must stay on authorized assets.
// Reverse-IP, shared hosting and certificate SANs routinely surface hostnames
// that belong to OTHER organisations — scanning those would be unauthorized.
//
// The model is: hostnames are allowed only when they fall under an in-scope
// registrable domain; an IP is allowed only when it is the target itself or
// inside an extra CIDR. IPs that an in-scope NAME resolves to are admitted by the
// Collector (see Collector.MarkResolved) — so the MX/NS/CNAME servers of a
// domain, which belong to other organisations, are never probed even though
// discovery resolves them. A zero Scope (strict == false) allows everything.
type Scope struct {
	strict   bool
	targetIP net.IP       // the scan target when it is an IP
	domains  []string     // in-scope registrable domains, lower-case (e.g. "example.com")
	nets     []*net.IPNet // in-scope CIDRs from ExtraScope
}

// NewScope builds a Scope for a target. extras may contain additional domains
// and CIDRs ("10.0.0.0/8") that should also be treated as in scope.
func NewScope(t Target, strict bool, extras []string) Scope {
	s := Scope{strict: strict}
	addDomain := func(d string) {
		d = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(d, ".")))
		if d == "" {
			return
		}
		if reg, err := publicsuffix.EffectiveTLDPlusOne(d); err == nil {
			d = reg
		}
		for _, existing := range s.domains {
			if existing == d {
				return
			}
		}
		s.domains = append(s.domains, d)
	}
	if t.Domain != "" {
		addDomain(t.Domain)
	}
	if t.IP != "" {
		s.targetIP = net.ParseIP(t.IP)
	}
	for _, e := range extras {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if _, ipnet, err := net.ParseCIDR(e); err == nil {
			s.nets = append(s.nets, ipnet)
			continue
		}
		addDomain(e)
	}
	return s
}

// Strict reports whether the scope guard is enforced.
func (s Scope) Strict() bool { return s.strict }

// Allows reports whether an active source may probe the given host (a hostname
// or an IP literal) by the static rules alone. Collector.InScope additionally
// admits IPs resolved from in-scope names during the scan.
func (s Scope) Allows(host string) bool {
	if !s.strict {
		return true
	}
	host = strings.ToLower(strings.TrimSpace(strings.Trim(strings.TrimSpace(host), "[]")))
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		if s.targetIP != nil && s.targetIP.Equal(ip) {
			return true
		}
		for _, n := range s.nets {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	for _, d := range s.domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}
