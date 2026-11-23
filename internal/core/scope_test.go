package core

import "testing"

func TestScopeStrict(t *testing.T) {
	s := NewScope(ParseTarget("example.com"), true, []string{"partner.org", "10.0.0.0/8"})

	in := []string{
		"example.com", "www.example.com", "a.b.example.com",
		"partner.org", "api.partner.org",
		"1.2.3.4",  // any discovered IP is target infra
		"10.1.2.3", // extra CIDR
	}
	for _, h := range in {
		if !s.Allows(h) {
			t.Errorf("expected %q in scope", h)
		}
	}
	out := []string{"evil.com", "example.com.attacker.net", "notexample.com"}
	for _, h := range out {
		if s.Allows(h) {
			t.Errorf("expected %q out of scope", h)
		}
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
