package core

import "testing"

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in         string
		wantIP     string
		wantDomain string
		wantIsIP   bool
	}{
		{"example.com", "", "example.com", false},
		{"https://example.com/path?q=1", "", "example.com", false},
		{"http://Example.COM:8443/", "", "example.com", false},
		{"sub.example.com.", "", "sub.example.com", false},
		{"1.2.3.4", "1.2.3.4", "", true},
		{"1.2.3.4:443", "1.2.3.4", "", true},
		{"[2606:4700:4700::1111]:443", "2606:4700:4700::1111", "", true},
		{"  example.com  ", "", "example.com", false},
	}
	for _, c := range cases {
		got := ParseTarget(c.in)
		if got.IP != c.wantIP || got.Domain != c.wantDomain || got.IsIP != c.wantIsIP {
			t.Errorf("ParseTarget(%q) = %+v, want ip=%q domain=%q isIP=%v",
				c.in, got, c.wantIP, c.wantDomain, c.wantIsIP)
		}
	}
}

func TestValidDomain(t *testing.T) {
	good := []string{"example.com", "sub.example.com", "a-b.example.co.uk", "xn--80ak6aa92e.com", "x1.io"}
	for _, g := range good {
		if !ValidDomain(g) {
			t.Errorf("%q should be valid", g)
		}
	}
	bad := []string{"", "example", "!!!@@@", "a..b", "-x.com", "x-.com", "a b.com", "foo.1", "http://x"}
	for _, b := range bad {
		if ValidDomain(b) {
			t.Errorf("%q should be invalid", b)
		}
	}
}

func TestParseTargetValid(t *testing.T) {
	if !ParseTarget("example.com").Valid {
		t.Error("example.com should be valid")
	}
	if !ParseTarget("1.2.3.4").Valid {
		t.Error("ip should be valid")
	}
	if ParseTarget("!!!bad").Valid {
		t.Error("junk should be invalid")
	}
}
