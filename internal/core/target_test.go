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
