package scan

import "testing"

func TestParseProductVersion(t *testing.T) {
	cases := []struct {
		in      string
		product string
		version string
		ok      bool
	}{
		{"nginx/1.18.0", "nginx", "1.18.0", true},
		{"Apache/2.4.41 (Ubuntu)", "Apache", "2.4.41", true},
		{"PHP/7.4.3", "PHP", "7.4.3", true},
		{"Microsoft-IIS/10.0", "Microsoft-IIS", "10.0", true},
		{"WordPress 6.2.1", "WordPress", "6.2.1", true},
		{"cloudflare", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		p, v, ok := parseProductVersion(c.in)
		if ok != c.ok || p != c.product || v != c.version {
			t.Errorf("parseProductVersion(%q) = (%q,%q,%v), want (%q,%q,%v)",
				c.in, p, v, ok, c.product, c.version, c.ok)
		}
	}
}

func TestParseBanner(t *testing.T) {
	cases := []struct {
		in      string
		product string
		version string
		ok      bool
	}{
		{"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", "OpenSSH", "8.2", true},
		{"220 ProFTPD 1.3.5a Server ready", "ProFTPD", "1.3.5", true},
		{"220 mail.example.com ESMTP Postfix", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		p, v, ok := parseBanner(c.in)
		if ok != c.ok || p != c.product || v != c.version {
			t.Errorf("parseBanner(%q) = (%q,%q,%v), want (%q,%q,%v)",
				c.in, p, v, ok, c.product, c.version, c.ok)
		}
	}
}

func TestStatusFilter(t *testing.T) {
	f := ParseStatusFilter("2xx,3xx,401,403,405,5xx")
	allow := []int{200, 204, 301, 401, 403, 405, 500, 503}
	for _, code := range allow {
		if !f.Allows(code) {
			t.Errorf("expected %d allowed", code)
		}
	}
	deny := []int{404, 400, 418}
	for _, code := range deny {
		if f.Allows(code) {
			t.Errorf("expected %d denied", code)
		}
	}
	// Empty spec allows everything.
	if !ParseStatusFilter("").Allows(404) {
		t.Error("empty spec should allow all")
	}
	// Unparsable spec fails open.
	if !ParseStatusFilter("garbage").Allows(404) {
		t.Error("unparsable spec should fail open")
	}
}

func TestFaviconHashDeterministic(t *testing.T) {
	if murmur3x86_32(nil) != 0 {
		t.Errorf("mmh3 of empty should be 0, got %d", murmur3x86_32(nil))
	}
	a := faviconHash([]byte("osint-forge favicon bytes"))
	b := faviconHash([]byte("osint-forge favicon bytes"))
	if a != b {
		t.Errorf("faviconHash not deterministic: %d != %d", a, b)
	}
	if faviconHash([]byte("different")) == a {
		t.Error("faviconHash should differ for different input")
	}
}
