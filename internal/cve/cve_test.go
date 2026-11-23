package cve

import "testing"

func TestToCPE23(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		ok     bool
		pinned bool
	}{
		{"cpe:/a:igor_sysoev:nginx:1.18.0", "cpe:2.3:a:igor_sysoev:nginx:1.18.0:*:*:*:*:*:*:*", true, true},
		{"cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*", "cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*", true, true},
		{"cpe:/a:apache:http_server", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", true, false},
		{"not-a-cpe", "", false, false},
		{"", "", false, false},
	}
	for _, c := range cases {
		got, ok := toCPE23(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("toCPE23(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
		if ok && hasVersion(got) != c.pinned {
			t.Errorf("hasVersion(%q) = %v, want %v", got, hasVersion(got), c.pinned)
		}
	}
}

func TestBuildQuery(t *testing.T) {
	q, isCPE := buildQuery("cpe:/a:igor_sysoev:nginx:1.18.0", "nginx", "1.18.0")
	if !isCPE || q == "" {
		t.Errorf("expected CPE query, got (%q,%v)", q, isCPE)
	}
	q, isCPE = buildQuery("", "nginx", "1.18.0")
	if isCPE || q != "nginx 1.18.0" {
		t.Errorf("expected keyword query, got (%q,%v)", q, isCPE)
	}
	// Product without version is too weak to query.
	if q, _ := buildQuery("", "nginx", ""); q != "" {
		t.Errorf("expected empty query for versionless product, got %q", q)
	}
}

func TestFilterByProduct(t *testing.T) {
	in := []Match{
		{ID: "CVE-1", Summary: "A flaw in nginx allows RCE"},
		{ID: "CVE-2", Summary: "Unrelated Apache issue"},
		{ID: "CVE-3", Summary: "nginx buffer overflow"},
	}
	out := filterByProduct(in, "nginx 1.18.0")
	if len(out) != 2 {
		t.Fatalf("expected 2 nginx matches, got %d", len(out))
	}
	for _, m := range out {
		if m.ID == "CVE-2" {
			t.Error("Apache CVE should have been filtered out")
		}
	}
}

func TestLongestToken(t *testing.T) {
	cases := map[string]string{
		"nginx 1.18.0":  "nginx",
		"Microsoft-IIS": "microsoft",
		"PHP 7.4":       "php",
		"a b":           "",
	}
	for in, want := range cases {
		if got := longestToken(in); got != want {
			t.Errorf("longestToken(%q) = %q, want %q", in, got, want)
		}
	}
}
