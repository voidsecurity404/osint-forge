package scan

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// scopedCollector builds a collector for example.com with the strict scope on,
// where www.example.com resolved to 93.184.216.34 (in scope) and the MX host
// resolved to a Google IP (out of scope).
func scopedCollector() *core.Collector {
	t := core.ParseTarget("example.com")
	c := core.NewCollector(t, graph.New(), nil)
	c.SetScope(core.NewScope(t, true, nil))
	for _, ip := range []string{"93.184.216.34", "142.250.1.27", "2606:2800:220:1::248"} {
		c.Node(graph.NodeIP, ip, ip, nil)
	}
	c.MarkResolved("www.example.com", "93.184.216.34")
	c.MarkResolved("www.example.com", "2606:2800:220:1::248")
	c.MarkResolved("aspmx.l.google.com", "142.250.1.27")
	return c
}

func TestScopedIPsSkipsOutOfScope(t *testing.T) {
	v4, v6, skipped := scopedIPs(scopedCollector())
	if !reflect.DeepEqual(v4, []string{"93.184.216.34"}) {
		t.Errorf("v4 = %v", v4)
	}
	if !reflect.DeepEqual(v6, []string{"2606:2800:220:1::248"}) {
		t.Errorf("v6 = %v", v6)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1 (the MX IP)", skipped)
	}
}

// The TLS source used to strip "https://" by hand: "https://x.com/admin" became
// the host "x.com/admin" and "https://1.2.3.4:8443" was dialled as
// "[1.2.3.4:8443]:443", so non-standard ports were never checked.
func TestTLSEndpoint(t *testing.T) {
	cases := map[string]string{
		"https://example.com":          "example.com:443",
		"https://example.com/admin":    "example.com:443",
		"https://1.2.3.4:8443":         "1.2.3.4:8443",
		"https://[2001:db8::1]:9443/x": "[2001:db8::1]:9443",
		"https://[2001:db8::1]":        "[2001:db8::1]:443",
	}
	for in, want := range cases {
		host, port, ok := tlsEndpoint(in)
		if got := joinHostPort(host, port); !ok || got != want {
			t.Errorf("tlsEndpoint(%q) = %q (ok=%v), want %q", in, got, ok, want)
		}
	}
	if _, _, ok := tlsEndpoint("http://example.com"); ok {
		t.Error("plain http must not be treated as a TLS endpoint")
	}
}

// nmap silently drops IPv6 targets unless -6 is given ("you have to use the -6
// option"), and refuses to mix families — so each family gets its own run.
func TestNmapArgsPerFamily(t *testing.T) {
	a4 := nmapArgs("-sV -T4", []string{"1.2.3.4"}, false)
	if slices.Contains(a4, "-6") || a4[len(a4)-1] != "1.2.3.4" {
		t.Errorf("v4 args = %v", a4)
	}
	a6 := nmapArgs("", []string{"2001:db8::1"}, true)
	if !slices.Contains(a6, "-6") || !slices.Contains(a6, "-sV") {
		t.Errorf("v6 args = %v (want -6 and the default -sV)", a6)
	}
	// A user-supplied -6 must not be duplicated or leak into the v4 run.
	a4u := nmapArgs("-sV -6", []string{"1.2.3.4"}, false)
	if slices.Contains(a4u, "-6") {
		t.Errorf("v4 run must not carry -6: %v", a4u)
	}
}

// A redirect from an in-scope host to an out-of-scope one must not be
// followed: the http client used to chase up to 5 redirects to ANY host.
func TestProbeDoesNotFollowRedirectOutOfScope(t *testing.T) {
	var evilHits atomic.Int32
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		evilHits.Add(1)
	}))
	defer evil.Close()
	_, evilPort, _ := net.SplitHostPort(strings.TrimPrefix(evil.URL, "http://"))
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// "localhost" is not in the scope of target 127.0.0.1.
		http.Redirect(w, r, "http://localhost:"+evilPort+"/landing", http.StatusFound)
	}))
	defer good.Close()

	tgt := core.ParseTarget("127.0.0.1")
	c := core.NewCollector(tgt, graph.New(), nil)
	c.SetScope(core.NewScope(tgt, true, nil))
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(good.URL, "http://"))
	h := HTTPSource{Cfg: config.Default()}
	h.filter = ParseStatusFilter("")
	h.probe(withScope(context.Background(), c), c, "127.0.0.1", port, graph.NodeID(graph.NodeIP, "127.0.0.1"), "http")

	if n := evilHits.Load(); n != 0 {
		t.Fatalf("out-of-scope redirect target was requested %d time(s)", n)
	}
	n, ok := c.GetNode(graph.NodeURL, good.URL)
	if !ok || n.Props["status"] != 302 {
		t.Fatalf("expected the 302 itself to be recorded, got %+v", n)
	}
}

func TestChromeKeepsSandboxUnlessRoot(t *testing.T) {
	if slices.Contains(chromeArgs("https://x", "/tmp/o.png", false), "--no-sandbox") {
		t.Error("renderer sandbox disabled for a normal user")
	}
	if !slices.Contains(chromeArgs("https://x", "/tmp/o.png", true), "--no-sandbox") {
		t.Error("root needs --no-sandbox or Chromium refuses to start")
	}
}

// Sitemap <loc> values are XML text: "&amp;" must become "&", or the URL
// "search?q=x&amp;redirect=/home" hides the redirect parameter ("amp;redirect").
func TestSitemapLocIsXMLUnescaped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<urlset><url><loc> http://127.0.0.1/search?q=x&amp;redirect=/home </loc></url></urlset>`))
	}))
	defer srv.Close()
	tgt := core.ParseTarget("127.0.0.1")
	c := core.NewCollector(tgt, graph.New(), nil)
	c.SetScope(core.NewScope(tgt, true, nil))
	RobotsSource{Cfg: config.Default()}.importSitemap(context.Background(), c, srv.URL, srv.URL+"/sitemap.xml")
	if _, ok := c.GetNode(graph.NodeURL, "http://127.0.0.1/search?q=x&redirect=/home"); !ok {
		t.Fatalf("unescaped sitemap URL missing; have %v", c.ListByType(graph.NodeURL))
	}
}
