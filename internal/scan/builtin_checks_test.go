package scan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

func TestTemplatesLoad(t *testing.T) {
	ts := loadTemplates()
	if len(ts) < 5 {
		t.Fatalf("expected embedded templates, got %d", len(ts))
	}
	for _, x := range ts {
		if x.ID == "" || x.Path == "" || len(x.Matchers) == 0 {
			t.Fatalf("bad template: %+v", x)
		}
		if len(x.compiledRe) != len(x.Matchers) {
			t.Fatalf("compiledRe not sized for %s", x.ID)
		}
	}
}

func TestMatchTemplate(t *testing.T) {
	tmpl := checkTemplate{
		Condition: "and",
		Matchers: []checkMatcher{
			{Type: "status", Status: []int{200}},
			{Type: "word", Words: []string{"PHP Version"}, Part: "body"},
		},
	}
	tmpl.compiledRe = make([][]*regexpRe, len(tmpl.Matchers))
	if !matchTemplate(tmpl, 200, http.Header{}, []byte("PHP Version 8.1")) {
		t.Error("should match on status+word")
	}
	if matchTemplate(tmpl, 404, http.Header{}, []byte("PHP Version 8.1")) {
		t.Error("wrong status must fail AND")
	}
	if matchTemplate(tmpl, 200, http.Header{}, []byte("nothing here")) {
		t.Error("missing word must fail AND")
	}

	// OR condition.
	orT := checkTemplate{
		Condition: "or",
		Matchers: []checkMatcher{
			{Type: "word", Words: []string{"zzz"}, Part: "body"},
			{Type: "word", Words: []string{"swagger"}, Part: "body"},
		},
	}
	orT.compiledRe = make([][]*regexpRe, len(orT.Matchers))
	if !matchTemplate(orT, 200, http.Header{}, []byte("openapi swagger 2.0")) {
		t.Error("OR should match when one word present")
	}

	// header word matcher
	ht := checkTemplate{
		Condition: "and",
		Matchers:  []checkMatcher{{Type: "word", Words: []string{"nginx"}, Part: "header"}},
	}
	ht.compiledRe = make([][]*regexpRe, 1)
	h := http.Header{}
	h.Set("Server", "nginx/1.25")
	if !matchTemplate(ht, 200, h, []byte("")) {
		t.Error("header matcher should see Server: nginx")
	}
}

// runChecks runs the built-in checks against one live base URL served by h and
// returns the finding node ids.
func runChecks(t *testing.T, h http.Handler) []string {
	t.Helper()
	srv := httptest.NewServer(h)
	defer srv.Close()
	tgt := core.ParseTarget("127.0.0.1")
	c := core.NewCollector(tgt, graph.New(), nil)
	c.SetScope(core.NewScope(tgt, true, nil))
	c.Node(graph.NodeURL, srv.URL, srv.URL, map[string]any{"status": 200})
	cfg := config.Default()
	if err := (BuiltinChecksSource{Cfg: cfg}).Run(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	return c.ListByType(graph.NodeFinding)
}

// A catch-all server answers 200 for every path and echoes the path in the
// page ("Sahifa /debug/pprof/ ..."). That used to produce findings such as
// "Go pprof oshkor" for paths that do not exist.
func TestBuiltinChecksIgnoreCatchAllEcho(t *testing.T) {
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><title>Shop</title><body>Sahifa %s ochilmoqda… goroutine graphql swagger</body></html>", r.URL.Path)
	})
	if f := runChecks(t, echo); len(f) != 0 {
		t.Fatalf("catch-all host produced findings: %v", f)
	}
}

func TestBuiltinChecksStillFindRealExposure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/phpinfo.php", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><title>phpinfo()</title>"+strings.Repeat("<tr><td>PHP Version</td><td>8.1.2</td></tr>", 200)+"</html>")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body>Sahifa %s</body></html>", r.URL.Path) // catch-all too
	})
	found := runChecks(t, mux)
	if len(found) != 1 || !strings.Contains(found[0], "phpinfo") {
		t.Fatalf("want exactly the phpinfo finding, got %v", found)
	}
}
