package recon

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// Shodan puts the API key in the query string. A failed request used to put
// the whole URL — key included — into the error, which is shown in the UI log.
func TestGetJSONErrorRedactsSecrets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	defer srv.Close()

	err := getJSON(context.Background(), config.Default(), srv.URL+"/shodan/host/1.2.3.4?key=SUPERSECRET", nil, &struct{}{})
	if err == nil {
		t.Fatal("expected an error for HTTP 401")
	}
	if strings.Contains(err.Error(), "SUPERSECRET") {
		t.Fatalf("API key leaked into error: %v", err)
	}
	if !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("error lost the status: %v", err)
	}
}

func TestCymruOriginMalformed(t *testing.T) {
	// "| 1.2.3.0/24 | US" has an empty ASN field; strings.Fields(...)[0] used
	// to panic on it, killing the whole ASN source.
	for _, txt := range []string{" | 1.2.3.0/24 | US | arin | 2000-01-01", "|", ""} {
		asn, _, _, ok := parseCymruOrigin(txt)
		if ok || asn != "" {
			t.Errorf("parseCymruOrigin(%q) = %q, %v; want no result", txt, asn, ok)
		}
	}
	asn, prefix, cc, ok := parseCymruOrigin("15169 | 8.8.8.0/24 | US | arin | 1992-12-01")
	if !ok || asn != "15169" || prefix != "8.8.8.0/24" || cc != "US" {
		t.Errorf("good line parsed wrong: %q %q %q %v", asn, prefix, cc, ok)
	}
}

func TestZoneHostInDomain(t *testing.T) {
	for host, want := range map[string]bool{
		"example.com.":         true,
		"www.example.com.":     true,
		"evilexample.com.":     false, // suffix without a dot boundary
		"example.com.evil.net": false,
	} {
		if got := inDomain(strings.TrimSuffix(host, "."), "example.com"); got != want {
			t.Errorf("inDomain(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestDMARCTag(t *testing.T) {
	rec := "v=DMARC1; p=reject; sp=none; rua=mailto:x@example.com"
	if got := dmarcTag(rec, "p"); got != "reject" {
		t.Errorf("p = %q, want reject (sp=none must not be read as p=none)", got)
	}
	if got := dmarcTag("v=DMARC1;p=None", "p"); got != "none" {
		t.Errorf("p = %q, want none", got)
	}
}

func TestDMARCFallsBackToOrganizationalDomain(t *testing.T) {
	if got := orgDomain("api.eu.example.co.uk"); got != "example.co.uk" {
		t.Errorf("orgDomain = %q", got)
	}
	if got := orgDomain("example.com"); got != "example.com" {
		t.Errorf("orgDomain(root) = %q", got)
	}
}

// crt.sh responses for big domains can exceed the size cap; a truncated body
// must still yield the entries that were read instead of failing completely.
func TestDecodeCrtShPartial(t *testing.T) {
	body := `[{"name_value":"a.example.com"},{"name_value":"b.example.com\n*.c.example.com"},{"name_va`
	entries, err := decodeCrtSh(strings.NewReader(body))
	if len(entries) != 2 {
		t.Fatalf("got %d entries (err=%v), want the 2 complete ones", len(entries), err)
	}
	if err == nil {
		t.Error("truncation should still be reported")
	}
}

func TestOTXDoesNotDuplicateRoot(t *testing.T) {
	g := graph.New()
	c := core.NewCollector(core.ParseTarget("example.com"), g, nil)
	c.Node(graph.NodeDomain, "example.com", "example.com", nil)
	c.Node(graph.NodeSubdomain, "example.com", "example.com", map[string]any{"via": "otx"})
	if n, _ := g.Counts(); n != 1 {
		t.Fatalf("root duplicated as subdomain: %d nodes", n)
	}
}

func TestCrtShRetryable(t *testing.T) {
	for msg, want := range map[string]bool{
		"HTTP 404": true, "HTTP 503": true, "HTTP 429": true,
		"read tcp: i/o timeout": true, "unexpected EOF": true,
		"HTTP 400": false, "invalid character": false,
	} {
		if got := retryable(errors.New(msg)); got != want {
			t.Errorf("retryable(%q) = %v, want %v", msg, got, want)
		}
	}
}
