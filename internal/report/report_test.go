package report

import (
	"encoding/json"
	"strings"
	"testing"

	"osint-forge/internal/graph"
)

func sampleDelta() graph.Delta {
	return graph.Delta{Nodes: []*graph.Node{
		{ID: "finding:env", Type: graph.NodeFinding, Label: ".env exposed",
			Props: map[string]any{"severity": "critical", "description": "secrets leaked"}},
		{ID: "cve:CVE-2021-1", Type: graph.NodeCVE, Label: "CVE-2021-1",
			Props: map[string]any{"severity": "HIGH", "score": 7.5, "summary": "nginx overflow", "epss": 0.42, "known_exploited": true}},
		{ID: "subdomain:a.example.com", Type: graph.NodeSubdomain, Label: "a.example.com"},
		{ID: "ip:1.1.1.1", Type: graph.NodeIP, Label: "1.1.1.1"},
	}}
}

func TestMarkdown(t *testing.T) {
	md := Markdown(sampleDelta(), "example.com")
	for _, want := range []string{"# osint-forge", "CVE-2021-1", ".env exposed", "a.example.com"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}

func TestCSV(t *testing.T) {
	data, err := CSV(sampleDelta())
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, "type,severity,id") || !strings.Contains(s, "CVE-2021-1") {
		t.Errorf("unexpected CSV:\n%s", s)
	}
}

func TestSARIFValid(t *testing.T) {
	data, err := SARIF(sampleDelta(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("expected SARIF 2.1.0, got %v", doc["version"])
	}
	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("expected one run, got %v", doc["runs"])
	}
	results := runs[0].(map[string]any)["results"].([]any)
	if len(results) != 2 {
		t.Errorf("expected 2 results (finding + cve), got %d", len(results))
	}
}
