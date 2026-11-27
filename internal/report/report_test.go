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
	for _, want := range []string{"# Отчёт osint-forge", "CVE-2021-1", ".env exposed", "a.example.com"} {
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

// A CVE reported by Shodan has no CVSS score: reports printed "<nil>".
func TestNoNilScores(t *testing.T) {
	d := sampleDelta()
	d.Nodes = append(d.Nodes, &graph.Node{ID: "cve:CVE-2020-9", Type: graph.NodeCVE, Label: "CVE-2020-9",
		Props: map[string]any{"source": "shodan"}})
	md := Markdown(d, "example.com")
	csv, _ := CSV(d)
	for name, out := range map[string]string{"markdown": md, "csv": string(csv)} {
		if strings.Contains(out, "<nil>") {
			t.Errorf("%s contains <nil>:\n%s", name, out)
		}
	}
}

// GitHub code scanning rejects SARIF results without a location.
func TestSARIFResultsHaveLocations(t *testing.T) {
	d := sampleDelta()
	d.Nodes = append(d.Nodes, &graph.Node{ID: "url:https://a.example.com", Type: graph.NodeURL, Label: "https://a.example.com"})
	d.Edges = append(d.Edges, &graph.Edge{ID: "x", Source: "url:https://a.example.com", Target: "finding:env", Label: "finding"})
	data, err := SARIF(d, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	for _, r := range doc.Runs[0].Results {
		if len(r.Locations) == 0 || r.Locations[0].PhysicalLocation.ArtifactLocation.URI == "" {
			t.Fatalf("result %s has no location", r.RuleID)
		}
		if r.RuleID == "env" && r.Locations[0].PhysicalLocation.ArtifactLocation.URI != "https://a.example.com" {
			t.Errorf("finding location = %q, want the affected URL", r.Locations[0].PhysicalLocation.ArtifactLocation.URI)
		}
	}
}

func TestHTMLNeverLinksNonHTTP(t *testing.T) {
	d := graph.Delta{Nodes: []*graph.Node{{ID: "url:javascript:alert(1)", Type: graph.NodeURL, Label: "x"}}}
	if out := HTML(d, "example.com"); strings.Contains(out, `href="javascript:`) {
		t.Fatal("HTML report links a javascript: URL")
	}
}
