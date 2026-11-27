package notes

import (
	"testing"

	"osint-forge/internal/graph"
)

func TestSetLoadAnnotate(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	n, err := Set("example.com", "url:https://example.com/admin", Note{Tags: []string{"checked", "vuln", "bogus", "vuln"}, Text: "  403 bypass ishladi  "})
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Tags) != 2 || n.Tags[0] != "vuln" || n.Text != "403 bypass ishladi" {
		t.Fatalf("normalisation failed: %+v", n)
	}
	all, _ := Load("example.com")
	if len(all) != 1 {
		t.Fatalf("load: %v", all)
	}
	d := Annotate(graph.Delta{Nodes: []*graph.Node{{ID: "url:https://example.com/admin", Props: map[string]any{"status": 403}}, {ID: "x"}}}, all)
	if d.Nodes[0].Props["pentester_tags"] != "Уязвимо, Проверено" || d.Nodes[0].Props["pentester_note"] == nil {
		t.Fatalf("annotate: %+v", d.Nodes[0].Props)
	}
	// clearing removes it
	if _, err := Set("example.com", "url:https://example.com/admin", Note{}); err != nil {
		t.Fatal(err)
	}
	if all, _ := Load("example.com"); len(all) != 0 {
		t.Fatalf("not removed: %v", all)
	}
}
