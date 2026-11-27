package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"osint-forge/internal/graph"
)

// Markdown renders the scan as a Markdown report (for wikis, tickets, PRs).
func Markdown(d graph.Delta, target string) string {
	byType := groupByType(d)
	var b strings.Builder
	fmt.Fprintf(&b, "# osint-forge hisoboti — %s\n\n", target)
	fmt.Fprintf(&b, "_%s · %d node, %d edge_\n\n", time.Now().Format("2006-01-02 15:04"), len(d.Nodes), len(d.Edges))

	b.WriteString("## Xulosa\n\n| Tur | Soni |\n|---|---|\n")
	for _, t := range []graph.NodeType{graph.NodeSubdomain, graph.NodeIP, graph.NodePort, graph.NodeService, graph.NodeCVE, graph.NodeFinding, graph.NodeURL} {
		fmt.Fprintf(&b, "| %s | %d |\n", t, len(byType[t]))
	}
	b.WriteString("\n")

	if f := byType[graph.NodeFinding]; len(f) > 0 {
		sortBySeverity(f, func(n *graph.Node) string { s, _ := n.Props["severity"].(string); return s })
		b.WriteString("## Topilmalar\n\n| Og'irlik | Nomi | Tavsif |\n|---|---|---|\n")
		for _, n := range f {
			sev, _ := n.Props["severity"].(string)
			desc, _ := n.Props["description"].(string)
			fmt.Fprintf(&b, "| %s | %s | %s |\n", strings.ToUpper(sev), mdCell(n.Label), mdCell(desc))
		}
		b.WriteString("\n")
	}

	if cves := byType[graph.NodeCVE]; len(cves) > 0 {
		sortBySeverity(cves, func(n *graph.Node) string { s, _ := n.Props["severity"].(string); return s })
		b.WriteString("## CVE zaifliklari\n\n| CVE | Og'irlik | CVSS | EPSS | KEV |\n|---|---|---|---|---|\n")
		for _, n := range cves {
			sev, _ := n.Props["severity"].(string)
			score := scoreString(n.Props)
			epss := ""
			if e, ok := n.Props["epss"].(float64); ok {
				epss = fmt.Sprintf("%.1f%%", e*100)
			}
			kev := ""
			if ke, _ := n.Props["known_exploited"].(bool); ke {
				kev = "⚠️"
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", n.Label, strings.ToUpper(sev), score, epss, kev)
		}
		b.WriteString("\n")
	}

	if noted := notedNodes(d); len(noted) > 0 {
		b.WriteString("## Pentester eslatmalari\n\n| Element | Teglar | Eslatma |\n|---|---|---|\n")
		for _, n := range noted {
			tags, _ := n.Props["pentester_tags"].(string)
			note, _ := n.Props["pentester_note"].(string)
			fmt.Fprintf(&b, "| %s `%s` | %s | %s |\n", mdCell(n.Label), n.Type, mdCell(tags), mdCell(note))
		}
		b.WriteString("\n")
	}

	writeMDList(&b, "Subdomenlar", byType[graph.NodeSubdomain])
	writeMDList(&b, "IP manzillar", byType[graph.NodeIP])
	return b.String()
}

func writeMDList(b *strings.Builder, title string, nodes []*graph.Node) {
	if len(nodes) == 0 {
		return
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Label < nodes[j].Label })
	fmt.Fprintf(b, "## %s\n\n", title)
	for _, n := range nodes {
		fmt.Fprintf(b, "- `%s`\n", n.Label)
	}
	b.WriteString("\n")
}

// CSV returns a flat findings+CVE CSV, one row per security-relevant item.
func CSV(d graph.Delta) ([]byte, error) {
	var sb strings.Builder
	w := csv.NewWriter(&sb)
	_ = w.Write([]string{"type", "severity", "id", "title", "cvss", "epss", "kev", "detail"})
	for _, n := range d.Nodes {
		switch n.Type {
		case graph.NodeFinding:
			sev, _ := n.Props["severity"].(string)
			desc, _ := n.Props["description"].(string)
			_ = w.Write([]string{"finding", sev, n.ID, n.Label, "", "", "", desc})
		case graph.NodeCVE:
			sev, _ := n.Props["severity"].(string)
			summary, _ := n.Props["summary"].(string)
			epss := ""
			if e, ok := n.Props["epss"].(float64); ok {
				epss = fmt.Sprintf("%.4f", e)
			}
			kev := ""
			if ke, _ := n.Props["known_exploited"].(bool); ke {
				kev = "true"
			}
			_ = w.Write([]string{"cve", strings.ToLower(sev), n.Label, n.Label, scoreString(n.Props), epss, kev, summary})
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}

// scoreString formats a CVSS score prop, or "" when there is none (Shodan
// reports CVE ids without scores — fmt.Sprint(nil) printed "<nil>").
func scoreString(props map[string]any) string {
	v, ok := props["score"]
	if !ok || v == nil {
		return ""
	}
	if f, ok := v.(float64); ok && f == 0 {
		return ""
	}
	return fmt.Sprint(v)
}

// findingKind is the stable kind of a finding id: "finding:spf-missing:x.com"
// → "spf-missing"; template/nuclei/js-secret findings keep their sub-kind
// ("check/adminer"), so each SARIF rule describes one kind of issue.
func findingKind(id string) string {
	parts := strings.SplitN(strings.TrimPrefix(id, "finding:"), ":", 3)
	switch {
	case len(parts) >= 2 && (parts[0] == "check" || parts[0] == "nuclei" || parts[0] == "js-secret"):
		return parts[0] + "/" + parts[1]
	case parts[0] != "":
		return parts[0]
	}
	return "finding"
}

// affected returns, for every finding/CVE node, a location string for the
// entity it is attached to: the URL for url nodes, the host for host nodes,
// ip:port for services.
func affected(d graph.Delta) map[string]string {
	byID := make(map[string]*graph.Node, len(d.Nodes))
	for _, n := range d.Nodes {
		byID[n.ID] = n
	}
	out := map[string]string{}
	for _, e := range d.Edges {
		if _, done := out[e.Target]; done {
			continue
		}
		src := byID[e.Source]
		if src == nil {
			continue
		}
		key := strings.SplitN(src.ID, ":", 2)
		if len(key) != 2 {
			continue
		}
		switch src.Type {
		case graph.NodeURL, graph.NodeDomain, graph.NodeSubdomain, graph.NodeIP, graph.NodeService, graph.NodeEmail:
			out[e.Target] = key[1]
		}
	}
	return out
}

// SARIF renders findings and CVEs as a SARIF 2.1.0 log so results can be
// ingested by CI/code-scanning dashboards (every result carries a location —
// GitHub code scanning rejects results without one).
func SARIF(d graph.Delta, target string) ([]byte, error) {
	type sarifMsg struct {
		Text string `json:"text"`
	}
	type sarifRule struct {
		ID               string         `json:"id"`
		Name             string         `json:"name"`
		ShortDescription sarifMsg       `json:"shortDescription"`
		Properties       map[string]any `json:"properties,omitempty"`
	}
	type sarifArtifact struct {
		URI string `json:"uri"`
	}
	type sarifPhysical struct {
		ArtifactLocation sarifArtifact `json:"artifactLocation"`
	}
	type sarifLocation struct {
		PhysicalLocation sarifPhysical `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID    string          `json:"ruleId"`
		Level     string          `json:"level"`
		Message   sarifMsg        `json:"message"`
		Locations []sarifLocation `json:"locations"`
	}
	where := affected(d)
	rules := map[string]sarifRule{}
	var results []sarifResult
	add := func(ruleID, name, level, text, nodeID string, props map[string]any) {
		if _, ok := rules[ruleID]; !ok {
			rules[ruleID] = sarifRule{ID: ruleID, Name: ruleID, ShortDescription: sarifMsg{Text: name}, Properties: props}
		}
		loc := where[nodeID]
		if loc == "" {
			loc = target
		}
		if loc == "" {
			loc = "unknown"
		}
		results = append(results, sarifResult{RuleID: ruleID, Level: level, Message: sarifMsg{Text: text},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: loc}}}}})
	}
	for _, n := range d.Nodes {
		switch n.Type {
		case graph.NodeFinding:
			sev, _ := n.Props["severity"].(string)
			desc, _ := n.Props["description"].(string)
			add(findingKind(n.ID), n.Label, sarifLevel(sev), n.Label+": "+desc, n.ID, nil)
		case graph.NodeCVE:
			sev, _ := n.Props["severity"].(string)
			summary, _ := n.Props["summary"].(string)
			var props map[string]any
			if s := scoreString(n.Props); s != "" {
				props = map[string]any{"security-severity": s} // GitHub severity ranking
			}
			add(n.Label, n.Label, sarifLevel(sev), n.Label+": "+summary, n.ID, props)
		}
	}
	ruleList := make([]sarifRule, 0, len(rules))
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })

	doc := map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name":           "osint-forge",
				"informationUri": "https://github.com/voidsecurity404/osint-forge",
				"rules":          ruleList,
			}},
			"results": results,
			"properties": map[string]any{
				"target":  target,
				"scanned": time.Now().UTC().Format(time.RFC3339),
			},
		}},
	}
	return json.MarshalIndent(doc, "", "  ")
}

func sarifLevel(sev string) string {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func groupByType(d graph.Delta) map[graph.NodeType][]*graph.Node {
	m := map[graph.NodeType][]*graph.Node{}
	for _, n := range d.Nodes {
		m[n.Type] = append(m[n.Type], n)
	}
	return m
}

func sortBySeverity(nodes []*graph.Node, sev func(*graph.Node) string) {
	sort.SliceStable(nodes, func(i, j int) bool {
		return sevRank[strings.ToLower(sev(nodes[i]))] < sevRank[strings.ToLower(sev(nodes[j]))]
	})
}

// mdCell makes a string safe for a single Markdown table cell.
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}
