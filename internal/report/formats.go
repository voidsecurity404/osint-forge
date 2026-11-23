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
			score := fmt.Sprint(n.Props["score"])
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
			_ = w.Write([]string{"cve", strings.ToLower(sev), n.Label, n.Label, fmt.Sprint(n.Props["score"]), epss, kev, summary})
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}

// SARIF renders findings and CVEs as a SARIF 2.1.0 log so results can be
// ingested by CI/code-scanning dashboards.
func SARIF(d graph.Delta, target string) ([]byte, error) {
	type sarifMsg struct {
		Text string `json:"text"`
	}
	type sarifRule struct {
		ID               string   `json:"id"`
		Name             string   `json:"name"`
		ShortDescription sarifMsg `json:"shortDescription"`
	}
	type sarifResult struct {
		RuleID  string   `json:"ruleId"`
		Level   string   `json:"level"`
		Message sarifMsg `json:"message"`
	}
	rules := map[string]sarifRule{}
	var results []sarifResult
	add := func(ruleID, name, level, text string) {
		if _, ok := rules[ruleID]; !ok {
			rules[ruleID] = sarifRule{ID: ruleID, Name: name, ShortDescription: sarifMsg{Text: name}}
		}
		results = append(results, sarifResult{RuleID: ruleID, Level: level, Message: sarifMsg{Text: text}})
	}
	for _, n := range d.Nodes {
		switch n.Type {
		case graph.NodeFinding:
			sev, _ := n.Props["severity"].(string)
			desc, _ := n.Props["description"].(string)
			add("finding/"+severitySlug(sev), n.Label, sarifLevel(sev), n.Label+": "+desc)
		case graph.NodeCVE:
			sev, _ := n.Props["severity"].(string)
			summary, _ := n.Props["summary"].(string)
			add(n.Label, n.Label, sarifLevel(sev), n.Label+": "+summary)
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
				"informationUri": "https://github.com/osint-forge",
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

func severitySlug(sev string) string {
	sev = strings.ToLower(strings.TrimSpace(sev))
	if sev == "" {
		return "info"
	}
	return sev
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
