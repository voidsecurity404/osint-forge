// Package report renders a scan graph into shareable JSON and HTML reports.
package report

import (
	"encoding/json"
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"osint-forge/internal/graph"
)

// isWebURL reports whether u is an http(s) URL — the only kind a report links.
func isWebURL(u string) bool {
	l := strings.ToLower(strings.TrimSpace(u))
	return strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://")
}

// JSON returns the graph snapshot as indented JSON.
func JSON(d graph.Delta) ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}

var sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "": 5, "unknown": 5, "none": 5}

func sevColor(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "#dc2626"
	case "high":
		return "#f97316"
	case "medium":
		return "#eab308"
	case "low":
		return "#84cc16"
	case "info":
		return "#38bdf8"
	}
	return "#64748b"
}

// HTML renders a standalone, styled HTML report.
func HTML(d graph.Delta, target string) string {
	byType := map[graph.NodeType][]*graph.Node{}
	for _, n := range d.Nodes {
		byType[n.Type] = append(byType[n.Type], n)
	}

	var b strings.Builder
	fmt.Fprintf(&b, `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>osint-forge report — %s</title><style>
:root{color-scheme:dark}
body{margin:0;background:#0b1120;color:#e2e8f0;font-family:Inter,system-ui,sans-serif;font-size:14px;line-height:1.5}
.wrap{max-width:1000px;margin:0 auto;padding:32px 20px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 12px;border-bottom:1px solid #1e293b;padding-bottom:6px}
.sub{color:#64748b;margin-bottom:24px}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0}
.card{background:#111a2e;border:1px solid #1e293b;border-radius:10px;padding:14px 18px;min-width:110px}
.card .n{font-size:26px;font-weight:700}.card .l{color:#64748b;font-size:12px;text-transform:uppercase}
table{width:100%%;border-collapse:collapse;margin:8px 0}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #1e293b;vertical-align:top}
th{color:#64748b;font-weight:500;font-size:12px;text-transform:uppercase}
.sev{display:inline-block;padding:2px 8px;border-radius:6px;font-size:11px;font-weight:700;color:#0b1120}
.pill{font-family:ui-monospace,monospace;font-size:12px}
.muted{color:#64748b}a{color:#38bdf8}
</style></head><body><div class="wrap">`, html.EscapeString(target))

	fmt.Fprintf(&b, `<h1>🕸️ osint-forge hisoboti</h1><div class="sub">Nishon: <b>%s</b> · %s</div>`,
		html.EscapeString(target), time.Now().Format("2006-01-02 15:04"))

	// Summary cards.
	b.WriteString(`<div class="cards">`)
	for _, t := range []graph.NodeType{graph.NodeSubdomain, graph.NodeIP, graph.NodePort, graph.NodeService, graph.NodeCVE, graph.NodeFinding, graph.NodeURL} {
		fmt.Fprintf(&b, `<div class="card"><div class="n">%d</div><div class="l">%s</div></div>`, len(byType[t]), t)
	}
	b.WriteString(`</div>`)

	// Findings (sorted by severity).
	writeSeverityTable(&b, "Xavfsizlik topilmalari (Findings)", byType[graph.NodeFinding], func(n *graph.Node) (string, string, string) {
		sev, _ := n.Props["severity"].(string)
		desc, _ := n.Props["description"].(string)
		return sev, n.Label, desc
	})

	// CVEs.
	writeCVETable(&b, byType[graph.NodeCVE])

	// Pentester notes / tags (from the UI).
	if noted := notedNodes(d); len(noted) > 0 {
		b.WriteString(`<h2>Pentester eslatmalari</h2><table><tr><th>Element</th><th>Teglar</th><th>Eslatma</th></tr>`)
		for _, n := range noted {
			tags, _ := n.Props["pentester_tags"].(string)
			note, _ := n.Props["pentester_note"].(string)
			fmt.Fprintf(&b, `<tr><td><span class="muted">%s</span><br>%s</td><td>%s</td><td style="white-space:pre-wrap">%s</td></tr>`,
				html.EscapeString(string(n.Type)), html.EscapeString(n.Label), html.EscapeString(tags), html.EscapeString(note))
		}
		b.WriteString(`</table>`)
	}

	// Hosts & subdomains.
	writeListTable(&b, "Subdomenlar", byType[graph.NodeSubdomain])
	writeListTable(&b, "IP manzillar", byType[graph.NodeIP])

	// Services / ports.
	if svcs := byType[graph.NodeService]; len(svcs) > 0 {
		b.WriteString(`<h2>Servislar</h2><table><tr><th>Servis</th><th>Mahsulot</th><th>Versiya</th></tr>`)
		for _, n := range svcs {
			prod, _ := n.Props["product"].(string)
			ver, _ := n.Props["version"].(string)
			fmt.Fprintf(&b, `<tr><td>%s</td><td>%s</td><td class="pill">%s</td></tr>`,
				html.EscapeString(n.Label), html.EscapeString(prod), html.EscapeString(ver))
		}
		b.WriteString(`</table>`)
	}

	// URLs.
	if urls := byType[graph.NodeURL]; len(urls) > 0 {
		b.WriteString(`<h2>URL / endpointlar</h2><table><tr><th>URL</th><th>Status</th></tr>`)
		sort.Slice(urls, func(i, j int) bool { return urls[i].ID < urls[j].ID })
		for _, n := range urls {
			u := strings.TrimPrefix(n.ID, "url:")
			status := ""
			if s, ok := n.Props["status"]; ok && s != nil {
				status = html.EscapeString(fmt.Sprint(s))
			}
			cell := html.EscapeString(u)
			if isWebURL(u) {
				cell = fmt.Sprintf(`<a href="%s" rel="noopener noreferrer">%s</a>`, html.EscapeString(u), cell)
			}
			fmt.Fprintf(&b, `<tr><td>%s</td><td class="pill">%s</td></tr>`, cell, status)
		}
		b.WriteString(`</table>`)
	}

	b.WriteString(`<p class="muted" style="margin-top:40px">osint-forge tomonidan yaratilgan. Faqat avtorizatsiya qilingan test uchun.</p></div></body></html>`)
	return b.String()
}

func writeSeverityTable(b *strings.Builder, title string, nodes []*graph.Node, get func(*graph.Node) (sev, name, desc string)) {
	if len(nodes) == 0 {
		return
	}
	sort.Slice(nodes, func(i, j int) bool {
		si, _, _ := get(nodes[i])
		sj, _, _ := get(nodes[j])
		return sevRank[strings.ToLower(si)] < sevRank[strings.ToLower(sj)]
	})
	fmt.Fprintf(b, `<h2>%s (%d)</h2><table><tr><th>Og'irlik</th><th>Nomi</th><th>Tavsif</th></tr>`, title, len(nodes))
	for _, n := range nodes {
		sev, name, desc := get(n)
		fmt.Fprintf(b, `<tr><td><span class="sev" style="background:%s">%s</span></td><td>%s</td><td class="muted">%s</td></tr>`,
			sevColor(sev), html.EscapeString(strings.ToUpper(sev)), html.EscapeString(name), html.EscapeString(desc))
	}
	b.WriteString(`</table>`)
}

func writeCVETable(b *strings.Builder, nodes []*graph.Node) {
	if len(nodes) == 0 {
		return
	}
	sort.Slice(nodes, func(i, j int) bool {
		si, _ := nodes[i].Props["severity"].(string)
		sj, _ := nodes[j].Props["severity"].(string)
		return sevRank[strings.ToLower(si)] < sevRank[strings.ToLower(sj)]
	})
	fmt.Fprintf(b, `<h2>CVE zaifliklari (%d)</h2><table><tr><th>CVE</th><th>Og'irlik</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Tavsif</th></tr>`, len(nodes))
	for _, n := range nodes {
		sev, _ := n.Props["severity"].(string)
		summary, _ := n.Props["summary"].(string)
		if len(summary) > 160 {
			summary = summary[:160] + "…"
		}
		score := html.EscapeString(scoreString(n.Props))
		epss := ""
		if e, ok := n.Props["epss"].(float64); ok {
			epss = fmt.Sprintf("%.1f%%", e*100)
		}
		kev := ""
		if ke, _ := n.Props["known_exploited"].(bool); ke {
			kev = "⚠️"
		}
		url, _ := n.Props["url"].(string)
		idCell := html.EscapeString(n.Label)
		if isWebURL(url) {
			idCell = fmt.Sprintf(`<a href="%s" class="pill" rel="noopener noreferrer">%s</a>`, html.EscapeString(url), idCell)
		}
		fmt.Fprintf(b, `<tr><td>%s</td><td><span class="sev" style="background:%s">%s</span></td><td class="pill">%s</td><td class="pill">%s</td><td>%s</td><td class="muted">%s</td></tr>`,
			idCell, sevColor(sev), html.EscapeString(strings.ToUpper(sev)),
			score, epss, kev, html.EscapeString(summary))
	}
	b.WriteString(`</table>`)
}

func writeListTable(b *strings.Builder, title string, nodes []*graph.Node) {
	if len(nodes) == 0 {
		return
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Label < nodes[j].Label })
	fmt.Fprintf(b, `<h2>%s (%d)</h2><table>`, title, len(nodes))
	for _, n := range nodes {
		fmt.Fprintf(b, `<tr><td class="pill">%s</td></tr>`, html.EscapeString(n.Label))
	}
	b.WriteString(`</table>`)
}

// notedNodes returns nodes the pentester tagged or annotated, vulnerable first.
func notedNodes(d graph.Delta) []*graph.Node {
	var out []*graph.Node
	for _, n := range d.Nodes {
		if _, ok := n.Props["pentester_tags"]; ok {
			out = append(out, n)
		} else if _, ok := n.Props["pentester_note"]; ok {
			out = append(out, n)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		ti, _ := out[i].Props["pentester_tags"].(string)
		tj, _ := out[j].Props["pentester_tags"].(string)
		vi, vj := strings.Contains(ti, "Zaif"), strings.Contains(tj, "Zaif")
		if vi != vj {
			return vi
		}
		return out[i].ID < out[j].ID
	})
	return out
}
