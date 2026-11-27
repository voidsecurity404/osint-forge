package graph

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// ExportVault writes the whole graph as an Obsidian vault under dir: one Markdown
// note per node, cross-linked with [[wikilinks]] so Obsidian's graph view renders
// the same relationships. It returns the number of notes written.
func (g *Graph) ExportVault(dir string) (int, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}

	// Assign a unique, filesystem-safe basename to each node.
	base := make(map[string]string, len(g.nodes))
	used := map[string]bool{}
	for id, n := range g.nodes {
		name := safeName(string(n.Type) + " - " + displayKey(n))
		candidate := name
		for i := 2; used[candidate]; i++ {
			candidate = fmt.Sprintf("%s (%d)", name, i)
		}
		used[candidate] = true
		base[id] = candidate
	}

	// Build adjacency: node id -> outgoing/incoming (relation, neighbor id).
	type link struct {
		rel      string
		neighbor string
		out      bool
	}
	adj := map[string][]link{}
	for _, e := range g.edges {
		adj[e.Source] = append(adj[e.Source], link{e.Label, e.Target, true})
		adj[e.Target] = append(adj[e.Target], link{e.Label, e.Source, false})
	}

	written := 0
	for id, n := range g.nodes {
		var b strings.Builder
		// YAML frontmatter for Obsidian properties.
		b.WriteString("---\n")
		fmt.Fprintf(&b, "type: %s\n", n.Type)
		fmt.Fprintf(&b, "label: %q\n", n.Label)
		b.WriteString("tags: [osint-forge, " + string(n.Type) + "]\n")
		b.WriteString("---\n\n")
		fmt.Fprintf(&b, "# %s\n\n", n.Label)

		keys := sortedPropKeys(n.Props)
		if len(keys) > 0 {
			b.WriteString("## Properties\n\n")
			for _, k := range keys {
				fmt.Fprintf(&b, "- **%s:** %v\n", k, n.Props[k])
			}
			b.WriteString("\n")
		}

		links := adj[id]
		if len(links) > 0 {
			sort.Slice(links, func(i, j int) bool { return links[i].rel < links[j].rel })
			b.WriteString("## Connections\n\n")
			for _, l := range links {
				arrow := "→"
				if !l.out {
					arrow = "←"
				}
				nb := g.nodes[l.neighbor]
				label := l.neighbor
				if nb != nil {
					label = nb.Label
				}
				fmt.Fprintf(&b, "- %s %s [[%s|%s]]\n", l.rel, arrow, base[l.neighbor], label)
			}
		}

		path := filepath.Join(dir, base[id]+".md")
		if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

// displayKey strips the type prefix from a node id for naming.
func displayKey(n *Node) string {
	if n.Label != "" {
		return n.Label
	}
	if i := strings.IndexByte(n.ID, ':'); i >= 0 {
		return n.ID[i+1:]
	}
	return n.ID
}

func sortedPropKeys(p map[string]any) []string {
	keys := make([]string, 0, len(p))
	for k := range p {
		if k == "root" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// safeName makes a string usable as a filename across platforms and as an
// Obsidian wikilink target ([ ] # ^ | have special meaning inside [[…]]).
func safeName(s string) string {
	repl := strings.NewReplacer(
		"/", "-", "\\", "-", ":", "-", "*", "-", "?", "-",
		"\"", "'", "<", "(", ">", ")", "|", "-", "\n", " ", "\t", " ", "\r", " ",
		"[", "(", "]", ")", "#", "-", "^", "-",
	)
	s = repl.Replace(s)
	s = strings.TrimSpace(s)
	// Truncate on a rune boundary: a byte cut could split a multi-byte
	// character and produce an invalid UTF-8 file name.
	if len(s) > 120 {
		cut := 120
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = strings.TrimSpace(s[:cut])
	}
	// Windows forbids names ending in a dot or space.
	s = strings.TrimRight(s, ". ")
	if s == "" {
		s = "node"
	}
	return s
}
