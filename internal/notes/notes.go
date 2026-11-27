// Package notes stores the pentester's own annotations on graph nodes — tags
// (vulnerable / checked / interesting / false positive) and free text — per
// target, so they survive rescans and show up in reports.
package notes

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"osint-forge/internal/config"
	"osint-forge/internal/graph"
)

// Allowed tags and their human labels (Uzbek), in display order.
var Tags = []struct{ Key, Label string }{
	{"vuln", "Zaif"},
	{"checked", "Tekshirildi"},
	{"interesting", "Qiziq"},
	{"fp", "False positive"},
}

func validTag(t string) bool {
	for _, x := range Tags {
		if x.Key == t {
			return true
		}
	}
	return false
}

// TagLabel returns the human label of a tag key.
func TagLabel(t string) string {
	for _, x := range Tags {
		if x.Key == t {
			return x.Label
		}
	}
	return t
}

// Note is one node's annotation.
type Note struct {
	Tags    []string  `json:"tags,omitempty"`
	Text    string    `json:"text,omitempty"`
	Updated time.Time `json:"updated"`
}

// Empty reports whether the note carries nothing.
func (n Note) Empty() bool { return len(n.Tags) == 0 && strings.TrimSpace(n.Text) == "" }

var mu sync.Mutex // serialises read-modify-write of the per-target files

func file(target string) (string, error) {
	dir, err := config.Dir()
	if err != nil {
		return "", err
	}
	dir = filepath.Join(dir, "notes")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(dir, sanitize(target)+".json"), nil
}

// Load returns all notes of a target, keyed by node id.
func Load(target string) (map[string]Note, error) {
	mu.Lock()
	defer mu.Unlock()
	return load(target)
}

func load(target string) (map[string]Note, error) {
	out := map[string]Note{}
	p, err := file(target)
	if err != nil {
		return out, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return out, err
	}
	err = json.Unmarshal(b, &out)
	return out, err
}

// Set stores (or, when empty, removes) the note of one node.
func Set(target, nodeID string, n Note) (Note, error) {
	if strings.TrimSpace(target) == "" || nodeID == "" {
		return Note{}, errors.New("target and node are required")
	}
	if len(n.Text) > 20000 {
		return Note{}, errors.New("note too long")
	}
	seen := map[string]bool{}
	var tags []string
	for _, t := range n.Tags {
		if validTag(t) && !seen[t] {
			seen[t] = true
			tags = append(tags, t)
		}
	}
	sort.Slice(tags, func(i, j int) bool { return tagOrder(tags[i]) < tagOrder(tags[j]) })
	n.Tags = tags
	n.Text = strings.TrimSpace(n.Text)
	n.Updated = time.Now()

	mu.Lock()
	defer mu.Unlock()
	all, err := load(target)
	if err != nil {
		return Note{}, err
	}
	if n.Empty() {
		delete(all, nodeID)
	} else {
		all[nodeID] = n
	}
	p, err := file(target)
	if err != nil {
		return Note{}, err
	}
	b, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return Note{}, err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return Note{}, err
	}
	return n, os.Rename(tmp, p)
}

func tagOrder(t string) int {
	for i, x := range Tags {
		if x.Key == t {
			return i
		}
	}
	return len(Tags)
}

// Annotate returns a copy of the snapshot with each annotated node carrying
// "pentester_tags" / "pentester_note" props, which the reports render.
func Annotate(d graph.Delta, all map[string]Note) graph.Delta {
	if len(all) == 0 {
		return d
	}
	out := graph.Delta{Edges: d.Edges}
	for _, n := range d.Nodes {
		note, ok := all[n.ID]
		if !ok || note.Empty() {
			out.Nodes = append(out.Nodes, n)
			continue
		}
		c := *n
		c.Props = make(map[string]any, len(n.Props)+2)
		for k, v := range n.Props {
			c.Props[k] = v
		}
		if len(note.Tags) > 0 {
			labels := make([]string, len(note.Tags))
			for i, t := range note.Tags {
				labels[i] = TagLabel(t)
			}
			c.Props["pentester_tags"] = strings.Join(labels, ", ")
		}
		if note.Text != "" {
			c.Props["pentester_note"] = note.Text
		}
		out.Nodes = append(out.Nodes, &c)
	}
	return out
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "target"
	}
	return b.String()
}
