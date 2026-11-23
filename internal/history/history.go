// Package history persists scan snapshots to disk and diffs them, so repeat
// scans of the same target reveal what changed (new subdomains, new open
// ports, new CVEs) — the basis of a monitoring workflow.
package history

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"osint-forge/internal/graph"
)

// Dir returns the per-target history directory, creating it if needed.
func Dir(target string) (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "osint-forge", "history", sanitize(target))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

// Save writes a snapshot for a target, timestamped. It returns the file path.
func Save(target string, d graph.Delta) (string, error) {
	dir, err := Dir(target)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	// Nanosecond granularity so two scans in the same second never collide.
	path := filepath.Join(dir, strconv.FormatInt(time.Now().UnixNano(), 10)+".json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// snapshot is one stored scan with its timestamp.
type snapshot struct {
	When  time.Time
	Delta graph.Delta
}

// loadAll returns every stored snapshot for a target, oldest first.
func loadAll(target string) ([]snapshot, error) {
	dir, err := Dir(target)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []snapshot
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		ts, err := strconv.ParseInt(strings.TrimSuffix(e.Name(), ".json"), 10, 64)
		if err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var d graph.Delta
		if json.Unmarshal(data, &d) != nil {
			continue
		}
		out = append(out, snapshot{When: time.Unix(0, ts), Delta: d})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].When.Before(out[j].When) })
	return out, nil
}

// Diff describes what changed between two scans of a target.
type Diff struct {
	Target      string        `json:"target"`
	Previous    time.Time     `json:"previous"`
	Added       []*graph.Node `json:"added"`
	Removed     []*graph.Node `json:"removed"`
	HasPrevious bool          `json:"hasPrevious"`
}

// DiffAgainstPrevious compares a current (not-yet-saved) snapshot to the most
// recent stored snapshot for the target. Use this before Save.
func DiffAgainstPrevious(target string, current graph.Delta) (Diff, error) {
	snaps, err := loadAll(target)
	if err != nil {
		return Diff{Target: target}, err
	}
	diff := Diff{Target: target}
	if len(snaps) == 0 {
		return diff, nil
	}
	prev := snaps[len(snaps)-1]
	diff.HasPrevious = true
	diff.Previous = prev.When
	diffNodes(&diff, prev.Delta, current)
	return diff, nil
}

// DiffLastTwo compares the two most recent stored snapshots. Use this after the
// current scan has already been saved (e.g. an on-demand "what changed?").
func DiffLastTwo(target string) (Diff, error) {
	snaps, err := loadAll(target)
	if err != nil {
		return Diff{Target: target}, err
	}
	diff := Diff{Target: target}
	if len(snaps) < 2 {
		return diff, nil
	}
	prev := snaps[len(snaps)-2]
	cur := snaps[len(snaps)-1]
	diff.HasPrevious = true
	diff.Previous = prev.When
	diffNodes(&diff, prev.Delta, cur.Delta)
	return diff, nil
}

// diffNodes fills diff.Added/Removed from the node-id difference of old→new.
func diffNodes(diff *Diff, old, new graph.Delta) {
	oldIDs := map[string]*graph.Node{}
	for _, n := range old.Nodes {
		oldIDs[n.ID] = n
	}
	newIDs := map[string]*graph.Node{}
	for _, n := range new.Nodes {
		newIDs[n.ID] = n
		if _, ok := oldIDs[n.ID]; !ok {
			diff.Added = append(diff.Added, n)
		}
	}
	for _, n := range old.Nodes {
		if _, ok := newIDs[n.ID]; !ok {
			diff.Removed = append(diff.Removed, n)
		}
	}
	sort.Slice(diff.Added, func(i, j int) bool { return diff.Added[i].ID < diff.Added[j].ID })
	sort.Slice(diff.Removed, func(i, j int) bool { return diff.Removed[i].ID < diff.Removed[j].ID })
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
	out := b.String()
	if out == "" {
		return "target"
	}
	return out
}
