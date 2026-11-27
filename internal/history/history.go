// Package history persists scan snapshots to disk and diffs them, so repeat
// scans of the same target reveal what changed (new subdomains, new open
// ports, new CVEs) — the basis of a monitoring workflow.
package history

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"osint-forge/internal/graph"
)

// ErrNoScans is returned when a target has no stored scans.
var ErrNoScans = errors.New("для этой цели нет сохранённых сканирований — сначала выполните сканирование")

// maxScansPerTarget caps how many scans are kept per target; the oldest are
// pruned. Identical consecutive scans also replace each other (see Save), so
// this mostly bounds long-running monitoring.
const maxScansPerTarget = 200

// labelFile stores the real target label next to its scans: the directory name
// is sanitised (an IPv6 "2606:4700::1" becomes "2606_4700__1").
const labelFile = ".target"

// Dir returns the per-target history directory, creating it if needed.
func Dir(target string) (string, error) { return dirFor(target, true) }

// dirFor returns the per-target directory. Only writers create it: a read for
// a target that was never scanned must not leave an empty directory behind.
func dirFor(target string, create bool) (string, error) {
	base, err := baseDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, sanitize(target))
	if create {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}
	}
	return dir, nil
}

// Save writes a snapshot for a target, timestamped. It returns the file path.
//
// When the newest stored scan has exactly the same set of entities, it is
// replaced instead of kept (a monitor re-scanning an unchanged target every few
// minutes would otherwise fill the disk), and at most maxScansPerTarget scans
// are kept. Diffs must therefore be computed BEFORE saving (DiffAgainstPrevious).
func Save(target string, d graph.Delta) (string, error) {
	dir, err := Dir(target)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(dir, labelFile)); err != nil {
		_ = os.WriteFile(filepath.Join(dir, labelFile), []byte(strings.TrimSpace(target)), 0o644)
	}
	data, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	ids := scanIDs(dir)
	// Nanosecond granularity so two scans in the same second never collide.
	path := filepath.Join(dir, strconv.FormatInt(time.Now().UnixNano(), 10)+".json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	if len(ids) > 0 {
		last := ids[len(ids)-1]
		if prev, err := Load(target, last); err == nil && sameEntities(prev, d) {
			_ = os.Remove(filepath.Join(dir, last+".json"))
			ids = ids[:len(ids)-1]
		}
	}
	// ids now holds the older scans; keep room for the one just written.
	for len(ids) >= maxScansPerTarget {
		_ = os.Remove(filepath.Join(dir, ids[0]+".json"))
		ids = ids[1:]
	}
	return path, nil
}

// sameEntities reports whether two snapshots contain the same node ids.
func sameEntities(a, b graph.Delta) bool {
	if len(a.Nodes) != len(b.Nodes) {
		return false
	}
	set := make(map[string]bool, len(a.Nodes))
	for _, n := range a.Nodes {
		set[n.ID] = true
	}
	for _, n := range b.Nodes {
		if !set[n.ID] {
			return false
		}
	}
	return true
}

// readLabel returns the real target label stored in dir, or fallback.
func readLabel(dir, fallback string) string {
	if b, err := os.ReadFile(filepath.Join(dir, labelFile)); err == nil {
		if l := strings.TrimSpace(string(b)); l != "" {
			return l
		}
	}
	return fallback
}

// snapshot is one stored scan with its timestamp.
type snapshot struct {
	When  time.Time
	Delta graph.Delta
}

// loadAll returns every stored snapshot for a target, oldest first.
func loadAll(target string) ([]snapshot, error) {
	dir, err := dirFor(target, false)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // never scanned: no history, not an error
		}
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

// ---- Browsing API (web UI history page) ----

// Entry describes one stored scan.
type Entry struct {
	ID       string    `json:"id"` // unix-nano timestamp (the file name)
	Target   string    `json:"target"`
	When     time.Time `json:"when"`
	Nodes    int       `json:"nodes"`
	Edges    int       `json:"edges"`
	Findings int       `json:"findings"` // finding + cve nodes
}

// TargetSummary is one scanned target with its latest scan.
type TargetSummary struct {
	Target string    `json:"target"`
	Scans  int       `json:"scans"`
	Last   time.Time `json:"last"`
}

func baseDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "osint-forge", "history"), nil
}

// validID reports whether id looks like a stored scan id (digits only), so it
// can never be used for path traversal.
func validID(id string) bool {
	if id == "" || len(id) > 25 {
		return false
	}
	for _, r := range id {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Targets lists every target that has stored scans, most recent first.
func Targets() ([]TargetSummary, error) {
	base, err := baseDir()
	if err != nil {
		return nil, err
	}
	dirs, err := os.ReadDir(base)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []TargetSummary
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		dir := filepath.Join(base, d.Name())
		ids := scanIDs(dir)
		if len(ids) == 0 {
			continue
		}
		ts, _ := strconv.ParseInt(ids[len(ids)-1], 10, 64)
		out = append(out, TargetSummary{Target: readLabel(dir, d.Name()), Scans: len(ids), Last: time.Unix(0, ts)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Last.After(out[j].Last) })
	return out, nil
}

// scanIDs returns the scan ids in a target dir, oldest first.
func scanIDs(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var ids []string
	for _, e := range entries {
		id := strings.TrimSuffix(e.Name(), ".json")
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") && validID(id) {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		a, _ := strconv.ParseInt(ids[i], 10, 64)
		b, _ := strconv.ParseInt(ids[j], 10, 64)
		return a < b
	})
	return ids
}

// List returns the stored scans of a target, newest first.
func List(target string) ([]Entry, error) {
	dir, err := dirFor(target, false)
	if err != nil {
		return nil, err
	}
	ids := scanIDs(dir)
	label := readLabel(dir, sanitize(target))
	out := make([]Entry, 0, len(ids))
	for i := len(ids) - 1; i >= 0; i-- {
		d, err := Load(target, ids[i])
		if err != nil {
			continue
		}
		ts, _ := strconv.ParseInt(ids[i], 10, 64)
		e := Entry{ID: ids[i], Target: label, When: time.Unix(0, ts), Nodes: len(d.Nodes), Edges: len(d.Edges)}
		for _, n := range d.Nodes {
			if n.Type == graph.NodeFinding || n.Type == graph.NodeCVE {
				e.Findings++
			}
		}
		out = append(out, e)
	}
	return out, nil
}

// Load reads one stored scan.
func Load(target, id string) (graph.Delta, error) {
	if !validID(id) {
		return graph.Delta{}, os.ErrNotExist
	}
	dir, err := dirFor(target, false)
	if err != nil {
		return graph.Delta{}, err
	}
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		if os.IsNotExist(err) {
			return graph.Delta{}, errors.New("сканирование не найдено")
		}
		return graph.Delta{}, err
	}
	var d graph.Delta
	err = json.Unmarshal(data, &d)
	return d, err
}

// Latest returns the newest stored scan of the most recently scanned target.
func Latest() (target string, d graph.Delta, ok bool) {
	ts, err := Targets()
	if err != nil || len(ts) == 0 {
		return "", graph.Delta{}, false
	}
	dir, err := dirFor(ts[0].Target, false)
	if err != nil {
		return "", graph.Delta{}, false
	}
	ids := scanIDs(dir)
	if len(ids) == 0 {
		return "", graph.Delta{}, false
	}
	d, err = Load(ts[0].Target, ids[len(ids)-1])
	if err != nil {
		return "", graph.Delta{}, false
	}
	return ts[0].Target, d, true
}

// Delete removes one stored scan.
func Delete(target, id string) error {
	if !validID(id) {
		return os.ErrNotExist
	}
	dir, err := dirFor(target, false)
	if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, id+".json")); err != nil {
		if os.IsNotExist(err) {
			return errors.New("сканирование не найдено")
		}
		return err
	}
	// Drop the directory with its last scan, so the target leaves the list.
	if len(scanIDs(dir)) == 0 {
		_ = os.RemoveAll(dir)
	}
	return nil
}

// Compare is a visual diff between two scans of one target: Graph is the union
// of both (so removed entities can still be drawn), Added/Removed list the node
// ids that appeared in / disappeared from the newer scan.
type Compare struct {
	Target  string      `json:"target"`
	From    string      `json:"from"`
	To      string      `json:"to"`
	Graph   graph.Delta `json:"graph"`
	Added   []string    `json:"added"`
	Removed []string    `json:"removed"`
}

// CompareScans diffs scan `from` (older) against scan `to` (newer). An empty
// `from` means "the scan just before `to`".
func CompareScans(target, from, to string) (Compare, error) {
	c := Compare{Target: sanitize(target), From: from, To: to}
	dir, err := dirFor(target, false)
	if err != nil {
		return c, err
	}
	ids := scanIDs(dir)
	if len(ids) == 0 {
		return c, ErrNoScans
	}
	c.Target = readLabel(dir, c.Target)
	if to == "" {
		to = ids[len(ids)-1]
	}
	if from == "" {
		for i, id := range ids {
			if id == to && i > 0 {
				from = ids[i-1]
			}
		}
	}
	c.From, c.To = from, to
	newer, err := Load(target, to)
	if err != nil {
		return c, err
	}
	var older graph.Delta
	if from != "" {
		if older, err = Load(target, from); err != nil {
			return c, err
		}
	}
	newIDs := map[string]bool{}
	for _, n := range newer.Nodes {
		newIDs[n.ID] = true
	}
	oldIDs := map[string]bool{}
	for _, n := range older.Nodes {
		oldIDs[n.ID] = true
	}
	c.Graph.Nodes = append(c.Graph.Nodes, newer.Nodes...)
	c.Graph.Edges = append(c.Graph.Edges, newer.Edges...)
	for _, n := range newer.Nodes {
		if from != "" && !oldIDs[n.ID] {
			c.Added = append(c.Added, n.ID)
		}
	}
	edgeSeen := map[string]bool{}
	for _, e := range newer.Edges {
		edgeSeen[e.ID] = true
	}
	for _, n := range older.Nodes {
		if !newIDs[n.ID] {
			c.Removed = append(c.Removed, n.ID)
			c.Graph.Nodes = append(c.Graph.Nodes, n)
		}
	}
	// Keep old edges that touch removed nodes so they are drawn in context.
	removed := map[string]bool{}
	for _, id := range c.Removed {
		removed[id] = true
	}
	for _, e := range older.Edges {
		if !edgeSeen[e.ID] && (removed[e.Source] || removed[e.Target]) {
			c.Graph.Edges = append(c.Graph.Edges, e)
		}
	}
	sort.Strings(c.Added)
	sort.Strings(c.Removed)
	return c, nil
}
