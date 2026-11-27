package main

import (
	"errors"
	"strings"

	"osint-forge/internal/core"
	"osint-forge/internal/graph"
	"osint-forge/internal/history"
	"osint-forge/internal/notes"
)

// OpenScan replaces the current graph with a stored scan, so it can be viewed,
// annotated and exported again.
func (a *App) OpenScan(target, id string) (graph.Delta, error) {
	target = historyLabel(target)
	d, err := history.Load(target, id)
	if err != nil {
		return graph.Delta{}, err
	}
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return graph.Delta{}, errors.New("skan ketmoqda — avval uni to'xtating")
	}
	a.g = graph.FromDelta(d)
	a.target = target
	a.timings = nil
	snap := a.g.Snapshot()
	a.mu.Unlock()
	// Other open tabs must redraw too, or they keep showing the old graph.
	a.publish(evtReset, map[string]string{"target": target})
	return snap, nil
}

// historyLabel maps a {target} path value to the history key: the parsed label
// for a valid target ("https://Example.com/x" → "example.com"), else the raw
// value (an already-sanitised directory name from an older version).
func historyLabel(raw string) string {
	raw = strings.TrimSpace(raw)
	if t := core.ParseTarget(raw); t.Valid {
		return labelOf(t)
	}
	return raw
}

// labelFor maps user input (or "" = the current target) to the history/notes
// key: the domain, else the IP.
func (a *App) labelFor(raw string) string {
	if strings.TrimSpace(raw) == "" {
		a.mu.Lock()
		raw = a.target
		a.mu.Unlock()
	}
	t := core.ParseTarget(raw)
	if l := labelOf(t); l != "" {
		return l
	}
	return strings.TrimSpace(raw)
}

// annotated merges the current target's notes into a snapshot (for exports).
func (a *App) annotated(d graph.Delta) graph.Delta {
	all, err := notes.Load(a.labelFor(""))
	if err != nil {
		return d
	}
	return notes.Annotate(d, all)
}
