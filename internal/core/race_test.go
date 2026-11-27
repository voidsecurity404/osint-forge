package core

import (
	"sync"
	"testing"

	"osint-forge/internal/graph"
)

// GetNode must hand out a snapshot: Enrich-stage sources read a node's Props
// (liveBaseURLs, tls, cve) while sibling sources merge new props into the very
// same node (screenshots adds "screenshot" to base URLs). Reading the live map
// during that write is a fatal "concurrent map read and map write" — a crash
// recover() cannot catch, which took the whole server down. Run with -race.
func TestGetNodeIsSafeDuringConcurrentMerge(t *testing.T) {
	g := graph.New()
	c := NewCollector(ParseTarget("example.com"), g, nil)
	c.Node(graph.NodeURL, "https://example.com", "https://example.com", map[string]any{"status": 200})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // writer: e.g. ScreenshotSource
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			c.Node(graph.NodeURL, "https://example.com", "", map[string]any{"screenshot": i})
		}
	}()
	go func() { // reader: e.g. liveBaseURLs / TLSSource / cve.Source
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			if n, ok := c.GetNode(graph.NodeURL, "https://example.com"); ok {
				_ = n.Props["status"]
				for range n.Props {
				}
			}
		}
	}()
	wg.Wait()
}
