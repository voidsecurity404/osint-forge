package graph

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Obsidian wikilinks break on [ ] # ^ |, and cutting at a fixed byte offset
// could split a multi-byte character, producing an invalid file name.
func TestSafeName(t *testing.T) {
	got := safeName("param - ids[] #frag ^block|x")
	if strings.ContainsAny(got, "[]#^|") {
		t.Errorf("safeName kept wikilink syntax: %q", got)
	}
	long := strings.Repeat("ў", 100) // 2 bytes each → 200 bytes
	if n := safeName(long); !utf8.ValidString(n) || len(n) > 120 {
		t.Errorf("truncation broke UTF-8 or the limit: len=%d valid=%v", len(n), utf8.ValidString(n))
	}
}
