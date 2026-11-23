package scan

import (
	"bufio"
	"embed"
	"os"
	"sort"
	"strings"
)

// SecLists Web-Content wordlists bundled into the binary so the tool is
// self-contained. Source: github.com/danielmiessler/SecLists.
//
//go:embed wordlists/*.txt
var wordlistFS embed.FS

// builtinWordlists maps a selector name to an embedded SecLists file.
var builtinWordlists = map[string]string{
	"common":           "wordlists/common.txt",
	"raft-directories": "wordlists/raft-medium-directories.txt",
	"raft-files":       "wordlists/raft-medium-files.txt",
}

// WordlistNames returns the available builtin selector names (for the UI).
func WordlistNames() []string {
	names := []string{"common", "raft-directories", "raft-files", "combo"}
	return names
}

// LoadWordlist resolves cfg.FuzzWordlist into a concrete list of paths.
// Accepted values:
//   - "" or "common"        → SecLists common.txt (default)
//   - "raft-directories"    → SecLists raft-medium-directories.txt
//   - "raft-files"          → SecLists raft-medium-files.txt
//   - "combo"               → directories + files, de-duplicated
//   - any filesystem path   → a custom wordlist the user downloaded
//
// It returns the words and a human label describing the chosen source.
func LoadWordlist(sel string) ([]string, string) {
	sel = strings.TrimSpace(sel)
	switch sel {
	case "", "common":
		return readEmbedded(builtinWordlists["common"]), "SecLists/common.txt"
	case "raft-directories", "raft-files":
		return readEmbedded(builtinWordlists[sel]), "SecLists/" + sel
	case "combo":
		set := map[string]bool{}
		for _, f := range []string{builtinWordlists["raft-directories"], builtinWordlists["raft-files"]} {
			for _, w := range readEmbedded(f) {
				set[w] = true
			}
		}
		out := make([]string, 0, len(set))
		for w := range set {
			out = append(out, w)
		}
		sort.Strings(out)
		return out, "SecLists combo (dirs+files)"
	}
	// Treat as a filesystem path to a custom wordlist.
	if words := readFile(sel); len(words) > 0 {
		return words, sel
	}
	// Fallback to common if the path was unusable.
	return readEmbedded(builtinWordlists["common"]), "SecLists/common.txt"
}

func readEmbedded(name string) []string {
	f, err := wordlistFS.Open(name)
	if err != nil {
		return nil
	}
	defer f.Close()
	return scanLines(f)
}

func readFile(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	return scanLines(f)
}

func scanLines(r interface{ Read([]byte) (int, error) }) []string {
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "/")
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
