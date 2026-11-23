package scan

import (
	"strconv"
	"strings"
)

// StatusFilter decides which HTTP status codes are recorded (http probe + fuzz).
// It is compiled from a user spec, a comma-separated list of exact codes ("200"),
// ranges ("200-299") or classes ("2xx","3xx","4xx","5xx"). An empty spec — or one
// that parses to nothing — allows every code.
type StatusFilter struct {
	all    bool
	codes  map[int]bool
	ranges [][2]int
}

// ParseStatusFilter compiles a spec string into a StatusFilter.
func ParseStatusFilter(spec string) StatusFilter {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return StatusFilter{all: true}
	}
	f := StatusFilter{codes: map[int]bool{}}
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(strings.ToLower(tok))
		switch {
		case tok == "":
			continue
		case len(tok) == 3 && strings.HasSuffix(tok, "xx"):
			if d, err := strconv.Atoi(tok[:1]); err == nil {
				f.ranges = append(f.ranges, [2]int{d * 100, d*100 + 99})
			}
		case strings.Contains(tok, "-"):
			p := strings.SplitN(tok, "-", 2)
			lo, e1 := strconv.Atoi(strings.TrimSpace(p[0]))
			hi, e2 := strconv.Atoi(strings.TrimSpace(p[1]))
			if e1 == nil && e2 == nil && lo <= hi {
				f.ranges = append(f.ranges, [2]int{lo, hi})
			}
		default:
			if c, err := strconv.Atoi(tok); err == nil {
				f.codes[c] = true
			}
		}
	}
	if len(f.codes) == 0 && len(f.ranges) == 0 {
		f.all = true // unparsable spec: fail open rather than hide everything
	}
	return f
}

// Allows reports whether a status code should be recorded.
func (f StatusFilter) Allows(code int) bool {
	if f.all {
		return true
	}
	if f.codes[code] {
		return true
	}
	for _, r := range f.ranges {
		if code >= r[0] && code <= r[1] {
			return true
		}
	}
	return false
}
