package core

import (
	"net"
	"regexp"
	"strings"
)

// Target is the normalized subject of a scan: either an IP address or a domain
// (or both, once DNS resolution links them).
type Target struct {
	Raw    string `json:"raw"`
	IsIP   bool   `json:"isIP"`
	IP     string `json:"ip"`     // set when the input is/resolves to an IP
	Domain string `json:"domain"` // set when the input is a hostname
	Valid  bool   `json:"valid"`  // the input is a usable IP or domain
}

// ParseTarget normalizes free-form user input into a Target. It strips a
// scheme, path and port if the user pasted a URL.
func ParseTarget(raw string) Target {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	// Drop a trailing :port. For a bracketed IPv6 authority ("[::1]:443" or
	// "[::1]") SplitHostPort returns the bare address; a plain bracketed host
	// without a port is unbracketed directly. A bare IPv6 literal ("2606::1")
	// has too many colons for SplitHostPort and is left untouched.
	if strings.HasPrefix(s, "[") {
		if host, _, err := net.SplitHostPort(s); err == nil {
			s = host
		} else {
			s = strings.Trim(s, "[]")
		}
	} else if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	s = strings.Trim(s, "[]")
	s = strings.ToLower(strings.TrimSuffix(s, "."))

	t := Target{Raw: raw}
	if ip := net.ParseIP(s); ip != nil {
		t.IsIP = true
		t.IP = s
		t.Valid = true
		return t
	}
	t.Domain = s
	t.Valid = ValidDomain(s)
	return t
}

// domainLabel matches one DNS label: starts and ends alphanumeric (ASCII or
// unicode letter), may contain hyphens inside, 1..63 chars.
var domainLabel = regexp.MustCompile(`^[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?$`)

// ValidDomain reports whether s is a syntactically valid hostname worth
// scanning: at least two dot-separated labels, each a valid label, a TLD that is
// not purely numeric, and total length ≤ 253. It rejects junk like "!!!@@@",
// "a..b", "-x.com" and bare words without a TLD.
func ValidDomain(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false // needs a TLD
	}
	for _, l := range labels {
		if !domainLabel.MatchString(l) {
			return false
		}
	}
	tld := labels[len(labels)-1]
	if len(tld) < 2 {
		return false
	}
	allDigits := true
	for _, r := range tld {
		if r < '0' || r > '9' {
			allDigits = false
			break
		}
	}
	return !allDigits // a numeric-only TLD is never valid (and an all-numeric dotted string is an IP, handled above)
}
