package core

import (
	"net"
	"strings"
)

// Target is the normalized subject of a scan: either an IP address or a domain
// (or both, once DNS resolution links them).
type Target struct {
	Raw    string `json:"raw"`
	IsIP   bool   `json:"isIP"`
	IP     string `json:"ip"`     // set when the input is/resolves to an IP
	Domain string `json:"domain"` // set when the input is a hostname
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
		return t
	}
	t.Domain = s
	return t
}
