// Package cve matches discovered services to known vulnerabilities using the
// NVD (National Vulnerability Database), caching results in SQLite.
package cve

import "strings"

// toCPE23 converts an nmap-style CPE 2.2 URI (e.g. "cpe:/a:igor_sysoev:nginx:1.18.0")
// into a CPE 2.3 formatted string suitable for the NVD virtualMatchString
// parameter: "cpe:2.3:a:igor_sysoev:nginx:1.18.0:*:*:*:*:*:*:*". It returns
// ("", false) when the input is not a usable CPE.
func toCPE23(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	if strings.HasPrefix(raw, "cpe:2.3:") {
		return raw, true
	}
	if !strings.HasPrefix(raw, "cpe:/") {
		return "", false
	}
	// cpe:/a:vendor:product:version:update:edition:lang
	body := strings.TrimPrefix(raw, "cpe:/")
	parts := strings.Split(body, ":")
	// Pad to 11 components (part..other) with wildcards.
	fields := make([]string, 11)
	for i := range fields {
		fields[i] = "*"
	}
	for i, p := range parts {
		if i >= 11 {
			break
		}
		if p == "" {
			continue
		}
		fields[i] = p
	}
	// Require at least part + vendor + product to be meaningful.
	if fields[0] == "*" || fields[1] == "*" || fields[2] == "*" {
		return "", false
	}
	return "cpe:2.3:" + strings.Join(fields, ":"), true
}

// hasVersion reports whether a CPE 2.3 string pins a concrete version (so a
// match is precise rather than product-wide).
func hasVersion(cpe23 string) bool {
	parts := strings.Split(cpe23, ":")
	return len(parts) > 5 && parts[5] != "*" && parts[5] != "-" && parts[5] != ""
}
