package scan

import (
	"net/http"
	"strings"
)

// detectCDN identifies a CDN/WAF in front of a host from response headers and
// the Server banner. Returns a short vendor name (or "") and whether a WAF
// signature was seen. Knowing a host is behind a CDN matters: the IP you scanned
// is the edge, not the origin — so port/host findings describe the CDN, and the
// real server may be reachable another way.
func detectCDN(h http.Header) (vendor string, waf bool) {
	server := strings.ToLower(h.Get("Server"))
	has := func(k string) bool { return h.Get(k) != "" }

	switch {
	case server == "cloudflare" || has("CF-RAY") || has("CF-Cache-Status"):
		vendor = "Cloudflare"
	case strings.Contains(server, "akamai") || has("X-Akamai-Transformed"):
		vendor = "Akamai"
	case has("X-Amz-Cf-Id") || strings.Contains(server, "cloudfront"):
		vendor = "AWS CloudFront"
	case strings.Contains(server, "fastly") || has("Fastly-Debug-Digest"):
		vendor = "Fastly"
	case strings.Contains(server, "sucuri") || has("X-Sucuri-ID"):
		vendor = "Sucuri"
	case has("X-Azure-Ref"):
		vendor = "Azure Front Door"
	case strings.Contains(server, "awselb"):
		vendor = "AWS ELB"
	case has("X-CDN"):
		vendor = h.Get("X-CDN")
	}

	// WAF signatures (may stand alone or accompany a CDN).
	if has("X-Sucuri-ID") || has("X-Mod-Security") || has("X-WAF") || has("X-Firewall") {
		waf = true
	}
	return vendor, waf
}
