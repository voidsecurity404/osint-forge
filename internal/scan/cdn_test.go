package scan

import (
	"net/http"
	"testing"
)

func hdr(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1]) // Set canonicalises keys, like a real response
	}
	return h
}

func TestDetectCDN(t *testing.T) {
	if v, _ := detectCDN(hdr("Server", "cloudflare", "CF-RAY", "abc")); v != "Cloudflare" {
		t.Errorf("cloudflare not detected: %q", v)
	}
	if v, waf := detectCDN(hdr("X-Sucuri-ID", "x")); v != "Sucuri" || !waf {
		t.Errorf("sucuri/waf not detected: %q %v", v, waf)
	}
	if v, _ := detectCDN(hdr("X-Amz-Cf-Id", "z")); v != "AWS CloudFront" {
		t.Errorf("cloudfront not detected: %q", v)
	}
	if v, waf := detectCDN(hdr("Server", "nginx")); v != "" || waf {
		t.Errorf("false positive: %q %v", v, waf)
	}
}
