package recon

import "testing"

func TestPlausibleArchivedURL(t *testing.T) {
	good := []string{
		"https://example.com/about",
		"http://example.com/api/v1/users?id=5",
		"https://example.com/path/to/page.html?a=1&b=2",
	}
	for _, g := range good {
		if !plausibleArchivedURL(g) {
			t.Errorf("%q should be plausible", g)
		}
	}
	bad := []string{
		"",
		"ftp://example.com/x",
		`http://example.com/%22%20onclick=%22alert(1)%22`,
		`https://example.com/!$%27()*+./:;=?%40_~=&%2C-=`,
		"http://example.com/%22%20-F%20%22file=@/etc/passwd",
		"not a url",
	}
	for _, b := range bad {
		if plausibleArchivedURL(b) {
			t.Errorf("%q should be filtered", b)
		}
	}
}
