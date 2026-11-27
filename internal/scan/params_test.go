package scan

import "testing"

func TestValidParamName(t *testing.T) {
	good := []string{"id", "q", "order_id", "utm_source", "page[0]", "user.name", "a1", "X-Token"}
	for _, g := range good {
		if !validParamName(g) {
			t.Errorf("%q should be valid", g)
		}
	}
	bad := []string{"", ",-", "@_~", "123", "--", "__", "a b", "\"onclick", "x=y", strings_repeat("a", 65)}
	for _, b := range bad {
		if validParamName(b) {
			t.Errorf("%q should be invalid", b)
		}
	}
}

func strings_repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}
