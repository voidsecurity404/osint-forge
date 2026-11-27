package scan

import "testing"

func TestEndpointAndSecretRegex(t *testing.T) {
	js := `const API="/api/v1/users?id=1";fetch('/api/v1/orders?order_id=5&redirect=https://x');` +
		`var k="AKIAIOSFODNN7EXAMPLE";var g="AIzaSyD-1234567890abcdefghijklmnopqrstuv";` +
		`axios.get("/internal/admin/export?file=report.pdf");img.src="/logo.png";`
	var eps []string
	for _, m := range endpointRe.FindAllStringSubmatch(js, -1) {
		if !skipEndpoint(m[1]) {
			eps = append(eps, m[1])
		}
	}
	want := map[string]bool{"/api/v1/users?id=1": true, "/api/v1/orders?order_id=5&redirect=https://x": true, "/internal/admin/export?file=report.pdf": true}
	got := map[string]bool{}
	for _, e := range eps {
		got[e] = true
	}
	for w := range want {
		if !got[w] {
			t.Errorf("endpoint %q not extracted; got %v", w, eps)
		}
	}
	if got["/logo.png"] {
		t.Error("static asset should be skipped")
	}
	hits := 0
	for _, sr := range secretRes {
		if sr.re.MatchString(js) {
			hits++
		}
	}
	if hits < 2 {
		t.Errorf("expected AWS+Google secrets, got %d", hits)
	}
}

func TestClassifyParam(t *testing.T) {
	if k := classifyParam("redirect"); len(k) == 0 || k[0] != "redirect" {
		t.Errorf("redirect misclassified: %v", k)
	}
	if k := classifyParam("file"); len(k) == 0 {
		t.Error("file should be lfi/path candidate")
	}
	if k := classifyParam("zzz_unknown"); len(k) != 0 {
		t.Errorf("unknown param should have no kinds: %v", k)
	}
}
