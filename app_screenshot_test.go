package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"osint-forge/internal/config"
	"osint-forge/internal/graph"
)

const (
	liveURL    = "http://127.0.0.1:8000/admin"         // probed during the scan (has a status)
	archiveURL = "http://127.0.0.1:8000/products?id=5" // from a sitemap: never requested
)

// fakeChromium puts a fake headless browser on PATH that counts its runs and
// writes a PNG to the --screenshot= path.
func fakeChromium(t *testing.T) (runs func() int) {
	t.Helper()
	bin := t.TempDir()
	count := filepath.Join(t.TempDir(), "runs")
	script := "#!/bin/sh\necho run >> \"$COUNT_FILE\"\nfor a in \"$@\"; do case \"$a\" in --screenshot=*) printf PNG > \"${a#--screenshot=}\" ;; esac; done\n"
	if err := os.WriteFile(filepath.Join(bin, "chromium"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":/usr/bin:/bin")
	t.Setenv("COUNT_FILE", count)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	return func() int {
		b, _ := os.ReadFile(count)
		return strings.Count(string(b), "run")
	}
}

func captureApp() *App {
	g := graph.New()
	g.AddNode(&graph.Node{ID: graph.NodeID(graph.NodeURL, liveURL), Type: graph.NodeURL, Label: "/admin", Props: map[string]any{"status": 403}})
	g.AddNode(&graph.Node{ID: graph.NodeID(graph.NodeURL, archiveURL), Type: graph.NodeURL, Label: "/products?id=5", Props: map[string]any{"source": "sitemap"}})
	return &App{cfg: config.Default(), g: g, hub: NewHub()}
}

type captureResult struct {
	URL     string    `json:"url"`
	Path    string    `json:"path"`
	TakenAt time.Time `json:"takenAt"`
	Cached  bool      `json:"cached"`
	Error   string    `json:"error"`
}

func postCapture(t *testing.T, a *App, body string) (int, captureResult) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/screenshot", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	newRouter(a, fstest.MapFS{}).ServeHTTP(rec, req)
	var res captureResult
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	return rec.Code, res
}

func TestCaptureEndpoint(t *testing.T) {
	runs := fakeChromium(t)
	a := captureApp()
	events := a.hub.Subscribe()

	// A page the scan already requested is captured automatically.
	code, res := postCapture(t, a, `{"url":"`+liveURL+`","auto":true}`)
	if code != 200 || res.Path == "" || res.Cached || res.TakenAt.IsZero() {
		t.Fatalf("auto capture: %d %+v", code, res)
	}
	if n, _ := a.g.Copy(graph.NodeID(graph.NodeURL, liveURL)); n.Props["screenshot"] != res.Path {
		t.Fatalf("node not updated: %+v", n.Props)
	}
	select {
	case m := <-events:
		if m.event != evtDelta || !strings.Contains(string(m.data), "screenshot") {
			t.Fatalf("unexpected event %s %s", m.event, m.data)
		}
	case <-time.After(time.Second):
		t.Fatal("no delta pushed to the browsers (gallery would not update)")
	}

	// Opening the node again reuses the image — no second browser run.
	if code, res := postCapture(t, a, `{"url":"`+liveURL+`","auto":true}`); code != 200 || !res.Cached {
		t.Fatalf("cached: %d %+v", code, res)
	}
	if runs() != 1 {
		t.Fatalf("cached request started the browser (runs=%d)", runs())
	}
	// "Yangilash" forces a fresh capture.
	if code, res := postCapture(t, a, `{"url":"`+liveURL+`","force":true}`); code != 200 || res.Cached {
		t.Fatalf("force: %d %+v", code, res)
	}
	if runs() != 2 {
		t.Fatalf("force did not re-capture (runs=%d)", runs())
	}

	// Never-requested pages (sitemap/wayback) are not contacted automatically —
	// that would turn a passive scan into active traffic. A click is required.
	if code, res := postCapture(t, a, `{"url":"`+archiveURL+`","auto":true}`); code != http.StatusConflict || res.Error == "" {
		t.Fatalf("auto on an uncontacted page: %d %+v", code, res)
	}
	if code, _ := postCapture(t, a, `{"url":"`+archiveURL+`"}`); code != 200 {
		t.Fatalf("manual capture of an uncontacted page: %d", code)
	}

	// Only pages of the graph on screen, only http(s).
	if code, _ := postCapture(t, a, `{"url":"http://evil.example/"}`); code != http.StatusNotFound {
		t.Fatalf("URL outside the graph: %d", code)
	}
	for _, u := range []string{"file:///etc/passwd", "javascript:alert(1)", ""} {
		if code, _ := postCapture(t, a, `{"url":"`+u+`"}`); code != http.StatusBadRequest {
			t.Fatalf("%q accepted: %d", u, code)
		}
	}
}

func TestCaptureRespectsScreenshotToggle(t *testing.T) {
	fakeChromium(t)
	a := captureApp()
	a.cfg.Screenshots = false
	if code, res := postCapture(t, a, `{"url":"`+liveURL+`","auto":true}`); code != http.StatusConflict || !strings.Contains(res.Error, "отключены") {
		t.Fatalf("auto with screenshots off: %d %+v", code, res)
	}
	if code, _ := postCapture(t, a, `{"url":"`+liveURL+`"}`); code != 200 {
		t.Fatalf("explicit click with screenshots off: %d", code)
	}
}

func TestCaptureWithoutBrowser(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	if code, res := postCapture(t, captureApp(), `{"url":"`+liveURL+`"}`); code != http.StatusNotImplemented || !strings.Contains(res.Error, "Chromium или Firefox") {
		t.Fatalf("no browser: %d %+v", code, res)
	}
}
