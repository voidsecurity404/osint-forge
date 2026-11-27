package scan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

// fakeBidi is a scripted WebDriver BiDi endpoint. After navigate it emits the
// given events (method, delay) for navigation "n1"; documentURI is what
// script.evaluate returns.
type fakeBidi struct {
	events      []fakeEvent
	documentURI string
}

type fakeEvent struct {
	method, navigation, url string
	after                   time.Duration
}

func (f fakeBidi) serve(ws *websocket.Conn) {
	send := func(v any) {
		b, _ := json.Marshal(v)
		_ = websocket.Message.Send(ws, string(b))
	}
	for {
		var raw string
		if websocket.Message.Receive(ws, &raw) != nil {
			return
		}
		var cmd struct {
			ID     int64  `json:"id"`
			Method string `json:"method"`
		}
		_ = json.Unmarshal([]byte(raw), &cmd)
		ok := func(res any) { send(map[string]any{"type": "success", "id": cmd.ID, "result": res}) }
		switch cmd.Method {
		case "browsingContext.create":
			ok(map[string]string{"context": "c1"})
			// a fresh tab's own about:blank load must be ignored
			send(map[string]any{"type": "event", "method": "browsingContext.load",
				"params": map[string]string{"context": "c1", "navigation": "n0", "url": "about:blank"}})
		case "browsingContext.navigate":
			ok(map[string]string{"navigation": "n1", "url": "http://t/"})
			go func() {
				start := time.Now()
				for _, e := range f.events {
					time.Sleep(e.after - time.Since(start))
					send(map[string]any{"type": "event", "method": e.method,
						"params": map[string]string{"context": "c1", "navigation": e.navigation, "url": e.url}})
				}
			}()
		case "script.evaluate":
			ok(map[string]any{"type": "success", "result": map[string]string{"type": "string", "value": f.documentURI}})
		case "browsingContext.captureScreenshot":
			ok(map[string]string{"data": base64.StdEncoding.EncodeToString([]byte("PNG-" + time.Now().Format("150405.000")))})
		default:
			ok(map[string]any{})
		}
	}
}

func dialFake(t *testing.T, f fakeBidi) *bidiConn {
	t.Helper()
	srv := httptest.NewServer(websocket.Handler(f.serve))
	t.Cleanup(srv.Close)
	ws, err := websocket.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/session", "", "http://localhost/")
	if err != nil {
		t.Fatal(err)
	}
	c := newBidiConn(ws)
	t.Cleanup(func() { ws.Close() })
	if err := c.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	return c
}

func withWaits(t *testing.T, hard, afterDOM time.Duration) {
	oh, oa, os := bidiHardWait, bidiAfterDOM, bidiSettle
	bidiHardWait, bidiAfterDOM, bidiSettle = hard, afterDOM, 10*time.Millisecond
	t.Cleanup(func() { bidiHardWait, bidiAfterDOM, bidiSettle = oh, oa, os })
}

func timed(c *bidiConn) ([]byte, error, time.Duration) {
	start := time.Now()
	png, err := c.capture(context.Background(), "http://t/")
	return png, err, time.Since(start)
}

// A page that loads is captured right after its load event.
func TestBidiCapturesOnLoad(t *testing.T) {
	withWaits(t, 3*time.Second, 2*time.Second)
	c := dialFake(t, fakeBidi{documentURI: "http://t/", events: []fakeEvent{
		{"browsingContext.domContentLoaded", "n1", "http://t/", 50 * time.Millisecond},
		{"browsingContext.load", "n1", "http://t/", 150 * time.Millisecond},
	}})
	png, err, d := timed(c)
	if err != nil || !strings.HasPrefix(string(png), "PNG-") {
		t.Fatalf("capture: %v %q", err, png)
	}
	if d < 150*time.Millisecond || d > time.Second {
		t.Fatalf("captured after %v: must wait for OUR load, not the tab's about:blank", d)
	}
}

// A resource that never finishes (tracker, dead CDN) must not block the
// capture: shortly after the DOM is ready, whatever rendered is saved.
func TestBidiDoesNotWaitForHangingResources(t *testing.T) {
	withWaits(t, 5*time.Second, 300*time.Millisecond)
	c := dialFake(t, fakeBidi{documentURI: "http://t/", events: []fakeEvent{
		{"browsingContext.domContentLoaded", "n1", "http://t/", 50 * time.Millisecond},
	}})
	_, err, d := timed(c)
	if err != nil {
		t.Fatal(err)
	}
	if d > time.Second {
		t.Fatalf("waited %v for a page whose load never comes", d)
	}
}

// No DOM at all within the hard limit: the page did not answer.
func TestBidiUnresponsivePageFails(t *testing.T) {
	withWaits(t, 300*time.Millisecond, time.Second)
	c := dialFake(t, fakeBidi{documentURI: "http://t/"})
	_, err, d := timed(c)
	var pe errPage
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v, want a page error", err)
	}
	if d > time.Second {
		t.Fatalf("took %v", d)
	}
}

// Firefox's own error page (DNS / refused / TLS) is not a screenshot of the target.
func TestBidiErrorPageIsAFailure(t *testing.T) {
	withWaits(t, 3*time.Second, time.Second)
	c := dialFake(t, fakeBidi{documentURI: "about:neterror?e=connectionFailure", events: []fakeEvent{
		{"browsingContext.load", "n1", "http://t/", 20 * time.Millisecond},
	}})
	_, err, _ := timed(c)
	var pe errPage
	if !errors.As(err, &pe) || !strings.Contains(err.Error(), "about:neterror") {
		t.Fatalf("err = %v", err)
	}
}

// Events of another navigation (e.g. a previous page in the same tab) are ignored.
func TestBidiIgnoresOtherNavigations(t *testing.T) {
	withWaits(t, 2*time.Second, 2*time.Second)
	c := dialFake(t, fakeBidi{documentURI: "http://t/", events: []fakeEvent{
		{"browsingContext.load", "n-old", "http://t/old", 20 * time.Millisecond},
		{"browsingContext.load", "n1", "http://t/", 300 * time.Millisecond},
	}})
	_, err, d := timed(c)
	if err != nil || d < 300*time.Millisecond {
		t.Fatalf("err=%v after %v: captured on a foreign navigation's load", err, d)
	}
}
