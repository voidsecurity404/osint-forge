package scan

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

// Real-Firefox checks of the fast screenshot path. Skipped without Firefox
// (CI) or with -short.
func TestFirefoxBidiRealPages(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}
	if _, err := exec.LookPath("firefox"); err != nil {
		t.Skip("firefox not installed")
	}
	for _, b := range chromeBinaries {
		if _, err := exec.LookPath(b); err == nil {
			t.Skip("a Chromium browser is preferred on this machine")
		}
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Cleanup(ShutdownBrowsers)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body style="background:#0a7"><h1>fast</h1></body></html>`))
	})
	mux.HandleFunc("/hanging", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body style="background:#a70"><h1>content</h1><img src="/never.png"></body></html>`))
	})
	never := make(chan struct{})
	mux.HandleFunc("/never.png", func(w http.ResponseWriter, r *http.Request) {
		select { // a tracker that never answers
		case <-never:
		case <-r.Context().Done():
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	defer close(never)
	tlsSrv := httptest.NewTLSServer(mux) // self-signed certificate
	defer tlsSrv.Close()

	capture := func(u string) (time.Duration, error) {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		p, err := Capture(ctx, u)
		if err == nil {
			if info, serr := os.Stat(p); serr != nil || info.Size() < 1000 {
				t.Errorf("%s: suspicious PNG (%v)", u, serr)
			}
		}
		return time.Since(start), err
	}

	if d, err := capture(srv.URL + "/"); err != nil {
		t.Fatalf("first capture (includes browser start): %v", err)
	} else {
		t.Logf("first capture incl. browser start: %v", d)
	}
	d, err := capture(srv.URL + "/?again")
	if err != nil || d > 2*time.Second {
		t.Fatalf("warm capture took %v (%v); the persistent browser should make it fast", d, err)
	}
	t.Logf("warm capture: %v", d)

	d, err = capture(srv.URL + "/hanging")
	if err != nil || d > bidiAfterDOM+3*time.Second {
		t.Fatalf("page with a hanging resource: %v after %v (must not wait for it)", err, d)
	}
	t.Logf("hanging resource: %v", d)

	if d, err = capture(tlsSrv.URL + "/"); err != nil {
		t.Fatalf("self-signed TLS page: %v", err)
	}
	t.Logf("self-signed TLS: %v", d)

	// A closed port: an error, quickly — not Firefox's error page as a "screenshot".
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := "http://" + ln.Addr().String() + "/"
	ln.Close()
	if d, err = capture(dead); err == nil {
		t.Fatal("closed port produced a screenshot (Firefox's error page)")
	} else if d > 5*time.Second {
		t.Fatalf("closed port took %v to fail", d)
	}

	// Parallel captures share the one browser.
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := capture(srv.URL + "/?p=" + string(rune('a'+i))); err != nil {
				t.Errorf("parallel %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	t.Logf("6 parallel captures: %v", time.Since(start))
}
