package scan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeBrowser installs a fake "chromium" on PATH that records each run in a
// counter file, waits a little (so concurrent captures overlap) and writes a
// PNG to the --screenshot= path — or fails when FAKE_FAIL=1.
func fakeBrowser(t *testing.T) (countFile string) {
	t.Helper()
	bin := t.TempDir()
	countFile = filepath.Join(t.TempDir(), "runs")
	script := `#!/bin/sh
echo run >> "$COUNT_FILE"
sleep 0.3
[ "$FAKE_FAIL" = 1 ] && exit 1
for a in "$@"; do
  case "$a" in --screenshot=*) printf 'PNGDATA' > "${a#--screenshot=}" ;; esac
done
`
	if err := os.WriteFile(filepath.Join(bin, "chromium"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":/usr/bin:/bin")
	t.Setenv("COUNT_FILE", countFile)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	return countFile
}

func runs(t *testing.T, countFile string) int {
	b, _ := os.ReadFile(countFile)
	return strings.Count(string(b), "run")
}

// Double-clicking a node while the scan's screenshot source (or another tab)
// captures the same page must not start a second browser for it.
func TestCaptureSharesOneBrowserRunPerURL(t *testing.T) {
	count := fakeBrowser(t)
	var wg sync.WaitGroup
	paths := make([]string, 3)
	for i := range paths {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p, err := Capture(context.Background(), "http://127.0.0.1:8000/admin")
			if err != nil {
				t.Errorf("capture %d: %v", i, err)
			}
			paths[i] = p
		}(i)
	}
	wg.Wait()
	if n := runs(t, count); n != 1 {
		t.Fatalf("browser started %d times for one URL, want 1", n)
	}
	want, _ := ScreenshotPath("http://127.0.0.1:8000/admin")
	for _, p := range paths {
		if p != want {
			t.Fatalf("path %q, want %q", p, want)
		}
	}
	if b, _ := os.ReadFile(want); string(b) != "PNGDATA" {
		t.Fatalf("png content %q", b)
	}
	// A later call captures again (fresh screenshot on demand).
	if _, err := Capture(context.Background(), "http://127.0.0.1:8000/admin"); err != nil {
		t.Fatal(err)
	}
	if n := runs(t, count); n != 2 {
		t.Fatalf("second capture did not run the browser (runs=%d)", n)
	}
}

// A failed capture must leave the previous screenshot untouched.
func TestCaptureFailureKeepsPreviousImage(t *testing.T) {
	fakeBrowser(t)
	out, err := ScreenshotPath("http://127.0.0.1:8000/")
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(out, []byte("OLD"), 0o644)
	t.Setenv("FAKE_FAIL", "1")
	if _, err := Capture(context.Background(), "http://127.0.0.1:8000/"); !errors.Is(err, ErrCaptureFailed) {
		t.Fatalf("err = %v, want ErrCaptureFailed", err)
	}
	if b, _ := os.ReadFile(out); string(b) != "OLD" {
		t.Fatalf("previous screenshot clobbered: %q", b)
	}
	entries, _ := os.ReadDir(filepath.Dir(out))
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %d entries", len(entries))
	}
}

func TestCaptureWithoutBrowser(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, err := Capture(context.Background(), "http://127.0.0.1/"); !errors.Is(err, ErrNoBrowser) {
		t.Fatalf("err = %v, want ErrNoBrowser", err)
	}
}

func TestCaptureRejectsNonHTTP(t *testing.T) {
	fakeBrowser(t)
	for _, u := range []string{"file:///etc/passwd", "javascript:alert(1)", "about:blank", ""} {
		if _, err := Capture(context.Background(), u); err == nil {
			t.Errorf("Capture(%q) accepted a non-web URL", u)
		}
	}
}

// A caller that gives up (the user clicked another node) returns at once; the
// shared run still finishes and its image is used next time.
func TestCaptureCallerCancelDoesNotKillSharedRun(t *testing.T) {
	count := fakeBrowser(t)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := Capture(ctx, "http://127.0.0.1:8000/slow"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if time.Since(start) > 250*time.Millisecond {
		t.Fatal("cancelled caller was not released promptly")
	}
	out, _ := ScreenshotPath("http://127.0.0.1:8000/slow")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if b, _ := os.ReadFile(out); string(b) == "PNGDATA" {
			if n := runs(t, count); n != 1 {
				t.Fatalf("runs = %d", n)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("shared run did not complete after the caller left")
}
