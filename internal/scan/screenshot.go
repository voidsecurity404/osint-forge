package scan

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// browser describes a headless-capable browser found on the system.
type browser struct {
	path string
	kind string // "chrome" or "firefox"
}

// chromeBinaries are the Chromium-family browsers we try, in order.
var chromeBinaries = []string{
	"chromium", "chromium-browser", "google-chrome", "google-chrome-stable",
	"chrome", "chrome-headless-shell", "brave-browser",
}

// firefoxBinaries are the Firefox-family browsers we try, in order.
var firefoxBinaries = []string{"firefox", "firefox-esr", "librewolf"}

// findBrowser returns the first available headless browser (Chromium preferred
// for speed, then Firefox). Either works with no extra install if present.
func findBrowser() browser {
	for _, b := range chromeBinaries {
		if p, err := exec.LookPath(b); err == nil {
			return browser{p, "chrome"}
		}
	}
	for _, b := range firefoxBinaries {
		if p, err := exec.LookPath(b); err == nil {
			return browser{p, "firefox"}
		}
	}
	return browser{}
}

// BrowserAvailable reports whether any headless browser is present (UI hint).
func BrowserAvailable() bool { return findBrowser().path != "" }

// ScreenshotSource captures a PNG screenshot of each live web host with whatever
// headless browser is already installed (Chromium or Firefox), recording the
// file path on the URL node. Active; gated on consent, the config toggle, and a
// browser being present. Nothing to install if the system has either browser.
type ScreenshotSource struct{ Cfg config.Config }

func (ScreenshotSource) Name() string      { return "screenshots" }
func (ScreenshotSource) Stage() core.Stage { return core.StageEnrich }
func (s ScreenshotSource) Applicable(core.Target) bool {
	return s.Cfg.Screenshots && BrowserAvailable()
}

func (s ScreenshotSource) Run(ctx context.Context, c *core.Collector) error {
	b := findBrowser()
	if b.path == "" {
		return nil
	}
	bases := liveBaseURLs(c)
	// A few browsers in parallel: one at a time took 30s per slow host, so a
	// target with dozens of web hosts ran past the scan budget.
	sem := make(chan struct{}, screenshotWorkers)
	var wg sync.WaitGroup
	var count atomic.Int64
	for _, base := range bases {
		if ctx.Err() != nil || !inScopeURL(c, base) {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(base string) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			if path, err := Capture(ctx, base); err == nil {
				c.Node(graph.NodeURL, base, base, map[string]any{"screenshot": path})
				count.Add(1)
				c.Flush()
			}
		}(base)
	}
	wg.Wait()
	c.Log(core.LogInfo, "скриншоты: снято "+itoa(int(count.Load()))+"/"+itoa(len(bases))+" ("+b.kind+")")
	return nil
}

// screenshotWorkers is how many pages one scan captures at once.
const screenshotWorkers = 3

// maxBrowsers caps headless browsers running at the same time across the whole
// process (the scan's screenshot source plus on-demand captures from the UI),
// so clicking through many nodes can never spawn dozens of browsers.
const maxBrowsers = 4

// captureTimeout bounds one browser run, whoever asked for it.
const captureTimeout = 30 * time.Second

var (
	// ErrNoBrowser means neither Chromium nor Firefox is installed.
	ErrNoBrowser = errors.New("для скриншотов в системе нужен Chromium или Firefox")
	// ErrCaptureFailed means the browser ran but produced no image.
	ErrCaptureFailed = errors.New("браузер не смог снять страницу (она не открылась или истекло время)")

	browserSlots = make(chan struct{}, maxBrowsers)
	flightMu     sync.Mutex
	flights      = map[string]*captureFlight{} // keyed by output path (= URL)
)

// captureFlight is one in-progress browser run that every caller asking for
// the same URL waits on.
type captureFlight struct {
	done chan struct{}
	ok   bool
}

// ScreenshotPath is where the screenshot of a URL is stored (one file per URL;
// a new capture replaces it).
func ScreenshotPath(url string) (string, error) {
	dir, err := screenshotDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, shortHash(url)+".png"), nil
}

// Capture takes a screenshot of url with the installed headless browser and
// returns the PNG path. Concurrent calls for the same URL share ONE browser
// run; at most maxBrowsers run at once. The run is detached from the caller:
// a caller that gives up (ctx done) returns immediately, while the run still
// finishes within captureTimeout and its image is reused next time.
func Capture(ctx context.Context, url string) (string, error) {
	if !isWebURL(url) {
		return "", errors.New("скриншот можно сделать только для http(s)-страниц")
	}
	b := findBrowser()
	if b.path == "" {
		return "", ErrNoBrowser
	}
	out, err := ScreenshotPath(url)
	if err != nil {
		return "", err
	}

	flightMu.Lock()
	f := flights[out]
	if f == nil {
		f = &captureFlight{done: make(chan struct{})}
		flights[out] = f
		go func() {
			defer func() {
				flightMu.Lock()
				delete(flights, out)
				flightMu.Unlock()
				close(f.done)
			}()
			rctx, cancel := context.WithTimeout(context.Background(), captureTimeout)
			defer cancel()
			select {
			case browserSlots <- struct{}{}:
				defer func() { <-browserSlots }()
			case <-rctx.Done():
				return
			}
			f.ok = runBrowser(rctx, b, url, out)
		}()
	}
	flightMu.Unlock()

	select {
	case <-f.done:
		if f.ok {
			return out, nil
		}
		return "", ErrCaptureFailed
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// isWebURL reports whether u is an absolute http(s) URL.
func isWebURL(u string) bool {
	l := strings.ToLower(strings.TrimSpace(u))
	return (strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://")) && len(l) > len("https://")
}

// chromeArgs builds the headless Chromium command line. The renderer sandbox
// stays ON: the browser loads pages of the (possibly hostile) target, and
// --no-sandbox would turn any renderer bug into code execution as the user.
// Chromium refuses to start as root with the sandbox, so only then is it off.
func chromeArgs(url, out string, root bool) []string {
	args := []string{"--headless=new", "--disable-gpu", "--hide-scrollbars",
		"--disable-dev-shm-usage", "--window-size=1280,800",
		// --timeout: hard stop at 10 s — a hanging resource no longer blocks
		// the capture; what has rendered by then is saved.
		"--virtual-time-budget=8000", "--timeout=10000", "--screenshot=" + out}
	if root {
		args = append(args, "--no-sandbox")
	}
	return append(args, url)
}

// runBrowser renders url into out. Firefox: a tab of the persistent BiDi
// browser (fast, see bidi.go), falling back to a one-shot CLI run only when
// the BiDi browser itself is unavailable. The image goes to a unique temp file
// that replaces out only on success.
func runBrowser(ctx context.Context, b browser, url, out string) bool {
	if b.kind == "firefox" && !disableBidi {
		png, err := captureBidi(ctx, b.path, url)
		if err == nil {
			return writeAtomic(out, png)
		}
		var pe errPage
		if errors.As(err, &pe) || ctx.Err() != nil {
			return false // the page failed; another browser would not do better
		}
		// BiDi unavailable (old Firefox, launch failure…): one-shot CLI below.
	}
	return runBrowserCLI(ctx, b, url, out)
}

// disableBidi forces the one-shot CLI path (tests).
var disableBidi = false

// captureBidi captures url as a tab of the shared Firefox.
func captureBidi(ctx context.Context, path, url string) ([]byte, error) {
	conn, release, err := firefoxPool.get(ctx, path)
	if err != nil {
		return nil, err
	}
	defer release()
	return conn.capture(ctx, url)
}

// writeAtomic writes data to a temp file next to out and renames it over out.
func writeAtomic(out string, data []byte) bool {
	tf, err := os.CreateTemp(filepath.Dir(out), ".shot-*.png")
	if err != nil {
		return false
	}
	tmp := tf.Name()
	_, werr := tf.Write(data)
	cerr := tf.Close()
	if werr != nil || cerr != nil || os.Rename(tmp, out) != nil {
		_ = os.Remove(tmp)
		return false
	}
	return true
}

// runBrowserCLI is the one-shot fallback: a whole browser per page.
func runBrowserCLI(ctx context.Context, b browser, url, out string) bool {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tf, err := os.CreateTemp(filepath.Dir(out), ".shot-*.png")
	if err != nil {
		return false
	}
	tmp := tf.Name()
	_ = tf.Close() // empty: a browser that writes nothing leaves size 0 → failure

	var cmd *exec.Cmd
	switch b.kind {
	case "firefox":
		// A throwaway profile with -no-remote guarantees a fresh headless
		// instance even when the user already has Firefox open (otherwise the
		// command would attach to the running browser and never screenshot).
		prof, err := os.MkdirTemp("", "osint-forge-ff-*")
		if err != nil {
			return false
		}
		defer os.RemoveAll(prof)
		cmd = exec.CommandContext(cctx, b.path,
			"--headless", "--no-remote", "--profile", prof,
			"--window-size=1280,800", "--screenshot", tmp, url)
	default: // chrome family
		cmd = exec.CommandContext(cctx, b.path, chromeArgs(url, tmp, os.Geteuid() == 0)...)
	}
	// The browser writes to a temp file that replaces the final PNG only on
	// success: a stale image from an earlier scan is never mistaken for a fresh
	// capture, and a failed capture keeps the earlier scan's image intact.
	defer os.Remove(tmp)
	if err := cmd.Run(); err != nil {
		return false
	}
	if info, err := os.Stat(tmp); err != nil || info.Size() == 0 {
		return false
	}
	return os.Rename(tmp, out) == nil
}

func screenshotDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "osint-forge", "screenshots")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

func shortHash(s string) string {
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:8])
}
