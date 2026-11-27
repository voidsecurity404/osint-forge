package scan

// Fast screenshots: ONE persistent headless Firefox driven over WebDriver BiDi
// (built into Firefox — nothing extra to install). Each screenshot is a tab in
// that browser instead of a whole new browser process.
//
// Why: `firefox --screenshot URL` started a fresh browser + profile for every
// page (~1 s of pure overhead) and waited for the page's `load` event — every
// image, script and tracker. On real targets something always hangs (a closed
// port, a dead CDN, analytics), so captures took 8–30 s or produced NOTHING
// after being killed at the timeout. Here a page is captured as soon as it has
// loaded, or — when some resource hangs — shortly after its DOM is ready, with
// whatever has rendered by then. Self-signed certificates are accepted.

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/websocket"
)

// Page-wait budget of one capture.
var (
	// bidiHardWait: no DOM at all by then → the page did not answer (failure).
	bidiHardWait = 15 * time.Second
	// bidiAfterDOM: once the DOM is ready, how long to wait for `load` (images,
	// scripts…) before capturing what has rendered so far.
	bidiAfterDOM = 3 * time.Second
	// bidiSettle: after `load`, a short pause for late paints/fonts.
	bidiSettle = 120 * time.Millisecond
	// bidiIdle: the browser is closed after this long without captures.
	bidiIdle = 3 * time.Minute
)

// errPage marks a failure of the PAGE (unreachable, error page): another
// browser would not do better, so there is no CLI fallback for it.
type errPage struct{ msg string }

func (e errPage) Error() string { return e.msg }

// bidiConn is a WebDriver BiDi session over one websocket.
type bidiConn struct {
	ws     *websocket.Conn
	sendMu sync.Mutex
	nextID atomic.Int64

	mu      sync.Mutex
	pending map[int64]chan bidiMsg
	subs    map[string]chan bidiMsg // browsing context → its events
	err     error                   // set when the connection died
	done    chan struct{}
}

type bidiMsg struct {
	Type    string          `json:"type"` // success | error | event
	ID      int64           `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	Result  json.RawMessage `json:"result"`
	Error   string          `json:"error"`
	Message string          `json:"message"`
}

func newBidiConn(ws *websocket.Conn) *bidiConn {
	c := &bidiConn{ws: ws, pending: map[int64]chan bidiMsg{}, subs: map[string]chan bidiMsg{}, done: make(chan struct{})}
	ws.MaxPayloadBytes = 64 << 20 // full-page PNGs arrive base64-encoded
	go c.readLoop()
	return c
}

func (c *bidiConn) readLoop() {
	var err error
	for {
		var raw []byte
		if err = websocket.Message.Receive(c.ws, &raw); err != nil {
			break
		}
		var m bidiMsg
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		c.mu.Lock()
		if m.Type == "event" {
			var p struct {
				Context string `json:"context"`
			}
			_ = json.Unmarshal(m.Params, &p)
			if ch := c.subs[p.Context]; ch != nil {
				select {
				case ch <- m:
				default: // nobody waiting for more; drop
				}
			}
		} else if ch := c.pending[m.ID]; ch != nil {
			delete(c.pending, m.ID)
			ch <- m
		}
		c.mu.Unlock()
	}
	c.mu.Lock()
	c.err = fmt.Errorf("соединение BiDi закрыто: %w", err)
	for id, ch := range c.pending {
		delete(c.pending, id)
		close(ch)
	}
	c.mu.Unlock()
	close(c.done)
}

func (c *bidiConn) alive() bool {
	select {
	case <-c.done:
		return false
	default:
		return true
	}
}

// call sends one command and waits for its result.
func (c *bidiConn) call(ctx context.Context, method string, params any, out any) error {
	id := c.nextID.Add(1)
	ch := make(chan bidiMsg, 1)
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return c.err
	}
	c.pending[id] = ch
	c.mu.Unlock()
	msg, _ := json.Marshal(map[string]any{"id": id, "method": method, "params": params})
	c.sendMu.Lock()
	err := websocket.Message.Send(c.ws, string(msg))
	c.sendMu.Unlock()
	if err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return fmt.Errorf("отправка BiDi: %w", err)
	}
	select {
	case m, ok := <-ch:
		if !ok {
			return errors.New("соединение BiDi закрыто")
		}
		if m.Type == "error" {
			return fmt.Errorf("%s: %s %s", method, m.Error, m.Message)
		}
		if out != nil {
			return json.Unmarshal(m.Result, out)
		}
		return nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return ctx.Err()
	}
}

func (c *bidiConn) subscribe(context string) chan bidiMsg {
	ch := make(chan bidiMsg, 16)
	c.mu.Lock()
	c.subs[context] = ch
	c.mu.Unlock()
	return ch
}

func (c *bidiConn) unsubscribe(context string) {
	c.mu.Lock()
	delete(c.subs, context)
	c.mu.Unlock()
}

// start opens the session: insecure certificates accepted (recon targets
// often use self-signed ones) and load events delivered.
func (c *bidiConn) start(ctx context.Context) error {
	caps := map[string]any{"capabilities": map[string]any{"alwaysMatch": map[string]any{"acceptInsecureCerts": true}}}
	if err := c.call(ctx, "session.new", caps, nil); err != nil {
		return err
	}
	return c.call(ctx, "session.subscribe", map[string]any{
		"events": []string{"browsingContext.load", "browsingContext.domContentLoaded"},
	}, nil)
}

// capture renders url in a new tab and returns the PNG.
func (c *bidiConn) capture(ctx context.Context, url string) ([]byte, error) {
	var created struct {
		Context string `json:"context"`
	}
	if err := c.call(ctx, "browsingContext.create", map[string]any{"type": "tab", "background": true}, &created); err != nil {
		return nil, err
	}
	tab := created.Context
	events := c.subscribe(tab)
	defer func() {
		c.unsubscribe(tab)
		cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = c.call(cctx, "browsingContext.close", map[string]any{"context": tab}, nil)
	}()
	// wait:"none" — we decide ourselves how long to wait (see below).
	var nav struct {
		Navigation string `json:"navigation"`
	}
	if err := c.call(ctx, "browsingContext.navigate", map[string]any{"context": tab, "url": url, "wait": "none"}, &nav); err != nil {
		return nil, errPage{"страница не открылась: " + err.Error()}
	}

	hard := time.NewTimer(bidiHardWait)
	defer hard.Stop()
	var afterDOM <-chan time.Time
	loaded, dom := false, false
wait:
	for {
		select {
		case m := <-events:
			// Only events of OUR navigation: a fresh tab also fires load for
			// its initial about:blank, which would yield an empty capture.
			var ev struct {
				Navigation string `json:"navigation"`
				URL        string `json:"url"`
			}
			_ = json.Unmarshal(m.Params, &ev)
			if ev.URL == "about:blank" || (nav.Navigation != "" && ev.Navigation != "" && ev.Navigation != nav.Navigation) {
				continue
			}
			switch m.Method {
			case "browsingContext.domContentLoaded":
				if !dom {
					dom = true
					afterDOM = time.After(bidiAfterDOM)
				}
			case "browsingContext.load":
				dom, loaded = true, true
				break wait
			}
		case <-afterDOM:
			break wait // DOM ready, some resource hangs: capture what rendered
		case <-hard.C:
			break wait
		case <-c.done:
			return nil, errors.New("соединение BiDi закрыто")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if !dom {
		return nil, errPage{fmt.Sprintf("страница не ответила за %s", bidiHardWait)}
	}
	if loaded {
		select {
		case <-time.After(bidiSettle):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	// Firefox shows its own page for DNS/connection/TLS failures — that is not
	// a screenshot of the target.
	var doc struct {
		Type   string `json:"type"`
		Result struct {
			Value string `json:"value"`
		} `json:"result"`
	}
	if err := c.call(ctx, "script.evaluate", map[string]any{
		"expression": "document.documentURI", "target": map[string]string{"context": tab}, "awaitPromise": false,
	}, &doc); err == nil && strings.HasPrefix(doc.Result.Value, "about:") && strings.Contains(doc.Result.Value, "error") {
		return nil, errPage{"страница не открылась (" + strings.SplitN(doc.Result.Value, "?", 2)[0] + ")"}
	}
	var shot struct {
		Data string `json:"data"`
	}
	if err := c.call(ctx, "browsingContext.captureScreenshot", map[string]any{"context": tab, "origin": "viewport"}, &shot); err != nil {
		return nil, err
	}
	png, err := base64.StdEncoding.DecodeString(shot.Data)
	if err != nil || len(png) == 0 {
		return nil, errors.New("пустой скриншот")
	}
	return png, nil
}

// ---- the persistent Firefox process ---------------------------------------

type bidiProc struct {
	conn    *bidiConn
	cmd     *exec.Cmd
	profile string
}

func (p *bidiProc) close() {
	if p.conn != nil {
		_ = p.conn.ws.Close()
	}
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
		_ = p.cmd.Wait()
	}
	if p.profile != "" {
		_ = os.RemoveAll(p.profile)
	}
}

// firefoxChromeHeight is the height of the (invisible) tab strip + toolbar
// that headless Firefox still subtracts from the screen for the viewport.
const firefoxChromeHeight = 86

// bidiOrigin is the Origin our websocket client sends.
const bidiOrigin = "http://localhost"

var bidiListenRe = regexp.MustCompile(`WebDriver BiDi listening on (ws://\S+)`)

// firefoxPrefs keep a throwaway profile quiet: no updates, telemetry or
// first-run pages, no background traffic of its own.
const firefoxPrefs = `user_pref("app.update.disabledForTesting", true);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("browser.aboutwelcome.enabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("toolkit.telemetry.reportingpolicy.firstRun", false);
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("network.captive-portal-service.enabled", false);
user_pref("extensions.update.enabled", false);
user_pref("media.autoplay.default", 5);
`

// removeStaleProfiles deletes throwaway profiles left by an osint-forge that
// was killed (kill -9 / crash skip the cleanup). Each profile records its
// owner's pid; profiles of a still-running instance are kept.
func removeStaleProfiles() {
	dirs, _ := filepath.Glob(filepath.Join(os.TempDir(), "osint-forge-bidi-*"))
	for _, d := range dirs {
		b, err := os.ReadFile(filepath.Join(d, ".owner"))
		if err != nil {
			continue // not ours, or still being created
		}
		var pid int
		if _, err := fmt.Sscan(string(b), &pid); err == nil && !processAlive(pid) {
			_ = os.RemoveAll(d)
		}
	}
}

func launchFirefoxBidi(ctx context.Context, path string) (*bidiProc, error) {
	removeStaleProfiles()
	profile, err := os.MkdirTemp("", "osint-forge-bidi-*")
	if err != nil {
		return nil, err
	}
	p := &bidiProc{profile: profile}
	_ = os.WriteFile(filepath.Join(profile, ".owner"), []byte(fmt.Sprint(os.Getpid())), 0o600)
	_ = os.WriteFile(filepath.Join(profile, "user.js"), []byte(firefoxPrefs), 0o600)
	// Not CommandContext: the browser outlives the request that started it.
	// The websocket client always sends an Origin header, and Firefox's remote
	// agent rejects any Origin it was not told about ("bad status") — allow
	// exactly the one we send. The agent listens on 127.0.0.1 only.
	cmd := exec.Command(path, "--headless", "--no-remote", "--profile", profile,
		"--remote-debugging-port=0", "--remote-allow-origins="+bidiOrigin,
		// every tab inherits this size: no per-tab setViewport (it costs ~1 s)
		"--window-size=1280,800", "about:blank")
	// Headless screen size: tabs get their viewport from it (the toolbar takes
	// the rest), so no per-tab setViewport round trip is needed.
	cmd.Env = append(os.Environ(), "MOZ_HEADLESS_WIDTH=1280", fmt.Sprintf("MOZ_HEADLESS_HEIGHT=%d", 800+firefoxChromeHeight))
	dieWithParent(cmd)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		p.close()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		p.close()
		return nil, err
	}
	p.cmd = cmd
	found := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			if m := bidiListenRe.FindStringSubmatch(sc.Text()); m != nil {
				found <- m[1]
				break
			}
		}
		_, _ = io.Copy(io.Discard, stderr) // keep draining or Firefox blocks
	}()
	var wsURL string
	select {
	case wsURL = <-found:
	case <-time.After(20 * time.Second):
		p.close()
		return nil, errors.New("Firefox BiDi не запустился")
	case <-ctx.Done():
		p.close()
		return nil, ctx.Err()
	}
	ws, err := websocket.Dial(strings.TrimSuffix(wsURL, "/")+"/session", "", bidiOrigin)
	if err != nil {
		p.close()
		return nil, err
	}
	p.conn = newBidiConn(ws)
	if err := p.conn.start(ctx); err != nil {
		p.close()
		return nil, err
	}
	return p, nil
}

// bidiPool shares one browser between all captures; it is started on first
// use, restarted when it dies and closed after bidiIdle without use.
type bidiPool struct {
	mu       sync.Mutex
	proc     *bidiProc
	starting chan struct{} // closed when an in-progress launch finishes
	users    int
	idle     *time.Timer
	broken   time.Time // last launch failure: fall back to the CLI for a while
}

var firefoxPool = &bidiPool{}

// get returns a live browser connection (launching one if needed) and a
// release func the caller must call when done.
func (bp *bidiPool) get(ctx context.Context, path string) (*bidiConn, func(), error) {
	for {
		bp.mu.Lock()
		if time.Since(bp.broken) < time.Minute {
			bp.mu.Unlock()
			return nil, nil, errors.New("BiDi временно недоступен")
		}
		if bp.proc != nil && !bp.proc.conn.alive() {
			bp.proc.close()
			bp.proc = nil
		}
		if bp.proc != nil {
			bp.users++
			if bp.idle != nil {
				bp.idle.Stop()
			}
			conn := bp.proc.conn
			bp.mu.Unlock()
			return conn, bp.release, nil
		}
		if wait := bp.starting; wait != nil {
			bp.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
		}
		bp.starting = make(chan struct{})
		bp.mu.Unlock()

		// Launch detached from the caller: others may be waiting on it.
		lctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		proc, err := launchFirefoxBidi(lctx, path)
		cancel()
		bp.mu.Lock()
		close(bp.starting)
		bp.starting = nil
		if err != nil {
			bp.broken = time.Now()
			bp.mu.Unlock()
			return nil, nil, err
		}
		bp.proc = proc
		bp.mu.Unlock()
	}
}

func (bp *bidiPool) release() {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	bp.users--
	if bp.users > 0 {
		return
	}
	if bp.idle != nil {
		bp.idle.Stop()
	}
	bp.idle = time.AfterFunc(bidiIdle, func() {
		bp.mu.Lock()
		defer bp.mu.Unlock()
		if bp.users == 0 && bp.proc != nil {
			bp.proc.close()
			bp.proc = nil
		}
	})
}

// Close shuts the browser down (server exit).
func (bp *bidiPool) Close() {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	if bp.proc != nil {
		bp.proc.close()
		bp.proc = nil
	}
}

// ShutdownBrowsers stops the persistent screenshot browser, if running.
func ShutdownBrowsers() { firefoxPool.Close() }
