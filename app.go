package main

import (
	"context"
	"errors"
	"sync"
	"time"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/cve"
	"osint-forge/internal/graph"
	"osint-forge/internal/history"
	"osint-forge/internal/recon"
	"osint-forge/internal/scan"
)

// SSE event names consumed by the frontend.
const (
	evtStart    = "scan:start" // a scan began (from any tab or the monitor): reset the view
	evtDelta    = "scan:delta"
	evtLog      = "scan:log"
	evtProgress = "scan:progress"
	evtTiming   = "scan:timing"
	evtReset    = "graph:reset" // the server graph was replaced (history scan opened)
)

// ScanResult is handed to OnScanDone hooks once a scan has finished.
type ScanResult struct {
	Request  ScanRequest
	Snapshot graph.Delta
	// Diff is the change versus the previously stored scan of the target,
	// computed BEFORE this scan was saved (Save may replace an identical scan).
	Diff history.Diff
	// Complete is false when the scan was cancelled or hit its time budget:
	// its result is partial and must not be read as "things disappeared".
	Complete bool
}

// App is the backend behind the HTTP API. Events are pushed to browsers over SSE.
type App struct {
	ctx context.Context
	hub *Hub

	mu       sync.Mutex
	cfg      config.Config
	g        *graph.Graph
	cancel   context.CancelFunc
	running  bool
	target   string
	cveStore *cve.Store
	onDone   []func(ScanResult)
	timings  []core.SourceTiming
	monitor  *Monitor
}

// publish forwards an event to every connected browser (no-op without a hub).
func (a *App) publish(event string, v any) {
	if a.hub != nil {
		a.hub.Publish(event, v)
	}
}

// NewApp creates a new App application struct.
func NewApp() *App {
	cfg, _ := config.Load()
	a := &App{cfg: cfg, g: graph.New(), hub: NewHub(), ctx: context.Background()}
	// Reopen the most recent scan so a server restart doesn't lose the graph.
	if label, d, ok := history.Latest(); ok {
		a.g = graph.FromDelta(d)
		a.target = label
	}
	if p, err := cve.DefaultPath(); err == nil {
		if store, err := cve.Open(p); err == nil {
			a.cveStore = store
		}
	}
	return a
}

// shutdown is called when the app closes; it releases the CVE database.
func (a *App) shutdown() {
	scan.ShutdownBrowsers() // the persistent screenshot browser
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cveStore != nil {
		_ = a.cveStore.Close()
		a.cveStore = nil
	}
}

// --- Emitter implementation (core.Emitter + core.ProgressEmitter) ---

func (a *App) EmitDelta(d graph.Delta)      { a.publish(evtDelta, d) }
func (a *App) EmitLog(l core.LogLine)       { a.publish(evtLog, l) }
func (a *App) EmitProgress(p core.Progress) { a.publish(evtProgress, p) }

// EmitTiming records and broadcasts a per-source timing update.
func (a *App) EmitTiming(t core.SourceTiming) {
	a.mu.Lock()
	replaced := false
	for i := range a.timings {
		if a.timings[i].Name == t.Name {
			a.timings[i] = t
			replaced = true
			break
		}
	}
	if !replaced {
		a.timings = append(a.timings, t)
	}
	a.mu.Unlock()
	a.publish(evtTiming, t)
}

// Timings returns the per-source stats of the current/last scan.
func (a *App) Timings() []core.SourceTiming {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]core.SourceTiming{}, a.timings...)
}

// --- Bound API ---

// ParseTarget lets the UI preview how input will be interpreted.
func (a *App) ParseTarget(raw string) core.Target { return core.ParseTarget(raw) }

// ScanRequest describes one scan to run.
type ScanRequest struct {
	Target     string   `json:"target"`
	Consent    bool     `json:"consent"`              // caller asserts authorization for active probing
	ExtraScope []string `json:"extraScope,omitempty"` // added to the configured scope (project scope)
	Project    string   `json:"project,omitempty"`    // project id that queued it, if any
	Monitor    bool     `json:"-"`                    // true when queued by the scheduler
}

// StartScan begins a scan of the given target. consent must be true for the
// active (nmap/http) stages — the caller is asserting authorization. It returns
// an error if a scan is already running or input is invalid.
func (a *App) StartScan(raw string, consent bool) error {
	return a.startScan(ScanRequest{Target: raw, Consent: consent})
}

// labelOf is the history key of a target (domain, else IP).
func labelOf(t core.Target) string {
	if t.Domain != "" {
		return t.Domain
	}
	return t.IP
}

func (a *App) startScan(req ScanRequest) error {
	t := core.ParseTarget(req.Target)
	if !t.Valid {
		return errors.New("noto'g'ri nishon: to'g'ri IP manzil yoki domen kiriting (masalan 1.1.1.1 yoki example.com)")
	}

	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return errors.New("a scan is already running")
	}
	// Fresh graph per scan.
	a.g = graph.New()
	ctx, cancel := context.WithCancel(a.ctx)
	// Enforce an overall scan budget so a scan can never run unbounded.
	if a.cfg.ScanTimeoutMin > 0 {
		var cancelTimeout context.CancelFunc
		ctx, cancelTimeout = context.WithTimeout(ctx, time.Duration(a.cfg.ScanTimeoutMin)*time.Minute)
		parent := cancel
		cancel = func() { cancelTimeout(); parent() }
	}
	label := labelOf(t)
	a.cancel = cancel
	a.running = true
	a.target = label // normalised: notes, exports and history all key on it
	a.timings = nil
	cfg := a.cfg
	g := a.g
	a.mu.Unlock()

	// Every open tab resets its graph — also for scans it did not start (the
	// monitor, another tab). Published before the pipeline runs, so it always
	// precedes this scan's deltas on each client's stream.
	a.publish(evtStart, map[string]any{"target": label, "consent": req.Consent, "monitor": req.Monitor})

	scope := append(append([]string{}, cfg.ExtraScope...), req.ExtraScope...)
	sources := buildSources(cfg, req.Consent, a.cveStore)
	pipe := core.NewPipeline(a, g, sources...)
	pipe.SetScope(core.NewScope(t, cfg.ScopeStrict, scope))

	go func() {
		defer cancel()
		pipe.Run(ctx, t)
		res := ScanResult{Request: req, Snapshot: g.Snapshot(), Complete: ctx.Err() == nil}
		// Diff first, then persist (Save may replace an identical last scan).
		res.Diff, _ = history.DiffAgainstPrevious(label, res.Snapshot)
		// A partial monitor run is not kept: the next run would report every
		// entity it missed as "new".
		if res.Complete || !req.Monitor {
			_, _ = history.Save(label, res.Snapshot)
		}
		a.mu.Lock()
		a.running = false
		a.cancel = nil
		hooks := append([]func(ScanResult){}, a.onDone...)
		a.mu.Unlock()
		for _, h := range hooks {
			h(res)
		}
	}()
	return nil
}

// OnScanDone registers a callback run after every scan finishes and is saved.
func (a *App) OnScanDone(f func(ScanResult)) {
	a.mu.Lock()
	a.onDone = append(a.onDone, f)
	a.mu.Unlock()
}

// DiffPrevious compares the current graph to the most recent stored scan of the
// same target, reporting what appeared or disappeared since.
func (a *App) DiffPrevious(target string) (history.Diff, error) {
	t := core.ParseTarget(target)
	label := t.Domain
	if label == "" {
		label = t.IP
	}
	return history.DiffLastTwo(label)
}

// CancelScan stops the current scan, if any.
func (a *App) CancelScan() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cancel != nil {
		a.cancel()
	}
}

// Snapshot returns the full current graph, for re-syncing the UI.
func (a *App) Snapshot() graph.Delta {
	a.mu.Lock()
	g := a.g
	a.mu.Unlock()
	return g.Snapshot()
}

// GetConfig returns the current configuration.
func (a *App) GetConfig() config.Config {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg
}

// SaveConfig persists and applies new configuration.
func (a *App) SaveConfig(cfg config.Config) error {
	cfg.Normalize()
	a.mu.Lock()
	a.cfg = cfg
	a.mu.Unlock()
	return config.Save(cfg)
}

// Status reports whether a scan is running and for which target, so a freshly
// opened browser tab can re-sync with an in-progress scan.
func (a *App) Status() (bool, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.running, a.target
}

// NmapInstalled reports whether nmap is available (UI hint).
func (a *App) NmapInstalled() bool { return scan.NmapAvailable() }

// FetchPage fetches a URL on demand so the detail panel can show its status,
// headers and raw HTML ("view HTML").
func (a *App) FetchPage(url string) (scan.Page, error) {
	a.mu.Lock()
	ua := a.cfg.HTTPUserAgent
	a.mu.Unlock()
	ctx, cancel := context.WithTimeout(a.ctx, 20*time.Second)
	defer cancel()
	return scan.FetchPage(ctx, ua, url)
}

// buildSources assembles the source set. Active probing (nmap, portscan, http)
// is only included when the user has asserted authorization. CVE enrichment runs
// whenever the store is available (it is a no-op without discovered services).
func buildSources(cfg config.Config, consent bool, store *cve.Store) []core.Source {
	sources := []core.Source{
		recon.DNSSource{},
		recon.WhoisSource{Cfg: cfg},
		recon.CrtShSource{Cfg: cfg},
		recon.ResolveSource{},
		recon.ReverseIPSource{Cfg: cfg},
		recon.ASNSource{Cfg: cfg},
		recon.WaybackSource{Cfg: cfg},
		recon.OTXSource{Cfg: cfg},
		recon.BruteforceSource{Cfg: cfg},
		recon.ShodanSource{Cfg: cfg},
		recon.CensysSource{Cfg: cfg},
		recon.GitHubSource{Cfg: cfg},
		scan.ParamSource{Cfg: cfg},
	}
	if consent {
		sources = append(sources,
			scan.NmapSource{Cfg: cfg},
			scan.PortScanSource{Cfg: cfg},
			scan.HTTPSource{Cfg: cfg},
			scan.WebPortsSource{Cfg: cfg},
			scan.RobotsSource{Cfg: cfg},
			scan.FuzzSource{Cfg: cfg},
			scan.TLSSource{Cfg: cfg},
			scan.WebChecksSource{Cfg: cfg},
			scan.TakeoverSource{Cfg: cfg},
			scan.BuiltinChecksSource{Cfg: cfg},
			scan.NucleiSource{Cfg: cfg}, // optional: only if external nuclei is installed
			scan.ScreenshotSource{Cfg: cfg},
			scan.JSAnalyzeSource{Cfg: cfg},
			recon.AXFRSource{Cfg: cfg},
			recon.HIBPSource{Cfg: cfg}, // reads emails harvested by the http probe
		)
	}
	if store != nil {
		sources = append(sources, cve.Source{
			Cfg:    cfg,
			Store:  store,
			Client: cve.NewClient(cfg.NVDKey, cfg.HTTPUserAgent),
		})
	}
	return sources
}
