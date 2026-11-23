package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/cve"
	"osint-forge/internal/graph"
	"osint-forge/internal/history"
	"osint-forge/internal/recon"
	"osint-forge/internal/report"
	"osint-forge/internal/scan"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// Wails event channels consumed by the frontend.
const (
	evtDelta    = "scan:delta"
	evtLog      = "scan:log"
	evtProgress = "scan:progress"
)

// App is the Wails-bound backend. Its exported methods are callable from JS.
type App struct {
	ctx context.Context

	mu       sync.Mutex
	cfg      config.Config
	g        *graph.Graph
	cancel   context.CancelFunc
	running  bool
	cveStore *cve.Store
}

// NewApp creates a new App application struct.
func NewApp() *App {
	cfg, _ := config.Load()
	a := &App{cfg: cfg, g: graph.New()}
	if p, err := cve.DefaultPath(); err == nil {
		if store, err := cve.Open(p); err == nil {
			a.cveStore = store
		}
	}
	return a
}

// startup is called when the app starts.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// shutdown is called when the app closes; it releases the CVE database.
func (a *App) shutdown(ctx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cveStore != nil {
		_ = a.cveStore.Close()
		a.cveStore = nil
	}
}

// --- Emitter implementation (core.Emitter + core.ProgressEmitter) ---

func (a *App) EmitDelta(d graph.Delta)      { wruntime.EventsEmit(a.ctx, evtDelta, d) }
func (a *App) EmitLog(l core.LogLine)       { wruntime.EventsEmit(a.ctx, evtLog, l) }
func (a *App) EmitProgress(p core.Progress) { wruntime.EventsEmit(a.ctx, evtProgress, p) }

// --- Bound API ---

// ParseTarget lets the UI preview how input will be interpreted.
func (a *App) ParseTarget(raw string) core.Target { return core.ParseTarget(raw) }

// StartScan begins a scan of the given target. consent must be true for the
// active (nmap/http) stages — the caller is asserting authorization. It returns
// an error if a scan is already running or input is invalid.
func (a *App) StartScan(raw string, consent bool) error {
	t := core.ParseTarget(raw)
	if t.IP == "" && t.Domain == "" {
		return errors.New("invalid target: enter an IP address or domain")
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
	if cfg := a.cfg; cfg.ScanTimeoutMin > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(cfg.ScanTimeoutMin)*time.Minute)
	}
	a.cancel = cancel
	a.running = true
	cfg := a.cfg
	g := a.g
	a.mu.Unlock()

	sources := buildSources(cfg, consent, a.cveStore)
	pipe := core.NewPipeline(a, g, sources...)
	pipe.SetScope(core.NewScope(t, cfg.ScopeStrict, cfg.ExtraScope))

	go func() {
		pipe.Run(ctx, t)
		// Persist this scan so a later run of the same target can be diffed.
		label := t.Domain
		if label == "" {
			label = t.IP
		}
		_, _ = history.Save(label, g.Snapshot())
		a.mu.Lock()
		a.running = false
		a.mu.Unlock()
	}()
	return nil
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
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 16
	}
	a.mu.Lock()
	a.cfg = cfg
	a.mu.Unlock()
	return config.Save(cfg)
}

// NmapInstalled reports whether nmap is available (UI hint).
func (a *App) NmapInstalled() bool { return scan.NmapAvailable() }

// OpenURL opens a URL in the user's default browser (used for CVE/URL nodes).
func (a *App) OpenURL(url string) { wruntime.BrowserOpenURL(a.ctx, url) }

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

// ExportObsidian asks for a folder and writes the current graph there as an
// Obsidian vault (one cross-linked note per node). It returns a status message.
func (a *App) ExportObsidian() (string, error) {
	dir, err := wruntime.OpenDirectoryDialog(a.ctx, wruntime.OpenDialogOptions{
		Title: "Obsidian vault papkasini tanlang",
	})
	if err != nil {
		return "", err
	}
	if dir == "" {
		return "", nil // user cancelled
	}
	a.mu.Lock()
	g := a.g
	a.mu.Unlock()
	n, err := g.ExportVault(dir)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d ta nota yozildi: %s", n, dir), nil
}

// ExportJSON saves the current graph as a JSON file.
func (a *App) ExportJSON() (string, error) {
	path, err := wruntime.SaveFileDialog(a.ctx, wruntime.SaveDialogOptions{
		Title: "JSON hisobotni saqlash", DefaultFilename: "osint-forge-report.json",
	})
	if err != nil || path == "" {
		return "", err
	}
	a.mu.Lock()
	g := a.g
	a.mu.Unlock()
	data, err := report.JSON(g.Snapshot())
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return "JSON saqlandi: " + path, nil
}

// ExportHTML saves a standalone HTML report of the current graph.
func (a *App) ExportHTML(target string) (string, error) {
	path, err := wruntime.SaveFileDialog(a.ctx, wruntime.SaveDialogOptions{
		Title: "HTML hisobotni saqlash", DefaultFilename: "osint-forge-report.html",
	})
	if err != nil || path == "" {
		return "", err
	}
	a.mu.Lock()
	g := a.g
	a.mu.Unlock()
	data := report.HTML(g.Snapshot(), target)
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		return "", err
	}
	return "HTML saqlandi: " + path, nil
}

// ExportMarkdown saves a Markdown report of the current graph.
func (a *App) ExportMarkdown(target string) (string, error) {
	path, err := wruntime.SaveFileDialog(a.ctx, wruntime.SaveDialogOptions{
		Title: "Markdown hisobotni saqlash", DefaultFilename: "osint-forge-report.md",
	})
	if err != nil || path == "" {
		return "", err
	}
	a.mu.Lock()
	g := a.g
	a.mu.Unlock()
	if err := os.WriteFile(path, []byte(report.Markdown(g.Snapshot(), target)), 0o644); err != nil {
		return "", err
	}
	return "Markdown saqlandi: " + path, nil
}

// ExportCSV saves a findings+CVE CSV of the current graph.
func (a *App) ExportCSV() (string, error) {
	path, err := wruntime.SaveFileDialog(a.ctx, wruntime.SaveDialogOptions{
		Title: "CSV hisobotni saqlash", DefaultFilename: "osint-forge-report.csv",
	})
	if err != nil || path == "" {
		return "", err
	}
	a.mu.Lock()
	g := a.g
	a.mu.Unlock()
	data, err := report.CSV(g.Snapshot())
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return "CSV saqlandi: " + path, nil
}

// ExportSARIF saves a SARIF 2.1.0 report (for CI / code-scanning dashboards).
func (a *App) ExportSARIF(target string) (string, error) {
	path, err := wruntime.SaveFileDialog(a.ctx, wruntime.SaveDialogOptions{
		Title: "SARIF hisobotni saqlash", DefaultFilename: "osint-forge-report.sarif",
	})
	if err != nil || path == "" {
		return "", err
	}
	a.mu.Lock()
	g := a.g
	a.mu.Unlock()
	data, err := report.SARIF(g.Snapshot(), target)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return "SARIF saqlandi: " + path, nil
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
	}
	if consent {
		sources = append(sources,
			scan.NmapSource{Cfg: cfg},
			scan.PortScanSource{Cfg: cfg},
			scan.HTTPSource{Cfg: cfg},
			scan.RobotsSource{Cfg: cfg},
			scan.FuzzSource{Cfg: cfg},
			scan.TLSSource{Cfg: cfg},
			scan.WebChecksSource{Cfg: cfg},
			scan.TakeoverSource{Cfg: cfg},
			scan.NucleiSource{Cfg: cfg},
			scan.ScreenshotSource{Cfg: cfg},
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
