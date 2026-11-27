package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"osint-forge/internal/config"
	"osint-forge/internal/graph"
	"osint-forge/internal/history"
	"osint-forge/internal/notes"
	"osint-forge/internal/notify"
	"osint-forge/internal/report"
)

// newRouter wires the JSON API, the SSE event stream and the embedded SPA.
func newRouter(a *App, dist fs.FS) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/events", a.handleEvents)
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		running, target := a.Status()
		writeJSON(w, map[string]any{"running": running, "target": target})
	})
	mux.HandleFunc("GET /api/parse", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, a.ParseTarget(r.URL.Query().Get("target")))
	})
	mux.HandleFunc("POST /api/scan", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Target  string `json:"target"`
			Consent bool   `json:"consent"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		if err := a.StartScan(req.Target, req.Consent); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/cancel", func(w http.ResponseWriter, r *http.Request) {
		a.CancelScan()
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /api/snapshot", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, a.Snapshot())
	})
	mux.HandleFunc("GET /api/diff", func(w http.ResponseWriter, r *http.Request) {
		d, err := a.DiffPrevious(r.URL.Query().Get("target"))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, d)
	})
	mux.HandleFunc("GET /api/config", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, a.GetConfig())
	})
	mux.HandleFunc("PUT /api/config", func(w http.ResponseWriter, r *http.Request) {
		var cfg config.Config
		if !readJSON(w, r, &cfg) {
			return
		}
		if err := a.SaveConfig(cfg); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /api/nmap", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, a.NmapInstalled())
	})
	mux.HandleFunc("GET /api/page", func(w http.ResponseWriter, r *http.Request) {
		p, err := a.FetchPage(r.URL.Query().Get("url"))
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, p)
	})
	mux.HandleFunc("GET /api/timings", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, a.Timings())
	})

	// --- scan history ---
	mux.HandleFunc("GET /api/history", func(w http.ResponseWriter, r *http.Request) {
		ts, err := history.Targets()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		if ts == nil {
			ts = []history.TargetSummary{}
		}
		writeJSON(w, ts)
	})
	mux.HandleFunc("GET /api/history/{target}", func(w http.ResponseWriter, r *http.Request) {
		l, err := history.List(historyLabel(r.PathValue("target")))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, l)
	})
	mux.HandleFunc("GET /api/history/{target}/compare", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		c, err := history.CompareScans(historyLabel(r.PathValue("target")), q.Get("from"), q.Get("to"))
		if err != nil {
			writeErr(w, http.StatusNotFound, err)
			return
		}
		writeJSON(w, c)
	})
	mux.HandleFunc("POST /api/history/{target}/{id}/open", func(w http.ResponseWriter, r *http.Request) {
		d, err := a.OpenScan(r.PathValue("target"), r.PathValue("id"))
		if err != nil {
			writeErr(w, http.StatusConflict, err)
			return
		}
		writeJSON(w, d)
	})
	mux.HandleFunc("DELETE /api/history/{target}/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := history.Delete(historyLabel(r.PathValue("target")), r.PathValue("id")); err != nil {
			writeErr(w, http.StatusNotFound, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})

	// --- pentester notes / tags ---
	mux.HandleFunc("GET /api/notes", func(w http.ResponseWriter, r *http.Request) {
		all, err := notes.Load(a.labelFor(r.URL.Query().Get("target")))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, all)
	})
	mux.HandleFunc("PUT /api/notes", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Target string   `json:"target"`
			Node   string   `json:"node"`
			Tags   []string `json:"tags"`
			Text   string   `json:"text"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		n, err := notes.Set(a.labelFor(req.Target), req.Node, notes.Note{Tags: req.Tags, Text: req.Text})
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, n)
	})

	// --- continuous monitoring ---
	mux.HandleFunc("GET /api/monitor", func(w http.ResponseWriter, r *http.Request) {
		if a.monitor == nil {
			writeJSON(w, []any{})
			return
		}
		writeJSON(w, a.monitor.List())
	})
	mux.HandleFunc("POST /api/monitor", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Target      string       `json:"target"`
			IntervalMin int          `json:"intervalMin"`
			Consent     bool         `json:"consent"`
			Filter      *AlertFilter `json:"filter"`
			Preset      string       `json:"preset"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		// An explicit filter wins; else a preset name; else every change.
		filter := PresetFilter(req.Preset)
		if req.Filter != nil {
			filter = *req.Filter
		}
		watch, err := a.monitor.AddWatch(req.Target, req.IntervalMin, req.Consent, filter)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, watch)
	})
	mux.HandleFunc("DELETE /api/monitor/{target}", func(w http.ResponseWriter, r *http.Request) {
		a.monitor.Remove(r.PathValue("target"))
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/notify/test", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		cfg := a.cfg
		a.mu.Unlock()
		nc := notify.Config{TelegramToken: cfg.TelegramToken, TelegramChatID: cfg.TelegramChatID, WebhookURL: cfg.WebhookURL}
		if !nc.Enabled() {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("Telegram или webhook не настроены"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		if err := notify.Send(ctx, nc, "✅ Тестовое сообщение osint-forge — уведомления работают."); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})

	mux.HandleFunc("GET /api/screenshot", a.handleScreenshot)
	mux.HandleFunc("POST /api/screenshot", a.handleCapture)
	mux.HandleFunc("GET /api/export/{format}", a.handleExport)

	// SPA: serve built assets, fall back to index.html for unknown paths.
	files := http.FileServerFS(dist)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p != "" {
			if _, err := fs.Stat(dist, p); err != nil {
				r.URL.Path = "/"
			}
		}
		files.ServeHTTP(w, r)
	})

	return guard(mux)
}

// guard blocks cross-site requests: a malicious web page open in the same
// browser must not be able to start scans or read results from this local API
// (CSRF / DNS-rebinding). Only same-origin requests reach the API.
func guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if origin := r.Header.Get("Origin"); origin != "" {
				u, err := url.Parse(origin)
				if err != nil || u.Host != r.Host {
					http.Error(w, "кросс-доменный запрос заблокирован", http.StatusForbidden)
					return
				}
			}
			if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
				http.Error(w, "межсайтовый запрос заблокирован", http.StatusForbidden)
				return
			}
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// handleEvents streams scan:delta / scan:log / scan:progress as SSE.
func (a *App) handleEvents(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "потоковая передача не поддерживается", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := a.hub.Subscribe()
	defer a.hub.Unsubscribe(ch)

	fmt.Fprint(w, "retry: 1500\n: connected\n\n")
	fl.Flush()

	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		case msg, ok := <-ch:
			if !ok {
				return // dropped as too slow; browser reconnects + resyncs
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", msg.event, msg.data)
			// Drain whatever else is queued before flushing (batch writes).
		drain:
			for n := 0; n < 256; n++ {
				select {
				case m, ok := <-ch:
					if !ok {
						fl.Flush()
						return
					}
					fmt.Fprintf(w, "event: %s\ndata: %s\n\n", m.event, m.data)
				default:
					break drain
				}
			}
			fl.Flush()
		}
	}
}

// handleScreenshot serves a captured PNG, but only from the screenshot cache dir.
func (a *App) handleScreenshot(w http.ResponseWriter, r *http.Request) {
	base, err := os.UserCacheDir()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	dir := filepath.Join(base, "osint-forge", "screenshots")
	p := filepath.Clean(r.URL.Query().Get("path"))
	rel, err := filepath.Rel(dir, p)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		http.Error(w, "доступ запрещён", http.StatusForbidden)
		return
	}
	// The same path is overwritten by every new capture of that URL: always
	// revalidate, or "Yangilash" would keep showing the cached old image.
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeFile(w, r, p)
}

// handleExport returns the current graph as a downloadable report.
func (a *App) handleExport(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	a.mu.Lock()
	g := a.g
	a.mu.Unlock()
	snap := a.annotated(g.Snapshot())

	var (
		data  []byte
		err   error
		name  string
		ctype string
	)
	switch r.PathValue("format") {
	case "json":
		data, err = report.JSON(snap)
		name, ctype = "osint-forge-report.json", "application/json"
	case "html":
		data = []byte(report.HTML(snap, target))
		name, ctype = "osint-forge-report.html", "text/html; charset=utf-8"
	case "md":
		data = []byte(report.Markdown(snap, target))
		name, ctype = "osint-forge-report.md", "text/markdown; charset=utf-8"
	case "csv":
		data, err = report.CSV(snap)
		name, ctype = "osint-forge-report.csv", "text/csv; charset=utf-8"
	case "sarif":
		data, err = report.SARIF(snap, target)
		name, ctype = "osint-forge-report.sarif", "application/sarif+json"
	case "obsidian":
		// Build from the annotated snapshot so the vault carries pentester notes too.
		data, err = obsidianZip(graph.FromDelta(snap).ExportVault)
		name, ctype = "osint-forge-vault.zip", "application/zip"
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	_, _ = w.Write(data)
}

// obsidianZip writes the vault into a temp dir and zips it for download.
func obsidianZip(export func(string) (int, error)) ([]byte, error) {
	tmp, err := os.MkdirTemp("", "osint-forge-vault-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	vault := filepath.Join(tmp, "osint-forge")
	if _, err := export(vault); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	err = filepath.WalkDir(vault, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(tmp, p)
		f, err := zw.Create(filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		src, err := os.Open(p)
		if err != nil {
			return err
		}
		defer src.Close()
		_, err = io.Copy(f, src)
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// --- helpers ---

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		http.Error(w, "Content-Type должен быть application/json", http.StatusUnsupportedMediaType)
		return false
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
