package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"osint-forge/internal/graph"
	"osint-forge/internal/scan"
)

// captureWait bounds how long the UI waits for an on-demand screenshot.
const captureWait = 45 * time.Second

type captureRequest struct {
	URL string `json:"url"`
	// Force takes a fresh screenshot even when one is stored ("Yangilash").
	Force bool `json:"force"`
	// Auto marks a capture the UI started by itself when a node was opened
	// (as opposed to the user clicking a button). Auto captures only touch
	// pages the scan already requested and honour the "screenshots" setting.
	Auto bool `json:"auto"`
}

type captureResponse struct {
	URL     string    `json:"url"`
	Path    string    `json:"path"`
	TakenAt time.Time `json:"takenAt"`
	Cached  bool      `json:"cached"`
}

// handleCapture returns the screenshot of one URL node, taking it on demand
// when none is stored yet: POST /api/screenshot {url, force?, auto?}.
func (a *App) handleCapture(w http.ResponseWriter, r *http.Request) {
	var req captureRequest
	if !readJSON(w, r, &req) {
		return
	}
	u := strings.TrimSpace(req.URL)
	l := strings.ToLower(u)
	if !strings.HasPrefix(l, "http://") && !strings.HasPrefix(l, "https://") {
		writeErr(w, http.StatusBadRequest, errors.New("скриншот можно сделать только для http(s)-страниц"))
		return
	}
	path, err := scan.ScreenshotPath(u)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	// A stored image costs nothing to show — no request reaches the target.
	if !req.Force {
		if info, err := os.Stat(path); err == nil && info.Size() > 0 {
			a.setScreenshot(u, path)
			writeJSON(w, captureResponse{URL: u, Path: path, TakenAt: info.ModTime(), Cached: true})
			return
		}
	}

	a.mu.Lock()
	g, cfg := a.g, a.cfg
	a.mu.Unlock()
	node, ok := g.Copy(graph.NodeID(graph.NodeURL, u))
	if !ok {
		writeErr(w, http.StatusNotFound, errors.New("этого URL нет в текущем графе"))
		return
	}
	if req.Auto {
		if !cfg.Screenshots {
			writeErr(w, http.StatusConflict, errors.New("скриншоты отключены в настройках — нажмите кнопку, чтобы сделать снимок"))
			return
		}
		if _, contacted := node.Props["status"]; !contacted {
			writeErr(w, http.StatusConflict, errors.New("во время сканирования к этой странице не обращались (архив/sitemap/JS) — нажмите кнопку, чтобы сделать снимок"))
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), captureWait)
	defer cancel()
	p, err := scan.Capture(ctx, u)
	switch {
	case err == nil:
	case errors.Is(err, scan.ErrNoBrowser):
		writeErr(w, http.StatusNotImplemented, err)
		return
	case r.Context().Err() != nil:
		return // the user moved on to another node; nobody is listening
	case ctx.Err() != nil:
		writeErr(w, http.StatusGatewayTimeout, errors.New("скриншот не успел сформироваться — попробуйте позже"))
		return
	default:
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	taken := time.Now()
	if info, err := os.Stat(p); err == nil {
		taken = info.ModTime()
	}
	a.setScreenshot(u, p)
	writeJSON(w, captureResponse{URL: u, Path: p, TakenAt: taken})
}

// setScreenshot records the image on the URL node of the current graph (so the
// gallery and exports include it) and pushes the change to every open tab.
func (a *App) setScreenshot(url, path string) {
	a.mu.Lock()
	g := a.g
	a.mu.Unlock()
	id := graph.NodeID(graph.NodeURL, url)
	cur, ok := g.Copy(id)
	if !ok || cur.Props["screenshot"] == path {
		return
	}
	n, _ := g.AddNode(&graph.Node{ID: id, Type: graph.NodeURL, Props: map[string]any{"screenshot": path}})
	a.publish(evtDelta, graph.Delta{Nodes: []*graph.Node{n}})
}
