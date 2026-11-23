package scan

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// chromeBinaries are the headless-capable browsers we try, in order.
var chromeBinaries = []string{
	"chromium", "chromium-browser", "google-chrome", "google-chrome-stable",
	"chrome", "chrome-headless-shell", "brave-browser",
}

// findChrome returns the first available headless browser binary.
func findChrome() string {
	for _, b := range chromeBinaries {
		if p, err := exec.LookPath(b); err == nil {
			return p
		}
	}
	return ""
}

// ScreenshotSource captures a PNG screenshot of each live web host with a
// headless browser, recording the file path on the URL node. Active; gated on
// consent, the config toggle and a browser being installed.
type ScreenshotSource struct{ Cfg config.Config }

func (ScreenshotSource) Name() string      { return "screenshots" }
func (ScreenshotSource) Stage() core.Stage { return core.StageEnrich }
func (s ScreenshotSource) Applicable(core.Target) bool {
	return s.Cfg.Screenshots && findChrome() != ""
}

func (s ScreenshotSource) Run(ctx context.Context, c *core.Collector) error {
	chrome := findChrome()
	if chrome == "" {
		return nil
	}
	dir, err := screenshotDir()
	if err != nil {
		return err
	}
	bases := liveBaseURLs(c)
	count := 0
	for _, base := range bases {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		path := filepath.Join(dir, shortHash(base)+".png")
		if s.capture(ctx, chrome, base, path) {
			urlID := c.Node(graph.NodeURL, base, base, map[string]any{"screenshot": path})
			_ = urlID
			count++
			c.Flush()
		}
	}
	c.Log(core.LogInfo, "screenshots: captured "+itoa(count)+"/"+itoa(len(bases)))
	return nil
}

func (s ScreenshotSource) capture(ctx context.Context, chrome, url, out string) bool {
	cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	args := []string{
		"--headless=new", "--disable-gpu", "--no-sandbox", "--hide-scrollbars",
		"--disable-dev-shm-usage", "--window-size=1280,800",
		"--virtual-time-budget=8000", "--screenshot=" + out, url,
	}
	cmd := exec.CommandContext(cctx, chrome, args...)
	if err := cmd.Run(); err != nil {
		return false
	}
	info, err := os.Stat(out)
	return err == nil && info.Size() > 0
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
