package scan

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// WebChecksSource runs targeted, low-false-positive web security checks against
// each live host: CORS misconfiguration, exposed .git/.env, directory listing,
// and dangerous HTTP methods. Each check verifies response content before
// reporting, so findings are high-confidence.
type WebChecksSource struct{ Cfg config.Config }

func (WebChecksSource) Name() string                { return "webchecks" }
func (WebChecksSource) Stage() core.Stage           { return core.StageEnrich }
func (WebChecksSource) Applicable(core.Target) bool { return true }

func (s WebChecksSource) Run(ctx context.Context, c *core.Collector) error {
	for _, base := range s.liveBases(c) {
		baseID := graph.NodeID(graph.NodeURL, base)
		s.checkCORS(ctx, c, base, baseID)
		s.checkGit(ctx, c, base, baseID)
		s.checkEnv(ctx, c, base, baseID)
		s.checkDirListing(ctx, c, base, baseID)
		s.checkMethods(ctx, c, base, baseID)
		c.Flush()
	}
	return nil
}

func (s WebChecksSource) liveBases(c *core.Collector) []string { return liveBaseURLs(c) }

func (s WebChecksSource) do(ctx context.Context, method, url string, headers map[string]string) (*http.Response, []byte) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, method, url, nil)
	if err != nil {
		return nil, nil
	}
	req.Header.Set("User-Agent", s.Cfg.HTTPUserAgent)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := probeClient.Do(req)
	if err != nil {
		return nil, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 128<<10))
	resp.Body.Close()
	return resp, body
}

// checkCORS reflects a foreign Origin and inspects the ACAO/ACAC response.
func (s WebChecksSource) checkCORS(ctx context.Context, c *core.Collector, base, baseID string) {
	evil := "https://osint-forge-test.example"
	resp, _ := s.do(ctx, http.MethodGet, base, map[string]string{"Origin": evil})
	if resp == nil {
		return
	}
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := strings.EqualFold(resp.Header.Get("Access-Control-Allow-Credentials"), "true")
	if acao == evil && acac {
		c.Finding("high", "cors:"+base, "CORS noto'g'ri sozlangan (origin aks ettiriladi + credentials)",
			"Server ixtiyoriy Origin'ni aks ettiradi va credentials'ga ruxsat beradi — cross-origin ma'lumot o'g'irlash mumkin.", baseID)
	} else if acao == evil || acao == "*" && acac {
		c.Finding("medium", "cors:"+base, "CORS siyosati bo'sh",
			"Access-Control-Allow-Origin ixtiyoriy manbaga ruxsat beradi.", baseID)
	}
}

// checkGit verifies an exposed .git repository by content, not just status.
func (s WebChecksSource) checkGit(ctx context.Context, c *core.Collector, base, baseID string) {
	resp, body := s.do(ctx, http.MethodGet, base+"/.git/HEAD", nil)
	if resp == nil || resp.StatusCode != 200 {
		return
	}
	if strings.HasPrefix(strings.TrimSpace(string(body)), "ref:") {
		c.Finding("high", "git-exposed:"+base, ".git repozitoriysi ochiq",
			base+"/.git/ ochiq — manba kod va tarix yuklab olinishi mumkin (git-dumper).", baseID)
	}
}

// checkEnv verifies an exposed .env file by content.
func (s WebChecksSource) checkEnv(ctx context.Context, c *core.Collector, base, baseID string) {
	resp, body := s.do(ctx, http.MethodGet, base+"/.env", nil)
	if resp == nil || resp.StatusCode != 200 {
		return
	}
	b := string(body)
	if strings.Contains(b, "=") && (strings.Contains(b, "APP_") || strings.Contains(b, "DB_") ||
		strings.Contains(b, "SECRET") || strings.Contains(b, "API_KEY") || strings.Contains(b, "PASSWORD")) {
		c.Finding("critical", "env-exposed:"+base, ".env fayli ochiq",
			base+"/.env ochiq — maxfiy kalitlar va parollar oshkor bo'lishi mumkin.", baseID)
	}
}

// checkDirListing detects an Apache/nginx autoindex page.
func (s WebChecksSource) checkDirListing(ctx context.Context, c *core.Collector, base, baseID string) {
	resp, body := s.do(ctx, http.MethodGet, base+"/", nil)
	if resp == nil || resp.StatusCode != 200 {
		return
	}
	b := string(body)
	if strings.Contains(b, "<title>Index of /") || strings.Contains(b, "Directory listing for") {
		c.Finding("low", "dirlisting:"+base, "Katalog ro'yxati ochiq (directory listing)",
			base+" fayllar ro'yxatini ko'rsatadi — autoindex o'chirilishi kerak.", baseID)
	}
}

// checkMethods flags dangerous enabled HTTP methods via OPTIONS.
func (s WebChecksSource) checkMethods(ctx context.Context, c *core.Collector, base, baseID string) {
	resp, _ := s.do(ctx, http.MethodOptions, base, nil)
	if resp == nil {
		return
	}
	allow := strings.ToUpper(resp.Header.Get("Allow"))
	var risky []string
	for _, m := range []string{"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"} {
		if strings.Contains(allow, m) {
			risky = append(risky, m)
		}
	}
	if len(risky) > 0 {
		c.Finding("low", "http-methods:"+base, "Xavfli HTTP metodlar yoqilgan",
			base+" quyidagi metodlarга ruxsat beradi: "+strings.Join(risky, ", "), baseID)
	}
}
