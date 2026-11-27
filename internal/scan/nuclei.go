package scan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// NucleiAvailable reports whether the nuclei binary is on PATH.
func NucleiAvailable() bool {
	_, err := exec.LookPath("nuclei")
	return err == nil
}

// NucleiSource runs ProjectDiscovery's nuclei templates against the live web
// hosts discovered so far, importing each match as a finding. Active; gated on
// consent, the config toggle and the binary being installed.
type NucleiSource struct{ Cfg config.Config }

func (NucleiSource) Name() string                  { return "nuclei" }
func (NucleiSource) Stage() core.Stage             { return core.StageEnrich }
func (s NucleiSource) Applicable(core.Target) bool { return s.Cfg.Nuclei && NucleiAvailable() }

type nucleiResult struct {
	TemplateID string `json:"template-id"`
	Host       string `json:"host"`
	MatchedAt  string `json:"matched-at"`
	Info       struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
	} `json:"info"`
}

func (s NucleiSource) Run(ctx context.Context, c *core.Collector) error {
	var bases []string
	for _, b := range liveBaseURLs(c) {
		if inScopeURL(c, b) {
			bases = append(bases, b)
		}
	}
	if len(bases) == 0 {
		return nil
	}
	// Feed targets via a temp file so one nuclei process covers them all.
	tmp, err := os.CreateTemp("", "osint-forge-nuclei-*.txt")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	for _, b := range bases {
		_, _ = tmp.WriteString(b + "\n")
	}
	_ = tmp.Close()

	// Honour the configured politeness limit (nuclei's own default is 150 req/s).
	rate := s.Cfg.RateLimitPerHost
	if rate <= 0 {
		rate = 40
	}
	args := []string{"-silent", "-jsonl", "-disable-update-check", "-rl", itoa(rate), "-l", tmp.Name()}
	cmd := exec.CommandContext(ctx, "nuclei", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	c.Log(core.LogInfo, "запуск nuclei, хостов: "+itoa(len(bases)))
	// nuclei exits non-zero when it finds nothing on some targets; parse output
	// regardless of exit status.
	_ = cmd.Run()

	count := 0
	sc := bufio.NewScanner(&out)
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var r nucleiResult
		if json.Unmarshal([]byte(line), &r) != nil {
			continue
		}
		at := r.MatchedAt
		if at == "" {
			at = r.Host
		}
		sev := normaliseSeverity(r.Info.Severity)
		title := r.Info.Name
		if title == "" {
			title = r.TemplateID
		}
		baseID := graph.NodeID(graph.NodeURL, strings.TrimSuffix(r.Host, "/"))
		c.Finding(sev, "nuclei:"+r.TemplateID+":"+at,
			"Nuclei: "+title+" ("+at+")",
			"Сработал шаблон Nuclei ("+r.TemplateID+"): "+at, baseID)
		count++
	}
	c.Log(core.LogInfo, "nuclei: совпадений "+itoa(count))
	c.Flush()
	return nil
}

// normaliseSeverity maps nuclei severities onto the app's finding levels.
func normaliseSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "info"
	}
}
