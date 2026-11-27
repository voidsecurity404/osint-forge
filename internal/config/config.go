// Package config loads and persists user settings (API keys, paths) under the
// XDG config directory. Missing keys simply disable the sources that need them.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// Config holds all user-configurable settings.
type Config struct {
	// API keys for reverse-IP / passive DNS sources. Empty = source skipped.
	SecurityTrailsKey string `json:"securitytrails_key"`
	VirusTotalKey     string `json:"virustotal_key"`
	NVDKey            string `json:"nvd_key"` // optional, raises NVD rate limit

	// Scan behaviour.
	NmapArgs      string `json:"nmap_args"` // extra nmap flags; sane default if empty
	HTTPUserAgent string `json:"http_user_agent"`
	MaxConcurrent int    `json:"max_concurrent"` // worker pool size
	FuzzEnabled   bool   `json:"fuzz_enabled"`   // content/path fuzzing of live web hosts
	FuzzWordlist  string `json:"fuzz_wordlist"`  // builtin name (common|raft-directories|raft-files|combo) or a file path

	SubdomainBruteforce bool `json:"subdomain_bruteforce"` // DNS brute-force of common subdomains
	ZoneTransfer        bool `json:"zone_transfer"`        // attempt AXFR against name servers (active)

	// StatusCodes controls which HTTP status codes are recorded (http probe + fuzz).
	// Comma-separated list of exact codes (200), ranges (200-299) or classes
	// (2xx,3xx,4xx,5xx). Empty = show all. Default excludes 404.
	StatusCodes string `json:"status_codes"`

	// Safety / scope.
	ScanTimeoutMin   int      `json:"scan_timeout_min"`    // overall scan budget in minutes; 0 = no limit
	ScopeStrict      bool     `json:"scope_strict"`        // active probing only against in-scope hosts
	ExtraScope       []string `json:"extra_scope"`         // extra in-scope domains / CIDRs
	RateLimitPerHost int      `json:"rate_limit_per_host"` // max requests/sec per host for fuzz/brute; 0 = internal default

	// Optional API keys (empty = source skipped, same as SecurityTrails/VirusTotal).
	ShodanKey    string `json:"shodan_key"`
	CensysID     string `json:"censys_id"`     // Censys Search API v2 API ID
	CensysSecret string `json:"censys_secret"` // Censys Search API v2 secret
	HIBPKey      string `json:"hibp_key"`      // HaveIBeenPwned
	GitHubToken  string `json:"github_token"`  // GitHub code search (leaked-secret dorking)

	// External-tool integrations (run only when the binary is on PATH).
	// Notifications + continuous monitoring.
	TelegramToken  string `json:"telegram_token"`
	TelegramChatID string `json:"telegram_chat_id"`
	WebhookURL     string `json:"webhook_url"`

	BuiltinChecks bool `json:"builtin_checks"` // in-process template checks (no external tool)
	Screenshots   bool `json:"screenshots"`    // capture screenshots of live web hosts (Firefox/Chromium)
	FaviconHash   bool `json:"favicon_hash"`   // compute shodan-style mmh3 favicon hash
	Nuclei        bool `json:"nuclei"`         // ALSO run external ProjectDiscovery nuclei, if installed
}

// Default returns a config with safe defaults for first run.
func Default() Config {
	return Config{
		NmapArgs:      "-sV -T4 --top-ports 1000",
		HTTPUserAgent: "osint-forge/0.1 (+recon)",
		MaxConcurrent: 16,
		FuzzEnabled:   true,
		FuzzWordlist:  "common",

		SubdomainBruteforce: true,
		ZoneTransfer:        true,
		StatusCodes:         "2xx,3xx,401,403,405,5xx",

		ScanTimeoutMin:   30,
		ScopeStrict:      true, // fail-safe: never actively probe out-of-scope hosts
		RateLimitPerHost: 0,

		// In-app capabilities — on by default, need nothing installed.
		BuiltinChecks: true,
		Screenshots:   true,
		FaviconHash:   true,
	}
}

// maxConcurrentCap bounds the worker pool. Some sources multiply it (DNS
// brute-force uses ×8), so an unbounded value from the settings form could
// spawn hundreds of thousands of goroutines/sockets.
const maxConcurrentCap = 256

// Normalize trims and clamps user-supplied values so a sloppy settings form or
// hand-edited file can never produce a broken scan configuration.
func (c *Config) Normalize() {
	d := Default()
	trim := func(p *string) { *p = strings.TrimSpace(*p) }
	for _, p := range []*string{
		&c.SecurityTrailsKey, &c.VirusTotalKey, &c.NVDKey, &c.NmapArgs, &c.HTTPUserAgent,
		&c.FuzzWordlist, &c.StatusCodes, &c.ShodanKey, &c.CensysID, &c.CensysSecret,
		&c.HIBPKey, &c.GitHubToken, &c.TelegramToken, &c.TelegramChatID, &c.WebhookURL,
	} {
		trim(p)
	}
	c.NmapArgs = strings.Join(strings.Fields(c.NmapArgs), " ")
	if c.HTTPUserAgent == "" {
		c.HTTPUserAgent = d.HTTPUserAgent
	}
	if c.FuzzWordlist == "" {
		c.FuzzWordlist = d.FuzzWordlist
	}
	switch {
	case c.MaxConcurrent <= 0:
		c.MaxConcurrent = d.MaxConcurrent
	case c.MaxConcurrent > maxConcurrentCap:
		c.MaxConcurrent = maxConcurrentCap
	}
	if c.ScanTimeoutMin < 0 {
		c.ScanTimeoutMin = 0
	}
	if c.RateLimitPerHost < 0 {
		c.RateLimitPerHost = 0
	}
	seen := map[string]bool{}
	scope := make([]string, 0, len(c.ExtraScope))
	for _, e := range c.ExtraScope {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" || seen[e] {
			continue
		}
		seen[e] = true
		scope = append(scope, e)
	}
	c.ExtraScope = scope
}

// Dir returns the config directory, creating it if needed.
func Dir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "osint-forge")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

func path() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

// Load reads the config file, falling back to defaults when it is absent.
func Load() (Config, error) {
	cfg := Default()
	p, err := path()
	if err != nil {
		return cfg, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	// Overlay stored values onto defaults so new fields keep their defaults.
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	// Migration: in-app features are default-ON, but a config file written before
	// a feature existed has no key for it, which JSON decodes as false. When the
	// key is absent, keep the Default() value instead of silently disabling it.
	var raw map[string]json.RawMessage
	if json.Unmarshal(b, &raw) == nil {
		d := Default()
		if _, ok := raw["builtin_checks"]; !ok {
			cfg.BuiltinChecks = d.BuiltinChecks
		}
		if _, ok := raw["screenshots"]; !ok {
			cfg.Screenshots = d.Screenshots
		}
		if _, ok := raw["favicon_hash"]; !ok {
			cfg.FaviconHash = d.FaviconHash
		}
	}
	cfg.Normalize()
	return cfg, nil
}

// Save writes the config file atomically.
func Save(cfg Config) error {
	p, err := path()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
