package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultsInAppFeaturesOn(t *testing.T) {
	d := Default()
	if !d.BuiltinChecks || !d.Screenshots || !d.FaviconHash {
		t.Fatalf("in-app features must default on: %+v", d)
	}
}

// An old config file (pre-dating builtin_checks) must not silently disable it.
func TestLoadMigrationKeepsDefaultsForAbsentKeys(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	cfgDir := filepath.Join(dir, "osint-forge")
	os.MkdirAll(cfgDir, 0o755)
	// Old file: screenshots explicitly false, no builtin_checks/favicon_hash keys.
	os.WriteFile(filepath.Join(cfgDir, "config.json"),
		[]byte(`{"screenshots":false,"max_concurrent":8}`), 0o600)

	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Screenshots {
		t.Error("explicit false must be respected")
	}
	if !c.BuiltinChecks || !c.FaviconHash {
		t.Error("absent in-app keys must fall back to default ON")
	}
	if c.MaxConcurrent != 8 {
		t.Errorf("existing value lost: %d", c.MaxConcurrent)
	}
}

// Values from the settings form are not trusted: an empty/negative/huge
// "max_concurrent" became 0 or 100000 workers (×8 for DNS brute-force), and a
// blank extra-scope line became an empty scope entry.
func TestNormalize(t *testing.T) {
	c := Config{
		MaxConcurrent:    100000,
		ScanTimeoutMin:   -5,
		RateLimitPerHost: -1,
		HTTPUserAgent:    "   ",
		FuzzWordlist:     "  ",
		NmapArgs:         "  -sV  ",
		ExtraScope:       []string{" partner.org ", "", "partner.org", "10.0.0.0/8"},
		WebhookURL:       " https://hooks.example/x ",
	}
	c.Normalize()
	if c.MaxConcurrent != maxConcurrentCap {
		t.Errorf("MaxConcurrent = %d", c.MaxConcurrent)
	}
	if c.ScanTimeoutMin != 0 || c.RateLimitPerHost != 0 {
		t.Errorf("negatives not clamped: %d %d", c.ScanTimeoutMin, c.RateLimitPerHost)
	}
	if c.HTTPUserAgent != Default().HTTPUserAgent || c.FuzzWordlist != "common" || c.NmapArgs != "-sV" {
		t.Errorf("blank strings not defaulted/trimmed: %+v", c)
	}
	if len(c.ExtraScope) != 2 || c.ExtraScope[0] != "partner.org" {
		t.Errorf("ExtraScope = %q", c.ExtraScope)
	}
	if c.WebhookURL != "https://hooks.example/x" {
		t.Errorf("WebhookURL = %q", c.WebhookURL)
	}
	z := Config{}
	z.Normalize()
	if z.MaxConcurrent != 16 {
		t.Errorf("zero MaxConcurrent = %d, want 16", z.MaxConcurrent)
	}
}
