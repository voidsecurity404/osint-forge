package recon

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// HIBPSource checks harvested email addresses against HaveIBeenPwned's breach
// database. Requires an API key; skipped when absent. Emails are only present
// after active web probing harvested them, so this runs in the enrich stage.
type HIBPSource struct{ Cfg config.Config }

func (HIBPSource) Name() string                  { return "hibp" }
func (HIBPSource) Stage() core.Stage             { return core.StageEnrich }
func (s HIBPSource) Applicable(core.Target) bool { return s.Cfg.HIBPKey != "" }

type hibpBreach struct {
	Name        string   `json:"Name"`
	Title       string   `json:"Title"`
	BreachDate  string   `json:"BreachDate"`
	DataClasses []string `json:"DataClasses"`
}

func (s HIBPSource) Run(ctx context.Context, c *core.Collector) error {
	headers := map[string]string{"hibp-api-key": s.Cfg.HIBPKey}
	for _, email := range c.ListByType(graph.NodeEmail) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		endpoint := "https://haveibeenpwned.com/api/v3/breachedaccount/" +
			url.PathEscape(email) + "?truncateResponse=false"
		var breaches []hibpBreach
		if err := getJSON(ctx, s.Cfg, endpoint, headers, &breaches); err != nil {
			// 404 = address not found in any breach (the common, healthy case).
			if !strings.Contains(err.Error(), "HTTP 404") {
				c.Log(core.LogWarn, "hibp "+email+": "+err.Error())
			}
			s.pause(ctx)
			continue
		}
		if len(breaches) == 0 {
			s.pause(ctx)
			continue
		}
		names := make([]string, 0, len(breaches))
		for _, b := range breaches {
			title := b.Title
			if title == "" {
				title = b.Name
			}
			names = append(names, title)
		}
		emailID := graph.NodeID(graph.NodeEmail, email)
		c.Finding("medium", "hibp:"+email,
			fmt.Sprintf("Email buzilgan bazalarda: %s (%d ta)", email, len(breaches)),
			email+" quyidagi buzilishlarda uchraydi: "+strings.Join(names, ", "), emailID)
		c.Log(core.LogWarn, fmt.Sprintf("hibp: %s found in %d breaches", email, len(breaches)))
		c.Flush()
		s.pause(ctx)
	}
	return nil
}

// pause respects HIBP's rate limit between requests.
func (s HIBPSource) pause(ctx context.Context) {
	select {
	case <-time.After(1600 * time.Millisecond):
	case <-ctx.Done():
	}
}
