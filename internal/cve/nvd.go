package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"
)

// nvdEndpoint is the NVD 2.0 CVE API.
const nvdEndpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// Client queries the NVD API, respecting its rate limits. NVD allows ~5 requests
// per 30s without a key and ~50/30s with one; we serialize requests and space
// them accordingly so a scan never trips the limiter.
type Client struct {
	apiKey    string
	userAgent string

	mu       sync.Mutex
	lastCall time.Time
	http     *http.Client
}

// NewClient builds an NVD client.
func NewClient(apiKey, userAgent string) *Client {
	return &Client{
		apiKey:    apiKey,
		userAgent: userAgent,
		http:      &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) minInterval() time.Duration {
	if c.apiKey != "" {
		return 700 * time.Millisecond
	}
	return 6 * time.Second
}

// throttle blocks until enough time has elapsed since the previous call.
func (c *Client) throttle(ctx context.Context) error {
	c.mu.Lock()
	wait := c.minInterval() - time.Since(c.lastCall)
	c.mu.Unlock()
	if wait > 0 {
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	c.mu.Lock()
	c.lastCall = time.Now()
	c.mu.Unlock()
	return nil
}

// nvd 2.0 response (subset).
type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				V31 []nvdMetric `json:"cvssMetricV31"`
				V30 []nvdMetric `json:"cvssMetricV30"`
				V2  []nvdMetric `json:"cvssMetricV2"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdMetric struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"` // v2 puts severity here
}

// QueryCPE fetches CVEs matching a CPE 2.3 string via virtualMatchString.
func (c *Client) QueryCPE(ctx context.Context, cpe23 string) ([]Match, error) {
	q := url.Values{"virtualMatchString": {cpe23}, "resultsPerPage": {"50"}}
	return c.query(ctx, q)
}

// QueryKeyword fetches CVEs by free-text keyword (fallback when no CPE).
func (c *Client) QueryKeyword(ctx context.Context, keyword string) ([]Match, error) {
	q := url.Values{"keywordSearch": {keyword}, "resultsPerPage": {"20"}}
	return c.query(ctx, q)
}

func (c *Client) query(ctx context.Context, q url.Values) ([]Match, error) {
	if err := c.throttle(ctx); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, nvdEndpoint+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 30<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nvd HTTP %d", resp.StatusCode)
	}

	var r nvdResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}

	var out []Match
	for _, v := range r.Vulnerabilities {
		m := Match{ID: v.CVE.ID, Published: v.CVE.Published}
		for _, d := range v.CVE.Descriptions {
			if d.Lang == "en" {
				m.Summary = d.Value
				break
			}
		}
		m.Score, m.Severity = pickMetric(v.CVE.Metrics.V31, v.CVE.Metrics.V30, v.CVE.Metrics.V2)
		out = append(out, m)
	}
	// Most severe first.
	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out, nil
}

// pickMetric chooses the best available CVSS metric (v3.1 > v3.0 > v2).
func pickMetric(groups ...[]nvdMetric) (float64, string) {
	for _, g := range groups {
		if len(g) == 0 {
			continue
		}
		m := g[0]
		sev := m.CVSSData.BaseSeverity
		if sev == "" {
			sev = m.BaseSeverity // CVSS v2 location
		}
		if sev == "" {
			sev = severityFromScore(m.CVSSData.BaseScore)
		}
		return m.CVSSData.BaseScore, sev
	}
	return 0, "UNKNOWN"
}

func severityFromScore(s float64) string {
	switch {
	case s >= 9:
		return "CRITICAL"
	case s >= 7:
		return "HIGH"
	case s >= 4:
		return "MEDIUM"
	case s > 0:
		return "LOW"
	default:
		return "NONE"
	}
}
