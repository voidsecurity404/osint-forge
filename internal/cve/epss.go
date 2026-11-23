package cve

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// epssURL is FIRST.org's EPSS API (Exploit Prediction Scoring System): the
// probability a CVE will be exploited in the next 30 days. Keyless.
const epssURL = "https://api.first.org/data/v1/epss"

type epssResponse struct {
	Data []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
	} `json:"data"`
}

// FetchEPSS returns EPSS scores (0..1) for the given CVE IDs, batching requests.
func FetchEPSS(ctx context.Context, userAgent string, ids []string) map[string]float64 {
	out := map[string]float64{}
	client := &http.Client{Timeout: 20 * time.Second}
	const batch = 100
	for i := 0; i < len(ids); i += batch {
		end := i + batch
		if end > len(ids) {
			end = len(ids)
		}
		url := epssURL + "?cve=" + strings.Join(ids[i:end], ",")
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", userAgent)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
		resp.Body.Close()
		var r epssResponse
		if json.Unmarshal(body, &r) != nil {
			continue
		}
		for _, d := range r.Data {
			if f, err := strconv.ParseFloat(d.EPSS, 64); err == nil {
				out[d.CVE] = f
			}
		}
	}
	return out
}
