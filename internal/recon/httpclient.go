package recon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"osint-forge/internal/config"
)

// httpClient is a shared client with a generous timeout: crt.sh in particular is
// frequently slow to respond.
var httpClient = &http.Client{Timeout: 45 * time.Second}

// getJSON performs a GET with the configured user-agent and optional headers,
// decoding a JSON body into out. Non-2xx responses return an error.
func getJSON(ctx context.Context, cfg config.Config, url string, headers map[string]string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", cfg.HTTPUserAgent)
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 20<<20)) // cap at 20MB
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(body, out)
}

// postJSON performs a POST with a JSON body, decoding a JSON response into out.
func postJSON(ctx context.Context, cfg config.Config, url string, headers map[string]string, payload any, out any) error {
	buf, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", cfg.HTTPUserAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(body, out)
}
