package recon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"osint-forge/internal/config"
)

// httpClient is a shared client with a generous timeout: crt.sh in particular is
// frequently slow to respond.
var httpClient = &http.Client{Timeout: 45 * time.Second}

// redact returns the URL without its query string and userinfo. Several APIs
// (Shodan) take the API key as a query parameter, and errors end up in the UI
// log — the key must never be part of an error message.
func redact(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<url>"
	}
	u.RawQuery = ""
	u.User = nil
	u.Fragment = ""
	return u.String()
}

// do sends the request and returns the (size-capped) body of a 2xx response.
func do(req *http.Request) ([]byte, error) {
	resp, err := httpClient.Do(req)
	if err != nil {
		// *url.Error embeds the full URL (key included) in its message.
		if ue, ok := err.(*url.Error); ok {
			return nil, fmt.Errorf("%s %s: %w", ue.Op, redact(ue.URL), ue.Err)
		}
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 20<<20)) // cap at 20MB
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s: HTTP %d", redact(req.URL.String()), resp.StatusCode)
	}
	return body, nil
}

// getJSON performs a GET with the configured user-agent and optional headers,
// decoding a JSON body into out. Non-2xx responses return an error.
func getJSON(ctx context.Context, cfg config.Config, url string, headers map[string]string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("неверный URL запроса %s", redact(url))
	}
	req.Header.Set("User-Agent", cfg.HTTPUserAgent)
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	body, err := do(req)
	if err != nil || out == nil {
		return err
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
		return fmt.Errorf("неверный URL запроса %s", redact(url))
	}
	req.Header.Set("User-Agent", cfg.HTTPUserAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	body, err := do(req)
	if err != nil || out == nil {
		return err
	}
	return json.Unmarshal(body, out)
}
