// Package notify sends scan alerts to external channels. Currently Telegram and
// a generic webhook. All sends are best-effort and time-bounded.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strings"
	"time"
)

// Config holds notification endpoints (stored in the app config).
type Config struct {
	TelegramToken  string `json:"telegram_token"`
	TelegramChatID string `json:"telegram_chat_id"`
	WebhookURL     string `json:"webhook_url"`
	// APIBase overrides the Telegram API root (used in tests). Empty = real API.
	APIBase string `json:"-"`
}

// Enabled reports whether any channel is configured.
func (c Config) Enabled() bool {
	return (c.TelegramToken != "" && c.TelegramChatID != "") || c.WebhookURL != ""
}

var client = &http.Client{Timeout: 12 * time.Second}

// Send delivers a plain-text message to every configured channel. It returns the
// first error encountered but always tries every channel.
func Send(ctx context.Context, c Config, text string) error {
	var firstErr error
	if c.TelegramToken != "" && c.TelegramChatID != "" {
		if err := sendTelegram(ctx, c, text); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if c.WebhookURL != "" {
		if err := sendWebhook(ctx, c.WebhookURL, text); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func base(c Config) string {
	if c.APIBase != "" {
		return strings.TrimRight(c.APIBase, "/")
	}
	return "https://api.telegram.org"
}

// telegramMaxLen is Telegram's message length limit (in UTF-16 units; runes
// are a safe approximation for our text).
const telegramMaxLen = 4000

func sendTelegram(ctx context.Context, c Config, text string) error {
	if r := []rune(text); len(r) > telegramMaxLen {
		text = string(r[:telegramMaxLen]) + "…"
	}
	payload, _ := json.Marshal(map[string]any{
		"chat_id":                  c.TelegramChatID,
		"text":                     text,
		"disable_web_page_preview": true,
	})
	url := fmt.Sprintf("%s/bot%s/sendMessage", base(c), c.TelegramToken)
	return post(ctx, url, "Telegram", "application/json", payload)
}

func sendWebhook(ctx context.Context, url, text string) error {
	payload, _ := json.Marshal(map[string]string{"text": text})
	return post(ctx, url, "webhook ("+safeHost(url)+")", "application/json", payload)
}

// safeHost returns only scheme://host of a URL. Webhook URLs (Slack, Discord)
// carry their secret in the path and the Telegram URL carries the bot token,
// so neither may appear in an error message.
func safeHost(raw string) string {
	u, err := neturl.Parse(raw)
	if err != nil || u.Host == "" {
		return "?"
	}
	return u.Scheme + "://" + u.Host
}

// post sends body to url. name describes the channel in errors — the URL
// itself never appears in them.
func post(ctx context.Context, url, name, ctype string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notify: %s: noto'g'ri URL", name)
	}
	req.Header.Set("Content-Type", ctype)
	resp, err := client.Do(req)
	if err != nil {
		// *url.Error's message embeds the full URL; keep only the cause.
		var ue *neturl.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("notify: %s: %v", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		// Telegram explains rejections (bad chat id, bot blocked…) in JSON.
		var tg struct {
			Description string `json:"description"`
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if json.Unmarshal(b, &tg) == nil && tg.Description != "" {
			return fmt.Errorf("notify: %s HTTP %d: %s", name, resp.StatusCode, tg.Description)
		}
		return fmt.Errorf("notify: %s HTTP %d", name, resp.StatusCode)
	}
	return nil
}
