package notify

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSendTelegramAndWebhook(t *testing.T) {
	var tgBody, whBody string
	tg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/botTKN/sendMessage") {
			t.Errorf("bad telegram path: %s", r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		tgBody = string(b)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer tg.Close()
	wh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		whBody = string(b)
	}))
	defer wh.Close()

	cfg := Config{TelegramToken: "TKN", TelegramChatID: "42", WebhookURL: wh.URL, APIBase: tg.URL}
	if !cfg.Enabled() {
		t.Fatal("should be enabled")
	}
	if err := Send(context.Background(), cfg, "hello scan"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tgBody, "hello scan") || !strings.Contains(tgBody, `"chat_id":"42"`) {
		t.Errorf("telegram body wrong: %s", tgBody)
	}
	if !strings.Contains(whBody, "hello scan") {
		t.Errorf("webhook body wrong: %s", whBody)
	}
}

func TestDisabled(t *testing.T) {
	if (Config{}).Enabled() {
		t.Error("empty config must be disabled")
	}
}

// The bot token is part of the Telegram URL path; errors (shown in the UI
// toast and logs) used to contain the full URL — i.e. the token.
func TestErrorsDoNotLeakToken(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	defer bad.Close()
	err := Send(context.Background(), Config{TelegramToken: "123:SECRETTOKEN", TelegramChatID: "1", APIBase: bad.URL}, "x")
	if err == nil || strings.Contains(err.Error(), "SECRETTOKEN") {
		t.Fatalf("status error leaks token or is missing: %v", err)
	}
	dead := bad.URL
	bad.Close() // connection refused → *url.Error carrying the URL
	err = Send(context.Background(), Config{TelegramToken: "123:SECRETTOKEN", TelegramChatID: "1", APIBase: dead}, "x")
	if err == nil || strings.Contains(err.Error(), "SECRETTOKEN") {
		t.Fatalf("transport error leaks token or is missing: %v", err)
	}
	// Webhook URLs often embed a secret too (Slack/Discord); keep only scheme+host.
	err = Send(context.Background(), Config{WebhookURL: dead + "/hooks/T000/SECRETPATH"}, "x")
	if err == nil || strings.Contains(err.Error(), "SECRETPATH") {
		t.Fatalf("webhook error leaks its secret path: %v", err)
	}
}
