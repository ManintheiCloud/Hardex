package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ManintheiCloud/Hardex/core/finding"
)

func sampleEvents() []Event {
	f := finding.Finding{RuleID: "HX-WL-001", Title: "Privileged container", Severity: finding.Critical,
		Resource: finding.Resource{Kind: "Pod", Namespace: "x", Name: "<!channel> evil"}}
	return []Event{{Type: FindingIntroduced, Finding: &f, Message: "m"}, {Type: AssessmentCompleted, Message: "1 active finding"}}
}

func TestWebhookRequiresHTTPS(t *testing.T) {
	if _, err := NewWebhook("http://hooks.example.com/x", nil, ""); err == nil {
		t.Fatal("accepted plain http")
	}
	if _, err := NewWebhook("https://hooks.example.com/x", nil, "teams"); err == nil {
		t.Fatal("accepted unknown format")
	}
}

func TestWebhookSignsRetriesAndVerifies(t *testing.T) {
	secret := []byte("s3cret")
	var attempts int
	var gotBody []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		body, _ := io.ReadAll(r.Body)
		if attempts == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if err := Verify(secret, r.Header.Get("X-Hardex-Timestamp"), r.Header.Get("X-Hardex-Signature-256"), body, time.Now(), 5*time.Minute); err != nil {
			t.Errorf("signature: %v", err)
		}
		gotBody = body
	}))
	defer srv.Close()
	wh, err := NewWebhook(srv.URL, secret, FormatGeneric)
	if err != nil {
		t.Fatal(err)
	}
	wh.Client = srv.Client()
	wh.sleep = func(time.Duration) {}
	if err := wh.Send(context.Background(), sampleEvents()); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Errorf("attempts = %d, want 2 (retry after 503)", attempts)
	}
	var payload struct {
		Source string  `json:"source"`
		Events []Event `json:"events"`
	}
	if err := json.Unmarshal(gotBody, &payload); err != nil || payload.Source != "hardex" || len(payload.Events) != 2 {
		t.Errorf("payload = %s", gotBody)
	}
	// Tampered body or stale timestamp must not verify.
	ts := "1700000000"
	sig := Sign(secret, ts, gotBody)
	if Verify(secret, ts, sig, append(gotBody, ' '), time.Unix(1700000000, 0), time.Minute) == nil {
		t.Error("tampered body verified")
	}
	if Verify(secret, ts, sig, gotBody, time.Unix(1700000000, 0).Add(time.Hour), time.Minute) == nil {
		t.Error("stale timestamp verified")
	}
}

func TestWebhookDoesNotRetryClientErrors(t *testing.T) {
	attempts := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	wh, _ := NewWebhook(srv.URL, nil, FormatSlack)
	wh.Client = srv.Client()
	wh.sleep = func(time.Duration) {}
	if err := wh.Send(context.Background(), sampleEvents()); err == nil || attempts != 1 {
		t.Fatalf("err=%v attempts=%d", err, attempts)
	}
}

func TestSlackTextEscapesUntrustedNames(t *testing.T) {
	text := SlackText(sampleEvents())
	if strings.Contains(text, "<!channel>") {
		t.Fatal("object name can trigger a Slack mention")
	}
	if !strings.Contains(text, "&lt;!channel&gt;") || !strings.Contains(text, "HX-WL-001") {
		t.Errorf("text = %s", text)
	}
}

func TestJSONLines(t *testing.T) {
	var buf bytes.Buffer
	if err := (JSONLines{W: &buf}).Send(context.Background(), sampleEvents()); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(buf.String(), "\n"); n != 2 {
		t.Errorf("%d lines, want 2", n)
	}
}
