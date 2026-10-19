// Package notify delivers security events — findings introduced or resolved,
// incomplete assessments — to people and systems: JSON Lines for log
// pipelines and SIEMs, and signed webhooks for chat and incident tooling.
//
// Events carry the same redacted finding data as reports; they never contain
// secret values.
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ManintheiCloud/Hardex/core/finding"
)

// Event types.
const (
	FindingIntroduced    = "finding.introduced"
	FindingResolved      = "finding.resolved"
	AssessmentIncomplete = "assessment.incomplete"
	AssessmentCompleted  = "assessment.completed"
)

// Event is one notification.
type Event struct {
	Type    string           `json:"type"`
	Time    time.Time        `json:"time"`
	Inputs  []string         `json:"inputs"`
	Profile string           `json:"profile"`
	Message string           `json:"message"`
	Finding *finding.Finding `json:"finding,omitempty"`
	Summary *finding.Summary `json:"summary,omitempty"`
	// Drift is the number of active findings not present in the approved
	// baseline, when a baseline is configured.
	Drift *int `json:"drift,omitempty"`
}

// Sink receives batches of events.
type Sink interface {
	Name() string
	Send(ctx context.Context, events []Event) error
}

// JSONLines writes one JSON object per line.
type JSONLines struct {
	W io.Writer
}

func (j JSONLines) Name() string { return "events" }

func (j JSONLines) Send(_ context.Context, events []Event) error {
	enc := json.NewEncoder(j.W)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	return nil
}

// Webhook formats.
const (
	FormatGeneric = "generic"
	FormatSlack   = "slack"
)

// Webhook POSTs each batch to an HTTPS endpoint.
//
// Requests carry X-Hardex-Timestamp and X-Hardex-Signature-256 headers. The
// signature is "sha256=" + hex(HMAC-SHA256(secret, timestamp + "." + body)),
// so receivers can verify authenticity and reject replays of old
// timestamps. Redirects are not followed.
type Webhook struct {
	URL    string
	Secret []byte
	Format string
	Client *http.Client
	// Retries is the number of extra attempts after a failure (default 2).
	Retries int
	now     func() time.Time
	sleep   func(time.Duration)
}

// NewWebhook validates the endpoint and returns a sink.
func NewWebhook(rawURL string, secret []byte, format string) (*Webhook, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid webhook URL")
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("webhook URL must use https; events describe security weaknesses")
	}
	if format == "" {
		format = FormatGeneric
	}
	if format != FormatGeneric && format != FormatSlack {
		return nil, fmt.Errorf("unknown webhook format %q (want generic or slack)", format)
	}
	return &Webhook{URL: rawURL, Secret: secret, Format: format, Retries: 2,
		Client: &http.Client{
			Timeout:       15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}}, nil
}

func (w *Webhook) Name() string { return "webhook" }

// Send delivers the batch, retrying transient failures with backoff.
func (w *Webhook) Send(ctx context.Context, events []Event) error {
	if len(events) == 0 {
		return nil
	}
	body, err := w.payload(events)
	if err != nil {
		return err
	}
	now, sleep := w.now, w.sleep
	if now == nil {
		now = time.Now
	}
	if sleep == nil {
		sleep = time.Sleep
	}
	var last error
	for attempt := 0; attempt <= w.Retries; attempt++ {
		if attempt > 0 {
			sleep(time.Duration(attempt) * 2 * time.Second)
		}
		retry, err := w.post(ctx, body, now())
		if err == nil {
			return nil
		}
		last = err
		if !retry {
			break
		}
	}
	return fmt.Errorf("webhook delivery failed: %w", last)
}

func (w *Webhook) post(ctx context.Context, body []byte, at time.Time) (retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	ts := strconv.FormatInt(at.Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "hardex")
	req.Header.Set("X-Hardex-Timestamp", ts)
	if len(w.Secret) > 0 {
		req.Header.Set("X-Hardex-Signature-256", Sign(w.Secret, ts, body))
	}
	resp, err := w.Client.Do(req)
	if err != nil {
		return true, err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return false, nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return true, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return false, fmt.Errorf("HTTP %d", resp.StatusCode)
}

// Sign computes the X-Hardex-Signature-256 header value.
func Sign(secret []byte, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Verify checks a signature and that the timestamp is within maxAge of now.
// It is provided for receivers written in Go.
func Verify(secret []byte, timestamp, signature string, body []byte, now time.Time, maxAge time.Duration) error {
	sec, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return errors.New("invalid timestamp")
	}
	if age := now.Sub(time.Unix(sec, 0)); age > maxAge || age < -maxAge {
		return errors.New("timestamp outside allowed window")
	}
	if !hmac.Equal([]byte(Sign(secret, timestamp, body)), []byte(signature)) {
		return errors.New("signature mismatch")
	}
	return nil
}

func (w *Webhook) payload(events []Event) ([]byte, error) {
	if w.Format == FormatSlack {
		return json.Marshal(map[string]string{"text": SlackText(events)})
	}
	return json.Marshal(map[string]any{"source": "hardex", "events": events})
}

// SlackText renders a compact, human-readable summary of a batch.
func SlackText(events []Event) string {
	var b strings.Builder
	var introduced, resolved []Event
	for _, e := range events {
		switch e.Type {
		case FindingIntroduced:
			introduced = append(introduced, e)
		case FindingResolved:
			resolved = append(resolved, e)
		case AssessmentIncomplete, AssessmentCompleted:
			fmt.Fprintf(&b, "*Hardex*: %s\n", escapeSlack(e.Message))
		}
	}
	list := func(title string, es []Event) {
		if len(es) == 0 {
			return
		}
		fmt.Fprintf(&b, "%s (%d):\n", title, len(es))
		for i, e := range es {
			if i == 20 {
				fmt.Fprintf(&b, "• …and %d more\n", len(es)-20)
				break
			}
			f := e.Finding
			fmt.Fprintf(&b, "• [%s] %s %s — %s\n", strings.ToUpper(f.Severity.String()), f.RuleID, escapeSlack(f.Resource.String()), escapeSlack(f.Title))
		}
	}
	list(":rotating_light: New findings", introduced)
	list(":white_check_mark: Resolved", resolved)
	return b.String()
}

// escapeSlack neutralises Slack control characters in untrusted text
// (object names come from manifests), preventing mentions and link
// injection.
func escapeSlack(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}
