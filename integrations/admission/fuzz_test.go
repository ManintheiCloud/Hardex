package admission

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// FuzzServeHTTP: arbitrary request bodies must never panic the webhook and
// must yield either an HTTP error or a well-formed review.
func FuzzServeHTTP(f *testing.F) {
	f.Add(`{"request":{"uid":"u","operation":"CREATE","kind":{"kind":"Pod","version":"v1"},"object":` + privilegedPod + `}}`)
	f.Add(`{"request":{"uid":"u","operation":"UPDATE","object":{"kind":"Role","rules":[null,{"verbs":"*"}]}}}`)
	h := handler(&testing.T{}, Enforce, "")
	f.Fuzz(func(t *testing.T, body string) {
		req := httptest.NewRequest(http.MethodPost, "/validate", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK && !strings.Contains(rec.Body.String(), `"response"`) {
			t.Fatalf("200 without a response: %s", rec.Body.String())
		}
	})
}
