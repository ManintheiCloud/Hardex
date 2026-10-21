// Package admission runs Hardex rules inside a Kubernetes validating
// admission webhook, so the checks that run in CI and in scheduled scans
// also guard the API server at the moment a change is made.
//
// Only rules whose verdict depends on the object alone run at admission
// (assessment.Metadata.NeedsInventory == false): the webhook sees one object
// at a time and must not reject it for context it cannot see.
package admission

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/policy"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

// Mode selects what the webhook does with findings.
type Mode string

const (
	// Enforce rejects requests with findings at or above the threshold,
	// and rejects requests it cannot evaluate (fail closed).
	Enforce Mode = "enforce"
	// Warn admits everything and returns findings as warnings to the client.
	Warn Mode = "warn"
	// Audit admits everything and only logs.
	Audit Mode = "audit"
)

// ParseMode parses enforce, warn or audit.
func ParseMode(s string) (Mode, error) {
	switch m := Mode(s); m {
	case Enforce, Warn, Audit:
		return m, nil
	}
	return "", fmt.Errorf("unknown mode %q (want enforce, warn or audit)", s)
}

// maxBody bounds an AdmissionReview; the API server limits objects to
// about 1.5 MiB.
const maxBody = 3 << 20

// Handler serves AdmissionReview requests.
type Handler struct {
	Rules     []assessment.Rule
	Config    *policy.Config
	Mode      Mode
	Threshold finding.Severity
	// Log receives one JSON line per decision (nil disables logging).
	Log io.Writer
	Now func() time.Time

	logMu sync.Mutex
}

// AdmissionOnly filters rules to those that can run on a single object.
func AdmissionOnly(rules []assessment.Rule) []assessment.Rule {
	var out []assessment.Rule
	for _, r := range rules {
		if !r.Metadata().NeedsInventory {
			out = append(out, r)
		}
	}
	return out
}

type review struct {
	APIVersion string    `json:"apiVersion"`
	Kind       string    `json:"kind"`
	Request    *Request  `json:"request,omitempty"`
	Response   *Response `json:"response,omitempty"`
}

type Request struct {
	UID  string `json:"uid"`
	Kind struct {
		Group, Version, Kind string
	} `json:"kind"`
	// SubResource is set for requests to a subresource, e.g.
	// "ephemeralcontainers" for kubectl debug.
	SubResource string          `json:"subResource,omitempty"`
	Namespace   string          `json:"namespace"`
	Name        string          `json:"name"`
	Operation   string          `json:"operation"`
	DryRun      bool            `json:"dryRun"`
	Object      json.RawMessage `json:"object"`
	UserInfo    struct {
		Username string `json:"username"`
	} `json:"userInfo"`
}

type Response struct {
	UID      string   `json:"uid"`
	Allowed  bool     `json:"allowed"`
	Status   *status  `json:"status,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

type status struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		http.Error(w, "content type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		http.Error(w, "request too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}
	var in review
	if err := json.Unmarshal(body, &in); err != nil || in.Request == nil || in.Request.UID == "" {
		http.Error(w, "invalid AdmissionReview", http.StatusBadRequest)
		return
	}
	resp := h.Decide(in.Request)
	out := review{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview", Response: resp}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// Decide evaluates one admission Request.
func (h *Handler) Decide(req *Request) *Response {
	resp := &Response{UID: req.UID, Allowed: true}
	if req.Operation != "CREATE" && req.Operation != "UPDATE" {
		return resp
	}
	findings, evalErr := h.evaluate(req)
	if req.SubResource == "ephemeralcontainers" {
		// kubectl debug adds containers to a running Pod through this
		// subresource and can change nothing else: judge the ephemeral
		// containers, not the rest of the Pod (already admitted).
		findings = ephemeralOnly(req, findings)
	}

	var blocking, advisory []finding.Finding
	for _, f := range findings {
		if f.Severity >= h.Threshold {
			blocking = append(blocking, f)
		} else {
			advisory = append(advisory, f)
		}
	}
	switch h.Mode {
	case Enforce:
		if evalErr != nil {
			resp.Allowed = false
			resp.Status = &status{Code: http.StatusForbidden, Message: "hardex: request could not be evaluated, denying (fail closed): " + evalErr.Error()}
		} else if len(blocking) > 0 {
			resp.Allowed = false
			resp.Status = &status{Code: http.StatusForbidden, Message: denyMessage(blocking)}
		}
		resp.Warnings = warnings(advisory)
	case Warn:
		resp.Warnings = warnings(append(blocking, advisory...))
		if evalErr != nil {
			resp.Warnings = append([]string{"hardex: could not evaluate request: " + truncate(evalErr.Error(), 200)}, resp.Warnings...)
		}
	}
	h.log(req, resp, findings, evalErr)
	return resp
}

func (h *Handler) evaluate(req *Request) ([]finding.Finding, error) {
	var raw map[string]any
	if err := json.Unmarshal(req.Object, &raw); err != nil || raw == nil {
		return nil, fmt.Errorf("object is not valid JSON")
	}
	if _, ok := raw["kind"]; !ok {
		raw["kind"] = req.Kind.Kind
	}
	if _, ok := raw["apiVersion"]; !ok {
		gv := req.Kind.Version
		if req.Kind.Group != "" {
			gv = req.Kind.Group + "/" + gv
		}
		raw["apiVersion"] = gv
	}
	meta, _ := raw["metadata"].(map[string]any)
	if meta == nil {
		meta = map[string]any{}
		raw["metadata"] = meta
	}
	if _, ok := meta["namespace"]; !ok && req.Namespace != "" {
		meta["namespace"] = req.Namespace
	}
	if name, _ := meta["name"].(string); name == "" {
		// generateName requests have no name yet; identify them by prefix.
		gen, _ := meta["generateName"].(string)
		meta["name"] = gen + "*"
	}
	obj, err := resource.NewObject(raw, "admission:"+req.UID, 0)
	if err != nil {
		return nil, err
	}
	inv := resource.NewInventory()
	inv.Add(obj)
	res := assessment.Evaluate(inv, h.Rules, assessment.Options{IncludeSystem: h.Config.IncludeSystem})
	if len(res.Errors) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(res.Errors, "; "))
	}
	now := time.Now()
	if h.Now != nil {
		now = h.Now()
	}
	active, _, _ := policy.Apply(h.Config, res.Findings, now)
	return active, nil
}

// ephemeralOnly keeps the findings on the Pod's ephemeral containers.
func ephemeralOnly(req *Request, fs []finding.Finding) []finding.Finding {
	var pod struct {
		Spec struct {
			EphemeralContainers []struct {
				Name string `json:"name"`
			} `json:"ephemeralContainers"`
		} `json:"spec"`
	}
	_ = json.Unmarshal(req.Object, &pod)
	names := map[string]bool{}
	for _, c := range pod.Spec.EphemeralContainers {
		names[c.Name] = true
	}
	var out []finding.Finding
	for _, f := range fs {
		if f.Resource.Container != "" && names[f.Resource.Container] {
			out = append(out, f)
		}
	}
	return out
}

func denyMessage(fs []finding.Finding) string {
	var parts []string
	for _, f := range fs {
		parts = append(parts, fmt.Sprintf("[%s] %s %s", strings.ToUpper(f.Severity.String()), f.RuleID, f.Message))
	}
	return truncate("hardex: denied: "+strings.Join(parts, "; ")+" (see `hardex rules <ID>` for remediation)", 1024)
}

func warnings(fs []finding.Finding) []string {
	var out []string
	for i, f := range fs {
		if i == 10 {
			out = append(out, fmt.Sprintf("hardex: and %d more finding(s)", len(fs)-10))
			break
		}
		out = append(out, truncate(fmt.Sprintf("hardex: [%s] %s %s", f.Severity, f.RuleID, f.Message), 256))
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func (h *Handler) log(req *Request, resp *Response, fs []finding.Finding, evalErr error) {
	if h.Log == nil {
		return
	}
	ids := make([]string, 0, len(fs))
	for _, f := range fs {
		ids = append(ids, f.RuleID)
	}
	entry := map[string]any{
		"time": time.Now().UTC().Format(time.RFC3339), "uid": req.UID, "user": req.UserInfo.Username,
		"operation": req.Operation, "kind": req.Kind.Kind, "namespace": req.Namespace, "name": req.Name,
		"dryRun": req.DryRun, "mode": h.Mode, "allowed": resp.Allowed, "findings": ids,
	}
	if evalErr != nil {
		entry["error"] = evalErr.Error()
	}
	h.logMu.Lock()
	defer h.logMu.Unlock()
	json.NewEncoder(h.Log).Encode(entry)
}
