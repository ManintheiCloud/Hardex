// Package finding defines the result model shared by every Hardex component:
// assessment produces findings, policy filters and waives them, reporting
// renders them, and verification compares them across runs.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// Severity orders findings by the impact of the weakness if exploited.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = []string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < Info || s > Critical {
		return fmt.Sprintf("severity(%d)", int(s))
	}
	return severityNames[s]
}

// ParseSeverity parses a severity name (case-insensitive). "none" is accepted
// and returns a value above Critical, meaning "never".
func ParseSeverity(s string) (Severity, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "none" || s == "never" {
		return Critical + 1, nil
	}
	for i, n := range severityNames {
		if n == s {
			return Severity(i), nil
		}
	}
	return Info, fmt.Errorf("unknown severity %q (want one of %s, none)", s, strings.Join(severityNames, ", "))
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Severity) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	v, err := ParseSeverity(str)
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// Reference ties a rule to external guidance.
type Reference struct {
	// Framework is one of "PSS", "NSA-CISA", "CIS", "NIST", "Kubernetes".
	Framework string `json:"framework"`
	// Control identifies the item within the framework.
	Control string `json:"control"`
	URL     string `json:"url,omitempty"`
}

// Resource identifies the object a finding is about.
type Resource struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	// Container is set when the finding concerns one container of a workload.
	Container string `json:"container,omitempty"`
	Source    string `json:"source,omitempty"`
	Line      int    `json:"line,omitempty"`
}

func (r Resource) String() string {
	s := r.Kind + " "
	if r.Namespace != "" {
		s += r.Namespace + "/"
	}
	s += r.Name
	if r.Container != "" {
		s += " [" + r.Container + "]"
	}
	return s
}

// Finding is a single detected weakness.
type Finding struct {
	RuleID   string   `json:"ruleId"`
	Title    string   `json:"title"`
	Severity Severity `json:"severity"`
	Category string   `json:"category"`
	Resource Resource `json:"resource"`
	// Message explains this specific occurrence.
	Message string `json:"message"`
	// Path is the field path that triggered the finding, e.g.
	// "spec.template.spec.containers[0].securityContext.privileged".
	Path string `json:"path,omitempty"`
	// Observed is the observed value, rendered as a string. Rules must never
	// place secret material here.
	Observed    string      `json:"observed,omitempty"`
	Remediation string      `json:"remediation,omitempty"`
	References  []Reference `json:"references,omitempty"`
	// Fingerprint is a stable identifier for this finding across runs; it does
	// not depend on file paths or line numbers, so moving a manifest does not
	// make a persisting finding look new.
	Fingerprint string `json:"fingerprint"`
	// Waiver is set when an accepted-risk waiver suppresses the finding.
	Waiver *WaiverRef `json:"waiver,omitempty"`
}

// WaiverRef records which waiver applied, for auditability.
type WaiverRef struct {
	Justification string `json:"justification"`
	Owner         string `json:"owner,omitempty"`
	Expires       string `json:"expires"`
}

// ComputeFingerprint fills in the finding's fingerprint.
func (f *Finding) ComputeFingerprint() {
	h := sha256.New()
	for _, part := range []string{f.RuleID, f.Resource.Kind, f.Resource.Namespace, f.Resource.Name, f.Resource.Container, f.Path} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	f.Fingerprint = hex.EncodeToString(h.Sum(nil))[:16]
}
