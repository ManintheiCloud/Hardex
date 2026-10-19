package finding

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"
)

// SchemaVersion identifies the JSON report format. Bump the major component
// on any breaking change; consumers should reject unknown majors.
const SchemaVersion = "hardex.dev/report/v1alpha1"

// Report is the complete, machine-readable result of one assessment.
type Report struct {
	Schema      string    `json:"schema"`
	Tool        Tool      `json:"tool"`
	GeneratedAt time.Time `json:"generatedAt"`
	Profile     string    `json:"profile"`
	Inputs      []string  `json:"inputs"`
	// ObjectsEvaluated is the number of Kubernetes objects read.
	ObjectsEvaluated int `json:"objectsEvaluated"`
	// RulesEvaluated lists the rule IDs that ran.
	RulesEvaluated []string `json:"rulesEvaluated"`
	// Findings are active (unwaived) findings.
	Findings []Finding `json:"findings"`
	// Waived are findings suppressed by an unexpired waiver.
	Waived []Finding `json:"waived,omitempty"`
	// Warnings are conditions the operator should know about but that did
	// not stop the assessment (skipped documents, expired waivers).
	Warnings []string `json:"warnings,omitempty"`
	// Errors are rule failures. A report with errors is incomplete and must
	// not be read as a clean bill of health.
	Errors  []string `json:"errors,omitempty"`
	Summary Summary  `json:"summary"`
}

// Tool identifies the producer of a report.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Summary counts active findings by severity.
type Summary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Waived   int `json:"waived"`
}

// Complete reports whether every rule ran successfully.
func (r *Report) Complete() bool { return len(r.Errors) == 0 }

// Sort orders findings deterministically: severity descending, then rule,
// then resource. Deterministic output is required for diffing and review.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.Resource.String() != b.Resource.String() {
			return a.Resource.String() < b.Resource.String()
		}
		return a.Path < b.Path
	})
}

// Summarize recomputes the summary from the findings.
func (r *Report) Summarize() {
	s := Summary{Total: len(r.Findings), Waived: len(r.Waived)}
	for _, f := range r.Findings {
		switch f.Severity {
		case Critical:
			s.Critical++
		case High:
			s.High++
		case Medium:
			s.Medium++
		case Low:
			s.Low++
		default:
			s.Info++
		}
	}
	r.Summary = s
}

// HighestSeverity returns the highest active severity, or -1 if none.
func (r *Report) HighestSeverity() Severity {
	max := Severity(-1)
	for _, f := range r.Findings {
		if f.Severity > max {
			max = f.Severity
		}
	}
	return max
}

// ReadReport decodes a JSON report and checks its schema.
func ReadReport(rd io.Reader) (*Report, error) {
	var r Report
	dec := json.NewDecoder(rd)
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("decode report: %w", err)
	}
	if r.Schema != SchemaVersion {
		return nil, fmt.Errorf("unsupported report schema %q (want %q)", r.Schema, SchemaVersion)
	}
	return &r, nil
}
