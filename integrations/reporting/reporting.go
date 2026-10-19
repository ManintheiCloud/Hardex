// Package reporting renders assessment reports for humans (text) and
// machines (JSON, SARIF 2.1.0 for code-scanning platforms).
package reporting

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/finding"
)

// Formats lists the supported output formats.
var Formats = []string{"text", "json", "sarif", "html", "markdown"}

// Write renders a report in the named format.
func Write(w io.Writer, format string, r *finding.Report, rules []assessment.Metadata) error {
	switch format {
	case "text":
		return Text(w, r)
	case "json":
		return JSON(w, r)
	case "sarif":
		return SARIF(w, r, rules)
	case "html", "markdown":
		return Evidence(w, format, r, rules, "")
	}
	return fmt.Errorf("unknown format %q (want %s)", format, strings.Join(Formats, ", "))
}

// JSON writes the report as indented JSON.
func JSON(w io.Writer, r *finding.Report) error { return JSONValue(w, r) }

// JSONValue writes any value as indented JSON.
func JSONValue(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// Text writes a human-readable report.
func Text(w io.Writer, r *finding.Report) error {
	p := &printer{w: w}
	p.f("Hardex %s — profile %q — %d objects, %d rules\n\n", r.Tool.Version, r.Profile, r.ObjectsEvaluated, len(r.RulesEvaluated))

	if len(r.Findings) == 0 {
		p.f("No findings.\n")
	}
	for _, f := range r.Findings {
		p.f("[%s] %s %s\n", strings.ToUpper(f.Severity.String()), f.RuleID, f.Title)
		p.f("  resource: %s\n", f.Resource)
		if f.Resource.Source != "" {
			p.f("  location: %s:%d\n", f.Resource.Source, f.Resource.Line)
		}
		if f.Path != "" {
			obs := ""
			if f.Observed != "" {
				obs = " = " + f.Observed
			}
			p.f("  field:    %s%s\n", f.Path, obs)
		}
		p.f("  detail:   %s\n", f.Message)
		p.f("  fix:      %s\n\n", f.Remediation)
	}

	if len(r.Waived) > 0 {
		p.f("Waived (%d):\n", len(r.Waived))
		for _, f := range r.Waived {
			p.f("  - %s %s (expires %s): %s\n", f.RuleID, f.Resource, f.Waiver.Expires, f.Waiver.Justification)
		}
		p.f("\n")
	}
	for _, msg := range r.Warnings {
		p.f("warning: %s\n", msg)
	}
	for _, msg := range r.Errors {
		p.f("error: %s\n", msg)
	}
	s := r.Summary
	p.f("\nSummary: %d findings (critical %d, high %d, medium %d, low %d, info %d), %d waived\n",
		s.Total, s.Critical, s.High, s.Medium, s.Low, s.Info, s.Waived)
	if !r.Complete() {
		p.f("ASSESSMENT INCOMPLETE: %d rule(s) failed; results understate risk.\n", len(r.Errors))
	}
	return p.err
}

type printer struct {
	w   io.Writer
	err error
}

// f formats a line. String arguments are sanitized: names, paths and values
// come from untrusted manifests, and terminal control sequences embedded in
// them must not reach the operator's terminal.
func (p *printer) f(format string, args ...any) {
	if p.err != nil {
		return
	}
	for i, a := range args {
		switch v := a.(type) {
		case string:
			args[i] = Sanitize(v)
		case fmt.Stringer:
			args[i] = Sanitize(v.String())
		}
	}
	_, p.err = fmt.Fprintf(p.w, format, args...)
}

// Sanitize replaces control characters (including ESC and newlines) with
// visible escapes.
func Sanitize(s string) string {
	clean := true
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			fmt.Fprintf(&b, "\\x%02x", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
