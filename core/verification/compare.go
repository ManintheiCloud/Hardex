// Package verification compares assessments over time. It answers the
// question the README puts above all others: did the change actually work?
//
// Comparison is by finding fingerprint, which is independent of file paths
// and line numbers, so reorganising manifests does not masquerade as
// remediation.
package verification

import (
	"fmt"

	"github.com/ManintheiCloud/Hardex/core/finding"
)

// Comparison is the difference between a "before" and "after" report.
type Comparison struct {
	// Resolved findings were present before and are gone after.
	Resolved []finding.Finding `json:"resolved"`
	// Introduced findings are new in the after report.
	Introduced []finding.Finding `json:"introduced"`
	// Persisting findings are present in both (including findings that are
	// waived in the after report: accepting a risk does not remove it).
	Persisting []finding.Finding `json:"persisting"`
	// Unverified findings are absent from the after report only because the
	// rule that produced them did not run there. They are not resolved.
	Unverified []finding.Finding `json:"unverified,omitempty"`
	// Caveats explain why the comparison may not be like-for-like.
	Caveats []string `json:"caveats,omitempty"`
}

// Compare diffs two reports.
func Compare(before, after *finding.Report) Comparison {
	var c Comparison
	b := index(before.Findings)
	for fp, f := range index(before.Waived) {
		b[fp] = f
	}
	a := index(after.Findings)
	// A waived finding is accepted risk, not a fixed one.
	for fp, f := range index(after.Waived) {
		a[fp] = f
	}
	ranAfter := map[string]bool{}
	for _, id := range after.RulesEvaluated {
		ranAfter[id] = true
	}
	// A finding can disappear because its rule did not run, not because it
	// was fixed. Those are reported as unverified, never as resolved.
	for fp, f := range b {
		switch _, ok := a[fp]; {
		case ok:
			c.Persisting = append(c.Persisting, a[fp])
		case !ranAfter[f.RuleID]:
			c.Unverified = append(c.Unverified, f)
		default:
			c.Resolved = append(c.Resolved, f)
		}
	}
	for fp, f := range a {
		if _, ok := b[fp]; !ok && f.Waiver == nil {
			c.Introduced = append(c.Introduced, f)
		}
	}
	finding.Sort(c.Resolved)
	finding.Sort(c.Introduced)
	finding.Sort(c.Persisting)
	finding.Sort(c.Unverified)

	missing := map[string]bool{}
	for _, f := range c.Unverified {
		if !missing[f.RuleID] {
			missing[f.RuleID] = true
			c.Caveats = append(c.Caveats, fmt.Sprintf("rule %s did not run in the after report; its findings are unverified", f.RuleID))
		}
	}
	if before.Profile != after.Profile {
		c.Caveats = append(c.Caveats, fmt.Sprintf("profiles differ (%s vs %s)", before.Profile, after.Profile))
	}
	if !after.Complete() {
		c.Caveats = append(c.Caveats, "after report is incomplete (rule errors); resolution cannot be confirmed")
	}
	return c
}

// Regressed reports whether the after state introduced findings at or above
// the given severity.
func (c Comparison) Regressed(threshold finding.Severity) bool {
	for _, f := range c.Introduced {
		if f.Severity >= threshold {
			return true
		}
	}
	return false
}

func index(fs []finding.Finding) map[string]finding.Finding {
	m := make(map[string]finding.Finding, len(fs))
	for _, f := range fs {
		m[f.Fingerprint] = f
	}
	return m
}
