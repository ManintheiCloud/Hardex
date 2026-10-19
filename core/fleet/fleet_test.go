package fleet

import (
	"testing"

	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/finding"
)

func rep(profile string, rules []string, failing ...string) *finding.Report {
	r := &finding.Report{Schema: finding.SchemaVersion, Profile: profile, RulesEvaluated: rules}
	for _, id := range failing {
		r.Findings = append(r.Findings, finding.Finding{RuleID: id, Severity: finding.High})
	}
	r.Summarize()
	return r
}

func TestCompare(t *testing.T) {
	metas := []assessment.Metadata{
		{ID: "A-1", Title: "a", Severity: finding.High}, {ID: "A-2", Title: "b", Severity: finding.Critical},
		{ID: "A-3", Title: "c", Severity: finding.Low},
	}
	c := Compare([]Member{
		{Label: "prod", Report: rep("baseline", []string{"A-1", "A-2"}, "A-1")},
		{Label: "dev", Report: rep("restricted", []string{"A-1", "A-2", "A-3"}, "A-1", "A-2", "A-3")},
	}, metas)
	byID := map[string]Row{}
	for _, r := range c.Rows {
		byID[r.RuleID] = r
	}
	if !byID["A-2"].Inconsistent || byID["A-1"].Inconsistent || !byID["A-1"].FailingEverywhere {
		t.Errorf("rows = %+v", c.Rows)
	}
	// A-3 was only evaluated in dev: failing there, but not "inconsistent".
	if byID["A-3"].Inconsistent || byID["A-3"].Cells[0].Evaluated {
		t.Errorf("A-3 = %+v", byID["A-3"])
	}
	if c.Rows[0].RuleID != "A-2" {
		t.Error("inconsistent controls must be listed first")
	}
	if len(c.Caveats) == 0 {
		t.Error("differing profiles not flagged")
	}
}
