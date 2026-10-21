package score

import (
	"testing"

	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/finding"
)

func meta(id string, sev finding.Severity, cat string) assessment.Metadata {
	return assessment.Metadata{ID: id, Title: id, Severity: sev, Category: cat,
		References: []finding.Reference{{Framework: "PSS", Control: "Baseline: X"}}}
}

func TestCompute(t *testing.T) {
	metas := []assessment.Metadata{
		meta("A-1", finding.Critical, "w"), meta("A-2", finding.High, "w"),
		meta("A-3", finding.Low, "n"), meta("A-4", finding.Medium, "n"),
	}
	r := &finding.Report{Schema: finding.SchemaVersion, RulesEvaluated: []string{"A-1", "A-2", "A-3", "A-4", "UNKNOWN"},
		Findings: []finding.Finding{{RuleID: "A-2", Severity: finding.High}, {RuleID: "A-2", Severity: finding.High}},
		Waived:   []finding.Finding{{RuleID: "A-3", Severity: finding.Low}}}
	res := Compute(r, metas)
	// Weights: 10 + 5 + 1 + 3 = 19; failing A-2 (5): 14/19 = 73.7
	if res.Score != 73.7 || res.Grade != "C" || !res.Valid {
		t.Errorf("score %.1f grade %s valid %v", res.Score, res.Grade, res.Valid)
	}
	status := map[string]Status{}
	for _, rr := range res.Rules {
		status[rr.ID] = rr.Status
	}
	if status["A-2"] != Fail || status["A-3"] != Accepted || status["A-1"] != Pass || len(status) != 4 {
		t.Errorf("statuses = %v", status)
	}
	if len(res.Frameworks) != 1 || res.Frameworks[0].Controls[0].Failed != 1 {
		t.Errorf("frameworks = %+v", res.Frameworks)
	}
}

func TestCriticalCapsGradeAndIncompleteIsInvalid(t *testing.T) {
	var metas []assessment.Metadata
	var ids []string
	for i := 0; i < 30; i++ {
		id := "B-" + string(rune('A'+i%26)) + string(rune('A'+i/26))
		metas = append(metas, meta(id, finding.Critical, "w"))
		ids = append(ids, id)
	}
	// One failing rule of 30 equal weights = 96.7, but an active critical
	// finding caps the grade.
	r := &finding.Report{Schema: finding.SchemaVersion, RulesEvaluated: ids,
		Findings: []finding.Finding{{RuleID: ids[0], Severity: finding.Critical}}}
	res := Compute(r, metas)
	if res.Score < 96 || res.Grade != "D" || res.GradeNote == "" {
		t.Errorf("score %.1f grade %s note %q", res.Score, res.Grade, res.GradeNote)
	}
	r.Errors = []string{"rule failed"}
	if res := Compute(r, metas); res.Valid || res.Grade != "—" {
		t.Errorf("incomplete report graded %s", res.Grade)
	}
}

func TestInventoryRulesNotScored(t *testing.T) {
	r := &finding.Report{Schema: finding.SchemaVersion, RulesEvaluated: []string{"HX-A", "HX-INV"},
		Findings: []finding.Finding{{RuleID: "HX-INV", Severity: finding.Info}}}
	r.Summarize()
	metas := []assessment.Metadata{{ID: "HX-A", Severity: finding.High, Category: "c"}, {ID: "HX-INV", Severity: finding.Info, Category: "c", Inventory: true}}
	res := Compute(r, metas)
	if res.Score != 100 {
		t.Errorf("score = %v; an inventory finding must not lower it", res.Score)
	}
	for _, rr := range res.Rules {
		if rr.ID == "HX-INV" {
			t.Error("inventory rule listed as a scored control")
		}
	}
}
