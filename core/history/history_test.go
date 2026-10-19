package history

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ManintheiCloud/Hardex/core/finding"
)

func report(at time.Time, rules []string, ids ...string) *finding.Report {
	r := &finding.Report{Schema: finding.SchemaVersion, GeneratedAt: at, Profile: "baseline", Inputs: []string{"x"}, RulesEvaluated: rules}
	for _, id := range ids {
		f := finding.Finding{RuleID: "HX-WL-001", Severity: finding.High, Resource: finding.Resource{Kind: "Pod", Name: id}}
		f.ComputeFingerprint()
		r.Findings = append(r.Findings, f)
	}
	r.Summarize()
	return r
}

func TestSaveListTrendPrune(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "h")
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	rules := []string{"HX-WL-001"}
	// Saved out of order, and two in the same second.
	for _, r := range []*finding.Report{report(t0.Add(time.Hour), rules, "a", "b"), report(t0, rules, "a"), report(t0.Add(time.Hour), rules, "b", "c")} {
		if _, err := s.Save(r); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(dir, "junk"+suffix), []byte("{"), 0o600)

	entries, warnings, err := s.List()
	if err != nil || len(entries) != 3 || len(warnings) != 1 {
		t.Fatalf("entries=%d warnings=%v err=%v", len(entries), warnings, err)
	}
	if !entries[0].Report.GeneratedAt.Equal(t0) {
		t.Error("not sorted by time")
	}
	pts := Trend(entries)
	if pts[1].Introduced != 1 || pts[1].Resolved != 0 || pts[2].Introduced != 1 || pts[2].Resolved != 1 {
		t.Errorf("trend = %+v", pts)
	}
	if info, _ := os.Stat(entries[0].Path); info.Mode().Perm() != 0o600 {
		t.Errorf("report mode = %v, want 0600", info.Mode().Perm())
	}
	if n, err := s.Prune(1); err != nil || n != 2 {
		t.Fatalf("pruned %d, %v", n, err)
	}
	latest, _ := s.Latest()
	if latest == nil || len(latest.Report.Findings) != 2 {
		t.Error("prune removed the newest report")
	}
}
