package monitoring

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/history"
	"github.com/ManintheiCloud/Hardex/integrations/notify"
)

type capture struct {
	batches [][]notify.Event
	err     error
}

func (c *capture) Name() string { return "capture" }
func (c *capture) Send(_ context.Context, es []notify.Event) error {
	c.batches = append(c.batches, es)
	return c.err
}

func rep(at time.Time, items map[string]finding.Severity) *finding.Report {
	r := &finding.Report{Schema: finding.SchemaVersion, GeneratedAt: at, Profile: "baseline", RulesEvaluated: []string{"HX-WL-001"}}
	for name, sev := range items {
		f := finding.Finding{RuleID: "HX-WL-001", Severity: sev, Resource: finding.Resource{Kind: "Pod", Name: name}}
		f.ComputeFingerprint()
		r.Findings = append(r.Findings, f)
	}
	r.Summarize()
	return r
}

func types(es []notify.Event) map[string]int {
	m := map[string]int{}
	for _, e := range es {
		m[e.Type]++
	}
	return m
}

func TestMonitorEventsAndDrift(t *testing.T) {
	store, _ := history.Open(filepath.Join(t.TempDir(), "h"))
	sink := &capture{}
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	baseline := rep(t0, map[string]finding.Severity{"known": finding.High})
	m := &Monitor{Store: store, Sinks: []notify.Sink{sink}, MinSeverity: finding.Medium, Baseline: baseline}

	res, err := m.Process(context.Background(), rep(t0, map[string]finding.Severity{"known": finding.High}))
	if err != nil || res.SincePrevious != nil || res.Regressed(finding.High) {
		t.Fatalf("first: %+v %v", res, err)
	}
	if got := types(res.Events); got[notify.AssessmentCompleted] != 1 || got[notify.FindingIntroduced] != 0 {
		t.Errorf("first events = %v", got)
	}

	res, _ = m.Process(context.Background(), rep(t0.Add(time.Hour), map[string]finding.Severity{
		"known": finding.High, "new-critical": finding.Critical, "new-low": finding.Low,
	}))
	if got := types(res.Events); got[notify.FindingIntroduced] != 1 {
		t.Errorf("low-severity finding not filtered: %v", got)
	}
	if !res.Regressed(finding.High) || *res.Events[len(res.Events)-1].Drift != 2 {
		t.Error("baseline drift not detected")
	}

	res, _ = m.Process(context.Background(), rep(t0.Add(2*time.Hour), map[string]finding.Severity{"known": finding.High}))
	if got := types(res.Events); got[notify.FindingResolved] != 1 {
		t.Errorf("resolution not reported: %v", got)
	}
	if res.Regressed(finding.Info) {
		t.Error("back at baseline but reported as regressed")
	}
	if entries, _, _ := store.List(); len(entries) != 3 {
		t.Errorf("history has %d entries, want 3", len(entries))
	}
}

func TestMonitorReportsIncompleteAndDeliveryFailure(t *testing.T) {
	store, _ := history.Open(filepath.Join(t.TempDir(), "h"))
	sink := &capture{err: errors.New("down")}
	m := &Monitor{Store: store, Sinks: []notify.Sink{sink}}
	r := rep(time.Now(), nil)
	r.Errors = []string{"collection: cannot list pods: forbidden"}
	res, err := m.Process(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if types(res.Events)[notify.AssessmentIncomplete] != 1 {
		t.Error("incomplete assessment not announced")
	}
	if len(res.DeliveryErrors) != 1 {
		t.Error("delivery failure not surfaced")
	}
}
