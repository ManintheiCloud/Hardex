package monitoring

import (
	"context"
	"errors"
	"fmt"
	"os"
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

// A failed delivery must delay alerts, not lose them: the next assessment
// compares with the recorded one, so its events alone would never repeat
// the missed "introduced" event.
func TestUndeliveredEventsAreRedelivered(t *testing.T) {
	store, err := history.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sink := &capture{}
	m := &Monitor{Store: store, Sinks: []notify.Sink{sink}}
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if _, err := m.Process(context.Background(), rep(t0, nil)); err != nil {
		t.Fatal(err)
	}
	// The sink is down when a critical finding appears.
	sink.err = errors.New("connection refused")
	res, err := m.Process(context.Background(), rep(t0.Add(time.Hour), map[string]finding.Severity{"evil": finding.Critical}))
	if err != nil || len(res.DeliveryErrors) != 1 {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	// Still down: the batch keeps both runs' events.
	if _, err := m.Process(context.Background(), rep(t0.Add(2*time.Hour), map[string]finding.Severity{"evil": finding.Critical})); err != nil {
		t.Fatal(err)
	}
	// Back up: the missed alert arrives, marked late, then the outbox is empty.
	sink.err = nil
	res, err = m.Process(context.Background(), rep(t0.Add(3*time.Hour), map[string]finding.Severity{"evil": finding.Critical}))
	if err != nil || len(res.DeliveryErrors) != 0 {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	last := sink.batches[len(sink.batches)-1]
	introduced, late := 0, 0
	for _, e := range last {
		if e.Type == notify.FindingIntroduced && e.Finding.Resource.Name == "evil" {
			introduced++
			if !e.Late {
				t.Error("redelivered event not marked late")
			}
		}
		if e.Late {
			late++
		}
	}
	if introduced != 1 || late == 0 {
		t.Fatalf("introduced=%d late=%d in %+v", introduced, late, last)
	}
	if _, err := os.Stat(filepath.Join(store.Dir(), "undelivered-capture.json")); !os.IsNotExist(err) {
		t.Errorf("outbox not cleared: %v", err)
	}
	// The next batch carries only its own events.
	res, _ = m.Process(context.Background(), rep(t0.Add(4*time.Hour), map[string]finding.Severity{"evil": finding.Critical}))
	for _, e := range sink.batches[len(sink.batches)-1] {
		if e.Late {
			t.Error("event redelivered twice")
		}
	}
	// The outbox is not mistaken for a report.
	entries, warns, _ := store.List()
	if len(entries) != 5 || len(warns) != 0 {
		t.Errorf("history: %d entries, warnings %v", len(entries), warns)
	}
}

func TestUndeliveredEventsAreBounded(t *testing.T) {
	store, _ := history.Open(t.TempDir())
	sink := &capture{err: errors.New("down")}
	m := &Monitor{Store: store, Sinks: []notify.Sink{sink}}
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	items := map[string]finding.Severity{}
	for i := 0; i < 700; i++ {
		items[fmt.Sprintf("p%d", i)] = finding.High
	}
	m.Process(context.Background(), rep(t0, nil))
	m.Process(context.Background(), rep(t0.Add(time.Hour), items)) // 700 introduced
	m.Process(context.Background(), rep(t0.Add(2*time.Hour), nil)) // 700 resolved
	sink.err = nil
	m.Process(context.Background(), rep(t0.Add(3*time.Hour), nil))
	last := sink.batches[len(sink.batches)-1]
	if len(last) != MaxUndelivered+1 || last[0].Type != notify.EventsDropped {
		t.Fatalf("batch of %d, first %q", len(last), last[0].Type)
	}
}
