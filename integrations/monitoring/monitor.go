// Package monitoring turns repeated assessments into continuous protection:
// every assessment is recorded, compared with the previous one, and changes
// are delivered as events.
package monitoring

import (
	"context"
	"fmt"
	"time"

	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/history"
	"github.com/ManintheiCloud/Hardex/core/verification"
	"github.com/ManintheiCloud/Hardex/integrations/notify"
)

// Monitor processes successive assessments.
type Monitor struct {
	Store *history.Store
	// Baseline, if set, is the approved state: findings not present in it
	// are counted as drift and govern the exit status of one-shot runs.
	Baseline *finding.Report
	Sinks    []notify.Sink
	// MinSeverity filters per-finding events (summary events are always sent).
	MinSeverity finding.Severity
	// Keep bounds the history (0 = unlimited).
	Keep int
}

// Result describes one processed assessment.
type Result struct {
	Path string
	// Changes since the previous recorded assessment (nil on the first).
	SincePrevious *verification.Comparison
	// SinceBaseline is set when a baseline is configured.
	SinceBaseline *verification.Comparison
	Events        []notify.Event
	// DeliveryErrors are sinks that failed. Undelivered alerts are a
	// failure of the monitor, so callers should surface them.
	DeliveryErrors []error
}

// Process records a report, compares it and delivers events.
func (m *Monitor) Process(ctx context.Context, r *finding.Report) (*Result, error) {
	prev, err := m.Store.Latest()
	if err != nil {
		return nil, fmt.Errorf("read history: %w", err)
	}
	path, err := m.Store.Save(r)
	if err != nil {
		return nil, fmt.Errorf("record assessment: %w", err)
	}
	if _, err := m.Store.Prune(m.Keep); err != nil {
		return nil, fmt.Errorf("prune history: %w", err)
	}
	res := &Result{Path: path}
	if prev != nil {
		c := verification.Compare(prev.Report, r)
		res.SincePrevious = &c
	}
	if m.Baseline != nil {
		c := verification.Compare(m.Baseline, r)
		res.SinceBaseline = &c
	}
	res.Events = m.events(r, res, prev == nil)
	for _, s := range m.Sinks {
		if err := s.Send(ctx, res.Events); err != nil {
			res.DeliveryErrors = append(res.DeliveryErrors, fmt.Errorf("%s: %w", s.Name(), err))
		}
	}
	return res, nil
}

func (m *Monitor) events(r *finding.Report, res *Result, first bool) []notify.Event {
	base := notify.Event{Time: r.GeneratedAt, Inputs: r.Inputs, Profile: r.Profile}
	var out []notify.Event
	if c := res.SincePrevious; c != nil {
		for i := range c.Introduced {
			f := c.Introduced[i]
			if f.Severity < m.MinSeverity {
				continue
			}
			e := base
			e.Type, e.Finding = notify.FindingIntroduced, &f
			e.Message = fmt.Sprintf("new %s finding %s on %s: %s", f.Severity, f.RuleID, f.Resource, f.Message)
			out = append(out, e)
		}
		for i := range c.Resolved {
			f := c.Resolved[i]
			if f.Severity < m.MinSeverity {
				continue
			}
			e := base
			e.Type, e.Finding = notify.FindingResolved, &f
			e.Message = fmt.Sprintf("resolved %s finding %s on %s", f.Severity, f.RuleID, f.Resource)
			out = append(out, e)
		}
	}
	if !r.Complete() {
		e := base
		e.Type = notify.AssessmentIncomplete
		e.Message = fmt.Sprintf("assessment incomplete (%d error(s)); results understate risk: %v", len(r.Errors), r.Errors)
		out = append(out, e)
	}
	summary := r.Summary
	e := base
	e.Type, e.Summary = notify.AssessmentCompleted, &summary
	e.Message = fmt.Sprintf("%d active findings (critical %d, high %d)", summary.Total, summary.Critical, summary.High)
	switch {
	case first && m.Baseline == nil:
		e.Message += "; first recorded assessment, reference established"
	case res.SincePrevious != nil:
		e.Message += fmt.Sprintf("; %d new, %d resolved since the previous assessment", len(res.SincePrevious.Introduced), len(res.SincePrevious.Resolved))
	}
	if c := res.SinceBaseline; c != nil {
		drift := len(c.Introduced)
		e.Drift = &drift
		e.Message += fmt.Sprintf("; %d finding(s) drifted from the approved baseline", drift)
	}
	return append(out, e)
}

// Regressed reports whether this assessment should fail a one-shot run:
// drift from the baseline (if set) or new findings since the previous
// assessment, at or above the threshold.
func (r *Result) Regressed(threshold finding.Severity) bool {
	if r.SinceBaseline != nil {
		return r.SinceBaseline.Regressed(threshold)
	}
	return r.SincePrevious != nil && r.SincePrevious.Regressed(threshold)
}

// Every runs fn immediately and then at each interval until ctx is done.
func Every(ctx context.Context, interval time.Duration, fn func(context.Context)) {
	fn(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn(ctx)
		}
	}
}
