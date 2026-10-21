// Package score turns a report into a posture score and per-framework
// evidence.
//
// The score is deliberately simple so that anyone can recompute it by hand:
// every evaluated rule carries a weight by its default severity (critical 10,
// high 5, medium 3, low 1, info 0.5), and the score is the weighted share of
// rules with no active findings. Instance counts do not move the score —
// twenty privileged pods and one privileged pod are the same failed control —
// they are reported alongside it. Inventory rules (lists for review, such as
// HX-WL-022) are not scored.
//
// A score is evidence, not a verdict: passing every rule does not make a
// cluster secure, and an incomplete assessment has no valid score at all.
package score

import (
	"math"
	"sort"

	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/finding"
)

// Weights by default rule severity.
var Weights = map[finding.Severity]float64{
	finding.Critical: 10, finding.High: 5, finding.Medium: 3, finding.Low: 1, finding.Info: 0.5,
}

// Status of one rule in one assessment.
type Status string

const (
	Pass     Status = "pass"
	Fail     Status = "fail"
	Accepted Status = "accepted" // only waived findings: risk accepted, not fixed
)

// RuleResult is one rule's outcome.
type RuleResult struct {
	ID       string           `json:"id"`
	Title    string           `json:"title"`
	Category string           `json:"category"`
	Severity finding.Severity `json:"severity"`
	Status   Status           `json:"status"`
	Active   int              `json:"active"`
	Waived   int              `json:"waived"`
	Weight   float64          `json:"weight"`
}

// Group aggregates rule results (a category or a framework control).
type Group struct {
	Name   string       `json:"name"`
	Score  float64      `json:"score"`
	Passed int          `json:"passed"`
	Failed int          `json:"failed"`
	Rules  []RuleResult `json:"rules"`
}

// Framework is evidence for one external framework.
type Framework struct {
	Name     string  `json:"name"`
	Controls []Group `json:"controls"`
}

// Result is the full scoring of a report.
type Result struct {
	// Valid is false when the assessment was incomplete; Score and Grade
	// are then not meaningful.
	Valid      bool         `json:"valid"`
	Score      float64      `json:"score"`
	Grade      string       `json:"grade"`
	GradeNote  string       `json:"gradeNote,omitempty"`
	Rules      []RuleResult `json:"rules"`
	Categories []Group      `json:"categories"`
	Frameworks []Framework  `json:"frameworks"`
}

// Compute scores a report. metas describes the rules (built-in and module
// rules); evaluated rules without metadata are ignored.
func Compute(r *finding.Report, metas []assessment.Metadata) Result {
	byID := map[string]assessment.Metadata{}
	for _, m := range metas {
		byID[m.ID] = m
	}
	active, waived := map[string]int{}, map[string]int{}
	critical := false
	for _, f := range r.Findings {
		active[f.RuleID]++
		if f.Severity == finding.Critical {
			critical = true
		}
	}
	for _, f := range r.Waived {
		waived[f.RuleID]++
	}

	res := Result{Valid: r.Complete()}
	cats := map[string]*Group{}
	frameworks := map[string]map[string]*Group{}
	for _, id := range r.RulesEvaluated {
		m, ok := byID[id]
		if !ok || m.Inventory {
			continue // inventories list things for review; they are not controls
		}
		rr := RuleResult{ID: id, Title: m.Title, Category: m.Category, Severity: m.Severity,
			Active: active[id], Waived: waived[id], Weight: Weights[m.Severity], Status: Pass}
		switch {
		case rr.Active > 0:
			rr.Status = Fail
		case rr.Waived > 0:
			rr.Status = Accepted
		}
		res.Rules = append(res.Rules, rr)
		add(cats, m.Category, rr)
		for _, ref := range m.References {
			if frameworks[ref.Framework] == nil {
				frameworks[ref.Framework] = map[string]*Group{}
			}
			add(frameworks[ref.Framework], ref.Control, rr)
		}
	}
	res.Score = scoreOf(res.Rules)
	res.Grade, res.GradeNote = grade(res.Score, critical)
	if !res.Valid {
		res.Grade, res.GradeNote = "—", "assessment incomplete; no valid score"
	}
	res.Categories = flatten(cats)
	names := make([]string, 0, len(frameworks))
	for n := range frameworks {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		res.Frameworks = append(res.Frameworks, Framework{Name: n, Controls: flatten(frameworks[n])})
	}
	return res
}

func add(groups map[string]*Group, name string, rr RuleResult) {
	g := groups[name]
	if g == nil {
		g = &Group{Name: name}
		groups[name] = g
	}
	g.Rules = append(g.Rules, rr)
	if rr.Status == Fail {
		g.Failed++
	} else {
		g.Passed++
	}
}

func flatten(groups map[string]*Group) []Group {
	out := make([]Group, 0, len(groups))
	for _, g := range groups {
		g.Score = scoreOf(g.Rules)
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func scoreOf(rules []RuleResult) float64 {
	var total, passed float64
	for _, r := range rules {
		total += r.Weight
		if r.Status != Fail {
			passed += r.Weight
		}
	}
	if total == 0 {
		return 100
	}
	return math.Round(1000*passed/total) / 10
}

// grade maps a score to A–F. Any active critical finding caps the grade at
// D: a single direct path to compromise outweighs any number of passing
// controls.
func grade(s float64, critical bool) (string, string) {
	g := "F"
	switch {
	case s >= 90:
		g = "A"
	case s >= 80:
		g = "B"
	case s >= 70:
		g = "C"
	case s >= 60:
		g = "D"
	}
	if critical && g < "D" {
		return "D", "capped at D: active critical findings"
	}
	return g, ""
}
