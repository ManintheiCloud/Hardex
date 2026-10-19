// Package fleet compares assessments of several clusters (or environments)
// to expose inconsistent security practices: controls enforced in one place
// and missing in another.
package fleet

import (
	"sort"

	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/score"
)

// Member is one assessed environment.
type Member struct {
	Label  string
	Report *finding.Report
}

// Cell is one rule's outcome in one member.
type Cell struct {
	Evaluated bool         `json:"evaluated"`
	Status    score.Status `json:"status,omitempty"`
	Active    int          `json:"active"`
}

// Row is one rule across the fleet.
type Row struct {
	RuleID   string           `json:"ruleId"`
	Title    string           `json:"title"`
	Severity finding.Severity `json:"severity"`
	Cells    []Cell           `json:"cells"`
	// Inconsistent: evaluated in at least two members, failing in some and
	// passing in others.
	Inconsistent bool `json:"inconsistent"`
	// FailingEverywhere: failing in every member that evaluated it.
	FailingEverywhere bool `json:"failingEverywhere"`
}

// Summary is one member's headline.
type Summary struct {
	Label    string          `json:"label"`
	Score    float64         `json:"score"`
	Grade    string          `json:"grade"`
	Valid    bool            `json:"valid"`
	Profile  string          `json:"profile"`
	Findings finding.Summary `json:"findings"`
}

// Comparison is the fleet view.
type Comparison struct {
	Members []Summary `json:"members"`
	// Rows lists every rule that fails somewhere, worst first.
	Rows []Row `json:"rows"`
	// Caveats explain why members may not be comparable.
	Caveats []string `json:"caveats,omitempty"`
}

// Compare builds the fleet view.
func Compare(members []Member, metas []assessment.Metadata) Comparison {
	var c Comparison
	results := make([]score.Result, len(members))
	profiles := map[string]bool{}
	for i, m := range members {
		results[i] = score.Compute(m.Report, metas)
		c.Members = append(c.Members, Summary{Label: m.Label, Score: results[i].Score, Grade: results[i].Grade,
			Valid: results[i].Valid, Profile: m.Report.Profile, Findings: m.Report.Summary})
		profiles[m.Report.Profile] = true
		if !results[i].Valid {
			c.Caveats = append(c.Caveats, m.Label+": assessment incomplete; its results understate risk")
		}
	}
	if len(profiles) > 1 {
		c.Caveats = append(c.Caveats, "members were assessed with different profiles; rules not evaluated everywhere are marked")
	}

	rows := map[string]*Row{}
	for i, res := range results {
		for _, rr := range res.Rules {
			row := rows[rr.ID]
			if row == nil {
				row = &Row{RuleID: rr.ID, Title: rr.Title, Severity: rr.Severity, Cells: make([]Cell, len(members))}
				rows[rr.ID] = row
			}
			row.Cells[i] = Cell{Evaluated: true, Status: rr.Status, Active: rr.Active}
		}
	}
	for _, row := range rows {
		evaluated, failing := 0, 0
		for _, cell := range row.Cells {
			if cell.Evaluated {
				evaluated++
				if cell.Status == score.Fail {
					failing++
				}
			}
		}
		if failing == 0 {
			continue
		}
		row.Inconsistent = evaluated >= 2 && failing < evaluated
		row.FailingEverywhere = failing == evaluated
		c.Rows = append(c.Rows, *row)
	}
	sort.Slice(c.Rows, func(i, j int) bool {
		a, b := c.Rows[i], c.Rows[j]
		if a.Inconsistent != b.Inconsistent {
			return a.Inconsistent
		}
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		return a.RuleID < b.RuleID
	})
	return c
}
