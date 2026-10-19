package assessment

import (
	"fmt"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

// Registry is an ordered, validated set of rules with unique IDs.
type Registry struct {
	rules []Rule
	byID  map[string]Rule
}

// NewRegistry validates and indexes the given rules.
func NewRegistry(rules ...Rule) (*Registry, error) {
	r := &Registry{byID: map[string]Rule{}}
	for _, rule := range rules {
		m := rule.Metadata()
		if err := m.Validate(); err != nil {
			return nil, err
		}
		if _, dup := r.byID[m.ID]; dup {
			return nil, fmt.Errorf("duplicate rule id %s", m.ID)
		}
		r.byID[m.ID] = rule
		r.rules = append(r.rules, rule)
	}
	sort.Slice(r.rules, func(i, j int) bool {
		return r.rules[i].Metadata().ID < r.rules[j].Metadata().ID
	})
	return r, nil
}

// All returns every rule, sorted by ID.
func (r *Registry) All() []Rule { return append([]Rule(nil), r.rules...) }

// Get returns a rule by ID.
func (r *Registry) Get(id string) (Rule, bool) {
	rule, ok := r.byID[strings.ToUpper(id)]
	return rule, ok
}

// Result is the raw output of evaluating rules, before policy is applied.
type Result struct {
	Findings []finding.Finding
	Errors   []string
	Ran      []string
	// Timings records how long each rule took, in evaluation order.
	Timings []Timing
}

// Timing is the wall-clock cost of one rule.
type Timing struct {
	RuleID   string
	Duration time.Duration
	Findings int
}

// Evaluate runs each rule against the inventory.
//
// A rule that panics is recorded as an error rather than crashing the run or
// being silently dropped: an assessment that quietly skipped a check would
// overstate the cluster's security, which is the failure mode Hardex exists
// to prevent.
func Evaluate(inv *resource.Inventory, rules []Rule, opts Options) Result {
	var res Result
	for _, rule := range rules {
		meta := rule.Metadata()
		ctx := &Context{Inventory: inv, Options: opts, meta: meta}
		start := time.Now()
		err := safeEvaluate(rule, ctx)
		res.Timings = append(res.Timings, Timing{RuleID: meta.ID, Duration: time.Since(start), Findings: len(ctx.findings)})
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", meta.ID, err))
			continue
		}
		res.Ran = append(res.Ran, meta.ID)
		res.Findings = append(res.Findings, ctx.findings...)
	}
	finding.Sort(res.Findings)
	return res
}

func safeEvaluate(rule Rule, ctx *Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("rule panicked: %v (stack: %s)", r, firstFrames(debug.Stack()))
		}
	}()
	rule.Evaluate(ctx)
	return nil
}

// firstFrames condenses a stack trace to the frames inside rule code, so a
// panic report points at the faulty check without flooding the output.
func firstFrames(stack []byte) string {
	var frames []string
	for _, line := range strings.Split(string(stack), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "/Hardex/kubernetes/") && strings.Contains(line, ".go:") {
			if i := strings.LastIndex(line, " +0x"); i > 0 {
				line = line[:i]
			}
			frames = append(frames, line)
			if len(frames) == 3 {
				break
			}
		}
	}
	if len(frames) == 0 {
		return "unavailable"
	}
	return strings.Join(frames, " <- ")
}
