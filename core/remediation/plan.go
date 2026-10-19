package remediation

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

// Risk is the likelihood that applying a change disrupts a workload.
type Risk int

const (
	// Low: the change removes a capability almost no workload uses.
	Low Risk = iota + 1
	// Medium: many workloads are unaffected, some will fail to start or
	// misbehave; test before applying.
	Medium
	// High: commonly breaks workloads or connectivity; never applied in bulk.
	High
)

func (r Risk) String() string {
	switch r {
	case Low:
		return "low"
	case Medium:
		return "medium"
	case High:
		return "high"
	}
	return fmt.Sprintf("risk(%d)", int(r))
}

func (r Risk) MarshalJSON() ([]byte, error) { return []byte(`"` + r.String() + `"`), nil }

func (r *Risk) UnmarshalJSON(b []byte) error {
	v, err := ParseRisk(strings.Trim(string(b), `"`))
	if err != nil {
		return err
	}
	*r = v
	return nil
}

// ParseRisk parses low, medium or high.
func ParseRisk(s string) (Risk, error) {
	switch strings.ToLower(s) {
	case "low":
		return Low, nil
	case "medium":
		return Medium, nil
	case "high":
		return High, nil
	}
	return 0, fmt.Errorf("unknown risk %q (want low, medium or high)", s)
}

// Assignment sets (or removes) one field, addressed by path segments from the
// object root. Missing intermediate objects are created.
type Assignment struct {
	Path   []string
	Value  any
	Remove bool
}

// Change is what a fixer proposes for one finding.
type Change struct {
	Description string
	Risk        Risk
	// Set modifies the finding's object.
	Set []Assignment
	// Create is a new object to add instead (e.g. a default-deny
	// NetworkPolicy). Creations are never applied to a cluster
	// automatically; they are emitted as manifests for review.
	Create map[string]any
}

// Fixer proposes a change for a finding on obj, or returns a reason why it
// cannot be fixed automatically.
type Fixer func(obj *resource.Object, f finding.Finding) (*Change, string)

// Target identifies a changed object.
type Target struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
	Source     string `json:"source,omitempty"`
	Line       int    `json:"line,omitempty"`
}

func (t Target) String() string {
	if t.Namespace != "" {
		return t.Kind + " " + t.Namespace + "/" + t.Name
	}
	return t.Kind + " " + t.Name
}

// FixSummary records which finding a change addresses.
type FixSummary struct {
	RuleID      string `json:"ruleId"`
	Fingerprint string `json:"fingerprint"`
	Container   string `json:"container,omitempty"`
	Description string `json:"description"`
	Risk        Risk   `json:"risk"`
}

// ObjectPlan is the combined change to one object.
type ObjectPlan struct {
	Target Target       `json:"target"`
	Fixes  []FixSummary `json:"fixes"`
	Risk   Risk         `json:"risk"`
	// Patch is the guarded forward patch.
	Patch []Op `json:"patch"`
	// Inverse restores the original values; it is guarded by tests on the
	// values Patch sets, so it refuses to undo changes made by someone else.
	Inverse []Op `json:"inverse"`

	Original map[string]any `json:"-"`
	Patched  map[string]any `json:"-"`
}

// CreatePlan is a new object proposed for review.
type CreatePlan struct {
	Fix    FixSummary     `json:"fix"`
	Object map[string]any `json:"object"`
}

// Skip is a finding that will not be remediated, and why.
type Skip struct {
	RuleID      string `json:"ruleId"`
	Fingerprint string `json:"fingerprint"`
	Resource    string `json:"resource"`
	Reason      string `json:"reason"`
}

// Plan is the complete set of proposed changes.
type Plan struct {
	Objects []ObjectPlan `json:"objects"`
	Creates []CreatePlan `json:"creates,omitempty"`
	Skipped []Skip       `json:"skipped,omitempty"`
}

// Options control planning.
type Options struct {
	// Rules limits remediation to these rule IDs; empty means all.
	Rules map[string]bool
	// MaxRisk excludes changes riskier than this.
	MaxRisk Risk
	// GuardResourceVersion adds a test on metadata.resourceVersion, so a
	// patch against a live object fails if the object changed since it was
	// read.
	GuardResourceVersion bool
}

// Build plans remediation of findings against the inventory they came from.
func Build(inv *resource.Inventory, findings []finding.Finding, fixers map[string]Fixer, opts Options) (*Plan, error) {
	if opts.MaxRisk == 0 {
		opts.MaxRisk = Medium
	}
	plan := &Plan{}
	type group struct {
		obj      *resource.Object
		findings []finding.Finding
	}
	groups := map[*resource.Object]*group{}
	createdNames := map[string]bool{}
	var order []*resource.Object

	for _, f := range findings {
		skip := func(reason string) {
			plan.Skipped = append(plan.Skipped, Skip{RuleID: f.RuleID, Fingerprint: f.Fingerprint, Resource: f.Resource.String(), Reason: reason})
		}
		if len(opts.Rules) > 0 && !opts.Rules[f.RuleID] {
			continue
		}
		if f.Waiver != nil {
			skip("waived")
			continue
		}
		if fixers[f.RuleID] == nil {
			skip("no automatic fix; see the rule's remediation guidance")
			continue
		}
		obj := find(inv, f.Resource)
		if obj == nil {
			// Some fixes create an object rather than changing one (e.g. a
			// NetworkPolicy for a namespace that has no Namespace manifest).
			if ch, _ := fixers[f.RuleID](nil, f); ch != nil && ch.Create != nil {
				if ch.Risk > opts.MaxRisk {
					skip(fmt.Sprintf("risk %s exceeds the allowed maximum (%s)", ch.Risk, opts.MaxRisk))
				} else {
					addCreate(plan, createdNames, ch, FixSummary{RuleID: f.RuleID, Fingerprint: f.Fingerprint, Description: ch.Description, Risk: ch.Risk})
				}
				continue
			}
			skip("object not found in input")
			continue
		}
		g, ok := groups[obj]
		if !ok {
			g = &group{obj: obj}
			groups[obj] = g
			order = append(order, obj)
		}
		g.findings = append(g.findings, f)
	}

	for _, obj := range order {
		g := groups[obj]
		state := DeepCopy(obj.Raw).(map[string]any)
		op := ObjectPlan{
			Target:   Target{APIVersion: obj.APIVersion, Kind: obj.Kind, Namespace: namespaceOf(obj), Name: obj.Name, Source: obj.Source, Line: obj.Line},
			Original: obj.Raw,
		}
		var inverseGroups [][]Op
		for _, f := range g.findings {
			ch, reason := fixers[f.RuleID](obj, f)
			skip := func(r string) {
				plan.Skipped = append(plan.Skipped, Skip{RuleID: f.RuleID, Fingerprint: f.Fingerprint, Resource: f.Resource.String(), Reason: r})
			}
			if ch == nil {
				skip(reason)
				continue
			}
			if ch.Risk > opts.MaxRisk {
				skip(fmt.Sprintf("risk %s exceeds the allowed maximum (%s)", ch.Risk, opts.MaxRisk))
				continue
			}
			summary := FixSummary{RuleID: f.RuleID, Fingerprint: f.Fingerprint, Container: f.Resource.Container, Description: ch.Description, Risk: ch.Risk}
			if ch.Create != nil {
				addCreate(plan, createdNames, ch, summary)
				continue
			}
			var fixOps []Op
			var err error
			for _, a := range ch.Set {
				var ops, inv []Op
				state, ops, inv, err = assign(state, a)
				if err != nil {
					break
				}
				fixOps = append(fixOps, ops...)
				inverseGroups = append(inverseGroups, inv)
			}
			if err != nil {
				skip("cannot build patch: " + err.Error())
				continue
			}
			if len(fixOps) == 0 {
				skip("already satisfied by another change in this plan")
				continue
			}
			op.Patch = append(op.Patch, fixOps...)
			op.Fixes = append(op.Fixes, summary)
			if ch.Risk > op.Risk {
				op.Risk = ch.Risk
			}
		}
		if len(op.Patch) == 0 {
			continue
		}
		if rv := resource.String(obj.Raw, "metadata", "resourceVersion"); opts.GuardResourceVersion && rv != "" {
			op.Patch = append([]Op{{Op: "test", Path: "/metadata/resourceVersion", Value: rv}}, op.Patch...)
		}
		for i := len(inverseGroups) - 1; i >= 0; i-- {
			op.Inverse = append(op.Inverse, inverseGroups[i]...)
		}
		// Self-check: the patch must apply to the original and the inverse
		// must restore it exactly. A plan that fails this is a bug.
		patched, err := Apply(obj.Raw, op.Patch)
		if err != nil {
			return nil, fmt.Errorf("%s: internal error: patch does not apply: %w", op.Target, err)
		}
		restored, err := Apply(patched, op.Inverse)
		if err != nil || !jsonEqual(restored, obj.Raw) {
			return nil, fmt.Errorf("%s: internal error: inverse patch does not restore the original", op.Target)
		}
		op.Patched = patched
		plan.Objects = append(plan.Objects, op)
	}
	sort.SliceStable(plan.Objects, func(i, j int) bool { return plan.Objects[i].Target.String() < plan.Objects[j].Target.String() })
	return plan, nil
}

func addCreate(plan *Plan, seen map[string]bool, ch *Change, summary FixSummary) {
	key := fmt.Sprint(ch.Create["kind"], "/", resource.String(ch.Create, "metadata", "namespace"), "/", resource.String(ch.Create, "metadata", "name"))
	if !seen[key] {
		seen[key] = true
		plan.Creates = append(plan.Creates, CreatePlan{Fix: summary, Object: ch.Create})
	}
}

// assign applies one assignment to state, returning the new state, the
// guarded forward ops and the ops that undo them.
func assign(state map[string]any, a Assignment) (map[string]any, []Op, []Op, error) {
	var ops, inverse []Op
	var cur any = state
	for i, seg := range a.Path[:len(a.Path)-1] {
		m, ok := cur.(map[string]any)
		if arr, isArr := cur.([]any); isArr {
			idx, err := arrayIndex(seg, len(arr), false)
			if err != nil {
				return nil, nil, nil, err
			}
			cur = arr[idx]
			continue
		}
		if !ok {
			return nil, nil, nil, fmt.Errorf("%s is not an object", Pointer(a.Path[:i]))
		}
		next, exists := m[seg]
		if !exists || next == nil {
			if a.Remove {
				return state, nil, nil, nil // nothing to remove
			}
			p := Pointer(a.Path[:i+1])
			ops = append(ops, Op{Op: "add", Path: p, Value: map[string]any{}})
			inverse = append([]Op{{Op: "test", Path: p, Value: map[string]any{}}, {Op: "remove", Path: p}}, inverse...)
			m[seg] = map[string]any{}
			next = m[seg]
		}
		cur = next
	}
	parent, ok := cur.(map[string]any)
	if !ok {
		return nil, nil, nil, fmt.Errorf("%s is not an object", Pointer(a.Path[:len(a.Path)-1]))
	}
	key := a.Path[len(a.Path)-1]
	p := Pointer(a.Path)
	old, exists := parent[key]
	switch {
	case a.Remove && !exists:
		return state, ops, inverse, nil
	case a.Remove:
		ops = append(ops, Op{Op: "test", Path: p, Value: old}, Op{Op: "remove", Path: p})
		inverse = append([]Op{{Op: "add", Path: p, Value: old}}, inverse...)
		delete(parent, key)
	case exists && jsonEqual(old, a.Value):
		return state, ops, inverse, nil
	case exists:
		ops = append(ops, Op{Op: "test", Path: p, Value: old}, Op{Op: "replace", Path: p, Value: a.Value})
		inverse = append([]Op{{Op: "test", Path: p, Value: a.Value}, {Op: "replace", Path: p, Value: old}}, inverse...)
		parent[key] = DeepCopy(a.Value)
	default:
		ops = append(ops, Op{Op: "add", Path: p, Value: a.Value})
		inverse = append([]Op{{Op: "test", Path: p, Value: a.Value}, {Op: "remove", Path: p}}, inverse...)
		parent[key] = DeepCopy(a.Value)
	}
	return state, ops, inverse, nil
}

func find(inv *resource.Inventory, r finding.Resource) *resource.Object {
	for _, o := range inv.OfKind(r.Kind) {
		if o.Name == r.Name && o.EffectiveNamespace() == r.Namespace {
			return o
		}
	}
	return nil
}

func namespaceOf(o *resource.Object) string { return o.EffectiveNamespace() }

// ParsePath splits a finding path such as
// "spec.template.spec.containers[0].securityContext.privileged" into
// segments. Bracketed segments may contain dots and slashes (annotation keys).
func ParsePath(p string) []string {
	var segs []string
	var cur strings.Builder
	inBracket := false
	flush := func() {
		if cur.Len() > 0 {
			segs = append(segs, cur.String())
			cur.Reset()
		}
	}
	for _, r := range p {
		switch {
		case r == '[' && !inBracket:
			flush()
			inBracket = true
		case r == ']' && inBracket:
			flush()
			inBracket = false
		case r == '.' && !inBracket:
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return segs
}
