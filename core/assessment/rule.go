// Package assessment defines the rule contract and the engine that evaluates
// rules against an inventory of Kubernetes objects.
package assessment

import (
	"fmt"
	"regexp"

	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

// Categories group rules by the part of the cluster they assess.
const (
	CategoryWorkloads    = "workloads"
	CategoryRBAC         = "rbac"
	CategoryNetworking   = "networking"
	CategoryControlPlane = "control-plane"
	CategoryNodes        = "nodes"
	CategorySecrets      = "secrets"
	CategorySupplyChain  = "supply-chain"
)

// Metadata describes a rule. Every field except References is required; the
// registry rejects incomplete rules so that every finding a user sees comes
// with an explanation and a fix.
type Metadata struct {
	ID       string
	Title    string
	Severity finding.Severity
	Category string
	// Description says what the rule checks.
	Description string
	// Rationale says why it matters: what an attacker gains.
	Rationale string
	// Remediation says how to fix it.
	Remediation string
	References  []finding.Reference
	// Limitations documents known blind spots (static analysis gaps, defaults
	// that cannot be observed from manifests). Optional but encouraged.
	Limitations string
}

var idPattern = regexp.MustCompile(`^HX-[A-Z]+-\d{3}$`)

// Validate reports whether the metadata is complete.
func (m Metadata) Validate() error {
	switch {
	case !idPattern.MatchString(m.ID):
		return fmt.Errorf("rule id %q does not match %s", m.ID, idPattern)
	case m.Title == "", m.Category == "", m.Description == "", m.Rationale == "", m.Remediation == "":
		return fmt.Errorf("rule %s: title, category, description, rationale and remediation are required", m.ID)
	case m.Severity < finding.Info || m.Severity > finding.Critical:
		return fmt.Errorf("rule %s: invalid severity", m.ID)
	}
	return nil
}

// Rule is a single security check.
//
// Rules must be pure functions of the inventory: they must not perform I/O,
// mutate objects, or depend on wall-clock time. This keeps assessments
// reproducible, which is a precondition for verification.
type Rule interface {
	Metadata() Metadata
	Evaluate(ctx *Context)
}

// Options tune rule behaviour.
type Options struct {
	// IncludeSystem evaluates objects that Kubernetes itself manages
	// (system:* RBAC objects, kube-system networking). Off by default because
	// operators usually cannot change them, but available for full audits.
	IncludeSystem bool
}

// Context is passed to a rule during evaluation.
type Context struct {
	Inventory *resource.Inventory
	Options   Options

	meta     Metadata
	findings []finding.Finding
}

// Hit describes one occurrence of a rule's weakness.
type Hit struct {
	Object    *resource.Object
	Container string
	Path      string
	Observed  string
	Message   string
	// Severity overrides the rule's default severity for this occurrence
	// (e.g. a wildcard ClusterRole is worse than a wildcard Role). Zero value
	// means "use the rule default"; use SeverityOverride to set Info.
	Severity *finding.Severity
}

// SeverityOverride is a helper for Hit.Severity.
func SeverityOverride(s finding.Severity) *finding.Severity { return &s }

// Report records a finding for the current rule.
func (c *Context) Report(h Hit) {
	sev := c.meta.Severity
	if h.Severity != nil {
		sev = *h.Severity
	}
	f := finding.Finding{
		RuleID:   c.meta.ID,
		Title:    c.meta.Title,
		Severity: sev,
		Category: c.meta.Category,
		Resource: finding.Resource{
			Kind:      h.Object.Kind,
			Namespace: h.Object.EffectiveNamespace(),
			Name:      h.Object.Name,
			Container: h.Container,
			Source:    h.Object.Source,
			Line:      h.Object.Line,
		},
		Message:     h.Message,
		Path:        h.Path,
		Observed:    h.Observed,
		Remediation: c.meta.Remediation,
		References:  c.meta.References,
	}
	f.ComputeFingerprint()
	c.findings = append(c.findings, f)
}

// ObjectRule is a convenience Rule that evaluates each object of the listed
// kinds independently.
type ObjectRule struct {
	Meta  Metadata
	Kinds []string
	Check func(ctx *Context, obj *resource.Object)
}

func (r ObjectRule) Metadata() Metadata { return r.Meta }

func (r ObjectRule) Evaluate(ctx *Context) {
	for _, o := range ctx.Inventory.OfKind(r.Kinds...) {
		r.Check(ctx, o)
	}
}

// InventoryRule is a convenience Rule that reasons over the whole inventory.
type InventoryRule struct {
	Meta  Metadata
	Check func(ctx *Context)
}

func (r InventoryRule) Metadata() Metadata    { return r.Meta }
func (r InventoryRule) Evaluate(ctx *Context) { r.Check(ctx) }
