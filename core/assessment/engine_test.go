package assessment

import (
	"strings"
	"testing"

	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

func meta(id string) Metadata {
	return Metadata{ID: id, Title: "t", Severity: finding.Low, Category: CategoryWorkloads,
		Description: "d", Rationale: "r", Remediation: "f"}
}

func TestRegistryRejectsIncompleteAndDuplicateRules(t *testing.T) {
	noop := func(*Context) {}
	if _, err := NewRegistry(InventoryRule{Meta: Metadata{ID: "HX-WL-001"}, Check: noop}); err == nil {
		t.Error("accepted rule without description/rationale/remediation")
	}
	if _, err := NewRegistry(InventoryRule{Meta: meta("bad-id"), Check: noop}); err == nil {
		t.Error("accepted malformed id")
	}
	if _, err := NewRegistry(InventoryRule{Meta: meta("HX-WL-001"), Check: noop}, InventoryRule{Meta: meta("HX-WL-001"), Check: noop}); err == nil {
		t.Error("accepted duplicate id")
	}
}

func TestPanickingRuleIsReportedNotSwallowed(t *testing.T) {
	inv := resource.NewInventory()
	boom := InventoryRule{Meta: meta("HX-WL-998"), Check: func(*Context) { panic("boom") }}
	ok := InventoryRule{Meta: meta("HX-WL-999"), Check: func(ctx *Context) {
		ctx.Report(Hit{Object: &resource.Object{Kind: "Pod", Name: "p"}, Message: "m"})
	}}
	res := Evaluate(inv, []Rule{boom, ok}, Options{})
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "HX-WL-998") {
		t.Fatalf("errors = %v", res.Errors)
	}
	if len(res.Findings) != 1 || len(res.Ran) != 1 {
		t.Errorf("other rules must still run: findings=%d ran=%v", len(res.Findings), res.Ran)
	}
}

func TestFingerprintIgnoresLocation(t *testing.T) {
	a := finding.Finding{RuleID: "HX-WL-001", Resource: finding.Resource{Kind: "Pod", Name: "p", Source: "a.yaml", Line: 1}}
	b := a
	b.Resource.Source, b.Resource.Line = "moved/b.yaml", 40
	a.ComputeFingerprint()
	b.ComputeFingerprint()
	if a.Fingerprint != b.Fingerprint {
		t.Error("moving a manifest changed the fingerprint")
	}
}
