package tests

import (
	"strings"
	"testing"

	"github.com/ManintheiCloud/Hardex"
	"github.com/ManintheiCloud/Hardex/core/policy"
	"github.com/ManintheiCloud/Hardex/core/verification"
)

func mustConfig(t *testing.T, y string) *policy.Config {
	t.Helper()
	cfg, err := policy.ParseConfig([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// Remediation verification: fixing a workload resolves its findings and
// nothing else changes.
func TestVerifyRemediation(t *testing.T) {
	before := scan(t, "restricted", "fixtures/insecure")
	after := scan(t, "restricted", "fixtures/insecure/rbac.yaml", "fixtures/insecure/control-plane.yaml",
		"fixtures/insecure/kubelet.yaml", "fixtures/insecure/services.yaml", "fixtures/insecure/secrets.yaml",
		"fixtures/hardened/workloads.yaml")
	c := verification.Compare(before, after)
	if len(c.Resolved) == 0 {
		t.Fatal("replacing insecure workloads resolved nothing")
	}
	for _, f := range c.Resolved {
		if f.Resource.Kind != "Deployment" && f.Resource.Kind != "Pod" && f.Resource.Kind != "Namespace" {
			t.Errorf("unexpectedly resolved: %s %s", f.RuleID, f.Resource)
		}
	}
	if len(c.Introduced) != 0 {
		t.Errorf("hardened workloads introduced findings: %+v", c.Introduced)
	}
	if c.Regressed(0) {
		t.Error("reported a regression")
	}
}

func TestRuleNotRunIsUnverifiedNotResolved(t *testing.T) {
	before := scan(t, "restricted", "fixtures/insecure")
	after := scan(t, "minimal", "fixtures/insecure")
	c := verification.Compare(before, after)
	if len(c.Resolved) != 0 {
		t.Errorf("findings from rules that did not run were counted as resolved: %d", len(c.Resolved))
	}
	if len(c.Unverified) == 0 || len(c.Caveats) == 0 {
		t.Error("expected unverified findings and caveats")
	}
}

func TestWaiversAndExpiry(t *testing.T) {
	cfg := mustConfig(t, `
apiVersion: hardex.dev/v1alpha1
kind: HardexConfig
profile: restricted
waivers:
  - rule: HX-SEC-001
    kind: Secret
    namespace: shop
    name: db-credentials
    justification: Test fixture; values are not real.
    owner: platform-security
    expires: "2026-12-31"
  - rule: HX-NET-004
    namespace: shop
    justification: Expired acceptance.
    expires: "2026-01-31"
`)
	r, _, err := hardex.Scan(hardex.ScanOptions{Paths: []string{"fixtures/insecure"}, Config: cfg, Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	waived := map[string]bool{}
	for _, f := range r.Waived {
		waived[f.RuleID] = true
	}
	if !waived["HX-SEC-001"] {
		t.Error("valid waiver not applied")
	}
	if waived["HX-NET-004"] {
		t.Error("expired waiver applied")
	}
	foundWarning := false
	for _, w := range r.Warnings {
		if contains(w, "expired") {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Error("expired waiver produced no warning")
	}
}

func TestDisabledRuleIsRecorded(t *testing.T) {
	cfg := mustConfig(t, `
apiVersion: hardex.dev/v1alpha1
kind: HardexConfig
disabledRules:
  - id: HX-SEC-001
    justification: Scanning a live-cluster export.
`)
	r, _, err := hardex.Scan(hardex.ScanOptions{Paths: []string{"fixtures/insecure"}, Config: cfg, Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range r.Findings {
		if f.RuleID == "HX-SEC-001" {
			t.Fatal("disabled rule still ran")
		}
	}
	if len(r.Warnings) == 0 || !contains(r.Warnings[0], "HX-SEC-001 disabled") {
		t.Errorf("disabling was not recorded: %v", r.Warnings)
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
