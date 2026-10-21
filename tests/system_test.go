package tests

import (
	"github.com/ManintheiCloud/Hardex/core/finding"
	"testing"

	"github.com/ManintheiCloud/Hardex"
	"github.com/ManintheiCloud/Hardex/core/policy"
)

// Platform objects (fixtures/hardened/platform.yaml) are quiet by default,
// found by a real kind cluster's end-to-end run, and still assessed when
// asked for with --include-system.
func TestPlatformObjectsOnlyWithIncludeSystem(t *testing.T) {
	quiet := scan(t, "restricted", "fixtures/hardened/platform.yaml")
	inventoried := 0
	for _, f := range quiet.Findings {
		if f.RuleID == systemInventory && f.Severity == finding.Info {
			inventoried++
			continue
		}
		t.Errorf("reported by default: %s %s", f.RuleID, f.Resource)
	}
	if inventoried == 0 {
		t.Error("host-access platform workloads are not listed in the kube-system inventory (HX-WL-022)")
	}
	cfg := policy.DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.IncludeSystem = true
	full, _, err := hardex.Scan(hardex.ScanOptions{Paths: []string{"fixtures/hardened/platform.yaml"}, Profile: "restricted", Config: cfg, Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"HX-WL-001": false, "HX-RBAC-007": false, "HX-RBAC-002": false}
	for _, f := range full.Findings {
		if f.RuleID == systemInventory {
			t.Errorf("inventory reported with --include-system, where the full rules apply: %s", f.Resource)
		}
		if _, ok := want[f.RuleID]; ok {
			want[f.RuleID] = true
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("%s not reported with --include-system", id)
		}
	}
}
