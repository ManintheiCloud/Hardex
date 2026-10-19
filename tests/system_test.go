package tests

import (
	"testing"

	"github.com/ManintheiCloud/Hardex"
	"github.com/ManintheiCloud/Hardex/core/policy"
)

// Platform objects (fixtures/hardened/platform.yaml) are quiet by default,
// found by a real kind cluster's end-to-end run, and still assessed when
// asked for with --include-system.
func TestPlatformObjectsOnlyWithIncludeSystem(t *testing.T) {
	quiet := scan(t, "restricted", "fixtures/hardened/platform.yaml")
	if len(quiet.Findings) != 0 {
		for _, f := range quiet.Findings {
			t.Errorf("reported by default: %s %s", f.RuleID, f.Resource)
		}
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
