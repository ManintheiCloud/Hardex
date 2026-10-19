package policy

import (
	"testing"
	"time"

	"github.com/ManintheiCloud/Hardex/core/finding"
)

// FuzzParseConfig: arbitrary configuration must be rejected or accepted
// without panicking, and an accepted configuration must be usable.
func FuzzParseConfig(f *testing.F) {
	f.Add([]byte("apiVersion: hardex.dev/v1alpha1\nkind: HardexConfig\nwaivers:\n  - {rule: HX-WL-001, name: a, justification: j, expires: \"2030-01-01\"}\n"))
	f.Add([]byte("apiVersion: hardex.dev/v1alpha1\nkind: HardexConfig\nseverityOverrides: {HX-WL-001: low}\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		cfg, err := ParseConfig(data)
		if err != nil {
			return
		}
		Apply(cfg, []finding.Finding{{RuleID: "HX-WL-001", Resource: finding.Resource{Kind: "Pod", Name: "a"}}}, time.Now())
	})
}
