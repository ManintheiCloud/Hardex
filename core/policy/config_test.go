package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/ManintheiCloud/Hardex/core/finding"
)

func TestConfigRejectsUnsafeOrAmbiguousInput(t *testing.T) {
	header := "apiVersion: hardex.dev/v1alpha1\nkind: HardexConfig\n"
	cases := map[string]string{
		"unknown field (typo)":          header + "waviers: []\n",
		"wrong kind":                    "apiVersion: hardex.dev/v1alpha1\nkind: Other\n",
		"disable without justification": header + "disabledRules:\n  - id: HX-WL-001\n",
		"waiver without expiry":         header + "waivers:\n  - {rule: HX-WL-001, name: x, justification: y}\n",
		"waiver bad date":               header + "waivers:\n  - {rule: HX-WL-001, name: x, justification: y, expires: soon}\n",
		"waiver matching everything":    header + "waivers:\n  - {rule: HX-WL-001, justification: y, expires: \"2030-01-01\"}\n",
		"invalid severity override":     header + "severityOverrides: {HX-WL-001: urgent}\n",
		"duplicate key":                 header + "profile: baseline\nprofile: minimal\n",
	}
	for name, y := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseConfig([]byte(y)); err == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
}

func TestWaiverValidThroughExpiryDay(t *testing.T) {
	cfg, err := ParseConfig([]byte(`apiVersion: hardex.dev/v1alpha1
kind: HardexConfig
waivers:
  - {rule: HX-WL-001, name: web, justification: test, expires: "2026-10-01"}
`))
	if err != nil {
		t.Fatal(err)
	}
	f := finding.Finding{RuleID: "HX-WL-001", Resource: finding.Resource{Kind: "Pod", Name: "web"}}
	_, waived, _ := Apply(cfg, []finding.Finding{f}, time.Date(2026, 10, 1, 23, 0, 0, 0, time.UTC))
	if len(waived) != 1 {
		t.Error("waiver should apply on its expiry day")
	}
	active, _, warnings := Apply(cfg, []finding.Finding{f}, time.Date(2026, 10, 2, 0, 0, 1, 0, time.UTC))
	if len(active) != 1 || len(warnings) == 0 || !strings.Contains(warnings[0], "expired") {
		t.Errorf("expired waiver: active=%d warnings=%v", len(active), warnings)
	}
}

func TestSeverityOverride(t *testing.T) {
	cfg, err := ParseConfig([]byte("apiVersion: hardex.dev/v1alpha1\nkind: HardexConfig\nseverityOverrides: {hx-wl-009: medium}\n"))
	if err != nil {
		t.Fatal(err)
	}
	active, _, _ := Apply(cfg, []finding.Finding{{RuleID: "HX-WL-009", Severity: finding.Low}}, time.Now())
	if active[0].Severity != finding.Medium {
		t.Errorf("severity = %s, want medium", active[0].Severity)
	}
}
