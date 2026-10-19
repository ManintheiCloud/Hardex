// Package hardex is the library entry point: it loads input, selects rules
// from a profile and configuration, evaluates them, applies policy and returns
// a report. The hardex CLI is a thin wrapper around Scan.
package hardex

import (
	"fmt"
	"io"
	"time"

	"github.com/hardex-project/hardex/baselines"
	"github.com/hardex-project/hardex/core/assessment"
	"github.com/hardex-project/hardex/core/finding"
	"github.com/hardex-project/hardex/core/policy"
	"github.com/hardex-project/hardex/core/resource"
	"github.com/hardex-project/hardex/kubernetes"
)

// Version is set at build time with -ldflags "-X github.com/hardex-project/hardex.Version=...".
var Version = "0.1.0-dev"

// ScanOptions configures a scan.
type ScanOptions struct {
	// Paths are files, directories, or "-" for Stdin.
	Paths []string
	Stdin io.Reader
	// Config is the policy; nil means policy.DefaultConfig().
	Config *policy.Config
	// Profile overrides Config.Profile when non-empty.
	Profile string
	// Now is the reference time for waiver expiry; zero means time.Now().
	Now time.Time
}

// Scan runs a complete assessment.
func Scan(opts ScanOptions) (*finding.Report, []assessment.Metadata, error) {
	cfg := opts.Config
	if cfg == nil {
		cfg = policy.DefaultConfig()
		if err := cfg.Validate(); err != nil {
			return nil, nil, err
		}
	}
	profileName := cfg.Profile
	if opts.Profile != "" {
		profileName = opts.Profile
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	reg, err := kubernetes.Registry()
	if err != nil {
		return nil, nil, fmt.Errorf("internal error: %w", err)
	}
	profile, err := baselines.Profile(profileName)
	if err != nil {
		return nil, nil, err
	}
	rules, warnings, err := policy.SelectRules(reg, profile, cfg)
	if err != nil {
		return nil, nil, err
	}
	inv, err := resource.Load(opts.Paths, opts.Stdin)
	if err != nil {
		return nil, nil, err
	}

	res := assessment.Evaluate(inv, rules, assessment.Options{IncludeSystem: cfg.IncludeSystem})
	active, waived, policyWarnings := policy.Apply(cfg, res.Findings, now)

	report := &finding.Report{
		Schema:           finding.SchemaVersion,
		Tool:             finding.Tool{Name: "hardex", Version: Version},
		GeneratedAt:      now.UTC().Truncate(time.Second),
		Profile:          profile.Name,
		Inputs:           inv.Sources,
		ObjectsEvaluated: len(inv.Objects),
		RulesEvaluated:   res.Ran,
		Findings:         nonNil(active),
		Waived:           waived,
		Warnings:         append(append(warnings, inv.Skipped...), policyWarnings...),
		Errors:           res.Errors,
	}
	if len(inv.Objects) == 0 {
		report.Warnings = append(report.Warnings, "no Kubernetes objects were found in the input; nothing was assessed")
	}
	report.Summarize()

	metas := make([]assessment.Metadata, len(rules))
	for i, r := range rules {
		metas[i] = r.Metadata()
	}
	return report, metas, nil
}

func nonNil(fs []finding.Finding) []finding.Finding {
	if fs == nil {
		return []finding.Finding{}
	}
	return fs
}
