// Package hardex is the library entry point: it loads input, selects rules
// from a profile and configuration, evaluates them, applies policy and returns
// a report. The hardex CLI is a thin wrapper around Scan.
package hardex

import (
	"fmt"
	"io"
	"time"

	"github.com/ManintheiCloud/Hardex/baselines"
	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/cloudiam"
	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/modules"
	"github.com/ManintheiCloud/Hardex/core/policy"
	"github.com/ManintheiCloud/Hardex/core/resource"
	"github.com/ManintheiCloud/Hardex/kubernetes"
)

// Version is set at build time with -ldflags "-X github.com/ManintheiCloud/Hardex.Version=...".
var Version = "0.8.3-dev"

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
	// Inventory, when set, is assessed instead of loading Paths (e.g. a
	// live-cluster collection).
	Inventory *resource.Inventory
	// CollectionErrors are reported as assessment errors: an incomplete
	// collection must not produce a clean-looking report.
	CollectionErrors []string
	// CollectionWarnings are reported as warnings.
	CollectionWarnings []string
	// Modules are declarative rule module files. Their rules run in
	// addition to the profile unless disabled in configuration.
	Modules []string
	// CloudIAM are cloud IAM export files (see core/cloudiam); their
	// identities let attack-path analysis rate workload cloud identities.
	CloudIAM []string
	// Stats, when non-nil, receives timings of the scan.
	Stats *Stats
}

// Stats are the timings of a scan, for diagnosing performance on large
// clusters (hardex scan --stats).
type Stats struct {
	Load     time.Duration // loading files; zero for a pre-collected inventory
	Evaluate time.Duration
	Objects  int
	Rules    []assessment.Timing
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

	var moduleRules []assessment.Rule
	for _, path := range opts.Modules {
		rules, err := modules.Load(path)
		if err != nil {
			return nil, nil, err
		}
		moduleRules = append(moduleRules, rules...)
	}
	reg, err := kubernetes.Registry(moduleRules...)
	if err != nil {
		return nil, nil, fmt.Errorf("rules: %w", err)
	}
	profile, err := baselines.Profile(profileName)
	if err != nil {
		return nil, nil, err
	}
	for _, r := range moduleRules {
		profile.Rules = append(profile.Rules, r.Metadata().ID)
	}
	rules, warnings, err := policy.SelectRules(reg, profile, cfg)
	if err != nil {
		return nil, nil, err
	}
	inv := opts.Inventory
	loadStart := time.Now()
	if inv == nil {
		if inv, err = resource.Load(opts.Paths, opts.Stdin); err != nil {
			return nil, nil, err
		}
		if opts.Stats != nil {
			opts.Stats.Load = time.Since(loadStart)
		}
	}

	if len(opts.CloudIAM) > 0 {
		ids, err := cloudiam.Load(opts.CloudIAM)
		if err != nil {
			return nil, nil, fmt.Errorf("cloud IAM: %w", err)
		}
		for _, o := range ids {
			inv.Add(o)
		}
		inv.Sources = append(inv.Sources, opts.CloudIAM...)
	}

	evalStart := time.Now()
	res := assessment.Evaluate(inv, rules, assessment.Options{IncludeSystem: cfg.IncludeSystem})
	if opts.Stats != nil {
		opts.Stats.Evaluate, opts.Stats.Objects, opts.Stats.Rules = time.Since(evalStart), len(inv.Objects), res.Timings
	}
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
		Warnings:         append(append(append(warnings, inv.Skipped...), opts.CollectionWarnings...), policyWarnings...),
		Errors:           append(append([]string(nil), opts.CollectionErrors...), res.Errors...),
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
