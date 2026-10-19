package policy

import (
	"fmt"
	"time"

	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/finding"
)

// Profile is a named, reviewable list of rules. Profiles are data, not code,
// so that what a profile enforces can be audited without reading Go.
type Profile struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Rules       []string `yaml:"rules"`
}

// SelectRules returns the rules that a profile and config enable, plus a
// warning for every rule the config disabled.
func SelectRules(reg *assessment.Registry, profile Profile, cfg *Config) ([]assessment.Rule, []string, error) {
	disabled := map[string]string{}
	for _, d := range cfg.DisabledRules {
		if _, ok := reg.Get(d.ID); !ok {
			return nil, nil, fmt.Errorf("config disables unknown rule %s", d.ID)
		}
		disabled[d.ID] = d.Justification
	}
	for id := range cfg.overrides {
		if _, ok := reg.Get(id); !ok {
			return nil, nil, fmt.Errorf("config overrides severity of unknown rule %s", id)
		}
	}
	for _, w := range cfg.Waivers {
		if _, ok := reg.Get(w.Rule); !ok {
			return nil, nil, fmt.Errorf("waiver references unknown rule %s", w.Rule)
		}
	}

	var rules []assessment.Rule
	var warnings []string
	for _, id := range profile.Rules {
		rule, ok := reg.Get(id)
		if !ok {
			return nil, nil, fmt.Errorf("profile %s references unknown rule %s", profile.Name, id)
		}
		if why, off := disabled[id]; off {
			warnings = append(warnings, fmt.Sprintf("rule %s disabled by configuration: %s", id, why))
			continue
		}
		rules = append(rules, rule)
	}
	return rules, warnings, nil
}

// Apply adjusts severities and separates waived findings from active ones.
// Expired waivers are not applied and produce a warning, so accepted risk
// resurfaces instead of persisting indefinitely.
func Apply(cfg *Config, findings []finding.Finding, now time.Time) (active, waived []finding.Finding, warnings []string) {
	expiredWarned := map[int]bool{}
	for _, f := range findings {
		if sev, ok := cfg.overrides[f.RuleID]; ok {
			f.Severity = sev
		}
		applied := false
		for i, w := range cfg.Waivers {
			if !w.matches(f) {
				continue
			}
			if !now.Before(w.expires) {
				if !expiredWarned[i] {
					warnings = append(warnings, fmt.Sprintf("waiver for %s expired on %s and was not applied", w.describe(), w.Expires))
					expiredWarned[i] = true
				}
				continue
			}
			f.Waiver = &finding.WaiverRef{Justification: w.Justification, Owner: w.Owner, Expires: w.Expires}
			applied = true
			break
		}
		if applied {
			waived = append(waived, f)
		} else {
			active = append(active, f)
		}
	}
	for i, w := range cfg.Waivers {
		if !expiredWarned[i] && !used(w, findings) {
			warnings = append(warnings, fmt.Sprintf("waiver for %s matched no findings; remove it if the risk is resolved", w.describe()))
		}
	}
	finding.Sort(active)
	finding.Sort(waived)
	return active, waived, warnings
}

func used(w Waiver, fs []finding.Finding) bool {
	for _, f := range fs {
		if w.matches(f) {
			return true
		}
	}
	return false
}
