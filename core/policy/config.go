// Package policy turns raw assessment results into a decision: which rules
// run (profiles, disabled rules), how severe their findings are (overrides),
// and which findings are accepted risks (waivers).
//
// Policy is deliberately strict. A malformed or ambiguous configuration is an
// error, never a silent fallback, because a typo that quietly disables a check
// weakens security without anyone noticing.
package policy

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ManintheiCloud/Hardex/internal/yamlsafe"

	"github.com/ManintheiCloud/Hardex/core/finding"
)

const (
	ConfigAPIVersion = "hardex.dev/v1alpha1"
	ConfigKind       = "HardexConfig"
)

// Config is the on-disk policy file (conventionally hardex.yaml).
type Config struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	// Profile selects the baseline: minimal, baseline or restricted.
	Profile string `yaml:"profile"`
	// IncludeSystem also evaluates Kubernetes-managed objects.
	IncludeSystem bool `yaml:"includeSystem"`
	// DisabledRules turns rules off. A justification is mandatory.
	DisabledRules []DisabledRule `yaml:"disabledRules"`
	// SeverityOverrides adjusts rule severity for this environment.
	SeverityOverrides map[string]string `yaml:"severityOverrides"`
	// Waivers accept specific findings as known risks until they expire.
	Waivers []Waiver `yaml:"waivers"`

	overrides map[string]finding.Severity
}

// DisabledRule turns one rule off for the whole assessment.
type DisabledRule struct {
	ID            string `yaml:"id"`
	Justification string `yaml:"justification"`
}

// Waiver accepts a specific finding as a known risk.
//
// Empty match fields match anything, but at least the rule and one of kind,
// namespace or name must be given: a waiver covering every occurrence of a
// rule is a disabled rule and must be declared as one.
type Waiver struct {
	Rule      string `yaml:"rule"`
	Kind      string `yaml:"kind"`
	Namespace string `yaml:"namespace"`
	Name      string `yaml:"name"`
	Container string `yaml:"container"`

	Justification string `yaml:"justification"`
	Owner         string `yaml:"owner"`
	// Expires is a date (YYYY-MM-DD). Waivers without an expiry are rejected:
	// accepted risk must be revisited.
	Expires string `yaml:"expires"`

	expires time.Time
}

// DefaultConfig is used when no configuration file is given.
func DefaultConfig() *Config {
	return &Config{APIVersion: ConfigAPIVersion, Kind: ConfigKind, Profile: "baseline"}
}

// LoadConfig reads and validates a configuration file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(data)
}

// ParseConfig decodes and validates configuration bytes. Unknown fields are
// rejected.
func ParseConfig(data []byte) (*Config, error) {
	cfg := &Config{}
	if err := yamlsafe.Strict(data, cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return cfg, nil
}

// Validate checks the configuration and prepares parsed fields.
func (c *Config) Validate() error {
	if c.APIVersion != ConfigAPIVersion || c.Kind != ConfigKind {
		return fmt.Errorf("expected apiVersion %q and kind %q", ConfigAPIVersion, ConfigKind)
	}
	if c.Profile == "" {
		c.Profile = "baseline"
	}
	for i, d := range c.DisabledRules {
		if d.ID == "" || strings.TrimSpace(d.Justification) == "" {
			return fmt.Errorf("disabledRules[%d]: id and justification are required", i)
		}
		c.DisabledRules[i].ID = strings.ToUpper(d.ID)
	}
	c.overrides = map[string]finding.Severity{}
	for id, s := range c.SeverityOverrides {
		sev, err := finding.ParseSeverity(s)
		if err != nil || sev > finding.Critical {
			return fmt.Errorf("severityOverrides[%s]: invalid severity %q", id, s)
		}
		c.overrides[strings.ToUpper(id)] = sev
	}
	for i := range c.Waivers {
		w := &c.Waivers[i]
		if w.Rule == "" {
			return fmt.Errorf("waivers[%d]: rule is required", i)
		}
		w.Rule = strings.ToUpper(w.Rule)
		if w.Kind == "" && w.Namespace == "" && w.Name == "" {
			return fmt.Errorf("waivers[%d]: must narrow by kind, namespace or name (use disabledRules to turn a rule off entirely)", i)
		}
		if strings.TrimSpace(w.Justification) == "" {
			return fmt.Errorf("waivers[%d]: justification is required", i)
		}
		t, err := time.Parse("2006-01-02", w.Expires)
		if err != nil {
			return fmt.Errorf("waivers[%d]: expires must be a date in YYYY-MM-DD form", i)
		}
		// A waiver is valid through the end of its expiry day (UTC).
		w.expires = t.Add(24 * time.Hour)
	}
	return nil
}

func (w Waiver) matches(f finding.Finding) bool {
	return w.Rule == f.RuleID &&
		(w.Kind == "" || w.Kind == f.Resource.Kind) &&
		(w.Namespace == "" || w.Namespace == f.Resource.Namespace) &&
		(w.Name == "" || w.Name == f.Resource.Name) &&
		(w.Container == "" || w.Container == f.Resource.Container)
}

func (w Waiver) describe() string {
	parts := []string{w.Rule}
	for _, kv := range [][2]string{{"kind", w.Kind}, {"namespace", w.Namespace}, {"name", w.Name}, {"container", w.Container}} {
		if kv[1] != "" {
			parts = append(parts, kv[0]+"="+kv[1])
		}
	}
	return strings.Join(parts, " ")
}
