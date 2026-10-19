package baselines

import (
	"bytes"
	"embed"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/ManintheiCloud/Hardex/core/policy"
)

//go:embed profiles/*.yaml
var profileFS embed.FS

// Profile returns a built-in profile by name, or loads a custom profile when
// name is a path to a YAML file.
func Profile(name string) (policy.Profile, error) {
	if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
		data, err := os.ReadFile(name)
		if err != nil {
			return policy.Profile{}, err
		}
		return parseProfile(data, name)
	}
	data, err := profileFS.ReadFile("profiles/" + name + ".yaml")
	if err != nil {
		return policy.Profile{}, fmt.Errorf("unknown profile %q (built-in: %s)", name, strings.Join(ProfileNames(), ", "))
	}
	return parseProfile(data, name)
}

// ProfileNames lists the built-in profiles.
func ProfileNames() []string {
	entries, _ := profileFS.ReadDir("profiles")
	var names []string
	for _, e := range entries {
		names = append(names, strings.TrimSuffix(e.Name(), ".yaml"))
	}
	sort.Strings(names)
	return names
}

func parseProfile(data []byte, source string) (policy.Profile, error) {
	var p policy.Profile
	if err := yaml.NewDecoder(bytes.NewReader(data), yaml.DisallowUnknownField()).Decode(&p); err != nil {
		return p, fmt.Errorf("profile %s: %s", source, yaml.FormatError(err, false, false))
	}
	if p.Name == "" || len(p.Rules) == 0 {
		return p, fmt.Errorf("profile %s: name and at least one rule are required", source)
	}
	seen := map[string]bool{}
	for i, id := range p.Rules {
		id = strings.ToUpper(strings.TrimSpace(id))
		if seen[id] {
			return p, fmt.Errorf("profile %s: rule %s listed twice", source, id)
		}
		seen[id] = true
		p.Rules[i] = id
	}
	return p, nil
}
