package baselines_test

import (
	"regexp"
	"testing"

	"github.com/ManintheiCloud/Hardex/baselines"
	"github.com/ManintheiCloud/Hardex/kubernetes"
)

// Profiles must reference only real rules, be strictly nested
// (minimal ⊂ baseline ⊂ restricted), and restricted must contain every rule.
func TestProfilesAreConsistent(t *testing.T) {
	reg, err := kubernetes.Registry()
	if err != nil {
		t.Fatal(err)
	}
	sets := map[string]map[string]bool{}
	for _, name := range []string{"minimal", "baseline", "restricted"} {
		p, err := baselines.Profile(name)
		if err != nil {
			t.Fatal(err)
		}
		sets[name] = map[string]bool{}
		for _, id := range p.Rules {
			if _, ok := reg.Get(id); !ok {
				t.Errorf("profile %s references unknown rule %s", name, id)
			}
			sets[name][id] = true
		}
	}
	for id := range sets["minimal"] {
		if !sets["baseline"][id] {
			t.Errorf("%s is in minimal but not baseline", id)
		}
	}
	for id := range sets["baseline"] {
		if !sets["restricted"][id] {
			t.Errorf("%s is in baseline but not restricted", id)
		}
	}
	for _, r := range reg.All() {
		if !sets["restricted"][r.Metadata().ID] {
			t.Errorf("rule %s is not in the restricted profile", r.Metadata().ID)
		}
	}
}

func TestEveryRuleCitesGuidance(t *testing.T) {
	reg, _ := kubernetes.Registry()
	for _, r := range reg.All() {
		if len(r.Metadata().References) == 0 {
			t.Errorf("rule %s has no references", r.Metadata().ID)
		}
	}
}

// Built-in rule IDs follow HX-AREA-NNN; the looser pattern accepted by the
// registry exists only for declarative modules.
func TestBuiltinRuleIDs(t *testing.T) {
	reg, _ := kubernetes.Registry()
	re := regexp.MustCompile(`^HX-[A-Z]+-\d{3}$`)
	for _, r := range reg.All() {
		if !re.MatchString(r.Metadata().ID) {
			t.Errorf("built-in rule id %s does not match HX-AREA-NNN", r.Metadata().ID)
		}
	}
}

// Every built-in rule carries item-level guidance, and every CIS item it
// cites exists in the named benchmark version.
func TestItemLevelMappings(t *testing.T) {
	reg, _ := kubernetes.Registry()
	for _, r := range reg.All() {
		id := r.Metadata().ID
		m, ok := baselines.Mappings[id]
		if !ok || len(m.NSA) == 0 {
			t.Errorf("rule %s has no item-level NSA/CISA mapping", id)
		}
		for _, item := range m.CIS {
			if _, ok := baselines.CISItem(item); !ok {
				t.Errorf("rule %s cites unknown %s item %s", id, baselines.CISVersion, item)
			}
		}
	}
	for _, id := range baselines.MappedRuleIDs() {
		if _, ok := reg.Get(id); !ok {
			t.Errorf("mapping for unknown rule %s", id)
		}
	}
}
