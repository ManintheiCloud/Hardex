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

// The NIST SP 800-190 section 4 headings, exactly as in the document's table
// of contents. Every cited section must be one of them.
var nistTOC = map[string]bool{
	"4.1.1 Image vulnerabilities": true, "4.1.2 Image configuration defects": true,
	"4.1.3 Embedded malware": true, "4.1.4 Embedded clear text secrets": true,
	"4.1.5 Use of untrusted images": true, "4.2.1 Insecure connections to registries": true,
	"4.2.2 Stale images in registries": true, "4.2.3 Insufficient authentication and authorization restrictions": true,
	"4.3.1 Unbounded administrative access": true, "4.3.2 Unauthorized access": true,
	"4.3.3 Poorly separated inter-container network traffic": true, "4.3.4 Mixing of workload sensitivity levels": true,
	"4.3.5 Orchestrator node trust": true, "4.4.1 Vulnerabilities within the runtime software": true,
	"4.4.2 Unbounded network access from containers": true, "4.4.3 Insecure container runtime configurations": true,
	"4.4.4 App vulnerabilities": true, "4.4.5 Rogue containers": true,
	"4.5.1 Large attack surface": true, "4.5.2 Shared kernel": true,
	"4.5.3 Host OS component vulnerabilities": true, "4.5.4 Improper user access rights": true,
	"4.5.5 Host file system tampering": true, "4.6 Hardware Countermeasures": true,
}

func TestNISTMappings(t *testing.T) {
	reg, _ := kubernetes.Registry()
	for _, s := range baselines.NISTSections {
		if !nistTOC[s] {
			t.Errorf("%q is not a NIST SP 800-190 section 4 heading", s)
		}
	}
	for id, sections := range baselines.NISTMappings {
		if _, ok := reg.Get(id); !ok {
			t.Errorf("NIST mapping for unknown rule %s", id)
		}
		for _, s := range sections {
			if !nistTOC[s] {
				t.Errorf("rule %s cites %q, not a NIST SP 800-190 section 4 heading", id, s)
			}
		}
		r, _ := reg.Get(id)
		n := 0
		for _, ref := range r.Metadata().References {
			if ref.Framework == "NIST" {
				n++
			}
		}
		if n != len(sections) {
			t.Errorf("rule %s: %d NIST references, want %d", id, n, len(sections))
		}
	}
}
