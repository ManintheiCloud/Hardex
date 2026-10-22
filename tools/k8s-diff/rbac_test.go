package k8sdiff

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/ManintheiCloud/Hardex/kubernetes/rbac"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/component-helpers/auth/rbac/validation"
)

// RBAC: Hardex's rule matching and its "grants no more than the default"
// check, against validation.Covers, the comparison the API server uses to
// prevent privilege escalation (a request is allowed by a rule exactly when
// the rule covers it).

var (
	rbacGroups    = []string{"", "apps", "batch", "rbac.authorization.k8s.io", "authentication.k8s.io", "*", "Apps", "example.com"}
	rbacResources = []string{"pods", "pods/exec", "pods/attach", "pods/log", "secrets", "serviceaccounts", "serviceaccounts/token",
		"nodes", "nodes/proxy", "deployments", "deployments/scale", "roles", "clusterroles", "users", "*", "*/exec", "*/scale",
		"pods/*", "Pods", "secrets/", "pods/exec/x"}
	rbacVerbs = []string{"get", "list", "watch", "create", "update", "patch", "delete", "impersonate", "escalate", "bind", "*", "GET", "proxy"}
	rbacNames = []string{"a", "b", "*", ""}
)

func seedFromEnv(t *testing.T, name string) *rand.Rand {
	seed := time.Now().UnixNano()
	if s := os.Getenv(name); s != "" {
		seed, _ = strconv.ParseInt(s, 10, 64)
	}
	t.Logf("seed %d (rerun with %s=%d)", seed, name, seed)
	return rand.New(rand.NewSource(seed))
}

func some(r *rand.Rand, vocab []string, max int) []string {
	n := r.Intn(max + 1)
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, vocab[r.Intn(len(vocab))])
	}
	return out
}

func randomRule(r *rand.Rand) rbacv1.PolicyRule {
	rule := rbacv1.PolicyRule{APIGroups: some(r, rbacGroups, 2), Resources: some(r, rbacResources, 3), Verbs: some(r, rbacVerbs, 3)}
	if r.Intn(4) == 0 {
		rule.ResourceNames = some(r, rbacNames, 2)
	}
	return rule
}

// asMap gives a rule the shape Hardex reads from manifests.
func asMap(t *testing.T, v any) map[string]any {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestRuleAllowsMatchesCovers(t *testing.T) {
	r := seedFromEnv(t, "RBAC_DIFF_SEED")
	disagreements := map[string]string{}
	count := map[string]int{}
	for i := 0; i < 2000; i++ {
		rule := randomRule(r)
		m := asMap(t, rule)
		for _, g := range rbacGroups {
			if g == "*" {
				continue // a request names a concrete group
			}
			for _, res := range rbacResources {
				if res == "*" || res[0] == '*' {
					continue
				}
				for _, v := range rbacVerbs {
					if v == "*" {
						continue
					}
					want, _ := validation.Covers([]rbacv1.PolicyRule{rule}, []rbacv1.PolicyRule{{APIGroups: []string{g}, Resources: []string{res}, Verbs: []string{v}}})
					got := rbac.RuleAllows(m, g, res, v)
					if got == want {
						continue
					}
					key := fmt.Sprintf("Hardex=%v Kubernetes=%v for %q %q %q", got, want, g, res, v)
					count[key]++
					if _, ok := disagreements[key]; !ok {
						b, _ := json.Marshal(rule)
						disagreements[key] = string(b)
					}
				}
			}
		}
	}
	for k, rule := range disagreements {
		t.Errorf("RuleAllows: %s (%d times), e.g. rule %s", k, count[k], rule)
	}
}

// GrantsNoMoreThanDefault decides that an object is a default and is not
// reported. It may fail closed, but must never accept rules that grant more
// than the default: that would hide an added permission.
func TestDefaultsCheckIsSound(t *testing.T) {
	r := seedFromEnv(t, "RBAC_DIFF_SEED")
	keys := rbac.DefaultRoleKeys()
	accepted, unsound := 0, 0
	for i := 0; i < 20000; i++ {
		key := keys[r.Intn(len(keys))]
		var def []rbacv1.PolicyRule
		for _, m := range rbac.DefaultRules(key) {
			b, _ := json.Marshal(m)
			var pr rbacv1.PolicyRule
			if err := json.Unmarshal(b, &pr); err != nil {
				t.Fatal(err)
			}
			def = append(def, pr)
		}
		if len(def) == 0 {
			continue // aggregated: judged by isSystem on the aggregation rule
		}
		// A copy of some of the default's rules, some changed, some added.
		var rules []rbacv1.PolicyRule
		for _, d := range def {
			if r.Intn(3) == 0 {
				continue
			}
			d = *d.DeepCopy()
			switch r.Intn(6) {
			case 0:
				d.Verbs = append(d.Verbs, rbacVerbs[r.Intn(len(rbacVerbs))])
			case 1:
				d.Resources = append(d.Resources, rbacResources[r.Intn(len(rbacResources))])
			case 2:
				d.ResourceNames = nil
			case 3:
				d.APIGroups = append(d.APIGroups, rbacGroups[r.Intn(len(rbacGroups))])
			}
			rules = append(rules, d)
		}
		if r.Intn(4) == 0 {
			rules = append(rules, randomRule(r))
		}
		var ms []map[string]any
		for _, x := range rules {
			ms = append(ms, asMap(t, x))
		}
		if !rbac.GrantsNoMoreThanDefault(key, ms) {
			continue
		}
		accepted++
		if ok, missing := validation.Covers(def, rules); !ok {
			unsound++
			if unsound <= 10 {
				b, _ := json.Marshal(missing)
				t.Errorf("%s: Hardex treats these rules as the default, but they grant more: %s", key, b)
			}
		}
	}
	t.Logf("%d rule sets accepted as defaults, %d of them unsound", accepted, unsound)
	if accepted == 0 {
		t.Error("no rule set was accepted as a default; the test checks nothing")
	}
}
