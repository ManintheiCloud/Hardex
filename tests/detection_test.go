// Package tests holds end-to-end validation of the built-in rules against
// reproducible fixtures, following the README's validation priorities:
//
//   - detection accuracy:      every rule fires on the insecure fixtures
//   - false-positive control:  no rule fires on the hardened fixtures
//   - regression resistance:   every rule must have an expectation here
package tests

import (
	"strings"
	"testing"
	"time"

	"github.com/ManintheiCloud/Hardex"
	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/kubernetes"
)

var fixedNow = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

type expectation struct {
	rule     string
	resource string // finding.Resource.String() prefix
	severity finding.Severity
}

// Every built-in rule must appear here at least once (enforced below).
var insecureExpectations = []expectation{
	{"HX-WL-001", "Deployment shop/insecure-web [web]", finding.Critical},
	{"HX-WL-002", "Deployment shop/insecure-web", finding.High},
	{"HX-WL-002", "Pod shop/windows-host", finding.High},
	{"HX-WL-003", "Deployment shop/insecure-web", finding.Critical},
	{"HX-WL-004", "Deployment shop/insecure-web [web]", finding.Medium},
	{"HX-WL-005", "Deployment shop/insecure-web [web]", finding.High},
	{"HX-WL-006", "Deployment shop/insecure-web [web]", finding.Critical},
	{"HX-WL-007", "Deployment shop/insecure-web [web]", finding.Low},
	{"HX-WL-008", "Deployment shop/insecure-web [web]", finding.High},
	{"HX-WL-009", "Deployment shop/insecure-web [web]", finding.Low},
	{"HX-WL-010", "Deployment shop/insecure-web [web]", finding.Low},
	{"HX-WL-011", "Deployment shop/insecure-web [web]", finding.Medium},
	{"HX-WL-012", "Pod shop/windows-host [agent]", finding.Info},
	{"HX-WL-013", "Deployment shop/insecure-web", finding.Low},
	{"HX-WL-014", "Deployment shop/insecure-web [web]", finding.Medium},
	{"HX-WL-015", "Deployment shop/insecure-web [web]", finding.High},
	{"HX-WL-016", "Deployment shop/insecure-web [web]", finding.High},
	{"HX-WL-017", "Deployment shop/insecure-web [web]", finding.High},
	{"HX-WL-018", "Deployment shop/insecure-web", finding.Medium},
	{"HX-WL-019", "Deployment shop/insecure-web", finding.Low},
	{"HX-WL-020", "Pod shop/windows-host [agent]", finding.Critical},
	{"HX-SEC-001", "Secret shop/db-credentials", finding.Medium},
	{"HX-SEC-002", "Deployment shop/insecure-web [web]", finding.Medium},
	{"HX-RBAC-001", "ClusterRole god-mode", finding.High},
	{"HX-RBAC-002", "ClusterRoleBinding ci-admin", finding.Critical},
	{"HX-RBAC-003", "ClusterRole secrets-reader", finding.High},
	{"HX-RBAC-004", "ClusterRole escalator", finding.Critical},
	{"HX-RBAC-005", "Role shop/debugger", finding.Medium},
	{"HX-RBAC-006", "ClusterRole deployer", finding.Medium},
	{"HX-RBAC-007", "ClusterRoleBinding anonymous-view", finding.Critical},
	{"HX-RBAC-008", "Deployment ci/runner", finding.Critical},
	{"HX-PATH-001", "Deployment shop/insecure-web", finding.Critical},
	{"HX-NET-001", "Namespace shop", finding.Medium},
	{"HX-NET-002", "Namespace shop", finding.Low},
	{"HX-NET-003", "Service shop/public-lb", finding.Medium},
	{"HX-NET-003", "Service shop/node-port", finding.Low},
	{"HX-NET-004", "Service shop/hijack", finding.Medium},
	{"HX-NET-005", "Ingress shop/plain-http", finding.Medium},
	{"HX-NET-005", "Ingress shop/partial-tls", finding.Medium},
	{"HX-CP-001", "Pod kube-system/kube-apiserver-cp1", finding.Medium},
	{"HX-CP-002", "Pod kube-system/kube-apiserver-cp1", finding.Critical},
	{"HX-CP-003", "Pod kube-system/kube-apiserver-cp1", finding.Medium},
	{"HX-CP-004", "Pod kube-system/kube-scheduler-cp1", finding.Low},
	{"HX-CP-005", "Pod kube-system/kube-apiserver-cp1", finding.High},
	{"HX-CP-006", "Pod kube-system/etcd-cp1", finding.High},
	{"HX-CP-006", "Pod kube-system/kube-apiserver-cp1", finding.High},
	{"HX-CP-007", "Pod kube-system/kube-apiserver-cp1", finding.Medium},
	{"HX-CP-008", "Pod kube-system/kube-apiserver-cp1", finding.Medium},
	{"HX-CP-009", "ValidatingWebhookConfiguration policy-engine", finding.Medium},
	{"HX-NODE-001", "KubeletConfiguration kubelet.yaml", finding.High},
	{"HX-NODE-002", "KubeletConfiguration kubelet.yaml", finding.Critical},
	{"HX-NODE-003", "KubeletConfiguration kubelet.yaml", finding.Medium},
	{"HX-NODE-004", "KubeletConfiguration kubelet.yaml", finding.Low},
}

func scan(t *testing.T, profile string, paths ...string) *finding.Report {
	t.Helper()
	r, _, err := hardex.Scan(hardex.ScanOptions{Paths: paths, Profile: profile, Now: fixedNow})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !r.Complete() {
		t.Fatalf("assessment incomplete: %v", r.Errors)
	}
	return r
}

func TestDetectsInsecureFixtures(t *testing.T) {
	r := scan(t, "restricted", "fixtures/insecure")
	for _, e := range insecureExpectations {
		found := false
		for _, f := range r.Findings {
			if f.RuleID == e.rule && strings.HasPrefix(f.Resource.String(), e.resource) && f.Severity == e.severity {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %s at %s with severity %s; not reported", e.rule, e.resource, e.severity)
		}
	}
}

func TestEveryRuleHasADetectionExpectation(t *testing.T) {
	reg, err := kubernetes.Registry()
	if err != nil {
		t.Fatal(err)
	}
	covered := map[string]bool{}
	for _, e := range insecureExpectations {
		covered[e.rule] = true
	}
	for _, rule := range reg.All() {
		if id := rule.Metadata().ID; !covered[id] {
			t.Errorf("rule %s has no detection expectation in insecureExpectations", id)
		}
	}
}

func TestNoFalsePositivesOnHardenedFixtures(t *testing.T) {
	for _, profile := range []string{"minimal", "baseline", "restricted"} {
		t.Run(profile, func(t *testing.T) {
			r := scan(t, profile, "fixtures/hardened")
			for _, f := range r.Findings {
				t.Errorf("false positive: %s %s %s: %s", f.RuleID, f.Resource, f.Path, f.Message)
			}
			if r.ObjectsEvaluated == 0 {
				t.Fatal("hardened fixtures were not loaded")
			}
		})
	}
}

func TestSecretValuesNeverReported(t *testing.T) {
	r := scan(t, "restricted", "fixtures/insecure")
	for _, f := range r.Findings {
		for _, leaked := range []string{"hunter2", "aHVudGVyMg==", "YWRtaW4="} {
			if strings.Contains(f.Observed+f.Message+f.Path, leaked) {
				t.Errorf("%s leaks secret material %q", f.RuleID, leaked)
			}
		}
	}
}

func TestSystemObjectsIncludedOnRequest(t *testing.T) {
	r, _, err := hardex.Scan(hardex.ScanOptions{Paths: []string{"fixtures/hardened/rbac.yaml"}, Profile: "baseline", Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 {
		t.Fatalf("system RBAC reported by default: %+v", r.Findings)
	}
	cfg := mustConfig(t, "apiVersion: hardex.dev/v1alpha1\nkind: HardexConfig\nincludeSystem: true\n")
	r, _, err = hardex.Scan(hardex.ScanOptions{Paths: []string{"fixtures/hardened/rbac.yaml"}, Profile: "baseline", Config: cfg, Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) == 0 {
		t.Fatal("includeSystem did not assess the default cluster-admin role")
	}
}

func TestReportIsDeterministic(t *testing.T) {
	a := scan(t, "restricted", "fixtures/insecure")
	b := scan(t, "restricted", "fixtures/insecure")
	if len(a.Findings) != len(b.Findings) {
		t.Fatal("finding counts differ between identical runs")
	}
	for i := range a.Findings {
		if a.Findings[i].Fingerprint != b.Findings[i].Fingerprint {
			t.Fatalf("finding order differs at %d", i)
		}
	}
}

// Regression: YAML 1.1 boolean spellings that Kubernetes accepts must not
// evade detection.
func TestYAML11BooleansDoNotEvadeDetection(t *testing.T) {
	r := scan(t, "minimal", "fixtures/evasion")
	want := map[string]bool{"HX-WL-001": false, "HX-WL-002": false, "HX-NODE-001": false}
	for _, f := range r.Findings {
		if _, ok := want[f.RuleID]; ok {
			want[f.RuleID] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("%s evaded by YAML 1.1 boolean spelling", id)
		}
	}
}

// Distinct findings must have distinct fingerprints; otherwise diff, history
// and remediation verification would conflate them.
func TestFingerprintsAreUnique(t *testing.T) {
	for _, dir := range []string{"fixtures/insecure", "fixtures/evasion"} {
		r := scan(t, "restricted", dir)
		seen := map[string]finding.Finding{}
		for _, f := range r.Findings {
			if prev, dup := seen[f.Fingerprint]; dup {
				t.Errorf("fingerprint %s shared by %s %q and %s %q", f.Fingerprint, prev.RuleID, prev.Message, f.RuleID, f.Message)
			}
			seen[f.Fingerprint] = f
		}
	}
}
