package networking

import (
	"strings"
	"testing"

	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

func policy(t *testing.T, spec string) *resource.Object {
	t.Helper()
	inv, err := resource.Load([]string{"-"}, strings.NewReader("apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {name: p}\nspec:\n"+spec))
	if err != nil {
		t.Fatal(err)
	}
	return inv.Objects[0]
}

func TestIsolates(t *testing.T) {
	cases := []struct {
		name, spec      string
		ingress, egress bool
	}{
		{"deny all ingress (implied type)", "  podSelector: {}\n", true, false},
		{"deny both", "  podSelector: {}\n  policyTypes: [Ingress, Egress]\n", true, true},
		{"allow-all ingress rule", "  podSelector: {}\n  ingress: [{}]\n", false, false},
		{"selects subset", "  podSelector: {matchLabels: {app: a}}\n  policyTypes: [Ingress]\n", false, false},
		{"restricted egress", "  podSelector: {}\n  policyTypes: [Egress]\n  egress:\n    - ports: [{port: 53, protocol: UDP}]\n", false, true},
		// Peers that match everything are no restriction.
		{"from every namespace", "  podSelector: {}\n  ingress: [{from: [{namespaceSelector: {}}]}]\n", false, false},
		{"from every pod of every namespace", "  podSelector: {}\n  ingress: [{from: [{namespaceSelector: {}, podSelector: {}}]}]\n", false, false},
		{"one open peer among others", "  podSelector: {}\n  ingress: [{from: [{podSelector: {matchLabels: {app: fe}}}, {ipBlock: {cidr: 0.0.0.0/0}}]}]\n", false, false},
		{"to every IPv6 address", "  podSelector: {}\n  policyTypes: [Egress]\n  egress: [{to: [{ipBlock: {cidr: \"::/0\"}}]}]\n", false, false},
		{"every namespace's labelled pods", "  podSelector: {}\n  ingress: [{from: [{namespaceSelector: {}, podSelector: {matchLabels: {role: mon}}}]}]\n", true, false},
		{"any address but some", "  podSelector: {}\n  ingress: [{from: [{ipBlock: {cidr: 0.0.0.0/0, except: [10.0.0.0/8]}}]}]\n", true, false},
		{"labelled namespaces", "  podSelector: {}\n  ingress: [{from: [{namespaceSelector: {matchLabels: {team: a}}}]}]\n", true, false},
	}
	for _, c := range cases {
		p := policy(t, c.spec)
		if got := isolates(p, "Ingress"); got != c.ingress {
			t.Errorf("%s: ingress isolates = %v, want %v", c.name, got, c.ingress)
		}
		if got := isolates(p, "Egress"); got != c.egress {
			t.Errorf("%s: egress isolates = %v, want %v", c.name, got, c.egress)
		}
	}
}

func TestRetiredIngressNginxByImage(t *testing.T) {
	inv, err := resource.Load([]string{"-"}, strings.NewReader("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: ctl, namespace: ingress}\nspec:\n  template:\n    spec:\n      containers: [{name: c, image: registry.k8s.io/ingress-nginx/controller:v1.12.1}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	reg, _ := assessment.NewRegistry(retiredIngressNginx)
	res := assessment.Evaluate(inv, reg.All(), assessment.Options{})
	if len(res.Findings) != 1 || res.Findings[0].Resource.Name != "ctl" {
		t.Fatalf("findings = %+v", res.Findings)
	}
}

// Policies add up: an allow-all policy for every pod cancels a default deny
// beside it.
func TestAllowAllPolicyCancelsDefaultDeny(t *testing.T) {
	run := func(extra string) []string {
		y := `apiVersion: v1
kind: Pod
metadata: {name: p, namespace: app}
spec: {containers: [{name: c, image: x}]}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: deny, namespace: app}
spec: {podSelector: {}, policyTypes: [Ingress, Egress]}
` + extra
		inv, err := resource.Load([]string{"-"}, strings.NewReader(y))
		if err != nil {
			t.Fatal(err)
		}
		reg, _ := assessment.NewRegistry(ingressIsolation, egressIsolation)
		var out []string
		for _, f := range assessment.Evaluate(inv, reg.All(), assessment.Options{}).Findings {
			out = append(out, f.RuleID+" "+f.Observed)
		}
		return out
	}
	if got := run(""); len(got) != 0 {
		t.Errorf("default deny alone: %v", got)
	}
	allowAll := `---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: allow-all, namespace: app}
spec: {podSelector: {}, ingress: [{from: [{namespaceSelector: {}}]}]}
`
	got := strings.Join(run(allowAll), "; ")
	if got != "HX-NET-001 default deny cancelled by allow-all" {
		t.Errorf("with an allow-all ingress policy: %q", got)
	}
	// Opening one set of pods, or one port, does not cancel it.
	partial := `---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: web, namespace: app}
spec: {podSelector: {matchLabels: {app: web}}, ingress: [{}]}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: dns, namespace: app}
spec: {podSelector: {}, policyTypes: [Egress], egress: [{ports: [{port: 53, protocol: UDP}]}]}
`
	if got := run(partial); len(got) != 0 {
		t.Errorf("partial allows reported: %v", got)
	}
}
