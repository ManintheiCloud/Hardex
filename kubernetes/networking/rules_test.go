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
	if got != "HX-NET-001 default deny cancelled by NetworkPolicy allow-all" {
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

// Cilium and Calico allows add up with Kubernetes NetworkPolicies, so their
// allow-all policies cancel a default deny too, unless explicit deny rules
// exist (they take precedence, or may be ordered first).
func TestCNIAllowAllCancelsDefaultDeny(t *testing.T) {
	run := func(extra string) string {
		y := `apiVersion: v1
kind: Pod
metadata: {name: p, namespace: app}
spec: {containers: [{name: c, image: x}]}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: deny, namespace: app}
spec: {podSelector: {}, policyTypes: [Ingress, Egress]}
---
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
		return strings.Join(out, "; ")
	}
	const cnp = "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata: {name: open, namespace: app}\n"
	const ccnp = "apiVersion: cilium.io/v2\nkind: CiliumClusterwideNetworkPolicy\nmetadata: {name: open}\n"
	const cal = "apiVersion: crd.projectcalico.org/v1\nkind: NetworkPolicy\nmetadata: {name: open, namespace: app}\n"
	const gnp = "apiVersion: projectcalico.org/v3\nkind: GlobalNetworkPolicy\nmetadata: {name: open}\n"
	for _, c := range []struct{ name, extra, want string }{
		{"cilium from all entities", cnp + "spec: {endpointSelector: {}, ingress: [{fromEntities: [all]}]}\n",
			"HX-NET-001 default deny cancelled by CiliumNetworkPolicy open"},
		{"cilium egress to world", cnp + "spec: {endpointSelector: {}, egress: [{toEntities: [world]}]}\n",
			"HX-NET-002 default deny cancelled by CiliumNetworkPolicy open"},
		{"cilium clusterwide from every endpoint", ccnp + "spec: {endpointSelector: {}, ingress: [{fromEndpoints: [{}]}]}\n",
			"HX-NET-001 default deny cancelled by CiliumClusterwideNetworkPolicy open"},
		{"cilium with ports is partial", cnp + "spec: {endpointSelector: {}, ingress: [{fromEntities: [all], toPorts: [{ports: [{port: '80'}]}]}]}\n", ""},
		{"cilium narrowed selector", cnp + "spec: {endpointSelector: {matchLabels: {app: web}}, ingress: [{fromEntities: [all]}]}\n", ""},
		{"cilium deny rules: not judged", cnp + "spec: {endpointSelector: {}, ingress: [{fromEntities: [all]}], ingressDeny: [{fromEntities: [world]}]}\n", ""},
		{"calico allow all", cal + "spec: {selector: all(), types: [Ingress], ingress: [{action: Allow}]}\n",
			"HX-NET-001 default deny cancelled by NetworkPolicy open"},
		{"calico global allow all", gnp + "spec: {selector: all(), types: [Egress], egress: [{action: Allow}]}\n",
			"HX-NET-002 default deny cancelled by GlobalNetworkPolicy open"},
		{"calico allow with a source", cal + "spec: {selector: all(), types: [Ingress], ingress: [{action: Allow, source: {selector: app == 'fe'}}]}\n", ""},
		{"calico deny first: not judged", cal + "spec: {selector: all(), types: [Ingress], ingress: [{action: Deny, source: {nets: [10.0.0.0/8]}}, {action: Allow}]}\n", ""},
	} {
		if got := run(c.extra); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
