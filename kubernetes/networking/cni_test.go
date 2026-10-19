package networking

import (
	"strings"
	"testing"

	"github.com/ManintheiCloud/Hardex/core/resource"
)

func obj(t *testing.T, y string) *resource.Object {
	t.Helper()
	inv, err := resource.Load([]string{"-"}, strings.NewReader(y))
	if err != nil {
		t.Fatal(err)
	}
	return inv.Objects[0]
}

func TestCNIPolicies(t *testing.T) {
	const cnp = "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata: {name: p, namespace: a}\n"
	const ccnp = "apiVersion: cilium.io/v2\nkind: CiliumClusterwideNetworkPolicy\nmetadata: {name: p}\n"
	const cal = "apiVersion: crd.projectcalico.org/v1\nkind: NetworkPolicy\nmetadata: {name: p, namespace: a}\n"
	const gnp = "apiVersion: projectcalico.org/v3\nkind: GlobalNetworkPolicy\nmetadata: {name: p}\n"
	cases := []struct {
		name, y         string
		ingress, egress bool
		global          bool
	}{
		{"cilium deny-all with empty rules", cnp + "spec: {endpointSelector: {}, ingress: [{}], egress: [{}]}\n", true, true, false},
		{"cilium empty sections do not apply", cnp + "spec: {endpointSelector: {}, ingress: [], egress: []}\n", false, false, false},
		{"cilium default deny disabled", cnp + "spec: {endpointSelector: {}, ingress: [{}], enableDefaultDeny: {ingress: false}}\n", false, false, false},
		{"cilium allow from all entities", cnp + "spec: {endpointSelector: {}, ingress: [{fromEntities: [all]}]}\n", false, false, false},
		{"cilium egress to world is open", cnp + "spec: {endpointSelector: {}, egress: [{toEntities: [world]}]}\n", false, false, false},
		{"cilium restricted peers isolate", cnp + "spec: {endpointSelector: {}, ingress: [{fromEndpoints: [{matchLabels: {app: fe}}]}]}\n", true, false, false},
		{"cilium narrowed selector", cnp + "spec: {endpointSelector: {matchLabels: {app: x}}, ingress: [{}]}\n", false, false, false},
		{"cilium specs list", cnp + "specs: [{endpointSelector: {matchLabels: {a: b}}, ingress: [{}]}, {endpointSelector: {}, egress: [{}]}]\n", false, true, false},
		{"cilium clusterwide", ccnp + "spec: {endpointSelector: {}, ingress: [{}]}\n", true, false, true},
		{"cilium clusterwide allow all endpoints", ccnp + "spec: {endpointSelector: {}, ingress: [{fromEndpoints: [{}]}]}\n", false, false, true},
		{"calico deny with implied types", cal + "spec: {selector: all()}\n", true, false, false},
		{"calico explicit both, no rules", cal + "spec: {types: [Ingress, Egress]}\n", true, true, false},
		{"calico allow-all rule", cal + "spec: {selector: all(), types: [Ingress], ingress: [{action: Allow}]}\n", false, false, false},
		{"calico restricted allow", cal + "spec: {selector: all(), types: [Ingress], ingress: [{action: Allow, source: {selector: app == 'fe'}}]}\n", true, false, false},
		{"calico narrowed selector", cal + "spec: {selector: app == 'x', types: [Ingress]}\n", false, false, false},
		{"calico global", gnp + "spec: {selector: all(), types: [Ingress, Egress]}\n", true, true, true},
		{"calico global narrowed namespaces", gnp + "spec: {selector: all(), namespaceSelector: team == 'a', types: [Ingress]}\n", false, false, true},
	}
	for _, c := range cases {
		o := obj(t, c.y)
		in, g := policyScope(o, "Ingress")
		eg, _ := policyScope(o, "Egress")
		if in != c.ingress || eg != c.egress || (in || eg) && g != c.global {
			t.Errorf("%s: ingress=%v egress=%v global=%v; want %v %v %v", c.name, in, eg, g, c.ingress, c.egress, c.global)
		}
	}
}

func TestCalicoPolicyIsNotReadAsKubernetesPolicy(t *testing.T) {
	// Same kind name, different API group and schema.
	o := obj(t, "apiVersion: crd.projectcalico.org/v1\nkind: NetworkPolicy\nmetadata: {name: p, namespace: a}\nspec: {podSelector: {}, policyTypes: [Ingress], selector: \"app == 'x'\"}\n")
	if in, _ := policyScope(o, "Ingress"); in {
		t.Error("Calico policy with a narrowed selector treated as a Kubernetes default-deny")
	}
}
