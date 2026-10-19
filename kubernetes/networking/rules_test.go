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
