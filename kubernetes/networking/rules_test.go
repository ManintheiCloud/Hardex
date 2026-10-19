package networking

import (
	"strings"
	"testing"

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
