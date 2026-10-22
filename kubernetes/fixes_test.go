package kubernetes

import (
	"testing"

	"github.com/ManintheiCloud/Hardex/core/finding"
)

func TestFixCapabilitySpelling(t *testing.T) {
	fix := Fixers()["HX-WL-006"]
	const path = "spec.containers[0].securityContext.capabilities.add[0]"
	for observed, want := range map[string]any{
		"net_bind_service": "NET_BIND_SERVICE",
		"CAP_CHOWN":        "CHOWN",
		" kill ":           "KILL",
		"SYS_ADMIN":        nil, // not allowed in any spelling: a person decides
		"cap_sys_admin":    nil,
		"NET_BIND_SERVICE": nil, // already correct; HX-WL-006 does not report it
	} {
		c, _ := fix(nil, finding.Finding{RuleID: "HX-WL-006", Path: path, Observed: observed})
		switch {
		case want == nil && c != nil:
			t.Errorf("%q: fixed as %+v, want no automatic fix", observed, c.Set)
		case want != nil && (c == nil || len(c.Set) != 1 || c.Set[0].Value != want):
			t.Errorf("%q: %+v, want %v", observed, c, want)
		}
	}
}
