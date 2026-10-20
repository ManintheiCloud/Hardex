package admission

import (
	"encoding/json"
	"testing"

	"github.com/ManintheiCloud/Hardex/core/resource"
)

// Preflight must predict exactly what the webhook decides, object by object.
func TestPreflightAgreesWithTheWebhook(t *testing.T) {
	h := handler(t, Enforce, "")
	checked, deniedTotal := 0, 0
	// Each fixture set separately: both contain kube-system/kube-apiserver-cp1.
	for _, dir := range []string{"../../tests/fixtures/insecure", "../../tests/fixtures/hardened"} {
		c, d := checkPreflight(t, h, dir)
		checked, deniedTotal = checked+c, deniedTotal+d
	}
	if checked < 15 || deniedTotal == 0 {
		t.Fatalf("checked %d objects, %d denied", checked, deniedTotal)
	}
}

func checkPreflight(t *testing.T, h *Handler, dir string) (int, int) {
	t.Helper()
	inv, err := resource.Load([]string{dir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	denied := map[string]bool{}
	for _, d := range h.Preflight(inv, nil) {
		denied[d.Kind+"/"+d.Namespace+"/"+d.Name] = true
	}
	checked := 0
	for _, o := range inv.Objects {
		if !GuardedKinds[o.Kind] {
			continue
		}
		raw, _ := json.Marshal(o.Raw)
		req := &Request{UID: "u", Operation: "CREATE", Namespace: o.Namespace, Object: raw}
		req.Kind.Kind = o.Kind
		resp := h.Decide(req)
		if web, pre := !resp.Allowed, denied[o.Kind+"/"+o.Namespace+"/"+o.Name]; web != pre {
			t.Errorf("%s: webhook denies=%v, preflight denies=%v", o.Ref(), web, pre)
		}
		checked++
	}
	return checked, len(denied)
}

func TestPreflightHonoursExclusions(t *testing.T) {
	h := handler(t, Enforce, "")
	inv, _ := resource.Load([]string{"../../tests/fixtures/insecure"}, nil)
	for _, d := range h.Preflight(inv, map[string]bool{"shop": true}) {
		if d.Namespace == "shop" {
			t.Errorf("excluded namespace reported: %s %s", d.Kind, d.Name)
		}
	}
}
