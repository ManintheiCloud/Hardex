package admission

import (
	"encoding/json"
	"sort"

	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

// GuardedKinds are the kinds the shipped webhook configuration sends to
// Hardex (deploy/hardex-admission.yaml).
var GuardedKinds = map[string]bool{
	"Pod": true, "Service": true, "ServiceAccount": true,
	"Deployment": true, "DaemonSet": true, "StatefulSet": true, "ReplicaSet": true,
	"Job": true, "CronJob": true,
	"Role": true, "RoleBinding": true, "ClusterRole": true, "ClusterRoleBinding": true,
	"Ingress": true,
}

// Denial is an existing object that enforce mode would reject on its next
// create or update — for a controller, also every pod it creates.
type Denial struct {
	Kind      string            `json:"kind"`
	Namespace string            `json:"namespace,omitempty"`
	Name      string            `json:"name"`
	Findings  []finding.Finding `json:"findings"`
}

// Preflight evaluates existing objects exactly as the webhook would in
// enforce mode, one object at a time, and returns those that would be
// rejected. Objects in excluded namespaces are skipped, as the webhook's
// namespaceSelector skips them.
func (h *Handler) Preflight(inv *resource.Inventory, excluded map[string]bool) []Denial {
	var out []Denial
	for _, o := range inv.Objects {
		if !GuardedKinds[o.Kind] || excluded[o.EffectiveNamespace()] {
			continue
		}
		raw, err := json.Marshal(o.Raw)
		if err != nil {
			continue
		}
		req := &Request{UID: "preflight", Operation: "UPDATE", Namespace: o.Namespace, Object: raw}
		req.Kind.Kind = o.Kind
		findings, evalErr := h.evaluate(req)
		var blocking []finding.Finding
		for _, f := range findings {
			if f.Severity >= h.Threshold {
				blocking = append(blocking, f)
			}
		}
		if evalErr != nil {
			blocking = append(blocking, finding.Finding{RuleID: "evaluation-error", Severity: finding.Critical, Message: evalErr.Error()})
		}
		if len(blocking) > 0 {
			out = append(out, Denial{Kind: o.Kind, Namespace: o.Namespace, Name: o.Name, Findings: blocking})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	return out
}
