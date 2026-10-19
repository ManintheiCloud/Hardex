// Package kubernetes assembles the built-in Hardex rule set.
package kubernetes

import (
	"github.com/ManintheiCloud/Hardex/baselines"
	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/kubernetes/controlplane"
	"github.com/ManintheiCloud/Hardex/kubernetes/networking"
	"github.com/ManintheiCloud/Hardex/kubernetes/nodes"
	"github.com/ManintheiCloud/Hardex/kubernetes/paths"
	"github.com/ManintheiCloud/Hardex/kubernetes/rbac"
	"github.com/ManintheiCloud/Hardex/kubernetes/secrets"
	"github.com/ManintheiCloud/Hardex/kubernetes/workloads"
)

// Registry returns a validated registry of every built-in rule, plus any
// extra rules (e.g. from declarative modules).
func Registry(extra ...assessment.Rule) (*assessment.Registry, error) {
	all := append([]assessment.Rule(nil), extra...)
	for _, group := range [][]assessment.Rule{
		workloads.Rules(), secrets.Rules(), rbac.Rules(), networking.Rules(), controlplane.Rules(), nodes.Rules(), paths.Rules(),
	} {
		all = append(all, group...)
	}
	for i, r := range all {
		if _, mapped := baselines.Mappings[r.Metadata().ID]; mapped {
			all[i] = mappedRule{r}
		}
	}
	return assessment.NewRegistry(all...)
}

// mappedRule decorates a built-in rule with its item-level CIS and NSA/CISA
// references (baselines.Mappings), keeping guidance mappings in one
// reviewable table instead of scattered across rule definitions.
type mappedRule struct{ assessment.Rule }

func (m mappedRule) Metadata() assessment.Metadata {
	meta := m.Rule.Metadata()
	meta.References = baselines.MappedReferences(meta.ID, meta.References)
	return meta
}
