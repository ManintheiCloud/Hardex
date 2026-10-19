// Package kubernetes assembles the built-in Hardex rule set.
package kubernetes

import (
	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/kubernetes/controlplane"
	"github.com/ManintheiCloud/Hardex/kubernetes/networking"
	"github.com/ManintheiCloud/Hardex/kubernetes/nodes"
	"github.com/ManintheiCloud/Hardex/kubernetes/rbac"
	"github.com/ManintheiCloud/Hardex/kubernetes/secrets"
	"github.com/ManintheiCloud/Hardex/kubernetes/workloads"
)

// Registry returns a validated registry of every built-in rule.
func Registry() (*assessment.Registry, error) {
	var all []assessment.Rule
	for _, group := range [][]assessment.Rule{
		workloads.Rules(), secrets.Rules(), rbac.Rules(), networking.Rules(), controlplane.Rules(), nodes.Rules(),
	} {
		all = append(all, group...)
	}
	return assessment.NewRegistry(all...)
}
