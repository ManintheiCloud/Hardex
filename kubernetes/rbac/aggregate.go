package rbac

import (
	"sort"
	"strings"

	"github.com/ManintheiCloud/Hardex/core/resource"
)

// Effective rules of roles.
//
// A ClusterRole with an aggregationRule grants the union of the rules of
// every ClusterRole its selectors match: the API server's aggregation
// controller copies them in. In manifests that field is usually empty
// (rules: []), so a role must be resolved before it is judged, and a role
// labelled to aggregate into another one (aggregate-to-edit, say) grants its
// rules to everyone bound to that one. Roles that Kubernetes creates are
// often referenced without being in the input; their rules come from the
// upstream bootstrap policy (defaults.json).

// resolver computes the effective rules of the roles in an inventory.
type resolver struct {
	clusterRoles map[string]*resource.Object
	memo         map[string][]map[string]any
}

func newResolver(inv *resource.Inventory) *resolver {
	r := &resolver{clusterRoles: map[string]*resource.Object{}, memo: map[string][]map[string]any{}}
	for _, o := range inv.OfKind("ClusterRole") {
		r.clusterRoles[o.Name] = o
	}
	return r
}

// rules returns the effective rules of a Role or ClusterRole in the input.
func (r *resolver) rules(o *resource.Object) []map[string]any {
	if o.Kind != "ClusterRole" {
		return resource.Maps(o.Raw, "rules")
	}
	return r.resolve(o.Name, map[string]bool{})
}

// clusterRole returns the effective rules of the ClusterRole a binding
// names: the input's object, or else the Kubernetes default of that name.
// ok is false for a role that is neither, about which nothing can be
// concluded.
func (r *resolver) clusterRole(name string) (rules []map[string]any, ok bool) {
	d := loadDefaults()
	_, in := r.clusterRoles[name]
	_, agg := d.Aggregated["ClusterRole/"+name]
	_, def := d.Roles["ClusterRole/"+name]
	if !in && !agg && !def {
		return nil, false
	}
	return r.resolve(name, map[string]bool{}), true
}

// resolve computes a ClusterRole's rules by name: its own (from the input,
// or from the upstream policy if it is a default not in the input), and if
// it aggregates, those of every role its selectors select, resolved in turn.
// A default aggregated role also keeps the upstream permissions of the
// roles Kubernetes aggregates into it, which are rarely in the input.
func (r *resolver) resolve(name string, visiting map[string]bool) []map[string]any {
	if rules, ok := r.memo[name]; ok {
		return rules
	}
	if visiting[name] {
		return nil // a cycle; the outer resolution has these rules
	}
	visiting[name] = true
	defer delete(visiting, name)
	d := loadDefaults()
	agg, isAgg := d.Aggregated["ClusterRole/"+name]
	var rules, selectors []map[string]any
	aggregates := false
	if o, in := r.clusterRoles[name]; in {
		rules = append(rules, resource.Maps(o.Raw, "rules")...)
		if _, ok := resource.Lookup(o.Raw, "aggregationRule"); ok {
			aggregates = true
			selectors = resource.Maps(o.Raw, "aggregationRule", "clusterRoleSelectors")
			if isAgg {
				rules = append(rules, atomRules(agg.Permissions)...)
			}
		}
	} else if isAgg {
		aggregates, selectors = true, agg.Selectors
		rules = atomRules(agg.Permissions)
	} else {
		rules = atomRules(d.Roles["ClusterRole/"+name])
	}
	if aggregates {
		for _, other := range r.candidates() {
			if other == name {
				continue
			}
			for _, sel := range selectors {
				if selectorMatches(sel, r.labels(other)) {
					rules = append(rules, r.resolve(other, visiting)...)
					break
				}
			}
		}
	}
	if len(visiting) == 1 {
		r.memo[name] = rules // only complete results, not ones cut by a cycle
	}
	return rules
}

// candidates lists, sorted, the ClusterRoles that may aggregate or be
// aggregated: those in the input, and the defaults that aggregate (admin,
// edit, view) or carry aggregation labels (view, edit, system:aggregate-to-*).
func (r *resolver) candidates() []string {
	seen := map[string]bool{}
	for n := range r.clusterRoles {
		seen[n] = true
	}
	d := loadDefaults()
	for key := range d.AggregationLabels {
		seen[strings.TrimPrefix(key, "ClusterRole/")] = true
	}
	for key := range d.Aggregated {
		seen[strings.TrimPrefix(key, "ClusterRole/")] = true
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// labels returns a ClusterRole's labels: the input's object, or a default's
// aggregation labels.
func (r *resolver) labels(name string) map[string]any {
	if o, in := r.clusterRoles[name]; in {
		return resource.Map(o.Raw, "metadata", "labels")
	}
	out := map[string]any{}
	for k, v := range loadDefaults().AggregationLabels["ClusterRole/"+name] {
		out[k] = v
	}
	return out
}

// selectorsOf returns the aggregation selectors of a ClusterRole, from the
// input or the defaults, and whether it aggregates.
func (r *resolver) selectorsOf(name string) ([]map[string]any, bool) {
	if o, in := r.clusterRoles[name]; in {
		if _, ok := resource.Lookup(o.Raw, "aggregationRule"); ok {
			return resource.Maps(o.Raw, "aggregationRule", "clusterRoleSelectors"), true
		}
		return nil, false
	}
	if agg, ok := loadDefaults().Aggregated["ClusterRole/"+name]; ok {
		return agg.Selectors, true
	}
	return nil, false
}

// aggregatedInto lists the ClusterRoles (of the input, or Kubernetes
// defaults) that aggregate o, directly or through others: o's rules are
// granted to everyone bound to them.
func (r *resolver) aggregatedInto(o *resource.Object) []string {
	if o.Kind != "ClusterRole" {
		return nil
	}
	found := map[string]bool{}
	queue := []string{o.Name}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		labels := r.labels(cur)
		if len(labels) == 0 {
			continue
		}
		for _, other := range r.candidates() {
			if other == o.Name || found[other] {
				continue
			}
			sels, ok := r.selectorsOf(other)
			if !ok {
				continue
			}
			for _, sel := range sels {
				if selectorMatches(sel, labels) {
					found[other] = true
					queue = append(queue, other)
					break
				}
			}
		}
	}
	out := make([]string, 0, len(found))
	for n := range found {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// selectorMatches evaluates a Kubernetes label selector. An empty selector
// matches everything, as for aggregation rules.
func selectorMatches(sel map[string]any, labels map[string]any) bool {
	label := func(k string) (string, bool) {
		v, ok := labels[k].(string)
		return v, ok
	}
	for k, want := range resource.Map(sel, "matchLabels") {
		if v, ok := label(k); !ok || v != want {
			return false
		}
	}
	for _, e := range resource.Maps(sel, "matchExpressions") {
		k, op, vals := resource.String(e, "key"), resource.String(e, "operator"), resource.Strings(e, "values")
		v, has := label(k)
		switch op {
		case "In":
			if !has || !contains(vals, v) {
				return false
			}
		case "NotIn":
			if has && contains(vals, v) {
				return false
			}
		case "Exists":
			if !has {
				return false
			}
		case "DoesNotExist":
			if has {
				return false
			}
		default:
			return false // unknown operator: the API server rejects it
		}
	}
	return true
}

// atomRules turns defaults.json permissions back into policy rules.
func atomRules(atoms []string) []map[string]any {
	var out []map[string]any
	for _, a := range atoms {
		p := strings.Split(a, "|")
		switch {
		case len(p) == 3 && p[0] == "url":
			out = append(out, map[string]any{"nonResourceURLs": []any{p[1]}, "verbs": []any{p[2]}})
		case len(p) == 4:
			r := map[string]any{"apiGroups": []any{p[0]}, "resources": []any{p[1]}, "verbs": []any{p[3]}}
			if p[2] != "*" {
				r["resourceNames"] = []any{p[2]}
			}
			out = append(out, r)
		}
	}
	return out
}
