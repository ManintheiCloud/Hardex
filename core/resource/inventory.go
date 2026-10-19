package resource

import "sort"

// Inventory is the complete set of objects under assessment. Some rules
// evaluate objects one at a time; others (network segmentation, RBAC
// reachability) need to reason across the whole set.
type Inventory struct {
	Objects []*Object
	// Sources lists every file or stream that was read.
	Sources []string
	// Skipped records documents that were read but not evaluated, so that
	// partial coverage is visible instead of silent.
	Skipped []string

	byKind map[string][]*Object
}

// NewInventory returns an empty inventory.
func NewInventory() *Inventory {
	return &Inventory{byKind: map[string][]*Object{}}
}

// Add appends an object to the inventory.
func (inv *Inventory) Add(o *Object) {
	inv.Objects = append(inv.Objects, o)
	inv.byKind[o.Kind] = append(inv.byKind[o.Kind], o)
}

// OfKind returns all objects with any of the given kinds, in input order.
func (inv *Inventory) OfKind(kinds ...string) []*Object {
	if len(kinds) == 1 {
		return inv.byKind[kinds[0]]
	}
	var out []*Object
	for _, o := range inv.Objects {
		for _, k := range kinds {
			if o.Kind == k {
				out = append(out, o)
				break
			}
		}
	}
	return out
}

// Namespaces returns the sorted set of namespaces that contain workloads or
// that are declared by Namespace objects.
func (inv *Inventory) Namespaces() []string {
	set := map[string]bool{}
	for _, o := range inv.OfKind("Namespace") {
		set[o.Name] = true
	}
	for _, o := range inv.Objects {
		if IsWorkload(o) {
			set[o.EffectiveNamespace()] = true
		}
	}
	out := make([]string, 0, len(set))
	for ns := range set {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out
}
