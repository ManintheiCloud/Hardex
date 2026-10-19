// Package resource provides a minimal, dependency-light representation of
// Kubernetes objects and the inventory that assessment rules evaluate.
//
// Objects are kept as generic JSON-compatible maps rather than typed API
// structs. This keeps Hardex independent of any single Kubernetes client
// version and lets one rule set evaluate manifests from many cluster versions.
package resource

import (
	"fmt"
	"path/filepath"
)

// Object is a single Kubernetes object plus the provenance needed to point a
// human back to where it came from.
type Object struct {
	APIVersion string
	Kind       string
	Name       string
	Namespace  string

	// Source is the file path (or "<stdin>") the object was read from.
	Source string
	// Line is the 1-based line on which the object's YAML document begins.
	Line int

	// Raw is the full object as decoded JSON (map[string]any, []any, string,
	// float64, bool, nil).
	Raw map[string]any
}

// NewObject builds an Object from a decoded map, extracting identity fields.
func NewObject(raw map[string]any, source string, line int) (*Object, error) {
	kind := String(raw, "kind")
	if kind == "" {
		return nil, fmt.Errorf("%s:%d: document has no kind", source, line)
	}
	name := String(raw, "metadata", "name")
	if name == "" {
		// Configuration files such as KubeletConfiguration have no name;
		// identify them by where they came from.
		name = filepath.Base(source)
	}
	return &Object{
		APIVersion: String(raw, "apiVersion"),
		Kind:       kind,
		Name:       name,
		Namespace:  String(raw, "metadata", "namespace"),
		Source:     source,
		Line:       line,
		Raw:        raw,
	}, nil
}

// EffectiveNamespace returns the object's namespace, or "default" for a
// namespaced object that does not declare one. Cluster-scoped kinds return "".
func (o *Object) EffectiveNamespace() string {
	if clusterScoped[o.Kind] {
		return ""
	}
	if o.Namespace == "" {
		return "default"
	}
	return o.Namespace
}

// Ref returns a short human-readable identifier, e.g. "Deployment default/web".
func (o *Object) Ref() string {
	if ns := o.EffectiveNamespace(); ns != "" {
		return fmt.Sprintf("%s %s/%s", o.Kind, ns, o.Name)
	}
	return fmt.Sprintf("%s %s", o.Kind, o.Name)
}

var clusterScoped = map[string]bool{
	"Namespace":                      true,
	"Node":                           true,
	"ClusterRole":                    true,
	"ClusterRoleBinding":             true,
	"PersistentVolume":               true,
	"StorageClass":                   true,
	"CustomResourceDefinition":       true,
	"ValidatingWebhookConfiguration": true,
	"MutatingWebhookConfiguration":   true,
	"ValidatingAdmissionPolicy":      true,
	"PriorityClass":                  true,
	"RuntimeClass":                   true,
	// Node-local configuration files, not API objects, but they have no
	// namespace either.
	"KubeletConfiguration": true,
}

// IsClusterScopedKind reports whether Hardex treats the kind as cluster-scoped.
func IsClusterScopedKind(kind string) bool { return clusterScoped[kind] }
