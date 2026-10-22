package resource

import (
	"fmt"
	"sort"
	"strings"
)

// workloadPodSpecPath maps each workload kind to the location of its pod spec.
var workloadPodSpecPath = map[string][]string{
	"Pod":                   {"spec"},
	"Deployment":            {"spec", "template", "spec"},
	"StatefulSet":           {"spec", "template", "spec"},
	"DaemonSet":             {"spec", "template", "spec"},
	"ReplicaSet":            {"spec", "template", "spec"},
	"ReplicationController": {"spec", "template", "spec"},
	"Job":                   {"spec", "template", "spec"},
	"CronJob":               {"spec", "jobTemplate", "spec", "template", "spec"},
	"PodTemplate":           {"template", "spec"},
}

// groupPodSpecPath adds custom resources that embed a full pod template,
// keyed by API group and kind: a kind name alone can clash (Knative's
// Service is not the core Service). Their controllers create the pods, so a
// manifest scan must judge the template here or not at all.
var groupPodSpecPath = map[string][]string{
	"argoproj.io/Rollout":               {"spec", "template", "spec"},
	"serving.knative.dev/Service":       {"spec", "template", "spec"},
	"serving.knative.dev/Configuration": {"spec", "template", "spec"},
	"serving.knative.dev/Revision":      {"spec"},
	"keda.sh/ScaledJob":                 {"spec", "jobTargetRef", "template", "spec"},
	"apps.kruise.io/CloneSet":           {"spec", "template", "spec"},
	"apps.kruise.io/BroadcastJob":       {"spec", "template", "spec"},
}

// podSpecPath returns where an object's pod spec is, if it has one.
func podSpecPath(o *Object) ([]string, bool) {
	if p, ok := groupPodSpecPath[o.Group()+"/"+o.Kind]; ok {
		return p, true
	}
	// The built-in kinds by name alone, so that look-alikes keep their
	// assessment (OpenKruise's apps.kruise.io StatefulSet and DaemonSet
	// share the layout).
	p, ok := workloadPodSpecPath[o.Kind]
	return p, ok
}

// groupKinds are the kinds of groupPodSpecPath.
var groupKinds = func() map[string]bool {
	out := map[string]bool{}
	for k := range groupPodSpecPath {
		out[k[strings.LastIndex(k, "/")+1:]] = true
	}
	return out
}()

// IsWorkload reports whether the object carries a pod spec.
func IsWorkload(o *Object) bool {
	_, ok := podSpecPath(o)
	return ok
}

// WorkloadKinds returns every kind that may carry a pod spec (PodSpec
// decides for a given object, by group as well).
func WorkloadKinds() []string {
	seen := map[string]bool{}
	for k := range workloadPodSpecPath {
		seen[k] = true
	}
	for k := range groupKinds {
		seen[k] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// PodSpec returns the pod spec of a workload and its dotted path prefix
// (e.g. "spec.template.spec"), or nil if the object is not a workload.
func PodSpec(o *Object) (map[string]any, string) {
	path, ok := podSpecPath(o)
	if !ok {
		return nil, ""
	}
	return Map(o.Raw, path...), strings.Join(path, ".")
}

// Container is one container entry within a pod spec.
type Container struct {
	Spec map[string]any
	Name string
	// Field is "containers", "initContainers" or "ephemeralContainers".
	Field string
	Index int
}

// Path returns the dotted path of the container within its object.
func (c Container) Path(prefix string) string {
	return fmt.Sprintf("%s.%s[%d]", prefix, c.Field, c.Index)
}

// Containers returns all containers in a pod spec, including init and
// ephemeral containers. Every container runs with the pod's privileges, so
// every container must be assessed.
func Containers(podSpec map[string]any) []Container {
	var out []Container
	for _, field := range []string{"initContainers", "containers", "ephemeralContainers"} {
		for i, c := range Maps(podSpec, field) {
			out = append(out, Container{Spec: c, Name: String(c, "name"), Field: field, Index: i})
		}
	}
	return out
}
