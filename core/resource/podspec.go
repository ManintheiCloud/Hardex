package resource

import "fmt"

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

// IsWorkload reports whether the object carries a pod spec.
func IsWorkload(o *Object) bool {
	_, ok := workloadPodSpecPath[o.Kind]
	return ok
}

// WorkloadKinds returns every kind that carries a pod spec.
func WorkloadKinds() []string {
	out := make([]string, 0, len(workloadPodSpecPath))
	for k := range workloadPodSpecPath {
		out = append(out, k)
	}
	return out
}

// PodSpec returns the pod spec of a workload and its dotted path prefix
// (e.g. "spec.template.spec"), or nil if the object is not a workload.
func PodSpec(o *Object) (map[string]any, string) {
	path, ok := workloadPodSpecPath[o.Kind]
	if !ok {
		return nil, ""
	}
	prefix := ""
	for i, p := range path {
		if i > 0 {
			prefix += "."
		}
		prefix += p
	}
	return Map(o.Raw, path...), prefix
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
