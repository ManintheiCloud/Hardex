// Package controlplane implements checks on control-plane component
// configuration, read from static pod manifests (as written by kubeadm to
// /etc/kubernetes/manifests and visible in kube-system).
package controlplane

import (
	"path"
	"strings"

	"github.com/ManintheiCloud/Hardex/core/resource"
)

// component is a control-plane container found in the inventory.
type component struct {
	obj       *resource.Object
	container resource.Container
	prefix    string
	flags     map[string]string
}

// path returns the field path at which a container's flags live.
func (c component) path() string { return c.container.Path(c.prefix) + ".command" }

// flag returns a flag's value and whether it is set.
func (c component) flag(name string) (string, bool) {
	v, ok := c.flags[name]
	return v, ok
}

// findComponents returns every container running the named binary.
func findComponents(inv *resource.Inventory, binary string) []component {
	var out []component
	for _, o := range inv.OfKind("Pod") {
		pod, prefix := resource.PodSpec(o)
		for _, c := range resource.Containers(pod) {
			argv := append(resource.Strings(c.Spec, "command"), resource.Strings(c.Spec, "args")...)
			if !runs(argv, binary) && c.Name != binary {
				continue
			}
			out = append(out, component{obj: o, container: c, prefix: prefix, flags: parseFlags(argv)})
		}
	}
	return out
}

func runs(argv []string, binary string) bool {
	for _, a := range argv {
		if strings.HasPrefix(a, "-") {
			continue
		}
		return path.Base(a) == binary
	}
	return false
}

// parseFlags parses Go-style command-line flags: --name=value, --name value,
// and bare boolean --name. Later occurrences win, as with the flag package.
func parseFlags(argv []string) map[string]string {
	flags := map[string]string{}
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if !strings.HasPrefix(a, "-") {
			continue
		}
		a = strings.TrimLeft(a, "-")
		if k, v, ok := strings.Cut(a, "="); ok {
			flags[k] = v
			continue
		}
		if i+1 < len(argv) && !strings.HasPrefix(argv[i+1], "-") {
			flags[a] = argv[i+1]
			i++
			continue
		}
		flags[a] = "true"
	}
	return flags
}

// listContains reports whether a comma-separated flag value contains item.
func listContains(list, item string) bool {
	for _, s := range strings.Split(list, ",") {
		if strings.TrimSpace(s) == item {
			return true
		}
	}
	return false
}
