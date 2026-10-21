package cluster

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/ManintheiCloud/Hardex/core/resource"
)

// Resource identifies a listable API resource.
type Resource struct {
	Group    string // "" for the core group
	Version  string
	Plural   string
	Kind     string
	Optional bool // absent APIs (e.g. older clusters) are not an error
}

// APIVersion returns group/version (or just version for the core group).
func (r Resource) APIVersion() string {
	if r.Group == "" {
		return r.Version
	}
	return r.Group + "/" + r.Version
}

// ListPath returns the cluster-wide list path.
func (r Resource) ListPath() string {
	if r.Group == "" {
		return "/api/" + r.Version + "/" + r.Plural
	}
	return "/apis/" + r.Group + "/" + r.Version + "/" + r.Plural
}

// ObjectPath returns the path of one named object.
func (r Resource) ObjectPath(namespace, name string) string {
	base := "/apis/" + r.Group + "/" + r.Version
	if r.Group == "" {
		base = "/api/" + r.Version
	}
	if namespace != "" {
		base += "/namespaces/" + url.PathEscape(namespace)
	}
	return base + "/" + r.Plural + "/" + url.PathEscape(name)
}

// Collected lists what Hardex reads. Secrets are deliberately absent: the
// rules that need them (HX-SEC-001) target manifests in version control, and
// granting an assessment tool secret read access would make the tool's
// credentials a high-value target (see deploy/hardex-reader.yaml).
var Collected = []Resource{
	{"", "v1", "namespaces", "Namespace", false},
	{"", "v1", "pods", "Pod", false},
	{"", "v1", "services", "Service", false},
	{"", "v1", "serviceaccounts", "ServiceAccount", false},
	{"", "v1", "limitranges", "LimitRange", false},
	{"", "v1", "replicationcontrollers", "ReplicationController", false},
	{"apps", "v1", "deployments", "Deployment", false},
	{"apps", "v1", "daemonsets", "DaemonSet", false},
	{"apps", "v1", "statefulsets", "StatefulSet", false},
	{"apps", "v1", "replicasets", "ReplicaSet", false},
	{"batch", "v1", "jobs", "Job", false},
	{"batch", "v1", "cronjobs", "CronJob", true},
	{"networking.k8s.io", "v1", "networkpolicies", "NetworkPolicy", false},
	{"networking.k8s.io", "v1", "ingresses", "Ingress", false},
	{"networking.k8s.io", "v1", "ingressclasses", "IngressClass", false},
	// CNI-specific policies: optional, since the CRDs exist only where the
	// CNI is installed.
	{"cilium.io", "v2", "ciliumnetworkpolicies", "CiliumNetworkPolicy", true},
	{"cilium.io", "v2", "ciliumclusterwidenetworkpolicies", "CiliumClusterwideNetworkPolicy", true},
	{"crd.projectcalico.org", "v1", "networkpolicies", "NetworkPolicy", true},
	{"crd.projectcalico.org", "v1", "globalnetworkpolicies", "GlobalNetworkPolicy", true},
	{"gateway.networking.k8s.io", "v1", "gateways", "Gateway", true},
	{"admissionregistration.k8s.io", "v1", "validatingwebhookconfigurations", "ValidatingWebhookConfiguration", false},
	{"admissionregistration.k8s.io", "v1", "mutatingwebhookconfigurations", "MutatingWebhookConfiguration", false},
	{"rbac.authorization.k8s.io", "v1", "roles", "Role", false},
	{"rbac.authorization.k8s.io", "v1", "rolebindings", "RoleBinding", false},
	{"rbac.authorization.k8s.io", "v1", "clusterroles", "ClusterRole", false},
	{"rbac.authorization.k8s.io", "v1", "clusterrolebindings", "ClusterRoleBinding", false},
}

// Enrichment resources sharpen the analysis but are not required: when they
// cannot be read the assessment is still complete, with a warning naming
// what is less precise. Nodes let attack-path analysis place pods on the
// nodes they can actually be scheduled on (labels, affinity, taints).
var Enrichment = []Resource{
	{"", "v1", "nodes", "Node", true},
}

// enrichmentEffect explains what is lost without an enrichment resource.
var enrichmentEffect = map[string]string{
	"Node": "attack paths assume pods may share a node unless their node selectors exclude it",
}

// ResourceForKind returns the API resource for a collected kind.
func ResourceForKind(kind string) (Resource, bool) {
	for _, r := range Collected {
		if r.Kind == kind {
			return r, true
		}
	}
	return Resource{}, false
}

// Collection is the result of reading a cluster.
type Collection struct {
	Inventory *resource.Inventory
	// Errors are resources that could not be read. An assessment built on
	// an incomplete collection understates risk.
	Errors []string
	// Warnings describe enrichment resources that could not be read.
	Warnings []string
	// Skipped counts controller-owned objects omitted to avoid reporting
	// the same weakness on a Deployment, its ReplicaSet and every Pod.
	Skipped int
}

// pageSize bounds each LIST response.
const pageSize = 500

// Collect lists every resource in Collected, following pagination.
func Collect(ctx context.Context, c *Client) (*Collection, error) {
	col := &Collection{Inventory: resource.NewInventory()}
	source := "cluster:" + c.Context()
	col.Inventory.Sources = []string{source + " (" + c.Server() + ")"}
	reachable := false

	for _, r := range Collected {
		items, err := listAll(ctx, c, r)
		switch {
		case err == nil:
			reachable = true
		case IsNotFound(err) && r.Optional:
			continue
		case IsForbidden(err):
			reachable = true
			col.Errors = append(col.Errors, fmt.Sprintf("collection: cannot list %s: forbidden; grant the hardex-reader ClusterRole", r.Plural))
			continue
		default:
			col.Errors = append(col.Errors, fmt.Sprintf("collection: cannot list %s: %v", r.Plural, err))
			continue
		}
		for _, item := range items {
			item["apiVersion"] = r.APIVersion()
			item["kind"] = r.Kind
			if ownedByCollectedController(item) {
				// The owner's template is assessed instead, except for
				// containers added to this pod alone: ephemeral containers
				// (kubectl debug) are never in the template.
				eph, ok := withEphemeralOnly(item)
				if !ok {
					col.Skipped++
					continue
				}
				item = eph
			}
			obj, err := resource.NewObject(item, source, 0)
			if err != nil {
				continue
			}
			col.Inventory.Add(obj)
		}
	}
	for _, r := range Enrichment {
		if !reachable {
			break
		}
		items, err := listAll(ctx, c, r)
		if err != nil {
			reason := "forbidden"
			if !IsForbidden(err) {
				reason = err.Error()
			}
			col.Warnings = append(col.Warnings, fmt.Sprintf("collection: cannot list %s (%s): %s", r.Plural, reason, enrichmentEffect[r.Kind]))
			continue
		}
		for _, item := range items {
			item = minimal(item, r)
			if obj, err := resource.NewObject(item, source, 0); err == nil {
				col.Inventory.Add(obj)
			}
		}
	}
	if !reachable {
		return nil, fmt.Errorf("cannot reach the API server at %s: %s", c.Server(), strings.Join(col.Errors, "; "))
	}
	return col, nil
}

func listAll(ctx context.Context, c *Client, r Resource) ([]map[string]any, error) {
	var out []map[string]any
	q := url.Values{"limit": {fmt.Sprint(pageSize)}}
	for page := 0; ; page++ {
		if page > 10000 {
			return nil, fmt.Errorf("pagination did not terminate")
		}
		resp, err := c.Get(ctx, r.ListPath(), q)
		if err != nil {
			return nil, err
		}
		out = append(out, resource.Maps(resp, "items")...)
		cont := resource.String(resp, "metadata", "continue")
		if cont == "" {
			return out, nil
		}
		q.Set("continue", cont)
	}
}

// Controllers whose pod templates are assessed directly. Objects they own
// (a Deployment's ReplicaSets, a ReplicaSet's Pods, a CronJob's Jobs) carry
// the same template and would duplicate every finding.
var templateOwners = map[string]bool{
	"Deployment": true, "ReplicaSet": true, "StatefulSet": true, "DaemonSet": true,
	"Job": true, "CronJob": true, "ReplicationController": true,
}

// withEphemeralOnly returns a pod reduced to its ephemeral containers and
// the pod-level settings that decide their effective security (security
// context, OS, user namespace, service-account token), or false if it has
// none. Host namespaces, volumes and the regular containers are left out:
// they are the owner's template, already assessed there.
func withEphemeralOnly(pod map[string]any) (map[string]any, bool) {
	eph := resource.Maps(pod, "spec", "ephemeralContainers")
	if len(eph) == 0 {
		return nil, false
	}
	spec := map[string]any{"containers": []any{}}
	list := make([]any, len(eph))
	for i, c := range eph {
		list[i] = c
	}
	spec["ephemeralContainers"] = list
	for _, k := range []string{"securityContext", "os", "hostUsers", "serviceAccountName", "automountServiceAccountToken"} {
		if v, ok := resource.Lookup(pod, "spec", k); ok {
			spec[k] = v
		}
	}
	out := map[string]any{}
	for k, v := range pod {
		out[k] = v
	}
	out["spec"] = spec
	return out, true
}

func ownedByCollectedController(item map[string]any) bool {
	for _, ref := range resource.Maps(item, "metadata", "ownerReferences") {
		if isController, _ := resource.Bool(ref, "controller"); isController && templateOwners[resource.String(ref, "kind")] {
			return true
		}
	}
	return false
}

// minimal keeps only the fields the analysis uses: node addresses, images
// and status are not needed and stay out of reports and memory.
func minimal(item map[string]any, r Resource) map[string]any {
	meta := map[string]any{"name": resource.String(item, "metadata", "name")}
	if labels := resource.Map(item, "metadata", "labels"); labels != nil {
		meta["labels"] = labels
	}
	spec := map[string]any{}
	if t, ok := resource.Lookup(item, "spec", "taints"); ok {
		spec["taints"] = t
	}
	if u, ok := resource.Lookup(item, "spec", "unschedulable"); ok {
		spec["unschedulable"] = u
	}
	return map[string]any{"apiVersion": r.APIVersion(), "kind": r.Kind, "metadata": meta, "spec": spec}
}
