package paths

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ManintheiCloud/Hardex/baselines"
	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/cloudiam"
	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

// placement is the set of node labels a pod is constrained to: label key →
// allowed values. A nil placement means the pod may run on any node.
type placement map[string]map[string]bool

// placementOf derives node constraints from nodeSelector, nodeName and a
// single required node-affinity term with "In" expressions. Several terms
// are ORed by the scheduler, so they are not treated as constraints; that
// errs towards assuming pods can share a node.
func placementOf(pod map[string]any) placement {
	p := placement{}
	add := func(k string, vals []string) {
		set := map[string]bool{}
		for _, v := range vals {
			if existing, ok := p[k]; !ok || existing[v] {
				set[v] = true
			}
		}
		p[k] = set
	}
	if name := resource.String(pod, "nodeName"); name != "" {
		add("kubernetes.io/hostname", []string{name})
	}
	sel := resource.Map(pod, "nodeSelector")
	keys := make([]string, 0, len(sel))
	for k := range sel {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		add(k, []string{fmt.Sprint(sel[k])})
	}
	terms := resource.Maps(pod, "affinity", "nodeAffinity", "requiredDuringSchedulingIgnoredDuringExecution", "nodeSelectorTerms")
	if len(terms) == 1 {
		for _, e := range resource.Maps(terms[0], "matchExpressions") {
			if resource.String(e, "operator") == "In" {
				add(resource.String(e, "key"), resource.Strings(e, "values"))
			}
		}
	}
	if len(p) == 0 {
		return nil
	}
	return p
}

// compatible reports whether two placements could select a common node: they
// are incompatible only if they constrain a shared label to disjoint values.
func (p placement) compatible(o placement) bool {
	for k, vals := range p {
		other, ok := o[k]
		if !ok {
			continue
		}
		shared := false
		for v := range vals {
			if other[v] {
				shared = true
				break
			}
		}
		if !shared {
			return false
		}
	}
	return true
}

func (p placement) key() string {
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vals := make([]string, 0, len(p[k]))
		for v := range p[k] {
			vals = append(vals, v)
		}
		sort.Strings(vals)
		parts = append(parts, k+"="+strings.Join(vals, "|"))
	}
	return strings.Join(parts, ",")
}

// cloudIdentity returns the cloud identity a ServiceAccount's tokens can
// assume, and whether it is Azure Workload Identity (which also needs a pod
// label to take effect).
func cloudIdentity(sa *resource.Object) (string, bool) {
	ann := resource.Map(sa.Raw, "metadata", "annotations")
	get := func(k string) string { v, _ := ann[k].(string); return strings.TrimSpace(v) }
	switch {
	case get("eks.amazonaws.com/role-arn") != "":
		return "AWS IAM role " + get("eks.amazonaws.com/role-arn"), false
	case get("iam.gke.io/gcp-service-account") != "":
		return "Google service account " + get("iam.gke.io/gcp-service-account"), false
	case get("azure.workload.identity/client-id") != "":
		return "Azure managed identity " + get("azure.workload.identity/client-id"), true
	}
	return "", false
}

// cloudKey returns the provider and raw identifier of a ServiceAccount's
// cloud identity, as cloudiam names them.
func cloudKey(sa *resource.Object) (string, string) {
	ann := resource.Map(sa.Raw, "metadata", "annotations")
	get := func(k string) string { v, _ := ann[k].(string); return strings.TrimSpace(v) }
	switch {
	case get("eks.amazonaws.com/role-arn") != "":
		return cloudiam.AWS, get("eks.amazonaws.com/role-arn")
	case get("iam.gke.io/gcp-service-account") != "":
		return cloudiam.GCP, get("iam.gke.io/gcp-service-account")
	case get("azure.workload.identity/client-id") != "":
		return cloudiam.Azure, get("azure.workload.identity/client-id")
	}
	return "", ""
}

// cloudPrivilege is what a --cloud-iam export says about an identity.
type cloudPrivilege struct {
	level   string
	reasons []string
}

func (p cloudPrivilege) powerful() bool {
	return p.level == cloudiam.Admin || p.level == cloudiam.Escalation
}

func (p cloudPrivilege) describe() string {
	what := "account administrator"
	if p.level == cloudiam.Escalation {
		what = "can grant itself administrator"
	}
	if len(p.reasons) > 0 {
		what += ": " + strings.Join(p.reasons, "; ")
	}
	return what
}

// cloudIndex maps "provider/identifier" (lower case, including aliases) to
// the privilege recorded by CloudIdentity objects in the inventory.
func cloudIndex(inv *resource.Inventory) map[string]cloudPrivilege {
	out := map[string]cloudPrivilege{}
	for _, o := range inv.OfKind(cloudiam.Kind) {
		if o.APIVersion != cloudiam.APIVersion {
			continue
		}
		p := cloudPrivilege{level: resource.String(o.Raw, "spec", "privilege"), reasons: resource.Strings(o.Raw, "spec", "reasons")}
		provider := resource.String(o.Raw, "spec", "provider")
		for _, id := range append([]string{resource.String(o.Raw, "spec", "id")}, resource.Strings(o.Raw, "spec", "aliases")...) {
			if id != "" {
				out[provider+"/"+strings.ToLower(id)] = p
			}
		}
	}
	return out
}

// podLabel returns a label of the pod (or pod template) of a workload.
func podLabel(o *resource.Object, key string) string {
	_, prefix := resource.PodSpec(o)
	path := strings.Split(prefix, ".")
	if len(path) == 0 || path[0] == "" {
		return ""
	}
	meta := append(append([]string{}, path[:len(path)-1]...), "metadata", "labels", key)
	if o.Kind == "Pod" {
		meta = []string{"metadata", "labels", key}
	}
	return resource.String(o.Raw, meta...)
}

var cloudIdentities = assessment.InventoryRule{
	Meta: assessment.Metadata{
		ID:             "HX-PATH-002",
		Title:          "Workload token grants a cloud identity",
		Severity:       finding.Low,
		Category:       "attack-paths",
		Description:    "Reports workloads whose mounted service-account token is federated to a cloud identity through EKS IRSA (eks.amazonaws.com/role-arn), GKE Workload Identity (iam.gke.io/gcp-service-account) or Azure Workload Identity (azure.workload.identity/client-id plus the azure.workload.identity/use pod label). With IAM exports (--cloud-iam), identities that administer the cloud account are critical and identities that can grant themselves administrator are high.",
		Rationale:      "Workload identity is the right way to give pods cloud access, but it extends the pod's blast radius into the cloud account. An inventory of which workloads hold which role is what reviewers need to keep those roles least-privilege; HX-PATH-001 reports chains through these identities from other workloads.",
		Remediation:    "Confirm the workload needs the identity, scope the cloud role to the resources it uses, and keep tokens off pods that do not need cloud access (a separate service account, or automountServiceAccountToken: false).",
		References:     []finding.Reference{baselines.NSA("Protecting sensitive cloud infrastructure")},
		Limitations:    "Without --cloud-iam exports the cloud role's permissions are not evaluated. With them, unconditional grants are classified (AWS policy statements on all resources, GCP project bindings, Azure assignments at subscription or management-group scope); conditions, permission boundaries, SCPs, deny policies and resource policies are not evaluated, so treat 'limited' as unverified rather than safe. EKS Pod Identity associations are configured in AWS, not Kubernetes, and are not visible.",
		NeedsInventory: true,
	},
	Check: func(ctx *assessment.Context) {
		g := build(ctx.Inventory)
		for _, w := range g.workloads {
			if !w.token || (w.ns == "kube-system" && !ctx.Options.IncludeSystem) {
				continue
			}
			key := "sa:" + w.ns + "/" + w.sa
			id := g.cloud[key]
			if id == "" {
				continue
			}
			if sa := saObject(ctx.Inventory, w.ns, w.sa); sa != nil {
				if _, azure := cloudIdentity(sa); azure && podLabel(w.obj, "azure.workload.identity/use") != "true" {
					continue
				}
			}
			msg := fmt.Sprintf("the mounted token of service account %s/%s assumes %s", w.ns, w.sa, id)
			var sev *finding.Severity
			if p, ok := g.cloudPriv[key]; ok && p.powerful() {
				s := finding.High
				if p.level == cloudiam.Admin {
					s = finding.Critical
				}
				sev = &s
				msg += " — " + p.describe()
			}
			ctx.Report(assessment.Hit{Object: w.obj, Path: "spec", Observed: id, Severity: sev, Message: msg})
		}
	},
}

func saObject(inv *resource.Inventory, ns, name string) *resource.Object {
	for _, o := range inv.OfKind("ServiceAccount") {
		if o.Name == name && o.EffectiveNamespace() == ns {
			return o
		}
	}
	return nil
}
