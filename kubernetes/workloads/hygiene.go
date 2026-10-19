package workloads

import (
	"fmt"
	"strings"

	"github.com/ManintheiCloud/Hardex/baselines"
	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

var resourceLimits = eachContainer(assessment.Metadata{
	ID:             "HX-WL-010",
	Title:          "Missing resource limits",
	Severity:       finding.Low,
	Category:       assessment.CategoryWorkloads,
	Description:    "Detects containers without a memory limit (low) or CPU limit (info), unless a LimitRange in the same namespace supplies a default.",
	Rationale:      "Unbounded containers let one compromised or faulty workload exhaust node resources and deny service to its neighbours, including node-critical agents.",
	Remediation:    "Set resources.limits.memory on every container (and resources.requests.cpu, plus a CPU limit where your scheduling policy calls for one), or define a namespace LimitRange with defaults.",
	References:     []finding.Reference{baselines.NSA("Kubernetes Pod security — resource policies")},
	Limitations:    "CPU limits are reported at info severity because they can cause throttling; many operators deliberately rely on CPU requests only.",
	NeedsInventory: true,
}, func(ctx *assessment.Context, obj *resource.Object, _ map[string]any, prefix string, c resource.Container) {
	if c.Field == "ephemeralContainers" {
		return // ephemeral containers cannot declare resources
	}
	defaults := limitRangeDefaults(ctx.Inventory, obj.EffectiveNamespace())
	limits := resource.Map(c.Spec, "resources", "limits")
	if _, ok := limits["memory"]; !ok && !defaults["memory"] {
		ctx.Report(assessment.Hit{Object: obj, Container: c.Name, Path: c.Path(prefix) + ".resources.limits.memory", Observed: "<unset>",
			Message: fmt.Sprintf("container %q has no memory limit", c.Name)})
	}
	if _, ok := limits["cpu"]; !ok && !defaults["cpu"] {
		ctx.Report(assessment.Hit{Object: obj, Container: c.Name, Path: c.Path(prefix) + ".resources.limits.cpu", Observed: "<unset>", Severity: sevInfo,
			Message: fmt.Sprintf("container %q has no CPU limit", c.Name)})
	}
})

// limitRangeDefaults returns which resources have a default container limit
// in the namespace's LimitRanges.
func limitRangeDefaults(inv *resource.Inventory, ns string) map[string]bool {
	out := map[string]bool{}
	for _, lr := range inv.OfKind("LimitRange") {
		if lr.EffectiveNamespace() != ns {
			continue
		}
		for _, l := range resource.Maps(lr.Raw, "spec", "limits") {
			if resource.String(l, "type") != "Container" {
				continue
			}
			for k := range resource.Map(l, "default") {
				out[k] = true
			}
		}
	}
	return out
}

// imageRef splits an image reference into tag and digest.
func imageRef(image string) (tag, digest string) {
	if i := strings.Index(image, "@"); i >= 0 {
		digest = image[i+1:]
		image = image[:i]
	}
	last := image
	if i := strings.LastIndex(image, "/"); i >= 0 {
		last = image[i+1:]
	}
	if i := strings.LastIndex(last, ":"); i >= 0 {
		tag = last[i+1:]
	}
	return tag, digest
}

var mutableImageTag = eachContainer(assessment.Metadata{
	ID:          "HX-WL-011",
	Title:       "Mutable image tag",
	Severity:    finding.Medium,
	Category:    assessment.CategorySupplyChain,
	Description: "Detects containers whose image has no tag or uses the latest tag, and is not pinned by digest.",
	Rationale:   "An untagged or latest image can change between deployments without any manifest change, so what runs is neither reviewed nor reproducible, and a compromised registry push is picked up silently.",
	Remediation: "Reference images by an immutable version tag and, preferably, a digest (image@sha256:...).",
	References:  []finding.Reference{baselines.NSA("Kubernetes Pod security — image scanning and integrity"), baselines.K8s("Images: image names", "https://kubernetes.io/docs/concepts/containers/images/")},
}, func(ctx *assessment.Context, obj *resource.Object, _ map[string]any, prefix string, c resource.Container) {
	image := resource.String(c.Spec, "image")
	tag, digest := imageRef(image)
	if digest != "" || (tag != "" && tag != "latest") {
		return
	}
	ctx.Report(assessment.Hit{Object: obj, Container: c.Name, Path: c.Path(prefix) + ".image", Observed: image,
		Message: fmt.Sprintf("container %q uses a mutable image reference", c.Name)})
})

var imageDigest = eachContainer(assessment.Metadata{
	ID:          "HX-WL-012",
	Title:       "Image not pinned by digest",
	Severity:    finding.Info,
	Category:    assessment.CategorySupplyChain,
	Description: "Detects versioned image references that are not pinned by digest.",
	Rationale:   "Version tags can be overwritten in most registries. Only a digest guarantees that the reviewed image is the one that runs.",
	Remediation: "Pin the image by digest (e.g. registry/app:1.4.2@sha256:...), ideally maintained by an automated dependency updater.",
	References:  []finding.Reference{baselines.NSA("Kubernetes Pod security — image scanning and integrity")},
}, func(ctx *assessment.Context, obj *resource.Object, _ map[string]any, prefix string, c resource.Container) {
	image := resource.String(c.Spec, "image")
	tag, digest := imageRef(image)
	if digest != "" || tag == "" || tag == "latest" {
		return // pinned, or already reported by HX-WL-011
	}
	ctx.Report(assessment.Hit{Object: obj, Container: c.Name, Path: c.Path(prefix) + ".image", Observed: image,
		Message: fmt.Sprintf("container %q image is not pinned by digest", c.Name)})
})

var serviceAccountToken = eachPod(assessment.Metadata{
	ID:             "HX-WL-013",
	Title:          "Service account token auto-mounted",
	Severity:       finding.Low,
	Category:       assessment.CategoryWorkloads,
	Description:    "Detects pods that mount a Kubernetes API token without opting out, neither in the pod spec nor on a ServiceAccount found in the input.",
	Rationale:      "Most applications never call the Kubernetes API, yet every compromised container with a mounted token can. The token's RBAC permissions become the attacker's.",
	Remediation:    "Set automountServiceAccountToken: false on the pod spec or its ServiceAccount; enable it only for workloads that call the API, with a dedicated least-privilege ServiceAccount.",
	References:     []finding.Reference{baselines.NSA("Authentication and authorization"), baselines.CIS("5.1", "RBAC and Service Accounts")},
	Limitations:    "If the ServiceAccount is not part of the scanned input, its automount setting cannot be checked and the pod is reported.",
	NeedsInventory: true,
}, func(ctx *assessment.Context, obj *resource.Object, pod map[string]any, prefix string) {
	if v, set := resource.Bool(pod, "automountServiceAccountToken"); set {
		if v {
			ctx.Report(assessment.Hit{Object: obj, Path: prefix + ".automountServiceAccountToken", Observed: "true",
				Message: "pod explicitly mounts a service account token"})
		}
		return
	}
	sa := resource.String(pod, "serviceAccountName")
	if sa == "" {
		sa = "default"
	}
	for _, o := range ctx.Inventory.OfKind("ServiceAccount") {
		if o.Name == sa && o.EffectiveNamespace() == obj.EffectiveNamespace() {
			if v, set := resource.Bool(o.Raw, "automountServiceAccountToken"); set && !v {
				return
			}
		}
	}
	ctx.Report(assessment.Hit{Object: obj, Path: prefix + ".automountServiceAccountToken", Observed: "<unset>",
		Message: fmt.Sprintf("pod mounts the token of service account %q by default", sa)})
})
