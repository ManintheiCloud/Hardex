// Package owners removes duplicate findings on controller-owned objects
// without trusting ownerReferences blindly.
//
// A Deployment's ReplicaSets and Pods carry its pod template, so assessing
// all three would report every problem three times. Skipping owned objects
// is not safe, though: anyone who can create a Pod can give it an
// ownerReference to make it look owned, a ReplicaSet's template can be
// edited after the Deployment created it, and ephemeral containers
// (kubectl debug) exist only in the Pod. So every object is assessed, and a
// finding on an owned object is omitted only when its owner is verified
// (present, same kind, namespace, name and UID) and reports the same
// problem at the same place in the pod spec; or when the owned object is
// inert (a ReplicaSet scaled to zero, a finished Job, a terminated Pod).
// Anything else is reported.
package owners

import (
	"strings"

	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

// controllers are the kinds whose pod template their owned objects copy.
var controllers = map[string]bool{
	"Deployment": true, "ReplicaSet": true, "StatefulSet": true, "DaemonSet": true,
	"Job": true, "CronJob": true, "ReplicationController": true,
}

type key struct{ kind, ns, name string }

func keyOf(o *resource.Object) key { return key{o.Kind, o.EffectiveNamespace(), o.Name} }

// Deduplicate returns the findings to report and the number omitted.
func Deduplicate(inv *resource.Inventory, findings []finding.Finding) ([]finding.Finding, int) {
	objects := map[key]*resource.Object{}
	for _, o := range inv.Objects {
		objects[keyOf(o)] = o
	}
	// owner of each owned object, verified.
	owner := map[key]*resource.Object{}
	for _, o := range inv.Objects {
		if p := verifiedOwner(o, objects); p != nil {
			owner[keyOf(o)] = p
		}
	}
	if len(owner) == 0 {
		return findings, 0
	}
	// What each owner reports, comparable across template depths.
	reported := map[key]map[string]bool{}
	for _, f := range findings {
		k := key{f.Resource.Kind, f.Resource.Namespace, f.Resource.Name}
		o := objects[k]
		if o == nil {
			continue
		}
		if reported[k] == nil {
			reported[k] = map[string]bool{}
		}
		reported[k][signature(o, f)] = true
	}
	out := make([]finding.Finding, 0, len(findings))
	omitted := 0
	for _, f := range findings {
		k := key{f.Resource.Kind, f.Resource.Namespace, f.Resource.Name}
		o, p := objects[k], owner[k]
		if o != nil && p != nil && (inert(o) || reported[keyOf(p)][signature(o, f)]) {
			omitted++
			continue
		}
		out = append(out, f)
	}
	return out, omitted
}

// verifiedOwner returns o's controlling owner if it is a pod-template
// controller present in the inventory with the referenced UID.
func verifiedOwner(o *resource.Object, objects map[key]*resource.Object) *resource.Object {
	for _, ref := range resource.Maps(o.Raw, "metadata", "ownerReferences") {
		if c, _ := resource.Bool(ref, "controller"); !c {
			continue
		}
		kind := resource.String(ref, "kind")
		if !controllers[kind] {
			return nil
		}
		p := objects[key{kind, o.EffectiveNamespace(), resource.String(ref, "name")}]
		if p == nil {
			return nil
		}
		uid, puid := resource.String(ref, "uid"), resource.String(p.Raw, "metadata", "uid")
		if uid == "" || puid == "" || uid != puid {
			return nil
		}
		return p
	}
	return nil
}

// signature identifies a finding independently of the object it is on:
// rule, container, value and the field path relative to the pod spec.
func signature(o *resource.Object, f finding.Finding) string {
	_, prefix := resource.PodSpec(o)
	path := f.Path
	if prefix != "" && strings.HasPrefix(path, prefix) {
		path = "podspec" + strings.TrimPrefix(path, prefix)
	}
	return f.RuleID + "\x00" + f.Resource.Container + "\x00" + path + "\x00" + f.Observed
}

// inert reports owned objects that run nothing: findings on them describe
// history (a previous template), not the running workload.
func inert(o *resource.Object) bool {
	switch o.Kind {
	case "ReplicaSet", "ReplicationController":
		n, ok := resource.Lookup(o.Raw, "spec", "replicas")
		f, isNum := n.(float64)
		return ok && isNum && f == 0
	case "Job":
		if _, done := resource.Lookup(o.Raw, "status", "completionTime"); done {
			return true
		}
		for _, c := range resource.Maps(o.Raw, "status", "conditions") {
			if t := resource.String(c, "type"); (t == "Complete" || t == "Failed") && resource.String(c, "status") == "True" {
				return true
			}
		}
	case "Pod":
		switch resource.String(o.Raw, "status", "phase") {
		case "Succeeded", "Failed":
			return true
		}
	}
	return false
}
