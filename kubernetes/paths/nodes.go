package paths

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ManintheiCloud/Hardex/core/resource"
)

// nodeKey is the placement key holding the exact set of nodes a pod can be
// scheduled on, used when Node objects are part of the inventory. Two pods
// can then share a node only if their node sets intersect.
const nodeKey = "\x00nodes"

// eligibleNodes returns the placement of a pod across known nodes: the
// nodes whose labels satisfy its nodeName, nodeSelector and required node
// affinity, and whose NoSchedule/NoExecute taints it tolerates.
//
// Condition taints (node.kubernetes.io/*: not-ready, unreachable, pressure,
// unschedulable) are transient or tolerated automatically by DaemonSets, and
// are ignored; placement taints such as node-role.kubernetes.io/control-plane
// and dedicated node pools are what separate workloads.
func eligibleNodes(pod map[string]any, nodes []*resource.Object) placement {
	set := map[string]bool{}
	for _, n := range nodes {
		if schedulable(pod, n) {
			set[n.Name] = true
		}
	}
	return placement{nodeKey: set}
}

func schedulable(pod map[string]any, n *resource.Object) bool {
	if name := resource.String(pod, "nodeName"); name != "" && name != n.Name {
		return false
	}
	labels := resource.Map(n.Raw, "metadata", "labels")
	label := func(k string) (string, bool) {
		v, ok := labels[k]
		if !ok {
			return "", false
		}
		return fmt.Sprint(v), true
	}
	for k, want := range resource.Map(pod, "nodeSelector") {
		if v, ok := label(k); !ok || v != fmt.Sprint(want) {
			return false
		}
	}
	if terms := resource.Maps(pod, "affinity", "nodeAffinity", "requiredDuringSchedulingIgnoredDuringExecution", "nodeSelectorTerms"); len(terms) > 0 {
		any := false
		for _, t := range terms { // terms are ORed
			if termMatches(t, label, n.Name) {
				any = true
				break
			}
		}
		if !any {
			return false
		}
	}
	tolerations := resource.Maps(pod, "tolerations")
	for _, taint := range resource.Maps(n.Raw, "spec", "taints") {
		effect := resource.String(taint, "effect")
		key := resource.String(taint, "key")
		if effect == "PreferNoSchedule" || strings.HasPrefix(key, "node.kubernetes.io/") {
			continue
		}
		if !tolerated(taint, tolerations) {
			return false
		}
	}
	return true
}

func termMatches(term map[string]any, label func(string) (string, bool), nodeName string) bool {
	exprs := resource.Maps(term, "matchExpressions")
	fields := resource.Maps(term, "matchFields")
	if len(exprs) == 0 && len(fields) == 0 {
		return false // an empty term matches no objects
	}
	for _, e := range exprs {
		v, ok := label(resource.String(e, "key"))
		if !requirement(resource.String(e, "operator"), v, ok, resource.Strings(e, "values")) {
			return false
		}
	}
	for _, f := range fields {
		if resource.String(f, "key") != "metadata.name" {
			return false
		}
		if !requirement(resource.String(f, "operator"), nodeName, true, resource.Strings(f, "values")) {
			return false
		}
	}
	return true
}

func requirement(op, v string, present bool, values []string) bool {
	in := false
	for _, x := range values {
		if x == v {
			in = true
		}
	}
	switch op {
	case "In":
		return present && in
	case "NotIn":
		return !present || !in
	case "Exists":
		return present
	case "DoesNotExist":
		return !present
	case "Gt", "Lt":
		if !present || len(values) != 1 {
			return false
		}
		a, err1 := strconv.ParseInt(v, 10, 64)
		b, err2 := strconv.ParseInt(values[0], 10, 64)
		if err1 != nil || err2 != nil {
			return false
		}
		if op == "Gt" {
			return a > b
		}
		return a < b
	}
	return false
}

func tolerated(taint map[string]any, tolerations []map[string]any) bool {
	key, value, effect := resource.String(taint, "key"), resource.String(taint, "value"), resource.String(taint, "effect")
	for _, t := range tolerations {
		if e := resource.String(t, "effect"); e != "" && e != effect {
			continue
		}
		tk := resource.String(t, "key")
		switch resource.String(t, "operator") {
		case "Exists":
			if tk == "" || tk == key {
				return true
			}
		case "", "Equal":
			if tk == key && resource.String(t, "value") == value {
				return true
			}
		}
	}
	return false
}
