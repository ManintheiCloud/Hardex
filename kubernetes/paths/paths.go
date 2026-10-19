// Package paths finds multi-step privilege-escalation paths: chains of
// individually "moderate" weaknesses that together lead from one compromised
// workload to cluster administrator, a cloud identity, or root on a node.
//
// The analysis is a breadth-first search over principals (service accounts),
// nodes and goals, with edges for:
//
//   - container escape (privileged, hostPID, sensitive hostPath, critical
//     capabilities, HostProcess) → root on the nodes the pod can run on;
//   - root on a node → the token of every pod that mounts one and could be
//     scheduled on the same node (computed from Node labels and taints when
//     available, else from placement constraints that make two pods' node
//     sets provably disjoint);
//   - creating workloads → any service account in scope, and root on any
//     node where Pod Security admission does not enforce baseline or
//     restricted;
//   - exec/attach → the service accounts of pods in scope, and node root if
//     any of those pods can escape;
//   - minting tokens → any service account in scope;
//   - nodes/proxy → root-equivalent access to any node's pods;
//   - full control, escalate/bind, impersonate → cluster administrator;
//   - a token bound to a cloud workload identity (EKS IRSA, GKE Workload
//     Identity, Azure Workload Identity) → that cloud identity.
package paths

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ManintheiCloud/Hardex/baselines"
	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/resource"
	"github.com/ManintheiCloud/Hardex/kubernetes/rbac"
	"github.com/ManintheiCloud/Hardex/kubernetes/workloads"
)

// Rules returns the attack-path rules.
func Rules() []assessment.Rule { return []assessment.Rule{escalationPaths, cloudIdentities} }

// Goal states. Node states are "node:<placement>"; every node state also
// leads to the goal nodeGoal.
const (
	adminState = "goal:cluster-admin"
	cloudGoal  = "goal:cloud"
	nodeGoal   = "goal:node"
	anyNode    = "node:*"
)

type workload struct {
	obj       *resource.Object
	ns, sa    string
	token     bool
	escape    string
	canEsc    bool
	placement placement
}

type edge struct {
	to   string
	step string // empty for internal bookkeeping edges, which are not shown
}

type tokenHolder struct {
	state     string // "sa:ns/name"
	placement placement
}

type graph struct {
	idx       *rbac.Index
	workloads []workload
	// tokens are service accounts whose tokens some pod mounts, with the
	// placement of a pod that mounts them.
	tokens     []tokenHolder
	tokensByNS map[string][]string
	saByNS     map[string][]string
	escapeIn   map[string]workload // first escapable workload per namespace
	enforced   map[string]bool
	allNS      []string
	// cloud maps "sa:ns/name" to the cloud identity its token assumes.
	cloud      map[string]string
	placements map[string]placement // node state -> placement
	edges      map[string][]edge
}

func build(inv *resource.Inventory) *graph {
	nodes := inv.OfKind("Node")
	g := &graph{idx: rbac.NewIndex(inv), tokensByNS: map[string][]string{}, saByNS: map[string][]string{},
		escapeIn: map[string]workload{}, enforced: map[string]bool{}, cloud: map[string]string{},
		placements: map[string]placement{anyNode: nil}, edges: map[string][]edge{}}
	saSeen := map[string]bool{}
	addSA := func(ns, sa string) {
		if !saSeen[ns+"/"+sa] {
			saSeen[ns+"/"+sa] = true
			g.saByNS[ns] = append(g.saByNS[ns], sa)
		}
	}
	nsSeen := map[string]bool{}
	saCloud := map[string]string{}
	azureSA := map[string]bool{}
	for _, o := range inv.OfKind("ServiceAccount") {
		addSA(o.EffectiveNamespace(), o.Name)
		if id, azure := cloudIdentity(o); id != "" {
			saCloud[o.EffectiveNamespace()+"/"+o.Name] = id
			azureSA[o.EffectiveNamespace()+"/"+o.Name] = azure
		}
	}
	for _, o := range inv.OfKind("Namespace") {
		nsSeen[o.Name] = true
		level := resource.String(o.Raw, "metadata", "labels", "pod-security.kubernetes.io/enforce")
		g.enforced[o.Name] = level == "baseline" || level == "restricted"
	}
	tokenSeen := map[string]bool{}
	for _, o := range inv.Objects {
		pod, _ := resource.PodSpec(o)
		if pod == nil {
			continue
		}
		w := workload{obj: o, ns: o.EffectiveNamespace(), sa: rbac.ServiceAccountOf(pod), token: g.idx.TokenMounted(o, pod),
			placement: placementOf(pod)}
		if len(nodes) > 0 {
			w.placement = eligibleNodes(pod, nodes)
		}
		w.escape, w.canEsc = workloads.EscapeVector(pod)
		nsSeen[w.ns] = true
		addSA(w.ns, w.sa)
		key := w.ns + "/" + w.sa
		if id := saCloud[key]; id != "" {
			// Azure injects the federated token only into labelled pods.
			if !azureSA[key] || podLabel(o, "azure.workload.identity/use") == "true" {
				g.cloud["sa:"+key] = id
			}
		}
		if w.token {
			g.tokens = append(g.tokens, tokenHolder{state: "sa:" + key, placement: w.placement})
			if !tokenSeen[key] {
				tokenSeen[key] = true
				g.tokensByNS[w.ns] = append(g.tokensByNS[w.ns], w.sa)
			}
		}
		if w.canEsc {
			if _, ok := g.escapeIn[w.ns]; !ok {
				g.escapeIn[w.ns] = w
			}
			g.placements[nodeStateFor(w.placement)] = w.placement
		}
		g.workloads = append(g.workloads, w)
	}
	for ns := range nsSeen {
		g.allNS = append(g.allNS, ns)
	}
	sort.Strings(g.allNS)
	return g
}

func nodeStateFor(p placement) string {
	if len(p) == 0 {
		return anyNode
	}
	return "node:" + p.key()
}

// nodeEdges: root on a node in a placement group exposes the tokens of
// every pod that could run on the same node.
func (g *graph) nodeEdges(state string) []edge {
	p := g.placements[state]
	out := []edge{{to: nodeGoal}}
	seen := map[string]bool{}
	for _, t := range g.tokens {
		if seen[t.state] || !p.compatible(t.placement) {
			continue
		}
		seen[t.state] = true
		out = append(out, edge{to: t.state, step: "steals the token of service account " + strings.TrimPrefix(t.state, "sa:") + " from a pod that can run on the same node"})
	}
	return out
}

// saEdges computes the outgoing edges of a service account.
func (g *graph) saEdges(state string) []edge {
	ns, sa, _ := strings.Cut(strings.TrimPrefix(state, "sa:"), "/")
	var out []edge
	if id := g.cloud[state]; id != "" {
		out = append(out, edge{to: cloudGoal, step: "assumes " + id + " through the token's workload identity"})
	}
	inScope := func(p rbac.Permission) []string {
		if p.Namespace != "" {
			return []string{p.Namespace}
		}
		return g.allNS
	}
	for _, p := range g.idx.Permissions(ns, sa) {
		via := fmt.Sprintf("(%s, via %s)", p.Scope(), p.Via)
		switch p.Cap {
		case rbac.CapFullControl, rbac.CapEscalate, rbac.CapImpersonate:
			out = append(out, edge{to: adminState, step: fmt.Sprintf("obtains %s %s", p.Cap.Name(), via)})
		case rbac.CapNodeProxy:
			out = append(out, edge{to: anyNode, step: "reaches the kubelet API through nodes/proxy and executes in any pod " + via})
		case rbac.CapCreateWorkloads:
			for _, target := range inScope(p) {
				if !g.enforced[target] {
					out = append(out, edge{to: anyNode, step: fmt.Sprintf("creates a privileged pod, scheduled on any node, in namespace %s, which does not enforce Pod Security %s", target, via)})
					break
				}
			}
			for _, target := range inScope(p) {
				for _, other := range g.saByNS[target] {
					out = append(out, edge{to: "sa:" + target + "/" + other, step: fmt.Sprintf("creates a pod running as service account %s/%s %s", target, other, via)})
				}
			}
		case rbac.CapExec:
			for _, target := range inScope(p) {
				if w, ok := g.escapeIn[target]; ok {
					out = append(out, edge{to: nodeStateFor(w.placement), step: fmt.Sprintf("execs into %s %s/%s, which %s %s", w.obj.Kind, w.ns, w.obj.Name, w.escape, via)})
				}
				for _, other := range g.tokensByNS[target] {
					out = append(out, edge{to: "sa:" + target + "/" + other, step: fmt.Sprintf("execs into a pod of service account %s/%s and takes its token %s", target, other, via)})
				}
			}
		case rbac.CapMintTokens:
			for _, target := range inScope(p) {
				for _, other := range g.saByNS[target] {
					out = append(out, edge{to: "sa:" + target + "/" + other, step: fmt.Sprintf("mints a token for service account %s/%s %s", target, other, via)})
				}
			}
		}
	}
	return out
}

func (g *graph) next(state string) []edge {
	if e, ok := g.edges[state]; ok {
		return e
	}
	var out []edge
	switch {
	case strings.HasPrefix(state, "node:"):
		out = g.nodeEdges(state)
	case strings.HasPrefix(state, "sa:"):
		out = g.saEdges(state)
	}
	g.edges[state] = out
	return out
}

// hop is the next step from a state towards a goal.
type hop struct {
	to   string
	step string
}

// distances runs one breadth-first search backwards from goal over every
// state, so each workload's shortest path is a lookup instead of a search:
// the whole analysis stays linear in the size of the graph.
func (g *graph) distances(goal string) map[string]hop {
	var states []string
	for st := range g.placements {
		states = append(states, st)
	}
	sort.Strings(states)
	seen := map[string]bool{}
	for _, st := range states {
		seen[st] = true
	}
	for _, ns := range g.allNS {
		for _, sa := range g.saByNS[ns] {
			if st := "sa:" + ns + "/" + sa; !seen[st] {
				seen[st] = true
				states = append(states, st)
			}
		}
	}
	type rev struct{ from, step string }
	reverse := map[string][]rev{}
	for _, st := range states {
		for _, e := range g.next(st) {
			reverse[e.to] = append(reverse[e.to], rev{from: st, step: e.step})
		}
	}
	next := map[string]hop{goal: {}}
	queue := []string{goal}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, r := range reverse[cur] {
			if _, done := next[r.from]; done || strings.HasPrefix(r.from, "goal:") {
				continue
			}
			next[r.from] = hop{to: cur, step: r.step}
			queue = append(queue, r.from)
		}
	}
	return next
}

// shortest returns the visible steps of the shortest path from the start
// edges to goal, using precomputed distances.
func shortest(start []edge, goal string, next map[string]hop) []string {
	var best []string
	bestLen := -1
	for _, e := range start {
		if _, ok := next[e.to]; !ok {
			continue
		}
		steps := []string{e.step}
		hops := 1
		for st := e.to; st != goal; st = next[st].to {
			hops++
			if s := next[st].step; s != "" {
				steps = append(steps, s)
			}
		}
		if bestLen < 0 || hops < bestLen {
			best, bestLen = steps, hops
		}
	}
	return best
}

var escalationPaths = assessment.InventoryRule{
	Meta: assessment.Metadata{
		ID:             "HX-PATH-001",
		Title:          "Privilege-escalation path from workload",
		Severity:       finding.Critical,
		Category:       "attack-paths",
		Description:    "Searches for multi-step paths from each workload to cluster administrator (critical), to a cloud workload identity (high) or, failing those, to root on a node (high), combining container escape, token theft from pods that can share a node, workload creation, exec, token minting, RBAC escalation and cloud workload identities. Direct grants are reported by HX-RBAC-008 and HX-PATH-002, direct escapes by the HX-WL rules; this rule reports chains.",
		Rationale:      "Real attacks chain weaknesses: an exploited web pod that can escape to its node can steal the token of a privileged controller scheduled on the same node. Each step alone may look acceptable; the chain is a full compromise — of the cluster, or of the cloud account behind it.",
		Remediation:    "Break the chain at its cheapest link, listed in the finding: remove the escape vector, keep powerful tokens off shared node pools (node selectors or dedicated pools), stop mounting tokens in pods that do not need them, narrow the RBAC grant or cloud role, or enforce Pod Security admission in the namespace.",
		References:     []finding.Reference{baselines.NSA("Threat model"), baselines.K8s("RBAC good practices: privilege escalation risks", "https://kubernetes.io/docs/concepts/security/rbac-good-practices/#privilege-escalation-risks")},
		Limitations:    "When Node objects are available (live scans collect them), pods are placed on exactly the nodes their nodeName, nodeSelector, required node affinity and tolerations allow; otherwise pods may share a node unless their nodeSelector or a single required node-affinity term makes their node sets provably disjoint. Preferred affinity, pod (anti-)affinity and topology spread are not modelled. Namespaces without a Namespace object in the input are assumed not to enforce Pod Security. Cloud identities are recognised from ServiceAccount annotations (EKS IRSA, GKE Workload Identity, Azure Workload Identity); EKS Pod Identity associations live outside Kubernetes and are not visible. Workloads in kube-system are not reported as starting points unless --include-system is set, but their tokens are considered.",
		NeedsInventory: true,
	},
	Check: func(ctx *assessment.Context) {
		g := build(ctx.Inventory)
		toAdmin, toCloud, toNode := g.distances(adminState), g.distances(cloudGoal), g.distances(nodeGoal)
		for _, w := range g.workloads {
			if w.ns == "kube-system" && !ctx.Options.IncludeSystem {
				continue
			}
			own := "sa:" + w.ns + "/" + w.sa
			var start []edge
			if w.canEsc {
				start = append(start, edge{to: nodeStateFor(w.placement), step: "escapes to its node (" + w.escape + ")"})
			}
			ownToken := w.token && !directTo(g, own, adminState)
			if ownToken {
				start = append(start, edge{to: own, step: fmt.Sprintf("uses its mounted token (service account %s/%s)", w.ns, w.sa)})
			}
			if len(start) == 0 || (w.token && directTo(g, own, adminState)) {
				continue // direct grants are HX-RBAC-008's finding, not a path
			}
			report := func(sev finding.Severity, goal string, steps []string) {
				ctx.Report(assessment.Hit{Object: w.obj, Path: "spec", Observed: fmt.Sprintf("%d steps", len(steps)), Severity: &sev,
					Message: fmt.Sprintf("compromise of this workload leads to %s: %s", goal, strings.Join(steps, " → "))})
			}
			if steps := shortest(start, adminState, toAdmin); len(steps) >= 2 {
				report(finding.Critical, "cluster administrator", steps)
				continue
			}
			// A workload's own cloud identity is HX-PATH-002's finding.
			if steps := shortest(start, cloudGoal, toCloud); len(steps) >= 2 && !(w.token && g.cloud[own] != "" && len(steps) == 2) {
				report(finding.High, "a cloud identity", steps)
				continue
			}
			if w.canEsc {
				continue // reaching the node directly is reported by the HX-WL rules
			}
			if steps := shortest(start, nodeGoal, toNode); len(steps) >= 2 {
				report(finding.High, "root on a node", steps)
			}
		}
	},
}

func directTo(g *graph, state, goal string) bool {
	for _, e := range g.next(state) {
		if e.to == goal {
			return true
		}
	}
	return false
}
