// Package paths finds multi-step privilege-escalation paths: chains of
// individually "moderate" weaknesses that together lead from one compromised
// workload to node root or cluster administrator.
//
// The analysis is a breadth-first search over principals (service accounts)
// and the node, with edges for:
//
//   - container escape (privileged, hostPID, sensitive hostPath, critical
//     capabilities, HostProcess) → node root;
//   - node root → the token of every pod that mounts one, in any namespace
//     (the scheduler may co-locate any two pods);
//   - creating workloads → any service account in scope, and node root where
//     Pod Security admission does not enforce baseline or restricted;
//   - exec/attach → the service accounts of pods in scope, and node root if
//     any of those pods can escape;
//   - minting tokens → any service account in scope;
//   - nodes/proxy → node root (kubelet API: exec into any pod);
//   - full control, escalate/bind, impersonate → cluster administrator.
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
func Rules() []assessment.Rule { return []assessment.Rule{escalationPaths} }

const (
	nodeState  = "node"
	adminState = "cluster-admin"
)

type workload struct {
	obj      *resource.Object
	ns, sa   string
	token    bool
	escape   string
	canEsc   bool
	saPrefix string
}

type edge struct {
	to   string
	step string
}

type graph struct {
	idx       *rbac.Index
	workloads []workload
	// tokensByNS lists service accounts whose tokens are mounted by some pod,
	// per namespace.
	tokensByNS map[string][]string
	allTokens  []string
	// saByNS lists every service account known per namespace (objects and
	// references), for "create a pod as any service account".
	saByNS map[string][]string
	// escapable namespaces: a pod that can escape exists there.
	escapeIn map[string]string
	// enforced namespaces: Pod Security admission enforces baseline or
	// restricted, so new privileged pods are rejected.
	enforced map[string]bool
	allNS    []string
	edges    map[string][]edge
}

func build(inv *resource.Inventory) *graph {
	g := &graph{idx: rbac.NewIndex(inv), tokensByNS: map[string][]string{}, saByNS: map[string][]string{},
		escapeIn: map[string]string{}, enforced: map[string]bool{}, edges: map[string][]edge{}}
	saSeen := map[string]bool{}
	addSA := func(ns, sa string) {
		if !saSeen[ns+"/"+sa] {
			saSeen[ns+"/"+sa] = true
			g.saByNS[ns] = append(g.saByNS[ns], sa)
		}
	}
	tokenSeen := map[string]bool{}
	nsSeen := map[string]bool{}
	for _, o := range inv.OfKind("ServiceAccount") {
		addSA(o.EffectiveNamespace(), o.Name)
	}
	for _, o := range inv.OfKind("Namespace") {
		nsSeen[o.Name] = true
		level := resource.String(o.Raw, "metadata", "labels", "pod-security.kubernetes.io/enforce")
		g.enforced[o.Name] = level == "baseline" || level == "restricted"
	}
	for _, o := range inv.Objects {
		pod, _ := resource.PodSpec(o)
		if pod == nil {
			continue
		}
		w := workload{obj: o, ns: o.EffectiveNamespace(), sa: rbac.ServiceAccountOf(pod), token: g.idx.TokenMounted(o, pod)}
		w.escape, w.canEsc = workloads.EscapeVector(pod)
		nsSeen[w.ns] = true
		addSA(w.ns, w.sa)
		if w.token && !tokenSeen[w.ns+"/"+w.sa] {
			tokenSeen[w.ns+"/"+w.sa] = true
			g.tokensByNS[w.ns] = append(g.tokensByNS[w.ns], w.sa)
			g.allTokens = append(g.allTokens, w.ns+"/"+w.sa)
		}
		if w.canEsc {
			if _, ok := g.escapeIn[w.ns]; !ok {
				g.escapeIn[w.ns] = fmt.Sprintf("%s %s/%s, which %s", o.Kind, w.ns, o.Name, w.escape)
			}
		}
		g.workloads = append(g.workloads, w)
	}
	for ns := range nsSeen {
		g.allNS = append(g.allNS, ns)
	}
	sort.Strings(g.allNS)
	sort.Strings(g.allTokens)
	for _, t := range g.allTokens {
		g.edges[nodeState] = append(g.edges[nodeState], edge{to: "sa:" + t, step: "steals the token of service account " + t + " from a pod on the node"})
	}
	return g
}

// saEdges computes (and caches) the outgoing edges of a service account.
func (g *graph) saEdges(state string) []edge {
	if e, ok := g.edges[state]; ok {
		return e
	}
	ns, sa, _ := strings.Cut(strings.TrimPrefix(state, "sa:"), "/")
	var out []edge
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
			out = append(out, edge{to: nodeState, step: "reaches the kubelet API through nodes/proxy and executes in any pod " + via})
		case rbac.CapCreateWorkloads:
			for _, target := range inScope(p) {
				if !g.enforced[target] {
					out = append(out, edge{to: nodeState, step: fmt.Sprintf("creates a privileged pod in namespace %s, which does not enforce Pod Security %s", target, via)})
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
				if desc, ok := g.escapeIn[target]; ok {
					out = append(out, edge{to: nodeState, step: fmt.Sprintf("execs into %s %s", desc, via)})
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
	g.edges[state] = out
	return out
}

func (g *graph) next(state string) []edge {
	if state == nodeState {
		return g.edges[nodeState]
	}
	return g.saEdges(state)
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
	states := []string{nodeState}
	seen := map[string]bool{nodeState: true}
	for _, ns := range g.allNS {
		for _, sa := range g.saByNS[ns] {
			if st := "sa:" + ns + "/" + sa; !seen[st] {
				seen[st] = true
				states = append(states, st)
			}
		}
	}
	type rev struct {
		from string
		step string
	}
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
			if _, done := next[r.from]; done || r.from == adminState {
				continue
			}
			next[r.from] = hop{to: cur, step: r.step}
			queue = append(queue, r.from)
		}
	}
	return next
}

// shortest returns the steps of the shortest path from the start edges to
// goal, using precomputed distances.
func shortest(start []edge, goal string, next map[string]hop) []string {
	var best []string
	for _, e := range start {
		if _, ok := next[e.to]; !ok {
			continue
		}
		steps := []string{e.step}
		for st := e.to; st != goal; st = next[st].to {
			steps = append(steps, next[st].step)
		}
		if best == nil || len(steps) < len(best) {
			best = steps
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
		Description:    "Searches for multi-step paths from each workload to cluster administrator (critical) or, failing that, to root on a node (high), combining container escape, token theft from co-located pods, workload creation, exec, token minting and RBAC escalation. Direct grants are reported by HX-RBAC-008 and direct escapes by the HX-WL rules; this rule reports chains.",
		Rationale:      "Real attacks chain weaknesses: an exploited web pod that can escape to its node can steal the token of a privileged controller scheduled on the same node. Each step alone may look acceptable; the chain is a full compromise.",
		Remediation:    "Break the chain at its cheapest link, listed in the finding: remove the escape vector, stop mounting powerful tokens in pods that do not need them, narrow the RBAC grant, or enforce Pod Security admission in the namespace.",
		References:     []finding.Reference{baselines.NSA("Threat model"), baselines.K8s("RBAC good practices: privilege escalation risks", "https://kubernetes.io/docs/concepts/security/rbac-good-practices/#privilege-escalation-risks")},
		Limitations:    "Assumes any two pods may share a node (no node affinity analysis). Namespaces without a Namespace object in the input are assumed not to enforce Pod Security. Cloud IAM, legacy token Secrets and admission policies other than Pod Security are not modelled. Workloads in kube-system are not reported as starting points unless --include-system is set, but their tokens are considered.",
		NeedsInventory: true,
	},
	Check: func(ctx *assessment.Context) {
		g := build(ctx.Inventory)
		toAdmin, toNode := g.distances(adminState), g.distances(nodeState)
		for _, w := range g.workloads {
			if w.ns == "kube-system" && !ctx.Options.IncludeSystem {
				continue
			}
			own := "sa:" + w.ns + "/" + w.sa
			if w.token && directAdmin(g, own) {
				continue // a direct grant is HX-RBAC-008's finding, not a path
			}
			var start []edge
			if w.canEsc {
				start = append(start, edge{to: nodeState, step: "escapes to its node (" + w.escape + ")"})
			}
			if w.token {
				start = append(start, edge{to: own, step: fmt.Sprintf("uses its mounted token (service account %s/%s)", w.ns, w.sa)})
			}
			if len(start) == 0 {
				continue
			}
			sev, goal := finding.Critical, "cluster administrator"
			steps := shortest(start, adminState, toAdmin)
			if steps == nil {
				if w.canEsc {
					continue // reaching the node directly is reported by the HX-WL rules
				}
				sev, goal = finding.High, "root on a node"
				steps = shortest(start, nodeState, toNode)
			}
			if len(steps) < 2 {
				continue
			}
			ctx.Report(assessment.Hit{Object: w.obj, Path: "spec", Observed: fmt.Sprintf("%d steps", len(steps)), Severity: &sev,
				Message: fmt.Sprintf("compromise of this workload leads to %s: %s", goal, strings.Join(steps, " → "))})
		}
	},
}

func directAdmin(g *graph, state string) bool {
	for _, e := range g.next(state) {
		if e.to == adminState {
			return true
		}
	}
	return false
}
