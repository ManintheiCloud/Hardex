package modules

import (
	"strings"
	"testing"

	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

const header = "apiVersion: hardex.dev/v1alpha1\nkind: RuleModule\nname: t\nrules:\n"

func rule(extra string) string {
	return header + `  - id: T-WL-001
    title: t
    severity: medium
    description: d
    rationale: r
    remediation: f
` + extra
}

func TestParseRejectsInvalidModules(t *testing.T) {
	cases := map[string]string{
		"unknown field":      rule("    violaton: {path: a, op: absent}\n    match: {kinds: [Pod]}\n"),
		"reserved prefix":    strings.Replace(rule("    match: {kinds: [Pod]}\n    violation: {path: a, op: absent}\n"), "T-WL-001", "HX-WL-999", 1),
		"bad id":             strings.Replace(rule("    match: {kinds: [Pod]}\n    violation: {path: a, op: absent}\n"), "T-WL-001", "lower", 1),
		"bad op":             rule("    match: {kinds: [Pod]}\n    violation: {path: a, op: contains}\n"),
		"object needs kinds": rule("    violation: {path: a, op: absent}\n"),
		"missing value":      rule("    match: {kinds: [Pod]}\n    violation: {path: a, op: equals}\n"),
		"bad regex":          rule("    match: {kinds: [Pod]}\n    violation: {path: a, op: matches, pattern: '('}\n"),
		"non-numeric limit":  rule("    match: {kinds: [Pod]}\n    violation: {path: a, op: greaterThan, value: lots}\n"),
		"missing rationale":  strings.Replace(rule("    match: {kinds: [Pod]}\n    violation: {path: a, op: absent}\n"), "    rationale: r\n", "", 1),
		"wrong kind":         strings.Replace(rule("    match: {kinds: [Pod]}\n    violation: {path: a, op: absent}\n"), "RuleModule", "Rules", 1),
	}
	for name, y := range cases {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

const pods = `apiVersion: v1
kind: Pod
metadata: {name: a, namespace: x, labels: {team.example.com/owner: web}}
spec:
  containers:
    - {name: c1, image: docker.io/nginx:1, resources: {limits: {cpu: 2}}}
    - {name: c2, image: registry.example.com/app:1, resources: {limits: {cpu: 0.5}}}
---
apiVersion: v1
kind: Pod
metadata: {name: b, namespace: skip}
spec:
  containers: [{name: c, image: docker.io/x:1}]
`

func eval(t *testing.T, extra string) []string {
	t.Helper()
	rules, err := Parse([]byte(rule(extra)))
	if err != nil {
		t.Fatal(err)
	}
	inv, err := resource.Load([]string{"-"}, strings.NewReader(pods))
	if err != nil {
		t.Fatal(err)
	}
	res := assessment.Evaluate(inv, rules, assessment.Options{})
	if len(res.Errors) > 0 {
		t.Fatal(res.Errors)
	}
	var out []string
	for _, f := range res.Findings {
		out = append(out, f.Resource.Name+" "+f.Path+"="+f.Observed)
	}
	return out
}

func TestEvaluation(t *testing.T) {
	cases := map[string]struct {
		spec string
		want []string
	}{
		"container regex": {"    match: {scope: container, excludeNamespaces: [skip]}\n    violation: {path: image, op: notMatches, pattern: '^registry\\.example\\.com/'}\n",
			[]string{"a spec.containers[0].image=docker.io/nginx:1"}},
		"bracketed key exists": {"    match: {kinds: [Pod]}\n    violation: {path: 'metadata.labels[team.example.com/owner]', op: exists}\n",
			[]string{"a metadata.labels[team.example.com/owner]=web"}},
		"absent reports path": {"    match: {kinds: [Pod], namespaces: [x]}\n    violation: {path: metadata.labels.owner, op: absent}\n",
			[]string{"a metadata.labels.owner=<absent>"}},
		"wildcard and numbers": {"    match: {kinds: [Pod]}\n    violation: {path: 'spec.containers[*].resources.limits.cpu', op: greaterThan, value: 1}\n",
			[]string{"a spec.containers[0].resources.limits.cpu=2"}},
		"in list": {"    match: {scope: container}\n    violation: {path: name, op: in, values: [c2, c]}\n",
			[]string{"b spec.containers[0].name=c", "a spec.containers[1].name=c2"}},
	}
	for name, c := range cases {
		got := eval(t, c.spec)
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s:\n got  %q\n want %q", name, got, c.want)
		}
	}
}

func TestExampleModuleLoads(t *testing.T) {
	rules, err := Load("../../examples/modules/organization-policy.yaml")
	if err != nil || len(rules) != 3 {
		t.Fatalf("rules=%d err=%v", len(rules), err)
	}
}
