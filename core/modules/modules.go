// Package modules loads declarative rule modules: organisation- or
// community-maintained checks written in YAML instead of Go.
//
// A module rule describes a violation as "the value at PATH satisfies OP".
// Modules are trusted input in the same way as configuration: they are only
// loaded when named explicitly (--module), never discovered implicitly. They
// are validated strictly and fail closed: an invalid module is an error, not
// a module that silently checks nothing.
package modules

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ManintheiCloud/Hardex/internal/yamlsafe"

	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

const (
	APIVersion = "hardex.dev/v1alpha1"
	Kind       = "RuleModule"
)

// Module is the on-disk format.
type Module struct {
	APIVersion  string `yaml:"apiVersion"`
	Kind        string `yaml:"kind"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Rules       []Rule `yaml:"rules"`
}

// Rule is one declarative check.
type Rule struct {
	ID          string `yaml:"id"`
	Title       string `yaml:"title"`
	Severity    string `yaml:"severity"`
	Category    string `yaml:"category"`
	Description string `yaml:"description"`
	Rationale   string `yaml:"rationale"`
	Remediation string `yaml:"remediation"`
	Limitations string `yaml:"limitations"`
	References  []struct {
		Framework string `yaml:"framework"`
		Control   string `yaml:"control"`
		URL       string `yaml:"url"`
	} `yaml:"references"`
	Match     Match     `yaml:"match"`
	Violation Violation `yaml:"violation"`
	Message   string    `yaml:"message"`
}

// Match selects what a rule evaluates.
type Match struct {
	// Scope is "object" (paths from the object root), "podSpec" (from each
	// workload's pod spec) or "container" (from each container, including
	// init and ephemeral containers).
	Scope string `yaml:"scope"`
	// Kinds limits evaluation to these kinds; required for object scope.
	Kinds             []string `yaml:"kinds"`
	Namespaces        []string `yaml:"namespaces"`
	ExcludeNamespaces []string `yaml:"excludeNamespaces"`
}

// Violation is the condition that produces a finding.
type Violation struct {
	// Path is dotted; [key] addresses keys containing dots or slashes,
	// [N] an array element, and [*] every element or value.
	Path    string `yaml:"path"`
	Op      string `yaml:"op"`
	Value   any    `yaml:"value"`
	Values  []any  `yaml:"values"`
	Pattern string `yaml:"pattern"`
}

var (
	idPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]{0,15}(-[A-Z0-9]{1,15}){1,3}$`)
	ops       = map[string]bool{"exists": true, "absent": true, "equals": true, "notEquals": true, "in": true, "notIn": true,
		"matches": true, "notMatches": true, "greaterThan": true, "lessThan": true}
	scopes = map[string]bool{"object": true, "podSpec": true, "container": true}
)

// Load reads, validates and compiles a module file.
func Load(path string) ([]assessment.Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rules, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("module %s: %w", path, err)
	}
	return rules, nil
}

// Parse validates and compiles module bytes.
func Parse(data []byte) ([]assessment.Rule, error) {
	var m Module
	if err := yamlsafe.Strict(data, &m); err != nil {
		return nil, err
	}
	if m.APIVersion != APIVersion || m.Kind != Kind {
		return nil, fmt.Errorf("expected apiVersion %q and kind %q", APIVersion, Kind)
	}
	if m.Name == "" || len(m.Rules) == 0 {
		return nil, fmt.Errorf("name and at least one rule are required")
	}
	seen := map[string]bool{}
	var out []assessment.Rule
	for i, r := range m.Rules {
		compiled, err := compile(r)
		if err != nil {
			return nil, fmt.Errorf("rules[%d] %s: %w", i, r.ID, err)
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("rules[%d]: duplicate id %s", i, r.ID)
		}
		seen[r.ID] = true
		out = append(out, compiled)
	}
	return out, nil
}

type compiled struct {
	meta  assessment.Metadata
	match Match
	path  []string
	test  func(v any) bool
	op    string
	msg   string
	nsIn  map[string]bool
	nsOut map[string]bool
}

func compile(r Rule) (*compiled, error) {
	switch {
	case !idPattern.MatchString(r.ID):
		return nil, fmt.Errorf("id must look like ORG-AREA-001 (uppercase letters and digits, 2-4 parts)")
	case strings.HasPrefix(r.ID, "HX-"):
		return nil, fmt.Errorf("the HX- prefix is reserved for built-in rules")
	}
	sev, err := finding.ParseSeverity(r.Severity)
	if err != nil || sev > finding.Critical {
		return nil, fmt.Errorf("invalid severity %q", r.Severity)
	}
	if r.Category == "" {
		r.Category = "custom"
	}
	meta := assessment.Metadata{ID: r.ID, Title: r.Title, Severity: sev, Category: r.Category,
		Description: r.Description, Rationale: r.Rationale, Remediation: r.Remediation, Limitations: r.Limitations}
	for _, ref := range r.References {
		meta.References = append(meta.References, finding.Reference{Framework: ref.Framework, Control: ref.Control, URL: ref.URL})
	}
	if err := meta.Validate(); err != nil {
		return nil, err
	}
	c := &compiled{meta: meta, match: r.Match, op: r.Violation.Op, msg: r.Message}
	if c.match.Scope == "" {
		c.match.Scope = "object"
	}
	if !scopes[c.match.Scope] {
		return nil, fmt.Errorf("match.scope must be object, podSpec or container")
	}
	if c.match.Scope == "object" && len(c.match.Kinds) == 0 {
		return nil, fmt.Errorf("match.kinds is required for object scope")
	}
	c.nsIn, c.nsOut = set(c.match.Namespaces), set(c.match.ExcludeNamespaces)
	if r.Violation.Path == "" {
		return nil, fmt.Errorf("violation.path is required")
	}
	c.path = parsePath(r.Violation.Path)
	if !ops[r.Violation.Op] {
		return nil, fmt.Errorf("violation.op %q is not one of exists, absent, equals, notEquals, in, notIn, matches, notMatches, greaterThan, lessThan", r.Violation.Op)
	}
	v := r.Violation
	switch v.Op {
	case "exists", "absent":
		c.test = func(any) bool { return true }
	case "equals", "notEquals":
		if v.Value == nil {
			return nil, fmt.Errorf("violation.value is required for %s", v.Op)
		}
		want := normalize(v.Value)
		neg := v.Op == "notEquals"
		c.test = func(x any) bool { return (normalize(x) == want) != neg }
	case "in", "notIn":
		if len(v.Values) == 0 {
			return nil, fmt.Errorf("violation.values is required for %s", v.Op)
		}
		allowed := map[string]bool{}
		for _, a := range v.Values {
			allowed[normalize(a)] = true
		}
		neg := v.Op == "notIn"
		c.test = func(x any) bool { return allowed[normalize(x)] != neg }
	case "matches", "notMatches":
		// RE2: linear-time matching, so a module cannot cause catastrophic
		// backtracking on hostile input.
		re, err := regexp.Compile(v.Pattern)
		if err != nil || v.Pattern == "" {
			return nil, fmt.Errorf("violation.pattern must be a valid regular expression")
		}
		neg := v.Op == "notMatches"
		c.test = func(x any) bool {
			s, ok := x.(string)
			return ok && re.MatchString(s) != neg
		}
	case "greaterThan", "lessThan":
		limit, ok := number(v.Value)
		if !ok {
			return nil, fmt.Errorf("violation.value must be a number for %s", v.Op)
		}
		gt := v.Op == "greaterThan"
		c.test = func(x any) bool {
			n, ok := number(x)
			return ok && ((gt && n > limit) || (!gt && n < limit))
		}
	}
	if c.msg == "" {
		c.msg = r.Title
	}
	return c, nil
}

func (c *compiled) Metadata() assessment.Metadata { return c.meta }

func (c *compiled) Evaluate(ctx *assessment.Context) {
	for _, obj := range ctx.Inventory.Objects {
		if len(c.match.Kinds) > 0 && !contains(c.match.Kinds, obj.Kind) {
			continue
		}
		ns := obj.EffectiveNamespace()
		if (len(c.nsIn) > 0 && !c.nsIn[ns]) || c.nsOut[ns] {
			continue
		}
		switch c.match.Scope {
		case "object":
			c.check(ctx, obj, obj.Raw, "", "")
		case "podSpec", "container":
			pod, prefix := resource.PodSpec(obj)
			if pod == nil {
				continue
			}
			if c.match.Scope == "podSpec" {
				c.check(ctx, obj, pod, prefix, "")
				continue
			}
			for _, ctr := range resource.Containers(pod) {
				c.check(ctx, obj, ctr.Spec, ctr.Path(prefix), ctr.Name)
			}
		}
	}
}

func (c *compiled) check(ctx *assessment.Context, obj *resource.Object, root map[string]any, prefix, container string) {
	for _, m := range resolve(root, c.path, prefix) {
		violated := false
		switch c.op {
		case "absent":
			violated = !m.exists
		case "exists":
			violated = m.exists
		default:
			violated = m.exists && c.test(m.value)
		}
		if !violated {
			continue
		}
		observed := "<absent>"
		if m.exists {
			observed = fmt.Sprint(m.value)
		}
		ctx.Report(assessment.Hit{Object: obj, Container: container, Path: m.path, Observed: observed, Message: c.msg})
	}
}

type match struct {
	path   string
	value  any
	exists bool
}

// resolve expands the path against root, branching at [*].
func resolve(root any, segs []string, prefix string) []match {
	if len(segs) == 0 {
		return []match{{path: prefix, value: root, exists: true}}
	}
	seg, rest := segs[0], segs[1:]
	switch v := root.(type) {
	case map[string]any:
		if seg == "*" {
			var out []match
			for _, k := range sortedKeys(v) {
				out = append(out, resolve(v[k], rest, join(prefix, k))...)
			}
			return out
		}
		child, ok := v[seg]
		if !ok {
			return []match{{path: join(prefix, seg) + suffix(rest)}}
		}
		return resolve(child, rest, join(prefix, seg))
	case []any:
		if seg == "*" {
			var out []match
			for i, item := range v {
				out = append(out, resolve(item, rest, fmt.Sprintf("%s[%d]", prefix, i))...)
			}
			return out
		}
		i, err := strconv.Atoi(seg)
		if err != nil || i < 0 || i >= len(v) {
			return []match{{path: fmt.Sprintf("%s[%s]", prefix, seg) + suffix(rest)}}
		}
		return resolve(v[i], rest, fmt.Sprintf("%s[%d]", prefix, i))
	}
	// A scalar (or null) where a container was expected: the path is absent.
	return []match{{path: join(prefix, seg) + suffix(rest)}}
}

func needsBracket(key string) bool {
	return key == "*" || strings.ContainsAny(key, "./[]") || isIndex(key)
}

func isIndex(key string) bool {
	_, err := strconv.Atoi(key)
	return err == nil
}

func join(prefix, key string) string {
	switch {
	case needsBracket(key):
		return prefix + "[" + key + "]"
	case prefix == "":
		return key
	}
	return prefix + "." + key
}

// suffix renders the unresolved remainder of a path.
func suffix(rest []string) string {
	var b strings.Builder
	for _, r := range rest {
		if needsBracket(r) {
			b.WriteString("[" + r + "]")
		} else {
			b.WriteString("." + r)
		}
	}
	return b.String()
}

// parsePath splits "a.b[c.d][0][*].e" into segments.
func parsePath(p string) []string {
	var segs []string
	var cur strings.Builder
	inBracket := false
	flush := func() {
		if cur.Len() > 0 {
			segs = append(segs, cur.String())
			cur.Reset()
		}
	}
	for _, r := range p {
		switch {
		case r == '[' && !inBracket:
			flush()
			inBracket = true
		case r == ']' && inBracket:
			flush()
			inBracket = false
		case r == '.' && !inBracket:
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return segs
}

func normalize(v any) string {
	switch n := v.(type) {
	case int, int64, uint64, float64, float32, int32, uint32:
		f, _ := number(n)
		return strconv.FormatFloat(f, 'g', -1, 64)
	}
	return fmt.Sprint(v)
}

func number(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint64:
		return float64(n), true
	}
	return 0, false
}

func set(list []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range list {
		m[s] = true
	}
	return m
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
