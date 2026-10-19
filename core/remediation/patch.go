// Package remediation turns findings into reviewable, reversible changes.
//
// Every change is an RFC 6902 JSON Patch whose operations are guarded by
// "test" operations on the values they replace, so a patch computed against
// one version of an object fails rather than overwriting a different one.
// For every forward patch an inverse patch is computed, which is what
// rollback applies. The design constraints are recorded in
// docs/adr/0003-assessment-before-remediation.md and
// docs/adr/0005-remediation-engine.md.
package remediation

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// Op is one RFC 6902 operation. Hardex emits only add, replace, remove and
// test.
type Op struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value,omitempty"`
}

// MarshalJSON keeps an explicit "value": null for add/replace/test ops,
// which RFC 6902 requires to be present.
func (o Op) MarshalJSON() ([]byte, error) {
	m := map[string]any{"op": o.Op, "path": o.Path}
	if o.Op != "remove" {
		m["value"] = o.Value
	}
	return json.Marshal(m)
}

// Pointer encodes path segments as a JSON Pointer (RFC 6901).
func Pointer(segs []string) string {
	var b strings.Builder
	for _, s := range segs {
		b.WriteByte('/')
		b.WriteString(strings.NewReplacer("~", "~0", "/", "~1").Replace(s))
	}
	return b.String()
}

func parsePointer(p string) ([]string, error) {
	if p == "" {
		return nil, nil
	}
	if !strings.HasPrefix(p, "/") {
		return nil, fmt.Errorf("invalid JSON pointer %q", p)
	}
	parts := strings.Split(p[1:], "/")
	for i, s := range parts {
		parts[i] = strings.NewReplacer("~1", "/", "~0", "~").Replace(s)
	}
	return parts, nil
}

// DeepCopy copies a JSON-compatible value.
func DeepCopy(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, val := range t {
			m[k] = DeepCopy(val)
		}
		return m
	case []any:
		s := make([]any, len(t))
		for i, val := range t {
			s[i] = DeepCopy(val)
		}
		return s
	}
	return v
}

// Apply returns a copy of doc with the operations applied. It fails on the
// first operation that cannot be applied, including a failed test.
func Apply(doc map[string]any, ops []Op) (map[string]any, error) {
	root := DeepCopy(doc)
	for i, op := range ops {
		segs, err := parsePointer(op.Path)
		if err != nil {
			return nil, err
		}
		if len(segs) == 0 {
			return nil, fmt.Errorf("op %d: operations on the document root are not supported", i)
		}
		if root, err = applyOne(root, segs, op); err != nil {
			return nil, fmt.Errorf("op %d (%s %s): %w", i, op.Op, op.Path, err)
		}
	}
	return root.(map[string]any), nil
}

func applyOne(root any, segs []string, op Op) (any, error) {
	parent, err := lookup(root, segs[:len(segs)-1])
	if err != nil {
		return nil, err
	}
	key := segs[len(segs)-1]
	switch p := parent.(type) {
	case map[string]any:
		cur, exists := p[key]
		switch op.Op {
		case "test":
			if !exists || !jsonEqual(cur, op.Value) {
				return nil, fmt.Errorf("test failed: value is %s", render(cur, exists))
			}
		case "add":
			p[key] = DeepCopy(op.Value)
		case "replace":
			if !exists {
				return nil, fmt.Errorf("replace of missing member")
			}
			p[key] = DeepCopy(op.Value)
		case "remove":
			if !exists {
				return nil, fmt.Errorf("remove of missing member")
			}
			delete(p, key)
		default:
			return nil, fmt.Errorf("unsupported op")
		}
		return root, nil
	case []any:
		idx, err := arrayIndex(key, len(p), op.Op == "add")
		if err != nil {
			return nil, err
		}
		var updated []any
		switch op.Op {
		case "test":
			if !jsonEqual(p[idx], op.Value) {
				return nil, fmt.Errorf("test failed: value is %s", render(p[idx], true))
			}
			return root, nil
		case "add":
			updated = append(append(append([]any{}, p[:idx]...), DeepCopy(op.Value)), p[idx:]...)
		case "replace":
			p[idx] = DeepCopy(op.Value)
			return root, nil
		case "remove":
			updated = append(append([]any{}, p[:idx]...), p[idx+1:]...)
		default:
			return nil, fmt.Errorf("unsupported op")
		}
		// Arrays change length: re-attach to the grandparent.
		return setAt(root, segs[:len(segs)-1], updated)
	}
	return nil, fmt.Errorf("parent is not a container")
}

func arrayIndex(key string, n int, forAdd bool) (int, error) {
	if key == "-" && forAdd {
		return n, nil
	}
	idx, err := strconv.Atoi(key)
	if err != nil || idx < 0 || idx > n || (!forAdd && idx == n) {
		return 0, fmt.Errorf("array index %q out of range", key)
	}
	return idx, nil
}

func lookup(root any, segs []string) (any, error) {
	cur := root
	for _, s := range segs {
		switch c := cur.(type) {
		case map[string]any:
			v, ok := c[s]
			if !ok {
				return nil, fmt.Errorf("path segment %q not found", s)
			}
			cur = v
		case []any:
			idx, err := arrayIndex(s, len(c), false)
			if err != nil {
				return nil, err
			}
			cur = c[idx]
		default:
			return nil, fmt.Errorf("path segment %q: not a container", s)
		}
	}
	return cur, nil
}

func setAt(root any, segs []string, value any) (any, error) {
	if len(segs) == 0 {
		return value, nil
	}
	parent, err := lookup(root, segs[:len(segs)-1])
	if err != nil {
		return nil, err
	}
	key := segs[len(segs)-1]
	switch p := parent.(type) {
	case map[string]any:
		p[key] = value
	case []any:
		idx, err := arrayIndex(key, len(p), false)
		if err != nil {
			return nil, err
		}
		p[idx] = value
	}
	return root, nil
}

// Get returns the value at a JSON pointer.
func Get(doc map[string]any, pointer string) (any, bool) {
	segs, err := parsePointer(pointer)
	if err != nil {
		return nil, false
	}
	v, err := lookup(doc, segs)
	return v, err == nil
}

func jsonEqual(a, b any) bool {
	// Normalise numeric types by round-tripping through JSON.
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	var na, nb any
	_ = json.Unmarshal(ja, &na)
	_ = json.Unmarshal(jb, &nb)
	return reflect.DeepEqual(na, nb)
}

func render(v any, exists bool) string {
	if !exists {
		return "absent"
	}
	b, _ := json.Marshal(v)
	return string(b)
}
