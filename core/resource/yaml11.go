package resource

import (
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
)

// Kubernetes tooling (kubectl, and the API machinery via sigs.k8s.io/yaml)
// decodes YAML with YAML 1.1 scalar resolution, in which unquoted yes/no,
// on/off and y/n are booleans. Hardex's parser implements YAML 1.2, where
// they are strings. Without reconciling the two, `privileged: yes` would be
// applied by Kubernetes as true but read by Hardex as the string "yes" — a
// detection bypass. These are the YAML 1.1 forms that YAML 1.2 does not
// already treat as booleans.
var yaml11Bools = map[string]bool{
	"y": true, "Y": true, "yes": true, "Yes": true, "YES": true, "on": true, "On": true, "ON": true,
	"n": false, "N": false, "no": false, "No": false, "NO": false, "off": false, "Off": false, "OFF": false,
}

// normalizeYAML11 rewrites plain (unquoted) YAML 1.1 boolean scalars in
// value positions into booleans, matching how Kubernetes reads the document.
func normalizeYAML11(n ast.Node) ast.Node {
	switch v := n.(type) {
	case *ast.StringNode:
		if v.Token != nil && v.Token.Type == token.StringType {
			if b, ok := yaml11Bools[v.Value]; ok {
				return &ast.BoolNode{BaseNode: &ast.BaseNode{}, Token: v.Token, Value: b}
			}
		}
	case *ast.DocumentNode:
		v.Body = normalizeYAML11(v.Body)
	case *ast.MappingNode:
		for _, mv := range v.Values {
			normalizeYAML11(mv)
		}
	case *ast.MappingValueNode:
		// Keys are left alone: a field named "on" stays a field name.
		v.Value = normalizeYAML11(v.Value)
	case *ast.SequenceNode:
		for i := range v.Values {
			v.Values[i] = normalizeYAML11(v.Values[i])
		}
	case *ast.AnchorNode:
		v.Value = normalizeYAML11(v.Value)
	case *ast.TagNode:
		// An explicit tag (e.g. !!str yes) states the type; respect it.
	}
	return n
}
