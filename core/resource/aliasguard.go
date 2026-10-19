package resource

import (
	"fmt"

	"github.com/goccy/go-yaml/ast"
)

// MaxExpandedNodes bounds the number of YAML nodes a document may expand to
// once aliases are resolved. A few kilobytes of nested anchors and aliases
// (the "billion laughs" pattern) can otherwise expand to gigabytes during
// decoding. Real Kubernetes manifests are orders of magnitude below this.
const MaxExpandedNodes = 1_000_000

// checkAliasExpansion computes a parsed document's fully expanded size
// without expanding it, rejecting documents that exceed MaxExpandedNodes.
func checkAliasExpansion(f *ast.File) error {
	anchors := map[string]int{}
	for _, d := range f.Docs {
		n, err := expandedSize(d.Body, anchors)
		if err != nil {
			return err
		}
		if n > MaxExpandedNodes {
			return fmt.Errorf("document expands to more than %d nodes through YAML aliases; refusing to decode", MaxExpandedNodes)
		}
	}
	return nil
}

func expandedSize(n ast.Node, anchors map[string]int) (int, error) {
	if n == nil {
		return 0, nil
	}
	add := func(total, x int) (int, error) {
		total += x
		if total > MaxExpandedNodes {
			return total, fmt.Errorf("document expands to more than %d nodes through YAML aliases; refusing to decode", MaxExpandedNodes)
		}
		return total, nil
	}
	switch v := n.(type) {
	case *ast.AnchorNode:
		size, err := expandedSize(v.Value, anchors)
		if err != nil {
			return 0, err
		}
		anchors[v.Name.String()] = size
		return size, nil
	case *ast.AliasNode:
		return anchors[v.Value.String()], nil
	case *ast.MappingNode:
		total := 1
		for _, mv := range v.Values {
			s, err := expandedSize(mv, anchors)
			if err != nil {
				return 0, err
			}
			if total, err = add(total, s); err != nil {
				return 0, err
			}
		}
		return total, nil
	case *ast.MappingValueNode:
		k, err := expandedSize(v.Key, anchors)
		if err != nil {
			return 0, err
		}
		val, err := expandedSize(v.Value, anchors)
		if err != nil {
			return 0, err
		}
		return add(k, val)
	case *ast.MappingKeyNode:
		return expandedSize(v.Value, anchors)
	case *ast.SequenceNode:
		total := 1
		for _, item := range v.Values {
			s, err := expandedSize(item, anchors)
			if err != nil {
				return 0, err
			}
			if total, err = add(total, s); err != nil {
				return 0, err
			}
		}
		return total, nil
	case *ast.TagNode:
		return expandedSize(v.Value, anchors)
	case *ast.DocumentNode:
		return expandedSize(v.Body, anchors)
	}
	return 1, nil
}
