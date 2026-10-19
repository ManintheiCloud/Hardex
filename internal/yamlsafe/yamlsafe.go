// Package yamlsafe wraps the YAML library so that a panic inside it, on
// malformed or hostile input, becomes an ordinary error. Hardex treats a
// crash on bad input as a failure to fail safely: every YAML decode in the
// project goes through this package.
package yamlsafe

import (
	"bytes"
	"fmt"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

// Strict decodes data into v, rejecting unknown fields and duplicate keys.
func Strict(data []byte, v any) error {
	return Decode(data, v, yaml.Strict(), yaml.DisallowUnknownField())
}

// Decode decodes data into v with the given options.
func Decode(data []byte, v any, opts ...yaml.DecodeOption) (err error) {
	defer recoverInto(&err)
	if err := yaml.NewDecoder(bytes.NewReader(data), opts...).Decode(v); err != nil {
		return fmt.Errorf("%s", yaml.FormatError(err, false, false))
	}
	return nil
}

// Parse parses data into an AST.
func Parse(data []byte) (f *ast.File, err error) {
	defer recoverInto(&err)
	return parser.ParseBytes(data, 0)
}

// NodeToValue converts an AST node into a Go value.
func NodeToValue(n ast.Node, v any) (err error) {
	defer recoverInto(&err)
	return yaml.NodeToValue(n, v)
}

func recoverInto(err *error) {
	if r := recover(); r != nil {
		*err = fmt.Errorf("malformed YAML (parser failure: %v)", r)
	}
}
