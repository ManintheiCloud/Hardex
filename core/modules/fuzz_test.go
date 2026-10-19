package modules

import (
	"strings"
	"testing"

	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

// FuzzParse: arbitrary modules must not panic, and accepted modules must
// evaluate without errors against arbitrary-shaped objects.
func FuzzParse(f *testing.F) {
	f.Add([]byte(rule("    match: {scope: container}\n    violation: {path: 'a[*].b[c.d]', op: matches, pattern: '^x'}\n")))
	f.Add([]byte(rule("    match: {kinds: [Pod]}\n    violation: {path: spec, op: greaterThan, value: 3}\n")))
	inv, _ := resource.Load([]string{"-"}, strings.NewReader(pods))
	f.Fuzz(func(t *testing.T, data []byte) {
		rules, err := Parse(data)
		if err != nil {
			return
		}
		if res := assessment.Evaluate(inv, rules, assessment.Options{}); len(res.Errors) > 0 {
			t.Fatalf("accepted module fails at evaluation: %v", res.Errors)
		}
	})
}
