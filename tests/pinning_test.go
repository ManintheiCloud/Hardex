package tests

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Hardex reports unpinned images and actions in other people's projects
// (HX-WL-011, HX-WL-012); its own build must not have them. Actions are
// pinned to a full commit SHA, base images to a digest. Dependabot keeps
// both current.
func TestOwnDependenciesArePinned(t *testing.T) {
	files, _ := filepath.Glob("../.github/workflows/*.yml")
	files = append(files, "../action.yml")
	uses := regexp.MustCompile(`^\s*-?\s*uses:\s*(\S+)`)
	pinned := regexp.MustCompile(`^[\w.-]+/[\w./-]+@[0-9a-f]{40}$`)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			m := uses.FindStringSubmatch(line)
			if m == nil || strings.HasPrefix(m[1], "./") {
				continue
			}
			if !pinned.MatchString(m[1]) {
				t.Errorf("%s:%d: action %s is not pinned to a commit SHA", filepath.Base(f), i+1, m[1])
			}
		}
	}

	b, err := os.ReadFile("../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	from := regexp.MustCompile(`^FROM\s+(?:--platform=\S+\s+)?(\S+)`)
	n := 0
	for i, line := range strings.Split(string(b), "\n") {
		m := from.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		n++
		if !regexp.MustCompile(`@sha256:[0-9a-f]{64}$`).MatchString(m[1]) {
			t.Errorf("Dockerfile:%d: base image %s is not pinned by digest", i+1, m[1])
		}
	}
	if n == 0 {
		t.Error("no FROM lines found in the Dockerfile")
	}
}
