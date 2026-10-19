package main

import (
	"bytes"
	"os"
	"testing"
)

// The committed rule reference must match the code.
func TestRuleDocsUpToDate(t *testing.T) {
	want, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("../../docs/rules.md")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("docs/rules.md is stale; run: go run ./tools/gendocs")
	}
}
