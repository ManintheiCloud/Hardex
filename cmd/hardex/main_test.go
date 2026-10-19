package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func cli(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

const fixtures = "../../tests/fixtures/"

func TestExitCodes(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"clean", []string{"scan", "--profile", "restricted", fixtures + "hardened"}, exitOK},
		{"findings above threshold", []string{"scan", fixtures + "insecure"}, exitFindings},
		{"flags after path", []string{"scan", fixtures + "insecure", "--fail-on", "none", "--format", "json"}, exitOK},
		{"threshold none", []string{"scan", "--fail-on", "none", fixtures + "insecure"}, exitOK},
		{"no input", []string{"scan"}, exitUsage},
		{"bad severity", []string{"scan", "--fail-on", "urgent", fixtures + "insecure"}, exitUsage},
		{"bad profile", []string{"scan", "--profile", "nope", fixtures + "insecure"}, exitUsage},
		{"missing path", []string{"scan", "does-not-exist"}, exitUsage},
		{"unknown command", []string{"frobnicate"}, exitUsage},
		{"rule detail", []string{"rules", "hx-wl-001"}, exitOK},
		{"rule list", []string{"rules"}, exitOK},
		{"profiles", []string{"profiles"}, exitOK},
		{"example config", []string{"scan", "--config", "../../examples/hardex.yaml", fixtures + "hardened"}, exitOK},
		{"missing config", []string{"scan", "--config", "nope.yaml", fixtures + "hardened"}, exitUsage},
		{"custom profile file", []string{"scan", "--profile", "../../baselines/profiles/minimal.yaml", fixtures + "hardened"}, exitOK},
		{"unknown rule", []string{"rules", "HX-NOPE-001"}, exitUsage},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if code, _, stderr := cli(t, "", c.args...); code != c.want {
				t.Errorf("exit %d, want %d (stderr: %s)", code, c.want, stderr)
			}
		})
	}
}

func TestStdinAndFormats(t *testing.T) {
	pod := "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  containers: [{name: c, image: x:1, securityContext: {privileged: true}}]\n"
	for _, format := range []string{"text", "json", "sarif"} {
		code, out, _ := cli(t, pod, "scan", "--format", format, "-")
		if code != exitFindings || !strings.Contains(out, "HX-WL-001") {
			t.Errorf("%s: exit %d, output missing HX-WL-001", format, code)
		}
	}
}

func TestDiffWorkflow(t *testing.T) {
	dir := t.TempDir()
	before, after := filepath.Join(dir, "before.json"), filepath.Join(dir, "after.json")
	cli(t, "", "scan", "--format", "json", "-o", before, "--fail-on", "none", fixtures+"insecure")
	cli(t, "", "scan", "--format", "json", "-o", after, "--fail-on", "none", fixtures+"hardened")
	for _, p := range []string{before, after} {
		if _, err := os.Stat(p); err != nil {
			t.Fatal(err)
		}
	}
	code, out, _ := cli(t, "", "diff", before, after)
	if code != exitOK || !strings.Contains(out, "Resolved (") {
		t.Errorf("improvement: exit %d\n%s", code, out)
	}
	if code, _, _ := cli(t, "", "diff", after, before); code != exitFindings {
		t.Errorf("regression: exit %d, want %d", code, exitFindings)
	}
}

func TestMonitorOnce(t *testing.T) {
	dir := t.TempDir()
	m := filepath.Join(dir, "m")
	os.MkdirAll(m, 0o755)
	copyFile := func(src, dst string) {
		b, _ := os.ReadFile(src)
		os.WriteFile(dst, b, 0o644)
	}
	copyFile(fixtures+"hardened/workloads.yaml", filepath.Join(m, "a.yaml"))
	h := filepath.Join(dir, "h")
	if code, _, stderr := cli(t, "", "monitor", "--once", "--history", h, "--events", "", m); code != exitOK {
		t.Fatalf("first: exit %d %s", code, stderr)
	}
	copyFile(fixtures+"insecure/workloads.yaml", filepath.Join(m, "b.yaml"))
	code, out, _ := cli(t, "", "monitor", "--once", "--history", h, m)
	if code != exitFindings || !strings.Contains(out, `"finding.introduced"`) {
		t.Fatalf("drift: exit %d\n%s", code, out)
	}
	if code, out, _ := cli(t, "", "history", h); code != exitOK || !strings.Contains(out, "+") {
		t.Fatalf("history: exit %d\n%s", code, out)
	}
	if code, _, _ := cli(t, "", "monitor", "--once", "--history", h, "--webhook", "http://insecure.example", m); code != exitUsage {
		t.Error("accepted http webhook")
	}
}

func TestModules(t *testing.T) {
	mod := "../../examples/modules/organization-policy.yaml"
	code, out, stderr := cli(t, "", "scan", "--module", mod, "--format", "json", "--fail-on", "none", fixtures+"hardened")
	if code != exitOK || !strings.Contains(out, `"ORG-SC-001"`) || !strings.Contains(out, `"ORG-WL-001"`) {
		t.Fatalf("exit %d\n%s\n%s", code, out, stderr)
	}
	if code, out, _ := cli(t, "", "rules", "--module", mod, "ORG-SC-001"); code != exitOK || !strings.Contains(out, "unapproved registry") {
		t.Fatalf("rules: exit %d\n%s", code, out)
	}
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	os.WriteFile(bad, []byte("apiVersion: hardex.dev/v1alpha1\nkind: RuleModule\nname: x\nrules: []\n"), 0o644)
	if code, _, _ := cli(t, "", "scan", "--module", bad, fixtures+"hardened"); code != exitUsage {
		t.Fatal("invalid module accepted")
	}
}

func TestReportDigestMatchesFile(t *testing.T) {
	dir := t.TempDir()
	rep := filepath.Join(dir, "r.json")
	cli(t, "", "scan", "--format", "json", "-o", rep, "--fail-on", "none", fixtures+"insecure")
	data, _ := os.ReadFile(rep)
	sum := sha256.Sum256(data)
	code, out, stderr := cli(t, "", "report", rep, "--format", "markdown")
	if code != exitOK || !strings.Contains(out, hex.EncodeToString(sum[:])) {
		t.Fatalf("exit %d, digest missing\n%s", code, stderr)
	}
	if code, out, _ := cli(t, "", "report", rep, "--format", "score"); code != exitOK || !strings.Contains(out, `"grade"`) {
		t.Fatalf("score: exit %d\n%s", code, out)
	}
}

func TestImagesOffline(t *testing.T) {
	code, out, _ := cli(t, "", "images", "--offline", fixtures+"insecure")
	if code != exitOK || !strings.Contains(out, "nginx:latest") || !strings.Contains(out, "tag (mutable)") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if code, _, _ := cli(t, "", "images", "--offline", "--require-digest", fixtures+"insecure"); code != exitFindings {
		t.Errorf("--require-digest: exit %d, want %d", code, exitFindings)
	}
	if code, _, _ := cli(t, "", "images", "--require-signature", fixtures+"insecure"); code != exitUsage {
		t.Error("--require-signature without --key accepted")
	}
}
