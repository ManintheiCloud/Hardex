package tests

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ManintheiCloud/Hardex/core/finding"
)

// Pod Security Standards changes in Kubernetes 1.34–1.37, checked against
// pod-security-admission's policy package: host in probes and lifecycle
// hooks (1.34), the user-namespace relaxations of the root-user and /proc
// controls (1.35), and the larger safe sysctl set (1.32, 1.37).
func TestPSSRecentChanges(t *testing.T) {
	dir := t.TempDir()
	write := func(name, spec string) {
		y := "apiVersion: v1\nkind: Pod\nmetadata: {name: " + name + ", namespace: pss}\nspec:\n" + spec
		if err := os.WriteFile(filepath.Join(dir, name+".yaml"), []byte(y), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("userns", `
  hostUsers: false
  securityContext: {runAsUser: 0}
  containers:
    - {name: c, image: x, securityContext: {procMount: Unmasked}}
`)
	write("userns-yaml11", `
  hostUsers: no
  containers:
    - {name: c, image: x, securityContext: {runAsUser: 0}}
`)
	write("hostusers-string", `
  hostUsers: "false"
  containers:
    - {name: c, image: x, securityContext: {runAsUser: 0, procMount: Unmasked}}
`)
	write("sysctls", `
  securityContext:
    sysctls:
      - {name: net.ipv4.tcp_rmem, value: "4096 87380 6291456"}
      - {name: net.ipv4.tcp_wmem, value: "4096 16384 4194304"}
      - {name: net.ipv4.tcp_slow_start_after_idle, value: "0"}
      - {name: net.ipv4.tcp_notsent_lowat, value: "16384"}
      - {name: net.core.somaxconn, value: "1024"}
  containers: [{name: c, image: x}]
`)
	write("probes", `
  initContainers:
    - name: i
      image: x
      lifecycle: {preStop: {tcpSocket: {host: 127.0.0.1, port: 10250}}}
  containers:
    - name: c
      image: x
      readinessProbe: {httpGet: {host: "", path: /, port: 80}}
      startupProbe: {tcpSocket: {host: db.internal, port: 5432}}
      lifecycle: {postStart: {httpGet: {host: 10.0.0.1, path: /, port: 80}}}
`)

	write("hostnet-loopback", `
  hostNetwork: true
  containers:
    - name: c
      image: x
      livenessProbe: {httpGet: {host: 127.0.0.1, path: /, port: 7472}}
      readinessProbe: {httpGet: {host: 169.254.169.254, path: /, port: 80}}
`)

	r := scan(t, "restricted", dir)
	got := map[string][]finding.Finding{}
	for _, f := range r.Findings {
		got[f.RuleID+" "+f.Resource.Name] = append(got[f.RuleID+" "+f.Resource.Name], f)
	}
	count := func(rule, pod string) int { return len(got[rule+" "+pod]) }

	// 1.35: root in a user namespace is allowed.
	for _, pod := range []string{"userns", "userns-yaml11"} {
		if n := count("HX-WL-005", pod); n != 0 {
			t.Errorf("HX-WL-005 reported %d times for %s (hostUsers: false)", n, pod)
		}
	}
	// ... and an unmasked /proc is Baseline-allowed there, so low.
	if fs := got["HX-WL-017 userns"]; len(fs) != 1 || fs[0].Severity != finding.Low {
		t.Errorf("HX-WL-017 for userns: %+v, want one low finding", fs)
	}
	// A string is not hostUsers: false; nothing is relaxed.
	if count("HX-WL-005", "hostusers-string") != 1 {
		t.Error(`hostUsers: "false" (a string) relaxed HX-WL-005`)
	}
	if fs := got["HX-WL-017 hostusers-string"]; len(fs) != 1 || fs[0].Severity != finding.High {
		t.Errorf(`HX-WL-017 for hostUsers: "false": %+v, want one high finding`, fs)
	}

	// Safe sysctls up to 1.37 pass; somaxconn is not in the safe set.
	if fs := got["HX-WL-018 sysctls"]; len(fs) != 1 || fs[0].Observed != "net.core.somaxconn" {
		t.Errorf("HX-WL-018: %+v, want only net.core.somaxconn", fs)
	}

	// 1.34: host in probes and lifecycle hooks; an empty host is allowed.
	want := map[string]bool{
		"spec.initContainers[0].lifecycle.preStop.tcpSocket.host": false,
		"spec.containers[0].startupProbe.tcpSocket.host":          false,
		"spec.containers[0].lifecycle.postStart.httpGet.host":     false,
	}
	for _, f := range got["HX-WL-021 probes"] {
		if _, ok := want[f.Path]; !ok {
			t.Errorf("HX-WL-021 unexpected finding at %s", f.Path)
		}
		want[f.Path] = true
	}
	for p, found := range want {
		if !found {
			t.Errorf("HX-WL-021 missed %s", p)
		}
	}

	// In a hostNetwork pod a loopback host is the pod's own; low. Any other
	// host keeps the rule's severity.
	sev := map[string]finding.Severity{}
	for _, f := range got["HX-WL-021 hostnet-loopback"] {
		sev[f.Observed] = f.Severity
	}
	if sev["127.0.0.1"] != finding.Low || sev["169.254.169.254"] != finding.Medium {
		t.Errorf("HX-WL-021 in a hostNetwork pod: %v, want 127.0.0.1 low and 169.254.169.254 medium", sev)
	}
}
