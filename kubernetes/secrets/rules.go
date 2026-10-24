// Package secrets implements checks on how credentials are stored and passed
// to workloads.
//
// Every rule in this package must avoid copying secret material into
// findings: findings are written to terminals, CI logs and SARIF uploads.
package secrets

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	"github.com/ManintheiCloud/Hardex/baselines"
	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

// Rules returns every secrets rule.
func Rules() []assessment.Rule {
	return []assessment.Rule{inlineSecretData, literalEnvCredential, configMapCredential}
}

var refNSASecrets = baselines.NSA("Authentication and authorization — secrets")
var refCISSecrets = baselines.CIS("5.4", "Secrets Management")

// Secret types managed by Kubernetes or tooling rather than written by hand.
var managedSecretTypes = map[string]bool{
	"kubernetes.io/service-account-token": true,
	"helm.sh/release.v1":                  true,
	"bootstrap.kubernetes.io/token":       true,
}

var inlineSecretData = assessment.ObjectRule{
	Meta: assessment.Metadata{
		ID:          "HX-SEC-001",
		Title:       "Secret values in manifest",
		Severity:    finding.Medium,
		Category:    assessment.CategorySecrets,
		Description: "Detects Secret manifests that carry their values inline (data or stringData).",
		Rationale:   "Secret data is base64-encoded, not encrypted. A Secret manifest committed to version control exposes the credential to everyone with repository access, forever, including in history.",
		Remediation: "Keep secret values out of manifests: use an external secret store (e.g. via the Secrets Store CSI driver or an external-secrets operator) or encrypt them at rest in the repository (e.g. SOPS, sealed secrets).",
		References:  []finding.Reference{refNSASecrets, refCISSecrets},
		Limitations: "When scanning a live-cluster export, Secrets necessarily contain data; disable this rule for such scans.",
	},
	Kinds: []string{"Secret"},
	Check: func(ctx *assessment.Context, obj *resource.Object) {
		if managedSecretTypes[resource.String(obj.Raw, "type")] {
			return
		}
		n := len(resource.Map(obj.Raw, "data")) + len(resource.Map(obj.Raw, "stringData"))
		if n == 0 {
			return
		}
		ctx.Report(assessment.Hit{Object: obj, Path: "data", Observed: fmt.Sprintf("%d key(s), values redacted", n),
			Message: fmt.Sprintf("Secret carries %d value(s) inline", n)})
	},
}

// credentialWords are the name fragments that suggest a credential:
// passw(or)?d, secret, token, api[_-]?key, access[_-]?key, private[_-]?key,
// credential. Plain substring tests rather than a regexp: admission checks
// objects with thousands of variables and must stay fast (see
// integrations/admission/load_test.go).
var credentialWords = []string{"password", "passwd", "secret", "token", "apikey", "api_key", "api-key",
	"accesskey", "access_key", "access-key", "privatekey", "private_key", "private-key", "credential"}

// benignSuffixes conventionally hold non-secret values.
var benignSuffixes = []string{"_file", "_path", "_url", "_uri", "_endpoint", "_host", "_name", "_user", "_username",
	"_enabled", "_ttl", "_timeout", "_header"}

func credentialName(name string) bool {
	n := strings.ToLower(name)
	for _, w := range credentialWords {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}

func benignSuffix(name string) bool {
	n := strings.ToLower(name)
	for _, s := range benignSuffixes {
		if strings.HasSuffix(n, s) {
			return true
		}
	}
	return false
}

var literalEnvCredential = assessment.ObjectRule{
	Meta: assessment.Metadata{
		ID:          "HX-SEC-002",
		Title:       "Credential in environment variable literal",
		Severity:    finding.Medium,
		Category:    assessment.CategorySecrets,
		Description: "Detects container environment variables whose name suggests a credential and whose value is written literally in the manifest instead of referencing a Secret.",
		Rationale:   "Literal values live in the workload spec, which far more principals can read than Secrets (anyone with get on Deployments), and they are copied into version control and controller history.",
		Remediation: "Move the value into a Secret and reference it with env[].valueFrom.secretKeyRef, or mount it as a file.",
		References:  []finding.Reference{refNSASecrets, refCISSecrets},
		Limitations: "Name-based heuristic: credentials under unremarkable names are missed, and non-secret values under credential-like names may be reported. Values are never included in findings.",
	},
	Kinds: resource.WorkloadKinds(),
	Check: func(ctx *assessment.Context, obj *resource.Object) {
		pod, prefix := resource.PodSpec(obj)
		for _, c := range resource.Containers(pod) {
			for i, env := range resource.Maps(c.Spec, "env") {
				name := resource.String(env, "name")
				if resource.String(env, "value") == "" || !credentialName(name) || benignSuffix(name) {
					continue
				}
				ctx.Report(assessment.Hit{Object: obj, Container: c.Name,
					Path: fmt.Sprintf("%s.env[%d].value", c.Path(prefix), i), Observed: name + "=<redacted>",
					Message: fmt.Sprintf("container %q sets %s from a literal value", c.Name, name)})
			}
		}
	},
}

// benignKey is benignSuffix for ConfigMap keys, which are written with
// dashes, dots or camelCase (secretName, token-endpoint, password.file)
// rather than the _SUFFIX convention of environment variables.
func benignKey(key string) bool {
	n := strings.NewReplacer("-", "", ".", "", "_", "").Replace(strings.ToLower(key))
	for _, s := range benignSuffixes {
		if strings.HasSuffix(n, strings.TrimPrefix(s, "_")) {
			return true
		}
	}
	for _, s := range []string{"ref", "policy", "length", "lifetime", "expiry", "expiration", "rotation", "mode", "type", "store", "secretref"} {
		if strings.HasSuffix(n, s) {
			return true
		}
	}
	return false
}

// privateKeyPEM reports whether a value contains a PEM private key.
func privateKeyPEM(v string) bool {
	i := strings.Index(v, "-----BEGIN ")
	return i >= 0 && strings.Contains(v[i:], "PRIVATE KEY-----")
}

// placeholder reports values that are evidently not the credential itself.
func placeholder(v string) bool {
	t := strings.TrimSpace(v)
	switch {
	case t == "", t == `""`, t == "''", t == "changeme", t == "CHANGEME", t == "<redacted>", t == "REDACTED":
		return true
	case strings.HasPrefix(t, "${") || strings.HasPrefix(t, "{{") || strings.HasPrefix(t, "$("):
		return true // a template or variable, filled in elsewhere
	}
	return false
}

var configMapCredential = assessment.ObjectRule{
	Meta: assessment.Metadata{
		ID:          "HX-SEC-003",
		Title:       "Credential in a ConfigMap",
		Severity:    finding.Medium,
		Category:    assessment.CategorySecrets,
		Description: "Detects ConfigMap keys whose name suggests a credential and that hold a literal value, and any ConfigMap value or container environment literal that contains a PEM private key (high, whatever the name).",
		Rationale:   "ConfigMaps are readable by far more principals than Secrets: the default view role reads every ConfigMap in its namespace and no Secret, and ConfigMaps are not encrypted at rest by the usual API server configuration. A credential placed there is exposed to every viewer, and to everything that can read the manifests in version control.",
		Remediation: "Move the value into a Secret (and reference it with secretKeyRef or a secret volume); rotate it if the ConfigMap has been committed or applied.",
		References:  []finding.Reference{refNSASecrets, refCISSecrets, baselines.K8s("ConfigMaps: not for confidential data", "https://kubernetes.io/docs/concepts/configuration/configmap/")},
		Limitations: "Name-based heuristic for keys, as for HX-SEC-002; credentials inside configuration files stored under one key are found only if they contain a private key. Live-cluster scans do not read ConfigMaps (the reader role is kept minimal), so this applies to manifests. Values are never included in findings.",
	},
	Kinds: append([]string{"ConfigMap"}, resource.WorkloadKinds()...),
	Check: func(ctx *assessment.Context, obj *resource.Object) {
		if obj.Kind == "ConfigMap" {
			if obj.Name == "kube-root-ca.crt" {
				return
			}
			report := func(field, key, v string) {
				path := fmt.Sprintf("%s[%s]", field, key)
				switch {
				case privateKeyPEM(v):
					ctx.Report(assessment.Hit{Object: obj, Path: path, Observed: key + "=<private key>", Severity: assessment.SeverityOverride(finding.High),
						Message: fmt.Sprintf("ConfigMap key %s holds a private key", key)})
				case credentialName(key) && !benignKey(key) && !placeholder(v):
					ctx.Report(assessment.Hit{Object: obj, Path: path, Observed: key + "=<redacted>",
						Message: fmt.Sprintf("ConfigMap key %s looks like a credential", key)})
				}
			}
			for _, key := range sortedKeys(resource.Map(obj.Raw, "data")) {
				v, _ := resource.Map(obj.Raw, "data")[key].(string)
				report("data", key, v)
			}
			for _, key := range sortedKeys(resource.Map(obj.Raw, "binaryData")) {
				enc, _ := resource.Map(obj.Raw, "binaryData")[key].(string)
				if b, err := base64.StdEncoding.DecodeString(enc); err == nil {
					report("binaryData", key, string(b))
				}
			}
			return
		}
		pod, prefix := resource.PodSpec(obj)
		for _, c := range resource.Containers(pod) {
			for i, env := range resource.Maps(c.Spec, "env") {
				if v := resource.String(env, "value"); privateKeyPEM(v) {
					name := resource.String(env, "name")
					ctx.Report(assessment.Hit{Object: obj, Container: c.Name, Severity: assessment.SeverityOverride(finding.High),
						Path: fmt.Sprintf("%s.env[%d].value", c.Path(prefix), i), Observed: name + "=<private key>",
						Message: fmt.Sprintf("container %q has a private key in the literal value of %s", c.Name, name)})
				}
			}
		}
	},
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
