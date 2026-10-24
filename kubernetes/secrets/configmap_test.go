package secrets

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

const pemKey = "-----BEGIN RSA PRIVATE KEY-----\nMIIEsupersecretmaterial\n-----END RSA PRIVATE KEY-----\n"

func TestConfigMapCredential(t *testing.T) {
	pemYAML := strings.ReplaceAll(pemKey, "\n", "\\n")
	y := `apiVersion: v1
kind: ConfigMap
metadata: {name: app, namespace: a}
data:
  DB_PASSWORD: hunter2-supersecret
  apiKey: abcdef-supersecret
  secretName: app-credentials
  token-endpoint: https://idp.example/token
  password.file: /etc/app/password
  passwordPolicy: strict
  admin-token: "${ADMIN_TOKEN}"
  log-level: debug
  tls.key: "` + pemYAML + `"
binaryData:
  signing: ` + base64.StdEncoding.EncodeToString([]byte(pemKey)) + `
---
apiVersion: v1
kind: ConfigMap
metadata: {name: kube-root-ca.crt, namespace: a}
data: {ca.crt: "-----BEGIN CERTIFICATE-----"}
---
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: a}
spec:
  containers:
    - name: c
      image: x
      env:
        - {name: TLS_KEY, value: "` + pemYAML + `"}
        - {name: GREETING, value: hello}
`
	inv, err := resource.Load([]string{"-"}, strings.NewReader(y))
	if err != nil {
		t.Fatal(err)
	}
	reg, _ := assessment.NewRegistry(configMapCredential)
	got := map[string]string{}
	for _, f := range assessment.Evaluate(inv, reg.All(), assessment.Options{}).Findings {
		got[f.Resource.Name+" "+f.Path] = f.Severity.String()
		for _, s := range []string{f.Message, f.Observed, f.Path} {
			if strings.Contains(s, "supersecret") || strings.Contains(s, "hunter2") {
				t.Errorf("secret material in a finding: %q", s)
			}
		}
	}
	want := map[string]string{
		"app data[DB_PASSWORD]":             "medium",
		"app data[apiKey]":                  "medium",
		"app data[tls.key]":                 "high",
		"app binaryData[signing]":           "high",
		"p spec.containers[0].env[0].value": "high",
	}
	for k, sev := range want {
		if got[k] != sev {
			t.Errorf("%s: %q, want %q", k, got[k], sev)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected finding %s", k)
		}
	}
}
