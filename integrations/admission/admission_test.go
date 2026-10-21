package admission

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ManintheiCloud/Hardex/baselines"
	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/policy"
	"github.com/ManintheiCloud/Hardex/kubernetes"
)

func handler(t *testing.T, mode Mode, cfgYAML string) *Handler {
	t.Helper()
	reg, _ := kubernetes.Registry()
	prof, _ := baselines.Profile("restricted")
	cfg := policy.DefaultConfig()
	if cfgYAML != "" {
		var err error
		if cfg, err = policy.ParseConfig([]byte(cfgYAML)); err != nil {
			t.Fatal(err)
		}
	} else {
		cfg.Validate()
	}
	rules, _, err := policy.SelectRules(reg, prof, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &Handler{Rules: AdmissionOnly(rules), Config: cfg, Mode: mode, Threshold: finding.High, Log: &bytes.Buffer{}}
}

const privilegedPod = `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"bad"},"spec":{"containers":[{"name":"c","image":"x:1","securityContext":{"privileged":true}}]}}`

const compliantPod = `{"apiVersion":"v1","kind":"Pod","metadata":{"generateName":"ok-"},"spec":{
 "automountServiceAccountToken":false,
 "securityContext":{"runAsNonRoot":true,"seccompProfile":{"type":"RuntimeDefault"}},
 "containers":[{"name":"c","image":"r.example.com/a:1@sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
  "resources":{"limits":{"cpu":"1","memory":"1Gi"}},
  "securityContext":{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}}}]}}`

func send(t *testing.T, h http.Handler, op, object string) (int, map[string]any) {
	t.Helper()
	body := `{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"u-1","kind":{"group":"","version":"v1","kind":"Pod"},"namespace":"shop","operation":"` + op + `","object":` + object + `}}`
	req := httptest.NewRequest(http.MethodPost, "/validate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func resp(out map[string]any) map[string]any {
	r, _ := out["response"].(map[string]any)
	return r
}

func TestEnforceDeniesAndUsesWireFormat(t *testing.T) {
	code, out := send(t, handler(t, Enforce, ""), "CREATE", privilegedPod)
	r := resp(out)
	if code != 200 || out["apiVersion"] != "admission.k8s.io/v1" || out["kind"] != "AdmissionReview" || r == nil {
		t.Fatalf("bad envelope (keys must be lowercase): %v", out)
	}
	if r["uid"] != "u-1" || r["allowed"] != false {
		t.Fatalf("privileged pod admitted: %v", r)
	}
	msg := r["status"].(map[string]any)["message"].(string)
	if !strings.Contains(msg, "HX-WL-001") {
		t.Errorf("message = %s", msg)
	}
}

func TestCompliantPodAdmittedWithoutContextRules(t *testing.T) {
	_, out := send(t, handler(t, Enforce, ""), "CREATE", compliantPod)
	r := resp(out)
	if r["allowed"] != true {
		t.Fatalf("compliant pod denied: %v", r)
	}
	// NeedsInventory rules (e.g. HX-NET-001, which cannot see the namespace's
	// NetworkPolicies) must not run at admission.
	if ws, _ := r["warnings"].([]any); len(ws) > 0 {
		t.Errorf("unexpected warnings: %v", ws)
	}
}

func TestWarnAndAuditModesAdmit(t *testing.T) {
	_, out := send(t, handler(t, Warn, ""), "CREATE", privilegedPod)
	r := resp(out)
	if r["allowed"] != true || len(r["warnings"].([]any)) == 0 {
		t.Errorf("warn mode: %v", r)
	}
	h := handler(t, Audit, "")
	_, out = send(t, h, "CREATE", privilegedPod)
	if r := resp(out); r["allowed"] != true || r["warnings"] != nil {
		t.Errorf("audit mode: %v", r)
	}
	if !strings.Contains(h.Log.(*bytes.Buffer).String(), `"HX-WL-001"`) {
		t.Error("audit decision not logged")
	}
}

func TestDeleteAndMalformed(t *testing.T) {
	h := handler(t, Enforce, "")
	if _, out := send(t, h, "DELETE", privilegedPod); resp(out)["allowed"] != true {
		t.Error("DELETE should always be admitted")
	}
	if _, out := send(t, h, "CREATE", `"not an object"`); resp(out)["allowed"] != false {
		t.Error("unevaluable object admitted in enforce mode (must fail closed)")
	}
	req := httptest.NewRequest(http.MethodPost, "/validate", strings.NewReader("{"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("malformed review: %d", rec.Code)
	}
}

func TestWaiversApplyAtAdmission(t *testing.T) {
	h := handler(t, Enforce, `apiVersion: hardex.dev/v1alpha1
kind: HardexConfig
waivers:
  - {rule: HX-WL-001, namespace: shop, name: bad, justification: test, expires: "2999-01-01"}
`)
	if _, out := send(t, h, "CREATE", privilegedPod); resp(out)["allowed"] != true {
		t.Errorf("waived finding still denied: %v", resp(out))
	}
}

func TestCertificateReload(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	write := func(cn string) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		kd, _ := x509.MarshalECPrivateKey(key)
		os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
		os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600)
	}
	write("first")
	r, err := newCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	cn := func() string {
		c, _ := r.get(&tls.ClientHelloInfo{})
		leaf, _ := x509.ParseCertificate(c.Certificate[0])
		return leaf.Subject.CommonName
	}
	if cn() != "first" {
		t.Fatal("initial certificate not served")
	}
	write("second")
	future := time.Now().Add(time.Minute)
	os.Chtimes(certFile, future, future)
	r.checked = time.Time{} // skip the 10s re-check interval
	if cn() != "second" {
		t.Error("rotated certificate not picked up")
	}
	os.WriteFile(keyFile, []byte("garbage"), 0o600)
	os.Chtimes(certFile, future.Add(time.Minute), future.Add(time.Minute))
	r.checked = time.Time{}
	if cn() != "second" {
		t.Error("a broken rotation must keep serving the last good certificate")
	}
}

// kubectl debug goes through the pods/ephemeralcontainers subresource: a
// privileged debug container is denied, and only the ephemeral containers
// are judged (the rest of the Pod was admitted already).
func TestEphemeralContainersSubresource(t *testing.T) {
	h := handler(t, Enforce, "")
	sub := func(object string) map[string]any {
		body := `{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"u-2","kind":{"group":"","version":"v1","kind":"Pod"},"subResource":"ephemeralcontainers","namespace":"shop","name":"web","operation":"UPDATE","object":` + object + `}}`
		req := httptest.NewRequest(http.MethodPost, "/validate", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		return resp(out)
	}
	// An already-running Pod with a privileged container (admitted earlier,
	// or from an excluded period) gets a harmless debug container: allowed.
	harmless := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"web"},"spec":{
	 "containers":[{"name":"c","image":"x:1","securityContext":{"privileged":true}}],
	 "ephemeralContainers":[{"name":"dbg","image":"busybox","securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}}]}}`
	if r := sub(harmless); r["allowed"] != true {
		t.Errorf("harmless debug container denied because of the Pod's own containers: %v", r)
	}
	privileged := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"web"},"spec":{
	 "containers":[{"name":"c","image":"x:1"}],
	 "ephemeralContainers":[{"name":"dbg","image":"busybox","securityContext":{"privileged":true}}]}}`
	r := sub(privileged)
	if r["allowed"] != false {
		t.Fatalf("privileged debug container admitted: %v", r)
	}
	if msg := r["status"].(map[string]any)["message"].(string); !strings.Contains(msg, "HX-WL-001") {
		t.Errorf("message = %s", msg)
	}
}
