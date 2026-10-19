package sigstore

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// testdata holds the real checksum file and keyless bundle of Hardex
// release 0.4.0, signed by the release workflow on GitHub Actions.
func release(t *testing.T) ([]byte, []byte) {
	t.Helper()
	sums, err := os.ReadFile("testdata/SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := os.ReadFile("testdata/SHA256SUMS.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}
	return sums, bundle
}

var releasePolicy = Policy{
	IdentityRegexp: regexp.MustCompile(`^https://github\.com/ManintheiCloud/Hardex/\.github/workflows/release\.yml@refs/(tags/v|heads/main)`),
	Issuer:         "https://token.actions.githubusercontent.com",
}

func TestVerifyRealBundle(t *testing.T) {
	sums, bundle := release(t)
	d := sha256.Sum256(sums)
	res, err := Verify(bundle, Options{Root: PublicGood(), Policy: releasePolicy, Digest: d[:]})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Identity, "release.yml") || res.Issuer != releasePolicy.Issuer {
		t.Errorf("identity %q issuer %q", res.Identity, res.Issuer)
	}
	if len(res.TimeSources) != 2 {
		t.Errorf("time sources = %v; want the log and the TSA", res.TimeSources)
	}
	t.Logf("%+v", res)
}

func mutate(t *testing.T, bundle []byte, f func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(bundle, &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	out, _ := json.Marshal(m)
	return out
}

func flip(b64 string) string {
	raw, _ := base64.StdEncoding.DecodeString(b64)
	raw[len(raw)/2] ^= 1
	return base64.StdEncoding.EncodeToString(raw)
}

func vm(m map[string]any) map[string]any { return m["verificationMaterial"].(map[string]any) }
func entry(m map[string]any) map[string]any {
	return vm(m)["tlogEntries"].([]any)[0].(map[string]any)
}

func TestVerifyRejects(t *testing.T) {
	sums, bundle := release(t)
	d := sha256.Sum256(sums)
	root := PublicGood()
	cases := map[string]struct {
		bundle []byte
		digest []byte
		policy Policy
		want   string
	}{
		"other artifact": {bundle, func() []byte { x := sha256.Sum256([]byte("x")); return x[:] }(), releasePolicy, "different artifact"},
		"other identity": {bundle, d[:], Policy{Identity: "https://github.com/evil/repo/.github/workflows/release.yml@refs/heads/main", Issuer: releasePolicy.Issuer}, "does not match the required identity"},
		"other issuer":   {bundle, d[:], Policy{IdentityRegexp: releasePolicy.IdentityRegexp, Issuer: "https://accounts.google.com"}, "OIDC issuer"},
		"no policy":      {bundle, d[:], Policy{}, "policy needs"},
		"bad signature": {mutate(t, bundle, func(m map[string]any) {
			ms := m["messageSignature"].(map[string]any)
			ms["signature"] = flip(ms["signature"].(string))
		}), d[:], releasePolicy, "signature does not verify"},
		"bad SET and proof": {mutate(t, bundle, func(m map[string]any) {
			e := entry(m)
			p := e["inclusionPromise"].(map[string]any)
			p["signedEntryTimestamp"] = flip(p["signedEntryTimestamp"].(string))
		}), d[:], releasePolicy, "signed entry timestamp does not verify"},
		"bad inclusion proof": {mutate(t, bundle, func(m map[string]any) {
			p := entry(m)["inclusionProof"].(map[string]any)
			h := p["hashes"].([]any)
			h[0] = flip(h[0].(string))
		}), d[:], releasePolicy, "inclusion proof"},
		"forged checkpoint": {mutate(t, bundle, func(m map[string]any) {
			p := entry(m)["inclusionProof"].(map[string]any)
			cp := p["checkpoint"].(map[string]any)
			env := cp["envelope"].(string)
			i := strings.LastIndex(env, " ")
			cp["envelope"] = env[:i+1] + flip(strings.TrimSpace(env[i+1:])) + "\n"
		}), d[:], releasePolicy, "checkpoint"},
		"bad timestamp": {mutate(t, bundle, func(m map[string]any) {
			ts := vm(m)["timestampVerificationData"].(map[string]any)["rfc3161Timestamps"].([]any)[0].(map[string]any)
			raw, _ := base64.StdEncoding.DecodeString(ts["signedTimestamp"].(string))
			raw[len(raw)-10] ^= 1
			ts["signedTimestamp"] = base64.StdEncoding.EncodeToString(raw)
		}), d[:], releasePolicy, "timestamp"},
		"unknown log": {mutate(t, bundle, func(m map[string]any) {
			entry(m)["logId"] = map[string]any{"keyId": base64.StdEncoding.EncodeToString(make([]byte, 32))}
		}), d[:], releasePolicy, "not in the trusted root"},
		"no log entry": {mutate(t, bundle, func(m map[string]any) {
			vm(m)["tlogEntries"] = []any{}
		}), d[:], releasePolicy, "no transparency log entry"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Verify(c.bundle, Options{Root: root, Policy: c.policy, Digest: c.digest})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v; want %q", err, c.want)
			}
		})
	}
}

func TestSETAloneSuffices(t *testing.T) {
	sums, bundle := release(t)
	d := sha256.Sum256(sums)
	// A signed entry timestamp without an inclusion proof is accepted only
	// in v0.1 bundles (as cosign's legacy format produces).
	b := mutate(t, bundle, func(m map[string]any) {
		delete(entry(m), "inclusionProof")
		delete(vm(m), "timestampVerificationData")
	})
	if _, err := Verify(b, Options{Root: PublicGood(), Policy: releasePolicy, Digest: d[:]}); err == nil || !strings.Contains(err.Error(), "no inclusion proof") {
		t.Errorf("v0.3 bundle without inclusion proof: %v", err)
	}
	b = mutate(t, b, func(m map[string]any) { m["mediaType"] = "application/vnd.dev.sigstore.bundle+json;version=0.1" })
	if _, err := Verify(b, Options{Root: PublicGood(), Policy: releasePolicy, Digest: d[:]}); err != nil {
		t.Fatal(err)
	}
	// Without the SET and without a timestamp there is no trusted time.
	b = mutate(t, bundle, func(m map[string]any) {
		delete(entry(m), "inclusionPromise")
		delete(vm(m), "timestampVerificationData")
	})
	if _, err := Verify(b, Options{Root: PublicGood(), Policy: releasePolicy, Digest: d[:]}); err == nil || !strings.Contains(err.Error(), "no verified signing time") {
		t.Errorf("err = %v", err)
	}
}

func TestInclusionProofVectors(t *testing.T) {
	// A three-leaf tree: root = H(H(l0,l1), l2).
	leaf := func(s string) []byte { h := sha256.Sum256(append([]byte{0}, s...)); return h[:] }
	l0, l1, l2 := leaf("a"), leaf("b"), leaf("c")
	n01 := hashChildren(l0, l1)
	root := hashChildren(n01, l2)
	if err := verifyInclusion(2, 3, l2, [][]byte{n01}, root); err != nil {
		t.Error(err)
	}
	if err := verifyInclusion(0, 3, l0, [][]byte{l1, l2}, root); err != nil {
		t.Error(err)
	}
	if err := verifyInclusion(1, 3, l0, [][]byte{l1, l2}, root); err == nil {
		t.Error("wrong index accepted")
	}
	if err := verifyInclusion(3, 3, l2, nil, root); err == nil {
		t.Error("index outside tree accepted")
	}
}

func TestSCT(t *testing.T) {
	_, bundle := release(t)
	var b bundleJSON
	if err := json.Unmarshal(bundle, &b); err != nil {
		t.Fatal(err)
	}
	der, _ := base64.StdEncoding.DecodeString(b.VerificationMaterial.Certificate.RawBytes)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	root := PublicGood()
	chain, err := verifyChain(cert, root, cert.NotBefore.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySCT(cert, chain[1], root); err != nil {
		t.Errorf("valid SCT rejected: %v", err)
	}
	if err := verifySCT(cert, cert, root); err == nil {
		t.Error("SCT verified with the wrong issuer key hash")
	}
	noCT := *root
	noCT.CTLogs = nil
	if err := verifySCT(cert, chain[1], &noCT); err == nil {
		t.Error("SCT verified without a trusted CT log")
	}
	// Outside the certificate's 10-minute validity the chain must fail.
	if _, err := verifyChain(cert, root, cert.NotAfter.Add(time.Minute)); err == nil {
		t.Error("expired certificate accepted")
	}
}

// Bundles come from registries and release pages: malformed input must be
// rejected without panicking, and nothing but the real bundle may verify.
func FuzzVerify(f *testing.F) {
	sums, bundle := func() ([]byte, []byte) {
		s, _ := os.ReadFile("testdata/SHA256SUMS")
		b, _ := os.ReadFile("testdata/SHA256SUMS.sigstore.json")
		return s, b
	}()
	f.Add(bundle)
	f.Add([]byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`))
	d := sha256.Sum256(sums)
	root := PublicGood()
	f.Fuzz(func(t *testing.T, b []byte) {
		if _, err := Verify(b, Options{Root: root, Policy: releasePolicy, Digest: d[:]}); err == nil && !bytes.Equal(b, bundle) {
			// Re-encodings of the same bundle are fine; anything else that
			// verifies must at least carry the same signature.
			var got, want bundleJSON
			json.Unmarshal(b, &got)
			json.Unmarshal(bundle, &want)
			if got.MessageSignature == nil || got.MessageSignature.Signature != want.MessageSignature.Signature {
				t.Fatalf("a different bundle verified: %q", b)
			}
		}
	})
}

func FuzzRFC3161(f *testing.F) {
	_, bundle := release(&testing.T{})
	var b bundleJSON
	json.Unmarshal(bundle, &b)
	ts, _ := base64.StdEncoding.DecodeString(b.VerificationMaterial.TimestampVerificationData.RFC3161Timestamps[0].SignedTimestamp)
	f.Add(ts)
	root := PublicGood()
	f.Fuzz(func(t *testing.T, raw []byte) { verifyRFC3161(raw, []byte("sig"), root) })
}

func BenchmarkVerify(b *testing.B) {
	sums, bundle := release(&testing.T{})
	d := sha256.Sum256(sums)
	root := PublicGood()
	for i := 0; i < b.N; i++ {
		if _, err := Verify(bundle, Options{Root: root, Policy: releasePolicy, Digest: d[:]}); err != nil {
			b.Fatal(err)
		}
	}
}
