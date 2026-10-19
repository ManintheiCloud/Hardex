package sigstore

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	conformanceIdentity = "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main"
	conformanceIssuer   = "https://token.actions.githubusercontent.com"
)

// TestConformance runs the Sigstore project's client conformance vectors
// (testdata/conformance, see SOURCE.md).
func TestConformance(t *testing.T) {
	base := "testdata/conformance"
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	defaultArtifact, err := os.ReadFile(filepath.Join(base, "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	ran := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(base, e.Name())
		t.Run(e.Name(), func(t *testing.T) {
			if _, err := os.Stat(filepath.Join(dir, "key.pub")); err == nil {
				t.Skip("managed-key bundle; key-based verification is out of scope here")
			}
			read := func(name string, def []byte) []byte {
				b, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil {
					return def
				}
				return b
			}
			artifact := read("artifact", defaultArtifact)
			identity := strings.TrimSpace(string(read("identity", []byte(conformanceIdentity))))
			issuer := strings.TrimSpace(string(read("issuer", []byte(conformanceIssuer))))
			root := PublicGood()
			if raw, err := os.ReadFile(filepath.Join(dir, "trusted_root.json")); err == nil {
				if root, err = ParseTrustedRoot(raw); err != nil {
					if strings.HasSuffix(e.Name(), "_fail") {
						return // an unusable trusted root is a correct rejection
					}
					t.Fatalf("trusted root: %v", err)
				}
			}
			bundle := read("bundle.sigstore.json", nil)
			digest := sha256.Sum256(artifact)
			opts := Options{Root: root, Policy: Policy{Identity: identity, Issuer: issuer}, Digest: digest[:]}
			// For DSSE cases the artifact is the attestation subject; for
			// in-toto subjects named by digest, the digest is what matters.
			_, err := Verify(bundle, opts)
			if strings.HasSuffix(e.Name(), "_fail") {
				if err == nil {
					t.Errorf("verified; expected rejection (%s)", readme(dir))
				} else {
					t.Logf("rejected: %v", err)
				}
				return
			}
			if err != nil {
				t.Errorf("rejected: %v (%s)", err, readme(dir))
			}
		})
		ran++
	}
	if ran < 60 {
		t.Fatalf("only %d conformance cases found", ran)
	}
}

func readme(dir string) string {
	b, _ := os.ReadFile(filepath.Join(dir, "README"))
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

var _ = json.Marshal
