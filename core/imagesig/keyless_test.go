package imagesig

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/ManintheiCloud/Hardex/core/registry"
	"github.com/ManintheiCloud/Hardex/core/sigstore"
)

// The real keyless bundle of Hardex 0.4.0's SHA256SUMS signs that file's
// digest; served as a referrer of an "image" with the same digest, it
// exercises discovery and verification end to end.
func realBundle(t *testing.T) (digest string, bundle []byte) {
	t.Helper()
	sums, err := os.ReadFile("../sigstore/testdata/SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err = os.ReadFile("../sigstore/testdata/SHA256SUMS.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(sums)
	return "sha256:" + hex.EncodeToString(s[:]), bundle
}

func (f *fakeRegistry) attachBundle(repo, subject string, bundle []byte, viaAPI bool) {
	bd := digestOf(bundle)
	f.blobs[bd] = bundle
	man, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"artifactType": sigstore.BundleMediaType,
		"layers":       []any{map[string]any{"mediaType": sigstore.BundleMediaType, "digest": bd, "size": len(bundle)}},
		"subject":      map[string]any{"digest": subject}})
	md := digestOf(man)
	f.manifests[repo+":"+md] = man
	idx, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
		"manifests": []any{map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": md, "artifactType": sigstore.BundleMediaType}}})
	if viaAPI {
		f.referrers[repo+":"+subject] = idx
	} else {
		f.manifests[repo+":"+strings.Replace(subject, ":", "-", 1)] = idx
	}
}

var policy = sigstore.Policy{
	IdentityRegexp: regexp.MustCompile(`^https://github\.com/ManintheiCloud/Hardex/\.github/workflows/release\.yml@`),
	Issuer:         "https://token.actions.githubusercontent.com",
}

func TestVerifyKeyless(t *testing.T) {
	digest, bundle := realBundle(t)
	k := Keyless{Root: sigstore.PublicGood(), Policy: policy}
	for _, viaAPI := range []bool{true, false} {
		f := newFakeRegistry(t)
		f.attachBundle("app", digest, bundle, viaAPI)
		ref := registry.Ref{Registry: f.host(), Repository: "app"}
		if res := VerifyKeyless(context.Background(), f.client(), ref, digest, k); res.Status != Verified || !strings.Contains(res.Key, "release.yml") {
			t.Errorf("referrers API %v: %+v", viaAPI, res)
		}
	}

	f := newFakeRegistry(t)
	f.attachBundle("app", digest, bundle, true)
	ref := registry.Ref{Registry: f.host(), Repository: "app"}
	wrong := Keyless{Root: sigstore.PublicGood(), Policy: sigstore.Policy{Identity: "https://github.com/evil/x/.github/workflows/r.yml@refs/heads/main", Issuer: policy.Issuer}}
	if res := VerifyKeyless(context.Background(), f.client(), ref, digest, wrong); res.Status != Invalid {
		t.Errorf("wrong identity: %+v", res)
	}
	// A bundle attached to another digest must not verify this one.
	other := "sha256:" + strings.Repeat("ab", 32)
	f.attachBundle("app", other, bundle, true)
	if res := VerifyKeyless(context.Background(), f.client(), ref, other, k); res.Status != Invalid || !strings.Contains(res.Detail, "different artifact") {
		t.Errorf("bundle for another digest: %+v", res)
	}
	if res := VerifyKeyless(context.Background(), f.client(), registry.Ref{Registry: f.host(), Repository: "none"}, digest, k); res.Status != Unsigned {
		t.Errorf("unsigned: %+v", res)
	}
}

// The legacy annotation format carries the same material as a bundle; a
// round trip through it must still verify.
func TestLegacyBundle(t *testing.T) {
	digest, bundle := realBundle(t)
	var b struct {
		VerificationMaterial struct {
			Certificate struct{ RawBytes string } `json:"certificate"`
			TlogEntries []struct {
				LogIndex         string                 `json:"logIndex"`
				LogID            struct{ KeyID string } `json:"logId"`
				IntegratedTime   string                 `json:"integratedTime"`
				InclusionPromise struct {
					SignedEntryTimestamp string `json:"signedEntryTimestamp"`
				} `json:"inclusionPromise"`
				CanonicalizedBody string `json:"canonicalizedBody"`
			} `json:"tlogEntries"`
		} `json:"verificationMaterial"`
		MessageSignature struct{ Signature string } `json:"messageSignature"`
	}
	if err := json.Unmarshal(bundle, &b); err != nil {
		t.Fatal(err)
	}
	e := b.VerificationMaterial.TlogEntries[0]
	der, _ := base64.StdEncoding.DecodeString(b.VerificationMaterial.Certificate.RawBytes)
	id, _ := base64.StdEncoding.DecodeString(e.LogID.KeyID)
	rekor := `{"SignedEntryTimestamp":"` + e.InclusionPromise.SignedEntryTimestamp + `","Payload":{"body":"` + e.CanonicalizedBody +
		`","integratedTime":` + e.IntegratedTime + `,"logIndex":` + e.LogIndex + `,"logID":"` + hex.EncodeToString(id) + `"}}`
	ann := map[string]string{
		certificateAnnotation: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		bundleAnnotation:      rekor,
		signatureAnnotation:   b.MessageSignature.Signature,
	}
	converted, err := legacyBundle(ann)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
	if _, err := sigstore.Verify(converted, sigstore.Options{Root: sigstore.PublicGood(), Policy: policy, Digest: want}); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyKeylessPredicateType(t *testing.T) {
	digest, bundle := realBundle(t) // a message signature, not an attestation
	f := newFakeRegistry(t)
	f.attachBundle("app", digest, bundle, true)
	ref := registry.Ref{Registry: f.host(), Repository: "app"}
	any := VerifyKeyless(context.Background(), f.client(), ref, digest, Keyless{Root: sigstore.PublicGood(), Policy: policy})
	if any.Status != Verified || len(any.Verified) != 1 || !strings.HasPrefix(any.Verified[0], "signature by https://github.com/ManintheiCloud/Hardex/") {
		t.Errorf("any type: %+v", any)
	}
	want := VerifyKeyless(context.Background(), f.client(), ref, digest, Keyless{Root: sigstore.PublicGood(), Policy: policy, PredicateType: "https://slsa.dev/provenance/v1"})
	if want.Status != Invalid || !strings.Contains(want.Detail, "not an attestation of type https://slsa.dev/provenance/v1") {
		t.Errorf("required predicate: %+v", want)
	}
}
