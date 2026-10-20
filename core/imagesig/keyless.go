package imagesig

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/ManintheiCloud/Hardex/core/registry"
	"github.com/ManintheiCloud/Hardex/core/sigstore"
)

// Annotations of cosign's legacy keyless signature format.
const (
	certificateAnnotation = "dev.sigstore.cosign/certificate"
	bundleAnnotation      = "dev.sigstore.cosign/bundle"
	timestampAnnotation   = "dev.sigstore.cosign/rfc3161timestamp"
)

// Keyless configures keyless (Fulcio/Rekor) verification.
type Keyless struct {
	Root   *sigstore.TrustedRoot
	Policy sigstore.Policy
	// PredicateType, if set, accepts only DSSE attestations of that type
	// (e.g. https://slsa.dev/provenance/v1, or cosign v3's image signature
	// https://sigstore.dev/cosign/sign/v1); message signatures and legacy
	// cosign signatures then do not count.
	PredicateType string
}

// VerifyKeyless looks for Sigstore signatures of the image digest — bundles
// attached as OCI referrers (cosign v3 and GitHub attestations), and
// cosign's legacy ".sig" tag with certificate annotations — and verifies
// them completely offline against the trusted root and identity policy.
func VerifyKeyless(ctx context.Context, c *registry.Client, ref registry.Ref, digest string, k Keyless) Result {
	want, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
	if err != nil || !strings.HasPrefix(digest, "sha256:") || len(want) != sha256.Size {
		return Result{Status: Error, Detail: "unsupported digest " + digest}
	}
	reasons := map[string]bool{}
	found := false
	var ok []*sigstore.Result

	// 1. Sigstore bundles as OCI referrers.
	refs, err := c.Referrers(ctx, ref.Registry, ref.Repository, digest)
	if err != nil {
		return Result{Status: Error, Detail: "referrers: " + err.Error()}
	}
	opened := 0
	for _, d := range refs {
		// The listing's artifactType is a hint: cosign v3 publishes its
		// signature with an empty config, which the referrers tag schema
		// lists as application/vnd.oci.empty.v1+json. Open those too and
		// decide by the layers; skip only artifacts declared as something
		// else (SBOMs, provenance in other formats).
		if !isBundleType(d.ArtifactType) && d.ArtifactType != "" && d.ArtifactType != emptyArtifact {
			continue
		}
		if opened++; opened > maxReferrers {
			reasons[fmt.Sprintf("more than %d candidate referrers; the rest were not checked", maxReferrers)] = true
			break
		}
		m, err := c.GetManifest(ctx, ref.Registry, ref.Repository, d.Digest)
		if err != nil {
			reasons["bundle manifest unavailable: "+err.Error()] = true
			continue
		}
		var man registry.Index
		if err := json.Unmarshal(m.Body, &man); err != nil {
			reasons["bundle manifest is not valid JSON"] = true
			continue
		}
		for _, layer := range man.Layers {
			if !isBundleType(layer.MediaType) {
				continue
			}
			found = true
			blob, err := c.GetBlob(ctx, ref.Registry, ref.Repository, layer.Digest)
			if err != nil {
				reasons["bundle unavailable: "+err.Error()] = true
				continue
			}
			res, err := sigstore.Verify(blob, sigstore.Options{Root: k.Root, Policy: k.Policy, Digest: want, PredicateType: k.PredicateType})
			if err == nil && k.PredicateType != "" && res.Statement == nil {
				err = errors.New("message signature, not an attestation of type " + k.PredicateType)
			}
			if err != nil {
				reasons[err.Error()] = true
				continue
			}
			ok = append(ok, res)
		}
	}

	// 2. Legacy cosign keyless signatures.
	sigTag := strings.Replace(digest, ":", "-", 1) + ".sig"
	m, err := c.GetManifest(ctx, ref.Registry, ref.Repository, sigTag)
	switch {
	case errors.Is(err, registry.ErrNotFound):
	case err != nil:
		reasons["signature manifest unavailable: "+err.Error()] = true
	default:
		var man ociManifest
		if err := json.Unmarshal(m.Body, &man); err != nil {
			reasons["signature manifest is not valid JSON"] = true
			break
		}
		for _, layer := range man.Layers {
			if layer.Annotations[certificateAnnotation] == "" {
				continue
			}
			found = true
			if k.PredicateType != "" {
				reasons["legacy cosign signature, not an attestation of type "+k.PredicateType] = true
				continue
			}
			res, err := verifyLegacy(ctx, c, ref, digest, layer.Digest, layer.Annotations, k)
			if err != nil {
				reasons[err.Error()] = true
				continue
			}
			ok = append(ok, res)
		}
	}

	if len(ok) > 0 {
		return verified(ok)
	}
	if !found && len(reasons) == 0 {
		return Result{Status: Unsigned, Detail: "no Sigstore signature found"}
	}
	var list []string
	for r := range reasons {
		list = append(list, r)
	}
	sort.Strings(list)
	return Result{Status: Invalid, Detail: strings.Join(list, "; ")}
}

const (
	emptyArtifact = "application/vnd.oci.empty.v1+json"
	// maxReferrers bounds the manifests fetched per image, so a registry
	// cannot make verification arbitrarily slow.
	maxReferrers = 32
)

func isBundleType(t string) bool {
	return t == sigstore.BundleMediaType || strings.HasPrefix(t, "application/vnd.dev.sigstore.bundle+json")
}

func describe(r *sigstore.Result) string {
	kind := "signature"
	if r.Statement != nil && r.Statement.PredicateType != "" {
		kind = r.Statement.PredicateType
	}
	return fmt.Sprintf("%s by %s (Rekor log index %d, signed %s)", kind, r.Identity, r.LogIndex, r.SigningTime.Format("2006-01-02T15:04:05Z"))
}

func verified(rs []*sigstore.Result) Result {
	r := rs[0]
	signer := r.Identity
	if r.Statement != nil && r.Statement.PredicateType != "" {
		signer += " (" + r.Statement.PredicateType + ")"
	}
	out := Result{Status: Verified, Key: signer, Detail: fmt.Sprintf("%d verified", len(rs))}
	for _, x := range rs {
		out.Verified = append(out.Verified, describe(x))
	}
	sort.Strings(out.Verified)
	return out
}

// verifyLegacy converts cosign's annotation-based keyless signature into a
// bundle and verifies it; the signed payload must then name the digest.
func verifyLegacy(ctx context.Context, c *registry.Client, ref registry.Ref, digest, payloadDigest string, ann map[string]string, k Keyless) (*sigstore.Result, error) {
	payload, err := c.GetBlob(ctx, ref.Registry, ref.Repository, payloadDigest)
	if err != nil {
		return nil, fmt.Errorf("payload unavailable: %w", err)
	}
	var ss simpleSigning
	if err := json.Unmarshal(payload, &ss); err != nil || ss.Critical.Type != payloadType {
		return nil, errors.New("payload is not a cosign image signature")
	}
	if ss.Critical.Image.DockerManifestDigest != digest {
		return nil, errors.New("signature is for a different digest")
	}
	bundle, err := legacyBundle(ann)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(payload)
	return sigstore.Verify(bundle, sigstore.Options{Root: k.Root, Policy: k.Policy, Digest: sum[:]})
}

func legacyBundle(ann map[string]string) ([]byte, error) {
	cert := ann[certificateAnnotation]
	der, err := pemDER(cert)
	if err != nil {
		return nil, err
	}
	var rekor struct {
		SignedEntryTimestamp string `json:"SignedEntryTimestamp"`
		Payload              struct {
			Body           string `json:"body"`
			IntegratedTime int64  `json:"integratedTime"`
			LogIndex       int64  `json:"logIndex"`
			LogID          string `json:"logID"`
		} `json:"Payload"`
	}
	if err := json.Unmarshal([]byte(ann[bundleAnnotation]), &rekor); err != nil {
		return nil, errors.New("legacy signature has no Rekor bundle")
	}
	logID, err := hex.DecodeString(rekor.Payload.LogID)
	if err != nil {
		return nil, errors.New("malformed Rekor log ID")
	}
	body, err := base64.StdEncoding.DecodeString(rekor.Payload.Body)
	if err != nil {
		return nil, errors.New("malformed Rekor entry")
	}
	var kv struct {
		Kind       string `json:"kind"`
		APIVersion string `json:"apiVersion"`
	}
	json.Unmarshal(body, &kv)
	b := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
		"verificationMaterial": map[string]any{
			"x509CertificateChain": map[string]any{"certificates": []any{map[string]any{"rawBytes": base64.StdEncoding.EncodeToString(der)}}},
			"tlogEntries": []any{map[string]any{
				"logIndex":          fmt.Sprint(rekor.Payload.LogIndex),
				"logId":             map[string]any{"keyId": base64.StdEncoding.EncodeToString(logID)},
				"kindVersion":       map[string]any{"kind": kv.Kind, "version": kv.APIVersion},
				"integratedTime":    fmt.Sprint(rekor.Payload.IntegratedTime),
				"inclusionPromise":  map[string]any{"signedEntryTimestamp": rekor.SignedEntryTimestamp},
				"canonicalizedBody": rekor.Payload.Body,
			}},
		},
		"messageSignature": map[string]any{"signature": ann[signatureAnnotation]},
	}
	if ts := ann[timestampAnnotation]; ts != "" {
		var t struct {
			SignedRFC3161Timestamp string `json:"SignedRFC3161Timestamp"`
		}
		if json.Unmarshal([]byte(ts), &t) == nil && t.SignedRFC3161Timestamp != "" {
			b["verificationMaterial"].(map[string]any)["timestampVerificationData"] = map[string]any{
				"rfc3161Timestamps": []any{map[string]any{"signedTimestamp": t.SignedRFC3161Timestamp}}}
		}
	}
	return json.Marshal(b)
}

func pemDER(p string) ([]byte, error) {
	block, _ := pem.Decode([]byte(p))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("legacy signature certificate is not PEM")
	}
	return block.Bytes, nil
}
