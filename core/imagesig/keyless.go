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

	// 1. Sigstore bundles as OCI referrers.
	refs, err := c.Referrers(ctx, ref.Registry, ref.Repository, digest)
	if err != nil {
		return Result{Status: Error, Detail: "referrers: " + err.Error()}
	}
	for _, d := range refs {
		if !isBundleType(d.ArtifactType) {
			continue
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
			res, err := sigstore.Verify(blob, sigstore.Options{Root: k.Root, Policy: k.Policy, Digest: want})
			if err != nil {
				reasons[err.Error()] = true
				continue
			}
			return verified(res)
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
			res, err := verifyLegacy(ctx, c, ref, digest, layer.Digest, layer.Annotations, k)
			if err != nil {
				reasons[err.Error()] = true
				continue
			}
			return verified(res)
		}
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

func isBundleType(t string) bool {
	return t == sigstore.BundleMediaType || strings.HasPrefix(t, "application/vnd.dev.sigstore.bundle+json")
}

func verified(r *sigstore.Result) Result {
	signer := r.Identity
	if r.Statement != nil && r.Statement.PredicateType != "" {
		signer += " (" + r.Statement.PredicateType + ")"
	}
	return Result{Status: Verified, Key: signer, Detail: fmt.Sprintf("Rekor log index %d, signed %s", r.LogIndex, r.SigningTime.Format("2006-01-02T15:04:05Z"))}
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
