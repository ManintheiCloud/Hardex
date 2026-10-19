// Package imagesig verifies container image signatures made with a cosign
// key pair (cosign sign --key), using the signature format cosign stores
// next to the image (tag "sha256-<digest>.sig").
//
// Keyless (Fulcio/Rekor) signatures and the newer Sigstore bundle format
// stored as OCI referrers are reported as "not verified here"; verify those
// with cosign or enforce them at admission with a Sigstore policy
// controller. Hardex never reports an image as verified unless a signature
// over that exact digest checks out against a trusted key.
package imagesig

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ManintheiCloud/Hardex/core/registry"
)

const (
	signatureAnnotation = "dev.cosignproject.cosign/signature"
	payloadType         = "cosign container image signature"
)

// PublicKey is a trusted verification key.
type PublicKey struct {
	Name string
	key  crypto.PublicKey
}

// LoadPublicKey reads a PEM public key (as written by cosign generate-key-pair).
func LoadPublicKey(path string) (*PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePublicKey(path, data)
}

// ParsePublicKey parses PEM-encoded PKIX ECDSA, Ed25519 or RSA public keys.
func ParsePublicKey(name string, data []byte) (*PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("%s: expected a PEM \"PUBLIC KEY\" block", name)
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	switch k.(type) {
	case *ecdsa.PublicKey, ed25519.PublicKey, *rsa.PublicKey:
	default:
		return nil, fmt.Errorf("%s: unsupported key type %T", name, k)
	}
	return &PublicKey{Name: name, key: k}, nil
}

func (p *PublicKey) verify(payload, sig []byte) bool {
	digest := sha256.Sum256(payload)
	switch k := p.key.(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(k, digest[:], sig)
	case ed25519.PublicKey:
		return ed25519.Verify(k, payload, sig)
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig) == nil
	}
	return false
}

// Status of an image signature check.
type Status string

const (
	Verified Status = "verified"
	Unsigned Status = "unsigned" // no key-based cosign signature found
	Invalid  Status = "invalid"  // signatures exist but none verify for this digest
	Error    Status = "error"    // the check could not be completed
)

// Result is the outcome for one image digest.
type Result struct {
	Status Status `json:"status"`
	Key    string `json:"key,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type ociManifest struct {
	Layers []struct {
		MediaType   string            `json:"mediaType"`
		Digest      string            `json:"digest"`
		Annotations map[string]string `json:"annotations"`
	} `json:"layers"`
}

type simpleSigning struct {
	Critical struct {
		Identity struct {
			DockerReference string `json:"docker-reference"`
		} `json:"identity"`
		Image struct {
			DockerManifestDigest string `json:"docker-manifest-digest"`
		} `json:"image"`
		Type string `json:"type"`
	} `json:"critical"`
}

// Verify checks the signatures of the image at ref (registry/repository)
// with the given digest against the trusted keys.
func Verify(ctx context.Context, c *registry.Client, ref registry.Ref, digest string, keys []*PublicKey) Result {
	if len(keys) == 0 {
		return Result{Status: Error, Detail: "no trusted keys"}
	}
	sigTag := strings.Replace(digest, ":", "-", 1) + ".sig"
	m, err := c.GetManifest(ctx, ref.Registry, ref.Repository, sigTag)
	if errors.Is(err, registry.ErrNotFound) {
		return Result{Status: Unsigned, Detail: "no cosign key-based signature found (keyless/bundle signatures are not verified here)"}
	}
	if err != nil {
		return Result{Status: Error, Detail: err.Error()}
	}
	var man ociManifest
	if err := json.Unmarshal(m.Body, &man); err != nil {
		return Result{Status: Error, Detail: "signature manifest is not valid JSON"}
	}
	reasons := map[string]bool{}
	for _, layer := range man.Layers {
		encoded, ok := layer.Annotations[signatureAnnotation]
		if !ok {
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			reasons["malformed signature encoding"] = true
			continue
		}
		payload, err := c.GetBlob(ctx, ref.Registry, ref.Repository, layer.Digest)
		if err != nil {
			reasons["payload unavailable: "+err.Error()] = true
			continue
		}
		var ss simpleSigning
		if err := json.Unmarshal(payload, &ss); err != nil || ss.Critical.Type != payloadType {
			reasons["payload is not a cosign image signature"] = true
			continue
		}
		// The payload must name this exact digest: a valid signature for a
		// different image must never verify this one.
		if ss.Critical.Image.DockerManifestDigest != digest {
			reasons["signature is for a different digest"] = true
			continue
		}
		for _, k := range keys {
			if k.verify(payload, sig) {
				return Result{Status: Verified, Key: k.Name}
			}
		}
		reasons["signature does not verify with any trusted key"] = true
	}
	if len(reasons) == 0 {
		return Result{Status: Unsigned, Detail: "signature manifest contains no signatures"}
	}
	var list []string
	for r := range reasons {
		list = append(list, r)
	}
	sort.Strings(list)
	return Result{Status: Invalid, Detail: strings.Join(list, "; ")}
}
