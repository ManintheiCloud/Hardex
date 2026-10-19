package sigstore

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Bundle media types this package verifies.
var bundleMediaTypes = map[string]bool{
	"application/vnd.dev.sigstore.bundle+json;version=0.1": true,
	"application/vnd.dev.sigstore.bundle+json;version=0.2": true,
	"application/vnd.dev.sigstore.bundle+json;version=0.3": true,
	"application/vnd.dev.sigstore.bundle.v0.3+json":        true,
}

// BundleMediaType is the current bundle media type, as used for OCI
// referrer artifacts.
const BundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

// int64s are strings in protobuf JSON; accept numbers too.
type pbInt int64

func (n *pbInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	v, err := strconv.ParseInt(s, 10, 64)
	*n = pbInt(v)
	return err
}

type tlogEntry struct {
	LogIndex pbInt `json:"logIndex"`
	LogID    struct {
		KeyID string `json:"keyId"`
	} `json:"logId"`
	KindVersion struct {
		Kind    string `json:"kind"`
		Version string `json:"version"`
	} `json:"kindVersion"`
	IntegratedTime   pbInt `json:"integratedTime"`
	InclusionPromise *struct {
		SignedEntryTimestamp string `json:"signedEntryTimestamp"`
	} `json:"inclusionPromise"`
	InclusionProof *struct {
		LogIndex   pbInt    `json:"logIndex"`
		RootHash   string   `json:"rootHash"`
		TreeSize   pbInt    `json:"treeSize"`
		Hashes     []string `json:"hashes"`
		Checkpoint struct {
			Envelope string `json:"envelope"`
		} `json:"checkpoint"`
	} `json:"inclusionProof"`
	CanonicalizedBody string `json:"canonicalizedBody"`
}

type bundleJSON struct {
	MediaType            string `json:"mediaType"`
	VerificationMaterial struct {
		Certificate *struct {
			RawBytes string `json:"rawBytes"`
		} `json:"certificate"`
		X509CertificateChain *rawChain `json:"x509CertificateChain"`
		PublicKey            *struct {
			Hint string `json:"hint"`
		} `json:"publicKey"`
		TlogEntries               []tlogEntry `json:"tlogEntries"`
		TimestampVerificationData *struct {
			RFC3161Timestamps []struct {
				SignedTimestamp string `json:"signedTimestamp"`
			} `json:"rfc3161Timestamps"`
		} `json:"timestampVerificationData"`
	} `json:"verificationMaterial"`
	MessageSignature *struct {
		MessageDigest *struct {
			Algorithm string `json:"algorithm"`
			Digest    string `json:"digest"`
		} `json:"messageDigest"`
		Signature string `json:"signature"`
	} `json:"messageSignature"`
	DSSEEnvelope *dsseEnvelope `json:"dsseEnvelope"`
}

type dsseEnvelope struct {
	Payload     string `json:"payload"`
	PayloadType string `json:"payloadType"`
	Signatures  []struct {
		Sig   string `json:"sig"`
		KeyID string `json:"keyid"`
	} `json:"signatures"`
}

// Policy is the identity a signature must come from. Exactly one of
// Identity and IdentityRegexp, and one of Issuer and IssuerRegexp, is
// required: a keyless signature without an identity check proves only that
// someone, somewhere, signed.
type Policy struct {
	Identity       string
	IdentityRegexp *regexp.Regexp
	Issuer         string
	IssuerRegexp   *regexp.Regexp
}

func (p Policy) validate() error {
	if (p.Identity == "") == (p.IdentityRegexp == nil) {
		return errors.New("policy needs exactly one of a certificate identity or identity regexp")
	}
	if (p.Issuer == "") == (p.IssuerRegexp == nil) {
		return errors.New("policy needs exactly one of a certificate OIDC issuer or issuer regexp")
	}
	return nil
}

// Options configure verification.
type Options struct {
	Root   *TrustedRoot
	Policy Policy
	// Digest is the SHA-256 digest of the artifact: the signed blob, or the
	// subject an attestation must name (e.g. an image manifest digest).
	Digest []byte
	// PredicateType, if set, is required of DSSE attestations.
	PredicateType string
}

// Statement is a verified in-toto statement from a DSSE bundle.
type Statement struct {
	Type          string          `json:"_type"`
	PredicateType string          `json:"predicateType"`
	Subject       []Subject       `json:"subject"`
	Predicate     json.RawMessage `json:"predicate"`
}

// Subject is an in-toto statement subject.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Result describes a verified bundle.
type Result struct {
	Identity    string     `json:"identity"`
	Issuer      string     `json:"issuer"`
	SigningTime time.Time  `json:"signingTime"`
	TimeSources []string   `json:"timeSources"`
	LogIndex    int64      `json:"logIndex"`
	LogURL      string     `json:"log"`
	Statement   *Statement `json:"statement,omitempty"`
}

const (
	oidIssuerV1 = "1.3.6.1.4.1.57264.1.1"
	oidIssuerV2 = "1.3.6.1.4.1.57264.1.8"
	oidSCTList  = "1.3.6.1.4.1.11129.2.4.2"
)

// Verify checks a bundle completely, offline. It returns an error unless
// every check passes.
func Verify(bundle []byte, opts Options) (*Result, error) {
	if opts.Root == nil {
		return nil, errors.New("no trusted root")
	}
	if err := opts.Policy.validate(); err != nil {
		return nil, err
	}
	if len(opts.Digest) != sha256.Size {
		return nil, errors.New("artifact digest must be SHA-256")
	}
	var b bundleJSON
	if err := json.Unmarshal(bundle, &b); err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	if !bundleMediaTypes[b.MediaType] {
		return nil, fmt.Errorf("unsupported bundle media type %q", b.MediaType)
	}
	vm := b.VerificationMaterial
	var certDER string
	switch {
	case vm.Certificate != nil:
		certDER = vm.Certificate.RawBytes
	case vm.X509CertificateChain != nil && len(vm.X509CertificateChain.Certificates) > 0:
		certDER = vm.X509CertificateChain.Certificates[0].RawBytes
		// Trust comes from the trusted root, never from the bundle: a chain
		// that carries its own root is malformed (or an attempt to supply one).
		for _, c := range vm.X509CertificateChain.Certificates[1:] {
			raw, err := base64.StdEncoding.DecodeString(c.RawBytes)
			if err != nil {
				return nil, fmt.Errorf("certificate chain: %w", err)
			}
			cc, err := x509.ParseCertificate(raw)
			if err != nil {
				return nil, fmt.Errorf("certificate chain: %w", err)
			}
			if bytes.Equal(cc.RawSubject, cc.RawIssuer) && cc.CheckSignatureFrom(cc) == nil {
				return nil, errors.New("bundle certificate chain contains a root certificate")
			}
		}
	case vm.PublicKey != nil:
		return nil, errors.New("bundle is signed with a key, not keyless; verify with the key")
	default:
		return nil, errors.New("bundle has no verification material")
	}
	der, err := base64.StdEncoding.DecodeString(certDER)
	if err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}

	// 1. The signature over the artifact.
	var sig []byte
	res := &Result{}
	var rekorCheck func(body map[string]any, kind string) error
	// Rekor v2 entries are verified by recomputing the entry from the
	// bundle and proving that hash is in the log (v2Digest is the digest
	// the log entry records).
	var v2Digest []byte
	switch {
	case b.MessageSignature != nil:
		ms := b.MessageSignature
		if ms.MessageDigest != nil {
			d, err := base64.StdEncoding.DecodeString(ms.MessageDigest.Digest)
			if err != nil || ms.MessageDigest.Algorithm != "SHA2_256" || !bytes.Equal(d, opts.Digest) {
				return nil, errors.New("bundle is for a different artifact")
			}
		}
		if sig, err = base64.StdEncoding.DecodeString(ms.Signature); err != nil {
			return nil, fmt.Errorf("signature: %w", err)
		}
		if err := verifyDigest(cert.PublicKey, opts.Digest, sig); err != nil {
			return nil, fmt.Errorf("signature does not verify over the artifact: %w", err)
		}
		v2Digest = opts.Digest
		rekorCheck = func(body map[string]any, kind string) error {
			if kind != "hashedrekord" {
				return fmt.Errorf("log entry kind %s does not match a message signature", kind)
			}
			if str(body, "spec", "data", "hash", "algorithm") != "sha256" || str(body, "spec", "data", "hash", "value") != hex.EncodeToString(opts.Digest) {
				return errors.New("log entry is for a different artifact")
			}
			if str(body, "spec", "signature", "content") != base64.StdEncoding.EncodeToString(sig) {
				return errors.New("log entry is for a different signature")
			}
			return samePEMCert(str(body, "spec", "signature", "publicKey", "content"), der)
		}
	case b.DSSEEnvelope != nil:
		env := b.DSSEEnvelope
		if len(env.Signatures) != 1 {
			return nil, fmt.Errorf("DSSE envelope has %d signatures; expected 1", len(env.Signatures))
		}
		payload, err := base64.StdEncoding.DecodeString(env.Payload)
		if err != nil {
			return nil, fmt.Errorf("DSSE payload: %w", err)
		}
		if sig, err = base64.StdEncoding.DecodeString(env.Signatures[0].Sig); err != nil {
			return nil, fmt.Errorf("DSSE signature: %w", err)
		}
		pae := fmt.Sprintf("DSSEv1 %d %s %d ", len(env.PayloadType), env.PayloadType, len(payload))
		msg := append([]byte(pae), payload...)
		if err := verifyMessage(cert.PublicKey, msg, sig); err != nil {
			return nil, fmt.Errorf("DSSE signature does not verify: %w", err)
		}
		if env.PayloadType != "application/vnd.in-toto+json" {
			return nil, fmt.Errorf("unsupported DSSE payload type %q", env.PayloadType)
		}
		var st Statement
		if err := json.Unmarshal(payload, &st); err != nil {
			return nil, fmt.Errorf("in-toto statement: %w", err)
		}
		if opts.PredicateType != "" && st.PredicateType != opts.PredicateType {
			return nil, fmt.Errorf("predicate type %q, want %q", st.PredicateType, opts.PredicateType)
		}
		want := hex.EncodeToString(opts.Digest)
		found := false
		for _, s := range st.Subject {
			if strings.EqualFold(s.Digest["sha256"], want) {
				found = true
			}
		}
		if !found {
			return nil, errors.New("attestation does not name this artifact as its subject")
		}
		res.Statement = &st
		payloadHash := sha256.Sum256(payload)
		h := hashFor(cert.PublicKey).New()
		h.Write(msg)
		v2Digest = h.Sum(nil)
		rekorCheck = func(body map[string]any, kind string) error {
			if kind == "intoto" { // intoto 0.0.2: the envelope is stored, signatures double-encoded
				if str(body, "spec", "content", "payloadHash", "value") != hex.EncodeToString(payloadHash[:]) {
					return errors.New("log entry is for a different payload")
				}
				sigs, _ := lookup(body, "spec", "content", "envelope", "signatures").([]any)
				for _, s := range sigs {
					m, _ := s.(map[string]any)
					inner, err := base64.StdEncoding.DecodeString(str(m, "sig"))
					if err == nil && string(inner) == env.Signatures[0].Sig && samePEMCert(str(m, "publicKey"), der) == nil {
						return nil
					}
				}
				return errors.New("log entry is for a different signature or signer")
			}
			if kind != "dsse" {
				return fmt.Errorf("log entry kind %s does not match a DSSE envelope", kind)
			}
			if str(body, "spec", "payloadHash", "value") != hex.EncodeToString(payloadHash[:]) {
				return errors.New("log entry is for a different payload")
			}
			sigs, _ := lookup(body, "spec", "signatures").([]any)
			for _, s := range sigs {
				m, _ := s.(map[string]any)
				if str(m, "signature") == env.Signatures[0].Sig && samePEMCert(str(m, "verifier"), der) == nil {
					return nil
				}
			}
			return errors.New("log entry is for a different signature or signer")
		}
	default:
		return nil, errors.New("bundle has no signature")
	}

	// 2. The transparency log entry, and the times it proves.
	var times []time.Time
	logged := false
	var logErrs []string
	for _, e := range vm.TlogEntries {
		// From bundle v0.2 on, an inclusion proof is mandatory; a signed
		// entry timestamp alone is accepted only in v0.1 bundles.
		if e.InclusionProof == nil && b.MediaType != "application/vnd.dev.sigstore.bundle+json;version=0.1" {
			logErrs = append(logErrs, "log entry has no inclusion proof")
			continue
		}
		t, log, err := verifyTlogEntry(e, opts.Root, rekorCheck, func() ([]byte, error) { return v2LeafHash(cert, der, sig, v2Digest) })
		if err != nil {
			logErrs = append(logErrs, err.Error())
			continue
		}
		logged = true
		res.LogIndex, res.LogURL = int64(e.LogIndex), log.URL
		if !t.IsZero() {
			times = append(times, t)
			res.TimeSources = append(res.TimeSources, "transparency log "+log.URL)
		}
	}
	if !logged {
		if len(logErrs) == 0 {
			return nil, errors.New("bundle has no transparency log entry")
		}
		return nil, fmt.Errorf("transparency log: %s", strings.Join(logErrs, "; "))
	}

	// 3. Signed timestamps.
	if vm.TimestampVerificationData != nil {
		for _, ts := range vm.TimestampVerificationData.RFC3161Timestamps {
			raw, err := base64.StdEncoding.DecodeString(ts.SignedTimestamp)
			if err != nil {
				return nil, fmt.Errorf("timestamp: %w", err)
			}
			t, tsa, err := verifyRFC3161(raw, sig, opts.Root)
			if err != nil {
				return nil, fmt.Errorf("timestamp: %w", err)
			}
			times = append(times, t)
			res.TimeSources = append(res.TimeSources, "timestamp authority "+tsa)
		}
	}
	if len(times) == 0 {
		return nil, errors.New("no verified signing time (no signed entry timestamp or RFC 3161 timestamp)")
	}

	// 4. The certificate chain, at every verified signing time.
	var chain []*x509.Certificate
	for _, t := range times {
		c, err := verifyChain(cert, opts.Root, t)
		if err != nil {
			return nil, err
		}
		chain = c
	}
	res.SigningTime = times[0]

	// 5. Certificate transparency.
	if err := verifySCT(cert, chain[1], opts.Root); err != nil {
		return nil, fmt.Errorf("certificate transparency: %w", err)
	}

	// 6. Identity policy.
	res.Identity, res.Issuer = identity(cert), issuer(cert)
	if err := opts.Policy.match(res.Identity, res.Issuer); err != nil {
		return nil, err
	}
	return res, nil
}

func (p Policy) match(id, iss string) error {
	switch {
	case p.Identity != "" && id != p.Identity,
		p.IdentityRegexp != nil && !p.IdentityRegexp.MatchString(id):
		return fmt.Errorf("signed by %q, which does not match the required identity", id)
	case p.Issuer != "" && iss != p.Issuer,
		p.IssuerRegexp != nil && !p.IssuerRegexp.MatchString(iss):
		return fmt.Errorf("identity issued by %q, which does not match the required OIDC issuer", iss)
	}
	return nil
}

func verifyChain(cert *x509.Certificate, root *TrustedRoot, t time.Time) ([]*x509.Certificate, error) {
	var lastErr error
	for _, ca := range root.CAs {
		if !ca.ValidFor.contains(t) {
			continue
		}
		chains, err := cert.Verify(x509.VerifyOptions{Roots: ca.Roots, Intermediates: ca.Intermediates, CurrentTime: t,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}})
		if err == nil && len(chains) > 0 && len(chains[0]) >= 2 {
			return chains[0], nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no certificate authority was valid at the signing time")
	}
	return nil, fmt.Errorf("certificate does not chain to a trusted Fulcio CA at %s: %w", t.UTC().Format(time.RFC3339), lastErr)
}

// identity returns the certificate's subject alternative name.
func identity(cert *x509.Certificate) string {
	if len(cert.URIs) > 0 {
		return cert.URIs[0].String()
	}
	if len(cert.EmailAddresses) > 0 {
		return cert.EmailAddresses[0]
	}
	return ""
}

func issuer(cert *x509.Certificate) string {
	var v1 string
	for _, ext := range cert.Extensions {
		switch ext.Id.String() {
		case oidIssuerV2:
			var s string
			if _, err := asn1Unmarshal(ext.Value, &s); err == nil {
				return s
			}
		case oidIssuerV1:
			v1 = string(ext.Value)
		}
	}
	return v1
}

func samePEMCert(b64PEM string, der []byte) error {
	raw, err := base64.StdEncoding.DecodeString(b64PEM)
	if err != nil {
		return errors.New("log entry certificate is not base64")
	}
	got, err := pemCertDER(raw)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, der) {
		return errors.New("log entry is for a different certificate")
	}
	return nil
}

func lookup(m map[string]any, path ...string) any {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[p]
	}
	return cur
}

func str(m map[string]any, path ...string) string {
	s, _ := lookup(m, path...).(string)
	return s
}
