package sigstore

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func asn1Unmarshal(b []byte, v any) ([]byte, error) { return asn1.Unmarshal(b, v) }

func pemCertDER(p []byte) ([]byte, error) {
	block, _ := pem.Decode(p)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("log entry public key is not a PEM certificate")
	}
	return block.Bytes, nil
}

// verifyDigest verifies a signature over a precomputed SHA-256 digest.
func verifyDigest(pub crypto.PublicKey, digest, sig []byte) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if ecdsa.VerifyASN1(k, digest, sig) {
			return nil
		}
	case *rsa.PublicKey:
		if rsa.VerifyPKCS1v15(k, crypto.SHA256, digest, sig) == nil || rsa.VerifyPSS(k, crypto.SHA256, digest, sig, nil) == nil {
			return nil
		}
	default:
		return fmt.Errorf("unsupported key type %T for a digest signature", pub)
	}
	return errors.New("invalid signature")
}

// verifyMessage verifies a signature over a message (SHA-256 for ECDSA and
// RSA keys, which is what Sigstore clients use with P-256 keys).
func verifyMessage(pub crypto.PublicKey, msg, sig []byte) error {
	if k, ok := pub.(ed25519.PublicKey); ok {
		if ed25519.Verify(k, msg, sig) {
			return nil
		}
		return errors.New("invalid signature")
	}
	h := hashFor(pub).New()
	h.Write(msg)
	return verifyHashed(pub, h.Sum(nil), hashFor(pub), sig)
}

// hashFor follows the Sigstore convention of pairing ECDSA curves with
// their matching hash.
func hashFor(pub crypto.PublicKey) crypto.Hash {
	if k, ok := pub.(*ecdsa.PublicKey); ok {
		switch k.Curve.Params().BitSize {
		case 384:
			return crypto.SHA384
		case 521:
			return crypto.SHA512
		}
	}
	return crypto.SHA256
}

func verifyHashed(pub crypto.PublicKey, digest []byte, h crypto.Hash, sig []byte) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if ecdsa.VerifyASN1(k, digest, sig) {
			return nil
		}
	case *rsa.PublicKey:
		if rsa.VerifyPKCS1v15(k, h, digest, sig) == nil || rsa.VerifyPSS(k, h, digest, sig, nil) == nil {
			return nil
		}
	default:
		return fmt.Errorf("unsupported key type %T", pub)
	}
	return errors.New("invalid signature")
}

// verifyTlogEntry checks one Rekor entry: that it describes this signature,
// and that the log vouches for it (a signed entry timestamp, an inclusion
// proof against a signed checkpoint, or both; each one present must verify).
// It returns the integration time if the log signed it.
//
// Rekor v1 entries (hashedrekord, dsse 0.0.1; intoto 0.0.2) are checked
// field by field against the bundle. Rekor v2 entries (hashedrekord 0.0.2)
// carry no signed time; their entry is recomputed from the bundle and
// proven to be in the log, so the stored body is never trusted.
func verifyTlogEntry(e tlogEntry, root *TrustedRoot, check func(map[string]any, string) error, v2Leaf func() ([]byte, error)) (time.Time, *LogKey, error) {
	id, err := base64.StdEncoding.DecodeString(e.LogID.KeyID)
	if err != nil {
		return time.Time{}, nil, errors.New("malformed log ID")
	}
	log := findLog(root.Tlogs, id)
	if log == nil {
		return time.Time{}, nil, fmt.Errorf("log %s is not in the trusted root", e.LogID.KeyID)
	}
	if e.LogIndex < 0 {
		return time.Time{}, nil, errors.New("negative log index")
	}
	kind, version := e.KindVersion.Kind, e.KindVersion.Version
	v2 := kind == "hashedrekord" && version == "0.0.2"

	var body []byte
	if v2 {
		if e.InclusionProof == nil {
			return time.Time{}, nil, errors.New("Rekor v2 entry has no inclusion proof")
		}
		leaf, err := v2Leaf()
		if err != nil {
			return time.Time{}, nil, err
		}
		size, rootHash, err := verifyCheckpoint(e.InclusionProof.Checkpoint.Envelope, log, true)
		if err != nil {
			return time.Time{}, nil, err
		}
		hashes, err := decodeHashes(e.InclusionProof.Hashes)
		if err != nil {
			return time.Time{}, nil, err
		}
		if err := verifyInclusion(uint64(e.LogIndex), size, leaf, hashes, rootHash); err != nil {
			return time.Time{}, nil, err
		}
		// Integrated times in v2 entries are not signed by the log; the
		// signing time must come from a timestamp authority.
		return time.Time{}, log, nil
	}

	if body, err = base64.StdEncoding.DecodeString(e.CanonicalizedBody); err != nil {
		return time.Time{}, nil, errors.New("malformed log entry body")
	}
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return time.Time{}, nil, errors.New("malformed log entry body")
	}
	if str(parsed, "kind") != kind || str(parsed, "apiVersion") != version {
		return time.Time{}, nil, errors.New("log entry kind does not match its body")
	}
	supported := version == "0.0.1" && (kind == "hashedrekord" || kind == "dsse") || version == "0.0.2" && kind == "intoto"
	if !supported {
		return time.Time{}, nil, fmt.Errorf("log entry type %s %s is not supported", kind, version)
	}
	if err := check(parsed, kind); err != nil {
		return time.Time{}, nil, err
	}

	var signed time.Time
	proven := false
	if e.InclusionPromise != nil {
		set, err := base64.StdEncoding.DecodeString(e.InclusionPromise.SignedEntryTimestamp)
		if err != nil {
			return time.Time{}, nil, errors.New("malformed signed entry timestamp")
		}
		payload, _ := json.Marshal(struct {
			Body           string `json:"body"`
			IntegratedTime int64  `json:"integratedTime"`
			LogID          string `json:"logID"`
			LogIndex       int64  `json:"logIndex"`
		}{e.CanonicalizedBody, int64(e.IntegratedTime), hex.EncodeToString(id), int64(e.LogIndex)})
		if err := verifyMessage(log.Key, payload, set); err != nil {
			return time.Time{}, nil, fmt.Errorf("signed entry timestamp does not verify: %w", err)
		}
		signed = time.Unix(int64(e.IntegratedTime), 0).UTC()
		if !log.ValidFor.contains(signed) {
			return time.Time{}, nil, errors.New("log key was not valid at the integration time")
		}
		proven = true
	}
	if p := e.InclusionProof; p != nil {
		rootHash, err := base64.StdEncoding.DecodeString(p.RootHash)
		if err != nil {
			return time.Time{}, nil, errors.New("malformed inclusion proof root")
		}
		hashes, err := decodeHashes(p.Hashes)
		if err != nil {
			return time.Time{}, nil, err
		}
		leaf := sha256.Sum256(append([]byte{0}, body...))
		if err := verifyInclusion(uint64(p.LogIndex), uint64(p.TreeSize), leaf[:], hashes, rootHash); err != nil {
			return time.Time{}, nil, err
		}
		if p.Checkpoint.Envelope == "" {
			// Early v0.1 bundles carry proofs without a signed checkpoint:
			// the root is unsigned, so only the signed entry timestamp counts.
			if !proven {
				return time.Time{}, nil, errors.New("inclusion proof has no signed checkpoint")
			}
			return signed, log, nil
		}
		size, cpRoot, err := verifyCheckpoint(p.Checkpoint.Envelope, log, false)
		if err != nil {
			return time.Time{}, nil, err
		}
		if size != uint64(p.TreeSize) {
			return time.Time{}, nil, errors.New("checkpoint is for a different tree size")
		}
		if !bytes.Equal(cpRoot, rootHash) {
			return time.Time{}, nil, errors.New("checkpoint is for a different tree root")
		}
		proven = true
	}
	if !proven {
		return time.Time{}, nil, errors.New("log entry has neither a signed entry timestamp nor an inclusion proof")
	}
	return signed, log, nil
}

func decodeHashes(in []string) ([][]byte, error) {
	var out [][]byte
	for _, h := range in {
		b, err := base64.StdEncoding.DecodeString(h)
		if err != nil || len(b) != sha256.Size {
			return nil, errors.New("malformed inclusion proof")
		}
		out = append(out, b)
	}
	return out, nil
}

// v2LeafHash recomputes the Merkle leaf hash of the Rekor v2 hashedrekord
// entry that the bundle's signature must have produced: the RFC 8785
// canonical JSON of the entry, as the log serialises it.
func v2LeafHash(cert *x509.Certificate, der, sig, digest []byte) ([]byte, error) {
	details, alg, err := keyDetails(cert.PublicKey)
	if err != nil {
		return nil, err
	}
	b64 := base64.StdEncoding.EncodeToString
	// Keys in lexicographic order, no insignificant whitespace (RFC 8785);
	// every value is a base64 or identifier string needing no escaping.
	entry := `{"apiVersion":"0.0.2","kind":"hashedrekord","spec":{"hashedRekordV002":{"data":{"algorithm":"` + alg +
		`","digest":"` + b64(digest) + `"},"signature":{"content":"` + b64(sig) + `","verifier":{"keyDetails":"` + details +
		`","x509Certificate":{"rawBytes":"` + b64(der) + `"}}}}}}`
	leaf := sha256.Sum256(append([]byte{0}, entry...))
	return leaf[:], nil
}

// keyDetails names a signing key the way Sigstore's protobuf specs do.
func keyDetails(pub crypto.PublicKey) (string, string, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve.Params().BitSize {
		case 256:
			return "PKIX_ECDSA_P256_SHA_256", "SHA2_256", nil
		case 384:
			return "PKIX_ECDSA_P384_SHA_384", "SHA2_384", nil
		case 521:
			return "PKIX_ECDSA_P521_SHA_512", "SHA2_512", nil
		}
	case *rsa.PublicKey:
		switch k.N.BitLen() {
		case 2048, 3072, 4096:
			return fmt.Sprintf("PKIX_RSA_PKCS1V15_%d_SHA256", k.N.BitLen()), "SHA2_256", nil
		}
	}
	return "", "", fmt.Errorf("unsupported key type %T for a Rekor v2 entry", pub)
}

func hashChildren(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

// verifyInclusion implements the RFC 9162 (section 2.1.3.2) inclusion proof
// verification algorithm.
func verifyInclusion(index, size uint64, leaf []byte, proof [][]byte, root []byte) error {
	if index >= size {
		return errors.New("inclusion proof index is outside the tree")
	}
	fn, sn := index, size-1
	r := leaf
	for _, p := range proof {
		if sn == 0 {
			return errors.New("inclusion proof is too long")
		}
		if fn&1 == 1 || fn == sn {
			r = hashChildren(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = hashChildren(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 || !bytes.Equal(r, root) {
		return errors.New("inclusion proof does not lead to the tree root")
	}
	return nil
}

// verifyCheckpoint verifies a signed note (C2SP signed-note format) by the
// log and returns the tree size and root it commits to. Signatures from
// other keys (witness cosignatures) are ignored. For Rekor v2 the origin
// must be the log's host name.
func verifyCheckpoint(envelope string, log *LogKey, v2 bool) (uint64, []byte, error) {
	text, sigs, ok := strings.Cut(envelope, "\n\n")
	if !ok {
		return 0, nil, errors.New("malformed checkpoint")
	}
	text += "\n"
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) < 3 || lines[0] == "" {
		return 0, nil, errors.New("malformed checkpoint")
	}
	origin := lines[0]
	name := origin
	if i := strings.Index(name, " - "); i > 0 && !v2 {
		name = name[:i] // Rekor v1: "<host> - <tree ID>"
	}
	if v2 {
		u, err := url.Parse(log.URL)
		if err != nil || u.Hostname() != origin {
			return 0, nil, fmt.Errorf("checkpoint origin %q is not the log %s", origin, log.URL)
		}
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return 0, nil, errors.New("malformed checkpoint tree size")
	}
	rootHash, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(rootHash) != sha256.Size {
		return 0, nil, errors.New("malformed checkpoint root hash")
	}
	hint := log.ID[:4]
	if k, ok := log.Key.(ed25519.PublicKey); ok && !log.explicitID {
		h := sha256.Sum256(append(append([]byte(name+"\n"), 0x01), k...))
		hint = h[:4]
	}
	found := false
	for _, line := range strings.Split(sigs, "\n") {
		rest, ok := strings.CutPrefix(line, "\u2014 ")
		if !ok {
			continue
		}
		signer, b64, ok := strings.Cut(rest, " ")
		if !ok || signer != name {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(raw) < 5 || !bytes.Equal(raw[:4], hint) {
			continue
		}
		found = true
		if verifyMessage(log.Key, []byte(text), raw[4:]) == nil {
			return size, rootHash, nil
		}
	}
	if found {
		return 0, nil, errors.New("checkpoint signature does not verify")
	}
	return 0, nil, errors.New("checkpoint is not signed by the log")
}
