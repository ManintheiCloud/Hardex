package sigstore

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
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

// verifyTlogEntry checks one Rekor entry: that its body describes this
// signature, and that the log vouches for it (a signed entry timestamp,
// an inclusion proof against a signed checkpoint, or both; each one present
// must verify). It returns the integration time if the log signed it.
func verifyTlogEntry(e tlogEntry, root *TrustedRoot, check func(map[string]any, string) error) (time.Time, *LogKey, error) {
	id, err := base64.StdEncoding.DecodeString(e.LogID.KeyID)
	if err != nil {
		return time.Time{}, nil, errors.New("malformed log ID")
	}
	log := findLog(root.Tlogs, id)
	if log == nil {
		return time.Time{}, nil, fmt.Errorf("log %s is not in the trusted root", e.LogID.KeyID)
	}
	body, err := base64.StdEncoding.DecodeString(e.CanonicalizedBody)
	if err != nil {
		return time.Time{}, nil, errors.New("malformed log entry body")
	}
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return time.Time{}, nil, errors.New("malformed log entry body")
	}
	kind, version := str(parsed, "kind"), str(parsed, "apiVersion")
	if kind != e.KindVersion.Kind || version != e.KindVersion.Version {
		return time.Time{}, nil, errors.New("log entry kind does not match its body")
	}
	if version != "0.0.1" || (kind != "hashedrekord" && kind != "dsse") {
		return time.Time{}, nil, fmt.Errorf("log entry type %s %s is not supported; verify with cosign", kind, version)
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
		root, err := base64.StdEncoding.DecodeString(p.RootHash)
		if err != nil {
			return time.Time{}, nil, errors.New("malformed inclusion proof root")
		}
		var hashes [][]byte
		for _, h := range p.Hashes {
			b, err := base64.StdEncoding.DecodeString(h)
			if err != nil {
				return time.Time{}, nil, errors.New("malformed inclusion proof")
			}
			hashes = append(hashes, b)
		}
		leaf := sha256.Sum256(append([]byte{0}, body...))
		if err := verifyInclusion(uint64(p.LogIndex), uint64(p.TreeSize), leaf[:], hashes, root); err != nil {
			return time.Time{}, nil, err
		}
		if err := verifyCheckpoint(p.Checkpoint.Envelope, log, uint64(p.TreeSize), root); err != nil {
			return time.Time{}, nil, err
		}
		proven = true
	}
	if !proven {
		return time.Time{}, nil, errors.New("log entry has neither a signed entry timestamp nor an inclusion proof")
	}
	return signed, log, nil
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
// log, and that it commits to the given tree size and root.
func verifyCheckpoint(envelope string, log *LogKey, size uint64, root []byte) error {
	text, sigs, ok := strings.Cut(envelope, "\n\n")
	if !ok {
		return errors.New("malformed checkpoint")
	}
	text += "\n"
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) < 3 {
		return errors.New("malformed checkpoint")
	}
	name := lines[0]
	if i := strings.Index(name, " - "); i > 0 {
		name = name[:i]
	}
	n, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil || n != size {
		return errors.New("checkpoint is for a different tree size")
	}
	cpRoot, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || !bytes.Equal(cpRoot, root) {
		return errors.New("checkpoint is for a different tree root")
	}
	var hint []byte
	if k, ok := log.Key.(ed25519.PublicKey); ok {
		h := sha256.Sum256(append(append([]byte(name+"\n"), 0x01), k...))
		hint = h[:4]
	} else {
		hint = log.ID[:4]
	}
	for _, line := range strings.Split(sigs, "\n") {
		rest, ok := strings.CutPrefix(line, "— ")
		if !ok {
			continue
		}
		_, b64, ok := strings.Cut(rest, " ")
		if !ok {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(raw) < 5 || !bytes.Equal(raw[:4], hint) {
			continue
		}
		if verifyMessage(log.Key, []byte(text), raw[4:]) == nil {
			return nil
		}
		return errors.New("checkpoint signature does not verify")
	}
	return errors.New("checkpoint is not signed by the log")
}
