package sigstore

import (
	"bytes"
	"crypto"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// RFC 3161 / RFC 5652 structures, decoded with encoding/asn1.

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type encapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,tag:0"`
}

type signerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    algorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm algorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo encapsulatedContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type messageImprint struct {
	HashAlgorithm algorithmIdentifier
	HashedMessage []byte
}

type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time `asn1:"generalized"`
	// accuracy, ordering, nonce, tsa and extensions follow; encoding/asn1
	// ignores trailing elements of a SEQUENCE.
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

var (
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
)

var hashByOID = map[string]crypto.Hash{
	"2.16.840.1.101.3.4.2.1": crypto.SHA256,
	"2.16.840.1.101.3.4.2.2": crypto.SHA384,
	"2.16.840.1.101.3.4.2.3": crypto.SHA512,
	"1.2.840.10045.4.3.2":    crypto.SHA256, // ecdsa-with-SHA256
	"1.2.840.10045.4.3.3":    crypto.SHA384,
	"1.2.840.10045.4.3.4":    crypto.SHA512,
	"1.2.840.113549.1.1.11":  crypto.SHA256, // sha256WithRSAEncryption
	"1.2.840.113549.1.1.12":  crypto.SHA384,
	"1.2.840.113549.1.1.13":  crypto.SHA512,
}

// verifyRFC3161 verifies a timestamp token over the signature bytes against
// the trusted timestamp authorities and returns the time it attests.
func verifyRFC3161(token, signature []byte, root *TrustedRoot) (time.Time, string, error) {
	// Accept a bare TimeStampToken or a TimeStampResp wrapping one, as
	// Sigstore clients store the full response.
	var resp struct {
		Status asn1.RawValue
		Token  asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(token, &resp); err == nil && len(resp.Token.FullBytes) > 0 && resp.Status.Tag == asn1.TagSequence {
		var status int
		if _, err := asn1.Unmarshal(resp.Status.Bytes, &status); err != nil || status > 1 { // 0 granted, 1 grantedWithMods
			return time.Time{}, "", errors.New("timestamp request was not granted")
		}
		token = resp.Token.FullBytes
	}
	var ci contentInfo
	if _, err := asn1.Unmarshal(token, &ci); err != nil || !ci.ContentType.Equal(oidSignedData) {
		return time.Time{}, "", errors.New("not a CMS SignedData timestamp")
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return time.Time{}, "", fmt.Errorf("malformed SignedData: %w", err)
	}
	if !sd.EncapContentInfo.EContentType.Equal(oidTSTInfo) || len(sd.SignerInfos) != 1 {
		return time.Time{}, "", errors.New("not a timestamp token")
	}
	var info tstInfo
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.EContent, &info); err != nil {
		return time.Time{}, "", fmt.Errorf("malformed TSTInfo: %w", err)
	}
	h, ok := hashByOID[info.MessageImprint.HashAlgorithm.Algorithm.String()]
	if !ok {
		return time.Time{}, "", errors.New("unsupported message imprint hash")
	}
	hh := h.New()
	hh.Write(signature)
	if !bytes.Equal(hh.Sum(nil), info.MessageImprint.HashedMessage) {
		return time.Time{}, "", errors.New("timestamp is for a different signature")
	}

	si := sd.SignerInfos[0]
	if len(si.SignedAttrs.FullBytes) == 0 {
		return time.Time{}, "", errors.New("timestamp has no signed attributes")
	}
	digestHash, ok := hashByOID[si.DigestAlgorithm.Algorithm.String()]
	if !ok {
		return time.Time{}, "", errors.New("unsupported timestamp digest algorithm")
	}
	// The signed attributes must bind the TSTInfo and its content type.
	var attrs []attribute
	if _, err := asn1.UnmarshalWithParams(si.SignedAttrs.FullBytes, &attrs, "set,tag:0"); err != nil {
		return time.Time{}, "", fmt.Errorf("malformed signed attributes: %w", err)
	}
	dh := digestHash.New()
	dh.Write(sd.EncapContentInfo.EContent)
	sawDigest, sawType := false, false
	for _, a := range attrs {
		switch {
		case a.Type.Equal(oidMessageDigest):
			var d []byte
			if _, err := asn1.Unmarshal(a.Values.Bytes, &d); err != nil || !bytes.Equal(d, dh.Sum(nil)) {
				return time.Time{}, "", errors.New("timestamp message digest does not match")
			}
			sawDigest = true
		case a.Type.Equal(oidContentType):
			var ct asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(a.Values.Bytes, &ct); err != nil || !ct.Equal(oidTSTInfo) {
				return time.Time{}, "", errors.New("timestamp content type does not match")
			}
			sawType = true
		}
	}
	if !sawDigest || !sawType {
		return time.Time{}, "", errors.New("timestamp is missing signed attributes")
	}
	// The signature covers the DER SET OF attributes (tag 0x31, not [0]).
	signed := append([]byte{0x31}, si.SignedAttrs.FullBytes[1:]...)
	sigHash := digestHash
	if alt, ok := hashByOID[si.SignatureAlgorithm.Algorithm.String()]; ok {
		sigHash = alt
	}

	var lastErr error = errors.New("no trusted timestamp authority")
	for _, tsa := range root.TSAs {
		if tsa.Leaf == nil || !tsa.ValidFor.contains(info.GenTime) {
			continue
		}
		if _, err := tsa.Leaf.Verify(x509.VerifyOptions{Roots: tsa.Roots, Intermediates: tsa.Intermediates,
			CurrentTime: info.GenTime, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}); err != nil {
			lastErr = err
			continue
		}
		var err error
		for _, hash := range []crypto.Hash{sigHash, digestHash} {
			s := hash.New()
			s.Write(signed)
			if err = verifyHashed(tsa.Leaf.PublicKey, s.Sum(nil), hash, si.Signature); err == nil {
				return info.GenTime.UTC(), tsa.URI, nil
			}
		}
		lastErr = fmt.Errorf("timestamp signature does not verify with %s", tsa.URI)
	}
	return time.Time{}, "", lastErr
}
