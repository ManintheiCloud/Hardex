package sigstore

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// verifySCT checks that the certificate embeds a signed certificate
// timestamp from a trusted CT log (RFC 6962, section 3.2), proving the
// certificate was publicly logged when it was issued.
func verifySCT(cert, issuer *x509.Certificate, root *TrustedRoot) error {
	var list []byte
	for _, ext := range cert.Extensions {
		if ext.Id.String() == oidSCTList {
			if _, err := asn1.Unmarshal(ext.Value, &list); err != nil {
				return errors.New("malformed SCT list")
			}
		}
	}
	if list == nil {
		return errors.New("certificate has no embedded SCT")
	}
	tbs, err := removeExtension(cert.RawTBSCertificate, oidSCTList)
	if err != nil {
		return err
	}
	issuerKeyHash := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)

	if len(list) < 2 || int(binary.BigEndian.Uint16(list)) != len(list)-2 {
		return errors.New("malformed SCT list")
	}
	rest := list[2:]
	var lastErr error = errors.New("no SCT from a trusted CT log")
	for len(rest) > 0 {
		if len(rest) < 2 {
			return errors.New("malformed SCT list")
		}
		n := int(binary.BigEndian.Uint16(rest))
		if len(rest) < 2+n {
			return errors.New("malformed SCT list")
		}
		sct := rest[2 : 2+n]
		rest = rest[2+n:]
		// version(1) log_id(32) timestamp(8) extensions(2+len)
		// hash(1) sigalg(1) signature(2+len)
		if len(sct) < 1+32+8+2 || sct[0] != 0 {
			lastErr = errors.New("unsupported SCT version")
			continue
		}
		logID, ts := sct[1:33], sct[33:41]
		extLen := int(binary.BigEndian.Uint16(sct[41:43]))
		if len(sct) < 43+extLen+4 {
			return errors.New("malformed SCT")
		}
		exts := sct[43 : 43+extLen]
		sigPart := sct[43+extLen:]
		sigLen := int(binary.BigEndian.Uint16(sigPart[2:4]))
		if len(sigPart) != 4+sigLen {
			return errors.New("malformed SCT")
		}
		sig := sigPart[4:]
		log := findLog(root.CTLogs, logID)
		if log == nil {
			continue
		}
		when := time.UnixMilli(int64(binary.BigEndian.Uint64(ts)))
		if !log.ValidFor.contains(when) {
			lastErr = fmt.Errorf("CT log %s was not valid at %s", log.URL, when.UTC().Format(time.RFC3339))
			continue
		}
		var signed []byte
		signed = append(signed, 0, 0) // v1, certificate_timestamp
		signed = append(signed, ts...)
		signed = append(signed, 0, 1) // precert_entry
		signed = append(signed, issuerKeyHash[:]...)
		signed = append(signed, byte(len(tbs)>>16), byte(len(tbs)>>8), byte(len(tbs)))
		signed = append(signed, tbs...)
		signed = append(signed, byte(extLen>>8), byte(extLen))
		signed = append(signed, exts...)
		if err := verifyMessage(log.Key, signed, sig); err != nil {
			lastErr = fmt.Errorf("SCT from %s does not verify", log.URL)
			continue
		}
		return nil
	}
	return lastErr
}

// removeExtension re-encodes a TBSCertificate without the given extension,
// reconstructing the precertificate that the CT log signed.
func removeExtension(tbs []byte, oid string) ([]byte, error) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(tbs, &seq); err != nil {
		return nil, errors.New("malformed certificate")
	}
	var out []byte
	rest := seq.Bytes
	for len(rest) > 0 {
		var el asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &el); err != nil {
			return nil, errors.New("malformed certificate")
		}
		if el.Class != asn1.ClassContextSpecific || el.Tag != 3 {
			out = append(out, el.FullBytes...)
			continue
		}
		var exts asn1.RawValue
		if _, err := asn1.Unmarshal(el.Bytes, &exts); err != nil {
			return nil, errors.New("malformed certificate extensions")
		}
		var kept []byte
		er := exts.Bytes
		for len(er) > 0 {
			var ext asn1.RawValue
			if er, err = asn1.Unmarshal(er, &ext); err != nil {
				return nil, errors.New("malformed certificate extension")
			}
			var id asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(ext.Bytes, &id); err != nil {
				return nil, errors.New("malformed certificate extension")
			}
			if id.String() != oid {
				kept = append(kept, ext.FullBytes...)
			}
		}
		inner, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: kept})
		if err != nil {
			return nil, err
		}
		wrapped, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 3, IsCompound: true, Bytes: inner})
		if err != nil {
			return nil, err
		}
		out = append(out, wrapped...)
	}
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: out})
}
