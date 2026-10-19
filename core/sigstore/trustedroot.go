// Package sigstore verifies Sigstore keyless signatures — the format cosign,
// GitHub artifact attestations and other Sigstore clients produce — with the
// standard library only.
//
// A bundle is verified completely offline against a trusted root (the
// Fulcio certificate authorities, Rekor transparency logs, certificate
// transparency logs and timestamp authorities of a Sigstore instance):
//
//   - the signing certificate chains to a trusted Fulcio CA and was valid
//     at the signing time;
//   - the certificate carries an embedded SCT from a trusted CT log;
//   - the certificate's identity (subject alternative name) and OIDC issuer
//     match the caller's policy — without a policy nothing is verified;
//   - the signature verifies over the artifact digest (message signatures)
//     or the DSSE pre-authentication encoding (attestations);
//   - the Rekor entry matches the signature, certificate and artifact, and is
//     proven to be in the log: by an inclusion proof against a checkpoint
//     signed by the log, and/or by a signed entry timestamp;
//   - the signing time comes from a verified source: the log's signed
//     integration time, or an RFC 3161 timestamp from a trusted authority.
//
// The trusted root of the Sigstore public-good instance is embedded
// (trusted_root.json, from github.com/sigstore/root-signing, matching the
// hash in its TUF targets metadata). Pass a newer one with --trusted-root
// when Sigstore rotates keys.
package sigstore

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

//go:embed trusted_root.json
var publicGoodRoot []byte

// TrustedRootMediaType is the supported trusted root format.
const TrustedRootMediaType = "application/vnd.dev.sigstore.trustedroot+json;version=0.1"

type validity struct {
	Start *time.Time `json:"start"`
	End   *time.Time `json:"end"`
}

func (v validity) contains(t time.Time) bool {
	return (v.Start == nil || !t.Before(*v.Start)) && (v.End == nil || !t.After(*v.End))
}

type rawKey struct {
	RawBytes   string   `json:"rawBytes"`
	KeyDetails string   `json:"keyDetails"`
	ValidFor   validity `json:"validFor"`
}

type rawChain struct {
	Certificates []struct {
		RawBytes string `json:"rawBytes"`
	} `json:"certificates"`
}

type trustedRootJSON struct {
	MediaType string `json:"mediaType"`
	Tlogs     []struct {
		BaseURL   string `json:"baseUrl"`
		PublicKey rawKey `json:"publicKey"`
		LogID     struct {
			KeyID string `json:"keyId"`
		} `json:"logId"`
	} `json:"tlogs"`
	CertificateAuthorities []struct {
		URI       string   `json:"uri"`
		CertChain rawChain `json:"certChain"`
		ValidFor  validity `json:"validFor"`
	} `json:"certificateAuthorities"`
	Ctlogs []struct {
		BaseURL   string `json:"baseUrl"`
		PublicKey rawKey `json:"publicKey"`
		LogID     struct {
			KeyID string `json:"keyId"`
		} `json:"logId"`
	} `json:"ctlogs"`
	TimestampAuthorities []struct {
		URI       string   `json:"uri"`
		CertChain rawChain `json:"certChain"`
		ValidFor  validity `json:"validFor"`
	} `json:"timestampAuthorities"`
}

// LogKey is a transparency log's public key.
type LogKey struct {
	URL      string
	ID       []byte // SHA-256 of the DER public key
	Key      crypto.PublicKey
	ValidFor validity
}

// Authority is a certificate authority (Fulcio) or timestamp authority.
type Authority struct {
	URI           string
	Roots         *x509.CertPool
	Intermediates *x509.CertPool
	Leaf          *x509.Certificate // the TSA's signing certificate, if any
	ValidFor      validity
}

// TrustedRoot holds the keys and certificates of a Sigstore instance.
type TrustedRoot struct {
	Tlogs  []LogKey
	CTLogs []LogKey
	CAs    []Authority
	TSAs   []Authority
	digest string
	Source string
}

// Digest identifies the trusted root content (sha256 of the JSON).
func (r *TrustedRoot) Digest() string { return r.digest }

// PublicGood returns the embedded trusted root of the Sigstore public-good
// instance (Fulcio, Rekor and the Sigstore TSA at sigstore.dev).
func PublicGood() *TrustedRoot {
	r, err := ParseTrustedRoot(publicGoodRoot)
	if err != nil {
		panic("embedded trusted root: " + err.Error())
	}
	r.Source = "embedded Sigstore public-good root"
	return r
}

// LoadTrustedRoot reads a trusted_root.json file.
func LoadTrustedRoot(path string) (*TrustedRoot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r, err := ParseTrustedRoot(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	r.Source = path
	return r, nil
}

// ParseTrustedRoot parses a trusted root in the Sigstore protobuf-specs
// JSON format.
func ParseTrustedRoot(data []byte) (*TrustedRoot, error) {
	var raw trustedRootJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	if raw.MediaType != TrustedRootMediaType {
		return nil, fmt.Errorf("unsupported trusted root media type %q", raw.MediaType)
	}
	sum := sha256.Sum256(data)
	r := &TrustedRoot{digest: fmt.Sprintf("sha256:%x", sum)}
	parseLog := func(url string, k rawKey) (LogKey, error) {
		der, err := base64.StdEncoding.DecodeString(k.RawBytes)
		if err != nil {
			return LogKey{}, fmt.Errorf("log %s: %w", url, err)
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return LogKey{}, fmt.Errorf("log %s: %w", url, err)
		}
		id := sha256.Sum256(der)
		return LogKey{URL: url, ID: id[:], Key: pub, ValidFor: k.ValidFor}, nil
	}
	for _, t := range raw.Tlogs {
		k, err := parseLog(t.BaseURL, t.PublicKey)
		if err != nil {
			return nil, err
		}
		r.Tlogs = append(r.Tlogs, k)
	}
	for _, t := range raw.Ctlogs {
		k, err := parseLog(t.BaseURL, t.PublicKey)
		if err != nil {
			return nil, err
		}
		r.CTLogs = append(r.CTLogs, k)
	}
	parseChain := func(uri string, c rawChain, v validity, tsa bool) (Authority, error) {
		a := Authority{URI: uri, Roots: x509.NewCertPool(), Intermediates: x509.NewCertPool(), ValidFor: v}
		var certs []*x509.Certificate
		for _, raw := range c.Certificates {
			der, err := base64.StdEncoding.DecodeString(raw.RawBytes)
			if err != nil {
				return a, fmt.Errorf("authority %s: %w", uri, err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return a, fmt.Errorf("authority %s: %w", uri, err)
			}
			certs = append(certs, cert)
		}
		if len(certs) == 0 {
			return a, fmt.Errorf("authority %s: empty certificate chain", uri)
		}
		// The chain is ordered leaf-most first and ends with the root.
		a.Roots.AddCert(certs[len(certs)-1])
		start := 0
		if tsa && len(certs) > 1 {
			a.Leaf, start = certs[0], 1
		}
		for _, c := range certs[start : len(certs)-1] {
			a.Intermediates.AddCert(c)
		}
		if tsa && len(certs) == 1 {
			a.Leaf = certs[0]
		}
		return a, nil
	}
	for _, ca := range raw.CertificateAuthorities {
		a, err := parseChain(ca.URI, ca.CertChain, ca.ValidFor, false)
		if err != nil {
			return nil, err
		}
		r.CAs = append(r.CAs, a)
	}
	for _, ta := range raw.TimestampAuthorities {
		a, err := parseChain(ta.URI, ta.CertChain, ta.ValidFor, true)
		if err != nil {
			return nil, err
		}
		r.TSAs = append(r.TSAs, a)
	}
	if len(r.CAs) == 0 || len(r.Tlogs) == 0 {
		return nil, fmt.Errorf("trusted root has no certificate authority or transparency log")
	}
	return r, nil
}

func findLog(logs []LogKey, id []byte) *LogKey {
	for i := range logs {
		if string(logs[i].ID) == string(id) {
			return &logs[i]
		}
	}
	return nil
}
