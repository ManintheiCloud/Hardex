// Package vuln finds known vulnerabilities in container images from the
// SBOM attestations attached to them, using the OSV database.
//
// SBOMs are read from BuildKit attestation manifests (docker buildx
// --sbom=true), which the image index references by digest. Fetched by the
// index digest — the digest that is pinned and signed — the SBOM is
// integrity-protected transitively, although BuildKit does not sign it.
// Images without an SBOM attestation are reported as such, never as clean.
package vuln

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/ManintheiCloud/Hardex/core/registry"
)

// DefaultOSV is the public OSV API.
const DefaultOSV = "https://api.osv.dev"

const (
	attestationRefType = "attestation-manifest"
	inTotoLayer        = "application/vnd.in-toto+json"
	predicateTypeKey   = "in-toto.io/predicate-type"
	spdxPredicate      = "https://spdx.dev/Document"
	cdxPredicate       = "https://cyclonedx.org/bom"
)

// Package is a component found in an SBOM.
type Package struct {
	PURL     string   `json:"purl"`
	Vulns    []string `json:"vulnerabilities,omitempty"`
	Platform string   `json:"platform,omitempty"`
}

// Report is the outcome for one image.
type Report struct {
	SBOM     bool      `json:"sbom"`
	Packages int       `json:"packages"`
	Findings []Package `json:"findings,omitempty"`
}

// VulnCount is the number of distinct vulnerability IDs.
func (r *Report) VulnCount() int {
	ids := map[string]bool{}
	for _, f := range r.Findings {
		for _, v := range f.Vulns {
			ids[v] = true
		}
	}
	return len(ids)
}

// SBOMPackages returns the package URLs listed in the SBOM attestations of
// the image index at digest. ok is false if the image has none.
func SBOMPackages(ctx context.Context, c *registry.Client, ref registry.Ref, digest string) (purls map[string][]string, ok bool, err error) {
	m, err := c.GetManifest(ctx, ref.Registry, ref.Repository, digest)
	if err != nil {
		return nil, false, err
	}
	var idx registry.Index
	if err := json.Unmarshal(m.Body, &idx); err != nil {
		return nil, false, fmt.Errorf("image index: %w", err)
	}
	platforms := map[string]string{}
	for _, d := range idx.Manifests {
		if d.Platform != nil && d.Platform.OS != "unknown" {
			platforms[d.Digest] = d.Platform.OS + "/" + d.Platform.Architecture
		}
	}
	purls = map[string][]string{}
	for _, d := range idx.Manifests {
		if d.Annotations["vnd.docker.reference.type"] != attestationRefType {
			continue
		}
		am, err := c.GetManifest(ctx, ref.Registry, ref.Repository, d.Digest)
		if err != nil {
			return nil, false, fmt.Errorf("attestation manifest: %w", err)
		}
		var man registry.Index
		if err := json.Unmarshal(am.Body, &man); err != nil {
			return nil, false, fmt.Errorf("attestation manifest: %w", err)
		}
		platform := platforms[d.Annotations["vnd.docker.reference.digest"]]
		for _, l := range man.Layers {
			pt := l.Annotations[predicateTypeKey]
			if l.MediaType != inTotoLayer || (pt != spdxPredicate && !strings.HasPrefix(pt, cdxPredicate)) {
				continue
			}
			blob, err := c.GetBlob(ctx, ref.Registry, ref.Repository, l.Digest)
			if err != nil {
				return nil, false, fmt.Errorf("SBOM: %w", err)
			}
			list, err := ParseSBOMStatement(blob)
			if err != nil {
				return nil, false, err
			}
			ok = true
			for _, p := range list {
				purls[p] = appendUnique(purls[p], platform)
			}
		}
	}
	return purls, ok, nil
}

func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

// ParseSBOMStatement extracts package URLs from an in-toto statement whose
// predicate is an SPDX 2.x or CycloneDX document (or from a bare document).
func ParseSBOMStatement(data []byte) ([]string, error) {
	var st struct {
		Predicate json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("SBOM: %w", err)
	}
	doc := data
	if len(st.Predicate) > 0 {
		doc = st.Predicate
	}
	var sbom struct {
		Packages []struct {
			ExternalRefs []struct {
				ReferenceType    string `json:"referenceType"`
				ReferenceLocator string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
		Components []struct {
			PURL string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(doc, &sbom); err != nil {
		return nil, fmt.Errorf("SBOM: %w", err)
	}
	set := map[string]bool{}
	for _, p := range sbom.Packages {
		for _, r := range p.ExternalRefs {
			if r.ReferenceType == "purl" && strings.HasPrefix(r.ReferenceLocator, "pkg:") {
				set[r.ReferenceLocator] = true
			}
		}
	}
	for _, c := range sbom.Components {
		if strings.HasPrefix(c.PURL, "pkg:") {
			set[c.PURL] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		if strings.Contains(p, "@") { // OSV needs a version
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}

// OSV queries the OSV database.
type OSV struct {
	BaseURL string
	HTTP    *http.Client
}

const batchSize = 500

// Query returns the OSV vulnerability IDs affecting each package URL.
func (o *OSV) Query(ctx context.Context, purls []string) (map[string][]string, error) {
	out := map[string][]string{}
	for start := 0; start < len(purls); start += batchSize {
		end := min(start+batchSize, len(purls))
		type query struct {
			Package struct {
				PURL string `json:"purl"`
			} `json:"package"`
		}
		var req struct {
			Queries []query `json:"queries"`
		}
		for _, p := range purls[start:end] {
			var q query
			q.Package.PURL = p
			req.Queries = append(req.Queries, q)
		}
		body, _ := json.Marshal(req)
		hr, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(o.BaseURL, "/")+"/v1/querybatch", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		hr.Header.Set("Content-Type", "application/json")
		hr.Header.Set("User-Agent", "hardex")
		resp, err := o.HTTP.Do(hr)
		if err != nil {
			return nil, fmt.Errorf("OSV: %w", err)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("OSV: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("OSV: HTTP %d", resp.StatusCode)
		}
		var res struct {
			Results []struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
				NextPageToken string `json:"next_page_token"`
			} `json:"results"`
		}
		if err := json.Unmarshal(data, &res); err != nil {
			return nil, fmt.Errorf("OSV: %w", err)
		}
		if len(res.Results) != end-start {
			return nil, fmt.Errorf("OSV returned %d results for %d queries", len(res.Results), end-start)
		}
		for i, r := range res.Results {
			if r.NextPageToken != "" {
				return nil, fmt.Errorf("OSV: too many vulnerabilities for %s to list in one response", purls[start+i])
			}
			for _, v := range r.Vulns {
				out[purls[start+i]] = append(out[purls[start+i]], v.ID)
			}
		}
	}
	return out, nil
}

// Scan reads an image's SBOM and looks its packages up in OSV.
func Scan(ctx context.Context, c *registry.Client, ref registry.Ref, digest string, o *OSV) (*Report, error) {
	pkgs, ok, err := SBOMPackages(ctx, c, ref, digest)
	if err != nil || !ok {
		return &Report{SBOM: false}, err
	}
	purls := make([]string, 0, len(pkgs))
	for p := range pkgs {
		purls = append(purls, p)
	}
	sort.Strings(purls)
	ids, err := o.Query(ctx, purls)
	if err != nil {
		return nil, err
	}
	r := &Report{SBOM: true, Packages: len(purls)}
	for _, p := range purls {
		if v := ids[p]; len(v) > 0 {
			sort.Strings(v)
			r.Findings = append(r.Findings, Package{PURL: p, Vulns: v, Platform: strings.Join(pkgs[p], ", ")})
		}
	}
	return r, nil
}
