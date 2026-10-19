package vuln

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ManintheiCloud/Hardex/core/registry"
)

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

// An image index as docker buildx writes it with --sbom=true: one platform
// manifest and one attestation manifest whose layer is an SPDX statement.
func setup(t *testing.T, withSBOM bool) (*registry.Client, registry.Ref, string, *OSV, *int) {
	content := map[string][]byte{}
	put := func(b []byte) string { d := digestOf(b); content[d] = b; return d }
	platform := put([]byte(`{"schemaVersion":2,"layers":[]}`))
	sbom := put(mustJSON(map[string]any{
		"_type": "https://in-toto.io/Statement/v0.1", "predicateType": spdxPredicate,
		"predicate": map[string]any{"spdxVersion": "SPDX-2.3", "packages": []any{
			map[string]any{"name": "go-yaml", "externalRefs": []any{map[string]any{"referenceType": "purl", "referenceLocator": "pkg:golang/github.com/goccy/go-yaml@v1.11.0"}}},
			map[string]any{"name": "stdlib", "externalRefs": []any{map[string]any{"referenceType": "purl", "referenceLocator": "pkg:golang/stdlib@1.25.3"}}},
			map[string]any{"name": "unversioned", "externalRefs": []any{map[string]any{"referenceType": "purl", "referenceLocator": "pkg:golang/example.com/x"}}},
		}},
	}))
	att := put(mustJSON(map[string]any{"schemaVersion": 2, "layers": []any{
		map[string]any{"mediaType": inTotoLayer, "digest": sbom, "annotations": map[string]string{predicateTypeKey: spdxPredicate}}}}))
	manifests := []any{map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": platform, "platform": map[string]string{"os": "linux", "architecture": "amd64"}}}
	if withSBOM {
		manifests = append(manifests, map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": att,
			"platform":    map[string]string{"os": "unknown", "architecture": "unknown"},
			"annotations": map[string]string{"vnd.docker.reference.type": attestationRefType, "vnd.docker.reference.digest": platform}})
	}
	index := put(mustJSON(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": manifests}))

	queries := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/querybatch" {
			queries++
			var req struct {
				Queries []struct {
					Package struct{ PURL string } `json:"package"`
				} `json:"queries"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			var results []any
			for _, q := range req.Queries {
				if strings.Contains(q.Package.PURL, "go-yaml@v1.11.0") {
					results = append(results, map[string]any{"vulns": []any{map[string]any{"id": "GO-2024-0001"}, map[string]any{"id": "GHSA-xxxx-yyyy-zzzz"}}})
				} else {
					results = append(results, map[string]any{})
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"results": results})
			return
		}
		i := strings.LastIndex(r.URL.Path, "/")
		b, ok := content[r.URL.Path[i+1:]]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(srv.Close)
	ref := registry.Ref{Registry: strings.TrimPrefix(srv.URL, "https://"), Repository: "app"}
	return &registry.Client{HTTP: srv.Client()}, ref, index, &OSV{BaseURL: srv.URL, HTTP: srv.Client()}, &queries
}

func TestScan(t *testing.T) {
	c, ref, index, osv, queries := setup(t, true)
	r, err := Scan(context.Background(), c, ref, index, osv)
	if err != nil {
		t.Fatal(err)
	}
	if !r.SBOM || r.Packages != 2 || len(r.Findings) != 1 || r.VulnCount() != 2 {
		t.Fatalf("%+v", r)
	}
	if f := r.Findings[0]; f.PURL != "pkg:golang/github.com/goccy/go-yaml@v1.11.0" || f.Platform != "linux/amd64" {
		t.Errorf("%+v", f)
	}
	if *queries != 1 {
		t.Errorf("%d OSV requests", *queries)
	}
}

func TestNoSBOMIsNotClean(t *testing.T) {
	c, ref, index, osv, queries := setup(t, false)
	r, err := Scan(context.Background(), c, ref, index, osv)
	if err != nil {
		t.Fatal(err)
	}
	if r.SBOM || *queries != 0 {
		t.Errorf("%+v, %d queries", r, *queries)
	}
}

func TestParseCycloneDX(t *testing.T) {
	got, err := ParseSBOMStatement([]byte(`{"bomFormat":"CycloneDX","components":[{"purl":"pkg:npm/lodash@4.17.20"},{"purl":"pkg:npm/x"}]}`))
	if err != nil || len(got) != 1 || got[0] != "pkg:npm/lodash@4.17.20" {
		t.Errorf("%v %v", got, err)
	}
}
