package imagesig

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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

// fakeRegistry serves content-addressed manifests and blobs behind a
// bearer-token challenge.
type fakeRegistry struct {
	manifests map[string][]byte // "repo:ref" -> body
	blobs     map[string][]byte
	referrers map[string][]byte // "repo:digest" -> index (OCI referrers API)
	srv       *httptest.Server
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	f := &fakeRegistry{manifests: map[string][]byte{}, blobs: map[string][]byte{}, referrers: map[string][]byte{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			json.NewEncoder(w).Encode(map[string]string{"token": "t0k"})
			return
		}
		if r.Header.Get("Authorization") != "Bearer t0k" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+f.srv.URL+`/token",service="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/v2/")
		if i := strings.Index(path, "/referrers/"); i >= 0 {
			body, ok := f.referrers[path[:i]+":"+path[i+len("/referrers/"):]]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
			w.Write(body)
			return
		}
		if i := strings.Index(path, "/manifests/"); i >= 0 {
			body, ok := f.manifests[path[:i]+":"+path[i+len("/manifests/"):]]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			w.Write(body)
			return
		}
		if i := strings.Index(path, "/blobs/"); i >= 0 {
			body, ok := f.blobs[path[i+len("/blobs/"):]]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Write(body)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRegistry) host() string { return strings.TrimPrefix(f.srv.URL, "https://") }

func (f *fakeRegistry) client() *registry.Client {
	return &registry.Client{HTTP: f.srv.Client()}
}

// pushImage stores an image manifest under repo:tag and returns its digest.
func (f *fakeRegistry) pushImage(repo, tag, content string) string {
	body := []byte(`{"schemaVersion":2,"config":{"digest":"` + content + `"}}`)
	d := digestOf(body)
	f.manifests[repo+":"+tag] = body
	f.manifests[repo+":"+d] = body
	return d
}

// sign stores a cosign signature for digest, signing a payload that names
// payloadDigest (normally the same digest).
func (f *fakeRegistry) sign(repo, digest, payloadDigest string, key *ecdsa.PrivateKey) {
	payload := []byte(`{"critical":{"identity":{"docker-reference":"` + f.host() + "/" + repo + `"},"image":{"docker-manifest-digest":"` + payloadDigest + `"},"type":"cosign container image signature"},"optional":null}`)
	h := sha256.Sum256(payload)
	sig, _ := ecdsa.SignASN1(rand.Reader, key, h[:])
	pd := digestOf(payload)
	f.blobs[pd] = payload
	man, _ := json.Marshal(map[string]any{"schemaVersion": 2, "layers": []any{map[string]any{
		"mediaType": "application/vnd.dev.cosign.simplesigning.v1+json", "digest": pd,
		"annotations": map[string]string{signatureAnnotation: base64.StdEncoding.EncodeToString(sig)},
	}}})
	f.manifests[repo+":"+strings.Replace(digest, ":", "-", 1)+".sig"] = man
}

func keyPair(t *testing.T) (*ecdsa.PrivateKey, *PublicKey) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pub, err := ParsePublicKey("cosign.pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func TestVerify(t *testing.T) {
	f := newFakeRegistry(t)
	trusted, pub := keyPair(t)
	untrusted, _ := keyPair(t)
	c := f.client()
	ref := registry.Ref{Registry: f.host(), Repository: "org/app"}

	good := f.pushImage("org/app", "good", "a")
	f.sign("org/app", good, good, trusted)
	wrongKey := f.pushImage("org/app", "wrongkey", "b")
	f.sign("org/app", wrongKey, wrongKey, untrusted)
	replayed := f.pushImage("org/app", "replayed", "c")
	f.sign("org/app", replayed, good, trusted) // valid signature, but for another digest
	unsigned := f.pushImage("org/app", "unsigned", "d")

	cases := map[string]Status{good: Verified, wrongKey: Invalid, replayed: Invalid, unsigned: Unsigned}
	for d, want := range cases {
		if got := Verify(context.Background(), c, ref, d, []*PublicKey{pub}); got.Status != want {
			t.Errorf("%s: %s (%s), want %s", d, got.Status, got.Detail, want)
		}
	}

	// Tampered payload blob: the registry client rejects content that does
	// not match its digest.
	for k, v := range f.blobs {
		f.blobs[k] = append([]byte(nil), append(v[:len(v)-1], ' ')...)
	}
	if got := Verify(context.Background(), c, ref, good, []*PublicKey{pub}); got.Status == Verified {
		t.Error("verified a tampered payload")
	}
}

func TestResolveTagThroughTokenChallenge(t *testing.T) {
	f := newFakeRegistry(t)
	d := f.pushImage("org/app", "1.0", "x")
	m, err := f.client().GetManifest(context.Background(), f.host(), "org/app", "1.0")
	if err != nil || m.Digest != d {
		t.Fatalf("digest %v, err %v", m, err)
	}
	f.manifests["org/app:"+d] = []byte("substituted")
	if _, err := f.client().GetManifest(context.Background(), f.host(), "org/app", d); err == nil {
		t.Fatal("accepted manifest content that does not match its digest")
	}
}

func TestParsePublicKeyRejectsNonKeys(t *testing.T) {
	if _, err := ParsePublicKey("x", []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")); err == nil {
		t.Error("accepted a private key block")
	}
}
