// Package registry is a minimal, read-only OCI distribution (Docker
// Registry v2) client: enough to resolve tags to digests and fetch
// manifests and blobs for signature verification.
//
// Every manifest and blob fetched by digest is re-hashed and compared with
// the digest requested, so a malicious or compromised registry cannot
// substitute content.
package registry

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Ref is a parsed image reference.
type Ref struct {
	Registry   string // host[:port] used for API calls
	Repository string
	Tag        string
	Digest     string // "sha256:..." if pinned
	Original   string
}

// Name is registry/repository, as used in signatures.
func (r Ref) Name() string { return r.Registry + "/" + r.Repository }

const dockerHub = "registry-1.docker.io"

var digestRE = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// ParseRef parses an image reference the way container runtimes do:
// "nginx" is docker.io/library/nginx:latest.
func ParseRef(image string) (Ref, error) {
	r := Ref{Original: image}
	rest := image
	if i := strings.Index(rest, "@"); i >= 0 {
		r.Digest = rest[i+1:]
		rest = rest[:i]
		if !digestRE.MatchString(r.Digest) {
			return r, fmt.Errorf("invalid digest in %q", image)
		}
	}
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 2 && (strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost") {
		r.Registry, rest = parts[0], parts[1]
	} else {
		r.Registry = "docker.io"
	}
	if i := strings.LastIndex(rest, ":"); i >= 0 {
		r.Tag = rest[i+1:]
		rest = rest[:i]
	}
	if rest == "" {
		return r, fmt.Errorf("invalid image reference %q", image)
	}
	if r.Registry == "docker.io" || r.Registry == "index.docker.io" {
		r.Registry = dockerHub
		if !strings.Contains(rest, "/") {
			rest = "library/" + rest
		}
	}
	r.Repository = rest
	if r.Tag == "" && r.Digest == "" {
		r.Tag = "latest"
	}
	return r, nil
}

// Manifest media types accepted when resolving references.
var manifestTypes = strings.Join([]string{
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.docker.distribution.manifest.v2+json",
}, ", ")

const (
	maxManifest = 4 << 20
	maxBlob     = 16 << 20
)

// Client talks to registries.
type Client struct {
	HTTP *http.Client
	// Credentials maps a registry host to "user:password".
	Credentials map[string]string

	mu     sync.Mutex
	tokens map[string]string // host+scope -> bearer token
}

// NewClient returns a client using credentials from the Docker config file
// ($DOCKER_CONFIG/config.json or ~/.docker/config.json) when present.
// Credential helpers are not supported.
func NewClient() *Client {
	c := &Client{
		HTTP:        &http.Client{Timeout: 30 * time.Second},
		Credentials: dockerCredentials(),
	}
	return c
}

func dockerCredentials() map[string]string {
	dir := os.Getenv("DOCKER_CONFIG")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil
		}
		dir = filepath.Join(home, ".docker")
	}
	data, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		return nil
	}
	var cfg struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	if json.Unmarshal(data, &cfg) != nil {
		return nil
	}
	out := map[string]string{}
	for host, a := range cfg.Auths {
		dec, err := base64.StdEncoding.DecodeString(a.Auth)
		if err != nil || !strings.Contains(string(dec), ":") {
			continue
		}
		host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
		host = strings.TrimSuffix(strings.Split(host, "/")[0], "/")
		if host == "index.docker.io" || host == "docker.io" {
			host = dockerHub
		}
		out[host] = string(dec)
	}
	return out
}

// Manifest is a fetched manifest.
type Manifest struct {
	Body      []byte
	MediaType string
	Digest    string
}

// ErrNotFound is returned for 404 responses.
var ErrNotFound = errors.New("not found")

// GetManifest fetches a manifest by tag or digest. When fetched by digest,
// the content is verified against it.
func (c *Client) GetManifest(ctx context.Context, registry, repo, reference string) (*Manifest, error) {
	resp, body, err := c.get(ctx, registry, repo, "/v2/"+repo+"/manifests/"+reference, manifestTypes, maxManifest)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	computed := "sha256:" + hex.EncodeToString(sum[:])
	if strings.HasPrefix(reference, "sha256:") && reference != computed {
		return nil, fmt.Errorf("manifest content does not match digest %s", reference)
	}
	if hdr := resp.Header.Get("Docker-Content-Digest"); hdr != "" && hdr != computed {
		return nil, fmt.Errorf("registry reported digest %s for content hashing to %s", hdr, computed)
	}
	return &Manifest{Body: body, MediaType: resp.Header.Get("Content-Type"), Digest: computed}, nil
}

// Descriptor is an OCI content descriptor.
type Descriptor struct {
	MediaType    string            `json:"mediaType"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	Platform     *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	} `json:"platform,omitempty"`
}

// Index is an OCI image index (or a manifest's layer list, which shares the
// descriptor shape).
type Index struct {
	MediaType    string       `json:"mediaType"`
	ArtifactType string       `json:"artifactType,omitempty"`
	Manifests    []Descriptor `json:"manifests"`
	Layers       []Descriptor `json:"layers"`
}

// Referrers lists the artifacts that refer to digest (signatures,
// attestations, SBOMs), using the OCI 1.1 referrers API and falling back to
// the referrers tag schema ("sha256-<hex>") for registries without it. The
// listing itself is not content-addressed; callers must verify what they
// fetch from it.
func (c *Client) Referrers(ctx context.Context, registry, repo, digest string) ([]Descriptor, error) {
	if !digestRE.MatchString(digest) {
		return nil, fmt.Errorf("unsupported digest %q", digest)
	}
	_, body, err := c.get(ctx, registry, repo, "/v2/"+repo+"/referrers/"+digest, "application/vnd.oci.image.index.v1+json", maxManifest)
	if errors.Is(err, ErrNotFound) {
		var m *Manifest
		m, err = c.GetManifest(ctx, registry, repo, strings.Replace(digest, ":", "-", 1))
		if errors.Is(err, ErrNotFound) {
			return nil, nil
		}
		if err == nil {
			body = m.Body
		}
	}
	if err != nil {
		return nil, err
	}
	var idx Index
	if err := json.Unmarshal(body, &idx); err != nil {
		return nil, fmt.Errorf("referrers of %s: %w", digest, err)
	}
	return idx.Manifests, nil
}

// GetBlob fetches a blob and verifies its digest.
func (c *Client) GetBlob(ctx context.Context, registry, repo, digest string) ([]byte, error) {
	if !digestRE.MatchString(digest) {
		return nil, fmt.Errorf("unsupported digest %q", digest)
	}
	_, body, err := c.get(ctx, registry, repo, "/v2/"+repo+"/blobs/"+digest, "*/*", maxBlob)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	if "sha256:"+hex.EncodeToString(sum[:]) != digest {
		return nil, fmt.Errorf("blob content does not match digest %s", digest)
	}
	return body, nil
}

func (c *Client) get(ctx context.Context, registry, repo, path, accept string, limit int64) (*http.Response, []byte, error) {
	scope := "repository:" + repo + ":pull"
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+registry+path, nil)
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Accept", accept)
		req.Header.Set("User-Agent", "hardex")
		c.authorize(req, registry, scope)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return nil, nil, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		resp.Body.Close()
		if err != nil {
			return nil, nil, err
		}
		switch {
		case resp.StatusCode == http.StatusUnauthorized && attempt == 0:
			if err := c.login(ctx, registry, scope, resp.Header.Get("WWW-Authenticate")); err != nil {
				return nil, nil, err
			}
			continue
		case resp.StatusCode == http.StatusNotFound:
			return nil, nil, ErrNotFound
		case resp.StatusCode != http.StatusOK:
			return nil, nil, fmt.Errorf("%s%s: HTTP %d", registry, path, resp.StatusCode)
		case int64(len(body)) > limit:
			return nil, nil, fmt.Errorf("%s%s: response exceeds %d bytes", registry, path, limit)
		}
		return resp, body, nil
	}
	return nil, nil, fmt.Errorf("%s: authentication failed", registry)
}

func (c *Client) authorize(req *http.Request, registry, scope string) {
	c.mu.Lock()
	tok := c.tokens[registry+" "+scope]
	c.mu.Unlock()
	switch {
	case tok == "basic":
		user, pass, _ := strings.Cut(c.Credentials[registry], ":")
		req.SetBasicAuth(user, pass)
	case tok != "":
		req.Header.Set("Authorization", "Bearer "+tok)
	}
}

// login answers a WWW-Authenticate challenge (Bearer token service or Basic).
func (c *Client) login(ctx context.Context, registry, scope, challenge string) error {
	scheme, params := parseChallenge(challenge)
	c.mu.Lock()
	if c.tokens == nil {
		c.tokens = map[string]string{}
	}
	c.mu.Unlock()
	switch strings.ToLower(scheme) {
	case "basic":
		if c.Credentials[registry] == "" {
			return fmt.Errorf("%s requires credentials (docker login)", registry)
		}
		c.mu.Lock()
		c.tokens[registry+" "+scope] = "basic"
		c.mu.Unlock()
		return nil
	case "bearer":
	default:
		return fmt.Errorf("%s: unsupported authentication challenge", registry)
	}
	realm, err := url.Parse(params["realm"])
	if err != nil || realm.Scheme != "https" {
		return fmt.Errorf("%s: token service must use https", registry)
	}
	q := realm.Query()
	if s := params["service"]; s != "" {
		q.Set("service", s)
	}
	q.Set("scope", scope)
	realm.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return err
	}
	if cred := c.Credentials[registry]; cred != "" {
		user, pass, _ := strings.Cut(cred, ":")
		req.SetBasicAuth(user, pass)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: token request failed: HTTP %d", registry, resp.StatusCode)
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil {
		return err
	}
	t := tok.Token
	if t == "" {
		t = tok.AccessToken
	}
	if t == "" {
		return fmt.Errorf("%s: token service returned no token", registry)
	}
	c.mu.Lock()
	c.tokens[registry+" "+scope] = t
	c.mu.Unlock()
	return nil
}

var challengeParam = regexp.MustCompile(`(\w+)="([^"]*)"`)

func parseChallenge(h string) (string, map[string]string) {
	scheme, rest, _ := strings.Cut(strings.TrimSpace(h), " ")
	params := map[string]string{}
	for _, m := range challengeParam.FindAllStringSubmatch(rest, -1) {
		params[strings.ToLower(m[1])] = m[2]
	}
	return scheme, params
}
