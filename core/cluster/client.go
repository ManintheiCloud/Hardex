package cluster

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// maxResponseBytes bounds a single API response. Lists are paginated, so a
// legitimate page is far smaller.
const maxResponseBytes = 64 << 20

// Client is a minimal Kubernetes API client.
type Client struct {
	cfg      *Config
	http     *http.Client
	readOnly bool

	mu        sync.Mutex
	execToken string
	execCert  *tls.Certificate
}

// Mode controls whether a client may change cluster state.
type Mode int

const (
	// ReadOnly clients refuse every method except GET.
	ReadOnly Mode = iota
	// ReadWrite clients may also PATCH. Only the remediation apply and
	// rollback paths construct one.
	ReadWrite
)

// NewClient builds a client for the configuration.
func NewClient(cfg *Config, mode Mode) (*Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cfg.TLSServer}
	if len(cfg.CAData) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cfg.CAData) {
			return nil, errors.New("certificate authority data contains no valid PEM certificates")
		}
		tlsCfg.RootCAs = pool
	}
	c := &Client{cfg: cfg, readOnly: mode == ReadOnly}
	if len(cfg.CertData) > 0 {
		cert, err := tls.X509KeyPair(cfg.CertData, cfg.KeyData)
		if err != nil {
			return nil, fmt.Errorf("client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	} else if cfg.Exec != nil {
		tlsCfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if err := c.runExec(); err != nil {
				return nil, err
			}
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.execCert != nil {
				return c.execCert, nil
			}
			return &tls.Certificate{}, nil
		}
	}
	c.http = &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     tlsCfg,
			Proxy:               http.ProxyFromEnvironment,
			TLSHandshakeTimeout: 15 * time.Second,
		},
		// Never follow redirects: they could carry the bearer token to
		// another host.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return c, nil
}

// Server returns the API server URL.
func (c *Client) Server() string { return c.cfg.Server }

// Context returns the kubeconfig context name.
func (c *Client) Context() string { return c.cfg.Context }

// StatusError is a non-2xx API response.
type StatusError struct {
	Code    int
	Message string
}

func (e *StatusError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.Code, e.Message) }

// IsForbidden reports whether err is an authorization failure.
func IsForbidden(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && (se.Code == http.StatusForbidden || se.Code == http.StatusUnauthorized)
}

// IsNotFound reports whether err is a 404.
func IsNotFound(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == http.StatusNotFound
}

// Get fetches a path and decodes the JSON response.
func (c *Client) Get(ctx context.Context, path string, query url.Values) (map[string]any, error) {
	return c.do(ctx, http.MethodGet, path, query, nil, "")
}

// JSONPatch applies an RFC 6902 patch to the object at path.
func (c *Client) JSONPatch(ctx context.Context, path string, patch []byte) (map[string]any, error) {
	return c.do(ctx, http.MethodPatch, path, nil, patch, "application/json-patch+json")
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body []byte, contentType string) (map[string]any, error) {
	if c.readOnly && method != http.MethodGet {
		return nil, fmt.Errorf("refusing %s %s: client is read-only", method, path)
	}
	u := c.cfg.Server + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "hardex")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	token, err := c.token()
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxResponseBytes {
		return nil, fmt.Errorf("%s %s: response exceeds %d bytes", method, path, maxResponseBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var status struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &status)
		if status.Message == "" {
			status.Message = http.StatusText(resp.StatusCode)
		}
		return nil, &StatusError{Code: resp.StatusCode, Message: status.Message}
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("%s %s: invalid JSON response: %w", method, path, err)
	}
	return out, nil
}

func (c *Client) token() (string, error) {
	switch {
	case c.cfg.TokenFile != "":
		b, err := os.ReadFile(c.cfg.TokenFile)
		if err != nil {
			return "", fmt.Errorf("read token file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	case c.cfg.Token != "":
		return c.cfg.Token, nil
	case c.cfg.Exec != nil && len(c.cfg.CertData) == 0:
		if err := c.runExec(); err != nil {
			return "", err
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.execToken, nil
	}
	return "", nil
}

// runExec runs the credential plugin once per process.
func (c *Client) runExec() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.execToken != "" || c.execCert != nil {
		return nil
	}
	e := c.cfg.Exec
	apiVersion := e.APIVersion
	if apiVersion == "" {
		apiVersion = "client.authentication.k8s.io/v1"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, e.Command, e.Args...)
	cmd.Env = os.Environ()
	for _, kv := range e.Env {
		cmd.Env = append(cmd.Env, kv.Name+"="+kv.Value)
	}
	info, _ := json.Marshal(map[string]any{
		"apiVersion": apiVersion, "kind": "ExecCredential",
		"spec": map[string]any{"interactive": false},
	})
	cmd.Env = append(cmd.Env, "KUBERNETES_EXEC_INFO="+string(info))
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("credential plugin %q failed: %w", e.Command, err)
	}
	var cred struct {
		Status struct {
			Token                 string `json:"token"`
			ClientCertificateData string `json:"clientCertificateData"`
			ClientKeyData         string `json:"clientKeyData"`
		} `json:"status"`
	}
	if err := json.Unmarshal(out, &cred); err != nil {
		return fmt.Errorf("credential plugin %q: invalid ExecCredential: %w", e.Command, err)
	}
	if cred.Status.ClientCertificateData != "" {
		cert, err := tls.X509KeyPair([]byte(cred.Status.ClientCertificateData), []byte(cred.Status.ClientKeyData))
		if err != nil {
			return fmt.Errorf("credential plugin %q: %w", e.Command, err)
		}
		c.execCert = &cert
	}
	c.execToken = cred.Status.Token
	if c.execToken == "" && c.execCert == nil {
		return fmt.Errorf("credential plugin %q returned no credentials", e.Command)
	}
	return nil
}
