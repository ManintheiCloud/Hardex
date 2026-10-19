// Package cluster connects Hardex to a live Kubernetes API server.
//
// It implements just enough of the Kubernetes client protocol — kubeconfig
// and in-cluster authentication, paginated LIST, GET and JSON-patch — using
// the standard library, so Hardex does not depend on client-go (see
// docs/adr/0004-live-cluster-client.md).
//
// The client is read-only unless explicitly constructed for writes, and
// collection never reads Secrets: an assessment tool should not need
// credentials that could themselves compromise the cluster.
package cluster

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ManintheiCloud/Hardex/internal/yamlsafe"
)

// kubeconfig mirrors the subset of the kubeconfig file format Hardex uses.
// Unknown fields (extensions, preferences) are ignored, as kubectl does.
type kubeconfig struct {
	CurrentContext string `yaml:"current-context"`
	Clusters       []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server                   string `yaml:"server"`
			CertificateAuthority     string `yaml:"certificate-authority"`
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
			InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
			TLSServerName            string `yaml:"tls-server-name"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			Token                 string          `yaml:"token"`
			TokenFile             string          `yaml:"tokenFile"`
			ClientCertificate     string          `yaml:"client-certificate"`
			ClientCertificateData string          `yaml:"client-certificate-data"`
			ClientKey             string          `yaml:"client-key"`
			ClientKeyData         string          `yaml:"client-key-data"`
			Username              string          `yaml:"username"`
			AuthProvider          *map[string]any `yaml:"auth-provider"`
			Exec                  *ExecConfig     `yaml:"exec"`
		} `yaml:"user"`
	} `yaml:"users"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster   string `yaml:"cluster"`
			User      string `yaml:"user"`
			Namespace string `yaml:"namespace"`
		} `yaml:"context"`
	} `yaml:"contexts"`

	dir string // directory of the file, for resolving relative paths
}

// ExecConfig is a client-go credential plugin configuration
// (client.authentication.k8s.io), as used by EKS, GKE and AKS.
type ExecConfig struct {
	APIVersion string   `yaml:"apiVersion"`
	Command    string   `yaml:"command"`
	Args       []string `yaml:"args"`
	Env        []struct {
		Name  string `yaml:"name"`
		Value string `yaml:"value"`
	} `yaml:"env"`
	InteractiveMode string `yaml:"interactiveMode"`
}

// Config is a resolved connection configuration.
type Config struct {
	Context   string
	Server    string
	CAData    []byte
	TLSServer string

	Token     string
	TokenFile string // re-read on every request (projected tokens rotate)
	CertData  []byte
	KeyData   []byte
	Exec      *ExecConfig
}

// DefaultKubeconfigPaths returns the paths named by $KUBECONFIG, or
// ~/.kube/config.
func DefaultKubeconfigPaths() []string {
	if env := os.Getenv("KUBECONFIG"); env != "" {
		var out []string
		for _, p := range filepath.SplitList(env) {
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{filepath.Join(home, ".kube", "config")}
}

// LoadKubeconfig resolves a context from one or more kubeconfig files. As
// with kubectl, the first file to define a name wins and the first file to
// set current-context wins. An empty context selects current-context.
func LoadKubeconfig(paths []string, context string) (*Config, error) {
	var files []*kubeconfig
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var kc kubeconfig
		if err := yamlsafe.Decode(data, &kc); err != nil {
			return nil, fmt.Errorf("kubeconfig %s: %w", p, err)
		}
		kc.dir = filepath.Dir(p)
		files = append(files, &kc)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no kubeconfig found (looked in %s)", strings.Join(paths, ", "))
	}
	if context == "" {
		for _, f := range files {
			if f.CurrentContext != "" {
				context = f.CurrentContext
				break
			}
		}
	}
	if context == "" {
		return nil, errors.New("kubeconfig has no current-context; pass --context")
	}

	var clusterName, userName string
	found := false
	for _, f := range files {
		for _, c := range f.Contexts {
			if c.Name == context && !found {
				clusterName, userName, found = c.Context.Cluster, c.Context.User, true
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("context %q not found in kubeconfig", context)
	}
	cfg := &Config{Context: context}

	clusterFound := false
	for _, f := range files {
		for _, c := range f.Clusters {
			if c.Name != clusterName || clusterFound {
				continue
			}
			clusterFound = true
			cl := c.Cluster
			if cl.InsecureSkipTLSVerify {
				// Hardex will not send credentials to an unauthenticated
				// server; there is no flag to override this.
				return nil, fmt.Errorf("cluster %q sets insecure-skip-tls-verify; Hardex requires a verified server certificate", clusterName)
			}
			cfg.Server = strings.TrimSuffix(cl.Server, "/")
			cfg.TLSServer = cl.TLSServerName
			var err error
			if cfg.CAData, err = dataOrFile(cl.CertificateAuthorityData, cl.CertificateAuthority, f.dir); err != nil {
				return nil, fmt.Errorf("cluster %q certificate authority: %w", clusterName, err)
			}
		}
	}
	if !clusterFound || cfg.Server == "" {
		return nil, fmt.Errorf("cluster %q not found in kubeconfig", clusterName)
	}
	if !strings.HasPrefix(cfg.Server, "https://") {
		return nil, fmt.Errorf("cluster %q server %q is not https; credentials would be sent in clear text", clusterName, cfg.Server)
	}

	userFound := false
	for _, f := range files {
		for _, u := range f.Users {
			if u.Name != userName || userFound {
				continue
			}
			userFound = true
			usr := u.User
			switch {
			case usr.AuthProvider != nil:
				return nil, fmt.Errorf("user %q uses a legacy auth-provider; migrate to an exec credential plugin (e.g. gke-gcloud-auth-plugin, kubelogin)", userName)
			case usr.Username != "":
				return nil, fmt.Errorf("user %q uses basic authentication, which Kubernetes no longer supports", userName)
			}
			cfg.Token = usr.Token
			if usr.TokenFile != "" {
				cfg.TokenFile = resolve(usr.TokenFile, f.dir)
			}
			var err error
			if cfg.CertData, err = dataOrFile(usr.ClientCertificateData, usr.ClientCertificate, f.dir); err != nil {
				return nil, fmt.Errorf("user %q client certificate: %w", userName, err)
			}
			if cfg.KeyData, err = dataOrFile(usr.ClientKeyData, usr.ClientKey, f.dir); err != nil {
				return nil, fmt.Errorf("user %q client key: %w", userName, err)
			}
			if usr.Exec != nil {
				exec := *usr.Exec
				exec.Command = resolveCommand(exec.Command, f.dir)
				cfg.Exec = &exec
			}
		}
	}
	if !userFound {
		return nil, fmt.Errorf("user %q not found in kubeconfig", userName)
	}
	return cfg, nil
}

const (
	inClusterTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	inClusterCAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// InCluster returns the configuration of the pod's own service account.
func InCluster() (*Config, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("not running inside a Kubernetes pod (KUBERNETES_SERVICE_HOST unset)")
	}
	ca, err := os.ReadFile(inClusterCAPath)
	if err != nil {
		return nil, err
	}
	if strings.Contains(host, ":") { // IPv6
		host = "[" + host + "]"
	}
	return &Config{Context: "in-cluster", Server: "https://" + host + ":" + port, CAData: ca, TokenFile: inClusterTokenPath}, nil
}

func dataOrFile(data, file, dir string) ([]byte, error) {
	if data != "" {
		return base64.StdEncoding.DecodeString(data)
	}
	if file != "" {
		return os.ReadFile(resolve(file, dir))
	}
	return nil, nil
}

func resolve(p, dir string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(dir, p)
}

// resolveCommand follows kubectl: a command containing a path separator is
// resolved relative to the kubeconfig; a bare name is looked up on PATH.
func resolveCommand(cmd, dir string) string {
	if strings.ContainsRune(cmd, filepath.Separator) {
		return resolve(cmd, dir)
	}
	return cmd
}
