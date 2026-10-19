// Package node collects node-local configuration — the kubelet's
// configuration file and command-line overrides, and control-plane static
// pod manifests — by reading files on the node itself.
//
// This is the alternative to fetching kubelet configuration through the API
// server's nodes/proxy subresource (/api/v1/nodes/NAME/proxy/configz), which
// Hardex deliberately does not use: nodes/proxy grants exec into every pod on
// the node, so a scanner holding it would be a root-equivalent credential.
// Run `hardex scan --node` on the node, or in the read-only DaemonSet in
// deploy/hardex-node.yaml, which mounts the host paths read-only.
package node

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ManintheiCloud/Hardex/core/resource"
)

// KubeletConfigPaths are where distributions place the kubelet
// configuration file, in order of preference: kubeadm, EKS (AL2023 and AL2),
// GKE, AKS. Pass --kubelet-config for anything else.
var KubeletConfigPaths = []string{
	"/var/lib/kubelet/config.yaml",
	"/etc/kubernetes/kubelet/config.json",
	"/etc/kubernetes/kubelet/kubelet-config.json",
	"/home/kubernetes/kubelet-config.yaml",
	"/etc/default/kubeletconfig.json",
}

// FlagSources hold kubelet command-line arguments: kubeadm's flags file and
// systemd drop-ins.
var FlagSources = []string{
	"/var/lib/kubelet/kubeadm-flags.env",
	"/etc/default/kubelet",
	"/etc/sysconfig/kubelet",
	"/etc/systemd/system/kubelet.service.d",
	"/usr/lib/systemd/system/kubelet.service.d",
}

// ManifestDirs hold control-plane static pod manifests.
var ManifestDirs = []string{"/etc/kubernetes/manifests"}

// Options configures collection.
type Options struct {
	// Root is prepended to every host path, e.g. /host when the node's
	// filesystem is mounted into a container.
	Root string
	// NodeName names the node in findings (default: $NODE_NAME, else the
	// hostname).
	NodeName string
	// KubeletConfig overrides discovery of the kubelet configuration file
	// (a path on the node, without Root).
	KubeletConfig string
}

// Result is the outcome of collection.
type Result struct {
	Inventory *resource.Inventory
	// Notes describe what was read and what was overridden.
	Notes []string
	// Errors describe files that exist but could not be read or parsed.
	Errors []string
}

// flagFields maps kubelet flags that override security-relevant
// configuration fields to their KubeletConfiguration path.
var flagFields = map[string][]string{
	"anonymous-auth":                    {"authentication", "anonymous", "enabled"},
	"authentication-token-webhook":      {"authentication", "webhook", "enabled"},
	"authorization-mode":                {"authorization", "mode"},
	"read-only-port":                    {"readOnlyPort"},
	"protect-kernel-defaults":           {"protectKernelDefaults"},
	"client-ca-file":                    {"authentication", "x509", "clientCAFile"},
	"rotate-certificates":               {"rotateCertificates"},
	"event-qps":                         {"eventRecordQPS"},
	"tls-cert-file":                     {"tlsCertFile"},
	"tls-private-key-file":              {"tlsPrivateKeyFile"},
	"make-iptables-util-chains":         {"makeIPTablesUtilChains"},
	"streaming-connection-idle-timeout": {"streamingConnectionIdleTimeout"},
}

var boolFlags = map[string]bool{"anonymous-auth": true, "authentication-token-webhook": true, "protect-kernel-defaults": true, "rotate-certificates": true, "make-iptables-util-chains": true}
var intFlags = map[string]bool{"read-only-port": true, "event-qps": true}

// Collect reads node-local configuration under opts.Root.
func Collect(opts Options) (*Result, error) {
	res := &Result{Inventory: resource.NewInventory()}
	name := opts.NodeName
	if name == "" {
		name = os.Getenv("NODE_NAME")
	}
	if name == "" {
		name, _ = os.Hostname()
	}
	host := func(p string) string { return filepath.Join(opts.Root, p) }

	// Kubelet command-line flags (they override the configuration file).
	flags := map[string]string{}
	flagFile := ""
	for _, src := range FlagSources {
		for _, f := range listFiles(host(src)) {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			for k, v := range parseFlags(string(data)) {
				flags[k] = v
				flagFile = f
			}
		}
	}

	configPath := opts.KubeletConfig
	if configPath == "" {
		configPath = flags["config"]
	}
	candidates := KubeletConfigPaths
	if configPath != "" {
		candidates = []string{configPath}
	}
	var kubelet *resource.Object
	for _, c := range candidates {
		data, err := os.ReadFile(host(c))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("node: cannot read kubelet configuration %s: %v", c, err))
			break
		}
		inv := resource.NewInventory()
		if err := resource.LoadBytes(inv, data, c); err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("node: kubelet configuration %s: %v", c, err))
			break
		}
		for _, o := range inv.OfKind("KubeletConfiguration") {
			kubelet = o
		}
		if kubelet == nil {
			res.Errors = append(res.Errors, fmt.Sprintf("node: %s is not a KubeletConfiguration", c))
			break
		}
		res.Notes = append(res.Notes, "kubelet configuration: "+c)
		break
	}
	if kubelet == nil && len(flags) > 0 {
		// A kubelet configured only by flags: assess the flags alone.
		raw := map[string]any{"apiVersion": "kubelet.config.k8s.io/v1beta1", "kind": "KubeletConfiguration"}
		o, _ := resource.NewObject(raw, flagFile, 0)
		kubelet = o
		res.Notes = append(res.Notes, "kubelet has no configuration file; assessing command-line flags from "+strings.TrimPrefix(flagFile, opts.Root))
	}
	if kubelet != nil {
		var overridden []string
		for _, f := range sortedKeys(flags) {
			path, ok := flagFields[f]
			v := flags[f]
			if v == "" && boolFlags[f] {
				v = "true"
			}
			if !ok || v == "" {
				continue
			}
			setPath(kubelet.Raw, path, typed(f, v))
			overridden = append(overridden, "--"+f)
		}
		if len(overridden) > 0 {
			res.Notes = append(res.Notes, fmt.Sprintf("kubelet flags override the configuration file: %s (from %s)", strings.Join(overridden, ", "), strings.TrimPrefix(flagFile, opts.Root)))
		}
		kubelet.Name = name
		meta, _ := kubelet.Raw["metadata"].(map[string]any)
		if meta == nil {
			meta = map[string]any{}
			kubelet.Raw["metadata"] = meta
		}
		meta["name"] = name
		res.Inventory.Add(kubelet)
		res.Inventory.Sources = append(res.Inventory.Sources, "node:"+name+" "+kubelet.Source)
	} else {
		res.Notes = append(res.Notes, "no kubelet configuration found (looked in "+strings.Join(candidates, ", ")+")")
	}

	for _, dir := range ManifestDirs {
		files := listFiles(host(dir))
		for _, f := range files {
			if ext := filepath.Ext(f); ext != ".yaml" && ext != ".yml" && ext != ".json" {
				continue
			}
			data, err := os.ReadFile(f)
			if err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("node: cannot read %s: %v", f, err))
				continue
			}
			rel := strings.TrimPrefix(f, opts.Root)
			inv := resource.NewInventory()
			if err := resource.LoadBytes(inv, data, rel); err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("node: %s: %v", rel, err))
				continue
			}
			for _, o := range inv.Objects {
				res.Inventory.Add(o)
			}
			res.Inventory.Sources = append(res.Inventory.Sources, "node:"+name+" "+rel)
		}
		if len(files) > 0 {
			res.Notes = append(res.Notes, fmt.Sprintf("static pod manifests: %s (%d files)", dir, len(files)))
		}
	}
	if len(res.Inventory.Objects) == 0 && len(res.Errors) == 0 {
		return nil, fmt.Errorf("no node configuration found under %q; run on a node, or mount the host filesystem and pass --node-root", opts.Root+"/")
	}
	return res, nil
}

func listFiles(p string) []string {
	st, err := os.Stat(p)
	if err != nil {
		return nil
	}
	if !st.IsDir() {
		return []string{p}
	}
	entries, err := os.ReadDir(p)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			out = append(out, filepath.Join(p, e.Name()))
		}
	}
	sort.Strings(out)
	return out
}

var flagRE = regexp.MustCompile(`--([a-z0-9-]+)(?:=("[^"]*"|'[^']*'|[^\s"']*))?`)

// parseFlags extracts --flag=value arguments from environment files and
// systemd units.
func parseFlags(s string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		for _, m := range flagRE.FindAllStringSubmatch(line, -1) {
			// A bare --flag is recorded with an empty value; it means true
			// for boolean flags and is otherwise "--flag value", which is not
			// recognised.
			out[m[1]] = strings.Trim(m[2], `"'`)
		}
	}
	return out
}

func typed(flag, v string) any {
	switch {
	case boolFlags[flag]:
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
	case intFlags[flag]:
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			return n
		}
	case flag == "authorization-mode":
		// Comma-separated on the command line; the config takes one mode.
		if strings.Contains(v, "AlwaysAllow") {
			return "AlwaysAllow"
		}
		if strings.Contains(v, "Webhook") {
			return "Webhook"
		}
	}
	return v
}

func setPath(m map[string]any, path []string, v any) {
	for _, p := range path[:len(path)-1] {
		next, ok := m[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[p] = next
		}
		m = next
	}
	m[path[len(path)-1]] = v
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
