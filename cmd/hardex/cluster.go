package main

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/ManintheiCloud/Hardex/core/cluster"
	"github.com/ManintheiCloud/Hardex/core/policy"
)

// clusterFlags are the flags shared by every command that talks to a live
// cluster.
type clusterFlags struct {
	enabled      bool
	inCluster    bool
	kubeconfig   string
	context      string
	allowPartial bool
}

func (cf *clusterFlags) register(fs *flag.FlagSet) {
	fs.BoolVar(&cf.enabled, "cluster", false, "assess the live cluster from the current kubeconfig context (read-only)")
	fs.BoolVar(&cf.inCluster, "in-cluster", false, "use the pod's service account (when running inside Kubernetes)")
	fs.StringVar(&cf.kubeconfig, "kubeconfig", "", "kubeconfig file (default $KUBECONFIG or ~/.kube/config)")
	fs.StringVar(&cf.context, "context", "", "kubeconfig context (default current-context)")
	fs.BoolVar(&cf.allowPartial, "allow-partial", false, "report unreadable resources as warnings instead of failing the assessment (exit 3)")
}

func (cf *clusterFlags) active() bool { return cf.enabled || cf.inCluster }

func (cf *clusterFlags) connect(mode cluster.Mode) (*cluster.Client, error) {
	var (
		cfg *cluster.Config
		err error
	)
	switch {
	case cf.inCluster:
		cfg, err = cluster.InCluster()
	default:
		paths := cluster.DefaultKubeconfigPaths()
		if cf.kubeconfig != "" {
			paths = []string{cf.kubeconfig}
		}
		cfg, err = cluster.LoadKubeconfig(paths, cf.context)
	}
	if err != nil {
		return nil, err
	}
	return cluster.NewClient(cfg, mode)
}

// collect reads the cluster and splits collection problems into errors and
// warnings according to --allow-partial.
func (cf *clusterFlags) collect(ctx context.Context, c *cluster.Client) (*cluster.Collection, []string, []string, error) {
	col, err := cluster.Collect(ctx, c)
	if err != nil {
		return nil, nil, nil, err
	}
	warnings := []string{fmt.Sprintf("live cluster: %d controller-owned objects (ReplicaSets, Pods, Jobs) assessed through their owners", col.Skipped)}
	warnings = append(warnings, col.Warnings...)
	if cf.allowPartial {
		return col, nil, append(warnings, col.Errors...), nil
	}
	return col, col.Errors, warnings, nil
}

func loadConfig(path string, includeSystem bool) (*policy.Config, error) {
	var cfg *policy.Config
	if path != "" {
		var err error
		if cfg, err = policy.LoadConfig(path); err != nil {
			return nil, err
		}
	} else {
		cfg = policy.DefaultConfig()
		if err := cfg.Validate(); err != nil {
			return nil, errors.New("internal: default config invalid")
		}
	}
	if includeSystem {
		cfg.IncludeSystem = true
	}
	return cfg, nil
}
